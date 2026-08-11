import base64
import gzip
import re

import pytest

from hardening_agent import guidelines
from hardening_agent.guidelines import (
    all_guideline_sources,
    delete_guideline_source,
    discover_guidelines_for_platforms,
    discover_official_guidelines,
    generate_scap_remediation,
    generate_selected_scap_remediation,
    guideline_sources_for,
    guideline_status,
    install_scanner,
    integrate_scap_coverage,
    run_scap_scan,
    save_guideline_source,
    scanner_install_plan,
)
from hardening_agent.models import Inventory, Platform, Target
from hardening_agent.transport import CommandResult


def test_sles_guideline_status_exposes_native_scap_profile() -> None:
    inventory = Inventory(
        target="sles",
        collected_at="2026-08-11T10:00:00+00:00",
        platform=Platform("suse", "sles", "15.6", "SUSE Linux Enterprise Server 15.6"),
        sections={
            "compliance": (
                "TOOL:oscap=/usr/bin/oscap\n"
                "DATASTREAM:/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml|420|8\n"
                "PROFILE:/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml|xccdf_org.ssgproject.content_profile_stig\n"
                "SCAP_RULE:/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml|"
                "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
            )
        },
    )
    status = guideline_status(inventory)

    assert status["vendor"] == "SUSE"
    assert status["compatibility"] == "matched"
    assert status["native_scanner"]["ready"] is True
    assert status["native_scanner"]["data_streams"][0]["rules"] == 420
    assert status["native_scanner"]["profiles"] == ["xccdf_org.ssgproject.content_profile_stig"]
    assert status["native_scanner"]["profile_streams"] == {
        "xccdf_org.ssgproject.content_profile_stig": "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml"
    }
    assert status["native_scanner"]["sample_rules"] == [
        "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
    ]
    assert "catalog" not in status


def test_opensuse_uses_only_its_own_scap_stream() -> None:
    opensuse_stream = "/usr/share/xml/scap/ssg/content/ssg-opensuse-ds.xml"
    sle_stream = "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml"
    inventory = Inventory(
        target="opensuse",
        collected_at="2026-08-11T10:00:00+00:00",
        platform=Platform("suse", "opensuse-leap", "15.6", "openSUSE Leap 15.6"),
        sections={
            "compliance": (
                "TOOL:oscap=/usr/bin/oscap\n"
                f"DATASTREAM:{opensuse_stream}|360|1\n"
                f"PROFILE:{opensuse_stream}|xccdf_org.ssgproject.content_profile_standard\n"
                f"SCAP_RULE:{opensuse_stream}|xccdf_org.ssgproject.content_rule_opensuse_rule\n"
                f"DATASTREAM:{sle_stream}|920|2\n"
                f"PROFILE:{sle_stream}|xccdf_org.ssgproject.content_profile_stig\n"
                f"SCAP_RULE:{sle_stream}|xccdf_org.ssgproject.content_rule_sles_rule"
            )
        },
    )

    scanner = guideline_status(inventory)["native_scanner"]

    assert scanner["data_streams"] == [
        {"path": opensuse_stream, "rules": 360, "profiles": 1}
    ]
    assert scanner["profiles"] == ["xccdf_org.ssgproject.content_profile_standard"]
    assert scanner["sample_rules"] == ["xccdf_org.ssgproject.content_rule_opensuse_rule"]
    assert scanner["profile_streams"] == {
        "xccdf_org.ssgproject.content_profile_standard": opensuse_stream
    }


def test_missing_native_scanner_is_not_reported_as_complete() -> None:
    inventory = Inventory(
        target="debian",
        collected_at="2026-08-11T10:00:00+00:00",
        platform=Platform("debian", "debian", "13", "Debian GNU/Linux 13"),
        sections={},
    )

    status = guideline_status(inventory)

    assert status["native_scanner"]["ready"] is False
    assert "OpenSCAP" in status["recommendation"]


def test_scanner_without_policy_content_is_not_ready() -> None:
    inventory = Inventory(
        target="debian",
        collected_at="2026-08-11T10:00:00+00:00",
        platform=Platform("debian", "debian", "13", "Debian GNU/Linux 13"),
        sections={"compliance": "TOOL:oscap=/usr/bin/oscap"},
    )

    scanner = guideline_status(inventory)["native_scanner"]

    assert scanner["tool_ready"] is True
    assert scanner["content_ready"] is False
    assert scanner["ready"] is False


def test_debian13_never_falls_back_to_debian12_content() -> None:
    old_stream = "/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml"
    inventory = Inventory(
        target="debian13",
        collected_at="2026-08-11T10:00:00+00:00",
        platform=Platform("debian", "debian", "13", "Debian GNU/Linux 13"),
        sections={
            "compliance": (
                "TOOL:oscap=/usr/bin/oscap\n"
                f"DATASTREAM:{old_stream}|101|1\n"
                f"PROFILE:{old_stream}|xccdf_org.ssgproject.content_profile_standard\n"
                f"SCAP_RULE:{old_stream}|xccdf_org.ssgproject.content_rule_old"
            )
        },
    )

    status = guideline_status(inventory)
    scanner = status["native_scanner"]

    assert scanner["ready"] is False
    assert scanner["data_streams"] == []
    assert scanner["expected_stream"] == "ssg-debian13-ds.xml"
    assert scanner["available_data_streams"][0]["path"] == old_stream
    assert "Ältere Debian-Datenströme" in status["compatibility_message"]


def test_debian13_accepts_exact_official_content_from_usr_local() -> None:
    stream = "/usr/local/share/xml/scap/ssg/content/ssg-debian13-ds.xml"
    inventory = Inventory(
        target="debian13",
        collected_at="2026-08-11T10:00:00+00:00",
        platform=Platform("debian", "debian", "13", "Debian GNU/Linux 13"),
        sections={
            "compliance": (
                "TOOL:oscap=/usr/bin/oscap\n"
                f"DATASTREAM:{stream}|400|2\n"
                f"PROFILE:{stream}|xccdf_org.ssgproject.content_profile_anssi_bp28_minimal\n"
                f"SCAP_RULE:{stream}|xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
            )
        },
    )

    scanner = guideline_status(inventory)["native_scanner"]

    assert scanner["ready"] is True
    assert scanner["exact_stream_match"] is True
    assert scanner["data_streams"][0]["path"] == stream


def test_scanner_install_plans_are_distribution_specific() -> None:
    assert scanner_install_plan("opensuse-leap")["packages"] == [
        "openscap-utils",
        "scap-security-guide",
    ]
    assert scanner_install_plan("debian")["packages"] == [
        "openscap-scanner",
        "ssg-debian",
    ]
    assert scanner_install_plan("rhel")["packages"] == [
        "openscap-scanner",
        "scap-security-guide",
    ]
    assert scanner_install_plan("unknown") is None


def test_scanner_install_requires_noninteractive_privilege(monkeypatch) -> None:
    class FakeTransport:
        def __init__(self, _target):
            pass

        def run_script(self, script, timeout):
            assert "zypper --non-interactive install" in script
            assert timeout == 600
            return CommandResult(77, "@@LHA_PRIVILEGE_REQUIRED@@\n", "")

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    result = install_scanner(Target(name="suse", local=True), "opensuse-leap")

    assert result["status"] == "privilege_required"
    assert result["command"].startswith("sudo zypper")


def test_scanner_install_reports_success(monkeypatch) -> None:
    class FakeTransport:
        def __init__(self, _target):
            pass

        def run_script(self, _script, timeout):
            assert timeout == 600
            return CommandResult(0, "@@LHA_SCANNER_READY@@/usr/bin/oscap\n", "")

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)

    assert install_scanner(Target(name="debian", local=True), "debian")["status"] == "installed"
    with pytest.raises(ValueError, match="Keine sichere"):
        install_scanner(Target(name="unknown", local=True), "unknown")


def test_debian13_scanner_install_adds_official_versioned_content(monkeypatch) -> None:
    class FakeTransport:
        def __init__(self, _target):
            pass

        def run_script(self, _script, timeout):
            assert timeout == 600
            return CommandResult(0, "@@LHA_SCANNER_READY@@/usr/bin/oscap\n", "")

    calls = []
    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    monkeypatch.setattr(
        guidelines,
        "install_official_datastream",
        lambda _target, product: calls.append(product)
        or {"status": "installed", "path": "/usr/local/share/ssg-debian13-ds.xml"},
    )

    result = install_scanner(Target(name="debian", local=True), "debian", "13.1")

    assert result["status"] == "installed"
    assert calls == ["debian13"]
    assert result["official_content"]["status"] == "installed"


def test_scap_scan_parses_profile_results(monkeypatch) -> None:
    class FakeTransport:
        def __init__(self, _target):
            pass

        def run_script(self, script, timeout):
            assert "oscap xccdf eval --profile" in script
            assert "xccdf_org.ssgproject.content_profile_standard" in script
            assert timeout == 900
            return CommandResult(
                0,
                "@@LHA_SCAP_RC@@2\n"
                "xccdf_org.ssgproject.content_rule_sshd_disable_root_login:fail\n"
                "xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space:pass\n",
                "",
            )

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    scan = run_scap_scan(
        Target(name="suse", local=True),
        "xccdf_org.ssgproject.content_profile_standard",
        "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml",
    )

    assert scan["status"] == "completed"
    assert scan["counts"] == {"fail": 1, "pass": 1}
    assert scan["results"][0]["short_id"] == "sshd_disable_root_login"
    assert scan["results"][0]["topic"] == "ssh"
    assert scan["results"][1]["topic"] == "kernel"


def test_scap_scan_parses_xccdf_result_markers(monkeypatch) -> None:
    class FakeTransport:
        def __init__(self, _target):
            pass

        def run_script(self, script, timeout):
            assert '--results "$lha_results"' in script
            assert "rule-result" in script
            assert timeout == 900
            return CommandResult(
                0,
                "@@LHA_SCAP_RC@@2\n"
                "@@LHA_RESULT@@xccdf_org.ssgproject.content_rule_sshd_disable_root_login|fail\n"
                "@@LHA_RESULT@@xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space|pass\n",
                "",
            )

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    scan = run_scap_scan(
        Target(name="opensuse", local=True),
        "xccdf_org.ssgproject.content_profile_standard",
        "/usr/share/xml/scap/ssg/content/ssg-opensuse-ds.xml",
    )

    assert scan["counts"] == {"fail": 1, "pass": 1}
    assert [item["short_id"] for item in scan["results"]] == [
        "sshd_disable_root_login",
        "sysctl_kernel_randomize_va_space",
    ]


def test_scap_scan_parses_compressed_xccdf_xml(monkeypatch) -> None:
    xml = b"""<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>"""
    payload = base64.b64encode(gzip.compress(xml)).decode()

    class FakeTransport:
        def __init__(self, _target):
            pass

        def run_script(self, script, timeout):
            assert "@@LHA_XCCDF_GZIP_BEGIN@@" in script
            assert timeout == 900
            return CommandResult(
                0,
                "@@LHA_SCAP_RC@@2\n"
                f"@@LHA_XCCDF_GZIP_BEGIN@@\n{payload}\n@@LHA_XCCDF_GZIP_END@@\n",
                "",
            )

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    scan = run_scap_scan(
        Target(name="opensuse", local=True),
        "xccdf_org.ssgproject.content_profile_standard",
        "/usr/share/xml/scap/ssg/content/ssg-opensuse-ds.xml",
    )

    assert scan["counts"] == {"fail": 1, "pass": 1}
    assert scan["results"][0]["topic"] == "ssh"


def test_scap_scan_can_evaluate_selected_rules_outside_profile(monkeypatch) -> None:
    selected = "xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs"

    class FakeTransport:
        def __init__(self, _target):
            pass

        def run_script(self, script, timeout):
            command = next(line for line in script.splitlines() if "oscap xccdf eval" in line)
            assert "--tailoring-file" in command
            assert "xccdf_org.hardeningagent.content_profile_selected" in command
            assert "--rule" not in command
            assert "base64 -d" in script
            payload = re.search(r"printf '%s' ([A-Za-z0-9+/=]+) \| base64 -d", script)
            assert payload
            tailoring = base64.b64decode(payload.group(1)).decode()
            assert f'idref="{selected}" selected="true"' in tailoring
            assert 'extends="xccdf_org.ssgproject.content_profile_standard"' in tailoring
            assert re.search(r'<xccdf:version time="[^"]+">1</xccdf:version>', tailoring)
            assert timeout == 900
            return CommandResult(
                0,
                f"@@LHA_SCAP_RC@@2\n@@LHA_RESULT@@{selected}|fail\n",
                "",
            )

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    scan = run_scap_scan(
        Target(name="opensuse", local=True),
        "xccdf_org.ssgproject.content_profile_standard",
        "/usr/share/xml/scap/ssg/content/ssg-opensuse-ds.xml",
        rule_ids=[selected],
    )

    assert scan["counts"] == {"fail": 1}
    assert scan["results"][0]["id"] == selected


def test_full_benchmark_tailoring_does_not_extend_standard(monkeypatch) -> None:
    group = "xccdf_org.ssgproject.content_group_system"
    rules = [
        "xccdf_org.ssgproject.content_rule_rule_one",
        "xccdf_org.ssgproject.content_rule_rule_two",
    ]

    class FakeTransport:
        def __init__(self, _target):
            pass

        def run_script(self, script, timeout):
            assert timeout == 900
            payload = re.search(r"printf '%s' ([A-Za-z0-9+/=]+) \| base64 -d", script)
            assert payload
            tailoring = base64.b64decode(payload.group(1)).decode()
            assert 'id="xccdf_org.hardeningagent.content_profile_full_benchmark"' in tailoring
            assert "extends=" not in tailoring
            assert f'idref="{group}" selected="true"' in tailoring
            assert all(f'idref="{rule}" selected="true"' in tailoring for rule in rules)
            return CommandResult(
                0,
                "@@LHA_SCAP_RC@@2\n"
                + "\n".join(f"@@LHA_RESULT@@{rule}|fail" for rule in rules)
                + "\n",
                "",
            )

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    scan = run_scap_scan(
        Target(name="opensuse", local=True),
        guidelines.FULL_BENCHMARK_PROFILE,
        "/usr/share/xml/scap/ssg/content/ssg-opensuse-ds.xml",
        rule_ids=[group, *rules],
        replace_profile=True,
    )

    assert scan["profile"] == guidelines.FULL_BENCHMARK_PROFILE
    assert scan["counts"] == {"fail": 2}


def test_scap_scan_uses_real_rule_titles_from_standard_output(monkeypatch) -> None:
    class FakeTransport:
        def __init__(self, _target):
            pass

        def run_script(self, _script, timeout):
            assert timeout == 900
            return CommandResult(
                0,
                "@@LHA_SCAP_RC@@2\n"
                "Title   Disable SSH Root Login\n"
                "Rule    xccdf_org.ssgproject.content_rule_sshd_disable_root_login\n"
                "Result  fail\n",
                "",
            )

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    scan = run_scap_scan(
        Target(name="suse", local=True),
        "xccdf_org.ssgproject.content_profile_standard",
        "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml",
    )

    assert scan["results"][0]["title"] == "Disable SSH Root Login"
    assert scan["results"][0]["status"] == "fail"


def test_scap_scan_returns_manual_command_when_privilege_is_required(monkeypatch) -> None:
    class FakeTransport:
        def __init__(self, _target):
            pass

        def run_script(self, _script, timeout):
            assert timeout == 900
            return CommandResult(77, "@@LHA_PRIVILEGE_REQUIRED@@\n", "")

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    result = run_scap_scan(
        Target(name="debian", local=True),
        "xccdf_org.ssgproject.content_profile_standard",
        "/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml",
    )

    assert result["status"] == "privilege_required"
    assert result["command"].startswith("sudo oscap xccdf eval --profile")


def test_scap_scan_rejects_uninventoried_shapes() -> None:
    target = Target(name="local", local=True)
    with pytest.raises(ValueError, match="Profil-ID"):
        run_scap_scan(target, "standard; id", "/usr/share/policy.xml")
    with pytest.raises(ValueError, match="Datenstrom"):
        run_scap_scan(
            target,
            "xccdf_org.ssgproject.content_profile_standard",
            "/tmp/policy.xml",
        )


def test_selected_scap_remediation_rescans_only_selected_rules(monkeypatch) -> None:
    selected = "xccdf_org.ssgproject.content_rule_gid_passwd_group_same"

    class FakeTransport:
        calls = 0

        def __init__(self, _target):
            pass

        def run_script(self, script, timeout):
            FakeTransport.calls += 1
            if FakeTransport.calls == 1:
                assert "grep -oE" in script
                assert timeout == 120
                return CommandResult(
                    0,
                    "xccdf_org.ssgproject.content_group_system\n"
                    f"{selected}\n",
                    "",
                )
            assert "--tailoring-file \"$lha_tailoring\"" in script
            assert "--profile xccdf_org.hardeningagent.content_profile_remediation" in script
            payload = re.search(r"printf '%s' ([A-Za-z0-9+/=]+) \| base64 -d", script)
            assert payload
            tailoring = base64.b64decode(payload.group(1)).decode()
            assert 'idref="xccdf_org.ssgproject.content_group_system" selected="true"' in tailoring
            assert f'idref="{selected}" selected="true"' in tailoring
            assert tailoring.count(f'idref="{selected}"') == 1
            assert re.search(r'<xccdf:version time="[^"]+">1</xccdf:version>', tailoring)
            if FakeTransport.calls == 2:
                assert "--results \"$lha_results\"" in script
                assert "generate fix" not in script
                assert timeout == 1800
                xml = (
                    '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
                    f'<rule-result idref="{selected}"><result>fail</result></rule-result>'
                    "</TestResult>"
                ).encode()
                encoded = base64.b64encode(gzip.compress(xml)).decode()
                return CommandResult(
                    0,
                    f"@@LHA_SELECTED_SCAN_RC@@2\n"
                    f"@@LHA_XCCDF_GZIP_BEGIN@@\n{encoded}\n@@LHA_XCCDF_GZIP_END@@\n",
                    "",
                )
            assert "generate fix --fix-type bash" in script
            assert "--result-id" not in script
            assert timeout == 600
            return CommandResult(
                0,
                "@@LHA_FIX_BEGIN@@\n#!/bin/bash\necho selected\n@@LHA_FIX_END@@\n",
                "",
            )

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    result = generate_selected_scap_remediation(
        Target(name="suse", local=True),
        "xccdf_org.ssgproject.content_profile_standard",
        "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml",
        [selected],
    )

    assert result["status"] == "generated"
    assert result["rules"] == [selected]
    assert "echo selected" in result["script"]


def test_selected_scap_remediation_accepts_complete_results_with_rc_one(monkeypatch) -> None:
    selected = "xccdf_org.ssgproject.content_rule_file_permissions"

    class FakeTransport:
        calls = 0

        def __init__(self, _target):
            pass

        def run_script(self, _script, timeout):
            FakeTransport.calls += 1
            if FakeTransport.calls == 1:
                return CommandResult(0, f"{selected}\n", "")
            if FakeTransport.calls == 2:
                xml = (
                    '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
                    f'<rule-result idref="{selected}"><result>fail</result></rule-result>'
                    "</TestResult>"
                ).encode()
                encoded = base64.b64encode(gzip.compress(xml)).decode()
                return CommandResult(
                    0,
                    "@@LHA_SELECTED_SCAN_RC@@1\nScanner warning\n"
                    f"@@LHA_XCCDF_GZIP_BEGIN@@\n{encoded}\n@@LHA_XCCDF_GZIP_END@@\n",
                    "",
                )
            return CommandResult(
                0,
                "@@LHA_FIX_BEGIN@@\n#!/bin/bash\necho fix\n@@LHA_FIX_END@@\n",
                "",
            )

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    result = generate_selected_scap_remediation(
        Target(name="suse", local=True),
        "xccdf_org.ssgproject.content_profile_standard",
        "/usr/share/xml/scap/ssg/content/ssg-opensuse-ds.xml",
        [selected],
    )

    assert result["status"] == "generated"
    assert "RC 1" in result["warnings"][0]


def test_scap_results_are_attached_to_guideline() -> None:
    guideline = {}
    scan = {
        "profile": "xccdf_org.ssgproject.content_profile_standard",
        "data_stream": "/usr/share/policy.xml",
        "counts": {"pass": 1},
        "results": [{"topic": "ssh", "status": "pass"}],
    }

    integrated = integrate_scap_coverage(guideline, scan)

    assert integrated["scap_scan"]["results"] == 1


def test_custom_guideline_source_is_versioned_enabled_and_persistent(monkeypatch, tmp_path) -> None:
    path = tmp_path / "sources.json"
    monkeypatch.setattr(guidelines, "custom_guidelines_path", lambda: path)
    raw = {
        "id": "opensuse.leap15.local",
        "publisher": "SUSE",
        "title": "Reviewed Leap source",
        "url": "https://documentation.suse.com/example",
        "distribution": "opensuse-leap",
        "version_pattern": "15.*",
        "scope": "Local reviewed mapping",
        "categories": ["ssh", "audit"],
        "reviewed": "2026-08-11",
        "enabled": True,
    }
    saved = save_guideline_source(raw)
    inventory = Inventory(
        target="leap",
        collected_at="2026-08-11T10:00:00+00:00",
        platform=Platform("suse", "opensuse-leap", "15.6", "openSUSE Leap 15.6"),
        sections={},
    )

    assert saved["custom"] is True
    assert any(item["id"] == raw["id"] for item in guideline_sources_for(inventory))
    assert any(item["id"] == raw["id"] for item in all_guideline_sources())

    raw["enabled"] = False
    save_guideline_source(raw, original_id=raw["id"])
    assert all(item["id"] != raw["id"] for item in guideline_sources_for(inventory))
    delete_guideline_source(raw["id"])
    assert all_guideline_sources()


def test_guideline_source_rejects_unsafe_url_and_version(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(guidelines, "custom_guidelines_path", lambda: tmp_path / "sources.json")
    raw = {
        "id": "vendor.source",
        "publisher": "Vendor",
        "title": "Guide",
        "url": "http://unsafe.example/guide",
        "distribution": "debian",
        "version_pattern": "13;rm",
        "scope": "Test",
        "categories": ["ssh"],
        "reviewed": "2026-08-11",
        "enabled": True,
    }
    with pytest.raises(ValueError, match="Versionsmuster"):
        save_guideline_source(raw)
    raw["version_pattern"] = "13.*"
    with pytest.raises(ValueError, match="HTTPS"):
        save_guideline_source(raw)


def test_guideline_source_allows_no_manual_categories(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(guidelines, "custom_guidelines_path", lambda: tmp_path / "sources.json")
    saved = save_guideline_source(
        {
            "id": "debian.13.security",
            "publisher": "Debian",
            "title": "Debian Security Documentation",
            "url": "https://www.debian.org/security/",
            "distribution": "debian",
            "version_pattern": "13",
            "scope": "Official source mapping",
            "categories": [],
            "reviewed": "2026-08-11",
            "enabled": True,
        }
    )

    assert saved["categories"] == []


def test_online_guideline_discovery_keeps_only_allowlisted_https(monkeypatch) -> None:
    page = b"""
    <a class="result__a" href="https://documentation.suse.com/sles/16.0/html/SLES-openscap/">SUSE 16 OpenSCAP</a>
    <a class="result__a" href="/l/?uddg=https%3A%2F%2Fdocumentation.suse.com%2Fsles%2F16.0%2Fhtml%2FSLES-security%2F">SUSE 16 Security</a>
    <a class="result__a" href="https://evil.example/fake-guide">Fake guide</a>
    <a class="result__a" href="http://documentation.suse.com/insecure">Insecure guide</a>
    """

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return page

    monkeypatch.setattr(guidelines, "urlopen", lambda _request, timeout: FakeResponse())
    result = discover_official_guidelines("sles", "16.0")

    assert result["allowed_domains"] == ["documentation.suse.com"]
    assert result["candidates"] == [
        {
            "title": "SUSE 16 OpenSCAP",
            "url": "https://documentation.suse.com/sles/16.0/html/SLES-openscap/",
            "domain": "documentation.suse.com",
        },
        {
            "title": "SUSE 16 Security",
            "url": "https://documentation.suse.com/sles/16.0/html/SLES-security/",
            "domain": "documentation.suse.com",
        },
    ]


def test_online_guideline_discovery_requires_known_distribution() -> None:
    with pytest.raises(ValueError, match="Domainliste"):
        discover_official_guidelines("unknown-linux", "1")


def test_multi_platform_guideline_discovery_labels_candidates(monkeypatch) -> None:
    def fake_discovery(distribution, version, timeout):
        return {
            "candidates": [
                {
                    "title": f"{distribution} guide",
                    "url": f"https://example.invalid/{distribution}",
                    "domain": "example.invalid",
                }
            ],
            "warnings": [],
        }

    monkeypatch.setattr(guidelines, "discover_official_guidelines", fake_discovery)
    result = discover_guidelines_for_platforms([("sles", "16.0"), ("debian", "13")])

    assert result["candidates"][0]["distribution"] == "sles"
    assert result["candidates"][1]["version"] == "13"


def test_generate_scap_remediation_uses_inventoried_shapes(monkeypatch) -> None:
    class FakeTransport:
        def __init__(self, _target):
            pass

        def run_script(self, script, timeout):
            assert "oscap xccdf generate fix --fix-type bash" in script
            assert timeout == 300
            return CommandResult(0, "#!/bin/bash\necho hardened\n", "")

    monkeypatch.setattr(guidelines, "Transport", FakeTransport)
    script = generate_scap_remediation(
        Target(name="suse", local=True),
        "xccdf_org.ssgproject.content_profile_standard",
        "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml",
    )

    assert "echo hardened" in script
