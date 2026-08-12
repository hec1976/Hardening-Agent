import json
import re
from importlib.resources import files
from pathlib import Path

import pytest

from hardening_agent import webapp
from hardening_agent.config import load_targets, save_target
from hardening_agent.models import Target
from hardening_agent.transport import CommandResult


def test_gui_assets_are_packaged() -> None:
    web = files("hardening_agent").joinpath("web")
    assert "Linux Hardening Agent" in web.joinpath("index.html").read_text(encoding="utf-8")
    assert web.joinpath("app.js").read_text(encoding="utf-8")
    assert web.joinpath("style.css").read_text(encoding="utf-8")


def test_selected_bundle_can_be_staged_in_private_target_tmp(monkeypatch, tmp_path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for name in (
        "apply-native-policy.sh",
        "verify-native-policy.sh",
        "restore-native-policy.sh",
        "policy.json",
    ):
        (bundle / name).write_text(name, encoding="utf-8")
    uploads = []
    commands = []

    class FakeTransport:
        def __init__(self, target):
            assert target.name == "suse"

        def put_file(self, source, destination):
            uploads.append((source.name, destination))

        def run_script(self, script, timeout):
            commands.append(script)
            assert timeout == 120
            return CommandResult(0, "", "")

    monkeypatch.setattr(webapp, "Transport", FakeTransport)
    staged = webapp._stage_native_policy_bundle(Target(name="suse", local=True), bundle)

    assert re.fullmatch(r"/tmp/hardening-agent-[a-f0-9]{12}", staged["directory"])
    assert {name for name, _ in uploads} == {
        "apply-native-policy.sh",
        "verify-native-policy.sh",
        "restore-native-policy.sh",
        "policy.json",
    }
    assert all(path.startswith("/tmp/hardening-agent-") for _, path in uploads)
    assert "mkdir -m 700" in commands[0]
    assert staged["apply_command"].startswith("sudo /tmp/hardening-agent-")
    assert staged["verify_command"].startswith("sudo /tmp/hardening-agent-")
    assert staged["restore_command"].startswith("sudo /tmp/hardening-agent-")


def test_full_scan_keeps_results_when_some_rules_remain_unassessed() -> None:
    selected = "xccdf_org.ssgproject.content_rule_selected"
    blocked = "xccdf_org.ssgproject.content_rule_blocked"
    merged, evaluated, unassessed = webapp._merge_requested_scap_results(
        [
            {"id": selected, "status": "notselected"},
            {"id": blocked, "status": "notselected"},
        ],
        [
            {"id": selected, "status": "fail"},
            {"id": blocked, "status": "notselected"},
        ],
        [selected, blocked],
    )

    statuses = {item["id"]: item["status"] for item in merged}
    assert statuses == {selected: "fail", blocked: "notselected"}
    assert evaluated == 1
    assert unassessed == [blocked]


def test_status_exposes_installed_version(monkeypatch) -> None:
    monkeypatch.setattr(webapp.OllamaAdvisor, "health", lambda _self: False)
    monkeypatch.setattr(webapp.shutil, "which", lambda _name: None)
    monkeypatch.setattr(webapp, "load_targets", dict)
    state = webapp.WebState(
        token="test",
        output_root=Path("/tmp"),
        model="qwen3:14b",
        ollama_url="http://127.0.0.1:11434",
        libvirt_uri="qemu:///system",
        bind_host="127.0.0.1",
    )

    assert webapp._status(state)["version"] == webapp.__version__


def test_ai_hardening_review_rejects_invented_and_duplicate_rules() -> None:
    allowed = "xccdf_org.ssgproject.content_rule_real"
    result = webapp._sanitize_hardening_review(
        {
            "summary": "Priorisierung",
            "profile_name": "Basis",
            "recommendations": [
                {
                    "rule_id": allowed,
                    "priority": "high",
                    "disposition": "recommend",
                    "reason": "Realer Fehlschlag",
                    "operational_impact": "Anmeldung prüfen",
                    "validation": "OpenSCAP erneut ausführen",
                },
                {"rule_id": allowed, "priority": "low", "disposition": "defer"},
                {
                    "rule_id": "xccdf_org.ssgproject.content_rule_invented",
                    "priority": "critical",
                    "disposition": "recommend",
                },
            ],
            "warnings": [],
        },
        [{"id": allowed, "title": "Real rule", "short_id": "real", "topic": "auth"}],
        "qwen3:8b",
    )

    assert [item["rule_id"] for item in result["recommendations"]] == [allowed]
    assert result["selected_rule_ids"] == [allowed]
    assert "keine KI-generierten Shell-Befehle" in result["guardrail"]


def test_ai_baseline_setup_reports_platform_and_mechanism_without_commands() -> None:
    result = webapp._sanitize_baseline_setup(
        {
            "summary": "Firewall aktivieren",
            "recommendation": "apply",
            "mechanism": "firewalld (firewall-cmd)",
            "settings": [
                {"name": "firewall_enabled", "value": "true", "reason": "Blockiert unerlaubten Zugriff"}
            ],
            "prerequisites": [],
            "operational_impact": "Zugriffe werden eingeschränkt",
            "validation_steps": ["Firewallstatus prüfen"],
            "rollback_steps": ["Firewall deaktivieren"],
            "warnings": [],
        },
        {
            "id": "GLB-FW-001",
            "title": "Firewall aktivieren",
            "status": "manual",
            "failed_rule_ids": [],
        },
        "qwen3:8b",
        {"pretty_name": "openSUSE Leap 15.6", "distribution": "opensuse-leap", "version": "15.6"},
    )

    assert result["platform"] == "openSUSE Leap 15.6"
    assert result["mechanism"] == "firewalld (firewall-cmd)"
    assert "--" not in result["mechanism"]
    assert result["implementation_mode"] == "operator_review"


def test_ai_baseline_setup_uses_only_deterministic_failed_rules() -> None:
    real_rule = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
    result = webapp._sanitize_baseline_setup(
        {
            "summary": "Root-Anmeldung deaktivieren",
            "recommendation": "apply",
            "settings": [
                {"name": "PermitRootLogin", "value": "no", "reason": "Nachvollziehbarkeit"}
            ],
            "prerequisites": ["Administratives Benutzerkonto testen"],
            "operational_impact": "Direkte Root-Anmeldung entfällt",
            "validation_steps": ["OpenSCAP erneut prüfen"],
            "rollback_steps": ["Vorherige Konfiguration wiederherstellen"],
            "warnings": [],
            "rule_ids": ["invented-by-model"],
        },
        {
            "id": "GLB-SSH-001",
            "title": "SSH-Root-Login deaktivieren",
            "status": "fail",
            "failed_rule_ids": [real_rule],
        },
        "qwen3:8b",
    )

    assert result["implementation_mode"] == "openscap"
    assert result["rule_ids"] == [real_rule]
    assert "ohne Shell-Befehle" in result["guardrail"]


def test_status_selects_installed_8b_model_when_default_is_missing(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(webapp.OllamaAdvisor, "health", lambda _self: True)
    monkeypatch.setattr(
        webapp.OllamaAdvisor,
        "models",
        lambda _self: [{"name": "qwen3:8b", "size": 5_000_000_000}],
    )
    monkeypatch.setattr(webapp.shutil, "which", lambda _name: None)
    monkeypatch.setattr(webapp, "load_targets", dict)
    state = webapp.WebState(
        token="test",
        output_root=tmp_path,
        model="qwen3:14b",
        ollama_url="http://127.0.0.1:11434",
        libvirt_uri="qemu:///system",
        bind_host="127.0.0.1",
    )

    payload = webapp._status(state)

    assert payload["ollama"]["model"] == "qwen3:8b"
    assert payload["ollama"]["state"] == "ready"


def test_javascript_element_ids_exist_in_html() -> None:
    web = files("hardening_agent").joinpath("web")
    html = web.joinpath("index.html").read_text(encoding="utf-8")
    javascript = web.joinpath("app.js").read_text(encoding="utf-8")
    referenced = set(re.findall(r"getElementById\(['\"]([^'\"]+)", javascript))
    available = set(re.findall(r'id="([^"]+)"', html))
    assert referenced <= available


def test_gui_uses_independent_full_benchmark_workflow() -> None:
    web = files("hardening_agent").joinpath("web")
    html = web.joinpath("index.html").read_text(encoding="utf-8")
    javascript = web.joinpath("app.js").read_text(encoding="utf-8")

    assert "Hersteller-Benchmark" in html
    assert "Separate Einordnung nach ANSSI, BSI und NIST" in html
    assert "alle Regeln des XCCDF-Datenstroms" in html
    assert "scap_profile:" not in javascript
    assert 'id="full-scan"' in html
    assert "Hardening-Profil speichern" in javascript
    assert "Ausgewählte Zusatzregeln prüfen" not in javascript
    assert "/api/full-scan" in javascript
    assert "/api/compliance/selected-remediation" in javascript
    assert "/api/compliance/report-package" in javascript
    assert "/api/catalog" not in javascript
    assert "Agent-Kontrollen" not in html + javascript
    assert "/api/compliance/ai-prioritize" in javascript
    assert "KI-Vorschlag auswählen" in javascript
    assert "/api/general-baseline" in javascript
    assert "/api/general-baseline/setup" in javascript
    assert "/api/general-baseline/plan" in javascript
    assert "/api/general-baseline/package" in javascript
    assert "Allgemeines Linux-Hardening" in javascript
    assert "Hardening-Paket in 3 Schritten" in javascript
    assert "Paket herunterladen" in javascript
    assert "KI-Setup erstellen" in javascript
    assert 'id="general-hardening-summary"' in html
    assert "OFFIZIELLER HERSTELLER-BENCHMARK" in javascript
    assert "Benchmark-Bericht herunterladen" in javascript
    assert "Läuft" in javascript
    assert "Nicht erkannt" in javascript


def test_scanner_installation_finishes_before_inventory_refresh() -> None:
    web = files("hardening_agent").joinpath("web")
    javascript = web.joinpath("app.js").read_text(encoding="utf-8")

    assert "erfolgreich installiert" in javascript
    assert "Installation abgeschlossen; SCAP-Datenströme werden jetzt neu eingelesen" in javascript
    assert "window.setTimeout(() => loadApplicableControls(), 0)" in javascript
    assert "finally { button.disabled = false; }" in javascript


def test_report_view_exposes_configuration_and_guideline_sources() -> None:
    web = files("hardening_agent").joinpath("web")
    html = web.joinpath("index.html").read_text(encoding="utf-8")
    javascript = web.joinpath("app.js").read_text(encoding="utf-8")

    assert 'id="report"' in html
    assert 'id="report-summary"' in html
    assert "Systemkonfiguration und Referenzen" in html
    assert "Prüfbericht herunterladen" in javascript
    assert "/api/compliance/report-package" in javascript
    backend = Path(webapp.__file__).read_text(encoding="utf-8")
    assert "manufacturer-benchmark-report.html" in backend
    assert "general-linux-hardening-report.json" in backend
    for filter_id in (
        "report-kind",
        "report-status",
        "report-category",
        "report-source",
        "report-selection",
        "report-reset",
    ):
        assert f'id="{filter_id}"' in html
    assert "Allgemeines Linux-Hardening" in javascript
    assert "Keine Berichtseinträge entsprechen den gewählten Filtern" in javascript


def test_full_scan_exposes_readable_filterable_vulnerability_results() -> None:
    web = files("hardening_agent").joinpath("web")
    javascript = web.joinpath("app.js").read_text(encoding="utf-8")
    css = web.joinpath("style.css").read_text(encoding="utf-8")

    assert "OVAL-Schwachstellenresultate" in javascript
    assert "Nur betroffen" in javascript
    assert "Offiziellen OVAL-Feed öffnen" in javascript
    assert ".vulnerability-result-list" in css
    assert ".full-scan-panel .scan-scope strong" in css


def test_gui_refuses_root_by_default(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(webapp.os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="Refusing to run the GUI as root"):
        webapp.serve_gui(output_root=tmp_path, open_browser=False)


def test_host_name_supports_ipv4_and_ipv6() -> None:
    assert webapp._host_name("127.0.0.1:8765") == "127.0.0.1"
    assert webapp._host_name("[::1]:8765") == "::1"


def test_vms_are_optional_when_virsh_is_missing(monkeypatch) -> None:
    monkeypatch.setattr(webapp.shutil, "which", lambda _name: None)
    payload = webapp._vms_payload("qemu:///system")
    assert payload["vms"] == []
    assert "KVM ist optional" in payload["warnings"][0]


def test_native_policy_bundle_requires_confirmation_and_contains_verification(tmp_path) -> None:
    directory = webapp._write_native_policy_bundle(
        tmp_path,
        Target(name="suse-test", local=True),
        {
            "family": "suse",
            "distribution": "opensuse-leap",
            "version": "15.6",
            "pretty_name": "openSUSE Leap 15.6",
        },
        "xccdf_org.ssgproject.content_profile_standard",
        "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml",
        {"counts": {"fail": 3}},
        "#!/bin/bash\necho apply-full-profile\n",
        [],
        baseline_report={"target": "suse-test", "baseline": "general-linux"},
    )

    apply_script = (directory / "apply-native-policy.sh").read_text(encoding="utf-8")
    verify_script = (directory / "verify-native-policy.sh").read_text(encoding="utf-8")
    restore_script = (directory / "restore-native-policy.sh").read_text(encoding="utf-8")
    assert "APPLY standard" in apply_script
    assert "echo apply-full-profile" in apply_script
    assert "last-backup-path" in apply_script
    assert "oscap xccdf eval --progress" in verify_script
    assert "last-backup-path" in restore_script
    assert (directory / "SHA256SUMS").is_file()
    assert (directory / "general-linux-baseline.json").is_file()
    assert (directory / "backup-paths.txt").is_file()


def test_backup_paths_only_collect_safe_static_configuration_paths() -> None:
    paths = webapp._backup_paths_from_fix(
        "sed -i x /etc/ssh/sshd_config\n"
        "touch /etc/sysctl.d/99-hardening.conf\n"
        "rm -rf /var/lib/important\n"
    )

    assert paths == ["/etc/ssh/sshd_config", "/etc/sysctl.d/99-hardening.conf"]


def test_zip_bundle_keeps_directory_prefix(tmp_path) -> None:
    bundle = tmp_path / "guest-run"
    bundle.mkdir()
    bundle.joinpath("plan.json").write_text("{}\n", encoding="utf-8")
    archive = webapp._zip_bundle(bundle)
    assert archive.is_file()

    import zipfile

    with zipfile.ZipFile(archive) as opened:
        assert opened.namelist() == ["guest-run/plan.json"]


def test_policy_selection_accepts_only_failed_rules_from_latest_scan(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LHA_HOME", str(tmp_path))
    reports = tmp_path / "reports"
    reports.mkdir()
    reports.joinpath("suse-openscap.json").write_text(
        json.dumps(
            {
                "profile": "xccdf_org.ssgproject.content_profile_standard",
                "data_stream": "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml",
                "results": [
                    {"id": "xccdf_org.ssgproject.content_rule_failed", "status": "fail"},
                    {"id": "xccdf_org.ssgproject.content_rule_passed", "status": "pass"},
                ],
            }
        ),
        encoding="utf-8",
    )

    _report, selected = webapp._validated_policy_selection(
        "suse",
        "xccdf_org.ssgproject.content_profile_standard",
        "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml",
        ["xccdf_org.ssgproject.content_rule_failed"],
    )
    assert selected[0]["status"] == "fail"
    with pytest.raises(ValueError, match="Nur aktuell fehlgeschlagene"):
        webapp._validated_policy_selection(
            "suse",
            "xccdf_org.ssgproject.content_profile_standard",
            "/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml",
            ["xccdf_org.ssgproject.content_rule_passed"],
        )


def test_current_target_persists_refreshed_vagrant_connection(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LHA_HOME", str(tmp_path))
    stale = Target(
        name="opensuse",
        host="192.168.121.10",
        user="vagrant",
        vm_name="opensuse15_default",
    )
    refreshed = Target(
        name="opensuse",
        host="192.168.121.10",
        user="vagrant",
        identity_file="/tmp/vagrant-private-key",
        vm_name="opensuse15_default",
    )
    save_target(stale)
    monkeypatch.setattr(webapp, "refresh_vagrant_target", lambda _target: refreshed)

    target, changed = webapp._current_target("opensuse")

    assert changed is True
    assert target == refreshed
    assert load_targets()["opensuse"] == refreshed
