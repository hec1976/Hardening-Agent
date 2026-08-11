from hardening_agent.baseline import (
    BASELINE_CATEGORIES,
    BASELINE_SOURCES,
    SYSTEM_ROLES,
    build_baseline_hardening_plan,
    evaluate_general_linux_baseline,
)


def _report(results):
    return {
        "target": "suse-test",
        "generated_at": "2026-08-11T12:00:00+00:00",
        "platform": {"distribution": "opensuse-leap", "version": "15.6"},
        "data_stream": "/usr/share/xml/scap/ssg/content/ssg-opensuse-ds.xml",
        "results": results,
    }


def test_general_baseline_maps_real_scap_results_and_keeps_manual_controls() -> None:
    baseline = evaluate_general_linux_baseline(
        _report(
            [
                {
                    "id": "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
                    "short_id": "sshd_disable_root_login",
                    "title": "Disable SSH root login",
                    "status": "fail",
                },
                {
                    "id": "xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space",
                    "short_id": "sysctl_kernel_randomize_va_space",
                    "title": "Enable ASLR",
                    "status": "pass",
                },
            ]
        ),
        "basic",
    )

    controls = {item["id"]: item for item in baseline["controls"]}
    assert controls["GLB-SSH-001"]["status"] == "fail"
    assert controls["GLB-KRN-001"]["status"] == "pass"
    assert controls["GLB-OPS-001"]["status"] == "manual"
    assert (
        "xccdf_org.ssgproject.content_rule_sshd_disable_root_login" in baseline["selected_rule_ids"]
    )


def test_general_baseline_levels_and_categories_are_selective() -> None:
    basic = evaluate_general_linux_baseline(_report([]), "basic", ["ssh"])
    critical = evaluate_general_linux_baseline(_report([]), "critical", ["ssh", "crypto"])

    assert basic["enabled_categories"] == ["ssh"]
    assert all(item["category"] == "ssh" for item in basic["controls"])
    assert len(critical["controls"]) > len(basic["controls"])
    assert any(item["level"] == "critical" for item in critical["controls"])


def test_general_baseline_allows_intentionally_empty_category_selection() -> None:
    baseline = evaluate_general_linux_baseline(_report([]), "basic", [])

    assert baseline["enabled_categories"] == []
    assert baseline["controls"] == []


def test_general_baseline_exposes_only_official_https_sources() -> None:
    assert set(BASELINE_SOURCES) == {"anssi", "bsi", "nist"}
    assert all(source["url"].startswith("https://") for source in BASELINE_SOURCES.values())
    assert "operations" in BASELINE_CATEGORIES


def test_baseline_plan_combines_failed_rules_and_keeps_manual_work_visible() -> None:
    baseline = evaluate_general_linux_baseline(
        _report(
            [
                {
                    "id": "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
                    "short_id": "sshd_disable_root_login",
                    "title": "Disable SSH root login",
                    "status": "fail",
                }
            ]
        ),
        "basic",
    )

    plan = build_baseline_hardening_plan(baseline, "mail-server", ["GLB-SSH-001", "GLB-OPS-001"])

    assert plan["status"] == "review_required"
    assert plan["rule_ids"] == ["xccdf_org.ssgproject.content_rule_sshd_disable_root_login"]
    assert [item["id"] for item in plan["manual_controls"]] == ["GLB-OPS-001"]
    assert plan["counts"]["actionable_rules"] == 1


def test_baseline_plan_blocks_opposite_rule_pairs() -> None:
    baseline = {
        "target": "suse-test",
        "platform": {},
        "data_stream": "/tmp/ssg.xml",
        "controls": [
            {
                "id": "A",
                "title": "Enable demo",
                "category": "services",
                "status": "fail",
                "failed_rule_ids": ["xccdf_org.ssgproject.content_rule_service_demo_enabled"],
            },
            {
                "id": "B",
                "title": "Disable demo",
                "category": "services",
                "status": "fail",
                "failed_rule_ids": ["xccdf_org.ssgproject.content_rule_service_demo_disabled"],
            },
        ],
    }

    plan = build_baseline_hardening_plan(baseline, "general-server", ["A", "B"])

    assert plan["status"] == "blocked"
    assert plan["conflicts"][0]["severity"] == "blocking"


def test_baseline_offers_clear_system_roles() -> None:
    assert {"general-server", "mail-server", "virtualization-host"} <= set(SYSTEM_ROLES)
