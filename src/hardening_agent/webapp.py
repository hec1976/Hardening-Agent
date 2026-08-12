from __future__ import annotations

import hashlib
import html
import json
import mimetypes
import os
import re
import secrets
import shlex
import shutil
import subprocess
import threading
import webbrowser
import zipfile
from collections import Counter
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from . import __version__
from .advisor import AdvisorError, OllamaAdvisor
from .baseline import build_baseline_hardening_plan, evaluate_general_linux_baseline
from .config import (
    data_home,
    delete_target,
    get_target,
    load_policy_profiles,
    load_targets,
    save_inventory,
    save_policy_profiles,
    save_target,
)
from .guidelines import (
    FULL_BENCHMARK_PROFILE,
    TOPICS,
    all_guideline_sources,
    delete_guideline_source,
    discover_guidelines_for_platforms,
    discover_official_guidelines,
    discover_scap_selectable_ids,
    generate_scap_remediation,
    generate_selected_scap_remediation,
    guideline_status,
    install_scanner,
    integrate_scap_coverage,
    run_scap_scan,
    save_guideline_source,
)
from .inventory import collect_inventory
from .libvirt import list_vms, refresh_vagrant_target, vagrant_ssh_config
from .models import Target
from .transport import Transport, TransportError
from .vulnerabilities import run_vulnerability_scan

MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
POLICY_PROFILE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")


def _current_target(name: str) -> tuple[Target, bool]:
    target = get_target(name)
    refreshed = refresh_vagrant_target(target)
    changed = refreshed != target
    if changed:
        save_target(refreshed, original_name=target.name)
    return refreshed, changed


@dataclass
class WebState:
    token: str
    output_root: Path
    model: str
    ollama_url: str
    libvirt_uri: str
    bind_host: str
    downloads: dict[str, Path] = field(default_factory=dict)
    recommendation_jobs: dict[str, dict[str, Any]] = field(default_factory=dict)
    scan_jobs: dict[str, dict[str, Any]] = field(default_factory=dict)
    ai_state: str = "ready"
    ai_message: str = "Bereit für eine Analyse"
    lock: threading.Lock = field(default_factory=threading.Lock)


def _full_scan_progress(state: WebState, job_id: str, stage: str, percent: int) -> None:
    with state.lock:
        current = state.scan_jobs.get(job_id, {})
        state.scan_jobs[job_id] = {
            **current,
            "status": "running",
            "stage": stage,
            "percent": percent,
        }


def _merge_requested_scap_results(
    current_results: list[dict[str, Any]],
    supplemental_results: list[dict[str, Any]],
    requested_ids: list[str],
) -> tuple[list[dict[str, Any]], int, list[str]]:
    """Merge every returned result and report rules OpenSCAP could not assess."""
    merged = {str(item.get("id")): item for item in current_results if item.get("id")}
    returned = {str(item.get("id")): item for item in supplemental_results if item.get("id")}
    evaluated = 0
    unassessed: list[str] = []
    for rule_id in requested_ids:
        result = returned.get(rule_id)
        if result is not None:
            merged[rule_id] = result
        status = result.get("status") if result else None
        if status in {None, "notselected", "notchecked"}:
            unassessed.append(rule_id)
        else:
            evaluated += 1
    return list(merged.values()), evaluated, unassessed


def _run_full_scan_job(
    state: WebState,
    job_id: str,
    target: Target,
    data_stream: str,
    include_configuration: bool,
    include_vulnerabilities: bool,
) -> None:
    engines: dict[str, Any] = {}
    warnings: list[str] = []
    try:
        _full_scan_progress(state, job_id, "Systeminventar erfassen", 10)
        inventory = collect_inventory(target)
        save_inventory(inventory)
        warnings.extend(inventory.warnings)

        _full_scan_progress(state, job_id, "Prüfquellen vorbereiten", 25)
        guideline = guideline_status(inventory)
        _full_scan_progress(state, job_id, "Alle SCAP-Regeln als Vollprofil prüfen", 45)
        effective_profile = FULL_BENCHMARK_PROFILE
        if include_configuration and data_stream:
            scanner = guideline["native_scanner"]
            if data_stream not in {item["path"] for item in scanner["data_streams"]}:
                engines["configuration"] = {
                    "status": "unavailable",
                    "message": "Gewählter SCAP-Datenstrom ist auf dem Ziel nicht verfügbar.",
                }
            else:
                selectable_ids = discover_scap_selectable_ids(target, data_stream)
                all_rule_ids = [item_id for item_id in selectable_ids if "_rule_" in item_id]
                engines["configuration"] = run_scap_scan(
                    target,
                    effective_profile,
                    data_stream,
                    rule_ids=selectable_ids,
                    replace_profile=True,
                )
                if engines["configuration"].get("status") == "completed":
                    full_scan = engines["configuration"]
                    unassessed_ids = [
                        item["id"]
                        for item in full_scan["results"]
                        if item.get("status") in {"notselected", "notchecked"}
                    ]
                    full_scan["benchmark_rules"] = len(all_rule_ids)
                    full_scan["evaluated_rules"] = len(all_rule_ids) - len(unassessed_ids)
                    full_scan["unassessed_rules"] = len(unassessed_ids)
                    full_scan["unassessed_rule_ids"] = unassessed_ids
                    full_scan["coverage_status"] = "partial" if unassessed_ids else "complete"
                    full_scan["scan_scope"] = "independent_full_benchmark"
                    if unassessed_ids:
                        warnings.append(
                            f"OpenSCAP konnte {len(unassessed_ids)} von {len(all_rule_ids)} "
                            "Regeln wegen technischen Bedingungen nicht bewerten."
                        )
                    guideline = integrate_scap_coverage(guideline, engines["configuration"])
        elif not include_configuration:
            engines["configuration"] = {"status": "skipped", "message": "Nicht ausgewählt"}
        else:
            engines["configuration"] = {
                "status": "unavailable",
                "message": "Kein SCAP-Datenstrom gewählt; zuerst System erkennen.",
            }

        _full_scan_progress(state, job_id, "Offiziellen OVAL-Feed prüfen", 70)
        if include_vulnerabilities:
            try:
                engines["vulnerabilities"] = run_vulnerability_scan(target, inventory)
            except (OSError, RuntimeError, ValueError) as exc:
                engines["vulnerabilities"] = {"status": "error", "message": str(exc), "results": []}
        else:
            engines["vulnerabilities"] = {
                "status": "skipped",
                "message": "Nicht ausgewählt",
                "results": [],
            }

        configuration = engines.get("configuration", {})
        if configuration.get("status") == "completed":
            scap_report = {
                "schema_version": 1,
                "target": target.name,
                "generated_at": datetime.now(UTC).isoformat(),
                "platform": asdict(inventory.platform),
                "profile": effective_profile,
                "data_stream": data_stream,
                "counts": configuration.get("counts", {}),
                "results": configuration.get("results", []),
                "sources": guideline["documents"],
            }
            scap_path = data_home() / "reports" / f"{target.name}-openscap.json"
            scap_path.parent.mkdir(parents=True, exist_ok=True)
            scap_temporary = scap_path.with_suffix(".tmp")
            scap_temporary.write_text(
                json.dumps(scap_report, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            os.chmod(scap_temporary, 0o600)
            scap_temporary.replace(scap_path)

        _full_scan_progress(state, job_id, "Gesamtbericht speichern", 95)
        report = {
            "schema_version": 2,
            "scan_type": "full",
            "target": target.name,
            "generated_at": datetime.now(UTC).isoformat(),
            "platform": asdict(inventory.platform),
            "engines": engines,
            "guideline": guideline,
            "warnings": warnings,
        }
        report_path = data_home() / "reports" / f"{target.name}-full-scan.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = report_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        temporary.replace(report_path)
        with state.lock:
            state.scan_jobs[job_id] = {
                "status": "completed",
                "stage": "Full Scan abgeschlossen",
                "percent": 100,
                "report_path": str(report_path),
                "report": report,
            }
    except Exception as exc:  # noqa: BLE001 - final boundary keeps the GUI job pollable
        with state.lock:
            state.scan_jobs[job_id] = {
                "status": "failed",
                "stage": "Full Scan fehlgeschlagen",
                "percent": 100,
                "error": str(exc),
            }


def _run_source_review_job(
    state: WebState, job_id: str, guideline: dict[str, Any], model: str
) -> None:
    try:
        response = OllamaAdvisor(
            model=model,
            base_url=state.ollama_url,
            timeout=180,
        ).review_sources(
            guideline["platform"], guideline["documents"], guideline["source_coverage"]
        )
        deterministic_gaps = {item["id"] for item in guideline["source_coverage"].get("gaps", [])}
        suggestions = []
        for item in response.get("suggestions", []):
            category = str(item.get("category", ""))
            if category not in TOPICS or category not in deterministic_gaps:
                continue
            suggestions.append(
                {
                    "category": category,
                    "title": TOPICS[category],
                    "search_terms": str(item.get("search_terms", ""))[:300],
                    "reason": str(item.get("reason", ""))[:1000],
                }
            )
        result = {
            "status": "completed",
            "kind": "source_review",
            "summary": str(response.get("summary", ""))[:2000],
            "missing_categories": sorted(deterministic_gaps),
            "suggestions": suggestions,
            "warnings": [str(item)[:1000] for item in response.get("warnings", [])],
            "model": model,
        }
    except (AdvisorError, KeyError, TypeError) as exc:
        result = {"status": "failed", "kind": "source_review", "error": str(exc)}
    with state.lock:
        state.recommendation_jobs[job_id] = result
        if any(item.get("status") == "running" for item in state.recommendation_jobs.values()):
            state.ai_state = "working"
            state.ai_message = "Ein weiteres Modell analysiert die Kontrollen"
        else:
            state.ai_state = "ready" if result["status"] == "completed" else "error"
            state.ai_message = (
                f"Quellenanalyse mit {model} abgeschlossen"
                if result["status"] == "completed"
                else str(result.get("error", "Quellenanalyse fehlgeschlagen"))
            )


def _start_source_review_job(state: WebState, guideline: dict[str, Any]) -> str:
    job_id = secrets.token_urlsafe(18)
    with state.lock:
        if len(state.recommendation_jobs) >= 20:
            oldest = next(iter(state.recommendation_jobs))
            state.recommendation_jobs.pop(oldest, None)
        state.recommendation_jobs[job_id] = {"status": "running", "kind": "source_review"}
        state.ai_state = "working"
        state.ai_message = f"{state.model} prüft die Quellenabdeckung"
        model = state.model
    threading.Thread(
        target=_run_source_review_job,
        args=(state, job_id, guideline, model),
        daemon=True,
        name=f"lha-source-{job_id[:8]}",
    ).start()
    return job_id


def _sanitize_hardening_review(
    response: dict[str, Any], failed_rules: list[dict[str, Any]], model: str
) -> dict[str, Any]:
    allowed = {str(item.get("id")): item for item in failed_rules if item.get("id")}
    priorities = {"critical", "high", "medium", "low"}
    dispositions = {"recommend", "review", "defer"}
    recommendations = []
    seen: set[str] = set()
    for item in response.get("recommendations", [])[:8]:
        rule_id = str(item.get("rule_id", ""))
        if rule_id not in allowed or rule_id in seen:
            continue
        seen.add(rule_id)
        source = allowed[rule_id]
        priority = str(item.get("priority", "medium"))
        disposition = str(item.get("disposition", "review"))
        recommendations.append(
            {
                "rule_id": rule_id,
                "title": str(source.get("title") or source.get("short_id") or rule_id)[:500],
                "short_id": str(source.get("short_id") or rule_id.rsplit("_rule_", 1)[-1])[:300],
                "topic": str(source.get("topic") or "other")[:100],
                "priority": priority if priority in priorities else "medium",
                "disposition": disposition if disposition in dispositions else "review",
                "reason": str(item.get("reason", ""))[:2000],
                "operational_impact": str(item.get("operational_impact", ""))[:2000],
                "validation": str(item.get("validation", ""))[:2000],
            }
        )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    recommendations.sort(key=lambda item: (order[item["priority"]], item["title"]))
    return {
        "status": "completed",
        "kind": "hardening_review",
        "summary": str(response.get("summary", ""))[:4000],
        "profile_name": str(response.get("profile_name", "KI-Hardening-Auswahl"))[:100],
        "recommendations": recommendations,
        "selected_rule_ids": [
            item["rule_id"] for item in recommendations if item["disposition"] == "recommend"
        ],
        "warnings": [str(item)[:1000] for item in response.get("warnings", [])],
        "model": model,
        "guardrail": "Nur echte OpenSCAP-Fehlschläge; keine KI-generierten Shell-Befehle.",
    }


def _run_hardening_review_job(
    state: WebState,
    job_id: str,
    target_name: str,
    platform: dict[str, str],
    failed_rules: list[dict[str, Any]],
    security_context: dict[str, Any],
    model: str,
) -> None:
    try:
        supplied_rules = [
            {
                "id": str(item.get("id", "")),
                "title": str(item.get("title", "")),
                "short_id": str(item.get("short_id", "")),
                "topic": str(item.get("topic", "other")),
            }
            for item in failed_rules[:250]
        ]
        response = OllamaAdvisor(
            model=model, base_url=state.ollama_url, timeout=600
        ).prioritize_hardening(platform, supplied_rules, security_context)
        result = _sanitize_hardening_review(response, failed_rules, model)
        report = {
            "schema_version": 1,
            "target": target_name,
            "generated_at": datetime.now(UTC).isoformat(),
            "platform": platform,
            **{key: value for key, value in result.items() if key != "status"},
        }
        report_path = data_home() / "reports" / f"{target_name}-ai-hardening.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = report_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        temporary.replace(report_path)
        result["report_path"] = str(report_path)
    except (AdvisorError, OSError, KeyError, TypeError, ValueError) as exc:
        result = {"status": "failed", "kind": "hardening_review", "error": str(exc)}
    with state.lock:
        state.recommendation_jobs[job_id] = result
        running = any(
            item.get("status") == "running" for item in state.recommendation_jobs.values()
        )
        state.ai_state = (
            "working" if running else ("ready" if result["status"] == "completed" else "error")
        )
        state.ai_message = (
            "Ein weiteres Modell analysiert die Kontrollen"
            if running
            else f"Hardening-Priorisierung mit {model} abgeschlossen"
            if result["status"] == "completed"
            else str(result.get("error", "KI-Hardening-Analyse fehlgeschlagen"))
        )


def _start_hardening_review_job(
    state: WebState,
    target_name: str,
    platform: dict[str, str],
    failed_rules: list[dict[str, Any]],
    security_context: dict[str, Any],
) -> str:
    job_id = secrets.token_urlsafe(18)
    with state.lock:
        if len(state.recommendation_jobs) >= 20:
            state.recommendation_jobs.pop(next(iter(state.recommendation_jobs)), None)
        state.recommendation_jobs[job_id] = {"status": "running", "kind": "hardening_review"}
        state.ai_state = "working"
        state.ai_message = f"{state.model} priorisiert die OpenSCAP-Fehlschläge"
        model = state.model
    threading.Thread(
        target=_run_hardening_review_job,
        args=(state, job_id, target_name, platform, failed_rules, security_context, model),
        daemon=True,
        name=f"lha-hardening-{job_id[:8]}",
    ).start()
    return job_id


def _sanitize_baseline_setup(
    response: dict[str, Any],
    control: dict[str, Any],
    model: str,
    platform: dict[str, Any] | None = None,
) -> dict[str, Any]:
    recommendations = {"apply", "review", "keep", "not_recommended"}
    recommendation = str(response.get("recommendation", "review"))
    settings = []
    for item in response.get("settings", [])[:8]:
        if not isinstance(item, dict):
            continue
        settings.append(
            {
                "name": str(item.get("name", ""))[:200],
                "value": str(item.get("value", ""))[:500],
                "reason": str(item.get("reason", ""))[:1000],
            }
        )

    def short_list(name: str, limit: int = 6) -> list[str]:
        values = response.get(name, [])
        if not isinstance(values, list):
            return []
        return [str(item)[:1000] for item in values[:limit]]

    platform = platform or {}
    platform_label = str(
        platform.get("pretty_name")
        or " ".join(
            part
            for part in (platform.get("distribution"), platform.get("version"))
            if part
        )
        or ""
    ).strip()

    failed_rule_ids = [str(item) for item in control.get("failed_rule_ids", [])]
    implementation_mode = "openscap" if failed_rule_ids else "operator_review"
    return {
        "status": "completed",
        "kind": "baseline_setup",
        "control_id": str(control.get("id", "")),
        "control_title": str(control.get("title", ""))[:500],
        "control_status": str(control.get("status", ""))[:50],
        "platform": platform_label[:200],
        "summary": str(response.get("summary", ""))[:3000],
        "recommendation": (recommendation if recommendation in recommendations else "review"),
        "mechanism": str(response.get("mechanism", ""))[:200],
        "settings": settings,
        "prerequisites": short_list("prerequisites"),
        "operational_impact": str(response.get("operational_impact", ""))[:2000],
        "validation_steps": short_list("validation_steps"),
        "rollback_steps": short_list("rollback_steps"),
        "warnings": short_list("warnings"),
        "implementation_mode": implementation_mode,
        "rule_ids": failed_rule_ids,
        "model": model,
        "guardrail": (
            "KI-Entwurf ohne Shell-Befehle. Ausführbare Änderungen stammen nur aus "
            "erneut geprüften OpenSCAP-Fehlschlägen."
        ),
    }


def _run_baseline_setup_job(
    state: WebState,
    job_id: str,
    target_name: str,
    platform: dict[str, str],
    control: dict[str, Any],
    model: str,
) -> None:
    try:
        supplied_control = {
            "id": control.get("id"),
            "title": control.get("title"),
            "category": control.get("category"),
            "category_title": control.get("category_title"),
            "level": control.get("level"),
            "status": control.get("status"),
            "rationale": control.get("rationale"),
            "manual": control.get("manual"),
            "matched_rules": [
                {
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "short_id": item.get("short_id"),
                    "status": item.get("status"),
                }
                for item in control.get("matched_rules", [])[:30]
            ],
            "source_ids": [item.get("id") for item in control.get("sources", [])],
        }
        response = OllamaAdvisor(
            model=model, base_url=state.ollama_url, timeout=600
        ).design_baseline_setup(platform, supplied_control)
        result = _sanitize_baseline_setup(response, control, model, platform)
        report_path = data_home() / "reports" / f"{target_name}-ai-baseline-setups.json"
        existing: dict[str, Any] = {}
        if report_path.is_file():
            with suppress(OSError, json.JSONDecodeError):
                loaded = json.loads(report_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    existing = loaded
        setups = existing.get("setups", {})
        if not isinstance(setups, dict):
            setups = {}
        setups[result["control_id"]] = {
            key: value for key, value in result.items() if key != "status"
        }
        report = {
            "schema_version": 1,
            "target": target_name,
            "platform": platform,
            "updated_at": datetime.now(UTC).isoformat(),
            "setups": setups,
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = report_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        temporary.replace(report_path)
        result["report_path"] = str(report_path)
    except (AdvisorError, OSError, KeyError, TypeError, ValueError) as exc:
        result = {
            "status": "failed",
            "kind": "baseline_setup",
            "control_id": str(control.get("id", "")),
            "error": str(exc),
        }
    with state.lock:
        state.recommendation_jobs[job_id] = result
        running = any(
            item.get("status") == "running" for item in state.recommendation_jobs.values()
        )
        state.ai_state = (
            "working" if running else ("ready" if result["status"] == "completed" else "error")
        )
        state.ai_message = (
            "Ein weiteres Modell analysiert die Kontrollen"
            if running
            else f"Baseline-Setup mit {model} abgeschlossen"
            if result["status"] == "completed"
            else str(result.get("error", "KI-Baseline-Setup fehlgeschlagen"))
        )


def _start_baseline_setup_job(
    state: WebState,
    target_name: str,
    platform: dict[str, str],
    control: dict[str, Any],
) -> str:
    job_id = secrets.token_urlsafe(18)
    with state.lock:
        if len(state.recommendation_jobs) >= 20:
            state.recommendation_jobs.pop(next(iter(state.recommendation_jobs)), None)
        state.recommendation_jobs[job_id] = {
            "status": "running",
            "kind": "baseline_setup",
            "control_id": control.get("id"),
        }
        state.ai_state = "working"
        state.ai_message = f"{state.model} erstellt ein Setup für {control.get('id')}"
        model = state.model
    threading.Thread(
        target=_run_baseline_setup_job,
        args=(state, job_id, target_name, platform, control, model),
        daemon=True,
        name=f"lha-baseline-{job_id[:8]}",
    ).start()
    return job_id


def _run_discovery_review_job(
    state: WebState,
    job_id: str,
    guideline: dict[str, Any],
    candidates: list[dict[str, str]],
    model: str,
) -> None:
    try:
        gap_ids = [item["id"] for item in guideline["source_coverage"].get("gaps", [])]
        response = OllamaAdvisor(
            model=model,
            base_url=state.ollama_url,
            timeout=180,
        ).review_discovered_sources(guideline["platform"], candidates, gap_ids)
        recommendations = []
        for item in response.get("recommendations", []):
            index = int(item.get("candidate_index", -1))
            if not 0 <= index < len(candidates):
                continue
            categories = [
                str(category) for category in item.get("categories", []) if str(category) in TOPICS
            ]
            recommendations.append(
                {
                    "candidate_index": index,
                    "categories": list(dict.fromkeys(categories)),
                    "reason": str(item.get("reason", ""))[:1000],
                }
            )
        result = {
            "status": "completed",
            "kind": "guideline_discovery",
            "summary": str(response.get("summary", ""))[:2000],
            "recommendations": recommendations,
            "warnings": [str(item)[:1000] for item in response.get("warnings", [])],
            "model": model,
        }
    except (AdvisorError, KeyError, TypeError, ValueError) as exc:
        result = {"status": "failed", "kind": "guideline_discovery", "error": str(exc)}
    with state.lock:
        state.recommendation_jobs[job_id] = result
        if any(item.get("status") == "running" for item in state.recommendation_jobs.values()):
            state.ai_state = "working"
            state.ai_message = "Ein weiteres Modell analysiert die Kontrollen"
        else:
            state.ai_state = "ready" if result["status"] == "completed" else "error"
            state.ai_message = (
                f"Online-Richtlinienanalyse mit {model} abgeschlossen"
                if result["status"] == "completed"
                else str(result.get("error", "Online-Richtlinienanalyse fehlgeschlagen"))
            )


def _start_discovery_review_job(
    state: WebState, guideline: dict[str, Any], candidates: list[dict[str, str]]
) -> str:
    job_id = secrets.token_urlsafe(18)
    with state.lock:
        if len(state.recommendation_jobs) >= 20:
            oldest = next(iter(state.recommendation_jobs))
            state.recommendation_jobs.pop(oldest, None)
        state.recommendation_jobs[job_id] = {
            "status": "running",
            "kind": "guideline_discovery",
        }
        state.ai_state = "working"
        state.ai_message = f"{state.model} bewertet neue Hersteller-Richtlinien"
        model = state.model
    threading.Thread(
        target=_run_discovery_review_job,
        args=(state, job_id, guideline, candidates, model),
        daemon=True,
        name=f"lha-discovery-{job_id[:8]}",
    ).start()
    return job_id


def _zip_bundle(directory: Path) -> Path:
    archive = directory.parent / f"{directory.name}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                bundle.write(path, arcname=f"{directory.name}/{path.relative_to(directory)}")
    return archive


def _saved_general_baseline(target_name: str) -> dict[str, Any] | None:
    path = data_home() / "reports" / f"{target_name}-general-baseline.json"
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if payload.get("target") == target_name else None


def _stage_native_policy_bundle(target: Target, directory: Path) -> dict[str, str]:
    """Upload one generated bundle into a private, explicit /tmp directory."""
    token = secrets.token_hex(6)
    remote_directory = f"/tmp/hardening-agent-{token}"
    transport = Transport(target)
    uploaded: list[tuple[str, str]] = []
    try:
        for source in sorted(directory.iterdir()):
            if not source.is_file():
                continue
            temporary = f"/tmp/hardening-agent-{token}-{source.name}"
            transport.put_file(source, temporary)
            uploaded.append((temporary, source.name))
        commands = ["set -eu", f"mkdir -m 700 -- {shlex.quote(remote_directory)}"]
        commands.extend(
            f"mv -- {shlex.quote(temporary)} {shlex.quote(remote_directory + '/' + name)}"
            for temporary, name in uploaded
        )
        commands.extend(
            [
                f"chmod 600 -- {shlex.quote(remote_directory)}/*",
                (
                    f"chmod 700 -- {shlex.quote(remote_directory)}/apply-native-policy.sh "
                    f"{shlex.quote(remote_directory)}/verify-native-policy.sh "
                    f"{shlex.quote(remote_directory)}/restore-native-policy.sh"
                ),
            ]
        )
        result = transport.run_script("\n".join(commands) + "\n", timeout=120)
        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or "Paket konnte auf dem Ziel nicht eingerichtet werden"
            )
    except Exception:
        if uploaded:
            cleanup = "rm -f -- " + " ".join(shlex.quote(path) for path, _ in uploaded) + "\n"
            with suppress(TransportError):
                transport.run_script(cleanup, timeout=30)
        raise
    return {
        "directory": remote_directory,
        "apply_script": f"{remote_directory}/apply-native-policy.sh",
        "verify_script": f"{remote_directory}/verify-native-policy.sh",
        "restore_script": f"{remote_directory}/restore-native-policy.sh",
        "apply_command": f"sudo {remote_directory}/apply-native-policy.sh",
        "verify_command": f"sudo {remote_directory}/verify-native-policy.sh",
        "restore_command": f"sudo {remote_directory}/restore-native-policy.sh",
    }


def _backup_paths_from_fix(generated_fix: str) -> list[str]:
    pattern = re.compile(r"(?<![A-Za-z0-9_])(/(?:etc|boot|usr/local/etc)(?:/[A-Za-z0-9_.@+:-]+)+)")
    paths = list(dict.fromkeys(match.group(1) for match in pattern.finditer(generated_fix)))
    return sorted(paths)[:300]


def _write_native_policy_bundle(
    root: Path,
    target: Target,
    platform: dict[str, Any],
    profile: str,
    data_stream: str,
    scan_report: dict[str, Any],
    generated_fix: str,
    sources: list[dict[str, Any]],
    selected_rule_ids: list[str] | None = None,
    saved_profile_name: str | None = None,
    tailoring_xml: str | None = None,
    tailoring_profile: str | None = None,
    baseline_report: dict[str, Any] | None = None,
    baseline_plan: dict[str, Any] | None = None,
    ai_setup_report: dict[str, Any] | None = None,
) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    directory = root / f"native-policy-{target.name}-{stamp}-{secrets.token_hex(3)}"
    directory.mkdir(parents=True, exist_ok=False)
    profile_name = profile.removeprefix("xccdf_org.ssgproject.content_profile_")
    apply_script = directory / "apply-native-policy.sh"
    verify_script = directory / "verify-native-policy.sh"
    restore_script = directory / "restore-native-policy.sh"
    backup_paths = _backup_paths_from_fix(generated_fix)
    metadata = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "target": target.name,
        "platform": platform,
        "profile": profile,
        "data_stream": data_stream,
        "scan_counts": scan_report.get("counts", {}),
        "sources": sources,
        "selected_rule_ids": selected_rule_ids or [],
        "saved_profile_name": saved_profile_name,
        "tailoring_profile": tailoring_profile,
        "system_role": baseline_plan.get("role") if baseline_plan else None,
        "backup_paths": backup_paths,
        "warning": (
            "OpenSCAP remediation can change authentication, boot, network, services and "
            "filesystems. File restore is best effort and does not replace a VM snapshot."
        ),
    }
    selected = list(dict.fromkeys(selected_rule_ids or []))
    confirmation = f"APPLY {saved_profile_name or profile_name}"
    backup_manifest = directory / "backup-paths.txt"
    backup_manifest.write_text(
        "\n".join(backup_paths) + ("\n" if backup_paths else ""), encoding="utf-8"
    )
    wrapper = f"""#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo "Dieses Skript muss als root auf dem geprüften Zielsystem ausgeführt werden." >&2
  exit 1
fi
echo "ACHTUNG: Die ausgewählten OpenSCAP-Massnahmen können Anmeldung, Netzwerk, Boot, Dienste und Dateisysteme ändern."
echo "Vorher Snapshot/Backup und Konsolenzugang sicherstellen. Der enthaltene Restore ist nur dateibasiert."
read -r -p "Zum Fortfahren exakt '{confirmation}' eingeben: " answer
[[ "$answer" == "{confirmation}" ]] || {{ echo "Abgebrochen."; exit 2; }}

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
command -v sha256sum >/dev/null 2>&1 || {{ echo "sha256sum fehlt; Paket kann nicht geprüft werden." >&2; exit 3; }}
(cd "$script_dir" && sha256sum --check SHA256SUMS)
backup_root=/var/backups/linux-hardening-agent
backup_dir="$backup_root/{target.name}-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$backup_root" "$backup_dir" "$script_dir/state"
: >"$backup_dir/existing-paths.txt"
: >"$backup_dir/absent-paths.txt"
while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  case "$path" in /etc/*|/boot/*|/usr/local/etc/*) ;; *) echo "Unsicherer Backup-Pfad: $path" >&2; exit 3;; esac
  if [[ -e "$path" || -L "$path" ]]; then
    printf '%s\n' "$path" >>"$backup_dir/existing-paths.txt"
  else
    printf '%s\n' "$path" >>"$backup_dir/absent-paths.txt"
  fi
done <"$script_dir/backup-paths.txt"
if [[ -s "$backup_dir/existing-paths.txt" ]]; then
  tar --xattrs --acls --numeric-owner -cpf "$backup_dir/files.tar" -T "$backup_dir/existing-paths.txt"
fi
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${{binary:Package}}\t${{Version}}\n' >"$backup_dir/packages-before.txt"
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf '%{{NAME}}\t%{{EPOCHNUM}}:%{{VERSION}}-%{{RELEASE}}\n' | sort >"$backup_dir/packages-before.txt"
fi
printf '%s\n' "$backup_dir" >"$script_dir/state/last-backup-path"
chmod 600 "$script_dir/state/last-backup-path"
echo "Sicherung erstellt: $backup_dir"

{generated_fix}
"""
    if tailoring_xml and tailoring_profile:
        tailoring_path = directory / "selection-tailoring.xml"
        tailoring_path.write_text(tailoring_xml, encoding="utf-8")
        verify_scope = (
            f"--profile {shlex.quote(tailoring_profile)} "
            '--tailoring-file "$script_dir/selection-tailoring.xml"'
        )
    else:
        verify_scope = f"--profile {shlex.quote(profile)}"
    verify = f"""#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo "Die vollständige Prüfung muss als root ausgeführt werden." >&2
  exit 1
fi
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
exec oscap xccdf eval --progress {verify_scope} {shlex.quote(data_stream)}
"""
    restore = f"""#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo "Dieses Skript muss als root auf dem geprüften Zielsystem ausgeführt werden." >&2
  exit 1
fi
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
command -v sha256sum >/dev/null 2>&1 || {{ echo "sha256sum fehlt; Paket kann nicht geprüft werden." >&2; exit 2; }}
(cd "$script_dir" && sha256sum --check SHA256SUMS)
state_file="$script_dir/state/last-backup-path"
[[ -s "$state_file" ]] || {{ echo "Keine Sicherung dieses Pakets registriert." >&2; exit 2; }}
backup_dir=$(cat "$state_file")
case "$backup_dir" in /var/backups/linux-hardening-agent/*) ;; *) echo "Ungültiger Sicherungspfad." >&2; exit 3;; esac
[[ -d "$backup_dir" ]] || {{ echo "Sicherung fehlt: $backup_dir" >&2; exit 4; }}
echo "ACHTUNG: Dateibasierte Rücknahme aus $backup_dir"
echo "Paket-, Boot- und Dienständerungen können zusätzliche manuelle Schritte benötigen."
read -r -p "Zum Fortfahren exakt 'RESTORE {saved_profile_name or profile_name}' eingeben: " answer
[[ "$answer" == "RESTORE {saved_profile_name or profile_name}" ]] || {{ echo "Abgebrochen."; exit 5; }}
if [[ -s "$backup_dir/absent-paths.txt" ]]; then
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    case "$path" in /etc/*|/boot/*|/usr/local/etc/*) rm -rf -- "$path";; *) echo "Unsicherer Restore-Pfad: $path" >&2; exit 6;; esac
  done <"$backup_dir/absent-paths.txt"
fi
if [[ -f "$backup_dir/files.tar" ]]; then
  tar --xattrs --acls --numeric-owner -xpf "$backup_dir/files.tar" -C /
fi
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
echo "Dateien wurden wiederhergestellt. Dienste/Netzwerk kontrolliert neu laden und danach verify-native-policy.sh ausführen."
echo "Paketvergleich: $backup_dir/packages-before.txt"
"""
    readme = f"""Linux Hardening Agent – vollständiges natives Richtlinienpaket

Ziel: {target.name}
System: {platform.get("pretty_name", platform.get("distribution", "Linux"))}
OpenSCAP-Profil: {profile}
Datenstrom: {data_stream}

Dieses Paket stammt aus dem auf dem Ziel installierten maschinenlesbaren OpenSCAP-/SSG-Profil.
Ausgewählte Regeln: {len(selected) if selected else "vollständiges Profil"}

Sicherer Ablauf:
1. Paket auf das geprüfte Zielsystem übertragen.
2. KVM-Snapshot oder vollständiges Backup erstellen und Konsolenzugang testen.
3. policy.json, baseline-plan.json und apply-native-policy.sh fachlich prüfen.
4. sudo ./apply-native-policy.sh ausführen; dabei wird zuerst eine Dateisicherung erstellt.
5. sudo ./verify-native-policy.sh ausführen und den neuen Bericht archivieren.
6. Bei Problemen sudo ./restore-native-policy.sh verwenden und anschließend erneut prüfen.

Wichtig: OpenSCAP-Massnahmen können produktive Dienste oder den Remotezugang beeinflussen.
Der Restore stellt erkannte Konfigurationsdateien zurück. Paket-, Boot-, Laufzeit- und
Dienständerungen können zusätzliche manuelle Schritte oder den vorherigen Snapshot benötigen.
"""
    apply_script.write_text(wrapper, encoding="utf-8")
    verify_script.write_text(verify, encoding="utf-8")
    restore_script.write_text(restore, encoding="utf-8")
    (directory / "README.txt").write_text(readme, encoding="utf-8")
    (directory / "policy.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    if baseline_report:
        (directory / "general-linux-baseline.json").write_text(
            json.dumps(baseline_report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    if baseline_plan:
        (directory / "baseline-plan.json").write_text(
            json.dumps(baseline_plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    if ai_setup_report:
        (directory / "ai-baseline-setups.json").write_text(
            json.dumps(ai_setup_report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    os.chmod(apply_script, 0o700)
    os.chmod(verify_script, 0o700)
    os.chmod(restore_script, 0o700)
    checksums = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (directory / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    return directory


def _validated_policy_selection(
    target_name: str,
    profile: str,
    data_stream: str,
    raw_rule_ids: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(raw_rule_ids, list) or not raw_rule_ids:
        raise ValueError("Mindestens eine fehlgeschlagene OpenSCAP-Regel auswählen")
    rule_ids = [str(item) for item in raw_rule_ids]
    if len(rule_ids) != len(set(rule_ids)) or len(rule_ids) > 1000:
        raise ValueError("Ungültige oder zu grosse Regelauswahl")
    report_path = data_home() / "reports" / f"{target_name}-openscap.json"
    if not report_path.is_file():
        raise ValueError("Zuerst das vollständige OpenSCAP-Profil prüfen")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("profile") != profile or report.get("data_stream") != data_stream:
        raise ValueError("Die Auswahl gehört nicht zum zuletzt geprüften Profil")
    failed = {
        str(item.get("id")): item
        for item in report.get("results", [])
        if isinstance(item, dict) and item.get("status") == "fail"
    }
    unknown = [rule_id for rule_id in rule_ids if rule_id not in failed]
    if unknown:
        raise ValueError("Nur aktuell fehlgeschlagene Regeln können übernommen werden")
    return report, [failed[rule_id] for rule_id in rule_ids]


def _host_name(header: str) -> str:
    value = header.strip().lower()
    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def _vms_payload(uri: str) -> dict[str, Any]:
    if not shutil.which("virsh"):
        return {
            "vms": [],
            "warnings": [
                (
                    "virsh ist nicht installiert. KVM ist optional; lokale und SSH-Ziele "
                    "funktionieren weiterhin."
                )
            ],
        }
    try:
        vms, warnings = list_vms(uri)
        return {"vms": vms, "warnings": warnings}
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        return {
            "vms": [],
            "warnings": [
                f"KVM ist nicht verfügbar: {exc}. Lokale und SSH-Ziele funktionieren weiterhin."
            ],
        }


def _status(state: WebState) -> dict[str, Any]:
    advisor = OllamaAdvisor(model=state.model, base_url=state.ollama_url)
    ollama_reachable = advisor.health()
    models: list[dict[str, Any]] = []
    ollama_error = ""
    if ollama_reachable:
        try:
            models = advisor.models()
            installed_names = {item["name"] for item in models}
            with state.lock:
                running = any(
                    item.get("status") == "running" for item in state.recommendation_jobs.values()
                )
                if installed_names and state.model not in installed_names and not running:
                    state.model = "qwen3:8b" if "qwen3:8b" in installed_names else models[0]["name"]
                    state.ai_state = "ready"
                    state.ai_message = f"{state.model} wurde automatisch ausgewählt"
        except AdvisorError as exc:
            ollama_error = str(exc)
    with state.lock:
        ai_state = state.ai_state if ollama_reachable else "unavailable"
        ai_message = state.ai_message if ollama_reachable else "Ollama ist nicht erreichbar"
    vms: list[dict[str, object]] = []
    vm_warnings: list[str] = []
    if shutil.which("virsh"):
        try:
            vms, vm_warnings = list_vms(state.libvirt_uri)
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            vm_warnings = [str(exc)]
    return {
        "version": __version__,
        "ollama": {
            "reachable": ollama_reachable,
            "model": state.model,
            "models": models,
            "error": ollama_error,
            "state": ai_state,
            "message": ai_message,
        },
        "tools": {
            name: shutil.which(name) for name in ("ssh", "scp", "shellcheck", "virsh", "vagrant")
        },
        "counts": {"targets": len(load_targets()), "vms": len(vms)},
        "vm_warnings": vm_warnings,
        "running_as_root": os.geteuid() == 0,
    }


def _handler(state: WebState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"LinuxHardeningAgent/{__version__}"

        def log_message(self, fmt: str, *args: object) -> None:
            print(f"GUI {self.address_string()} {fmt % args}")

        def _host_allowed(self) -> bool:
            if state.bind_host not in {"127.0.0.1", "::1", "localhost"}:
                return True
            host = _host_name(self.headers.get("Host", ""))
            return host in {"127.0.0.1", "::1", "localhost"}

        def _json(self, payload: Any, status: int = 200) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'")
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                return

        def _static(self, name: str) -> None:
            resource = files("hardening_agent").joinpath("web", name)
            try:
                data = resource.read_bytes()
            except (FileNotFoundError, IsADirectoryError):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            if name == "index.html":
                data = data.replace(b"__LHA_TOKEN__", state.token.encode("ascii"))
            media_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", f"{media_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict[str, Any]:
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                raise ValueError("Content-Type must be application/json")
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 65536:
                raise ValueError("Request body is too large")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise TypeError("JSON body must be an object")
            return payload

        def _authorized(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-LHA-CSRF", ""), state.token)

        def do_GET(self) -> None:
            if not self._host_allowed():
                self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Host header")
                return
            path = urlparse(self.path).path
            try:
                if path == "/":
                    self._static("index.html")
                elif path == "/app.js":
                    self._static("app.js")
                elif path == "/style.css":
                    self._static("style.css")
                elif path == "/api/status":
                    self._json(_status(state))
                elif path == "/api/vms":
                    self._json(_vms_payload(state.libvirt_uri))
                elif path == "/api/targets":
                    self._json({"targets": [asdict(item) for item in load_targets().values()]})
                elif path == "/api/guideline-sources":
                    self._json({"sources": all_guideline_sources()})
                elif path == "/api/policy-profiles":
                    self._json({"profiles": load_policy_profiles()})
                elif path.startswith("/api/recommendations/"):
                    self._recommendation_status(path.rsplit("/", 1)[-1])
                elif path.startswith("/api/full-scan/"):
                    self._full_scan_status(path.rsplit("/", 1)[-1])
                elif path.startswith("/api/download/"):
                    self._download(path.rsplit("/", 1)[-1])
                else:
                    self.send_error(HTTPStatus.NOT_FOUND)
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                self._json({"error": str(exc)}, 400)

        def _download(self, download_id: str) -> None:
            if not self._authorized():
                self._json({"error": "Missing or invalid GUI token"}, 403)
                return
            with state.lock:
                path = state.downloads.get(download_id)
            if not path or not path.is_file():
                self._json({"error": "Bundle is unavailable"}, 404)
                return
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _recommendation_status(self, job_id: str) -> None:
            if not self._authorized():
                self._json({"error": "Missing or invalid GUI token"}, 403)
                return
            with state.lock:
                result = state.recommendation_jobs.get(job_id)
            if result is None:
                self._json({"error": "Unknown recommendation job"}, 404)
                return
            self._json(result)

        def _full_scan_status(self, job_id: str) -> None:
            if not self._authorized():
                self._json({"error": "Missing or invalid GUI token"}, 403)
                return
            with state.lock:
                result = state.scan_jobs.get(job_id)
            if result is None:
                self._json({"error": "Unknown full scan job"}, 404)
                return
            self._json(result)

        def do_POST(self) -> None:
            if not self._host_allowed():
                self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Host header")
                return
            if not self._authorized():
                self._json({"error": "Missing or invalid GUI token"}, 403)
                return
            try:
                body = self._body()
                path = urlparse(self.path).path
                if path == "/api/targets":
                    self._add_target(body)
                elif path == "/api/audit":
                    self._audit(body)
                elif path == "/api/guidelines":
                    self._guidelines(body)
                elif path == "/api/guidelines/review":
                    self._review_guideline_sources(body)
                elif path == "/api/guidelines/discover":
                    self._discover_guideline_sources(body)
                elif path == "/api/compliance/install":
                    self._install_compliance_scanner(body)
                elif path == "/api/compliance/scan":
                    self._scan_compliance_profile(body)
                elif path == "/api/compliance/scan-selected":
                    self._scan_selected_compliance_rules(body)
                elif path == "/api/compliance/remediation":
                    self._build_native_policy_remediation(body)
                elif path == "/api/compliance/selected-remediation":
                    self._build_selected_policy_remediation(body)
                elif path == "/api/compliance/report-package":
                    self._build_policy_report(body)
                elif path == "/api/compliance/ai-prioritize":
                    self._prioritize_hardening(body)
                elif path == "/api/general-baseline":
                    self._general_linux_baseline(body)
                elif path == "/api/general-baseline/setup":
                    self._general_linux_baseline_setup(body)
                elif path == "/api/general-baseline/plan":
                    self._general_linux_baseline_plan(body)
                elif path == "/api/general-baseline/package":
                    self._general_linux_baseline_package(body)
                elif path == "/api/policy-profiles":
                    self._save_policy_profile(body)
                elif path == "/api/full-scan":
                    self._start_full_scan(body)
                elif path == "/api/vagrant/config":
                    self._vagrant_config(body)
                elif path == "/api/ollama/pull":
                    self._pull_model(body)
                elif path == "/api/ollama/select":
                    self._select_model(body)
                elif path == "/api/guideline-sources":
                    source = save_guideline_source(
                        body.get("source"), str(body.get("original_id") or "") or None
                    )
                    self._json({"status": "saved", "source": source}, 201)
                else:
                    self._json({"error": "Unknown API route"}, 404)
            except (
                AdvisorError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
                subprocess.SubprocessError,
                json.JSONDecodeError,
            ) as exc:
                self._json({"error": str(exc)}, 400)

        def do_DELETE(self) -> None:
            if not self._host_allowed():
                self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Host header")
                return
            if not self._authorized():
                self._json({"error": "Missing or invalid GUI token"}, 403)
                return
            path = urlparse(self.path).path
            try:
                target_prefix = "/api/targets/"
                source_prefix = "/api/guideline-sources/"
                profile_prefix = "/api/policy-profiles/"
                if path.startswith(target_prefix) and path[len(target_prefix) :]:
                    name = unquote(path[len(target_prefix) :])
                    delete_target(name)
                    self._json({"status": "deleted", "target": name})
                elif path.startswith(source_prefix) and path[len(source_prefix) :]:
                    source_id = unquote(path[len(source_prefix) :])
                    delete_guideline_source(source_id)
                    self._json({"status": "deleted", "source_id": source_id})
                elif path.startswith(profile_prefix) and path[len(profile_prefix) :]:
                    profile_id = unquote(path[len(profile_prefix) :])
                    if not POLICY_PROFILE_ID_PATTERN.fullmatch(profile_id):
                        raise ValueError("Ungültige Profil-ID")
                    profiles = load_policy_profiles()
                    remaining = [item for item in profiles if item.get("id") != profile_id]
                    if len(remaining) == len(profiles):
                        raise ValueError("Gespeichertes Profil nicht gefunden")
                    save_policy_profiles(remaining)
                    self._json({"status": "deleted", "profile_id": profile_id})
                else:
                    self._json({"error": "Unknown API route"}, 404)
            except (OSError, RuntimeError, ValueError) as exc:
                self._json({"error": str(exc)}, 400)

        def _add_target(self, body: dict[str, Any]) -> None:
            original_name = str(body["original_name"]) if body.get("original_name") else None
            target = Target(
                name=str(body.get("name", "")),
                host=str(body.get("host", "localhost")),
                user=str(body["user"]) if body.get("user") else None,
                port=int(body.get("port", 22)),
                identity_file=str(Path(str(body["identity_file"])).expanduser())
                if body.get("identity_file")
                else None,
                local=bool(body.get("local", False)),
                vm_name=str(body["vm_name"]) if body.get("vm_name") else None,
                libvirt_uri=state.libvirt_uri,
                vagrant_directory=str(body["vagrant_directory"])
                if body.get("vagrant_directory")
                else None,
                vagrant_machine=str(body["vagrant_machine"])
                if body.get("vagrant_machine")
                else None,
                vagrant_home=str(body["vagrant_home"]) if body.get("vagrant_home") else None,
            )
            target = refresh_vagrant_target(target)
            save_target(target, original_name=original_name)
            status = "updated" if original_name else "saved"
            self._json({"status": status, "target": asdict(target)}, 201)

        def _start_full_scan(self, body: dict[str, Any]) -> None:
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            data_stream = str(body.get("data_stream", ""))
            if data_stream and (
                not data_stream.startswith(("/usr/share/", "/usr/local/share/"))
                or not data_stream.endswith(".xml")
            ):
                raise ValueError("Invalid OpenSCAP data stream")
            job_id = secrets.token_urlsafe(18)
            with state.lock:
                state.scan_jobs[job_id] = {
                    "status": "running",
                    "stage": "Full Scan wird vorbereitet",
                    "percent": 0,
                }
            threading.Thread(
                target=_run_full_scan_job,
                args=(
                    state,
                    job_id,
                    target,
                    data_stream,
                    body.get("include_configuration") is not False,
                    body.get("include_vulnerabilities") is not False,
                ),
                daemon=True,
            ).start()
            self._json(
                {
                    "status": "running",
                    "job_id": job_id,
                    "connection_refreshed": connection_refreshed,
                },
                202,
            )

        def _prioritize_hardening(self, body: dict[str, Any]) -> None:
            target_name = str(body.get("target", ""))
            get_target(target_name)
            report_path = data_home() / "reports" / f"{target_name}-full-scan.json"
            if not report_path.is_file():
                raise ValueError("Zuerst einen Full Scan für dieses Ziel ausführen")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            configuration = report.get("engines", {}).get("configuration", {})
            failed_rules = [
                item for item in configuration.get("results", []) if item.get("status") == "fail"
            ]
            if not failed_rules:
                raise ValueError("Der letzte Full Scan enthält keine fehlgeschlagenen SCAP-Regeln")
            vulnerabilities = report.get("engines", {}).get("vulnerabilities", {})
            affected = [
                item
                for item in vulnerabilities.get("results", [])
                if item.get("status") == "affected"
            ]
            security_context = {
                "vulnerability_counts": vulnerabilities.get("counts", {}),
                "affected_vulnerabilities": [
                    {
                        "title": str(item.get("title", ""))[:500],
                        "severity": str(item.get("severity", ""))[:50],
                        "cves": list(item.get("cves", []))[:20],
                    }
                    for item in affected[:30]
                ],
                "scope": "general_linux_server",
            }
            baseline = _saved_general_baseline(target_name)
            if baseline:
                security_context["general_linux_baseline"] = {
                    "level": baseline.get("level"),
                    "counts": baseline.get("counts", {}),
                    "failed_controls": [
                        {
                            "id": item.get("id"),
                            "title": item.get("title"),
                            "failed_rule_ids": item.get("failed_rule_ids", []),
                            "sources": [source.get("id") for source in item.get("sources", [])],
                        }
                        for item in baseline.get("controls", [])
                        if item.get("status") == "fail"
                    ],
                }
            advisor = OllamaAdvisor(model=state.model, base_url=state.ollama_url)
            if not advisor.health():
                raise ValueError("Ollama ist nicht erreichbar")
            job_id = _start_hardening_review_job(
                state,
                target_name,
                dict(report.get("platform", {})),
                failed_rules,
                security_context,
            )
            self._json({"status": "running", "job_id": job_id, "model": state.model}, 202)

        def _general_linux_baseline(self, body: dict[str, Any]) -> None:
            target_name = str(body.get("target", ""))
            get_target(target_name)
            report_path = data_home() / "reports" / f"{target_name}-openscap.json"
            if not report_path.is_file():
                raise ValueError("Zuerst einen OpenSCAP-Full-Scan für dieses Ziel ausführen")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            categories = body.get("categories")
            if categories is not None and not isinstance(categories, list):
                raise ValueError("Baseline-Kategorien müssen als Liste übergeben werden")
            baseline = evaluate_general_linux_baseline(
                report,
                str(body.get("level", "basic")),
                [str(item) for item in categories] if categories is not None else None,
            )
            baseline_path = data_home() / "reports" / f"{target_name}-general-baseline.json"
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = baseline_path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(baseline, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            os.chmod(temporary, 0o600)
            temporary.replace(baseline_path)
            self._json({**baseline, "report_path": str(baseline_path)})

        def _general_linux_baseline_setup(self, body: dict[str, Any]) -> None:
            target_name = str(body.get("target", ""))
            get_target(target_name)
            control_id = str(body.get("control_id", ""))
            baseline_path = data_home() / "reports" / f"{target_name}-general-baseline.json"
            if not baseline_path.is_file():
                raise ValueError("Zuerst die allgemeine Linux-Baseline auswerten")
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            control = next(
                (
                    item
                    for item in baseline.get("controls", [])
                    if isinstance(item, dict) and item.get("id") == control_id
                ),
                None,
            )
            if control is None:
                raise ValueError("Baseline-Eintrag ist in der aktuellen Auswahl nicht vorhanden")
            advisor = OllamaAdvisor(model=state.model, base_url=state.ollama_url)
            if not advisor.health():
                raise ValueError("Ollama ist nicht erreichbar")
            job_id = _start_baseline_setup_job(
                state,
                target_name,
                dict(baseline.get("platform", {})),
                control,
            )
            self._json(
                {
                    "status": "running",
                    "job_id": job_id,
                    "control_id": control_id,
                    "model": state.model,
                },
                202,
            )

        def _general_linux_baseline_plan(self, body: dict[str, Any]) -> None:
            target_name = str(body.get("target", ""))
            get_target(target_name)
            baseline_path = data_home() / "reports" / f"{target_name}-general-baseline.json"
            if not baseline_path.is_file():
                raise ValueError("Zuerst die allgemeine Linux-Baseline auswerten")
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            raw_control_ids = body.get("control_ids")
            if not isinstance(raw_control_ids, list):
                raise TypeError("Baseline-Auswahl fehlt")
            plan = build_baseline_hardening_plan(
                baseline,
                str(body.get("role", "general-server")),
                [str(item) for item in raw_control_ids],
            )
            plan_path = data_home() / "reports" / f"{target_name}-baseline-plan.json"
            temporary = plan_path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            os.chmod(temporary, 0o600)
            temporary.replace(plan_path)
            self._json({**plan, "report_path": str(plan_path)})

        def _general_linux_baseline_package(self, body: dict[str, Any]) -> None:
            if body.get("confirm_generation") is not True:
                raise ValueError("Paketerstellung muss ausdrücklich bestätigt werden")
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            baseline_path = data_home() / "reports" / f"{target.name}-general-baseline.json"
            if not baseline_path.is_file():
                raise ValueError("Zuerst die allgemeine Linux-Baseline auswerten")
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            raw_control_ids = body.get("control_ids")
            if not isinstance(raw_control_ids, list):
                raise TypeError("Baseline-Auswahl fehlt")
            plan = build_baseline_hardening_plan(
                baseline,
                str(body.get("role", "general-server")),
                [str(item) for item in raw_control_ids],
            )
            if plan["conflicts"]:
                raise ValueError("Blockierende Konflikte müssen vor dem Export aufgelöst werden")
            if plan["reviews"] and body.get("confirm_reviews") is not True:
                raise ValueError("Rollenabhängige Hinweise müssen zuerst bestätigt werden")
            if not plan["rule_ids"]:
                raise ValueError(
                    "Die Auswahl enthält keine aktuell fehlgeschlagene automatisierbare Regel"
                )
            report_path = data_home() / "reports" / f"{target.name}-openscap.json"
            if not report_path.is_file():
                raise ValueError("Zuerst den OpenSCAP-Full-Scan ausführen")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            profile = str(report.get("profile", ""))
            data_stream = str(report.get("data_stream", ""))
            report, selected = _validated_policy_selection(
                target.name, profile, data_stream, plan["rule_ids"]
            )
            generated = generate_selected_scap_remediation(
                target,
                profile,
                data_stream,
                [str(item["id"]) for item in selected],
                [
                    str(item["id"])
                    for item in report.get("results", [])
                    if isinstance(item, dict) and item.get("id")
                ],
            )
            if generated["status"] == "privilege_required":
                self._json({**generated, "connection_refreshed": connection_refreshed})
                return
            inventory = collect_inventory(target)
            guideline = guideline_status(inventory)
            ai_setup_path = data_home() / "reports" / f"{target.name}-ai-baseline-setups.json"
            ai_setup_report = None
            if ai_setup_path.is_file():
                with suppress(OSError, json.JSONDecodeError):
                    loaded = json.loads(ai_setup_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        ai_setup_report = loaded
            directory = _write_native_policy_bundle(
                state.output_root,
                target,
                asdict(inventory.platform),
                profile,
                data_stream,
                report,
                str(generated["script"]),
                guideline["documents"],
                selected_rule_ids=[str(item["id"]) for item in selected],
                saved_profile_name=f"{plan['role_info']['title']} Baseline",
                tailoring_xml=str(generated["tailoring"]),
                tailoring_profile=str(generated["tailoring_profile"]),
                baseline_report=baseline,
                baseline_plan=plan,
                ai_setup_report=ai_setup_report,
            )
            delivery = str(body.get("delivery", "download"))
            warnings = [
                *[str(item) for item in generated.get("warnings", [])],
                "Restore ist dateibasiert; Snapshot/Backup bleibt für produktive Systeme nötig.",
            ]
            if delivery == "stage":
                staged = _stage_native_policy_bundle(target, directory)
                self._json(
                    {
                        "status": "staged",
                        "rules": len(selected),
                        "controls": len(plan["selected_control_ids"]),
                        "connection_refreshed": connection_refreshed,
                        **staged,
                        "warnings": warnings,
                    },
                    201,
                )
                return
            if delivery != "download":
                raise ValueError("Unbekannte Übergabeart")
            archive = _zip_bundle(directory)
            download_id = secrets.token_urlsafe(24)
            with state.lock:
                state.downloads[download_id] = archive
            self._json(
                {
                    "status": "created",
                    "download_id": download_id,
                    "filename": archive.name,
                    "rules": len(selected),
                    "controls": len(plan["selected_control_ids"]),
                    "connection_refreshed": connection_refreshed,
                    "warnings": warnings,
                },
                201,
            )

        def _audit(self, body: dict[str, Any]) -> None:
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            inventory = collect_inventory(target)
            path = save_inventory(inventory)
            self._json(
                {
                    "status": "completed",
                    "path": str(path),
                    "platform": asdict(inventory.platform),
                    "warnings": inventory.warnings,
                    "sections": sorted(inventory.sections),
                    "connection_refreshed": connection_refreshed,
                }
            )

        def _guidelines(self, body: dict[str, Any]) -> None:
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            inventory = collect_inventory(target)
            save_inventory(inventory)
            self._json(
                {
                    "status": "completed",
                    "guideline": guideline_status(inventory),
                    "warnings": inventory.warnings,
                    "connection_refreshed": connection_refreshed,
                }
            )

        def _review_guideline_sources(self, body: dict[str, Any]) -> None:
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            inventory = collect_inventory(target)
            guideline = guideline_status(inventory)
            job_id = _start_source_review_job(state, guideline)
            self._json(
                {
                    "status": "running",
                    "job_id": job_id,
                    "guideline": guideline,
                    "connection_refreshed": connection_refreshed,
                },
                202,
            )

        def _discover_guideline_sources(self, body: dict[str, Any]) -> None:
            scope = str(body.get("scope", "target"))
            connection_refreshed = False
            if scope == "target":
                target, connection_refreshed = _current_target(str(body.get("target", "")))
                inventory = collect_inventory(target)
                guideline = guideline_status(inventory)
                discovery = discover_official_guidelines(
                    inventory.platform.distribution, inventory.platform.version
                )
                discovery["candidates"] = [
                    {
                        **item,
                        "distribution": inventory.platform.distribution,
                        "version": inventory.platform.version,
                    }
                    for item in discovery["candidates"]
                ]
            else:
                if scope == "manual":
                    distribution = str(body.get("distribution", "")).strip()
                    version = str(body.get("version", "")).strip()
                    if not re.fullmatch(r"[A-Za-z0-9.*_-]{1,64}", version):
                        raise ValueError("Invalid distribution version")
                    platforms = [(distribution, version)]
                elif scope == "inventories":
                    platforms = []
                    inventory_root = data_home() / "inventories"
                    for path in sorted(inventory_root.glob("*.json"))[:50]:
                        raw = json.loads(path.read_text(encoding="utf-8"))
                        platform = raw.get("platform", {})
                        platforms.append(
                            (
                                str(platform.get("distribution", "")),
                                str(platform.get("version", "")),
                            )
                        )
                    if not platforms:
                        raise ValueError("No saved inventories are available")
                elif scope == "supported":
                    platforms = [
                        ("sles", "all"),
                        ("opensuse-leap", "all"),
                        ("debian", "all"),
                        ("ubuntu", "all"),
                        ("rhel", "all"),
                        ("rocky", "all"),
                        ("almalinux", "all"),
                        ("ol", "all"),
                    ]
                else:
                    raise ValueError("Unsupported guideline search scope")
                discovery = discover_guidelines_for_platforms(platforms)
                guideline = {
                    "platform": {
                        "family": "multi",
                        "distribution": "multiple",
                        "version": "multiple",
                        "pretty_name": "Mehrere Linux-Versionen",
                    },
                    "source_coverage": {
                        "gaps": [{"id": topic, "title": title} for topic, title in TOPICS.items()]
                    },
                }
            candidates = discovery["candidates"]
            advisor = OllamaAdvisor(model=state.model, base_url=state.ollama_url)
            job_id = (
                _start_discovery_review_job(state, guideline, candidates)
                if candidates and advisor.health()
                else None
            )
            self._json(
                {
                    "status": "completed",
                    "search": discovery,
                    "guideline": guideline,
                    "job_id": job_id,
                    "ai_status": "running" if job_id else "unavailable",
                    "connection_refreshed": connection_refreshed,
                }
            )

        def _install_compliance_scanner(self, body: dict[str, Any]) -> None:
            if body.get("confirm_install") is not True:
                raise ValueError("OpenSCAP installation requires explicit confirmation")
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            inventory = collect_inventory(target)
            before = guideline_status(inventory)
            if before["native_scanner"]["ready"]:
                result = {
                    "status": "already_available",
                    "scanner": "oscap/usg",
                    "guideline": before,
                    "refresh_required": False,
                }
            else:
                result = install_scanner(
                    target,
                    inventory.platform.distribution,
                    inventory.platform.version,
                )
                if result["status"] == "installed":
                    result["refresh_required"] = True
            result["connection_refreshed"] = connection_refreshed
            self._json(result)

        def _scan_compliance_profile(self, body: dict[str, Any]) -> None:
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            inventory = collect_inventory(target)
            guideline = guideline_status(inventory)
            scanner = guideline["native_scanner"]
            if not scanner["ready"]:
                raise ValueError("OpenSCAP scanner and compatible policy content are required")
            profile = str(body.get("profile", ""))
            data_stream = str(body.get("data_stream", ""))
            if profile not in scanner["profiles"]:
                raise ValueError("Selected OpenSCAP profile is not available on the target")
            if data_stream not in {item["path"] for item in scanner["data_streams"]}:
                raise ValueError("Selected OpenSCAP data stream is not available on the target")
            expected_stream = scanner["profile_streams"].get(profile)
            if expected_stream and data_stream != expected_stream:
                raise ValueError("Selected OpenSCAP profile belongs to a different data stream")
            scan = run_scap_scan(target, profile, data_stream)
            if scan["status"] == "privilege_required":
                scan["connection_refreshed"] = connection_refreshed
                self._json(scan)
                return
            guideline = integrate_scap_coverage(guideline, scan)
            report = {
                "schema_version": 1,
                "target": target.name,
                "generated_at": datetime.now(UTC).isoformat(),
                "platform": asdict(inventory.platform),
                "profile": profile,
                "data_stream": data_stream,
                "counts": scan["counts"],
                "results": scan["results"],
                "sources": guideline["documents"],
            }
            report_path = data_home() / "reports" / f"{target.name}-openscap.json"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = report_path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            os.chmod(temporary, 0o600)
            temporary.replace(report_path)
            self._json(
                {
                    **scan,
                    "guideline": guideline,
                    "report_path": str(report_path),
                    "connection_refreshed": connection_refreshed,
                }
            )

        def _scan_selected_compliance_rules(self, body: dict[str, Any]) -> None:
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            inventory = collect_inventory(target)
            guideline = guideline_status(inventory)
            scanner = guideline["native_scanner"]
            profile = str(body.get("profile", ""))
            data_stream = str(body.get("data_stream", ""))
            if profile not in scanner["profiles"]:
                raise ValueError("Selected OpenSCAP profile is not available on the target")
            if data_stream not in {item["path"] for item in scanner["data_streams"]}:
                raise ValueError("Selected OpenSCAP data stream is not available on the target")
            raw_rule_ids = body.get("rule_ids")
            if not isinstance(raw_rule_ids, list) or not raw_rule_ids:
                raise ValueError("Mindestens eine nicht ausgewählte Regel angeben")
            rule_ids = list(dict.fromkeys(str(item) for item in raw_rule_ids))
            if len(rule_ids) != len(raw_rule_ids) or len(rule_ids) > 500:
                raise ValueError("Ungültige oder zu grosse Regelauswahl")

            report_path = data_home() / "reports" / f"{target.name}-openscap.json"
            if not report_path.is_file():
                raise ValueError("Zuerst das vollständige OpenSCAP-Profil prüfen")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if report.get("profile") != profile or report.get("data_stream") != data_stream:
                raise ValueError("Die Auswahl gehört nicht zum zuletzt geprüften Profil")
            existing = {
                str(item.get("id")): item
                for item in report.get("results", [])
                if isinstance(item, dict)
            }
            invalid = [
                rule_id
                for rule_id in rule_ids
                if existing.get(rule_id, {}).get("status") not in {"notselected", "notchecked"}
            ]
            if invalid:
                raise ValueError(
                    "Nur noch nicht vom Profil geprüfte Regeln können zusätzlich geprüft werden"
                )

            selected_scan = run_scap_scan(target, profile, data_stream, rule_ids=rule_ids)
            if selected_scan["status"] == "privilege_required":
                selected_scan["connection_refreshed"] = connection_refreshed
                self._json(selected_scan)
                return
            merged_results, evaluated, unevaluated = _merge_requested_scap_results(
                list(existing.values()), selected_scan["results"], rule_ids
            )
            merged_counts = dict(Counter(item["status"] for item in merged_results))
            merged_scan = {
                **selected_scan,
                "results": merged_results,
                "counts": merged_counts,
                "supplemental_rules": evaluated,
                "supplemental_attempted": len(rule_ids),
                "unassessed_rules": len(unevaluated),
                "unassessed_rule_ids": unevaluated,
                "coverage_status": "partial" if unevaluated else "complete",
                "warnings": (
                    [
                        (
                            f"OpenSCAP konnte {len(unevaluated)} der ausgewählten "
                            "Zusatzregeln nicht technisch bewerten."
                        )
                    ]
                    if unevaluated
                    else []
                ),
            }
            guideline = integrate_scap_coverage(guideline, merged_scan)
            report.update(
                {
                    "generated_at": datetime.now(UTC).isoformat(),
                    "counts": merged_counts,
                    "results": merged_results,
                    "sources": guideline["documents"],
                }
            )
            temporary = report_path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            os.chmod(temporary, 0o600)
            temporary.replace(report_path)
            self._json(
                {
                    **merged_scan,
                    "guideline": guideline,
                    "report_path": str(report_path),
                    "connection_refreshed": connection_refreshed,
                }
            )

        def _build_native_policy_remediation(self, body: dict[str, Any]) -> None:
            if body.get("confirm_generation") is not True:
                raise ValueError("Native policy generation requires explicit confirmation")
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            inventory = collect_inventory(target)
            guideline = guideline_status(inventory)
            scanner = guideline["native_scanner"]
            profile = str(body.get("profile", ""))
            data_stream = str(body.get("data_stream", ""))
            if profile not in scanner["profiles"]:
                raise ValueError("Selected OpenSCAP profile is not available on the target")
            if data_stream not in {item["path"] for item in scanner["data_streams"]}:
                raise ValueError("Selected OpenSCAP data stream is not available on the target")
            expected_stream = scanner["profile_streams"].get(profile)
            if expected_stream and data_stream != expected_stream:
                raise ValueError("Selected OpenSCAP profile belongs to a different data stream")
            report_path = data_home() / "reports" / f"{target.name}-openscap.json"
            if not report_path.is_file():
                raise ValueError("Run the complete OpenSCAP profile audit before generating fixes")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if report.get("profile") != profile or report.get("data_stream") != data_stream:
                raise ValueError("The latest OpenSCAP report belongs to a different profile")
            generated_fix = generate_scap_remediation(target, profile, data_stream)
            directory = _write_native_policy_bundle(
                state.output_root,
                target,
                asdict(inventory.platform),
                profile,
                data_stream,
                report,
                generated_fix,
                guideline["documents"],
                baseline_report=_saved_general_baseline(target.name),
            )
            archive = _zip_bundle(directory)
            download_id = secrets.token_urlsafe(24)
            with state.lock:
                state.downloads[download_id] = archive
            self._json(
                {
                    "status": "created",
                    "download_id": download_id,
                    "filename": archive.name,
                    "profile": profile,
                    "generated_script_bytes": len(generated_fix.encode("utf-8")),
                    "connection_refreshed": connection_refreshed,
                    "warnings": [
                        "Vor Anwendung Snapshot/Backup und Konsolenzugang sicherstellen.",
                        "Für das vollständige OpenSCAP-Profil ist kein allgemeiner automatischer Rollback möglich.",
                    ],
                },
                201,
            )

        def _save_policy_profile(self, body: dict[str, Any]) -> None:
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            name = str(body.get("name", "")).strip()
            if not 2 <= len(name) <= 80:
                raise ValueError("Profilname muss zwischen 2 und 80 Zeichen lang sein")
            profile_id = re.sub(r"[^a-z0-9_.-]+", "-", name.lower()).strip("-.")[:64]
            if not POLICY_PROFILE_ID_PATTERN.fullmatch(profile_id):
                raise ValueError("Aus dem Profilnamen konnte keine sichere ID erzeugt werden")
            base_profile = str(body.get("profile", ""))
            data_stream = str(body.get("data_stream", ""))
            report, selected = _validated_policy_selection(
                target.name,
                base_profile,
                data_stream,
                body.get("rule_ids"),
            )
            now = datetime.now(UTC).isoformat()
            profiles = load_policy_profiles()
            previous = next((item for item in profiles if item.get("id") == profile_id), None)
            saved = {
                "id": profile_id,
                "name": name,
                "target": target.name,
                "platform": report.get("platform", {}),
                "base_profile": base_profile,
                "data_stream": data_stream,
                "rules": selected,
                "rule_ids": [item["id"] for item in selected],
                "created_at": previous.get("created_at", now) if previous else now,
                "updated_at": now,
            }
            profiles = [item for item in profiles if item.get("id") != profile_id]
            profiles.append(saved)
            save_policy_profiles(profiles)
            self._json(
                {
                    "status": "saved",
                    "profile": saved,
                    "connection_refreshed": connection_refreshed,
                },
                201,
            )

        def _build_selected_policy_remediation(self, body: dict[str, Any]) -> None:
            if body.get("confirm_generation") is not True:
                raise ValueError("Die Paketerstellung muss ausdrücklich bestätigt werden")
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            profile = str(body.get("profile", ""))
            data_stream = str(body.get("data_stream", ""))
            report, selected = _validated_policy_selection(
                target.name,
                profile,
                data_stream,
                body.get("rule_ids"),
            )
            generated = generate_selected_scap_remediation(
                target,
                profile,
                data_stream,
                [item["id"] for item in selected],
                [
                    str(item["id"])
                    for item in report.get("results", [])
                    if isinstance(item, dict) and item.get("id")
                ],
            )
            if generated["status"] == "privilege_required":
                self._json({**generated, "connection_refreshed": connection_refreshed})
                return
            generation_warnings = [str(item) for item in generated.get("warnings", [])]
            inventory = collect_inventory(target)
            guideline = guideline_status(inventory)
            directory = _write_native_policy_bundle(
                state.output_root,
                target,
                asdict(inventory.platform),
                profile,
                data_stream,
                report,
                str(generated["script"]),
                guideline["documents"],
                selected_rule_ids=[item["id"] for item in selected],
                saved_profile_name=str(body.get("saved_profile_name", "")).strip() or None,
                tailoring_xml=str(generated["tailoring"]),
                tailoring_profile=str(generated["tailoring_profile"]),
                baseline_report=_saved_general_baseline(target.name),
            )
            delivery = str(body.get("delivery", "download"))
            if delivery not in {"download", "stage"}:
                raise ValueError("Unbekannte Übergabeart für das Hardening-Paket")
            if delivery == "stage":
                staged = _stage_native_policy_bundle(target, directory)
                self._json(
                    {
                        "status": "staged",
                        "rules": len(selected),
                        "connection_refreshed": connection_refreshed,
                        **staged,
                        "warnings": [
                            *generation_warnings,
                            "Das Paket wurde nur übertragen und noch nicht ausgeführt.",
                            "Vor der Ausführung Snapshot/Backup und Konsolenzugang sicherstellen.",
                        ],
                    },
                    201,
                )
                return
            archive = _zip_bundle(directory)
            download_id = secrets.token_urlsafe(24)
            with state.lock:
                state.downloads[download_id] = archive
            self._json(
                {
                    "status": "created",
                    "download_id": download_id,
                    "filename": archive.name,
                    "rules": len(selected),
                    "connection_refreshed": connection_refreshed,
                    "warnings": [
                        *generation_warnings,
                        "Nur die ausgewählten, erneut fehlgeschlagenen Regeln wurden aufgenommen.",
                        "Vor Anwendung Snapshot/Backup und Konsolenzugang sicherstellen.",
                    ],
                },
                201,
            )

        def _build_policy_report(self, body: dict[str, Any]) -> None:
            target, connection_refreshed = _current_target(str(body.get("target", "")))
            profile = str(body.get("profile", ""))
            data_stream = str(body.get("data_stream", ""))
            report_path = data_home() / "reports" / f"{target.name}-openscap.json"
            if not report_path.is_file():
                raise ValueError("Zuerst das vollständige OpenSCAP-Profil prüfen")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if report.get("profile") != profile or report.get("data_stream") != data_stream:
                raise ValueError("Der letzte Prüfbericht gehört zu einem anderen Herstellerprofil")
            raw_selected = body.get("selected_rule_ids", [])
            if not isinstance(raw_selected, list) or len(raw_selected) > 1000:
                raise ValueError("Ungültige Regelauswahl")
            selected_ids = {str(item) for item in raw_selected}
            failed_ids = {
                str(item.get("id"))
                for item in report.get("results", [])
                if isinstance(item, dict) and item.get("status") == "fail"
            }
            if not selected_ids.issubset(failed_ids):
                raise ValueError("Der Bericht darf nur aktuell fehlgeschlagene Regeln markieren")
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
            directory = state.output_root / f"{target.name}-policy-report-{stamp}"
            directory.mkdir(parents=True, exist_ok=False)
            exported = {**report, "selected_rule_ids": sorted(selected_ids)}
            json_path = directory / "manufacturer-benchmark-report.json"
            json_path.write_text(
                json.dumps(exported, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            baseline = _saved_general_baseline(target.name)
            baseline_path = directory / "general-linux-hardening-report.json"
            if baseline:
                baseline_path.write_text(
                    json.dumps(baseline, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
            rows = []
            for item in report.get("results", []):
                if not isinstance(item, dict):
                    continue
                rule_id = str(item.get("id", ""))
                rows.append(
                    "<tr>"
                    f"<td>{html.escape(str(item.get('status', 'unknown')))}</td>"
                    f"<td>{'Ja' if rule_id in selected_ids else 'Nein'}</td>"
                    f"<td>{html.escape(str(item.get('title') or item.get('short_id') or rule_id))}</td>"
                    f"<td><code>{html.escape(str(item.get('short_id') or rule_id))}</code></td>"
                    "</tr>"
                )
            html_path = directory / "manufacturer-benchmark-report.html"
            counts = report.get("counts", {})
            html_path.write_text(
                "<!doctype html><html lang='de'><meta charset='utf-8'>"
                "<title>Hersteller-Benchmark-Bericht</title><style>body{font:14px sans-serif;margin:2rem;"
                "color:#17313a}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd8dc;"
                "padding:.45rem;text-align:left}th{background:#edf5f6}code{font-size:12px}"
                ".summary{display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0}.summary b{padding:.5rem .7rem;"
                "background:#edf5f6;border-radius:.4rem}</style>"
                f"<h1>Hersteller-Benchmark: {html.escape(target.name)}</h1>"
                f"<p>Profil: <code>{html.escape(profile)}</code><br>Datenstrom: "
                f"<code>{html.escape(data_stream)}</code><br>Erstellt: "
                f"{html.escape(str(report.get('generated_at', '')))}</p><div class='summary'>"
                f"<b>Bestanden: {int(counts.get('pass', 0))}</b>"
                f"<b>Nicht bestanden: {int(counts.get('fail', 0))}</b>"
                f"<b>Nicht anwendbar: {int(counts.get('notapplicable', 0))}</b>"
                f"<b>Nicht ausgewählt/geprüft: {int(counts.get('notselected', 0)) + int(counts.get('notchecked', 0))}</b>"
                "</div>"
                "<table><thead><tr><th>Status</th><th>Für Maßnahme ausgewählt</th>"
                "<th>Regel</th><th>ID</th></tr></thead><tbody>"
                + "".join(rows)
                + "</tbody></table></html>\n",
                encoding="utf-8",
            )
            readme_path = directory / "README.txt"
            readme_path.write_text(
                "Linux Hardening Agent – Berichtspaket\n\n"
                "manufacturer-benchmark-report.html  Lesbarer vollständiger OpenSCAP-Bericht\n"
                "manufacturer-benchmark-report.json  Maschinenlesbarer OpenSCAP-Bericht\n"
                "general-linux-hardening-report.json  Separate ANSSI-/BSI-/NIST-Einordnung, falls vorhanden\n"
                "SHA256SUMS                         Prüfsummen aller enthaltenen Berichte\n",
                encoding="utf-8",
            )
            sums = []
            exported_paths = [json_path, html_path, readme_path]
            if baseline:
                exported_paths.append(baseline_path)
            for path in exported_paths:
                sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
            (directory / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
            archive = _zip_bundle(directory)
            download_id = secrets.token_urlsafe(24)
            with state.lock:
                state.downloads[download_id] = archive
            self._json(
                {
                    "status": "created",
                    "download_id": download_id,
                    "filename": archive.name,
                    "rules": len(report.get("results", [])),
                    "selected": len(selected_ids),
                    "connection_refreshed": connection_refreshed,
                },
                201,
            )

        def _vagrant_config(self, body: dict[str, Any]) -> None:
            vm_name = str(body.get("vm_name", ""))
            config = vagrant_ssh_config(vm_name, state.libvirt_uri)
            Target(
                name="vagrant-preview",
                host=str(config["host"]),
                user=str(config["user"]),
                port=int(config["port"]),
                identity_file=str(config["identity_file"]),
                vm_name=vm_name,
                libvirt_uri=state.libvirt_uri,
                vagrant_directory=str(config["directory"]),
                vagrant_machine=str(config["machine"]),
                vagrant_home=str(config.get("vagrant_home", "")) or None,
            )
            self._json({"status": "detected", "config": config})

        def _pull_model(self, body: dict[str, Any]) -> None:
            model = str(body.get("model", state.model))
            if not MODEL_PATTERN.fullmatch(model):
                raise ValueError("Unsafe Ollama model name")
            ollama = shutil.which("ollama")
            if not ollama:
                raise ValueError("Ollama CLI is not installed")
            result = subprocess.run(
                [ollama, "pull", model],
                text=True,
                capture_output=True,
                timeout=3600,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "Model download failed")
            self._json({"status": "available", "model": model})

        def _select_model(self, body: dict[str, Any]) -> None:
            model = str(body.get("model", ""))
            if not MODEL_PATTERN.fullmatch(model):
                raise ValueError("Unsafe Ollama model name")
            advisor = OllamaAdvisor(model=model, base_url=state.ollama_url)
            installed = {item["name"] for item in advisor.models()}
            if model not in installed:
                raise ValueError(f"Ollama model is not installed: {model}")
            with state.lock:
                if any(
                    item.get("status") == "running" for item in state.recommendation_jobs.values()
                ):
                    raise ValueError("Model cannot be changed while Qwen is analyzing")
                state.model = model
                state.ai_state = "ready"
                state.ai_message = f"{model} ist ausgewählt"
            self._json({"status": "selected", "model": model})

    return Handler


def serve_gui(
    host: str = "127.0.0.1",
    port: int = 8765,
    output_root: Path | None = None,
    model: str = "qwen3:14b",
    ollama_url: str = "http://127.0.0.1:11434",
    libvirt_uri: str = "qemu:///system",
    open_browser: bool = True,
    allow_root: bool = False,
    allow_remote: bool = False,
) -> None:
    if os.geteuid() == 0 and not allow_root:
        raise RuntimeError(
            "Refusing to run the GUI as root. Exit su and run it as the operator user. "
            "Use --allow-root only for isolated troubleshooting."
        )
    if host not in {"127.0.0.1", "::1", "localhost"} and not allow_remote:
        raise RuntimeError("Remote GUI binding requires --allow-remote")
    if not 1 <= port <= 65535:
        raise ValueError("GUI port must be between 1 and 65535")
    if not MODEL_PATTERN.fullmatch(model):
        raise ValueError("Unsafe Ollama model name")
    root = (output_root or Path.cwd() / "output").expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    state = WebState(
        token=secrets.token_urlsafe(32),
        output_root=root,
        model=model,
        ollama_url=ollama_url,
        libvirt_uri=libvirt_uri,
        bind_host=host,
    )
    server = ThreadingHTTPServer((host, port), _handler(state))
    url = f"http://{host}:{port}"
    print(f"Linux Hardening Agent GUI: {url}")
    print("Press Ctrl+C to stop. The GUI does not need root privileges.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nGUI stopped")
    finally:
        server.server_close()
