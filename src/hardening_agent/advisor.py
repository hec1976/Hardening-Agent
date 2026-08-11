from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class AdvisorError(RuntimeError):
    pass


SOURCE_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "missing_categories": {"type": "array", "items": {"type": "string"}},
        "suggestions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "category": {"type": "string"},
                    "search_terms": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["category", "search_terms", "reason"],
            },
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "missing_categories", "suggestions", "warnings"],
}

SOURCE_DISCOVERY_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "recommendations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "candidate_index": {"type": "integer"},
                    "categories": {"type": "array", "items": {"type": "string"}},
                    "reason": {"type": "string"},
                },
                "required": ["candidate_index", "categories", "reason"],
            },
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "recommendations", "warnings"],
}

HARDENING_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "profile_name": {"type": "string"},
        "recommendations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string"},
                    "priority": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "disposition": {
                        "type": "string",
                        "enum": ["recommend", "review", "defer"],
                    },
                    "reason": {"type": "string"},
                    "operational_impact": {"type": "string"},
                    "validation": {"type": "string"},
                },
                "required": [
                    "rule_id",
                    "priority",
                    "disposition",
                    "reason",
                    "operational_impact",
                    "validation",
                ],
            },
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "profile_name", "recommendations", "warnings"],
}

BASELINE_SETUP_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "recommendation": {
            "type": "string",
            "enum": ["apply", "review", "keep", "not_recommended"],
        },
        "settings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "value": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["name", "value", "reason"],
            },
        },
        "prerequisites": {"type": "array", "items": {"type": "string"}},
        "operational_impact": {"type": "string"},
        "validation_steps": {"type": "array", "items": {"type": "string"}},
        "rollback_steps": {"type": "array", "items": {"type": "string"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "summary",
        "recommendation",
        "settings",
        "prerequisites",
        "operational_impact",
        "validation_steps",
        "rollback_steps",
        "warnings",
    ],
}


class OllamaAdvisor:
    def __init__(
        self,
        model: str = "qwen3:14b",
        base_url: str = "http://127.0.0.1:11434",
        timeout: int = 180,
        total_timeout: int | None = None,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.total_timeout = total_timeout

    def health(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=3) as response:
                return response.status == 200
        except (OSError, urllib.error.URLError):
            return False

    def models(self) -> list[dict[str, Any]]:
        try:
            with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise AdvisorError(f"Cannot list Ollama models: {exc}") from exc
        result = []
        for item in payload.get("models", []):
            result.append(
                {
                    "name": str(item.get("name", "")),
                    "size": int(item.get("size", 0)),
                    "modified_at": str(item.get("modified_at", "")),
                }
            )
        return result

    def review_sources(
        self,
        platform: dict[str, str],
        documents: list[dict[str, Any]],
        coverage: dict[str, Any],
    ) -> dict[str, Any]:
        system = (
            "You review Linux hardening source coverage using only supplied metadata. "
            "Do not invent URLs, citations, commands, or claims that a document was read. "
            "Identify missing categories and propose official-vendor search terms for human review."
        )
        request_data = {
            "model": self.model,
            "stream": False,
            "think": False,
            "format": SOURCE_REVIEW_SCHEMA,
            "options": {"temperature": 0, "num_ctx": 8192, "num_predict": 1024},
            "messages": [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": json.dumps(
                        {"platform": platform, "documents": documents, "coverage": coverage},
                        ensure_ascii=False,
                    )
                    + "\n/no_think",
                },
            ],
        }
        request = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(request_data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            content = payload.get("message", {}).get("content", "")
            result = json.loads(content)
        except (OSError, urllib.error.URLError, json.JSONDecodeError, AttributeError) as exc:
            raise AdvisorError(f"Ollama source review failed: {exc}") from exc
        if not isinstance(result, dict):
            raise AdvisorError("Ollama returned an invalid source review")
        return result

    def review_discovered_sources(
        self,
        platform: dict[str, str],
        candidates: list[dict[str, str]],
        missing_categories: list[str],
    ) -> dict[str, Any]:
        system = (
            "You classify search results from allowlisted official Linux vendor domains. "
            "Use only the supplied titles, URLs, and platform. Never claim page contents were read. "
            "Recommend only plausible hardening or compliance documents and map category IDs from "
            "the supplied missing_categories list. Return candidate indices, never new URLs."
        )
        request_data = {
            "model": self.model,
            "stream": False,
            "think": False,
            "format": SOURCE_DISCOVERY_SCHEMA,
            "options": {"temperature": 0, "num_ctx": 8192, "num_predict": 1024},
            "messages": [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "platform": platform,
                            "missing_categories": missing_categories,
                            "candidates": [
                                {"candidate_index": index, **candidate}
                                for index, candidate in enumerate(candidates)
                            ],
                        },
                        ensure_ascii=False,
                    )
                    + "\n/no_think",
                },
            ],
        }
        request = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(request_data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            content = payload.get("message", {}).get("content", "")
            result = json.loads(content)
        except (OSError, urllib.error.URLError, json.JSONDecodeError, AttributeError) as exc:
            raise AdvisorError(f"Ollama guideline discovery review failed: {exc}") from exc
        if not isinstance(result, dict):
            raise AdvisorError("Ollama returned an invalid guideline discovery review")
        return result

    def prioritize_hardening(
        self,
        platform: dict[str, str],
        failed_rules: list[dict[str, str]],
        security_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        system = (
            "Du priorisierst ausschliesslich die gelieferten, durch OpenSCAP als fail bewerteten "
            "Linux-Hardening-Regeln. Antworte auf Deutsch. Verwende nur exakt gelieferte rule_id-"
            "Werte und erfinde weder Regeln, Systemzustände, Befehle noch Quellen. Berücksichtige "
            "Sperr-, Netzwerk-, Boot- und Verfügbarkeitsrisiken. 'recommend' bedeutet: für einen "
            "allgemeinen Server sinnvoll und mit überschaubarem Risiko; 'review' verlangt eine "
            "bewusste Betreiberentscheidung; 'defer' ist ohne weitere Systemkenntnis nicht zu "
            "empfehlen. Gib höchstens 8 priorisierte Empfehlungen zurück und formuliere reason, "
            "operational_impact und validation jeweils in einem kurzen Satz. OpenSCAP bleibt die "
            "einzige Quelle ausführbarer Massnahmen."
        )
        request_data = {
            "model": self.model,
            "stream": False,
            "think": False,
            "format": HARDENING_REVIEW_SCHEMA,
            "keep_alive": "10m",
            "options": {"temperature": 0, "num_ctx": 4096, "num_predict": 3072},
            "messages": [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "platform": platform,
                            "failed_rules": failed_rules,
                            "security_context": security_context or {},
                        },
                        ensure_ascii=False,
                    )
                    + "\n/no_think",
                },
            ],
        }
        request = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(request_data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            content = payload.get("message", {}).get("content", "")
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                repair_data = {
                    "model": self.model,
                    "stream": False,
                    "think": False,
                    "format": HARDENING_REVIEW_SCHEMA,
                    "keep_alive": "10m",
                    "options": {"temperature": 0, "num_ctx": 4096, "num_predict": 3072},
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "Repariere die folgende abgeschnittene oder ungültige JSON-Antwort. "
                                "Gib nur ein vollständiges JSON-Objekt gemäss Schema zurück. "
                                "Höchstens 8 Empfehlungen; keine neuen rule_id-Werte."
                            ),
                        },
                        {"role": "user", "content": str(content)[:12000] + "\n/no_think"},
                    ],
                }
                repair_request = urllib.request.Request(
                    f"{self.base_url}/api/chat",
                    data=json.dumps(repair_data).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(repair_request, timeout=self.timeout) as response:
                    repaired = json.loads(response.read().decode("utf-8"))
                result = json.loads(repaired.get("message", {}).get("content", ""))
        except json.JSONDecodeError as exc:
            raise AdvisorError(
                "Ollama lieferte trotz automatischem Reparaturversuch eine unvollständige Antwort"
            ) from exc
        except (OSError, urllib.error.URLError, AttributeError) as exc:
            raise AdvisorError(f"Ollama hardening review failed: {exc}") from exc
        if not isinstance(result, dict):
            raise AdvisorError("Ollama returned an invalid hardening review")
        return result

    def design_baseline_setup(
        self,
        platform: dict[str, str],
        control: dict[str, Any],
    ) -> dict[str, Any]:
        system = (
            "Du erstellst auf Deutsch einen sicheren, distributions- und versionsbezogenen "
            "Setup-Entwurf für genau eine gelieferte Linux-Baseline-Kontrolle. Verwende nur den "
            "gelieferten Prüfstatus, die gelieferten OpenSCAP-Regeln und Referenz-IDs. Erfinde "
            "keine Systemzustände oder Quellen. settings enthält konkrete Konfigurationsparameter "
            "und Sollwerte, aber keine Shell-Befehle. Berücksichtige Aussperrung, Netzwerk, Boot, "
            "Verfügbarkeit und Serverrolle. Bei status=pass soll die bestehende wirksame Einstellung "
            "beibehalten und validiert werden. Bei manual oder not_covered ist eine Betreiberprüfung "
            "erforderlich. Formuliere kompakt und liefere höchstens 8 Settings sowie je 6 Prüf- und "
            "Rollback-Schritte."
        )
        request_data = {
            "model": self.model,
            "stream": False,
            "think": False,
            "format": BASELINE_SETUP_SCHEMA,
            "keep_alive": "10m",
            "options": {"temperature": 0, "num_ctx": 4096, "num_predict": 2048},
            "messages": [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": json.dumps(
                        {"platform": platform, "control": control}, ensure_ascii=False
                    )
                    + "\n/no_think",
                },
            ],
        }
        request = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(request_data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            content = payload.get("message", {}).get("content", "")
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                repair_data = {
                    "model": self.model,
                    "stream": False,
                    "think": False,
                    "format": BASELINE_SETUP_SCHEMA,
                    "keep_alive": "10m",
                    "options": {"temperature": 0, "num_ctx": 4096, "num_predict": 2048},
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "Repariere die folgende ungültige JSON-Antwort. Gib nur ein "
                                "vollständiges JSON-Objekt gemäss Schema zurück; keine Befehle."
                            ),
                        },
                        {"role": "user", "content": str(content)[:10000] + "\n/no_think"},
                    ],
                }
                repair_request = urllib.request.Request(
                    f"{self.base_url}/api/chat",
                    data=json.dumps(repair_data).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(repair_request, timeout=self.timeout) as response:
                    repaired = json.loads(response.read().decode("utf-8"))
                result = json.loads(repaired.get("message", {}).get("content", ""))
        except json.JSONDecodeError as exc:
            raise AdvisorError(
                "Ollama lieferte trotz Reparaturversuch einen unvollständigen Baseline-Entwurf"
            ) from exc
        except (OSError, urllib.error.URLError, AttributeError) as exc:
            raise AdvisorError(f"Ollama Baseline-Setup fehlgeschlagen: {exc}") from exc
        if not isinstance(result, dict):
            raise AdvisorError("Ollama lieferte keinen gültigen Baseline-Setup-Entwurf")
        return result
