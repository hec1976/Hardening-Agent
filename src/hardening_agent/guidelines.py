from __future__ import annotations

import base64
import binascii
import html
import json
import os
import re
import shlex
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, date, datetime
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import parse_qs, quote_plus, unquote, urlparse
from urllib.request import Request, urlopen
from xml.etree import ElementTree

from .config import custom_guidelines_path
from .models import Inventory, Target
from .scap_content import install_official_datastream
from .transport import Transport

TOPICS = {
    "accounts": "Benutzer, Passwörter und PAM",
    "audit": "Audit-Protokollierung",
    "filesystem": "Dateisysteme und Mount-Optionen",
    "kernel": "Kernel und sysctl",
    "logging": "Systemprotokollierung",
    "lsm": "AppArmor oder SELinux",
    "network": "Netzwerk und Firewall",
    "services": "Dienste und minimale Pakete",
    "ssh": "SSH-Zugriff",
    "sudo": "Privilegien und sudo",
    "system": "Updates und Systempflege",
}

SOURCE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,127}$")
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9.*_-]{1,64}$")
SEARCH_LINK_PATTERN = re.compile(
    r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
TAG_PATTERN = re.compile(r"<[^>]+>")

OFFICIAL_DOMAINS = {
    "sles": ("documentation.suse.com",),
    "sled": ("documentation.suse.com",),
    "opensuse-leap": ("documentation.suse.com", "doc.opensuse.org"),
    "opensuse-tumbleweed": ("documentation.suse.com", "doc.opensuse.org"),
    "debian": ("debian.org",),
    "ubuntu": ("documentation.ubuntu.com", "ubuntu.com"),
    "rhel": ("docs.redhat.com", "access.redhat.com"),
    "rocky": ("docs.rockylinux.org", "docs.redhat.com"),
    "almalinux": ("wiki.almalinux.org", "docs.redhat.com"),
    "ol": ("docs.oracle.com",),
}


def _official_url(url: str, domains: tuple[str, ...]) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and any(
        host == domain or host.endswith(f".{domain}") for domain in domains
    )


def _search_result_url(value: str) -> str:
    decoded = html.unescape(value)
    if decoded.startswith("//"):
        decoded = f"https:{decoded}"
    elif decoded.startswith("/"):
        decoded = f"https://duckduckgo.com{decoded}"
    parsed = urlparse(decoded)
    if parsed.hostname and parsed.hostname.endswith("duckduckgo.com"):
        target = parse_qs(parsed.query).get("uddg", [""])[0]
        return unquote(target)
    return decoded


def _search_official_domain(
    distribution: str, version: str, domain: str, timeout: int
) -> list[dict[str, str]]:
    version_term = "" if version in {"*", "all"} else f' "{version}"'
    query = (
        f'site:{domain} "{distribution}"{version_term} '
        '("security hardening" OR OpenSCAP OR compliance OR STIG OR CIS OR AppArmor)'
    )
    request = Request(
        f"https://html.duckduckgo.com/html/?q={quote_plus(query)}",
        headers={"User-Agent": "Linux-Hardening-Agent/0.9 (+local guideline discovery)"},
    )
    with urlopen(request, timeout=timeout) as response:
        page = response.read(1_500_000).decode("utf-8", errors="replace")
    results = []
    for link, raw_title in SEARCH_LINK_PATTERN.findall(page):
        url = _search_result_url(link)
        if not _official_url(url, (domain,)):
            continue
        title = html.unescape(TAG_PATTERN.sub("", raw_title)).strip()
        if title:
            results.append({"title": title[:300], "url": url[:2000], "domain": domain})
    return results[:25]


def discover_official_guidelines(
    distribution: str, version: str, timeout: int = 15
) -> dict[str, Any]:
    domains = OFFICIAL_DOMAINS.get(distribution)
    if not domains:
        raise ValueError(f"Keine offizielle Domainliste für {distribution} definiert")
    errors = []
    discovered: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=min(3, len(domains))) as executor:
        jobs = {
            executor.submit(_search_official_domain, distribution, version, domain, timeout): domain
            for domain in domains
        }
        for job, domain in jobs.items():
            try:
                discovered.extend(job.result())
            except (OSError, URLError, TimeoutError) as exc:
                errors.append(f"{domain}: {exc}")
    unique = {item["url"]: item for item in discovered}
    return {
        "distribution": distribution,
        "version": version,
        "allowed_domains": list(domains),
        "candidates": list(unique.values())[:30],
        "warnings": errors,
    }


def discover_guidelines_for_platforms(
    platforms: list[tuple[str, str]], timeout: int = 15
) -> dict[str, Any]:
    unique_platforms = list(dict.fromkeys(platforms))[:20]
    if not any(distribution in OFFICIAL_DOMAINS for distribution, _version in unique_platforms):
        raise ValueError("Keine unterstützte Distribution für die Online-Suche gefunden")
    candidates = []
    warnings = []
    with ThreadPoolExecutor(max_workers=min(4, len(unique_platforms) or 1)) as executor:
        jobs = {
            executor.submit(discover_official_guidelines, distribution, version, timeout): (
                distribution,
                version,
            )
            for distribution, version in unique_platforms
            if distribution in OFFICIAL_DOMAINS
        }
        for job, (distribution, version) in jobs.items():
            try:
                result = job.result()
                candidates.extend(
                    {**item, "distribution": distribution, "version": version}
                    for item in result["candidates"]
                )
                warnings.extend(result["warnings"])
            except (OSError, URLError, TimeoutError, ValueError) as exc:
                warnings.append(f"{distribution} {version}: {exc}")
    unique_candidates = {item["url"]: item for item in candidates}
    return {
        "platforms": [
            {"distribution": distribution, "version": version}
            for distribution, version in unique_platforms
        ],
        "candidates": list(unique_candidates.values())[:60],
        "warnings": warnings,
    }


def _source_document(
    source_id: str,
    publisher: str,
    title: str,
    url: str,
    scope: str,
    distribution: str,
    version_pattern: str,
    categories: list[str],
) -> dict[str, Any]:
    return {
        "id": source_id,
        "publisher": publisher,
        "title": title,
        "url": url,
        "scope": scope,
        "distribution": distribution,
        "version_pattern": version_pattern,
        "categories": categories,
        "reviewed": "2026-08-11",
        "enabled": True,
        "custom": False,
    }


SOURCES: dict[str, dict[str, Any]] = {
    "suse": {
        "vendor": "SUSE",
        "framework": "OpenSCAP + SCAP Security Guide",
        "tool": "oscap",
        "documents": [
            _source_document(
                "suse.security.15",
                "SUSE",
                "SUSE Security and Hardening Guide",
                "https://documentation.suse.com/sles/15-SP7/html/SLES-all/book-security.html",
                "SLES 15 SP7; bei openSUSE muss die Übertragbarkeit geprüft werden",
                "*",
                "15*",
                list(TOPICS),
            ),
            _source_document(
                "suse.openscap.15",
                "SUSE",
                "Hardening SLES with OpenSCAP",
                "https://documentation.suse.com/sles/15-SP7/html/SLES-all/article-openscap.html",
                "SLES 15 und unterstützte SCAP-Profile",
                "*",
                "15*",
                list(TOPICS),
            ),
        ],
        "install_hint": "Auf dem Zielsystem: openscap-utils und scap-security-guide bereitstellen.",
    },
    "rhel": {
        "vendor": "Red Hat / kompatibler Hersteller",
        "framework": "OpenSCAP + SCAP Security Guide",
        "tool": "oscap",
        "documents": [
            _source_document(
                "rhel.security.9",
                "Red Hat",
                "RHEL Security hardening",
                "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/index",
                "RHEL 9; Derivate müssen ihre Versionspassung bestätigen",
                "*",
                "9*",
                list(TOPICS),
            )
        ],
        "install_hint": "Auf dem Zielsystem: openscap-scanner und scap-security-guide bereitstellen.",
    },
    "debian": {
        "vendor": "Debian oder Canonical",
        "framework": "Ubuntu USG oder distributionsbezogene SCAP-Inhalte",
        "tool": "oscap/usg",
        "documents": [
            _source_document(
                "ubuntu.usg",
                "Canonical",
                "Ubuntu Security Guide – Compliance",
                "https://documentation.ubuntu.com/security/compliance/usg/cis-benchmarks/",
                "Ubuntu mit passender USG-Lizenz und Benchmark-Version",
                "ubuntu",
                "*",
                list(TOPICS),
            ),
            _source_document(
                "debian.securing",
                "Debian",
                "Debian Securing Manual",
                "https://www.debian.org/doc/manuals/securing-debian-manual/index.en.html",
                "Teile sind historisch und müssen gegen die aktuelle Version geprüft werden",
                "debian",
                "*",
                ["accounts", "filesystem", "network", "services", "ssh", "system"],
            ),
        ],
        "install_hint": "Ubuntu: USG verwenden. Debian: aktuelle Pakete und SCAP-Inhalte separat prüfen.",
    },
}


def validate_guideline_source(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise TypeError("Herstellerquelle muss ein Objekt sein")
    required = {
        "id",
        "publisher",
        "title",
        "url",
        "distribution",
        "version_pattern",
        "scope",
        "categories",
        "reviewed",
        "enabled",
    }
    missing = sorted(required - raw.keys())
    if missing:
        raise ValueError(f"Herstellerquelle unvollständig: {', '.join(missing)}")
    result = {key: raw[key] for key in required}
    for field in (
        "id",
        "publisher",
        "title",
        "url",
        "distribution",
        "version_pattern",
        "scope",
        "reviewed",
    ):
        if not isinstance(result[field], str) or not result[field].strip():
            raise ValueError(f"Herstellerquelle: {field} fehlt")
        result[field] = result[field].strip()
    if not SOURCE_ID_PATTERN.fullmatch(result["id"]):
        raise ValueError("Ungültige Quellen-ID")
    if not VERSION_PATTERN.fullmatch(result["version_pattern"]):
        raise ValueError(
            "Versionsmuster darf nur Zahlen, Buchstaben, Punkt, Stern, _ und - enthalten"
        )
    parsed = urlparse(result["url"])
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Herstellerquelle benötigt eine HTTPS-URL")
    try:
        date.fromisoformat(result["reviewed"])
    except ValueError as exc:
        raise ValueError("Prüfdatum muss YYYY-MM-DD sein") from exc
    categories = result["categories"]
    if not isinstance(categories, list) or not set(categories) <= set(TOPICS):
        raise ValueError("Ungültige automatisch ermittelte Kategorien")
    result["categories"] = list(dict.fromkeys(categories))
    if not isinstance(result["enabled"], bool):
        raise TypeError("enabled muss true oder false sein")
    result["custom"] = True
    return result


def load_custom_guideline_sources() -> list[dict[str, Any]]:
    path = custom_guidelines_path()
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise TypeError("Ungültige Herstellerquellen-Datei")
    return [validate_guideline_source(item) for item in raw]


def save_guideline_source(raw: Any, original_id: str | None = None) -> dict[str, Any]:
    source = validate_guideline_source(raw)
    sources = load_custom_guideline_sources()
    if original_id:
        sources = [item for item in sources if item["id"] != original_id]
    elif any(item["id"] == source["id"] for item in sources):
        raise ValueError("Quellen-ID existiert bereits")
    sources.append(source)
    path = custom_guidelines_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(sources, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return source


def delete_guideline_source(source_id: str) -> None:
    if not SOURCE_ID_PATTERN.fullmatch(source_id):
        raise ValueError("Ungültige Quellen-ID")
    sources = load_custom_guideline_sources()
    remaining = [item for item in sources if item["id"] != source_id]
    if len(remaining) == len(sources):
        raise ValueError("Herstellerquelle nicht gefunden")
    path = custom_guidelines_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(remaining, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def guideline_sources_for(inventory: Inventory) -> list[dict[str, Any]]:
    source = SOURCES.get(inventory.platform.family)
    candidates = {item["id"]: item for item in (source["documents"] if source else [])}
    for item in load_custom_guideline_sources():
        candidates[item["id"]] = item
    result = []
    for item in candidates.values():
        distribution_matches = item.get("distribution", "*") in {
            "*",
            inventory.platform.distribution,
        }
        version_matches = fnmatchcase(inventory.platform.version, item.get("version_pattern", "*"))
        if distribution_matches and version_matches and item.get("enabled", True):
            result.append(item)
    return result


def all_guideline_sources() -> list[dict[str, Any]]:
    built_in = [document for source in SOURCES.values() for document in source["documents"]]
    unique = {item["id"]: item for item in built_in}
    for item in load_custom_guideline_sources():
        unique[item["id"]] = item
    return sorted(unique.values(), key=lambda item: (item["publisher"], item["title"]))


INSTALL_PLANS = {
    "sles": {
        "packages": ["openscap-utils", "scap-security-guide"],
        "command": "sudo zypper --non-interactive install --no-recommends openscap-utils scap-security-guide",
    },
    "sled": {
        "packages": ["openscap-utils", "scap-security-guide"],
        "command": "sudo zypper --non-interactive install --no-recommends openscap-utils scap-security-guide",
    },
    "opensuse-leap": {
        "packages": ["openscap-utils", "scap-security-guide"],
        "command": "sudo zypper --non-interactive install --no-recommends openscap-utils scap-security-guide",
    },
    "opensuse-tumbleweed": {
        "packages": ["openscap-utils", "scap-security-guide"],
        "command": "sudo zypper --non-interactive install --no-recommends openscap-utils scap-security-guide",
    },
    "rhel": {
        "packages": ["openscap-scanner", "scap-security-guide"],
        "command": "sudo dnf -y install openscap-scanner scap-security-guide",
    },
    "rocky": {
        "packages": ["openscap-scanner", "scap-security-guide"],
        "command": "sudo dnf -y install openscap-scanner scap-security-guide",
    },
    "almalinux": {
        "packages": ["openscap-scanner", "scap-security-guide"],
        "command": "sudo dnf -y install openscap-scanner scap-security-guide",
    },
    "ol": {
        "packages": ["openscap-scanner", "scap-security-guide"],
        "command": "sudo dnf -y install openscap-scanner scap-security-guide",
    },
    "debian": {
        "packages": ["openscap-scanner", "ssg-debian"],
        "command": "sudo apt-get update && sudo apt-get -y install openscap-scanner ssg-debian",
    },
    "ubuntu": {
        "packages": ["openscap-scanner", "ssg-debderived"],
        "command": "sudo apt-get update && sudo apt-get -y install openscap-scanner ssg-debderived",
    },
}


def scanner_install_plan(distribution: str) -> dict[str, Any] | None:
    plan = INSTALL_PLANS.get(distribution)
    return dict(plan) if plan else None


def _valid_scap_data_stream(data_stream: str) -> bool:
    return (
        data_stream.startswith(("/usr/share/", "/usr/local/share/"))
        and data_stream.endswith(".xml")
    )


def install_scanner(target: Target, distribution: str, version: str = "") -> dict[str, Any]:
    plan = scanner_install_plan(distribution)
    if plan is None:
        raise ValueError(f"Keine sichere OpenSCAP-Installation für {distribution} definiert")
    if distribution in {"sles", "sled", "opensuse-leap", "opensuse-tumbleweed"}:
        package_command = (
            "$lha_priv zypper --non-interactive install --no-recommends "
            "openscap-utils scap-security-guide"
        )
    elif distribution in {"rhel", "rocky", "almalinux", "ol"}:
        package_command = "$lha_priv dnf -y install openscap-scanner scap-security-guide"
    elif distribution == "debian":
        package_command = (
            "$lha_priv apt-get update && $lha_priv apt-get -y install openscap-scanner ssg-debian"
        )
    else:
        package_command = (
            "$lha_priv apt-get update && "
            "$lha_priv apt-get -y install openscap-scanner ssg-debderived"
        )
    script = f"""
set -eu
export LC_ALL=C
if ! command -v oscap >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
        lha_priv=""
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        lha_priv="sudo -n"
    else
        echo '@@LHA_PRIVILEGE_REQUIRED@@'
        exit 77
    fi
    {package_command}
fi
command -v oscap >/dev/null 2>&1
printf '@@LHA_SCANNER_READY@@%s\n' "$(command -v oscap)"
"""
    result = Transport(target).run_script(script, timeout=600)
    if result.returncode == 77 or "@@LHA_PRIVILEGE_REQUIRED@@" in result.stdout:
        return {
            "status": "privilege_required",
            "command": plan["command"],
            "packages": plan["packages"],
        }
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-4000:]
        raise RuntimeError(detail or "OpenSCAP-Installation fehlgeschlagen")
    installed = {
        "status": "installed",
        "command": plan["command"],
        "packages": plan["packages"],
        "scanner": "oscap",
    }
    if distribution == "debian" and version.split(".", 1)[0] == "13":
        content = install_official_datastream(target, "debian13")
        if content["status"] == "privilege_required":
            return content
        installed["official_content"] = content
    return installed


SCAP_PROFILE_PATTERN = re.compile(r"^xccdf_[A-Za-z0-9_.-]{1,240}$")
SCAP_RESULT_PATTERN = re.compile(
    r"^(xccdf_[A-Za-z0-9_.-]*_rule_[A-Za-z0-9_.-]+):"
    r"(pass|fail|error|unknown|notapplicable|notchecked|notselected|informational|fixed)$"
)


def _scap_item_kind(item_id: str) -> str | None:
    """Classify by the first XCCDF type marker, not words in the item name."""
    positions = {
        "rule": item_id.find("_rule_"),
        "group": item_id.find("_group_"),
    }
    present = [(position, kind) for kind, position in positions.items() if position >= 0]
    return min(present)[1] if present else None
SCAP_XML_RESULT_PATTERN = re.compile(
    r"^@@LHA_RESULT@@(xccdf_[A-Za-z0-9_.-]*_rule_[A-Za-z0-9_.-]+)\|"
    r"(pass|fail|error|unknown|notapplicable|notchecked|notselected|informational|fixed)$"
)
SCAP_BLOCK_FIELD = re.compile(r"^(Title|Rule|Result)\s+(.+)$")
XCCDF_PAYLOAD_PATTERN = re.compile(
    r"@@LHA_XCCDF_GZIP_BEGIN@@\s*([A-Za-z0-9+/=\r\n]+?)\s*@@LHA_XCCDF_GZIP_END@@",
    re.DOTALL,
)
SCAP_STATUSES = {
    "pass",
    "fail",
    "error",
    "unknown",
    "notapplicable",
    "notchecked",
    "notselected",
    "informational",
    "fixed",
}
FULL_BENCHMARK_PROFILE = "xccdf_org.hardeningagent.content_profile_full_benchmark"
MAX_XCCDF_COMPRESSED = 16 * 1024 * 1024
MAX_XCCDF_XML = 64 * 1024 * 1024


def _rule_topic(rule_id: str) -> str | None:
    value = rule_id.lower()
    patterns = {
        "ssh": ("ssh", "sshd"),
        "audit": ("audit", "auditd"),
        "filesystem": ("mount", "partition", "filesystem", "file_permission"),
        "kernel": ("sysctl", "kernel", "module"),
        "logging": ("journald", "rsyslog", "log_"),
        "lsm": ("apparmor", "selinux"),
        "network": ("firewall", "nft", "network", "tcp_", "ip_forward"),
        "sudo": ("sudo",),
        "accounts": ("account", "password", "pam_", "shadow", "login"),
        "system": ("update", "patch", "crypto_policy", "time_"),
        "services": ("service_", "package_", "daemon"),
    }
    for topic, needles in patterns.items():
        if any(needle in value for needle in needles):
            return topic
    return None


def _parse_xccdf_payload(output: str) -> dict[str, dict[str, Any]]:
    match = XCCDF_PAYLOAD_PATTERN.search(output)
    if not match:
        return {}
    encoded = "".join(match.group(1).split())
    if len(encoded) > (MAX_XCCDF_COMPRESSED * 4 // 3) + 8:
        raise RuntimeError("Komprimiertes XCCDF-Ergebnis überschreitet die Sicherheitsgrenze")
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("XCCDF-Ergebnis wurde unvollständig übertragen") from exc
    if len(compressed) > MAX_XCCDF_COMPRESSED:
        raise RuntimeError("Komprimiertes XCCDF-Ergebnis überschreitet die Sicherheitsgrenze")
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        xml_data = decoder.decompress(compressed, MAX_XCCDF_XML + 1)
        if len(xml_data) > MAX_XCCDF_XML:
            raise RuntimeError("XCCDF-Ergebnis überschreitet die Sicherheitsgrenze")
        xml_data += decoder.flush(MAX_XCCDF_XML + 1 - len(xml_data))
    except zlib.error as exc:
        raise RuntimeError("Komprimiertes XCCDF-Ergebnis ist beschädigt") from exc
    if len(xml_data) > MAX_XCCDF_XML or not decoder.eof:
        raise RuntimeError("XCCDF-Ergebnis überschreitet die Sicherheitsgrenze")
    try:
        root = ElementTree.fromstring(xml_data)
    except ElementTree.ParseError as exc:
        raise RuntimeError("OpenSCAP lieferte eine ungültige XCCDF-Ergebnisdatei") from exc

    parsed: dict[str, dict[str, Any]] = {}
    for element in root.iter():
        if str(element.tag).rsplit("}", 1)[-1].rsplit(":", 1)[-1] != "rule-result":
            continue
        rule_id = str(element.attrib.get("idref", ""))
        if not SCAP_PROFILE_PATTERN.fullmatch(rule_id) or _scap_item_kind(rule_id) != "rule":
            continue
        status = ""
        for child in element:
            if str(child.tag).rsplit("}", 1)[-1].rsplit(":", 1)[-1] == "result":
                status = (child.text or "").strip().lower()
                break
        if status not in SCAP_STATUSES:
            continue
        short_id = rule_id.split("_rule_", 1)[-1]
        parsed[rule_id] = {
            "id": rule_id,
            "short_id": short_id,
            "title": short_id.replace("_", " ").replace("-", " ").capitalize(),
            "status": status,
            "topic": _rule_topic(short_id),
        }
    return parsed


def discover_scap_selectable_ids(target: Target, data_stream: str) -> list[str]:
    if not _valid_scap_data_stream(data_stream):
        raise ValueError("Ungültiger OpenSCAP-Datenstrom")
    quoted = shlex.quote(data_stream)
    script = (
        "export LC_ALL=C\n"
        f"test -r {quoted} || exit 2\n"
        f"grep -oE 'id=\"xccdf_[A-Za-z0-9_.-]+_(group|rule)_[A-Za-z0-9_.-]+\"' {quoted} "
        "| sed -E 's/^id=\"//; s/\"$//' | sort -u\n"
    )
    result = Transport(target).run_script(script, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "SCAP-Regeln konnten nicht gelesen werden")
    item_ids = [
        line.strip()
        for line in result.stdout.splitlines()
        if SCAP_PROFILE_PATTERN.fullmatch(line.strip())
        and _scap_item_kind(line.strip()) in {"rule", "group"}
    ]
    if not any(_scap_item_kind(item_id) == "rule" for item_id in item_ids):
        raise RuntimeError("Im SCAP-Datenstrom wurden keine Regeln gefunden")
    if len(item_ids) > 10_000:
        raise RuntimeError("Der SCAP-Datenstrom enthält unerwartet viele auswählbare Elemente")
    return item_ids


def discover_scap_rule_ids(target: Target, data_stream: str) -> list[str]:
    return [
        item_id
        for item_id in discover_scap_selectable_ids(target, data_stream)
        if _scap_item_kind(item_id) == "rule"
    ]


def run_scap_scan(
    target: Target,
    profile: str,
    data_stream: str,
    rule_ids: list[str] | None = None,
    replace_profile: bool = False,
) -> dict[str, Any]:
    if not SCAP_PROFILE_PATTERN.fullmatch(profile):
        raise ValueError("Ungültige OpenSCAP-Profil-ID")
    if not _valid_scap_data_stream(data_stream):
        raise ValueError("Ungültiger OpenSCAP-Datenstrom")
    selected = list(dict.fromkeys(rule_ids or []))
    selection_limit = 10_000 if replace_profile else 500
    if len(selected) > selection_limit or any(
        not SCAP_PROFILE_PATTERN.fullmatch(item_id)
        or _scap_item_kind(item_id) not in {"rule", "group"}
        for item_id in selected
    ):
        raise ValueError("Ungültige oder zu grosse OpenSCAP-Regelauswahl")
    tailoring_profile = FULL_BENCHMARK_PROFILE if replace_profile else "xccdf_org.hardeningagent.content_profile_selected"
    tailoring_setup = ""
    if selected:
        tailoring_time = datetime.now(UTC).replace(microsecond=0).isoformat()
        selections = "\n".join(
            f'    <xccdf:select idref="{html.escape(rule_id, quote=True)}" selected="true"/>'
            for rule_id in selected
        )
        profile_parent = "" if replace_profile else f' extends="{html.escape(profile, quote=True)}"'
        tailoring_title = "Vollständiger Benchmark" if replace_profile else "Temporäre read-only Zusatzauswahl"
        tailoring_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.hardeningagent.content_tailoring_selected">
  <xccdf:benchmark href="file://{html.escape(data_stream, quote=True)}"/>
  <xccdf:version time="{tailoring_time}">1</xccdf:version>
  <xccdf:Profile id="{tailoring_profile}"{profile_parent}>
    <xccdf:title xml:lang="de">{tailoring_title}</xccdf:title>
{selections}
  </xccdf:Profile>
</xccdf:Tailoring>
"""
        encoded_tailoring = base64.b64encode(tailoring_xml.encode()).decode()
        tailoring_setup = (
            f"printf '%s' {shlex.quote(encoded_tailoring)} | base64 -d >\"$lha_tailoring\"\n"
            "chmod 600 \"$lha_tailoring\""
        )
        scan_scope = (
            f"--profile {shlex.quote(tailoring_profile)} --tailoring-file \"$lha_tailoring\""
        )
    else:
        scan_scope = f"--profile {shlex.quote(profile)}"
    manual_command = (
        f"sudo oscap xccdf eval --profile {shlex.quote(profile)} "
        f"--results /tmp/hardening-agent-results.xml "
        f"{shlex.quote(data_stream)}"
    )
    script = f"""
set +e
export LC_ALL=C
if [ "$(id -u)" -eq 0 ]; then
    lha_priv=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    lha_priv="sudo -n"
else
    echo '@@LHA_PRIVILEGE_REQUIRED@@'
    exit 77
fi
lha_dir="$(mktemp -d /tmp/hardening-agent-scap.XXXXXX)" || exit 78
lha_results="$lha_dir/results.xml"
lha_log="$lha_dir/oscap.log"
lha_tailoring="$lha_dir/tailoring.xml"
{tailoring_setup}
$lha_priv oscap xccdf eval {scan_scope} --results "$lha_results" {shlex.quote(data_stream)} >"$lha_log" 2>&1
lha_rc=$?
printf '@@LHA_SCAP_RC@@%s\n' "$lha_rc"
cat "$lha_log"
if [ -s "$lha_results" ]; then
    if command -v gzip >/dev/null 2>&1 && command -v base64 >/dev/null 2>&1; then
        printf '@@LHA_XCCDF_GZIP_BEGIN@@\n'
        $lha_priv gzip -c "$lha_results" | base64 | tr -d '\n'
        printf '\n@@LHA_XCCDF_GZIP_END@@\n'
    fi
    $lha_priv cat "$lha_results" \
        | tr '\n' ' ' \
        | sed -E 's#</([^:>]+:)?rule-result>#&\n#g' \
        | sed -nE 's#.*<([^:>]+:)?rule-result[^>]*idref="([^"]+)".*<([^:>]+:)?result[^>]*>[[:space:]]*([^<[:space:]]+)[[:space:]]*</([^:>]+:)?result>.*#@@LHA_RESULT@@\\2|\\4#p'
fi
$lha_priv rm -rf -- "$lha_dir"
exit 0
"""
    command_result = Transport(target).run_script(script, timeout=900)
    if command_result.returncode == 77 or "@@LHA_PRIVILEGE_REQUIRED@@" in command_result.stdout:
        return {"status": "privilege_required", "command": manual_command}
    match = re.search(r"^@@LHA_SCAP_RC@@(\d+)$", command_result.stdout, re.MULTILINE)
    if not match:
        raise RuntimeError(command_result.stderr.strip() or "Keine OpenSCAP-Ausgabe erhalten")
    scan_exit = int(match.group(1))
    if scan_exit not in {0, 2}:
        detail = command_result.stdout.split("@@LHA_SCAP_RC@@", 1)[-1].strip()[-4000:]
        raise RuntimeError(detail or f"OpenSCAP-Scan fehlgeschlagen ({scan_exit})")
    parsed_results = _parse_xccdf_payload(command_result.stdout)
    current_title = ""
    current_rule = ""
    for line in command_result.stdout.splitlines():
        stripped = line.strip()
        progress = SCAP_XML_RESULT_PATTERN.fullmatch(stripped)
        if progress:
            rule_id, status = progress.groups()
            short_id = rule_id.split("_rule_", 1)[-1]
            previous = parsed_results.get(rule_id, {})
            parsed_results[rule_id] = {
                "id": rule_id,
                "short_id": short_id,
                "title": previous.get("title")
                or short_id.replace("_", " ").replace("-", " ").capitalize(),
                "status": status,
                "topic": previous.get("topic") or _rule_topic(short_id),
            }
            continue
        progress = SCAP_RESULT_PATTERN.fullmatch(stripped)
        if progress:
            rule_id, status = progress.groups()
            short_id = rule_id.split("_rule_", 1)[-1]
            parsed_results[rule_id] = {
                "id": rule_id,
                "short_id": short_id,
                "title": short_id.replace("_", " ").replace("-", " ").capitalize(),
                "status": status,
                "topic": _rule_topic(short_id),
            }
            continue
        field = SCAP_BLOCK_FIELD.fullmatch(stripped)
        if not field:
            continue
        name, value = field.groups()
        if name == "Title":
            current_title = value.strip()
        elif name == "Rule":
            current_rule = value.strip()
        elif name == "Result" and current_rule:
            status = value.strip().lower()
            if status not in SCAP_STATUSES:
                continue
            rule_id = current_rule
            short_id = rule_id.split("_rule_", 1)[-1]
            previous = parsed_results.get(rule_id, {})
            parsed_results[rule_id] = {
                "id": rule_id,
                "short_id": short_id,
                "title": current_title or short_id.replace("_", " ").capitalize(),
                "status": status,
                "topic": previous.get("topic") or _rule_topic(short_id),
            }
            current_title = ""
            current_rule = ""
    results = list(parsed_results.values())
    for item in results:
        rule_id = item["id"]
        short_id = rule_id.split("_rule_", 1)[-1]
        item["topic"] = item.get("topic") or _rule_topic(short_id)
    if not results:
        raise RuntimeError("OpenSCAP lieferte keine auswertbaren Regelresultate")
    counts = Counter(item["status"] for item in results)
    decisive = sum(counts.get(status, 0) for status in ("pass", "fail", "error", "unknown", "fixed"))
    applicability_status = "compatible"
    applicability_message = ""
    if decisive == 0 and counts.get("notapplicable", 0) >= max(1, int(len(results) * 0.8)):
        applicability_status = "incompatible"
        applicability_message = (
            "Der SCAP-Datenstrom passt wahrscheinlich nicht zu dieser Distribution oder Version: "
            "OpenSCAP hat keine einzige Regel fachlich bewertet. Aus diesem Ergebnis wird kein "
            "Hardening erzeugt."
        )
    return {
        "status": "completed",
        "profile": tailoring_profile if replace_profile else profile,
        "data_stream": data_stream,
        "results": results,
        "counts": dict(counts),
        "scan_exit": scan_exit,
        "applicability_status": applicability_status,
        "applicability_message": applicability_message,
    }


def generate_scap_remediation(target: Target, profile: str, data_stream: str) -> str:
    if not SCAP_PROFILE_PATTERN.fullmatch(profile):
        raise ValueError("Ungültige OpenSCAP-Profil-ID")
    if not _valid_scap_data_stream(data_stream):
        raise ValueError("Ungültiger OpenSCAP-Datenstrom")
    command = (
        "oscap xccdf generate fix --fix-type bash "
        f"--profile {shlex.quote(profile)} {shlex.quote(data_stream)}"
    )
    result = Transport(target).run_script(f"export LC_ALL=C\nexec {command}\n", timeout=300)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-4000:]
        raise RuntimeError(detail or "OpenSCAP konnte keine Bash-Massnahmen erzeugen")
    script = result.stdout.strip()
    if not script or len(script.encode("utf-8")) > 8_000_000:
        raise RuntimeError("OpenSCAP lieferte kein gültiges Massnahmen-Skript")
    return script + "\n"


def generate_selected_scap_remediation(
    target: Target,
    profile: str,
    data_stream: str,
    rule_ids: list[str],
    benchmark_rule_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Rescan selected profile rules and generate fixes only from those failed results."""
    if not SCAP_PROFILE_PATTERN.fullmatch(profile):
        raise ValueError("Ungültige OpenSCAP-Profil-ID")
    if not _valid_scap_data_stream(data_stream):
        raise ValueError("Ungültiger OpenSCAP-Datenstrom")
    unique_ids = list(dict.fromkeys(rule_ids))
    if not unique_ids or len(unique_ids) > 1000:
        raise ValueError("Zwischen 1 und 1000 OpenSCAP-Regeln auswählen")
    if any(
        not SCAP_PROFILE_PATTERN.fullmatch(rule_id) or _scap_item_kind(rule_id) != "rule"
        for rule_id in unique_ids
    ):
        raise ValueError("Ungültige OpenSCAP-Regel-ID")
    benchmark_ids = list(dict.fromkeys(benchmark_rule_ids or unique_ids))
    if len(benchmark_ids) > 5000 or any(
        not SCAP_PROFILE_PATTERN.fullmatch(rule_id) or _scap_item_kind(rule_id) != "rule"
        for rule_id in benchmark_ids
    ):
        raise ValueError("Ungültige Benchmark-Regelliste")
    if not set(unique_ids).issubset(benchmark_ids):
        raise ValueError("Die Auswahl gehört nicht zum ermittelten Benchmark")
    tailoring_profile = "xccdf_org.hardeningagent.content_profile_remediation"
    tailoring_time = datetime.now(UTC).replace(microsecond=0).isoformat()
    selected_set = set(unique_ids)
    group_ids = [
        item_id
        for item_id in discover_scap_selectable_ids(target, data_stream)
        if _scap_item_kind(item_id) == "group"
    ]
    group_selections = [
        f'    <xccdf:select idref="{html.escape(group_id, quote=True)}" selected="true"/>'
        for group_id in group_ids
    ]
    rule_selections = [
        f'    <xccdf:select idref="{html.escape(rule_id, quote=True)}" '
        f'selected="{"true" if rule_id in selected_set else "false"}"/>'
        for rule_id in benchmark_ids
    ]
    selections = "\n".join([*group_selections, *rule_selections])
    tailoring_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.hardeningagent.content_tailoring_remediation">
  <xccdf:benchmark href="file://{html.escape(data_stream, quote=True)}"/>
  <xccdf:version time="{tailoring_time}">1</xccdf:version>
  <xccdf:Profile id="{tailoring_profile}">
    <xccdf:title xml:lang="de">Ausgewählte Hardening-Massnahmen</xccdf:title>
{selections}
  </xccdf:Profile>
</xccdf:Tailoring>
"""
    encoded_tailoring = base64.b64encode(tailoring_xml.encode()).decode()
    manual_command = (
        f"sudo oscap xccdf eval --profile {shlex.quote(tailoring_profile)} "
        "--tailoring-file /tmp/hardening-agent-selection.xml "
        f"{shlex.quote(data_stream)}"
    )
    script = f"""
set +e
export LC_ALL=C
if [ "$(id -u)" -eq 0 ]; then
    lha_priv=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    lha_priv="sudo -n"
else
    echo '@@LHA_PRIVILEGE_REQUIRED@@'
    exit 77
fi
lha_dir=$(mktemp -d /tmp/lha-selected-XXXXXX) || exit 1
trap 'rm -rf -- "$lha_dir"' EXIT HUP INT TERM
lha_results="$lha_dir/results.xml"
lha_tailoring="$lha_dir/selection-tailoring.xml"
lha_log="$lha_dir/oscap.log"
printf '%s' {shlex.quote(encoded_tailoring)} | base64 -d >"$lha_tailoring"
chmod 600 "$lha_tailoring"
$lha_priv oscap xccdf eval --profile {shlex.quote(tailoring_profile)} --tailoring-file "$lha_tailoring" --results "$lha_results" {shlex.quote(data_stream)} >"$lha_log" 2>&1
lha_rc=$?
printf '@@LHA_SELECTED_SCAN_RC@@%s\n' "$lha_rc"
cat "$lha_log"
if [ ! -s "$lha_results" ] || ! command -v gzip >/dev/null 2>&1 || ! command -v base64 >/dev/null 2>&1; then
    echo '@@LHA_SELECTED_RESULTS_MISSING@@'
    exit 0
fi
printf '@@LHA_XCCDF_GZIP_BEGIN@@\n'
$lha_priv gzip -c "$lha_results" | base64 | tr -d '\n'
printf '\n@@LHA_XCCDF_GZIP_END@@\n'
exit 0
"""
    result = Transport(target).run_script(script, timeout=1800)
    if result.returncode == 77 or "@@LHA_PRIVILEGE_REQUIRED@@" in result.stdout:
        return {"status": "privilege_required", "command": manual_command}
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-4000:]
        raise RuntimeError(detail or "Ausgewählte OpenSCAP-Regeln konnten nicht verarbeitet werden")
    scan_rc_match = re.search(r"^@@LHA_SELECTED_SCAN_RC@@(\d+)$", result.stdout, re.MULTILINE)
    if not scan_rc_match:
        raise RuntimeError("OpenSCAP lieferte keinen Rückgabestatus für die Auswahlprüfung")
    scan_rc = int(scan_rc_match.group(1))
    rescanned = _parse_xccdf_payload(result.stdout)
    missing_results = [rule_id for rule_id in unique_ids if rule_id not in rescanned]
    if missing_results:
        log_text = result.stdout.split("@@LHA_SELECTED_SCAN_RC@@", 1)[-1]
        log_text = log_text.split("@@LHA_XCCDF_GZIP_BEGIN@@", 1)[0]
        log_text = re.sub(r"^\d+\s*", "", log_text).strip()
        detail = log_text[-3000:] or "OpenSCAP erzeugte keine vollständigen Regelresultate"
        raise RuntimeError(
            f"OpenSCAP-Auswahlprüfung fehlgeschlagen (RC {scan_rc}); "
            f"{len(missing_results)} von {len(unique_ids)} Resultaten fehlen: {detail}"
        )
    no_longer_failed = [
        rule_id
        for rule_id in unique_ids
        if rescanned.get(rule_id, {}).get("status") != "fail"
    ]
    if no_longer_failed:
        raise ValueError(
            f"{len(no_longer_failed)} ausgewählte Regeln sind nicht mehr fehlgeschlagen. "
            "Bitte Full Scan aktualisieren und die Auswahl neu speichern."
        )
    generation_script = f"""
set -e
export LC_ALL=C
lha_dir=$(mktemp -d /tmp/lha-fix-XXXXXX) || exit 1
trap 'rm -rf -- "$lha_dir"' EXIT HUP INT TERM
lha_tailoring="$lha_dir/selection-tailoring.xml"
printf '%s' {shlex.quote(encoded_tailoring)} | base64 -d >"$lha_tailoring"
chmod 600 "$lha_tailoring"
printf '@@LHA_FIX_BEGIN@@\n'
oscap xccdf generate fix --fix-type bash --profile {shlex.quote(tailoring_profile)} --tailoring-file "$lha_tailoring" {shlex.quote(data_stream)}
lha_fix_rc=$?
printf '\n@@LHA_FIX_END@@\n'
exit "$lha_fix_rc"
"""
    result = Transport(target).run_script(generation_script, timeout=600)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-4000:]
        raise RuntimeError(detail or "OpenSCAP konnte das ausgewählte Fix-Skript nicht erzeugen")
    match = re.search(
        r"@@LHA_FIX_BEGIN@@\n(?P<script>.*)\n@@LHA_FIX_END@@",
        result.stdout,
        re.DOTALL,
    )
    if not match:
        raise RuntimeError("OpenSCAP lieferte kein auswertbares Massnahmenpaket")
    generated = match.group("script").strip()
    if len(generated.encode("utf-8")) > 8_000_000:
        raise RuntimeError("Das erzeugte OpenSCAP-Paket ist unerwartet gross")
    warnings = []
    if scan_rc not in {0, 2}:
        warnings.append(
            f"OpenSCAP meldete bei der Nachprüfung RC {scan_rc}; alle {len(unique_ids)} "
            "ausgewählten Regelresultate waren dennoch vollständig auswertbar."
        )
    return {
        "status": "generated",
        "script": generated + "\n" if generated else "#!/bin/sh\n# Keine automatische Massnahme verfügbar.\n",
        "rules": unique_ids,
        "tailoring": tailoring_xml,
        "tailoring_profile": tailoring_profile,
        "warnings": warnings,
    }


def integrate_scap_coverage(guideline: dict[str, Any], scan: dict[str, Any]) -> dict[str, Any]:
    guideline["scap_scan"] = {
        "profile": scan["profile"],
        "data_stream": scan["data_stream"],
        "counts": scan["counts"],
        "results": len(scan["results"]),
        "applicability_status": scan.get("applicability_status", "compatible"),
        "applicability_message": scan.get("applicability_message", ""),
    }
    return guideline


def _compliance_inventory(inventory: Inventory) -> dict[str, Any]:
    raw = inventory.sections.get("compliance", "")
    tools = {}
    streams = []
    profiles = []
    profile_streams = {}
    stream_profiles: dict[str, list[str]] = {}
    native_rules = []
    stream_rules: dict[str, list[str]] = {}
    for line in raw.splitlines():
        if line.startswith("TOOL:"):
            name, _, value = line.removeprefix("TOOL:").partition("=")
            tools[name] = value or None
        elif line.startswith("DATASTREAM:"):
            path, _, counts = line.removeprefix("DATASTREAM:").partition("|")
            rule_count, _, profile_count = counts.partition("|")
            streams.append(
                {
                    "path": path,
                    "rules": int(rule_count) if rule_count.isdigit() else None,
                    "profiles": int(profile_count) if profile_count.isdigit() else None,
                }
            )
        elif line.startswith("PROFILE:"):
            value = line.removeprefix("PROFILE:")
            stream, separator, profile = value.partition("|")
            if separator and stream.startswith("/"):
                profiles.append(profile)
                profile_streams.setdefault(profile, stream)
                stream_profiles.setdefault(stream, []).append(profile)
            else:
                profiles.append(value)
        elif line.startswith("SCAP_RULE:"):
            value = line.removeprefix("SCAP_RULE:")
            stream, separator, rule = value.partition("|")
            if separator and stream.startswith("/"):
                native_rules.append(rule)
                stream_rules.setdefault(stream, []).append(rule)
            else:
                native_rules.append(value)
    return {
        "tools": tools,
        "data_streams": streams,
        "profiles": profiles,
        "profile_streams": profile_streams,
        "stream_profiles": stream_profiles,
        "native_rules": native_rules,
        "stream_rules": stream_rules,
        "raw": raw,
    }


def _platform_stream_name(distribution: str, version: str) -> str | None:
    major = version.split(".", 1)[0]
    if distribution == "opensuse-leap":
        return "ssg-opensuse-ds.xml"
    if distribution == "sles" and major.isdigit():
        return f"ssg-sle{major}-ds.xml"
    if distribution == "debian" and major.isdigit():
        return f"ssg-debian{major}-ds.xml"
    if distribution == "ubuntu":
        digits = "".join(part for part in version.split(".")[:2] if part.isdigit())
        return f"ssg-ubuntu{digits}-ds.xml" if digits else None
    if distribution in {"rhel", "rocky", "almalinux", "ol"} and major.isdigit():
        return f"ssg-rhel{major}-ds.xml"
    return None


def _platform_compliance(compliance: dict[str, Any], distribution: str, version: str) -> dict[str, Any]:
    expected = _platform_stream_name(distribution, version)
    available_streams = list(compliance["data_streams"])
    matching = [
        item for item in available_streams if Path(item["path"]).name == expected
    ]
    # A benchmark for an older or different distribution can execute but will often
    # classify every rule as not applicable. Never offer such a stream as a fallback.
    streams = matching if expected else available_streams
    paths = {item["path"] for item in streams}
    stream_profiles = compliance.get("stream_profiles", {})
    profiles = list(
        dict.fromkeys(
            profile
            for stream in streams
            for profile in stream_profiles.get(stream["path"], [])
        )
    )
    if not profiles and expected is None:
        profiles = list(dict.fromkeys(compliance["profiles"]))
    profile_streams = {
        profile: stream["path"]
        for stream in streams
        for profile in stream_profiles.get(stream["path"], [])
    }
    stream_rules = compliance.get("stream_rules", {})
    rules = list(
        dict.fromkeys(rule for path in paths for rule in stream_rules.get(path, []))
    )
    if not rules and expected is None:
        rules = list(dict.fromkeys(compliance["native_rules"]))
    return {
        **compliance,
        "data_streams": streams,
        "profiles": profiles,
        "profile_streams": profile_streams,
        "native_rules": rules,
        "expected_stream": expected,
        "exact_stream_match": bool(matching) if expected else bool(streams),
        "available_data_streams": available_streams,
    }


def guideline_status(inventory: Inventory) -> dict[str, Any]:
    source = SOURCES.get(inventory.platform.family)
    documents = guideline_sources_for(inventory)
    source_category_counts = Counter(
        category for document in documents for category in document.get("categories", [])
    )
    compliance = _platform_compliance(
        _compliance_inventory(inventory),
        inventory.platform.distribution,
        inventory.platform.version,
    )
    tool_names = set(compliance["tools"])
    tool_ready = "oscap" in tool_names or "usg" in tool_names
    content_ready = bool(compliance["data_streams"]) or "usg" in tool_names
    native_ready = tool_ready and content_ready
    exact_vendor_match = inventory.platform.distribution in {"sles", "rhel", "ubuntu", "debian"}
    if inventory.platform.distribution == "opensuse-leap":
        compatibility = "related"
        compatibility_message = (
            "openSUSE Leap erkannt. Die SLES-Richtlinie ist verwandt, aber nicht automatisch "
            "als vollständig versionsgleich freigegeben."
        )
    elif (
        inventory.platform.distribution == "debian"
        and compliance.get("expected_stream")
        and not compliance.get("exact_stream_match")
    ):
        compatibility = "unsupported"
        available_names = ", ".join(
            Path(item["path"]).name for item in compliance.get("available_data_streams", [])
        ) or "keine"
        compatibility_message = (
            f"Für Debian {inventory.platform.version} wird "
            f"{compliance['expected_stream']} benötigt. Vorhanden: {available_names}. "
            "Ältere Debian-Datenströme werden nicht verwendet."
        )
    elif source and exact_vendor_match:
        compatibility = "matched"
        compatibility_message = (
            "Herstellerfamilie erkannt; exakte Dokument- und Profilversion prüfen."
        )
    else:
        compatibility = "unsupported"
        compatibility_message = "Keine freigegebene Hersteller-Richtlinie zugeordnet."
    return {
        "platform": asdict(inventory.platform),
        "vendor": source["vendor"] if source else "Nicht zugeordnet",
        "framework": source["framework"] if source else "Kein natives Framework zugeordnet",
        "documents": documents,
        "install_hint": source["install_hint"]
        if source
        else "Manuelle Quellenzuordnung erforderlich.",
        "install_plan": scanner_install_plan(inventory.platform.distribution),
        "compatibility": compatibility,
        "compatibility_message": compatibility_message,
        "native_scanner": {
            "ready": native_ready,
            "tool_ready": tool_ready,
            "content_ready": content_ready,
            "tools": compliance["tools"],
            "data_streams": compliance["data_streams"],
            "profiles": compliance["profiles"],
            "profile_streams": compliance["profile_streams"],
            "sample_rules": compliance["native_rules"],
            "expected_stream": compliance.get("expected_stream"),
            "exact_stream_match": compliance.get("exact_stream_match", False),
            "available_data_streams": compliance.get("available_data_streams", []),
        },
        "source_coverage": {
            "configured": len(documents),
            "categories": [
                {
                    "id": topic,
                    "title": title,
                    "sources": source_category_counts.get(topic, 0),
                    "status": "covered" if source_category_counts.get(topic, 0) else "gap",
                }
                for topic, title in TOPICS.items()
            ],
            "gaps": [
                {"id": topic, "title": title}
                for topic, title in TOPICS.items()
                if not source_category_counts.get(topic, 0)
            ],
        },
        "recommendation": (
            "Das passende Herstellerprofil vollständig read-only prüfen und anschließend nur "
            "die gewünschten fehlgeschlagenen Regeln für Maßnahmen auswählen."
            if native_ready
            else "OpenSCAP und passende Herstellerinhalte installieren, bevor Hardening bewertet wird."
        ),
    }


def source_version_hint(pretty_name: str) -> str:
    match = re.search(r"\b(\d+(?:\.\d+)?(?:\s*SP\d+)?)\b", pretty_name, re.IGNORECASE)
    return match.group(1) if match else "unbekannt"
