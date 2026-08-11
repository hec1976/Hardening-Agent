from __future__ import annotations

import bz2
import gzip
import hashlib
import json
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .config import data_home
from .models import Inventory, Target
from .transport import Transport

MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_RESULT_LINES = 100_000
OVAL_LINE = re.compile(r"^Definition\s+([^: ]+(?::[^: ]+)+):\s+(true|false|unknown|error)\s*$")


@dataclass(frozen=True)
class FeedSpec:
    provider: str
    title: str
    url: str
    license: str
    kind: str = "vulnerability"


def feed_for(inventory: Inventory) -> FeedSpec | None:
    distribution = inventory.platform.distribution
    version = inventory.platform.version
    if distribution == "opensuse-leap" and re.fullmatch(r"15\.\d+", version):
        return FeedSpec(
            "SUSE",
            f"openSUSE Leap {version} Patch OVAL",
            f"https://ftp.suse.com/pub/projects/security/oval/opensuse.leap.{version}-patch.xml.bz2",
            "CC-BY-4.0",
            "patch",
        )
    if distribution in {"sles", "sled"}:
        return None  # Subscription/product streams must be selected explicitly.
    debian_codenames = {"12": "bookworm", "13": "trixie"}
    if distribution == "debian" and version.split(".", 1)[0] in debian_codenames:
        codename = debian_codenames[version.split(".", 1)[0]]
        return FeedSpec(
            "Debian",
            f"Debian {codename} OVAL",
            f"https://www.debian.org/security/oval/oval-definitions-{codename}.xml.bz2",
            "Debian security data terms",
        )
    if distribution == "ubuntu" and re.fullmatch(r"\d{2}\.\d{2}", version):
        return FeedSpec(
            "Canonical",
            f"Ubuntu {version} USN OVAL",
            f"https://security-metadata.canonical.com/oval/com.ubuntu.{version}.usn.oval.xml.bz2",
            "Canonical security metadata terms",
            "patch",
        )
    return None


def _cache_path(spec: FeedSpec) -> Path:
    suffix = ".xml.bz2" if spec.url.endswith(".bz2") else ".xml.gz" if spec.url.endswith(".gz") else ".xml"
    key = hashlib.sha256(spec.url.encode()).hexdigest()[:20]
    return data_home() / "feeds" / f"{spec.provider.lower()}-{key}{suffix}"


def download_feed(
    spec: FeedSpec, timeout: int = 120, max_age: timedelta = timedelta(hours=24)
) -> tuple[Path, dict[str, Any]]:
    parsed = urlparse(spec.url)
    allowed = {
        "ftp.suse.com",
        "www.debian.org",
        "security-metadata.canonical.com",
        "access.redhat.com",
    }
    if parsed.scheme != "https" or parsed.hostname not in allowed:
        raise ValueError("OVAL feed URL is not on the official allowlist")
    path = _cache_path(spec)
    metadata_path = path.with_suffix(path.suffix + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and metadata_path.is_file() and not path.is_symlink():
        try:
            cached = json.loads(metadata_path.read_text(encoding="utf-8"))
            fetched_at = datetime.fromisoformat(str(cached["fetched_at"]))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if (
                datetime.now(UTC) - fetched_at.astimezone(UTC) <= max_age
                and digest == cached.get("sha256")
                and cached.get("url") == spec.url
            ):
                return path, {**cached, "cache": "hit"}
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            pass
    request = Request(spec.url, headers={"User-Agent": "Linux-Hardening-Agent/1.0"})
    with urlopen(request, timeout=timeout) as response:
        declared = int(response.headers.get("Content-Length", "0") or 0)
        if declared > MAX_COMPRESSED_BYTES:
            raise ValueError("OVAL feed exceeds the configured download limit")
        digest = hashlib.sha256()
        total = 0
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
            temporary_path = Path(temporary.name)
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_COMPRESSED_BYTES:
                    temporary_path.unlink(missing_ok=True)
                    raise ValueError("OVAL feed exceeds the configured download limit")
                digest.update(chunk)
                temporary.write(chunk)
        os.chmod(temporary_path, 0o600)
        temporary_path.replace(path)
        metadata = {
            "provider": spec.provider,
            "title": spec.title,
            "url": spec.url,
            "license": spec.license,
            "kind": spec.kind,
            "sha256": digest.hexdigest(),
            "bytes": total,
            "fetched_at": datetime.now(UTC).isoformat(),
            "etag": response.headers.get("ETag", ""),
            "last_modified": response.headers.get("Last-Modified", ""),
            "cache": "refreshed",
        }
    temporary_meta = metadata_path.with_suffix(metadata_path.suffix + ".tmp")
    temporary_meta.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary_meta, 0o600)
    temporary_meta.replace(metadata_path)
    return path, metadata


def _opened_xml(path: Path) -> BinaryIO:
    if path.name.endswith(".bz2"):
        return bz2.open(path, "rb")
    if path.name.endswith(".gz"):
        return gzip.open(path, "rb")
    return path.open("rb")


def materialize_feed_xml(path: Path) -> tuple[Path, str]:
    """Decompress a cached feed locally so targets need no bzip2/gzip utility."""
    digest = hashlib.sha256()
    total = 0
    with tempfile.NamedTemporaryFile(prefix="lha-oval-", suffix=".xml", delete=False) as output:
        temporary = Path(output.name)
        try:
            with _opened_xml(path) as source:
                while chunk := source.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_UNCOMPRESSED_BYTES:
                        raise ValueError("Entpackter OVAL-Feed überschreitet die Sicherheitsgrenze")
                    digest.update(chunk)
                    output.write(chunk)
        except (OSError, ValueError):
            temporary.unlink(missing_ok=True)
            raise
    os.chmod(temporary, 0o600)
    return temporary, digest.hexdigest()


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def enrich_definitions(path: Path, wanted: set[str]) -> dict[str, dict[str, Any]]:
    enriched: dict[str, dict[str, Any]] = {}
    if not wanted:
        return enriched
    with _opened_xml(path) as stream:
        for _event, element in ET.iterparse(stream, events=("end",)):
            if _local_name(element.tag) != "definition":
                continue
            definition_id = element.attrib.get("id", "")
            if definition_id in wanted:
                title = ""
                severity = "unknown"
                references: list[str] = []
                for child in element.iter():
                    name = _local_name(child.tag)
                    if name == "title" and not title and child.text:
                        title = child.text.strip()
                    elif name == "severity" and child.text:
                        severity = child.text.strip().lower()
                    elif name == "reference":
                        ref_id = child.attrib.get("ref_id", "")
                        source = child.attrib.get("source", "")
                        if ref_id and source.upper() in {"CVE", "USN", "SUSE-SU", "DSA"}:
                            references.append(ref_id)
                enriched[definition_id] = {
                    "title": title or definition_id,
                    "severity": severity,
                    "references": list(dict.fromkeys(references)),
                    "definition_class": element.attrib.get("class", "unknown"),
                }
            element.clear()
    return enriched


def run_vulnerability_scan(target: Target, inventory: Inventory) -> dict[str, Any]:
    spec = feed_for(inventory)
    if spec is None:
        return {
            "status": "unsupported",
            "message": "Für diese Distribution/Version ist noch kein exakt passender Feed definiert.",
            "results": [],
            "counts": {},
        }
    feed_path, metadata = download_feed(spec)
    remote_feed = f"/tmp/lha-oval-{secrets_token()}.xml"
    transport = Transport(target)
    upload_path, upload_sha256 = materialize_feed_xml(feed_path)
    try:
        transport.put_file(upload_path, remote_feed, timeout=600)
    finally:
        upload_path.unlink(missing_ok=True)
    script = f"""
set +e
export LC_ALL=C
lha_feed={remote_feed!r}
trap 'rm -f -- "$lha_feed"' EXIT HUP INT TERM
command -v oscap >/dev/null 2>&1 || {{ echo '@@LHA_OSCAP_MISSING@@'; exit 78; }}
command -v sha256sum >/dev/null 2>&1 || exit 1
[ "$(sha256sum "$lha_feed" | awk '{{print $1}}')" = {upload_sha256!r} ] || {{ echo '@@LHA_HASH_MISMATCH@@'; exit 79; }}
ulimit -f 1048576 2>/dev/null || true
lha_output=$(oscap oval eval "$lha_feed" 2>&1)
lha_rc=$?
printf '@@LHA_OVAL_RC@@%s\n' "$lha_rc"
printf '%s\n' "$lha_output"
exit 0
"""
    result = transport.run_script(script, timeout=1800)
    if result.returncode == 78 or "@@LHA_OSCAP_MISSING@@" in result.stdout:
        return {"status": "scanner_missing", "feed": metadata, "results": [], "counts": {}}
    if result.returncode != 0 or "@@LHA_HASH_MISMATCH@@" in result.stdout:
        raise RuntimeError((result.stderr or result.stdout).strip()[-4000:] or "OVAL scan failed")
    verdicts: list[dict[str, Any]] = []
    for line in result.stdout.splitlines()[:MAX_RESULT_LINES]:
        match = OVAL_LINE.match(line.strip())
        if not match:
            continue
        definition_id, raw = match.groups()
        status = {
            "true": "affected",
            "false": "not_affected",
            "unknown": "unknown",
            "error": "error",
        }[raw]
        verdicts.append({"definition_id": definition_id, "status": status, "raw_result": raw})
    details = enrich_definitions(feed_path, {item["definition_id"] for item in verdicts})
    for item in verdicts:
        item.update(details.get(item["definition_id"], {}))
    counts = Counter(item["status"] for item in verdicts)
    return {
        "status": "completed",
        "semantic": "OVAL true means the vulnerability/patch definition matched",
        "feed": metadata,
        "results": verdicts,
        "counts": dict(counts),
        "complete": not any(item["status"] in {"unknown", "error"} for item in verdicts),
    }


def secrets_token() -> str:
    return os.urandom(8).hex()
