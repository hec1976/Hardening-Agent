from __future__ import annotations

import hashlib
import os
import re
import tempfile
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

from .config import data_home
from .models import Target
from .transport import Transport

CONTENT_VERSION = "0.1.81"
ARCHIVE_NAME = f"scap-security-guide-{CONTENT_VERSION}.zip"
RELEASE_BASE = (
    f"https://github.com/ComplianceAsCode/content/releases/download/v{CONTENT_VERSION}"
)
ARCHIVE_URL = f"{RELEASE_BASE}/{ARCHIVE_NAME}"
CHECKSUM_URL = f"{ARCHIVE_URL}.sha512"
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_DATASTREAM_BYTES = 256 * 1024 * 1024
SHA512_PATTERN = re.compile(r"\b([0-9a-fA-F]{128})\b")


def _download(url: str, destination: Path, limit: int) -> None:
    request = Request(url, headers={"User-Agent": "Linux-Hardening-Agent/1.0"})
    with urlopen(request, timeout=180) as response:
        declared = int(response.headers.get("Content-Length", "0") or 0)
        if declared > limit:
            raise ValueError("Offizieller SCAP-Download überschreitet die Sicherheitsgrenze")
        total = 0
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
            temporary = Path(output.name)
            try:
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > limit:
                        raise ValueError(
                            "Offizieller SCAP-Download überschreitet die Sicherheitsgrenze"
                        )
                    output.write(chunk)
            except Exception:
                temporary.unlink(missing_ok=True)
                raise
    os.chmod(temporary, 0o600)
    temporary.replace(destination)


def _official_checksum() -> str:
    request = Request(CHECKSUM_URL, headers={"User-Agent": "Linux-Hardening-Agent/1.0"})
    with urlopen(request, timeout=30) as response:
        payload = response.read(4096).decode("ascii", errors="strict")
    match = SHA512_PATTERN.search(payload)
    if not match:
        raise RuntimeError("Offizielle SHA-512-Prüfsumme konnte nicht gelesen werden")
    return match.group(1).lower()


def _archive() -> tuple[Path, str]:
    cache = data_home() / "feeds" / "complianceascode"
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / ARCHIVE_NAME
    expected = _official_checksum()
    if archive.is_file() and not archive.is_symlink():
        actual = hashlib.sha512(archive.read_bytes()).hexdigest()
        if actual == expected:
            return archive, actual
    _download(ARCHIVE_URL, archive, MAX_ARCHIVE_BYTES)
    actual = hashlib.sha512(archive.read_bytes()).hexdigest()
    if actual != expected:
        archive.unlink(missing_ok=True)
        raise RuntimeError("SHA-512-Prüfung des offiziellen SCAP-Inhalts fehlgeschlagen")
    return archive, actual


def _extract_datastream(archive: Path, product: str) -> Path:
    wanted = f"ssg-{product}-ds.xml"
    with zipfile.ZipFile(archive, mode="r") as bundle:
        candidates = [
            member
            for member in bundle.infolist()
            if not member.is_dir() and Path(member.filename).name == wanted
        ]
        if len(candidates) != 1:
            raise RuntimeError(f"{wanted} fehlt im offiziellen ComplianceAsCode-Archiv")
        member = candidates[0]
        if member.file_size <= 0 or member.file_size > MAX_DATASTREAM_BYTES:
            raise RuntimeError("SCAP-Datenstrom hat eine unerwartete Grösse")
        with bundle.open(member, mode="r") as source, tempfile.NamedTemporaryFile(
            prefix="lha-scap-", suffix=".xml", delete=False
        ) as out:
            temporary = Path(out.name)
            digest = hashlib.sha256()
            total = 0
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_DATASTREAM_BYTES:
                    temporary.unlink(missing_ok=True)
                    raise RuntimeError("SCAP-Datenstrom überschreitet die Sicherheitsgrenze")
                digest.update(chunk)
                out.write(chunk)
    os.chmod(temporary, 0o600)
    if total != member.file_size:
        temporary.unlink(missing_ok=True)
        raise RuntimeError("SCAP-Datenstrom wurde unvollständig entpackt")
    return temporary


def install_official_datastream(target: Target, product: str) -> dict[str, str]:
    if product != "debian13":
        raise ValueError("Für dieses System ist kein ergänzender SCAP-Inhalt definiert")
    archive, archive_sha512 = _archive()
    stream = _extract_datastream(archive, product)
    remote_temporary = f"/tmp/lha-scap-{product}-{CONTENT_VERSION}.xml"
    destination = f"/usr/local/share/xml/scap/ssg/content/ssg-{product}-ds.xml"
    try:
        transport = Transport(target)
        transport.put_file(stream, remote_temporary, timeout=900)
        script = f"""
set -eu
if [ "$(id -u)" -eq 0 ]; then
    lha_priv=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    lha_priv="sudo -n"
else
    echo '@@LHA_PRIVILEGE_REQUIRED@@'
    exit 77
fi
$lha_priv install -d -m 0755 /usr/local/share/xml/scap/ssg/content
$lha_priv install -m 0644 {remote_temporary} {destination}
oscap info {destination} >/dev/null
rm -f -- {remote_temporary}
printf '@@LHA_CONTENT_READY@@{destination}\n'
"""
        result = transport.run_script(script, timeout=300)
        if result.returncode == 77 or "@@LHA_PRIVILEGE_REQUIRED@@" in result.stdout:
            return {
                "status": "privilege_required",
                "command": (
                    "sudo install -d -m 0755 /usr/local/share/xml/scap/ssg/content && "
                    f"sudo install -m 0644 {remote_temporary} {destination}"
                ),
                "content_version": CONTENT_VERSION,
            }
        if result.returncode != 0 or "@@LHA_CONTENT_READY@@" not in result.stdout:
            detail = (result.stderr or result.stdout).strip()[-4000:]
            raise RuntimeError(detail or "Offizieller SCAP-Inhalt konnte nicht installiert werden")
        return {
            "status": "installed",
            "path": destination,
            "content_version": CONTENT_VERSION,
            "archive_sha512": archive_sha512,
            "source": ARCHIVE_URL,
        }
    finally:
        stream.unlink(missing_ok=True)
