from __future__ import annotations

import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Target

VM_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
VAGRANT_MACHINE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def _parse_vagrant_status(output: str, vagrant_home: str | None = None) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for line in output.splitlines():
        fields = line.split(maxsplit=4)
        if len(fields) != 5 or fields[2] != "libvirt":
            continue
        machine_id, machine, provider, state, directory = fields
        if not re.fullmatch(r"[A-Za-z0-9]+", machine_id):
            continue
        if not VAGRANT_MACHINE_PATTERN.fullmatch(machine):
            continue
        project = Path(directory).expanduser()
        if not project.is_absolute() or not project.is_dir():
            continue
        entry = {
            "id": machine_id,
            "machine": machine,
            "provider": provider,
            "state": state,
            "directory": str(project.resolve()),
        }
        if vagrant_home:
            entry["vagrant_home"] = vagrant_home
        entries.append(entry)
    return entries


def _vagrant_home_candidates(home_root: Path = Path("/home")) -> list[str | None]:
    configured = os.environ.get("VAGRANT_HOME")
    if configured:
        return [str(Path(configured).expanduser().resolve())]
    candidates: list[str | None] = [None]
    if os.geteuid() != 0:
        return candidates
    try:
        user_homes = sorted(home_root.glob("*/.vagrant.d"))
    except OSError:
        return candidates
    for candidate in user_homes:
        if candidate.is_dir():
            candidates.append(str(candidate.resolve()))
    return candidates


def _vagrant_project_roots() -> list[Path]:
    """Return bounded locations where local Vagrant projects commonly live."""
    roots = [Path("/mnt/data/vms")]
    operator = os.environ.get("LHA_OPERATOR", "")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", operator):
        try:
            operator_home = Path(pwd.getpwnam(operator).pw_dir).resolve()
        except (KeyError, OSError):
            operator_home = None
        if operator_home:
            roots.extend((operator_home / "vms", operator_home / "Vagrant"))
    return roots


def _vagrant_state_entries() -> list[dict[str, str]]:
    """Discover projects from local provider state without using the global index."""
    entries: list[dict[str, str]] = []
    for root in _vagrant_project_roots():
        try:
            state_directories = list(root.glob("*/.vagrant/machines/*/libvirt"))
        except OSError:
            continue
        for state_dir in state_directories:
            try:
                project = state_dir.parents[3].resolve()
                machine = state_dir.parent.name
            except (IndexError, OSError):
                continue
            if not VAGRANT_MACHINE_PATTERN.fullmatch(machine):
                continue
            provider_id = state_dir / "id"
            private_key = state_dir / "private_key"
            if not provider_id.is_file() or not private_key.is_file():
                continue
            try:
                machine_id = provider_id.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            entries.append(
                {
                    "id": machine_id,
                    "machine": machine,
                    "provider": "libvirt",
                    "state": "unknown",
                    "directory": str(project),
                }
            )
    return entries


def _vagrant_entries() -> list[dict[str, str]]:
    vagrant = shutil.which("vagrant")
    if not vagrant:
        return []
    entries: dict[tuple[str, str], dict[str, str]] = {}
    operator = os.environ.get("LHA_OPERATOR", "")
    runuser = shutil.which("runuser")
    env_command = shutil.which("env")
    if os.geteuid() == 0 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", operator):
        try:
            account = pwd.getpwnam(operator)
        except KeyError:
            account = None
        if account and runuser and env_command:
            operator_home = str(Path(account.pw_dir).resolve())
            vagrant_home = str((Path(operator_home) / ".vagrant.d").resolve())
            try:
                result = subprocess.run(
                    [
                        runuser,
                        "-u",
                        operator,
                        "--",
                        env_command,
                        f"HOME={operator_home}",
                        f"USER={operator}",
                        f"LOGNAME={operator}",
                        f"VAGRANT_HOME={vagrant_home}",
                        vagrant,
                        "global-status",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                result = None
            if result and result.returncode == 0:
                for entry in _parse_vagrant_status(result.stdout, vagrant_home):
                    entries[(entry["directory"], entry["machine"])] = entry
    for vagrant_home in _vagrant_home_candidates():
        environment = os.environ.copy()
        if vagrant_home:
            environment["VAGRANT_HOME"] = vagrant_home
        try:
            result = subprocess.run(
                [vagrant, "global-status"],
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode != 0:
            continue
        for entry in _parse_vagrant_status(result.stdout, vagrant_home):
            entries[(entry["directory"], entry["machine"])] = entry
    for entry in _vagrant_state_entries():
        entries.setdefault((entry["directory"], entry["machine"]), entry)
    return list(entries.values())


def _vagrant_metadata(entry: dict[str, str]) -> dict[str, Any]:
    state_dir = Path(entry["directory"]) / ".vagrant" / "machines" / entry["machine"] / "libvirt"
    identity = state_dir / "private_key"
    provider_id = state_dir / "id"
    return {
        "machine": entry["machine"],
        "directory": entry["directory"],
        "identity_file": str(identity) if identity.is_file() else "",
        "provider_id": provider_id.read_text(encoding="utf-8").strip()
        if provider_id.is_file()
        else "",
        "vagrant_home": entry.get("vagrant_home", ""),
    }


def vagrant_key_access(operator: str) -> list[dict[str, Any]]:
    """Inspect Vagrant key access without changing ownership or permissions."""
    account = pwd.getpwnam(operator)
    if os.geteuid() not in {0, account.pw_uid}:
        raise PermissionError("Vagrant key inspection must run as the operator user")
    operator_vagrant_home = str((Path(account.pw_dir) / ".vagrant.d").resolve())
    report: list[dict[str, Any]] = []
    for entry in _vagrant_entries():
        if entry.get("state") not in {None, "running", "unknown"}:
            continue
        entry_home = entry.get("vagrant_home", "")
        if entry_home and str(Path(entry_home).resolve()) != operator_vagrant_home:
            continue
        state_dir = (
            Path(entry["directory"]) / ".vagrant" / "machines" / entry["machine"] / "libvirt"
        )
        identity = state_dir / "private_key"
        item: dict[str, Any] = {
            "project": entry["directory"],
            "machine": entry["machine"],
            "identity_file": str(identity),
            "status": "missing",
        }
        if not identity.exists():
            report.append(item)
            continue
        if identity.is_symlink() or not stat.S_ISREG(identity.stat().st_mode):
            item["status"] = "unsafe-file-type"
            report.append(item)
            continue
        current = identity.stat()
        mode = stat.S_IMODE(current.st_mode)
        if current.st_uid == account.pw_uid and mode == 0o600:
            status = "ready"
        elif current.st_uid == 0 and mode == 0o600:
            status = "root-owned"
        else:
            status = "invalid-access"
        item.update(
            {
                "owner_uid": current.st_uid,
                "required_uid": account.pw_uid,
                "mode": f"{mode:03o}",
                "status": status,
            }
        )
        report.append(item)
    return report


def _match_vagrant(
    name: str,
    uuid: str,
    entries: list[dict[str, str]],
) -> dict[str, Any] | None:
    for entry in entries:
        metadata = _vagrant_metadata(entry)
        default_domain = f"{Path(entry['directory']).name}_{entry['machine']}"
        if metadata["provider_id"] == uuid or default_domain == name:
            return metadata
    return None


def _parse_vagrant_ssh_config(output: str) -> dict[str, str]:
    allowed = {"hostname", "user", "port", "identityfile"}
    values: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2 or fields[0].lower() not in allowed:
            continue
        key = fields[0].lower()
        try:
            parsed = shlex.split(fields[1])
        except ValueError:
            continue
        if len(parsed) == 1:
            values[key] = parsed[0]
    return values


def _vagrant_runtime_environment(metadata: dict[str, Any]) -> dict[str, str]:
    """Select the Vagrant home belonging to the owner that can read the managed key."""
    environment = os.environ.copy()
    identity = Path(str(metadata.get("identity_file", ""))).expanduser()
    try:
        root_owned_key = os.geteuid() == 0 and identity.is_file() and identity.stat().st_uid == 0
    except OSError:
        root_owned_key = False
    if root_owned_key:
        root_home = str(Path(pwd.getpwuid(0).pw_dir).resolve())
        environment.update(
            {
                "HOME": root_home,
                "USER": "root",
                "LOGNAME": "root",
                "VAGRANT_HOME": str(Path(root_home) / ".vagrant.d"),
            }
        )
    elif metadata.get("vagrant_home"):
        vagrant_home = str(metadata["vagrant_home"])
        environment["VAGRANT_HOME"] = vagrant_home
        environment["HOME"] = str(Path(vagrant_home).parent)
    return environment


def vagrant_ssh_config(vm_name: str, uri: str = "qemu:///system") -> dict[str, Any]:
    if not VM_NAME_PATTERN.fullmatch(vm_name):
        raise ValueError("Unsafe libvirt VM name")
    domains, _warnings = list_vms(uri)
    domain = next((item for item in domains if item["name"] == vm_name), None)
    if not domain or not domain.get("vagrant"):
        raise ValueError(f"No Vagrant configuration found for {vm_name}")
    metadata = domain["vagrant"]
    vagrant = shutil.which("vagrant")
    if not vagrant:
        raise RuntimeError("vagrant is not installed")
    environment = _vagrant_runtime_environment(metadata)
    result = subprocess.run(
        [vagrant, "ssh-config", str(metadata["machine"])],
        cwd=str(metadata["directory"]),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
        env=environment,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "vagrant ssh-config failed")
    config = _parse_vagrant_ssh_config(result.stdout)
    identity = config.get("identityfile") or str(metadata.get("identity_file", ""))
    identity_path = Path(identity).expanduser()
    if not identity or not identity_path.is_file() or not os.access(identity_path, os.R_OK):
        raise RuntimeError("Vagrant identity file is unavailable")
    return {
        "host": config.get("hostname") or next(iter(domain.get("addresses", [])), ""),
        "user": config.get("user", "vagrant"),
        "port": int(config.get("port", "22")),
        "identity_file": str(identity_path.resolve()),
        "machine": str(metadata["machine"]),
        "directory": str(metadata["directory"]),
        "vagrant_home": str(metadata.get("vagrant_home", "")),
    }


def refresh_vagrant_target(target: Target) -> Target:
    """Return a target with current Vagrant SSH settings when its VM is Vagrant-managed."""
    if target.local:
        return target
    domains, _warnings = list_vms(target.libvirt_uri)
    vagrant_domains = [item for item in domains if item.get("vagrant")]
    requested_name = target.vm_name or target.name
    domain = next((item for item in vagrant_domains if item["name"] == requested_name), None)
    if domain is None and not target.vm_name:
        address_matches = [
            item for item in vagrant_domains if target.host in item.get("addresses", [])
        ]
        if len(address_matches) == 1:
            domain = address_matches[0]
    if not domain or not domain.get("vagrant"):
        return target
    domain_name = str(domain["name"])
    config = vagrant_ssh_config(domain_name, target.libvirt_uri)
    return Target(
        name=target.name,
        host=str(config["host"]),
        user=str(config["user"]),
        port=int(config["port"]),
        identity_file=str(config["identity_file"]),
        local=False,
        vm_name=domain_name,
        libvirt_uri=target.libvirt_uri,
        vagrant_directory=str(config["directory"]),
        vagrant_machine=str(config["machine"]),
        vagrant_home=str(config.get("vagrant_home", "")) or None,
    )


def _virsh(uri: str, *arguments: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    virsh = shutil.which("virsh")
    if not virsh:
        raise RuntimeError("virsh is not installed")
    environment = os.environ.copy()
    # virsh localises both keys (for example "State") and values.  Parsing a
    # German dominfo response as English previously made every domain appear
    # as "unknown" and prevented the subsequent address lookup.
    environment.update({"LC_ALL": "C", "LANG": "C"})
    return subprocess.run(
        [virsh, "--connect", uri, *arguments],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=environment,
    )


def _parse_key_values(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip().lower().replace(" ", "_")] = value.strip()
    return result


def _vm_addresses(uri: str, name: str) -> list[str]:
    addresses: list[str] = []
    for source in ("agent", "lease", "arp"):
        result = _virsh(uri, "domifaddr", name, "--source", source, "--full")
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4 or fields[-2].lower() not in {"ipv4", "ipv6"}:
                continue
            address = fields[-1].split("/", 1)[0]
            if address not in {"127.0.0.1", "::1"} and address not in addresses:
                addresses.append(address)
        if addresses:
            break
    return addresses


def list_vms(uri: str = "qemu:///system") -> tuple[list[dict[str, object]], list[str]]:
    result = _virsh(uri, "list", "--all", "--name")
    if result.returncode != 0:
        return [], [result.stderr.strip() or "Unable to list libvirt domains"]
    warnings: list[str] = []
    vms: list[dict[str, object]] = []
    vagrant_entries = _vagrant_entries()
    for name in sorted(item.strip() for item in result.stdout.splitlines() if item.strip()):
        if not VM_NAME_PATTERN.fullmatch(name):
            warnings.append(f"Ignored domain with unsupported name: {name}")
            continue
        info_result = _virsh(uri, "dominfo", name)
        info = _parse_key_values(info_result.stdout) if info_result.returncode == 0 else {}
        if info_result.returncode != 0:
            detail = info_result.stderr.strip() or "dominfo konnte nicht gelesen werden"
            warnings.append(f"Status von {name} konnte nicht gelesen werden: {detail}")
        addresses = _vm_addresses(uri, name) if info.get("state") == "running" else []
        vm: dict[str, object] = {
            "name": name,
            "uuid": info.get("uuid", ""),
            "state": info.get("state", "unknown"),
            "autostart": info.get("autostart", "unknown"),
            "memory": info.get("max_memory", ""),
            "vcpus": info.get("cpu(s)", ""),
            "addresses": addresses,
        }
        vagrant = _match_vagrant(name, info.get("uuid", ""), vagrant_entries)
        if vagrant:
            vm["vagrant"] = vagrant
        vms.append(vm)
    return vms, warnings


def snapshot_command(target: Target) -> list[str] | None:
    if not target.vm_name:
        return None
    if not VM_NAME_PATTERN.fullmatch(target.vm_name):
        raise ValueError("Unsafe libvirt VM name")
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    name = f"lha-pre-hardening-{timestamp}"
    return [
        "virsh",
        "--connect",
        target.libvirt_uri,
        "snapshot-create-as",
        "--domain",
        target.vm_name,
        "--name",
        name,
        "--description",
        "Linux Hardening Agent pre-change snapshot",
        "--atomic",
    ]


def snapshot_command_text(target: Target) -> str | None:
    command = snapshot_command(target)
    return shlex.join(command) if command else None


def check_libvirt(target: Target) -> tuple[bool, str]:
    if not target.vm_name:
        return False, "No vm_name configured"
    if not shutil.which("virsh"):
        return False, "virsh is not installed"
    result = _virsh(target.libvirt_uri, "dominfo", target.vm_name)
    return result.returncode == 0, (result.stdout or result.stderr).strip()
