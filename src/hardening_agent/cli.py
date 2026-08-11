from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .advisor import AdvisorError, OllamaAdvisor
from .config import get_target, load_targets, save_inventory, save_target
from .inventory import collect_inventory
from .libvirt import check_libvirt, snapshot_command_text, vagrant_key_access
from .models import Target
from .transport import TransportError


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _target_add(args: argparse.Namespace) -> int:
    if args.local and args.host != "localhost":
        raise ValueError("--local cannot be combined with a remote --host")
    target = Target(
        name=args.name,
        host=args.host,
        user=args.user,
        port=args.port,
        identity_file=str(Path(args.identity_file).expanduser()) if args.identity_file else None,
        local=args.local,
        vm_name=args.vm_name,
        libvirt_uri=args.libvirt_uri,
    )
    save_target(target)
    print(f"Saved target {target.name}")
    return 0


def _target_list(_args: argparse.Namespace) -> int:
    targets = load_targets()
    if not targets:
        print("No targets configured")
        return 0
    for target in targets.values():
        mode = "local" if target.local else target.destination
        vm = f" vm={target.vm_name}" if target.vm_name else ""
        print(f"{target.name:20} {mode}:{target.port}{vm}")
    return 0


def _audit(args: argparse.Namespace) -> int:
    target = get_target(args.target)
    inventory = collect_inventory(target)
    path = save_inventory(inventory, Path(args.output) if args.output else None)
    print(f"Inventory saved: {path}")
    print(
        f"Detected: {inventory.platform.pretty_name} "
        f"({inventory.platform.distribution} {inventory.platform.version})"
    )
    for warning in inventory.warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    return 0


def _doctor(args: argparse.Namespace) -> int:
    checks = {
        "python": sys.version.split()[0],
        "ssh": shutil.which("ssh"),
        "scp": shutil.which("scp"),
        "shellcheck": shutil.which("shellcheck"),
        "virsh": shutil.which("virsh"),
        "vagrant": shutil.which("vagrant"),
    }
    advisor = OllamaAdvisor(model=args.model, base_url=args.ollama_url)
    checks["ollama_api"] = "reachable" if advisor.health() else "unavailable"
    checks["ollama_model"] = "unavailable"
    if advisor.health():
        try:
            installed = {item["name"] for item in advisor.models()}
            checks["ollama_model"] = "installed" if args.model in installed else "missing"
        except AdvisorError as exc:
            checks["ollama_model"] = f"error: {exc}"
    _print_json(checks)
    required_ok = bool(checks["ssh"])
    return 0 if required_ok else 1


def _snapshot(args: argparse.Namespace) -> int:
    target = get_target(args.target)
    command = snapshot_command_text(target)
    if not command:
        raise ValueError("Target has no vm_name configured")
    ok, detail = check_libvirt(target)
    print(detail)
    print("\nSnapshot command:")
    print(command)
    return 0 if ok else 1


def _vagrant_access(args: argparse.Namespace) -> int:
    operator = args.operator
    report = vagrant_key_access(operator)
    if not report:
        print(f"No Vagrant/libvirt machines found for {operator}")
        return 0
    statuses: set[str] = set()
    for item in report:
        status = str(item["status"])
        statuses.add(status)
        print(f"{status:18} {item['project']} [{item['machine']}]")
        print(f"  key: {item['identity_file']}")
    if not statuses or statuses == {"ready"}:
        return 0
    if statuses == {"root-owned"}:
        return 3
    return 2


def _gui(args: argparse.Namespace) -> int:
    from .webapp import serve_gui

    serve_gui(
        host=args.host,
        port=args.port,
        output_root=Path(args.output),
        model=args.model,
        ollama_url=args.ollama_url,
        libvirt_uri=args.libvirt_uri,
        open_browser=not args.no_browser,
        allow_root=args.allow_root,
        allow_remote=args.allow_remote,
    )
    return 0


def _add_connection_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--model", default="qwen3:14b")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardening-agent",
        description="Local OpenSCAP and OVAL hardening manager",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    target_parser = sub.add_parser("target", help="Manage target systems")
    target_sub = target_parser.add_subparsers(dest="target_command", required=True)
    target_add = target_sub.add_parser("add")
    target_add.add_argument("name")
    target_add.add_argument("--host", default="localhost")
    target_add.add_argument("--user")
    target_add.add_argument("--port", type=int, default=22)
    target_add.add_argument("--identity-file")
    target_add.add_argument("--local", action="store_true")
    target_add.add_argument("--vm-name")
    target_add.add_argument("--libvirt-uri", default="qemu:///system")
    target_add.set_defaults(func=_target_add)
    target_list = target_sub.add_parser("list")
    target_list.set_defaults(func=_target_list)

    audit = sub.add_parser("audit", help="Collect a read-only target inventory")
    audit.add_argument("target")
    audit.add_argument("--output")
    audit.set_defaults(func=_audit)

    doctor = sub.add_parser("doctor", help="Check local prerequisites")
    _add_connection_options(doctor)
    doctor.set_defaults(func=_doctor)

    snapshot = sub.add_parser("snapshot", help="Validate and print a KVM snapshot command")
    snapshot.add_argument("target")
    snapshot.set_defaults(func=_snapshot)

    vagrant_access = sub.add_parser(
        "vagrant-access", help="Check Vagrant private-key execution mode"
    )
    vagrant_access.add_argument("--operator", default=pwd.getpwuid(os.geteuid()).pw_name)
    vagrant_access.set_defaults(func=_vagrant_access)

    gui = sub.add_parser("gui", help="Start the local web management interface")
    gui.add_argument("--host", default="127.0.0.1")
    gui.add_argument("--port", type=int, default=8765)
    gui.add_argument("--output", default="output")
    gui.add_argument("--libvirt-uri", default="qemu:///system")
    gui.add_argument("--no-browser", action="store_true")
    gui.add_argument("--allow-root", action="store_true")
    gui.add_argument("--allow-remote", action="store_true")
    _add_connection_options(gui)
    gui.set_defaults(func=_gui)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (
        TypeError,
        ValueError,
        TransportError,
        OSError,
        RuntimeError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

