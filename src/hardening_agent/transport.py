from __future__ import annotations

import base64
import binascii
import json
import os
import pwd
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .models import Target


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class TransportError(RuntimeError):
    pass


class Transport:
    def __init__(self, target: Target):
        self.target = target

    def run_script(self, script: str, timeout: int = 60) -> CommandResult:
        cwd: str | None = None
        environment: dict[str, str] | None = None
        if self.target.local:
            command = ["sh", "-s"]
        elif self.target.vagrant_directory and self.target.vagrant_machine:
            vagrant = shutil.which("vagrant")
            if not vagrant:
                raise TransportError("Vagrant executable not found")
            project = Path(self.target.vagrant_directory)
            if not project.is_dir():
                raise TransportError(f"Vagrant project directory is unavailable: {project}")
            command = [vagrant, "ssh", self.target.vagrant_machine, "-c", "sh -s"]
            cwd = str(project)
            environment = os.environ.copy()
            identity = (
                Path(self.target.identity_file).expanduser() if self.target.identity_file else None
            )
            try:
                root_owned_key = (
                    os.geteuid() == 0
                    and identity is not None
                    and identity.is_file()
                    and identity.stat().st_uid == 0
                )
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
            elif self.target.vagrant_home:
                environment["VAGRANT_HOME"] = self.target.vagrant_home
                environment["HOME"] = str(Path(self.target.vagrant_home).parent)
        else:
            ssh = shutil.which("ssh")
            if not ssh:
                raise TransportError("OpenSSH client not found")
            command = [
                ssh,
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                "-p",
                str(self.target.port),
            ]
            if self.target.identity_file:
                identity = Path(self.target.identity_file).expanduser()
                if not identity.is_file():
                    raise TransportError(f"SSH identity file is unavailable: {identity}")
                command.extend(["-o", "IdentitiesOnly=yes", "-i", str(identity)])
            command.extend([self.target.destination, "sh", "-s"])

        try:
            completed = subprocess.run(
                command,
                input=script,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
                cwd=cwd,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise TransportError(f"Command timed out after {timeout}s") from exc
        except OSError as exc:
            raise TransportError(str(exc)) from exc
        result = CommandResult(completed.returncode, completed.stdout, completed.stderr)
        if (
            result.returncode != 0
            and self.target.vagrant_directory
            and self.target.vm_name
            and "Permission denied" in result.stderr
        ):
            try:
                fallback = self._run_qemu_guest_agent(script, timeout)
                notice = (
                    "Vagrant SSH rejected authentication; read-only audit used QEMU Guest Agent."
                )
                stderr = "\n".join(item for item in (notice, fallback.stderr) if item)
                return CommandResult(fallback.returncode, fallback.stdout, stderr)
            except TransportError as exc:
                detail = f"QEMU Guest Agent fallback unavailable: {exc}"
                stderr = "\n".join(item for item in (result.stderr.strip(), detail) if item)
                return CommandResult(result.returncode, result.stdout, stderr)
        return result

    def put_file(self, source: Path, destination: str, timeout: int = 300) -> None:
        """Copy a regular file to a target without embedding it in a command payload."""
        source = source.expanduser().resolve()
        if not source.is_file() or source.is_symlink():
            raise TransportError(f"Upload source is not a regular file: {source}")
        if not re.fullmatch(r"/tmp/[A-Za-z0-9_.-]{1,180}", destination):
            raise TransportError("Uploads are restricted to explicit /tmp destinations")
        if self.target.local:
            shutil.copyfile(source, destination)
            os.chmod(destination, 0o600)
            return

        cwd: str | None = None
        environment: dict[str, str] | None = None
        if self.target.vagrant_directory and self.target.vagrant_machine:
            vagrant = shutil.which("vagrant")
            if not vagrant:
                raise TransportError("Vagrant executable not found")
            cwd = self.target.vagrant_directory
            environment = self._vagrant_environment()
            command = [
                vagrant,
                "upload",
                str(source),
                destination,
                self.target.vagrant_machine,
            ]
        else:
            scp = shutil.which("scp")
            if not scp:
                raise TransportError("OpenSSH scp client not found")
            command = [
                scp,
                "-q",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                "-P",
                str(self.target.port),
            ]
            if self.target.identity_file:
                identity = Path(self.target.identity_file).expanduser()
                if not identity.is_file():
                    raise TransportError(f"SSH identity file is unavailable: {identity}")
                command.extend(["-o", "IdentitiesOnly=yes", "-i", str(identity)])
            command.extend([str(source), f"{self.target.destination}:{destination}"])
        try:
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
                cwd=cwd,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TransportError(str(exc)) from exc
        if completed.returncode != 0:
            raise TransportError(
                completed.stderr.strip() or completed.stdout.strip() or "File upload failed"
            )
        quoted_destination = shlex.quote(destination)
        secured = self.run_script(
            f"chmod 600 -- {quoted_destination} && test -f {quoted_destination}\n", timeout=30
        )
        if secured.returncode != 0:
            raise TransportError(secured.stderr.strip() or "Uploaded file could not be secured")

    def _vagrant_environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        identity = Path(self.target.identity_file).expanduser() if self.target.identity_file else None
        try:
            root_owned_key = (
                os.geteuid() == 0
                and identity is not None
                and identity.is_file()
                and identity.stat().st_uid == 0
            )
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
        elif self.target.vagrant_home:
            environment["VAGRANT_HOME"] = self.target.vagrant_home
            environment["HOME"] = str(Path(self.target.vagrant_home).parent)
        return environment

    def _run_qemu_guest_agent(self, script: str, timeout: int) -> CommandResult:
        virsh = shutil.which("virsh")
        if not virsh:
            raise TransportError("virsh executable not found")
        if not self.target.vm_name:
            raise TransportError("KVM domain name is missing")
        request = {
            "execute": "guest-exec",
            "arguments": {
                "path": "/bin/sh",
                "arg": ["-s"],
                "input-data": base64.b64encode(script.encode()).decode(),
                "capture-output": True,
            },
        }
        started = self._guest_agent_command(virsh, request, min(timeout, 15))
        try:
            pid = int(started["pid"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TransportError("QEMU Guest Agent returned no process ID") from exc
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError(f"QEMU Guest Agent command timed out after {timeout}s")
            status = self._guest_agent_command(
                virsh,
                {"execute": "guest-exec-status", "arguments": {"pid": pid}},
                min(max(1, int(remaining)), 15),
            )
            if status.get("exited"):
                break
            time.sleep(0.1)
        stdout = self._decode_guest_output(status.get("out-data", ""), "stdout")
        stderr = self._decode_guest_output(status.get("err-data", ""), "stderr")
        if status.get("out-truncated") or status.get("err-truncated"):
            stderr = "\n".join(
                item for item in (stderr, "QEMU Guest Agent output was truncated") if item
            )
        return CommandResult(int(status.get("exitcode", 1)), stdout, stderr)

    def _guest_agent_command(
        self, virsh: str, request: dict[str, object], timeout: int
    ) -> dict[str, object]:
        completed = subprocess.run(
            [
                virsh,
                "--connect",
                self.target.libvirt_uri,
                "qemu-agent-command",
                self.target.vm_name or "",
                json.dumps(request, separators=(",", ":")),
            ],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            raise TransportError(completed.stderr.strip() or "QEMU Guest Agent command failed")
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise TransportError("Invalid QEMU Guest Agent response") from exc
        if not isinstance(response, dict) or "return" not in response:
            error = response.get("error") if isinstance(response, dict) else None
            raise TransportError(f"QEMU Guest Agent error: {error or 'missing result'}")
        result = response["return"]
        if not isinstance(result, dict):
            raise TransportError("Invalid QEMU Guest Agent result")
        return result

    @staticmethod
    def _decode_guest_output(value: object, stream: str) -> str:
        if not value:
            return ""
        try:
            return base64.b64decode(str(value), validate=True).decode(errors="replace")
        except (binascii.Error, ValueError, UnicodeError) as exc:
            raise TransportError(f"Invalid QEMU Guest Agent {stream} data") from exc
