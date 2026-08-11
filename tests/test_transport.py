import base64
import json
import subprocess

import pytest

from hardening_agent.models import Target
from hardening_agent.transport import Transport, TransportError


def test_transport_rejects_missing_identity(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("hardening_agent.transport.shutil.which", lambda _name: "/usr/bin/ssh")
    target = Target(name="guest", host="192.0.2.10", identity_file=str(tmp_path / "missing"))
    with pytest.raises(TransportError, match="identity file is unavailable"):
        Transport(target).run_script("id")


def test_transport_uses_only_selected_identity(monkeypatch, tmp_path) -> None:
    identity = tmp_path / "private_key"
    identity.write_text("test", encoding="utf-8")
    captured = []

    def fake_run(command, **kwargs):
        del kwargs
        captured.extend(command)
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr("hardening_agent.transport.shutil.which", lambda _name: "/usr/bin/ssh")
    monkeypatch.setattr("hardening_agent.transport.subprocess.run", fake_run)
    target = Target(name="guest", host="192.0.2.10", identity_file=str(identity))
    Transport(target).run_script("id")
    assert "IdentitiesOnly=yes" in captured
    assert str(identity) in captured


def test_transport_uses_vagrant_cli_for_vagrant_target(monkeypatch, tmp_path) -> None:
    project = tmp_path / "opensuse15"
    project.mkdir()
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["cwd"] = kwargs["cwd"]
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr("hardening_agent.transport.shutil.which", lambda _name: "/usr/bin/vagrant")
    monkeypatch.setattr("hardening_agent.transport.subprocess.run", fake_run)
    target = Target(
        name="opensuse",
        host="192.168.121.10",
        user="vagrant",
        vm_name="opensuse15_default",
        vagrant_directory=str(project),
        vagrant_machine="default",
        vagrant_home="/home/hec/.vagrant.d",
    )

    result = Transport(target).run_script("id")

    assert result.returncode == 0
    assert captured["command"] == ["/usr/bin/vagrant", "ssh", "default", "-c", "sh -s"]
    assert captured["cwd"] == str(project)
    assert captured["env"]["VAGRANT_HOME"] == "/home/hec/.vagrant.d"


def test_root_owned_vagrant_key_uses_root_vagrant_environment(monkeypatch, tmp_path) -> None:
    project = tmp_path / "opensuse15"
    project.mkdir()
    identity = project / "private_key"
    identity.write_text("test", encoding="utf-8")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["cwd"] = kwargs["cwd"]
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(command, 0, "ok", "")

    account = type("Account", (), {"pw_dir": "/root"})()
    monkeypatch.setattr("hardening_agent.transport.os.geteuid", lambda: 0)
    monkeypatch.setattr("hardening_agent.transport.pwd.getpwuid", lambda _uid: account)
    monkeypatch.setattr("hardening_agent.transport.shutil.which", lambda _name: "/usr/bin/vagrant")
    monkeypatch.setattr("hardening_agent.transport.subprocess.run", fake_run)
    target = Target(
        name="opensuse15_default",
        host="192.168.121.10",
        user="vagrant",
        identity_file=str(identity),
        vm_name="opensuse15_default",
        vagrant_directory=str(project),
        vagrant_machine="default",
        vagrant_home="/home/hec/.vagrant.d",
    )

    result = Transport(target).run_script("id")

    assert result.returncode == 0
    assert captured["command"] == ["/usr/bin/vagrant", "ssh", "default", "-c", "sh -s"]
    assert captured["cwd"] == str(project)
    assert captured["env"]["HOME"] == "/root"
    assert captured["env"]["VAGRANT_HOME"] == "/root/.vagrant.d"


def test_vagrant_auth_failure_uses_qemu_guest_agent(monkeypatch, tmp_path) -> None:
    project = tmp_path / "opensuse15"
    project.mkdir()
    calls = []

    def fake_run(command, **kwargs):
        del kwargs
        calls.append(command)
        if command[0] == "/usr/bin/vagrant":
            return subprocess.CompletedProcess(command, 255, "", "Permission denied (publickey).")
        request = json.loads(command[-1])
        if request["execute"] == "guest-exec":
            return subprocess.CompletedProcess(command, 0, '{"return":{"pid":42}}', "")
        output = base64.b64encode(b"@@LHA_SECTION:os_release@@\nID=opensuse-leap\n").decode()
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps({"return": {"exited": True, "exitcode": 0, "out-data": output}}),
            "",
        )

    monkeypatch.setattr("hardening_agent.transport.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("hardening_agent.transport.subprocess.run", fake_run)
    target = Target(
        name="opensuse",
        host="192.168.121.10",
        user="vagrant",
        vm_name="opensuse15_default",
        vagrant_directory=str(project),
        vagrant_machine="default",
    )

    result = Transport(target).run_script("cat /etc/os-release")

    assert result.returncode == 0
    assert "ID=opensuse-leap" in result.stdout
    assert "used QEMU Guest Agent" in result.stderr
    assert any("qemu-agent-command" in command for command in calls)
