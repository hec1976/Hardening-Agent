import subprocess
from types import SimpleNamespace

from hardening_agent import libvirt
from hardening_agent.models import Target


def test_list_vms_reads_domain_and_guest_address(monkeypatch) -> None:
    outputs = {
        ("list", "--all", "--name"): (0, "suse01\n", ""),
        ("dominfo", "suse01"): (
            0,
            (
                "Id: 4\nName: suse01\nUUID: abc-123\nState: running\n"
                "CPU(s): 6\nMax memory: 8388608 KiB\nAutostart: enable\n"
            ),
            "",
        ),
        ("domifaddr", "suse01", "--source", "agent", "--full"): (
            0,
            (
                " Name MAC address Protocol Address\n"
                " vnet0 52:54:00:aa:bb:cc ipv4 192.168.122.44/24\n"
            ),
            "",
        ),
    }

    def fake_virsh(uri: str, *arguments: str, timeout: int = 15):
        del uri, timeout
        code, stdout, stderr = outputs[arguments]
        return subprocess.CompletedProcess(["virsh"], code, stdout, stderr)

    monkeypatch.setattr(libvirt, "_virsh", fake_virsh)
    monkeypatch.setattr(libvirt, "_vagrant_entries", list)
    vms, warnings = libvirt.list_vms()

    assert warnings == []
    assert vms[0]["name"] == "suse01"
    assert vms[0]["addresses"] == ["192.168.122.44"]
    assert vms[0]["vcpus"] == "6"


def test_list_vms_uses_lease_fallback(monkeypatch) -> None:
    def fake_virsh(uri: str, *arguments: str, timeout: int = 15):
        del uri, timeout
        if arguments[0] == "list":
            return subprocess.CompletedProcess(["virsh"], 0, "vm1\n", "")
        if arguments[0] == "dominfo":
            return subprocess.CompletedProcess(["virsh"], 0, "State: running\n", "")
        source = arguments[arguments.index("--source") + 1]
        if source == "agent":
            return subprocess.CompletedProcess(["virsh"], 1, "", "agent unavailable")
        return subprocess.CompletedProcess(
            ["virsh"], 0, "vnet0 52:54:00:00:00:01 ipv4 10.0.0.8/24\n", ""
        )

    monkeypatch.setattr(libvirt, "_virsh", fake_virsh)
    monkeypatch.setattr(libvirt, "_vagrant_entries", list)
    vms, _ = libvirt.list_vms()
    assert vms[0]["addresses"] == ["10.0.0.8"]


def test_virsh_forces_stable_non_localised_output(monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(libvirt.shutil, "which", lambda _name: "/usr/bin/virsh")

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        return subprocess.CompletedProcess(command, 0, "State: running\n", "")

    monkeypatch.setattr(libvirt.subprocess, "run", fake_run)

    result = libvirt._virsh("qemu:///system", "dominfo", "suse01")

    assert result.returncode == 0
    assert captured["environment"]["LC_ALL"] == "C"
    assert captured["environment"]["LANG"] == "C"


def test_list_vms_reports_unreadable_domain_status(monkeypatch) -> None:
    def fake_virsh(uri: str, *arguments: str, timeout: int = 15):
        del uri, timeout
        if arguments[0] == "list":
            return subprocess.CompletedProcess(["virsh"], 0, "vm1\n", "")
        return subprocess.CompletedProcess(["virsh"], 1, "", "permission denied")

    monkeypatch.setattr(libvirt, "_virsh", fake_virsh)
    monkeypatch.setattr(libvirt, "_vagrant_entries", list)

    vms, warnings = libvirt.list_vms()

    assert vms[0]["state"] == "unknown"
    assert "Status von vm1 konnte nicht gelesen werden" in warnings[0]


def test_parse_vagrant_status_keeps_libvirt_projects(tmp_path) -> None:
    output = (
        "id       name    provider state   directory\n"
        "abc1234  default libvirt  running " + str(tmp_path) + "\n"
        "def5678  default virtualbox running " + str(tmp_path) + "\n"
    )
    entries = libvirt._parse_vagrant_status(output)
    assert len(entries) == 1
    assert entries[0]["machine"] == "default"
    assert entries[0]["directory"] == str(tmp_path)


def test_discovers_vagrant_project_directly_from_provider_state(monkeypatch, tmp_path) -> None:
    project = tmp_path / "opensuse15"
    state = project / ".vagrant" / "machines" / "default" / "libvirt"
    state.mkdir(parents=True)
    state.joinpath("id").write_text("domain-uuid\n", encoding="utf-8")
    state.joinpath("private_key").write_text("key", encoding="utf-8")
    monkeypatch.setattr(libvirt, "_vagrant_project_roots", lambda: [tmp_path])

    entries = libvirt._vagrant_state_entries()

    assert entries == [
        {
            "id": "domain-uuid",
            "machine": "default",
            "provider": "libvirt",
            "state": "unknown",
            "directory": str(project),
        }
    ]


def test_root_discovers_vagrant_homes_of_regular_users(monkeypatch, tmp_path) -> None:
    vagrant_home = tmp_path / "hec" / ".vagrant.d"
    vagrant_home.mkdir(parents=True)
    monkeypatch.delenv("VAGRANT_HOME", raising=False)
    monkeypatch.setattr(libvirt.os, "geteuid", lambda: 0)

    candidates = libvirt._vagrant_home_candidates(tmp_path)

    assert candidates == [None, str(vagrant_home)]


def test_root_reads_operator_vagrant_index_through_runuser(monkeypatch, tmp_path) -> None:
    project = tmp_path / "opensuse15"
    project.mkdir()
    operator_home = tmp_path / "home" / "hec"
    operator_home.mkdir(parents=True)
    account = SimpleNamespace(pw_dir=str(operator_home))
    captured = []
    monkeypatch.setenv("LHA_OPERATOR", "hec")
    monkeypatch.delenv("VAGRANT_HOME", raising=False)
    monkeypatch.setattr(libvirt.os, "geteuid", lambda: 0)
    monkeypatch.setattr(libvirt.pwd, "getpwnam", lambda _name: account)
    monkeypatch.setattr(libvirt, "_vagrant_home_candidates", list)
    monkeypatch.setattr(
        libvirt.shutil,
        "which",
        lambda name: {
            "vagrant": "/usr/bin/vagrant",
            "runuser": "/usr/sbin/runuser",
            "env": "/usr/bin/env",
        }.get(name),
    )

    def fake_run(command, **kwargs):
        del kwargs
        captured.extend(command)
        output = f"35dc6d1 default libvirt running {project}\n"
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(libvirt.subprocess, "run", fake_run)

    entries = libvirt._vagrant_entries()

    assert entries[0]["directory"] == str(project)
    assert entries[0]["vagrant_home"] == str(operator_home / ".vagrant.d")
    assert captured[:4] == ["/usr/sbin/runuser", "-u", "hec", "--"]


def test_vagrant_key_access_preserves_root_owned_private_key(monkeypatch, tmp_path) -> None:
    project = tmp_path / "opensuse15"
    state = project / ".vagrant" / "machines" / "default" / "libvirt"
    state.mkdir(parents=True)
    identity = state / "private_key"
    identity.write_text("test-key", encoding="utf-8")
    identity.chmod(0o600)
    vagrant_home = tmp_path / "home" / ".vagrant.d"
    vagrant_home.mkdir(parents=True)
    account = SimpleNamespace(
        pw_uid=12345, pw_gid=identity.stat().st_gid, pw_dir=str(tmp_path / "home")
    )
    monkeypatch.setattr(libvirt.pwd, "getpwnam", lambda _name: account)
    monkeypatch.setattr(libvirt.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        libvirt,
        "_vagrant_entries",
        lambda: [
            {
                "directory": str(project),
                "machine": "default",
                "vagrant_home": str(vagrant_home),
            }
        ],
    )

    before_owner = identity.stat().st_uid
    report = libvirt.vagrant_key_access("hec")

    assert report[0]["status"] == "root-owned"
    assert report[0]["mode"] == "600"
    assert identity.stat().st_uid == before_owner


def test_vagrant_key_access_accepts_directly_discovered_project(monkeypatch, tmp_path) -> None:
    project = tmp_path / "opensuse15"
    state = project / ".vagrant" / "machines" / "default" / "libvirt"
    state.mkdir(parents=True)
    identity = state / "private_key"
    identity.write_text("key", encoding="utf-8")
    identity.chmod(0o600)
    account = SimpleNamespace(pw_uid=1000, pw_dir=str(tmp_path / "home"))
    monkeypatch.setattr(libvirt.pwd, "getpwnam", lambda _name: account)
    monkeypatch.setattr(libvirt.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        libvirt,
        "_vagrant_entries",
        lambda: [
            {
                "machine": "default",
                "directory": str(project),
                "state": "unknown",
            }
        ],
    )

    report = libvirt.vagrant_key_access("hec")

    assert report[0]["status"] == "root-owned"


def test_vagrant_ssh_config_uses_exact_managed_key(monkeypatch, tmp_path) -> None:
    identity = tmp_path / "private_key"
    identity.write_text("test-key", encoding="utf-8")
    vm = {
        "name": "opensuse15_default",
        "addresses": ["192.168.121.10"],
        "vagrant": {
            "machine": "default",
            "directory": str(tmp_path),
            "identity_file": str(identity),
            "provider_id": "uuid",
            "vagrant_home": str(tmp_path / ".vagrant.d"),
        },
    }
    monkeypatch.setattr(libvirt, "list_vms", lambda _uri: ([vm], []))
    monkeypatch.setattr(libvirt.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(libvirt.shutil, "which", lambda name: f"/usr/bin/{name}")

    captured_environment = {}

    def fake_run(*args, **kwargs):
        del args
        captured_environment.update(kwargs["env"])
        return subprocess.CompletedProcess(
            ["vagrant"],
            0,
            "Host default\n  HostName 192.168.121.10\n  User vagrant\n  Port 22\n"
            f'  IdentityFile "{identity}"\n  StrictHostKeyChecking no\n',
            "",
        )

    monkeypatch.setattr(libvirt.subprocess, "run", fake_run)
    config = libvirt.vagrant_ssh_config("opensuse15_default")
    assert config["host"] == "192.168.121.10"
    assert config["user"] == "vagrant"
    assert config["identity_file"] == str(identity)
    assert "stricthostkeychecking" not in config
    assert captured_environment["VAGRANT_HOME"] == str(tmp_path / ".vagrant.d")


def test_root_owned_key_selects_root_environment(monkeypatch, tmp_path) -> None:
    identity = tmp_path / "private_key"
    identity.write_text("test-key", encoding="utf-8")
    monkeypatch.setattr(libvirt.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        libvirt.pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_dir="/root"),
    )

    environment = libvirt._vagrant_runtime_environment(
        {
            "identity_file": str(identity),
            "vagrant_home": "/home/hec/.vagrant.d",
        }
    )

    assert environment["HOME"] == "/root"
    assert environment["USER"] == "root"
    assert environment["VAGRANT_HOME"] == "/root/.vagrant.d"


def test_match_vagrant_by_libvirt_provider_uuid(tmp_path) -> None:
    state = tmp_path / ".vagrant" / "machines" / "default" / "libvirt"
    state.mkdir(parents=True)
    state.joinpath("id").write_text("domain-uuid\n", encoding="utf-8")
    state.joinpath("private_key").write_text("test-key", encoding="utf-8")
    entry = {
        "id": "abc1234",
        "machine": "default",
        "provider": "libvirt",
        "state": "running",
        "directory": str(tmp_path),
    }
    metadata = libvirt._match_vagrant("custom-domain", "domain-uuid", [entry])
    assert metadata is not None
    assert metadata["identity_file"].endswith("/libvirt/private_key")


def test_refresh_vagrant_target_replaces_stale_connection(monkeypatch, tmp_path) -> None:
    identity = tmp_path / "private_key"
    identity.write_text("test-key", encoding="utf-8")
    vm = {"name": "opensuse15_default", "vagrant": {"machine": "default"}}
    monkeypatch.setattr(libvirt, "list_vms", lambda _uri: ([vm], []))
    monkeypatch.setattr(
        libvirt,
        "vagrant_ssh_config",
        lambda _name, _uri: {
            "host": "192.168.121.10",
            "user": "vagrant",
            "port": 22,
            "identity_file": str(identity),
            "machine": "default",
            "directory": str(tmp_path),
            "vagrant_home": str(tmp_path / ".vagrant.d"),
        },
    )
    stale = Target(
        name="guest",
        host="192.168.121.99",
        user="vagrant",
        vm_name="opensuse15_default",
    )

    refreshed = libvirt.refresh_vagrant_target(stale)

    assert refreshed.host == "192.168.121.10"
    assert refreshed.identity_file == str(identity)
    assert refreshed.vagrant_machine == "default"


def test_refresh_vagrant_target_leaves_plain_kvm_target_unchanged(monkeypatch) -> None:
    monkeypatch.setattr(libvirt, "list_vms", lambda _uri: ([{"name": "plain-vm"}], []))
    target = Target(name="guest", host="192.0.2.10", user="admin", vm_name="plain-vm")

    assert libvirt.refresh_vagrant_target(target) is target


def test_refresh_vagrant_target_infers_vm_from_target_name(monkeypatch, tmp_path) -> None:
    identity = tmp_path / "private_key"
    identity.write_text("test-key", encoding="utf-8")
    vm = {
        "name": "opensuse15_default",
        "addresses": ["192.168.121.10"],
        "vagrant": {"machine": "default"},
    }
    monkeypatch.setattr(libvirt, "list_vms", lambda _uri: ([vm], []))
    monkeypatch.setattr(
        libvirt,
        "vagrant_ssh_config",
        lambda _name, _uri: {
            "host": "192.168.121.10",
            "user": "vagrant",
            "port": 22,
            "identity_file": str(identity),
            "machine": "default",
            "directory": str(tmp_path),
            "vagrant_home": "/home/hec/.vagrant.d",
        },
    )
    target = Target(name="opensuse15_default", host="192.168.121.10", user="vagrant")

    refreshed = libvirt.refresh_vagrant_target(target)

    assert refreshed.vm_name == "opensuse15_default"
    assert refreshed.vagrant_machine == "default"
    assert refreshed.vagrant_directory == str(tmp_path)
