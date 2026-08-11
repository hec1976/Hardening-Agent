from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

TARGET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:%-]{0,252}$")
USER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
VM_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


@dataclass(frozen=True)
class Target:
    name: str
    host: str = "localhost"
    user: str | None = None
    port: int = 22
    identity_file: str | None = None
    local: bool = False
    vm_name: str | None = None
    libvirt_uri: str = "qemu:///system"
    vagrant_directory: str | None = None
    vagrant_machine: str | None = None
    vagrant_home: str | None = None

    def __post_init__(self) -> None:
        if not TARGET_NAME_PATTERN.fullmatch(self.name):
            raise ValueError(
                "Target name must contain only letters, numbers, dot, dash or underscore"
            )
        if not self.local and not HOST_PATTERN.fullmatch(self.host):
            raise ValueError("Unsafe or invalid target host")
        if self.user and not USER_PATTERN.fullmatch(self.user):
            raise ValueError("Unsafe or invalid SSH user")
        if not 1 <= self.port <= 65535:
            raise ValueError("SSH port must be between 1 and 65535")
        if not self.libvirt_uri.startswith(("qemu:///", "qemu+ssh://", "test:///")):
            raise ValueError("Unsupported libvirt URI")
        if self.vm_name and not VM_NAME_PATTERN.fullmatch(self.vm_name):
            raise ValueError("Unsafe KVM domain name")
        if self.vagrant_directory and not Path(self.vagrant_directory).is_absolute():
            raise ValueError("Vagrant directory must be an absolute path")
        if self.vagrant_home and not Path(self.vagrant_home).is_absolute():
            raise ValueError("Vagrant home must be an absolute path")
        if self.vagrant_machine and not TARGET_NAME_PATTERN.fullmatch(self.vagrant_machine):
            raise ValueError("Unsafe Vagrant machine name")

    @property
    def destination(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host


@dataclass(frozen=True)
class Platform:
    family: str
    distribution: str
    version: str
    pretty_name: str


@dataclass
class Inventory:
    target: str
    collected_at: str
    platform: Platform
    sections: dict[str, str]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data



