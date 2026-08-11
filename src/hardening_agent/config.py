from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path

from .models import TARGET_NAME_PATTERN, Inventory, Platform, Target


def data_home() -> Path:
    override = os.environ.get("LHA_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".local" / "share" / "linux-hardening-agent"


def targets_path() -> Path:
    return data_home() / "targets.json"


def custom_guidelines_path() -> Path:
    """Return the update-safe operator guideline-source location."""
    return data_home() / "guidelines" / "sources.json"


def policy_profiles_path() -> Path:
    """Return the operator-owned selected OpenSCAP profiles file."""
    return data_home() / "profiles" / "openscap.json"


def load_policy_profiles() -> list[dict[str, object]]:
    path = policy_profiles_path()
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise TypeError("Ungültige OpenSCAP-Profildatei")
    return [item for item in raw if isinstance(item, dict)]


def save_policy_profiles(profiles: list[dict[str, object]]) -> None:
    path = policy_profiles_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(profiles, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def load_targets() -> dict[str, Target]:
    path = targets_path()
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {name: Target(**value) for name, value in raw.items()}


def _write_targets(targets: dict[str, Target]) -> None:
    path = targets_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({name: asdict(item) for name, item in targets.items()}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def save_target(target: Target, original_name: str | None = None) -> None:
    targets = load_targets()
    if original_name is not None:
        if not TARGET_NAME_PATTERN.fullmatch(original_name):
            raise ValueError("Unsafe original target name")
        if original_name not in targets:
            raise ValueError(f"Unknown target {original_name!r}; reload the target list")
        if target.name != original_name and target.name in targets:
            raise ValueError(f"Target {target.name!r} already exists")
        if target.name != original_name:
            del targets[original_name]
    targets[target.name] = target
    _write_targets(targets)


def delete_target(name: str) -> None:
    if not TARGET_NAME_PATTERN.fullmatch(name):
        raise ValueError("Unsafe target name")
    targets = load_targets()
    if name not in targets:
        raise ValueError(f"Unknown target {name!r}; reload the target list")
    del targets[name]
    _write_targets(targets)


def get_target(name: str) -> Target:
    targets = load_targets()
    try:
        return targets[name]
    except KeyError as exc:
        raise ValueError(f"Unknown target {name!r}; add it first") from exc


def inventory_path(name: str) -> Path:
    if not TARGET_NAME_PATTERN.fullmatch(name):
        raise ValueError("Unsafe inventory name")
    return data_home() / "inventories" / f"{name}.json"


def save_inventory(inventory: Inventory, output: Path | None = None) -> Path:
    path = output or inventory_path(inventory.target)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(inventory.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
    return path


def load_inventory(path: Path) -> Inventory:
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["platform"] = Platform(**raw["platform"])
    return Inventory(**raw)
