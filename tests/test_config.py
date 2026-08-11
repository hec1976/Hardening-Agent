import pytest

from hardening_agent.config import delete_target, load_targets, save_target
from hardening_agent.models import Target


def test_save_target_can_rename_existing_target(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LHA_HOME", str(tmp_path))
    save_target(Target(name="old", host="192.0.2.10", user="admin"))

    save_target(
        Target(name="new", host="192.0.2.11", user="vagrant"),
        original_name="old",
    )

    targets = load_targets()
    assert list(targets) == ["new"]
    assert targets["new"].host == "192.0.2.11"


def test_save_target_refuses_rename_over_existing_target(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LHA_HOME", str(tmp_path))
    save_target(Target(name="first", local=True))
    save_target(Target(name="second", local=True))

    with pytest.raises(ValueError, match="already exists"):
        save_target(Target(name="second", local=True), original_name="first")

    assert set(load_targets()) == {"first", "second"}


def test_save_target_refuses_stale_edit(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LHA_HOME", str(tmp_path))

    with pytest.raises(ValueError, match="Unknown target"):
        save_target(Target(name="renamed", local=True), original_name="missing")


def test_delete_target_removes_only_selected_target(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LHA_HOME", str(tmp_path))
    save_target(Target(name="keep", local=True))
    save_target(Target(name="remove", local=True))

    delete_target("remove")

    assert set(load_targets()) == {"keep"}


def test_delete_target_refuses_unknown_target(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LHA_HOME", str(tmp_path))

    with pytest.raises(ValueError, match="Unknown target"):
        delete_target("missing")
