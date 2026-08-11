import pytest

from hardening_agent.models import Target


def test_target_rejects_path_traversal_name() -> None:
    with pytest.raises(ValueError, match="Target name"):
        Target(name="../guest")


def test_target_rejects_option_like_host() -> None:
    with pytest.raises(ValueError, match="target host"):
        Target(name="guest", host="-oProxyCommand=bad")


def test_target_accepts_local_target() -> None:
    target = Target(name="local-test", local=True)
    assert target.destination == "localhost"
