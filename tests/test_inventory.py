from hardening_agent.inventory import detect_platform


def test_detect_opensuse() -> None:
    platform = detect_platform(
        'NAME="openSUSE Leap"\nID="opensuse-leap"\nVERSION_ID="15.6"\n'
        'PRETTY_NAME="openSUSE Leap 15.6"\n'
    )
    assert platform.family == "suse"
    assert platform.distribution == "opensuse-leap"
    assert platform.version == "15.6"


def test_detect_debian_and_rhel_family() -> None:
    assert detect_platform('ID=debian\nVERSION_ID="13"\n').family == "debian"
    assert detect_platform('ID=rocky\nVERSION_ID="9.5"\n').family == "rhel"
