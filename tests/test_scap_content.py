import zipfile

from hardening_agent import scap_content
from hardening_agent.models import Target
from hardening_agent.transport import CommandResult


def test_extracts_only_exact_debian13_datastream(tmp_path) -> None:
    archive = tmp_path / "content.zip"
    payload = b"<data-stream-collection/>"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("scap-security-guide/ssg-debian13-ds.xml", payload)
        bundle.writestr("scap-security-guide/ssg-debian12-ds.xml", b"old")

    extracted = scap_content._extract_datastream(archive, "debian13")
    try:
        assert extracted.read_bytes() == payload
    finally:
        extracted.unlink(missing_ok=True)


def test_installs_verified_content_in_versioned_usr_local_path(monkeypatch, tmp_path) -> None:
    stream = tmp_path / "ssg-debian13-ds.xml"
    stream.write_text("<data-stream-collection/>", encoding="utf-8")
    uploads = []

    class FakeTransport:
        def __init__(self, _target):
            pass

        def put_file(self, source, destination, timeout):
            uploads.append((source, destination, timeout))

        def run_script(self, script, timeout):
            assert timeout == 300
            assert "oscap info /usr/local/share/xml/scap/ssg/content/ssg-debian13-ds.xml" in script
            return CommandResult(
                0,
                "@@LHA_CONTENT_READY@@/usr/local/share/xml/scap/ssg/content/ssg-debian13-ds.xml\n",
                "",
            )

    monkeypatch.setattr(scap_content, "Transport", FakeTransport)
    monkeypatch.setattr(scap_content, "_archive", lambda: (tmp_path / "archive.zip", "abc"))
    monkeypatch.setattr(scap_content, "_extract_datastream", lambda _archive, _product: stream)

    result = scap_content.install_official_datastream(
        Target(name="debian13", local=True), "debian13"
    )

    assert result["status"] == "installed"
    assert result["content_version"] == scap_content.CONTENT_VERSION
    assert uploads[0][1].startswith("/tmp/lha-scap-debian13-")
