import bz2
import hashlib

from hardening_agent.models import Inventory, Platform
from hardening_agent.vulnerabilities import enrich_definitions, feed_for, materialize_feed_xml


def inventory(distribution: str, version: str) -> Inventory:
    return Inventory(
        target="test",
        collected_at="2026-08-11T00:00:00+00:00",
        platform=Platform("test", distribution, version, f"{distribution} {version}"),
        sections={},
    )


def test_feed_selection_is_exact_and_does_not_reuse_rhel_for_derivatives() -> None:
    assert "opensuse.leap.15.6-patch.xml.bz2" in feed_for(
        inventory("opensuse-leap", "15.6")
    ).url
    assert "trixie" in feed_for(inventory("debian", "13.5")).url
    assert feed_for(inventory("rocky", "9.6")) is None
    assert feed_for(inventory("rhel", "10")) is None


def test_oval_metadata_enrichment_is_streamed(tmp_path) -> None:
    definition_id = "oval:org.example:def:1"
    xml = f"""<?xml version="1.0"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions><definition id="{definition_id}" class="vulnerability">
    <metadata><title>Example vulnerability</title><reference source="CVE" ref_id="CVE-2026-0001"/>
    <advisory><severity>High</severity></advisory></metadata>
  </definition></definitions>
</oval_definitions>"""
    path = tmp_path / "feed.xml.bz2"
    path.write_bytes(bz2.compress(xml.encode()))

    result = enrich_definitions(path, {definition_id})[definition_id]

    assert result["title"] == "Example vulnerability"
    assert result["severity"] == "high"
    assert result["references"] == ["CVE-2026-0001"]
    assert result["definition_class"] == "vulnerability"


def test_bzip2_feed_is_materialized_locally_before_target_upload(tmp_path) -> None:
    xml = b"<?xml version='1.0'?><oval_definitions/>"
    compressed = tmp_path / "feed.xml.bz2"
    compressed.write_bytes(bz2.compress(xml))

    materialized, digest = materialize_feed_xml(compressed)
    try:
        assert materialized.suffix == ".xml"
        assert materialized.read_bytes() == xml
        assert digest == hashlib.sha256(xml).hexdigest()
    finally:
        materialized.unlink(missing_ok=True)
