"""Tests for the gitleaks binding: registration and delegation to the SARIF importer.

The importer itself is tested in test_sarif_common.py; the golden fixture pins
the parsed ids. What is left for a binding is that it registers under its file
stem, carries the right tool name, and hands the document to `parse_sarif`
with its own tags.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.core.adapters.gitleaks_adapter import GitleaksAdapter
from scripts.core.plugin_loader import PluginLoader, PluginRegistry

GOLDEN = Path("tests/fixtures/golden/gitleaks/v8.30.1/raw-output.json")


def test_registers_under_its_file_stem():
    loader = PluginLoader(PluginRegistry())
    name = loader._load_plugin(
        Path("scripts/core/adapters/gitleaks_adapter.py").resolve()
    )
    assert name == "gitleaks"
    assert loader.registry.get("gitleaks") is GitleaksAdapter
    meta = GitleaksAdapter().metadata
    assert (meta.tool_name, meta.output_format) == ("gitleaks", "sarif")


def test_parses_the_golden_document_with_the_binding_tags():
    findings = GitleaksAdapter().parse(GOLDEN)
    assert len(findings) == 69
    assert all(f.tool["name"] == "gitleaks" for f in findings)
    # gitleaks 8.30.1 writes no driver.version, only semanticVersion "v8.0.0"
    # (measured); versions.yaml's row, added with the descriptor, wins.
    assert all(f.tool["version"] == "8.30.1" for f in findings)
    assert all({"secrets", "sarif"} <= set(f.tags) for f in findings)
    assert all("://" not in f.location["path"] for f in findings)
    # gitleaks gives no severity at all, and verifies nothing: HIGH, like an
    # unverified TruffleHog secret (decided 2026-09-26), so `--fail-on HIGH`
    # stops on a leaked secret. SARIF's own default would be MEDIUM.
    assert {f.severity for f in findings} == {"HIGH"}


def test_the_secret_never_reaches_a_finding():
    """gitleaks' SARIF carries each matched secret, unredacted, in
    `region.snippet.text` (measured on the golden: 69 of 69, 20 to 1,674
    characters), and the importer keeps the whole result as `raw`. Before the
    scrub every one of them reached findings.json, the dashboard and history:
    the defect trufflehog's adapter fixed for `Raw` (juice-shop's RSA key)."""
    document = json.loads(GOLDEN.read_bytes())
    secrets = [
        r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
        for r in document["runs"][0]["results"]
    ]
    assert len(secrets) == 69 and all(secrets)

    findings = GitleaksAdapter().parse(GOLDEN)
    written = json.dumps([f.to_dict() for f in findings])

    assert [s for s in secrets if s in written] == []
    # The rest of the location survives: only the snippet goes.
    region = findings[0].raw["locations"][0]["physicalLocation"]["region"]
    assert "startLine" in region and "snippet" not in region
