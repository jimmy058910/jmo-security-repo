"""Tests for the gitleaks binding: registration and delegation to the SARIF importer.

The importer itself is tested in test_sarif_common.py; the golden fixture pins
the parsed ids. What is left for a binding is that it registers under its file
stem, carries the right tool name, and hands the document to `parse_sarif`
with its own tags.
"""

from __future__ import annotations

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
    # Measured: gitleaks 8.30.1 writes no driver.version, only
    # semanticVersion "v8.0.0", and versions.yaml has no gitleaks row yet.
    assert all(f.tool["version"] == "v8.0.0" for f in findings)
    assert all({"secrets", "sarif"} <= set(f.tags) for f in findings)
    assert all("://" not in f.location["path"] for f in findings)
    # No level, no severity property: SARIF's documented default, MEDIUM.
    assert {f.severity for f in findings} == {"MEDIUM"}
