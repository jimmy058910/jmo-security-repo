"""Tests for the zizmor binding: registration and delegation to the SARIF importer.

The importer itself is tested in test_sarif_common.py; the golden fixture pins
the parsed ids. What is left for a binding is that it registers under its file
stem, carries the right tool name, and hands the document to `parse_sarif`
with its own tags.
"""

from __future__ import annotations

from pathlib import Path

from scripts.core.adapters.zizmor_adapter import ZizmorAdapter
from scripts.core.plugin_loader import PluginLoader, PluginRegistry

GOLDEN = Path("tests/fixtures/golden/zizmor/v1.30.1/raw-output.json")


def test_registers_under_its_file_stem():
    loader = PluginLoader(PluginRegistry())
    name = loader._load_plugin(
        Path("scripts/core/adapters/zizmor_adapter.py").resolve()
    )
    assert name == "zizmor"
    assert loader.registry.get("zizmor") is ZizmorAdapter
    meta = ZizmorAdapter().metadata
    assert (meta.tool_name, meta.output_format) == ("zizmor", "sarif")


def test_parses_the_golden_document_with_the_binding_tags():
    findings = ZizmorAdapter().parse(GOLDEN)
    assert len(findings) == 217
    assert all(f.tool["name"] == "zizmor" for f in findings)
    assert all(f.tool["version"] == "1.30.1" for f in findings)
    assert all({"github-actions", "workflow", "sarif"} <= set(f.tags) for f in findings)
    assert all("://" not in f.location["path"] for f in findings)
    # zizmor/severity, not level: level=note covers both Low and Informational.
    assert {f.severity for f in findings} == {"HIGH", "MEDIUM", "LOW", "INFO"}
