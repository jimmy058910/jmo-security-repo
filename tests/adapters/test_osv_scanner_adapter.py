"""Tests for the osv-scanner binding: registration and delegation to the SARIF importer.

The importer itself is tested in test_sarif_common.py; the golden fixture pins
the parsed ids. What is left for a binding is that it registers under its file
stem (`osv_scanner`, which is what the report phase derives from
`osv-scanner.json`), carries the binary name, and hands the document to
`parse_sarif` with its own tags.
"""

from __future__ import annotations

from pathlib import Path

from scripts.core.adapters.osv_scanner_adapter import OsvScannerAdapter
from scripts.core.plugin_loader import PluginLoader, PluginRegistry

GOLDEN = Path("tests/fixtures/golden/osv_scanner/v2.5.1/raw-output.json")


def test_registers_under_its_file_stem():
    loader = PluginLoader(PluginRegistry())
    name = loader._load_plugin(
        Path("scripts/core/adapters/osv_scanner_adapter.py").resolve()
    )
    assert name == "osv_scanner"
    assert loader.registry.get("osv_scanner") is OsvScannerAdapter
    assert loader._tool_to_adapter_name("osv-scanner") == "osv_scanner"
    meta = OsvScannerAdapter().metadata
    assert (meta.tool_name, meta.output_format) == ("osv-scanner", "sarif")


def test_parses_the_golden_document_with_the_binding_tags():
    findings = OsvScannerAdapter().parse(GOLDEN)
    assert len(findings) == 303
    assert all(f.tool["name"] == "osv-scanner" for f in findings)
    assert all(f.tool["version"] == "2.5.1" for f in findings)
    assert all({"sca", "vulnerability", "sarif"} <= set(f.tags) for f in findings)
    # The file:// URI is decoded to a path the report phase can root-strip.
    assert all("://" not in f.location["path"] for f in findings)
    assert all(f.location["path"].endswith("package-lock.json") for f in findings)
    # osv-scanner supplies no region: no line is invented.
    assert all("startLine" not in f.location for f in findings)
    # 285 of 303 results resolve through security-severity (spec section 2.1);
    # level alone would make all 303 MEDIUM.
    assert sum(1 for f in findings if f.cvss) == 285
    assert "CRITICAL" in {f.severity for f in findings}
