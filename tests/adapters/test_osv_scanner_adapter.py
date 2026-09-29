"""Tests for the osv-scanner binding: registration and delegation to the SARIF importer.

The importer itself is tested in test_sarif_common.py; the golden fixture pins
the parsed ids. What is left for a binding is that it registers under its file
stem (`osv_scanner`, which is what the report phase derives from
`osv-scanner.json`), carries the binary name, hands the document to
`parse_sarif` with its own tags, and reads each result's package (#1346).
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.core.adapters.osv_scanner_adapter import OsvScannerAdapter
from scripts.core.common_finding import fingerprint
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
    # versions.yaml's pin, read first, not the document's 2.5.1: the golden
    # predates the pin (Phase 4, O1), and the pin is the binary a scan runs.
    assert all(f.tool["version"] == "2.6.0" for f in findings)
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


def test_every_golden_result_names_its_package():
    """#1346. SARIF has no package field; osv-scanner's message template and
    its rule's `deprecatedIds` are where it puts the package and the aliases
    (measured on 2.5.1 and 2.6.0)."""
    findings = OsvScannerAdapter().parse(GOLDEN)
    assert all(f.dependency for f in findings)
    first = findings[0]
    assert first.message.startswith("Package 'minimatch@0.3.0' is vulnerable to")
    # deprecatedIds lists the rule's own id too; an alias is another id.
    assert first.dependency == {
        "name": "minimatch",
        "version": "0.3.0",
        "aliases": ["GHSA-23c5-xmqv-rm74"],
    }
    assert not any(f.ruleId in f.dependency["aliases"] for f in findings)
    # The id is keyed on the package, like trivy's and grype's.
    assert first.id == fingerprint(
        "osv-scanner",
        first.ruleId,
        first.location["path"],
        None,
        first.message,
        package="minimatch@0.3.0",
    )


def _document(tmp_path: Path, message: str) -> Path:
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "osv-scanner",
                        "rules": [
                            {
                                "id": "CVE-2023-45133",
                                "deprecatedIds": [
                                    "CVE-2023-45133",
                                    "GHSA-67hx-6x53-jw92",
                                ],
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "CVE-2023-45133",
                        "ruleIndex": 0,
                        "message": {"text": message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "package-lock.json"}
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path = tmp_path / "osv-scanner.json"
    path.write_bytes(json.dumps(doc).encode("utf-8"))
    return path


def test_a_scoped_name_keeps_its_scope(tmp_path):
    [finding] = OsvScannerAdapter().parse(
        _document(
            tmp_path,
            "Package '@babel/traverse@7.22.5' is vulnerable to 'CVE-2023-45133' "
            "(also known as 'GHSA-67hx-6x53-jw92').",
        )
    )
    assert (finding.dependency["name"], finding.dependency["version"]) == (
        "@babel/traverse",
        "7.22.5",
    )
    assert finding.dependency["aliases"] == ["GHSA-67hx-6x53-jw92"]


def test_a_message_outside_the_template_names_no_package(tmp_path):
    [finding] = OsvScannerAdapter().parse(_document(tmp_path, "something else"))
    assert finding.dependency is None
    assert finding.id == fingerprint(
        "osv-scanner", "CVE-2023-45133", "package-lock.json", None, "something else"
    )
