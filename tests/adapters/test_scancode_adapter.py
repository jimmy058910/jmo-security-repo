import json
from pathlib import Path

from scripts.core.adapters.scancode_adapter import ScancodeAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_scancode_adapter_mit_license(tmp_path: Path):
    """Test ScanCode adapter with MIT license detection."""
    data = {
        "headers": [
            {
                "tool_name": "scancode-toolkit",
                "tool_version": "32.0.0"
            }
        ],
        "files": [
            {
                "path": "src/main.py",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression": "mit",
                        "identifier": "mit-12345",
                        "matches": [
                            {
                                "score": 100.0,
                                "rule_identifier": "mit_1.RULE",
                                "license_expression": "mit"
                            }
                        ]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "scancode.json"
    write(f, data)
    adapter = ScancodeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "mit"
    assert items[0].severity == "INFO"
    assert "license-compliance" in items[0].tags
    assert "spdx" in items[0].tags
    assert items[0].context["license_expression"] == "mit"
    assert items[0].context["match_score"] == 100.0


def test_scancode_adapter_gpl_license(tmp_path: Path):
    """Test ScanCode adapter with GPL (copyleft) license detection."""
    data = {
        "headers": [{"tool_version": "32.0.0"}],
        "files": [
            {
                "path": "lib/utils.c",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression": "gpl-3.0",
                        "identifier": "gpl-67890",
                        "matches": [
                            {
                                "score": 95.5,
                                "rule_identifier": "gpl-3.0_1.RULE"
                            }
                        ]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "scancode.json"
    write(f, data)
    adapter = ScancodeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "gpl-3.0"
    assert items[0].severity == "LOW"  # Copyleft licenses flagged as LOW
    assert items[0].context["match_score"] == 95.5


def test_scancode_adapter_copyright_statement(tmp_path: Path):
    """Test ScanCode adapter with copyright detection."""
    data = {
        "headers": [{"tool_version": "32.0.0"}],
        "files": [
            {
                "path": "README.md",
                "type": "file",
                "copyrights": [
                    {
                        "value": "Copyright (c) 2023 Acme Corporation",
                        "start_line": 5,
                        "end_line": 5
                    }
                ]
            }
        ]
    }
    f = tmp_path / "scancode.json"
    write(f, data)
    adapter = ScancodeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "COPYRIGHT"
    assert items[0].severity == "INFO"
    assert "copyright" in items[0].tags
    assert items[0].location["startLine"] == 5
    assert "Acme Corporation" in items[0].context["copyright_statement"]


def test_scancode_adapter_license_and_copyright(tmp_path: Path):
    """Test ScanCode adapter with both license and copyright."""
    data = {
        "headers": [{"tool_version": "32.0.0"}],
        "files": [
            {
                "path": "LICENSE",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression": "apache-2.0",
                        "matches": [{"score": 100.0}]
                    }
                ],
                "copyrights": [
                    {
                        "value": "Copyright 2024 Example Inc.",
                        "start_line": 1,
                        "end_line": 1
                    }
                ]
            }
        ]
    }
    f = tmp_path / "scancode.json"
    write(f, data)
    adapter = ScancodeAdapter()
    items = adapter.parse(f)

    assert len(items) == 2  # One license + one copyright
    license_findings = [f for f in items if f.ruleId == "apache-2.0"]
    copyright_findings = [f for f in items if f.ruleId == "COPYRIGHT"]
    assert len(license_findings) == 1
    assert len(copyright_findings) == 1


def test_scancode_adapter_multiple_files(tmp_path: Path):
    """Test ScanCode adapter with multiple files."""
    data = {
        "headers": [{"tool_version": "32.0.0"}],
        "files": [
            {
                "path": "src/app.js",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression": "mit",
                        "matches": [{"score": 100.0}]
                    }
                ]
            },
            {
                "path": "src/utils.js",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression": "bsd-3-clause",
                        "matches": [{"score": 98.0}]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "scancode.json"
    write(f, data)
    adapter = ScancodeAdapter()
    items = adapter.parse(f)

    assert len(items) == 2
    assert items[0].ruleId == "mit"
    assert items[1].ruleId == "bsd-3-clause"


def test_scancode_adapter_skip_directories(tmp_path: Path):
    """Test ScanCode adapter skips directory entries."""
    data = {
        "headers": [{"tool_version": "32.0.0"}],
        "files": [
            {
                "path": "src",
                "type": "directory",  # Should be skipped
                "license_detections": [
                    {
                        "license_expression": "mit",
                        "matches": [{"score": 100.0}]
                    }
                ]
            },
            {
                "path": "src/main.py",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression": "mit",
                        "matches": [{"score": 100.0}]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "scancode.json"
    write(f, data)
    adapter = ScancodeAdapter()
    items = adapter.parse(f)

    # Only file should be processed
    assert len(items) == 1
    assert items[0].location["path"] == "src/main.py"


def test_scancode_adapter_empty_files(tmp_path: Path):
    """Test ScanCode adapter with empty files array."""
    data = {
        "headers": [{"tool_version": "32.0.0"}],
        "files": []
    }
    f = tmp_path / "scancode.json"
    write(f, data)
    adapter = ScancodeAdapter()
    items = adapter.parse(f)

    assert items == []


def test_scancode_adapter_no_detections(tmp_path: Path):
    """Test ScanCode adapter with file but no detections."""
    data = {
        "headers": [{"tool_version": "32.0.0"}],
        "files": [
            {
                "path": "test.txt",
                "type": "file",
                "license_detections": [],
                "copyrights": []
            }
        ]
    }
    f = tmp_path / "scancode.json"
    write(f, data)
    adapter = ScancodeAdapter()
    items = adapter.parse(f)

    assert items == []


def test_scancode_adapter_empty_file(tmp_path: Path):
    """Test ScanCode adapter handles empty JSON file."""
    f = tmp_path / "scancode.json"
    f.write_text("", encoding="utf-8")
    adapter = ScancodeAdapter()
    items = adapter.parse(f)

    assert items == []


def test_scancode_adapter_compliance_enrichment(tmp_path: Path):
    """Test that ScanCode findings are enriched with compliance mappings."""
    data = {
        "headers": [{"tool_version": "32.0.0"}],
        "files": [
            {
                "path": "LICENSE",
                "type": "file",
                "license_detections": [
                    {
                        "license_expression": "gpl-3.0",
                        "matches": [{"score": 100.0}]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "scancode.json"
    write(f, data)
    adapter = ScancodeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
