#!/usr/bin/env python3
"""Comprehensive tests for Phase 2: CSV Reporter (v1.0.0).

Tests the enterprise-grade CSV export functionality with configurable columns:
- Default columns: priority, kev, epss, severity, ruleId, path, line, message, tool, triaged
- Compliance columns: compliance_owasp, compliance_cwe, compliance_cis, compliance_nist, compliance_pci, compliance_attack
- Full columns: default + compliance
- CSV escaping: newlines, quotes, commas
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from scripts.core.reporters.csv_reporter import (
    write_csv,
    DEFAULT_COLUMNS,
    COMPLIANCE_COLUMNS,
    FULL_COLUMNS,
    _extract_row,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_findings() -> list[dict]:
    """Sample findings for testing CSV export."""
    return [
        {
            "schemaVersion": "1.2.0",
            "id": "finding-1",
            "ruleId": "CVE-2024-1234",
            "severity": "HIGH",
            "message": "Vulnerable dependency found",
            "tool": {"name": "trivy", "version": "0.50.0"},
            "location": {"path": "package.json", "startLine": 10},
            "priority": {"priority": 8.5, "is_kev": False, "epss": 0.12},
        },
        {
            "schemaVersion": "1.2.0",
            "id": "finding-2",
            "ruleId": "aws-secret-key",
            "severity": "CRITICAL",
            "message": "AWS secret key detected",
            "tool": {"name": "trufflehog", "version": "3.70.0"},
            "location": {"path": "config.yaml", "startLine": 5},
            "priority": {"priority": 9.8, "is_kev": True, "epss": 0.95},
        },
    ]


@pytest.fixture
def compliance_findings() -> list[dict]:
    """Sample findings with compliance mappings for testing."""
    return [
        {
            "schemaVersion": "1.2.0",
            "id": "compliance-test",
            "ruleId": "CWE-79",
            "severity": "HIGH",
            "message": "Cross-site scripting vulnerability",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "app.py", "startLine": 42},
            "priority": {"priority": 7.5, "is_kev": False, "epss": 0.05},
            "compliance": {
                "owaspTop10_2021": ["A03:2021"],
                "cweTop25_2024": [{"id": "CWE-79", "rank": 2, "category": "Web"}],
                "cisControlsV8_1": [{"control": "16.7", "ig": "IG1"}],
                "nistCsf2_0": [{"function": "PR", "category": "DS", "subcategory": "PR.DS-5"}],
                "pciDss4_0": [{"requirement": "6.5.7", "priority": "high"}],
                "mitreAttack": [{"tactic": "Initial Access", "technique": "T1190"}],
            },
        }
    ]


# ============================================================================
# Test: write_csv() with default columns
# ============================================================================


def test_write_csv_default_columns(tmp_path: Path, sample_findings):
    """Test write_csv() with default column set."""
    out_path = tmp_path / "findings.csv"

    write_csv(sample_findings, out_path)

    # Read back and verify structure
    with open(out_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Verify header
    assert reader.fieldnames == DEFAULT_COLUMNS

    # Verify row count
    assert len(rows) == 2

    # Verify first row
    row1 = rows[0]
    assert row1["priority"] == "8.5"
    assert row1["kev"] == "NO"
    assert row1["epss"] == "12.00%"
    assert row1["severity"] == "HIGH"
    assert row1["ruleId"] == "CVE-2024-1234"
    assert row1["path"] == "package.json"
    assert row1["line"] == "10"
    assert row1["message"] == "Vulnerable dependency found"
    assert row1["tool"] == "trivy"
    assert row1["triaged"] == "NO"

    # Verify second row (KEV finding)
    row2 = rows[1]
    assert row2["kev"] == "YES"
    assert row2["epss"] == "95.00%"


def test_write_csv_custom_columns(tmp_path: Path, sample_findings):
    """Test write_csv() with custom column selection."""
    out_path = tmp_path / "brief.csv"

    custom_columns = ["severity", "ruleId", "path", "message"]
    write_csv(sample_findings, out_path, columns=custom_columns)

    # Read back and verify
    with open(out_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Verify only specified columns
    assert reader.fieldnames == custom_columns
    assert len(rows) == 2
    assert "priority" not in rows[0]
    assert "tool" not in rows[0]


def test_write_csv_full_columns(tmp_path: Path, compliance_findings):
    """Test write_csv() with full column set (default + compliance)."""
    out_path = tmp_path / "full.csv"

    write_csv(compliance_findings, out_path, columns=FULL_COLUMNS)

    # Read back and verify
    with open(out_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Verify header includes all columns
    assert reader.fieldnames == FULL_COLUMNS

    # Verify compliance columns populated
    row = rows[0]
    assert row["compliance_owasp"] == "A03:2021"
    assert row["compliance_cwe"] == "CWE-79"
    assert row["compliance_cis"] == "16.7"
    assert row["compliance_nist"] == "PR.DS-5"
    assert row["compliance_pci"] == "6.5.7"
    assert row["compliance_attack"] == "T1190"


def test_write_csv_compliance_only_columns(tmp_path: Path, compliance_findings):
    """Test write_csv() with compliance columns only."""
    out_path = tmp_path / "compliance.csv"

    write_csv(compliance_findings, out_path, columns=COMPLIANCE_COLUMNS)

    # Read back and verify
    with open(out_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Verify compliance data extracted correctly
    row = rows[0]
    assert "CWE-79" in row["compliance_cwe"]
    assert "A03:2021" in row["compliance_owasp"]


def test_write_csv_no_header(tmp_path: Path, sample_findings):
    """Test write_csv() with header disabled."""
    out_path = tmp_path / "no_header.csv"

    write_csv(sample_findings, out_path, include_header=False)

    # Read file content
    content = out_path.read_text(encoding="utf-8")
    lines = content.strip().split("\n")

    # First line should be data, not header
    assert len(lines) == 2  # 2 findings
    assert "priority" not in lines[0]  # Should not have column names
    assert "8.5" in lines[0]  # Should have data


# ============================================================================
# Test: CSV escaping and special characters
# ============================================================================


def test_write_csv_escapes_newlines(tmp_path: Path):
    """Test that newlines in messages are converted to spaces."""
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "newline-test",
            "ruleId": "test-rule",
            "severity": "INFO",
            "message": "This is a multi-line\nmessage\nwith newlines",
            "tool": {"name": "test", "version": "1.0"},
            "location": {"path": "test.txt", "startLine": 1},
            "priority": {"priority": 5.0, "is_kev": False, "epss": 0.0},
        }
    ]

    out_path = tmp_path / "newlines.csv"
    write_csv(findings, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Message should be on single line (newlines replaced with spaces)
    lines = content.strip().split("\n")
    assert len(lines) == 2  # Header + 1 data row

    # Read with CSV parser to verify
    with open(out_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert "multi-line message with newlines" in rows[0]["message"]
    assert "\n" not in rows[0]["message"]


def test_write_csv_escapes_quotes(tmp_path: Path):
    """Test that quotes in messages are properly escaped."""
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "quote-test",
            "ruleId": "test-rule",
            "severity": "INFO",
            "message": 'Message with "double quotes" and special chars',
            "tool": {"name": "test", "version": "1.0"},
            "location": {"path": "test.txt", "startLine": 1},
            "priority": {"priority": 5.0, "is_kev": False, "epss": 0.0},
        }
    ]

    out_path = tmp_path / "quotes.csv"
    write_csv(findings, out_path)

    # Read with CSV parser to verify quotes preserved
    with open(out_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert 'Message with "double quotes" and special chars' in rows[0]["message"]


def test_write_csv_handles_commas(tmp_path: Path):
    """Test that commas in messages are properly quoted."""
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "comma-test",
            "ruleId": "test-rule",
            "severity": "INFO",
            "message": "Message with, commas, and, more, commas",
            "tool": {"name": "test", "version": "1.0"},
            "location": {"path": "test.txt", "startLine": 1},
            "priority": {"priority": 5.0, "is_kev": False, "epss": 0.0},
        }
    ]

    out_path = tmp_path / "commas.csv"
    write_csv(findings, out_path)

    # Read with CSV parser to verify commas preserved
    with open(out_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert "Message with, commas, and, more, commas" in rows[0]["message"]


def test_write_csv_utf8_encoding(tmp_path: Path):
    """Test write_csv() handles UTF-8 characters correctly."""
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "unicode-test",
            "ruleId": "test-rule",
            "severity": "INFO",
            "message": "Unicode test: 你好世界 🔒 café résumé",
            "tool": {"name": "test", "version": "1.0"},
            "location": {"path": "test.txt", "startLine": 1},
            "priority": {"priority": 5.0, "is_kev": False, "epss": 0.0},
        }
    ]

    out_path = tmp_path / "unicode.csv"
    write_csv(findings, out_path)

    # Read with CSV parser
    with open(out_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Unicode should be preserved
    assert "你好世界" in rows[0]["message"]
    assert "🔒" in rows[0]["message"]
    assert "café" in rows[0]["message"]
    assert "résumé" in rows[0]["message"]


# ============================================================================
# Test: Priority data handling
# ============================================================================


def test_extract_row_priority_formatting(sample_findings):
    """Test that priority score is formatted to 1 decimal place."""
    row = _extract_row(sample_findings[0], ["priority"])

    assert row == ["8.5"]


def test_extract_row_kev_boolean_conversion(sample_findings):
    """Test that is_kev boolean is converted to YES/NO."""
    row1 = _extract_row(sample_findings[0], ["kev"])  # is_kev: False
    row2 = _extract_row(sample_findings[1], ["kev"])  # is_kev: True

    assert row1 == ["NO"]
    assert row2 == ["YES"]


def test_extract_row_epss_percentage_formatting(sample_findings):
    """Test that EPSS score is formatted as percentage with 2 decimal places."""
    row1 = _extract_row(sample_findings[0], ["epss"])  # 0.12 -> 12.00%
    row2 = _extract_row(sample_findings[1], ["epss"])  # 0.95 -> 95.00%

    assert row1 == ["12.00%"]
    assert row2 == ["95.00%"]


def test_extract_row_missing_priority_data():
    """Test that missing priority data defaults gracefully."""
    finding = {
        "severity": "LOW",
        "ruleId": "test",
        "tool": {"name": "test"},
        "location": {"path": "test.txt"},
    }

    row = _extract_row(finding, ["priority", "kev", "epss"])

    assert row == ["0.0", "NO", ""]


def test_extract_row_null_epss():
    """Test that null EPSS score is handled."""
    finding = {
        "priority": {"priority": 5.0, "is_kev": False, "epss": None},
        "severity": "LOW",
        "ruleId": "test",
        "tool": {"name": "test"},
        "location": {"path": "test.txt"},
    }

    row = _extract_row(finding, ["epss"])

    assert row == [""]


# ============================================================================
# Test: Compliance data extraction
# ============================================================================


def test_extract_row_compliance_owasp(compliance_findings):
    """Test OWASP Top 10 extraction."""
    row = _extract_row(compliance_findings[0], ["compliance_owasp"])

    assert row == ["A03:2021"]


def test_extract_row_compliance_cwe_extracts_ids(compliance_findings):
    """Test CWE extraction with ID field."""
    row = _extract_row(compliance_findings[0], ["compliance_cwe"])

    # Should extract just the ID from the dict
    assert "CWE-79" in row[0]


def test_extract_row_compliance_cis_extracts_controls(compliance_findings):
    """Test CIS Controls extraction."""
    row = _extract_row(compliance_findings[0], ["compliance_cis"])

    assert "16.7" in row[0]


def test_extract_row_compliance_nist_extracts_subcategories(compliance_findings):
    """Test NIST CSF extraction."""
    row = _extract_row(compliance_findings[0], ["compliance_nist"])

    assert "PR.DS-5" in row[0]


def test_extract_row_compliance_pci_extracts_requirements(compliance_findings):
    """Test PCI DSS extraction."""
    row = _extract_row(compliance_findings[0], ["compliance_pci"])

    assert "6.5.7" in row[0]


def test_extract_row_compliance_attack_extracts_techniques(compliance_findings):
    """Test MITRE ATT&CK extraction."""
    row = _extract_row(compliance_findings[0], ["compliance_attack"])

    assert "T1190" in row[0]


def test_extract_row_multiple_compliance_values():
    """Test compliance extraction with multiple values."""
    finding = {
        "compliance": {
            "owaspTop10_2021": ["A03:2021", "A06:2021"],
            "cweTop25_2024": [{"id": "CWE-79"}, {"id": "CWE-89"}],
        },
        "severity": "HIGH",
        "ruleId": "test",
        "tool": {"name": "test"},
        "location": {"path": "test.txt"},
    }

    row = _extract_row(finding, ["compliance_owasp", "compliance_cwe"])

    assert "A03:2021, A06:2021" in row[0]
    assert "CWE-79, CWE-89" in row[1]


def test_extract_row_missing_compliance_data():
    """Test compliance extraction with missing data."""
    finding = {
        "severity": "LOW",
        "ruleId": "test",
        "tool": {"name": "test"},
        "location": {"path": "test.txt"},
    }

    row = _extract_row(finding, COMPLIANCE_COLUMNS)

    # All compliance columns should be empty
    assert row == ["", "", "", "", "", ""]


# ============================================================================
# Test: Location and tool extraction
# ============================================================================


def test_extract_row_path_extraction(sample_findings):
    """Test path extraction from location object."""
    row = _extract_row(sample_findings[0], ["path"])

    assert row == ["package.json"]


def test_extract_row_line_extraction(sample_findings):
    """Test line number extraction from location object."""
    row = _extract_row(sample_findings[0], ["line"])

    assert row == ["10"]


def test_extract_row_tool_name_extraction(sample_findings):
    """Test tool name extraction from tool object."""
    row = _extract_row(sample_findings[0], ["tool"])

    assert row == ["trivy"]


def test_extract_row_missing_location():
    """Test location extraction with missing location object."""
    finding = {
        "severity": "LOW",
        "ruleId": "test",
        "tool": {"name": "test"},
    }

    row = _extract_row(finding, ["path", "line"])

    assert row == ["", "0"]


def test_extract_row_missing_tool():
    """Test tool extraction with missing tool object."""
    finding = {
        "severity": "LOW",
        "ruleId": "test",
        "location": {"path": "test.txt"},
    }

    row = _extract_row(finding, ["tool"])

    assert row == [""]


# ============================================================================
# Test: File system operations
# ============================================================================


def test_write_csv_creates_parent_dirs(tmp_path: Path, sample_findings):
    """Test write_csv() creates parent directories if they don't exist."""
    out_path = tmp_path / "nested" / "dir" / "findings.csv"

    write_csv(sample_findings, out_path)

    assert out_path.exists()


def test_write_csv_overwrites_existing_file(tmp_path: Path, sample_findings):
    """Test write_csv() overwrites existing file."""
    out_path = tmp_path / "findings.csv"

    # Write first time
    write_csv(sample_findings[:1], out_path)
    first_content = out_path.read_text()

    # Write second time (all findings)
    write_csv(sample_findings, out_path)
    second_content = out_path.read_text()

    # Content should be different (more rows)
    assert first_content != second_content


# ============================================================================
# Test: Edge cases
# ============================================================================


def test_write_csv_empty_findings(tmp_path: Path):
    """Test write_csv() with empty findings list."""
    out_path = tmp_path / "empty.csv"

    write_csv([], out_path)

    # Should write header only
    content = out_path.read_text(encoding="utf-8")
    lines = content.strip().split("\n")
    assert len(lines) == 1  # Header only
    assert "priority" in lines[0]


def test_write_csv_large_dataset(tmp_path: Path):
    """Test CSV export with large dataset (1000+ findings)."""
    # Generate 1000 findings
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": f"finding-{i}",
            "ruleId": "test-rule",
            "severity": "INFO",
            "message": f"Finding {i}",
            "tool": {"name": "test", "version": "1.0"},
            "location": {"path": f"file{i}.txt", "startLine": i},
            "priority": {"priority": 5.0, "is_kev": False, "epss": 0.0},
        }
        for i in range(1000)
    ]

    out_path = tmp_path / "large.csv"
    write_csv(findings, out_path)

    # Read back and verify
    with open(out_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 1000


def test_write_csv_fallback_column():
    """Test _extract_row() fallback for unknown columns."""
    finding = {
        "custom_field": "custom_value",
        "severity": "LOW",
        "ruleId": "test",
        "tool": {"name": "test"},
        "location": {"path": "test.txt"},
    }

    row = _extract_row(finding, ["custom_field"])

    # Fallback: direct field access and convert to string
    assert row == ["custom_value"]


def test_write_csv_triaged_placeholder():
    """Test that triaged column shows placeholder value."""
    finding = {
        "severity": "LOW",
        "ruleId": "test",
        "tool": {"name": "test"},
        "location": {"path": "test.txt"},
    }

    row = _extract_row(finding, ["triaged"])

    # TODO: Hook into history DB for triage state (Feature #3)
    # For now, placeholder
    assert row == ["NO"]
