"""
Unit tests for FindingsLoader class.

Tests loading, filtering, pagination, and error handling for findings data.
Coverage target: ≥90%
"""

import json
from pathlib import Path
import pytest

from scripts.mcp.utils.findings_loader import FindingsLoader


class TestFindingsLoaderInit:
    """Test FindingsLoader initialization."""

    def test_init_with_valid_findings_file(self, results_dir_with_findings: Path):
        """Test initialization with valid findings.json."""
        loader = FindingsLoader(results_dir_with_findings)
        assert loader.results_dir == results_dir_with_findings
        assert loader.findings_file.exists()

    def test_init_with_missing_findings_file(self, results_dir_empty: Path):
        """Test initialization with missing findings.json raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError) as exc_info:
            FindingsLoader(results_dir_empty)

        assert "Findings file not found" in str(exc_info.value)
        assert "findings.json" in str(exc_info.value)

    def test_init_with_nonexistent_directory(self, tmp_path: Path):
        """Test initialization with nonexistent directory."""
        nonexistent_dir = tmp_path / "does_not_exist"
        with pytest.raises(FileNotFoundError):
            FindingsLoader(nonexistent_dir)


class TestLoadFindings:
    """Test loading findings from JSON file."""

    def test_load_findings_success(
        self, results_dir_with_findings: Path, sample_findings: list
    ):
        """Test successful loading of findings."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        assert len(findings) == len(sample_findings)
        assert findings[0]["id"] == "fingerprint-abc123"
        assert findings[0]["severity"] == "HIGH"

    def test_load_findings_empty_file(self, tmp_path: Path):
        """Test loading empty findings file returns empty list."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_file = summaries_dir / "findings.json"
        findings_file.write_text("[]")

        loader = FindingsLoader(results_dir)
        findings = loader.load_findings()

        assert findings == []

    def test_load_findings_malformed_json(self, tmp_path: Path):
        """Test loading malformed JSON raises JSONDecodeError."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_file = summaries_dir / "findings.json"
        findings_file.write_text("{invalid json")

        loader = FindingsLoader(results_dir)

        with pytest.raises(json.JSONDecodeError):
            loader.load_findings()


class TestFilterFindings:
    """Test filtering findings by various criteria."""

    def test_filter_by_severity_single(self, results_dir_with_findings: Path):
        """Test filtering by single severity level."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings, severity=["HIGH"])

        assert len(filtered) == 1
        assert filtered[0]["severity"] == "HIGH"
        assert filtered[0]["id"] == "fingerprint-abc123"

    def test_filter_by_severity_multiple(self, results_dir_with_findings: Path):
        """Test filtering by multiple severity levels."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings, severity=["HIGH", "CRITICAL"])

        assert len(filtered) == 3  # 1 HIGH + 2 CRITICAL
        severities = {f["severity"] for f in filtered}
        assert severities == {"HIGH", "CRITICAL"}

    def test_filter_by_tool(self, results_dir_with_findings: Path):
        """Test filtering by tool name."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings, tool="semgrep")

        assert len(filtered) == 2
        assert all(f["tool"]["name"] == "semgrep" for f in filtered)

    def test_filter_by_rule_id(self, results_dir_with_findings: Path):
        """Test filtering by rule ID."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings, rule_id="CWE-79")

        assert len(filtered) == 1
        assert filtered[0]["ruleId"] == "CWE-79"

    def test_filter_by_path_exact(self, results_dir_with_findings: Path):
        """Test filtering by exact file path."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings, path="src/app.js")

        assert len(filtered) == 1
        assert filtered[0]["location"]["path"] == "src/app.js"

    def test_filter_by_path_substring(self, results_dir_with_findings: Path):
        """Test filtering by path substring match."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings, path="src/")

        assert len(filtered) == 2  # src/app.js and src/db.py
        assert all("src/" in f["location"]["path"] for f in filtered)

    def test_filter_combined(self, results_dir_with_findings: Path):
        """Test filtering with multiple criteria combined."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(
            findings,
            severity=["CRITICAL"],
            tool="semgrep",
        )

        assert len(filtered) == 1
        assert filtered[0]["severity"] == "CRITICAL"
        assert filtered[0]["tool"]["name"] == "semgrep"

    def test_filter_no_matches(self, results_dir_with_findings: Path):
        """Test filtering with no matches returns empty list."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings, severity=["INFO"])

        assert filtered == []

    def test_filter_case_insensitive_severity(self, results_dir_with_findings: Path):
        """Test severity filtering is case-insensitive."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings, severity=["high"])

        assert len(filtered) == 1
        assert filtered[0]["severity"] == "HIGH"


class TestPagination:
    """Test pagination support in filter_findings."""

    def test_pagination_limit(self, results_dir_with_findings: Path):
        """Test limit parameter restricts results."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings, limit=2)

        assert len(filtered) == 2

    def test_pagination_offset(self, results_dir_with_findings: Path):
        """Test offset parameter skips results."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        # Get first 3 findings
        first_page = loader.filter_findings(findings, limit=3, offset=0)
        # Get next 2 findings
        second_page = loader.filter_findings(findings, limit=2, offset=3)

        assert len(first_page) == 3
        assert len(second_page) == 2
        assert first_page[0]["id"] != second_page[0]["id"]

    def test_pagination_limit_exceeds_results(self, results_dir_with_findings: Path):
        """Test limit larger than total results returns all."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings, limit=1000)

        assert len(filtered) == len(findings)

    def test_pagination_offset_exceeds_results(self, results_dir_with_findings: Path):
        """Test offset larger than total results returns empty list."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings, offset=1000)

        assert filtered == []

    def test_pagination_default_values(self, results_dir_with_findings: Path):
        """Test default pagination values (limit=100, offset=0)."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(findings)

        # Should return all findings (less than default limit of 100)
        assert len(filtered) == len(findings)


class TestGetFindingById:
    """Test retrieving single finding by fingerprint ID."""

    def test_get_finding_by_id_exists(self, results_dir_with_findings: Path):
        """Test retrieving existing finding by ID."""
        loader = FindingsLoader(results_dir_with_findings)

        finding = loader.get_finding_by_id("fingerprint-abc123")

        assert finding is not None
        assert finding["id"] == "fingerprint-abc123"
        assert finding["severity"] == "HIGH"

    def test_get_finding_by_id_not_exists(self, results_dir_with_findings: Path):
        """Test retrieving non-existent finding returns None."""
        loader = FindingsLoader(results_dir_with_findings)

        finding = loader.get_finding_by_id("nonexistent-id")

        assert finding is None

    def test_get_finding_by_id_empty_findings(self, tmp_path: Path):
        """Test retrieving from empty findings returns None."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_file = summaries_dir / "findings.json"
        findings_file.write_text("[]")

        loader = FindingsLoader(results_dir)
        finding = loader.get_finding_by_id("any-id")

        assert finding is None


class TestGetTotalCount:
    """Test getting total count of findings."""

    def test_get_total_count(
        self, results_dir_with_findings: Path, sample_findings: list
    ):
        """Test getting total count matches findings."""
        loader = FindingsLoader(results_dir_with_findings)

        count = loader.get_total_count()

        assert count == len(sample_findings)

    def test_get_total_count_empty(self, tmp_path: Path):
        """Test getting total count with empty findings."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_file = summaries_dir / "findings.json"
        findings_file.write_text("[]")

        loader = FindingsLoader(results_dir)
        count = loader.get_total_count()

        assert count == 0


class TestGetSeverityDistribution:
    """Test getting severity distribution statistics."""

    def test_get_severity_distribution(self, results_dir_with_findings: Path):
        """Test severity distribution calculation."""
        loader = FindingsLoader(results_dir_with_findings)

        distribution = loader.get_severity_distribution()

        assert distribution["CRITICAL"] == 2
        assert distribution["HIGH"] == 1
        assert distribution["MEDIUM"] == 1
        assert distribution["LOW"] == 1
        assert "INFO" not in distribution  # No INFO findings

    def test_get_severity_distribution_empty(self, tmp_path: Path):
        """Test severity distribution with empty findings."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_file = summaries_dir / "findings.json"
        findings_file.write_text("[]")

        loader = FindingsLoader(results_dir)
        distribution = loader.get_severity_distribution()

        assert distribution == {}

    def test_get_severity_distribution_single_severity(self, tmp_path: Path):
        """Test severity distribution with single severity level."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_file = summaries_dir / "findings.json"
        findings_file.write_text(
            json.dumps(
                [
                    {
                        "schemaVersion": "1.2.0",
                        "id": "test-1",
                        "severity": "HIGH",
                        "ruleId": "test-rule",
                        "tool": {"name": "test", "version": "1.0"},
                        "location": {"path": "test.py", "startLine": 1},
                        "message": "Test finding",
                    },
                    {
                        "schemaVersion": "1.2.0",
                        "id": "test-2",
                        "severity": "HIGH",
                        "ruleId": "test-rule",
                        "tool": {"name": "test", "version": "1.0"},
                        "location": {"path": "test.py", "startLine": 2},
                        "message": "Test finding 2",
                    },
                ]
            )
        )

        loader = FindingsLoader(results_dir)
        distribution = loader.get_severity_distribution()

        assert distribution == {"HIGH": 2}


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_load_findings_invalid_structure(self, tmp_path: Path):
        """Test loading findings.json with invalid structure (dict instead of list)."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        # Write dict instead of list
        findings_file = summaries_dir / "findings.json"
        findings_file.write_text(json.dumps({"findings": []}))

        loader = FindingsLoader(results_dir)

        with pytest.raises(ValueError) as exc_info:
            loader.load_findings()

        assert "must contain a list" in str(exc_info.value)

    def test_load_findings_file_permission_error(self, tmp_path: Path, monkeypatch):
        """Test loading findings.json with file permission error."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_file = summaries_dir / "findings.json"
        findings_file.write_text("[]")

        loader = FindingsLoader(results_dir)

        # Mock open to raise PermissionError
        import builtins

        original_open = builtins.open

        def mock_open(*args, **kwargs):
            if "findings.json" in str(args[0]):
                raise PermissionError("Permission denied")
            return original_open(*args, **kwargs)

        monkeypatch.setattr(builtins, "open", mock_open)

        with pytest.raises(PermissionError):
            loader.load_findings()

    def test_filter_with_none_values(self, results_dir_with_findings: Path):
        """Test filtering with all None values returns all findings."""
        loader = FindingsLoader(results_dir_with_findings)
        findings = loader.load_findings()

        filtered = loader.filter_findings(
            findings,
            severity=None,
            tool=None,
            rule_id=None,
            path=None,
        )

        assert len(filtered) == len(findings)

    def test_filter_empty_findings_list(self, results_dir_with_findings: Path):
        """Test filtering empty findings list returns empty list."""
        loader = FindingsLoader(results_dir_with_findings)

        filtered = loader.filter_findings([], severity=["HIGH"])

        assert filtered == []

    def test_findings_without_required_fields(self, tmp_path: Path):
        """Test handling findings with missing required fields."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        # Create finding missing 'tool' field
        findings_file = summaries_dir / "findings.json"
        findings_file.write_text(
            json.dumps(
                [
                    {
                        "id": "test-1",
                        "severity": "HIGH",
                        "ruleId": "test-rule",
                        # Missing 'tool' field
                        "location": {"path": "test.py", "startLine": 1},
                        "message": "Test finding",
                    }
                ]
            )
        )

        loader = FindingsLoader(results_dir)
        findings = loader.load_findings()

        # Should still load, but filtering by tool might fail gracefully
        assert len(findings) == 1

        # Filter by tool should handle missing field
        filtered = loader.filter_findings(findings, tool="test")
        # Should return empty since finding has no tool field
        assert len(filtered) == 0
