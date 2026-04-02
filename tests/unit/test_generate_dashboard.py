#!/usr/bin/env python3
"""Tests for scripts/core/generate_dashboard.py dashboard generation."""

from __future__ import annotations

import json
from pathlib import Path


from scripts.core.generate_dashboard import (
    calculate_metrics,
    generate_dashboard,
    parse_gitleaks,
    parse_noseyparker,
    parse_semgrep,
    parse_trufflehog,
)


class TestParseGitleaks:
    """Tests for parse_gitleaks function."""

    def test_parse_empty_file(self, tmp_path: Path) -> None:
        """Test parsing empty gitleaks JSON."""
        filepath = tmp_path / "gitleaks.json"
        filepath.write_text("[]")
        result = parse_gitleaks(str(filepath))
        assert result == []

    def test_parse_findings(self, tmp_path: Path) -> None:
        """Test parsing gitleaks findings."""
        filepath = tmp_path / "gitleaks.json"
        data = [
            {
                "RuleID": "aws-access-key",
                "File": "config.py",
                "StartLine": 10,
                "Description": "AWS Access Key detected",
            }
        ]
        filepath.write_text(json.dumps(data))
        result = parse_gitleaks(str(filepath))
        assert len(result) == 1
        assert result[0]["tool"] == "gitleaks"
        assert result[0]["type"] == "aws-access-key"
        assert result[0]["severity"] == "HIGH"
        assert result[0]["file"] == "config.py"
        assert result[0]["line"] == 10

    def test_parse_nonexistent_file(self, tmp_path: Path) -> None:
        """Test parsing nonexistent file returns empty list."""
        result = parse_gitleaks(str(tmp_path / "nonexistent.json"))
        assert result == []

    def test_parse_invalid_json(self, tmp_path: Path) -> None:
        """Test parsing invalid JSON returns empty list."""
        filepath = tmp_path / "gitleaks.json"
        filepath.write_text("not valid json")
        result = parse_gitleaks(str(filepath))
        assert result == []


class TestParseTrufflehog:
    """Tests for parse_trufflehog function."""

    def test_parse_empty_file(self, tmp_path: Path) -> None:
        """Test parsing empty trufflehog output."""
        filepath = tmp_path / "trufflehog.json"
        filepath.write_text("[]")
        result = parse_trufflehog(str(filepath))
        assert result == []

    def test_parse_verified_finding(self, tmp_path: Path) -> None:
        """Test parsing verified trufflehog finding."""
        filepath = tmp_path / "trufflehog.json"
        data = [
            {
                "DetectorName": "AWS",
                "Verified": True,
                "SourceMetadata": {"Data": {"Filesystem": {"file": "secrets.py"}}},
            }
        ]
        filepath.write_text(json.dumps(data))
        result = parse_trufflehog(str(filepath))
        assert len(result) == 1
        assert result[0]["tool"] == "trufflehog"
        assert result[0]["severity"] == "CRITICAL"
        assert result[0]["verified"] is True
        assert result[0]["file"] == "secrets.py"

    def test_parse_unverified_finding(self, tmp_path: Path) -> None:
        """Test parsing unverified trufflehog finding."""
        filepath = tmp_path / "trufflehog.json"
        data = [
            {
                "DetectorName": "Generic",
                "Verified": False,
                "SourceMetadata": {},
            }
        ]
        filepath.write_text(json.dumps(data))
        result = parse_trufflehog(str(filepath))
        assert len(result) == 1
        assert result[0]["severity"] == "MEDIUM"
        assert result[0]["verified"] is False

    def test_parse_ndjson_format(self, tmp_path: Path) -> None:
        """Test parsing NDJSON (newline-delimited JSON) format."""
        filepath = tmp_path / "trufflehog.json"
        lines = [
            json.dumps(
                {"DetectorName": "AWS", "Verified": False, "SourceMetadata": {}}
            ),
            json.dumps(
                {"DetectorName": "GitHub", "Verified": True, "SourceMetadata": {}}
            ),
        ]
        filepath.write_text("\n".join(lines))
        result = parse_trufflehog(str(filepath))
        assert len(result) == 2


class TestParseSemgrep:
    """Tests for parse_semgrep function."""

    def test_parse_empty_results(self, tmp_path: Path) -> None:
        """Test parsing semgrep with no results."""
        filepath = tmp_path / "semgrep.json"
        filepath.write_text(json.dumps({"results": []}))
        result = parse_semgrep(str(filepath))
        assert result == []

    def test_parse_findings(self, tmp_path: Path) -> None:
        """Test parsing semgrep findings."""
        filepath = tmp_path / "semgrep.json"
        data = {
            "results": [
                {
                    "check_id": "python.lang.security.sql-injection",
                    "path": "app.py",
                    "start": {"line": 42},
                    "extra": {
                        "severity": "ERROR",
                        "message": "SQL injection detected",
                    },
                }
            ]
        }
        filepath.write_text(json.dumps(data))
        result = parse_semgrep(str(filepath))
        assert len(result) == 1
        assert result[0]["tool"] == "semgrep"
        assert result[0]["type"] == "python.lang.security.sql-injection"
        assert result[0]["severity"] == "ERROR"
        assert result[0]["file"] == "app.py"
        assert result[0]["line"] == 42


class TestParseNoseyparker:
    """Tests for parse_noseyparker function."""

    def test_parse_empty_file(self, tmp_path: Path) -> None:
        """Test parsing empty noseyparker output."""
        filepath = tmp_path / "noseyparker.json"
        filepath.write_text("[]")
        result = parse_noseyparker(str(filepath))
        assert result == []

    def test_parse_findings_list(self, tmp_path: Path) -> None:
        """Test parsing noseyparker findings list format."""
        filepath = tmp_path / "noseyparker.json"
        data = [
            {
                "rule_name": "aws_secret_access_key",
                "matches": [
                    {
                        "provenance": [{"kind": "file", "path": "config.py"}],
                        "location": {"source_span": {"start": {"line": 5}}},
                        "snippet": {"matching": "AKIAIOSFODNN7EXAMPLE"},
                    }
                ],
            }
        ]
        filepath.write_text(json.dumps(data))
        result = parse_noseyparker(str(filepath))
        assert len(result) == 1
        assert result[0]["tool"] == "noseyparker"
        assert result[0]["type"] == "aws_secret_access_key"
        assert result[0]["file"] == "config.py"
        assert result[0]["line"] == 5


class TestCalculateMetrics:
    """Tests for calculate_metrics function."""

    def test_empty_results_directory(self, tmp_path: Path) -> None:
        """Test metrics calculation with no results."""
        metrics = calculate_metrics(str(tmp_path))
        assert metrics["total_findings"] == 0
        assert metrics["verified_secrets"] == 0
        assert metrics["critical_count"] == 0
        assert metrics["repo_stats"] == []

    def test_with_findings(self, tmp_path: Path) -> None:
        """Test metrics calculation with actual findings."""
        repos_dir = tmp_path / "individual-repos" / "test-repo"
        repos_dir.mkdir(parents=True)

        # Create gitleaks findings
        gitleaks_data = [
            {"RuleID": "secret", "File": "test.py", "StartLine": 1, "Description": ""}
        ]
        (repos_dir / "gitleaks.json").write_text(json.dumps(gitleaks_data))

        metrics = calculate_metrics(str(tmp_path))
        assert metrics["total_findings"] == 1
        assert metrics["high_count"] == 1
        assert len(metrics["repo_stats"]) == 1
        assert metrics["repo_stats"][0]["name"] == "test-repo"


class TestGenerateDashboard:
    """Tests for generate_dashboard function."""

    def test_generate_empty_dashboard(self, tmp_path: Path) -> None:
        """Test generating dashboard with no results."""
        output = tmp_path / "dashboard.html"
        generate_dashboard(str(tmp_path), str(output))
        assert output.exists()
        content = output.read_text()
        assert "Security Audit Dashboard" in content
        assert "Total Findings" in content

    def test_generate_with_custom_output(self, tmp_path: Path) -> None:
        """Test generating dashboard to custom output path."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        output = tmp_path / "custom" / "report.html"

        generate_dashboard(str(results_dir), str(output))
        assert output.exists()

    def test_dashboard_includes_severity_breakdown(self, tmp_path: Path) -> None:
        """Test dashboard includes severity breakdown table."""
        output = tmp_path / "dashboard.html"
        generate_dashboard(str(tmp_path), str(output))
        content = output.read_text()
        assert "Severity Breakdown" in content
        assert "Critical" in content
        assert "High" in content
        assert "Medium" in content
        assert "Low" in content
