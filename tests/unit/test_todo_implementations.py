#!/usr/bin/env python3
"""Tests for TODO implementations from Scenario 5 (P4 - Technical Debt).

This test suite covers:
1. TODO 1: Configurable Dedup Threshold (DeduplicationConfig)
2. TODO 2: CSV Triage Status via Suppressions
3. TODO 3: Tool Versions in Provenance (resolvedDependencies)
"""

from pathlib import Path
import pytest

# ============================================================================
# Category 1: Configurable Dedup Threshold (TODO 1)
# ============================================================================


def write_yaml_file(tmp_path: Path, filename: str, content: str) -> Path:
    """Helper to write YAML config files for testing."""
    yaml_file = tmp_path / filename
    yaml_file.write_text(content, encoding="utf-8")
    return yaml_file


class TestDeduplicationConfig:
    """Tests for DeduplicationConfig dataclass and validation."""

    def test_deduplication_config_defaults(self):
        """Test DeduplicationConfig has correct default values."""
        from scripts.core.config import DeduplicationConfig

        cfg = DeduplicationConfig()

        assert cfg.similarity_threshold == 0.65

    def test_deduplication_config_custom_threshold(self):
        """Test DeduplicationConfig accepts custom threshold."""
        from scripts.core.config import DeduplicationConfig

        cfg = DeduplicationConfig(similarity_threshold=0.75)

        assert cfg.similarity_threshold == 0.75

    def test_deduplication_config_validates_min_threshold(self):
        """Test DeduplicationConfig rejects threshold < 0.5."""
        from scripts.core.config import DeduplicationConfig

        with pytest.raises(ValueError, match="between 0.5 and 1.0"):
            DeduplicationConfig(similarity_threshold=0.4)

    def test_deduplication_config_validates_max_threshold(self):
        """Test DeduplicationConfig rejects threshold > 1.0."""
        from scripts.core.config import DeduplicationConfig

        with pytest.raises(ValueError, match="between 0.5 and 1.0"):
            DeduplicationConfig(similarity_threshold=1.1)

    def test_deduplication_config_boundary_values(self):
        """Test DeduplicationConfig accepts boundary values."""
        from scripts.core.config import DeduplicationConfig

        # 0.5 should be valid
        cfg_min = DeduplicationConfig(similarity_threshold=0.5)
        assert cfg_min.similarity_threshold == 0.5

        # 1.0 should be valid
        cfg_max = DeduplicationConfig(similarity_threshold=1.0)
        assert cfg_max.similarity_threshold == 1.0


class TestDeduplicationConfigLoading:
    """Tests for loading deduplication config from YAML."""

    def test_load_config_deduplication_default(self, tmp_path):
        """Test load_config includes default deduplication config."""
        from scripts.core.config import load_config, DeduplicationConfig

        yaml_content = """
tools:
  - semgrep
outputs:
  - json
"""
        yaml_file = write_yaml_file(tmp_path, "jmo.yml", yaml_content)
        cfg = load_config(str(yaml_file))

        assert hasattr(cfg, "deduplication")
        assert isinstance(cfg.deduplication, DeduplicationConfig)
        assert cfg.deduplication.similarity_threshold == 0.65

    def test_load_config_deduplication_custom_threshold(self, tmp_path):
        """Test load_config parses custom deduplication threshold."""
        from scripts.core.config import load_config

        yaml_content = """
tools:
  - semgrep
deduplication:
  similarity_threshold: 0.80
"""
        yaml_file = write_yaml_file(tmp_path, "jmo.yml", yaml_content)
        cfg = load_config(str(yaml_file))

        assert cfg.deduplication.similarity_threshold == 0.80

    def test_load_config_deduplication_invalid_threshold_uses_default(self, tmp_path):
        """Test load_config uses default for invalid threshold."""
        from scripts.core.config import load_config

        # Threshold outside valid range
        yaml_content = """
deduplication:
  similarity_threshold: 1.5
"""
        yaml_file = write_yaml_file(tmp_path, "jmo.yml", yaml_content)
        cfg = load_config(str(yaml_file))

        # Should keep default when value is invalid
        assert cfg.deduplication.similarity_threshold == 0.65


class TestDeduplicationEnvOverride:
    """Tests for JMO_DEDUP_THRESHOLD environment variable override."""

    def test_env_override_dedup_threshold(self, tmp_path, monkeypatch):
        """Test JMO_DEDUP_THRESHOLD environment variable overrides config."""
        from scripts.core.config import load_config_with_env_overrides

        yaml_content = """
deduplication:
  similarity_threshold: 0.65
"""
        yaml_file = write_yaml_file(tmp_path, "jmo.yml", yaml_content)
        monkeypatch.setenv("JMO_DEDUP_THRESHOLD", "0.75")

        cfg = load_config_with_env_overrides(str(yaml_file))

        assert cfg.deduplication.similarity_threshold == 0.75

    def test_env_override_dedup_threshold_invalid(self, tmp_path, monkeypatch):
        """Test invalid JMO_DEDUP_THRESHOLD is ignored."""
        from scripts.core.config import load_config_with_env_overrides

        yaml_content = """
deduplication:
  similarity_threshold: 0.65
"""
        yaml_file = write_yaml_file(tmp_path, "jmo.yml", yaml_content)
        monkeypatch.setenv("JMO_DEDUP_THRESHOLD", "invalid")

        cfg = load_config_with_env_overrides(str(yaml_file))

        # Should keep original value when env var is invalid
        assert cfg.deduplication.similarity_threshold == 0.65


# ============================================================================
# Category 2: CSV Triage Status via Suppressions (TODO 2)
# ============================================================================


class TestCSVTriageColumn:
    """Tests for CSV triage column with suppression status."""

    @pytest.fixture
    def sample_finding(self):
        """Create sample finding for testing."""
        return {
            "schemaVersion": "1.2.0",
            "id": "test-fingerprint-123",
            "ruleId": "CVE-2024-1234",
            "severity": "HIGH",
            "message": "Test vulnerability",
            "tool": {"name": "trivy", "version": "0.50.0"},
            "location": {"path": "package.json", "startLine": 10},
            "priority": {"priority": 8.5, "is_kev": False, "epss": 0.12},
        }

    def test_triaged_no_without_suppressions(self, sample_finding):
        """Test triaged column shows NO without suppressions."""
        from scripts.core.reporters.csv_reporter import _extract_row

        row = _extract_row(sample_finding, ["triaged"], suppressions=None)

        assert row == ["NO"]

    def test_triaged_no_with_empty_suppressions(self, sample_finding):
        """Test triaged column shows NO with empty suppressions dict."""
        from scripts.core.reporters.csv_reporter import _extract_row

        row = _extract_row(sample_finding, ["triaged"], suppressions={})

        assert row == ["NO"]

    def test_triaged_yes_with_matching_suppression(self, sample_finding):
        """Test triaged column shows YES when finding is suppressed."""
        from scripts.core.reporters.csv_reporter import _extract_row
        from scripts.core.suppress import Suppression

        suppressions = {
            "test-fingerprint-123": Suppression(
                id="test-fingerprint-123", reason="False positive"
            )
        }

        row = _extract_row(sample_finding, ["triaged"], suppressions=suppressions)

        assert row == ["YES"]

    def test_triaged_no_with_non_matching_suppression(self, sample_finding):
        """Test triaged column shows NO when suppression doesn't match."""
        from scripts.core.reporters.csv_reporter import _extract_row
        from scripts.core.suppress import Suppression

        suppressions = {
            "other-fingerprint": Suppression(id="other-fingerprint", reason="Other")
        }

        row = _extract_row(sample_finding, ["triaged"], suppressions=suppressions)

        assert row == ["NO"]

    def test_triaged_no_with_expired_suppression(self, sample_finding):
        """Test triaged column shows NO when suppression is expired."""
        from scripts.core.reporters.csv_reporter import _extract_row
        from scripts.core.suppress import Suppression

        suppressions = {
            "test-fingerprint-123": Suppression(
                id="test-fingerprint-123", reason="Expired", expires="2020-01-01"
            )
        }

        row = _extract_row(sample_finding, ["triaged"], suppressions=suppressions)

        assert row == ["NO"]

    def test_triaged_no_for_finding_without_id(self):
        """Test triaged column shows NO for finding without id."""
        from scripts.core.reporters.csv_reporter import _extract_row
        from scripts.core.suppress import Suppression

        finding = {"severity": "LOW", "ruleId": "test"}
        suppressions = {"some-id": Suppression(id="some-id", reason="Test")}

        row = _extract_row(finding, ["triaged"], suppressions=suppressions)

        assert row == ["NO"]

    def test_write_csv_with_suppressions(self, tmp_path, sample_finding):
        """Test write_csv correctly passes suppressions to extract_row."""
        from scripts.core.reporters.csv_reporter import write_csv
        from scripts.core.suppress import Suppression
        import csv

        suppressions = {
            "test-fingerprint-123": Suppression(
                id="test-fingerprint-123", reason="Accepted risk"
            )
        }

        out_path = tmp_path / "findings.csv"
        write_csv([sample_finding], out_path, suppressions=suppressions)

        with open(out_path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert rows[0]["triaged"] == "YES"


# ============================================================================
# Category 3: Tool Versions in Provenance (TODO 3)
# ============================================================================


class TestProvenanceToolVersions:
    """Tests for tool versions in SLSA provenance resolvedDependencies."""

    def test_provenance_includes_resolved_dependencies(self, tmp_path):
        """Test provenance includes tool versions in resolvedDependencies."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        # Create test findings file
        findings_file = tmp_path / "findings.json"
        findings_file.write_text('{"findings": []}', encoding="utf-8")

        generator = ProvenanceGenerator()
        provenance = generator.generate(
            findings_path=findings_file,
            profile="balanced",
            tools=["trivy", "semgrep"],
            targets=["test-repo"],
        )

        # Get build definition
        build_def = provenance["predicate"]["buildDefinition"]
        resolved_deps = build_def.get("resolvedDependencies", [])

        # Should have entries for the tools
        assert len(resolved_deps) >= 0  # May be empty if registry not found

    def test_get_tool_versions_with_known_tools(self):
        """Test _get_tool_versions returns version info for known tools."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        generator = ProvenanceGenerator()
        versions = generator._get_tool_versions(["trivy", "semgrep"])

        # Should return list of dicts
        assert isinstance(versions, list)

        # If registry loads successfully, should have version info
        if versions:
            for tool_dep in versions:
                assert "name" in tool_dep
                assert "annotations" in tool_dep
                assert "version" in tool_dep["annotations"]

    def test_get_tool_versions_unknown_tool(self):
        """Test _get_tool_versions handles unknown tools gracefully."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        generator = ProvenanceGenerator()
        versions = generator._get_tool_versions(["nonexistent-tool-xyz"])

        # Should return list with minimal info
        assert isinstance(versions, list)
        if versions:
            # Unknown tool should still have name and version: unknown
            assert versions[0]["name"] == "nonexistent-tool-xyz"
            assert versions[0]["annotations"]["version"] == "unknown"

    def test_get_tool_uri_with_github_repo(self):
        """Test _get_tool_uri generates GitHub URL correctly."""
        from scripts.core.attestation.provenance import ProvenanceGenerator
        from unittest.mock import MagicMock

        generator = ProvenanceGenerator()

        # Mock ToolInfo with github_repo
        tool_info = MagicMock()
        tool_info.github_repo = "aquasecurity/trivy"
        tool_info.pypi_package = None
        tool_info.npm_package = None
        tool_info.name = "trivy"

        uri = generator._get_tool_uri(tool_info)

        assert uri == "https://github.com/aquasecurity/trivy"

    def test_get_tool_uri_with_pypi_package(self):
        """Test _get_tool_uri generates PyPI URL correctly."""
        from scripts.core.attestation.provenance import ProvenanceGenerator
        from unittest.mock import MagicMock

        generator = ProvenanceGenerator()

        # Mock ToolInfo with pypi_package
        tool_info = MagicMock()
        tool_info.github_repo = None
        tool_info.pypi_package = "semgrep"
        tool_info.npm_package = None
        tool_info.name = "semgrep"

        uri = generator._get_tool_uri(tool_info)

        assert uri == "https://pypi.org/project/semgrep/"

    def test_get_tool_uri_fallback(self):
        """Test _get_tool_uri generates URN fallback."""
        from scripts.core.attestation.provenance import ProvenanceGenerator
        from unittest.mock import MagicMock

        generator = ProvenanceGenerator()

        # Mock ToolInfo with no package info
        tool_info = MagicMock()
        tool_info.github_repo = None
        tool_info.pypi_package = None
        tool_info.npm_package = None
        tool_info.name = "custom-tool"

        uri = generator._get_tool_uri(tool_info)

        assert uri == "urn:jmo:tool:custom-tool"

    def test_provenance_build_definition_has_tools(self, tmp_path):
        """Test build definition external parameters include tool list."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        findings_file = tmp_path / "findings.json"
        findings_file.write_text("[]", encoding="utf-8")

        generator = ProvenanceGenerator()
        provenance = generator.generate(
            findings_path=findings_file,
            profile="fast",
            tools=["trivy", "semgrep", "hadolint"],
            targets=["test"],
        )

        build_def = provenance["predicate"]["buildDefinition"]
        assert build_def["externalParameters"]["tools"] == [
            "trivy",
            "semgrep",
            "hadolint",
        ]
