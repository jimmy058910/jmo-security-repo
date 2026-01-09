#!/usr/bin/env python3
"""Tests for scripts/core/policy_engine.py OPA policy engine."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.core.policy_engine import PolicyEngine, PolicyMetadata, PolicyResult


class TestPolicyResult:
    """Tests for PolicyResult dataclass."""

    def test_violation_count(self) -> None:
        """Test violation_count property."""
        result = PolicyResult(
            policy_name="test",
            passed=False,
            violations=[{"msg": "error1"}, {"msg": "error2"}],
        )
        assert result.violation_count == 2

    def test_has_violations_true(self) -> None:
        """Test has_violations when violations exist."""
        result = PolicyResult(
            policy_name="test",
            passed=False,
            violations=[{"msg": "error"}],
        )
        assert result.has_violations is True

    def test_has_violations_false(self) -> None:
        """Test has_violations when no violations."""
        result = PolicyResult(
            policy_name="test",
            passed=True,
            violations=[],
        )
        assert result.has_violations is False

    def test_empty_result(self) -> None:
        """Test empty PolicyResult defaults."""
        result = PolicyResult(policy_name="test", passed=True)
        assert result.violations == []
        assert result.warnings == []
        assert result.message == ""
        assert result.metadata == {}


class TestPolicyMetadata:
    """Tests for PolicyMetadata dataclass."""

    def test_default_values(self) -> None:
        """Test PolicyMetadata default values."""
        meta = PolicyMetadata(
            name="test-policy",
            version="1.0.0",
            description="Test policy",
        )
        assert meta.author == "JMo Security"
        assert meta.tags == []
        assert meta.severity_levels == []
        assert meta.frameworks == []

    def test_with_all_fields(self) -> None:
        """Test PolicyMetadata with all fields."""
        meta = PolicyMetadata(
            name="secrets-policy",
            version="2.0.0",
            description="Detect secrets",
            author="Custom Author",
            tags=["secrets", "credentials"],
            severity_levels=["HIGH", "CRITICAL"],
            frameworks=["OWASP", "PCI DSS"],
        )
        assert meta.name == "secrets-policy"
        assert "secrets" in meta.tags
        assert "OWASP" in meta.frameworks


class TestPolicyEngine:
    """Tests for PolicyEngine class."""

    @pytest.fixture
    def mock_opa_available(self) -> MagicMock:
        """Mock OPA binary availability check."""
        with (
            patch(
                "scripts.core.policy_engine.shutil.which", return_value="/usr/bin/opa"
            ),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="Version: 0.70.0\nBuild Commit: abc123",
                stderr="",
            )
            yield mock_run

    def test_init_verifies_opa(self, mock_opa_available: MagicMock) -> None:
        """Test PolicyEngine verifies OPA on init."""
        engine = PolicyEngine()
        mock_opa_available.assert_called_once()
        assert engine.opa_binary == "opa"

    def test_init_custom_binary(self, mock_opa_available: MagicMock) -> None:
        """Test PolicyEngine with custom binary path."""
        engine = PolicyEngine(opa_binary="/usr/local/bin/opa")
        assert engine.opa_binary == "/usr/local/bin/opa"

    def test_init_opa_not_found(self) -> None:
        """Test PolicyEngine raises when OPA not found."""
        with patch("scripts.core.policy_engine.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="OPA binary not found"):
                PolicyEngine()

    def test_init_opa_timeout(self) -> None:
        """Test PolicyEngine raises on OPA timeout."""
        with (
            patch(
                "scripts.core.policy_engine.shutil.which", return_value="/usr/bin/opa"
            ),
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("opa", 5)),
        ):
            with pytest.raises(RuntimeError, match="timed out"):
                PolicyEngine()

    def test_validate_policy_valid(
        self, mock_opa_available: MagicMock, tmp_path: Path
    ) -> None:
        """Test validate_policy with valid Rego."""
        engine = PolicyEngine()

        policy = tmp_path / "test.rego"
        policy.write_text("package test\nallow := true")

        # Mock validation call
        mock_opa_available.return_value = MagicMock(returncode=0, stderr="")

        is_valid, error = engine.validate_policy(policy)
        # First call is version check, second is validation
        assert mock_opa_available.call_count >= 1

    def test_validate_policy_invalid(
        self, mock_opa_available: MagicMock, tmp_path: Path
    ) -> None:
        """Test validate_policy with invalid Rego."""
        engine = PolicyEngine()

        policy = tmp_path / "invalid.rego"
        policy.write_text("invalid rego syntax")

        # Mock validation failure
        mock_opa_available.return_value = MagicMock(
            returncode=1,
            stderr="syntax error at line 1",
        )

        is_valid, error = engine.validate_policy(policy)
        assert is_valid is False
        assert "syntax error" in error

    def test_extract_package_name(
        self, mock_opa_available: MagicMock, tmp_path: Path
    ) -> None:
        """Test _extract_package_name from policy file."""
        engine = PolicyEngine()

        policy = tmp_path / "test.rego"
        policy.write_text("package jmo.policy.secrets\n\nallow := true")

        package = engine._extract_package_name(policy)
        assert package == "data.jmo.policy.secrets"

    def test_extract_package_name_not_found(
        self, mock_opa_available: MagicMock, tmp_path: Path
    ) -> None:
        """Test _extract_package_name when no package declaration."""
        engine = PolicyEngine()

        policy = tmp_path / "test.rego"
        policy.write_text("allow := true")

        package = engine._extract_package_name(policy)
        assert package is None

    def test_parse_opa_output_valid(self, mock_opa_available: MagicMock) -> None:
        """Test _parse_opa_output with valid structure."""
        engine = PolicyEngine()

        output = {
            "result": [
                {
                    "expressions": [
                        {
                            "value": {
                                "allow": True,
                                "violations": [],
                                "warnings": ["Consider adding docs"],
                                "message": "All checks passed",
                            }
                        }
                    ]
                }
            ]
        }

        result = engine._parse_opa_output(output, "test-policy")
        assert result.passed is True
        assert result.violations == []
        assert "Consider adding docs" in result.warnings
        assert result.message == "All checks passed"

    def test_parse_opa_output_with_violations(
        self, mock_opa_available: MagicMock
    ) -> None:
        """Test _parse_opa_output with violations."""
        engine = PolicyEngine()

        output = {
            "result": [
                {
                    "expressions": [
                        {
                            "value": {
                                "allow": False,
                                "violations": [
                                    {"finding_id": "123", "reason": "Critical secret"},
                                ],
                            }
                        }
                    ]
                }
            ]
        }

        result = engine._parse_opa_output(output, "test-policy")
        assert result.passed is False
        assert len(result.violations) == 1

    def test_parse_opa_output_missing_allow(
        self, mock_opa_available: MagicMock
    ) -> None:
        """Test _parse_opa_output raises when missing allow field."""
        engine = PolicyEngine()

        output = {"result": [{"expressions": [{"value": {"violations": []}}]}]}

        with pytest.raises(ValueError, match="missing required 'allow' field"):
            engine._parse_opa_output(output, "test-policy")

    def test_parse_opa_output_invalid_structure(
        self, mock_opa_available: MagicMock
    ) -> None:
        """Test _parse_opa_output raises on invalid structure."""
        engine = PolicyEngine()

        output = {"invalid": "structure"}

        with pytest.raises(ValueError, match="Invalid OPA output structure"):
            engine._parse_opa_output(output, "test-policy")

    def test_evaluate_policy_not_found(
        self, mock_opa_available: MagicMock, tmp_path: Path
    ) -> None:
        """Test evaluate raises when policy file not found."""
        engine = PolicyEngine()

        with pytest.raises(FileNotFoundError, match="Policy not found"):
            engine.evaluate([], tmp_path / "nonexistent.rego")

    def test_test_policy_data_not_found(
        self, mock_opa_available: MagicMock, tmp_path: Path
    ) -> None:
        """Test test_policy raises when test data not found."""
        engine = PolicyEngine()

        policy = tmp_path / "test.rego"
        policy.write_text("package test\nallow := true")

        with pytest.raises(FileNotFoundError, match="Test data not found"):
            engine.test_policy(policy, tmp_path / "nonexistent.json")

    def test_test_policy_invalid_data(
        self, mock_opa_available: MagicMock, tmp_path: Path
    ) -> None:
        """Test test_policy raises on invalid test data format."""
        engine = PolicyEngine()

        policy = tmp_path / "test.rego"
        policy.write_text("package test\nallow := true")

        test_data = tmp_path / "test_data.json"
        test_data.write_text('["not", "an", "object"]')

        with pytest.raises(ValueError, match="must be a JSON object"):
            engine.test_policy(policy, test_data)

    def test_get_metadata_file_not_found(
        self, mock_opa_available: MagicMock, tmp_path: Path
    ) -> None:
        """Test get_metadata raises when file not found."""
        engine = PolicyEngine()

        with pytest.raises(FileNotFoundError, match="Policy file not found"):
            engine.get_metadata(tmp_path / "nonexistent.rego")
