"""
Tests for policy_reporter.py - Policy-as-Code evaluation reports.

Coverage targets:
- evaluate_policies with successful evaluation
- evaluate_policies with missing policies
- evaluate_policies with evaluation exceptions
- Builtin and user policy discovery
- User policies override builtin
- write_policy_report with violations and warnings
- write_policy_report with empty results
- write_policy_json with schema version
- write_policy_json with empty results
- write_policy_summary_md with all passed
- write_policy_summary_md with failures
- write_policy_summary_md with empty results
- Markdown formatting and escaping
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from scripts.core.reporters.policy_reporter import (
    evaluate_policies,
    write_policy_json,
    write_policy_report,
    write_policy_summary_md,
)


# Mock PolicyResult dataclass (matches policy_engine.py structure)
@dataclass
class MockPolicyResult:
    """Mock PolicyResult for testing without importing policy_engine."""

    policy_name: str
    passed: bool
    violations: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def violation_count(self) -> int:
        """Return total number of violations."""
        return len(self.violations)


@pytest.fixture
def sample_findings():
    """Create sample findings for policy evaluation."""
    return [
        {
            "id": "finding-1",
            "severity": "HIGH",
            "ruleId": "SQL-001",
            "message": "SQL injection vulnerability",
        },
        {
            "id": "finding-2",
            "severity": "MEDIUM",
            "ruleId": "XSS-001",
            "message": "Cross-site scripting vulnerability",
        },
    ]


@pytest.fixture
def sample_policy_results():
    """Create sample policy results for testing."""
    return {
        "no_high_severity": MockPolicyResult(
            policy_name="no_high_severity",
            passed=False,
            violations=[
                {"id": "finding-1", "severity": "HIGH", "message": "SQL injection"}
            ],
            message="Found 1 HIGH severity finding",
        ),
        "require_cwe": MockPolicyResult(
            policy_name="require_cwe",
            passed=True,
            warnings=["Some findings missing CWE"],
            message="All critical findings have CWE",
        ),
    }


def test_evaluate_policies_success(tmp_path, sample_findings):
    """Test successful policy evaluation."""
    builtin_dir = tmp_path / "builtin"
    user_dir = tmp_path / "user"
    builtin_dir.mkdir()
    user_dir.mkdir()

    # Create test policy files
    (builtin_dir / "test_policy.rego").write_text("package test")
    (user_dir / "custom_policy.rego").write_text("package custom")

    mock_result = MockPolicyResult(
        policy_name="test_policy", passed=True, message="Policy passed"
    )

    with patch("scripts.core.reporters.policy_reporter.PolicyEngine") as MockEngine:
        with patch(
            "scripts.core.reporters.policy_reporter.PolicyResult", MockPolicyResult
        ):
            mock_engine = MockEngine.return_value
            mock_engine.evaluate.return_value = mock_result

            results = evaluate_policies(
                sample_findings, ["test_policy"], builtin_dir, user_dir
            )

            assert "test_policy" in results
            assert results["test_policy"].passed is True
            assert results["test_policy"].message == "Policy passed"
            mock_engine.evaluate.assert_called_once()


def test_evaluate_policies_missing_policy(tmp_path, sample_findings, caplog):
    """Test evaluation with missing policy (logs warning)."""
    builtin_dir = tmp_path / "builtin"
    user_dir = tmp_path / "user"
    builtin_dir.mkdir()
    user_dir.mkdir()

    # Create one policy but request a different one
    (builtin_dir / "exists.rego").write_text("package exists")

    with patch("scripts.core.reporters.policy_reporter.PolicyEngine"):
        with caplog.at_level(logging.WARNING):
            results = evaluate_policies(
                sample_findings, ["missing_policy"], builtin_dir, user_dir
            )

            assert "missing_policy" not in results
            assert "Policy 'missing_policy' not found" in caplog.text


def test_evaluate_policies_evaluation_exception(tmp_path, sample_findings, caplog):
    """Test evaluation handles exceptions gracefully."""
    builtin_dir = tmp_path / "builtin"
    user_dir = tmp_path / "user"
    builtin_dir.mkdir()
    user_dir.mkdir()

    (builtin_dir / "fails.rego").write_text("package fails")

    with patch("scripts.core.reporters.policy_reporter.PolicyEngine") as MockEngine:
        mock_engine = MockEngine.return_value
        mock_engine.evaluate.side_effect = RuntimeError("Policy evaluation failed")

        with caplog.at_level(logging.ERROR):
            results = evaluate_policies(
                sample_findings, ["fails"], builtin_dir, user_dir
            )

            assert "fails" not in results
            assert "Failed to evaluate policy 'fails'" in caplog.text


def test_evaluate_policies_user_override_builtin(tmp_path, sample_findings):
    """Test user policies override builtin policies."""
    builtin_dir = tmp_path / "builtin"
    user_dir = tmp_path / "user"
    builtin_dir.mkdir()
    user_dir.mkdir()

    # Create same policy name in both directories
    (builtin_dir / "policy.rego").write_text("package builtin")
    (user_dir / "policy.rego").write_text("package user")

    with patch("scripts.core.reporters.policy_reporter.PolicyEngine") as MockEngine:
        with patch(
            "scripts.core.reporters.policy_reporter.PolicyResult", MockPolicyResult
        ):
            mock_engine = MockEngine.return_value
            mock_result = MockPolicyResult(
                policy_name="policy", passed=True, message="User policy"
            )
            mock_engine.evaluate.return_value = mock_result

            evaluate_policies(sample_findings, ["policy"], builtin_dir, user_dir)

            # Verify user policy was used (user_dir policy file should be passed to evaluate)
            call_args = mock_engine.evaluate.call_args
            assert call_args[0][1] == user_dir / "policy.rego"


def test_evaluate_policies_empty_directories(sample_findings):
    """Test evaluation with non-existent policy directories."""
    builtin_dir = Path("/nonexistent/builtin")
    user_dir = Path("/nonexistent/user")

    with patch("scripts.core.reporters.policy_reporter.PolicyEngine"):
        results = evaluate_policies(
            sample_findings, ["any_policy"], builtin_dir, user_dir
        )

        # No policies found, no results
        assert len(results) == 0


def test_write_policy_report_basic(tmp_path, sample_policy_results):
    """Test basic policy report generation."""
    output_path = tmp_path / "POLICY_REPORT.md"

    write_policy_report(sample_policy_results, output_path)

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")

    # Verify structure
    assert "# Policy-as-Code Evaluation Report" in content
    assert "Evaluated 2 policies" in content
    assert "## Summary" in content
    assert "| Policy | Status | Violations | Warnings | Message |" in content

    # Verify policy results
    assert "no_high_severity" in content
    assert "❌ FAILED" in content
    assert "require_cwe" in content
    assert "✅ PASSED" in content


def test_write_policy_report_with_violations_details(tmp_path):
    """Test policy report includes violation details."""
    output_path = tmp_path / "POLICY_REPORT.md"

    policy_results = {
        "test_policy": MockPolicyResult(
            policy_name="test_policy",
            passed=False,
            violations=[
                {"id": "v1", "severity": "HIGH"},
                {"id": "v2", "severity": "MEDIUM"},
            ],
            warnings=["Warning 1", "Warning 2"],
            message="Found violations",
        )
    }

    write_policy_report(policy_results, output_path)

    content = output_path.read_text(encoding="utf-8")

    # Verify violations section
    assert "## test_policy" in content
    assert "### Violations (2)" in content
    assert "#### Violation 1" in content
    assert "#### Violation 2" in content
    assert '"id": "v1"' in content

    # Verify warnings section
    assert "### Warnings (2)" in content
    assert "- Warning 1" in content
    assert "- Warning 2" in content


def test_write_policy_report_empty_results(tmp_path, caplog):
    """Test policy report handles empty results gracefully."""
    output_path = tmp_path / "POLICY_REPORT.md"

    with caplog.at_level(logging.INFO):
        write_policy_report({}, output_path)

        assert "No policy results to write" in caplog.text
        # File should not be created
        assert not output_path.exists()


def test_write_policy_report_pipe_escaping(tmp_path):
    """Test markdown pipe character escaping in messages."""
    output_path = tmp_path / "POLICY_REPORT.md"

    policy_results = {
        "pipe_test": MockPolicyResult(
            policy_name="pipe_test",
            passed=False,
            message="Message with | pipe | characters",
        )
    }

    write_policy_report(policy_results, output_path)

    content = output_path.read_text(encoding="utf-8")

    # Pipes should be escaped with backslash
    assert "Message with \\| pipe \\| characters" in content


def test_write_policy_json_basic(tmp_path, sample_policy_results):
    """Test policy JSON output generation."""
    output_path = tmp_path / "policy-results.json"

    write_policy_json(sample_policy_results, output_path)

    assert output_path.exists()
    data = json.loads(output_path.read_text(encoding="utf-8"))

    # Verify structure
    assert data["schemaVersion"] == "1.0.0"
    assert "policies" in data
    assert len(data["policies"]) == 2

    # Verify first policy
    policy1 = next(p for p in data["policies"] if p["name"] == "no_high_severity")
    assert policy1["passed"] is False
    assert len(policy1["violations"]) == 1
    assert policy1["message"] == "Found 1 HIGH severity finding"

    # Verify second policy
    policy2 = next(p for p in data["policies"] if p["name"] == "require_cwe")
    assert policy2["passed"] is True
    assert len(policy2["warnings"]) == 1


def test_write_policy_json_empty_results(tmp_path, caplog):
    """Test policy JSON handles empty results gracefully."""
    output_path = tmp_path / "policy-results.json"

    with caplog.at_level(logging.INFO):
        write_policy_json({}, output_path)

        assert "No policy results to write" in caplog.text
        # File should not be created
        assert not output_path.exists()


def test_write_policy_summary_md_all_passed(tmp_path):
    """Test policy summary with all policies passed."""
    output_path = tmp_path / "POLICY_SUMMARY.md"

    policy_results = {
        "policy1": MockPolicyResult(policy_name="policy1", passed=True),
        "policy2": MockPolicyResult(policy_name="policy2", passed=True),
    }

    write_policy_summary_md(policy_results, output_path)

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")

    # Verify success message
    assert "## Policy Evaluation" in content
    assert "✅ **All 2 policies passed**" in content
    assert "(0 violations)" in content

    # Verify table
    assert "| Policy | Status | Violations |" in content
    assert "| policy1 | ✅ | 0 |" in content


def test_write_policy_summary_md_with_failures(tmp_path):
    """Test policy summary with some failures."""
    output_path = tmp_path / "POLICY_SUMMARY.md"

    policy_results = {
        "passed_policy": MockPolicyResult(policy_name="passed_policy", passed=True),
        "failed_policy": MockPolicyResult(
            policy_name="failed_policy",
            passed=False,
            violations=[{"id": "v1"}, {"id": "v2"}],
        ),
    }

    write_policy_summary_md(policy_results, output_path)

    content = output_path.read_text(encoding="utf-8")

    # Verify failure message
    assert "❌ **1/2 policies failed**" in content
    assert "(2 violations)" in content

    # Verify table
    assert "| passed_policy | ✅ | 0 |" in content
    assert "| failed_policy | ❌ | 2 |" in content

    # Verify link to full report
    assert "See [POLICY_REPORT.md](POLICY_REPORT.md)" in content


def test_write_policy_summary_md_empty_results(tmp_path):
    """Test policy summary handles empty results gracefully."""
    output_path = tmp_path / "POLICY_SUMMARY.md"

    write_policy_summary_md({}, output_path)

    # File should not be created for empty results
    assert not output_path.exists()


def test_write_policy_report_json_formatting(tmp_path):
    """Test JSON formatting in policy report violations."""
    output_path = tmp_path / "POLICY_REPORT.md"

    policy_results = {
        "json_test": MockPolicyResult(
            policy_name="json_test",
            passed=False,
            violations=[
                {
                    "id": "finding-1",
                    "severity": "HIGH",
                    "location": {"path": "file.py", "line": 42},
                }
            ],
        )
    }

    write_policy_report(policy_results, output_path)

    content = output_path.read_text(encoding="utf-8")

    # Verify JSON formatting in code block
    assert "```json" in content
    assert '"id": "finding-1"' in content
    assert '"severity": "HIGH"' in content
    assert '"location":' in content


def test_evaluate_policies_logging(tmp_path, sample_findings, caplog):
    """Test evaluate_policies logs policy evaluation."""
    builtin_dir = tmp_path / "builtin"
    user_dir = tmp_path / "user"
    builtin_dir.mkdir()
    user_dir.mkdir()

    (builtin_dir / "log_test.rego").write_text("package log_test")

    with patch("scripts.core.reporters.policy_reporter.PolicyEngine") as MockEngine:
        with patch(
            "scripts.core.reporters.policy_reporter.PolicyResult", MockPolicyResult
        ):
            mock_engine = MockEngine.return_value
            mock_result = MockPolicyResult(
                policy_name="log_test", passed=True, message="Logged"
            )
            mock_engine.evaluate.return_value = mock_result

            with caplog.at_level(logging.INFO):
                evaluate_policies(sample_findings, ["log_test"], builtin_dir, user_dir)

                assert "Evaluating policy: log_test" in caplog.text


def test_write_policy_report_logging(tmp_path, sample_policy_results, caplog):
    """Test write_policy_report logs output path."""
    output_path = tmp_path / "POLICY_REPORT.md"

    with caplog.at_level(logging.INFO):
        write_policy_report(sample_policy_results, output_path)

        assert f"Wrote policy report: {output_path}" in caplog.text


def test_write_policy_json_logging(tmp_path, sample_policy_results, caplog):
    """Test write_policy_json logs output path."""
    output_path = tmp_path / "policy.json"

    with caplog.at_level(logging.INFO):
        write_policy_json(sample_policy_results, output_path)

        assert f"Wrote policy JSON: {output_path}" in caplog.text


def test_write_policy_summary_md_logging(tmp_path, sample_policy_results, caplog):
    """Test write_policy_summary_md logs output path."""
    output_path = tmp_path / "summary.md"

    with caplog.at_level(logging.INFO):
        write_policy_summary_md(sample_policy_results, output_path)

        assert f"Wrote policy summary: {output_path}" in caplog.text
