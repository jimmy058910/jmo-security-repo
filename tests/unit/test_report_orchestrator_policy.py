#!/usr/bin/env python3
"""
Unit tests for report_orchestrator.py policy integration.

This test suite verifies that:
1. CLI policies take precedence over config policies
2. Config policies are used when CLI not specified
3. Environment variables override config (via load_config_with_env_overrides)
4. Policy evaluation is skipped when disabled
5. fail_on_violation causes appropriate exit codes
6. auto_evaluate controls automatic policy evaluation

Target Coverage: ≥90%
"""

import argparse
import json
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        {
            "schemaVersion": "1.2.0",
            "id": "finding-1",
            "ruleId": "secret-001",
            "severity": "HIGH",
            "tool": {"name": "trufflehog", "version": "3.0.0"},
            "location": {"path": "config.py", "startLine": 10},
            "message": "Hardcoded secret detected",
        },
        {
            "schemaVersion": "1.2.0",
            "id": "finding-2",
            "ruleId": "xss-001",
            "severity": "MEDIUM",
            "tool": {"name": "semgrep", "version": "1.0.0"},
            "location": {"path": "app.py", "startLine": 20},
            "message": "Potential XSS vulnerability",
        },
    ]


@pytest.fixture
def mock_log_fn():
    """Mock logging function."""

    def _log(args, level, message):
        print(f"[{level}] {message}")

    return _log


def write_findings_json(tmp_path: Path, findings: list):
    """Helper to write findings.json for testing."""
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    summaries_dir = results_dir / "summaries"
    summaries_dir.mkdir(parents=True, exist_ok=True)

    findings_file = summaries_dir / "findings.json"
    findings_file.write_text(
        json.dumps({"meta": {}, "findings": findings}), encoding="utf-8"
    )

    return results_dir


def test_report_uses_config_policy_defaults(
    tmp_path, sample_findings, mock_log_fn, monkeypatch
):
    """Test that config policy defaults are used when CLI not specified."""
    from scripts.cli.report_orchestrator import cmd_report

    # Create jmo.yml with policy config
    jmo_yml = tmp_path / "jmo.yml"
    jmo_yml.write_text(
        """
policy:
  enabled: true
  auto_evaluate: true
  default_policies:
    - owasp-top-10
    - zero-secrets
outputs:
  - json
  - md
""",
        encoding="utf-8",
    )

    results_dir = write_findings_json(tmp_path, sample_findings)

    args = argparse.Namespace(
        config=str(jmo_yml),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        results_dir=str(results_dir),
        out=None,
        profile=False,
        threads=None,
        fail_on=None,
        policies=None,  # No CLI policies
        store_history=False,
    )

    # Mock policy evaluation to avoid ImportError
    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        mock_eval.return_value = {
            "owasp-top-10": MagicMock(passed=True),
            "zero-secrets": MagicMock(passed=True),
        }

        with patch("scripts.core.reporters.policy_reporter.write_policy_report"):
            with patch("scripts.core.reporters.policy_reporter.write_policy_json"):
                with patch(
                    "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                ):
                    result = cmd_report(args, mock_log_fn)

    # Should use config policies
    assert mock_eval.called
    call_args = mock_eval.call_args
    assert "owasp-top-10" in call_args[0][1]
    assert "zero-secrets" in call_args[0][1]
    assert result == 0


def test_report_cli_policies_override_config(tmp_path, sample_findings, mock_log_fn):
    """Test that CLI policies take precedence over config."""
    from scripts.cli.report_orchestrator import cmd_report

    # Create jmo.yml with different policies
    jmo_yml = tmp_path / "jmo.yml"
    jmo_yml.write_text(
        """
policy:
  enabled: true
  auto_evaluate: true
  default_policies:
    - owasp-top-10
outputs:
  - json
""",
        encoding="utf-8",
    )

    results_dir = write_findings_json(tmp_path, sample_findings)

    args = argparse.Namespace(
        config=str(jmo_yml),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        results_dir=str(results_dir),
        out=None,
        profile=False,
        threads=None,
        fail_on=None,
        policies=["zero-secrets"],  # CLI policy should override
        store_history=False,
    )

    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        mock_eval.return_value = {"zero-secrets": MagicMock(passed=True)}

        with patch("scripts.core.reporters.policy_reporter.write_policy_report"):
            with patch("scripts.core.reporters.policy_reporter.write_policy_json"):
                with patch(
                    "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                ):
                    result = cmd_report(args, mock_log_fn)

    # Should use CLI policy (zero-secrets), not config policy (owasp-top-10)
    assert mock_eval.called
    call_args = mock_eval.call_args
    assert call_args[0][1] == ["zero-secrets"]
    assert result == 0


def test_report_policy_disabled_skips_evaluation(
    tmp_path, sample_findings, mock_log_fn
):
    """Test that policy evaluation is skipped when disabled."""
    from scripts.cli.report_orchestrator import cmd_report

    jmo_yml = tmp_path / "jmo.yml"
    jmo_yml.write_text(
        """
policy:
  enabled: false
  default_policies:
    - owasp-top-10
outputs:
  - json
""",
        encoding="utf-8",
    )

    results_dir = write_findings_json(tmp_path, sample_findings)

    args = argparse.Namespace(
        config=str(jmo_yml),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        results_dir=str(results_dir),
        out=None,
        profile=False,
        threads=None,
        fail_on=None,
        policies=None,
        store_history=False,
    )

    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        result = cmd_report(args, mock_log_fn)

    # Should NOT call evaluate_policies
    assert not mock_eval.called
    assert result == 0


def test_report_auto_evaluate_false_skips_evaluation(
    tmp_path, sample_findings, mock_log_fn
):
    """Test that auto_evaluate=false skips automatic policy evaluation."""
    from scripts.cli.report_orchestrator import cmd_report

    jmo_yml = tmp_path / "jmo.yml"
    jmo_yml.write_text(
        """
policy:
  enabled: true
  auto_evaluate: false
  default_policies:
    - owasp-top-10
outputs:
  - json
""",
        encoding="utf-8",
    )

    results_dir = write_findings_json(tmp_path, sample_findings)

    args = argparse.Namespace(
        config=str(jmo_yml),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        results_dir=str(results_dir),
        out=None,
        profile=False,
        threads=None,
        fail_on=None,
        policies=None,  # No CLI policies
        store_history=False,
    )

    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        result = cmd_report(args, mock_log_fn)

    # Should NOT call evaluate_policies (auto_evaluate=false)
    assert not mock_eval.called
    assert result == 0


def test_report_fail_on_violation_returns_exit_code_1(
    tmp_path, sample_findings, mock_log_fn
):
    """Test that fail_on_violation causes exit code 1 when policies fail."""
    from scripts.cli.report_orchestrator import cmd_report

    jmo_yml = tmp_path / "jmo.yml"
    jmo_yml.write_text(
        """
policy:
  enabled: true
  auto_evaluate: true
  default_policies:
    - zero-secrets
  fail_on_violation: true
outputs:
  - json
""",
        encoding="utf-8",
    )

    results_dir = write_findings_json(tmp_path, sample_findings)

    args = argparse.Namespace(
        config=str(jmo_yml),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        results_dir=str(results_dir),
        out=None,
        profile=False,
        threads=None,
        fail_on=None,
        policies=None,
        store_history=False,
    )

    # Mock policy failure
    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        mock_eval.return_value = {
            "zero-secrets": MagicMock(passed=False)  # Policy FAILED
        }

        with patch("scripts.core.reporters.policy_reporter.write_policy_report"):
            with patch("scripts.core.reporters.policy_reporter.write_policy_json"):
                with patch(
                    "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                ):
                    result = cmd_report(args, mock_log_fn)

    # Should return 1 due to fail_on_violation=true and policy failure
    assert result == 1


def test_report_fail_on_violation_false_returns_exit_code_0(
    tmp_path, sample_findings, mock_log_fn
):
    """Test that fail_on_violation=false returns 0 even when policies fail."""
    from scripts.cli.report_orchestrator import cmd_report

    jmo_yml = tmp_path / "jmo.yml"
    jmo_yml.write_text(
        """
policy:
  enabled: true
  auto_evaluate: true
  default_policies:
    - zero-secrets
  fail_on_violation: false
outputs:
  - json
""",
        encoding="utf-8",
    )

    results_dir = write_findings_json(tmp_path, sample_findings)

    args = argparse.Namespace(
        config=str(jmo_yml),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        results_dir=str(results_dir),
        out=None,
        profile=False,
        threads=None,
        fail_on=None,
        policies=None,
        store_history=False,
    )

    # Mock policy failure
    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        mock_eval.return_value = {
            "zero-secrets": MagicMock(passed=False)  # Policy FAILED
        }

        with patch("scripts.core.reporters.policy_reporter.write_policy_report"):
            with patch("scripts.core.reporters.policy_reporter.write_policy_json"):
                with patch(
                    "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                ):
                    result = cmd_report(args, mock_log_fn)

    # Should return 0 (fail_on_violation=false)
    assert result == 0


def test_report_environment_variable_override(
    tmp_path, sample_findings, mock_log_fn, monkeypatch
):
    """Test that environment variables override config."""
    from scripts.cli.report_orchestrator import cmd_report

    jmo_yml = tmp_path / "jmo.yml"
    jmo_yml.write_text(
        """
policy:
  enabled: true
  auto_evaluate: true
  default_policies:
    - owasp-top-10
outputs:
  - json
""",
        encoding="utf-8",
    )

    # Override with environment variable
    monkeypatch.setenv("JMO_POLICY_DEFAULT_POLICIES", "pci-dss,hipaa-compliance")

    results_dir = write_findings_json(tmp_path, sample_findings)

    args = argparse.Namespace(
        config=str(jmo_yml),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        results_dir=str(results_dir),
        out=None,
        profile=False,
        threads=None,
        fail_on=None,
        policies=None,  # No CLI policies
        store_history=False,
    )

    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        mock_eval.return_value = {
            "pci-dss": MagicMock(passed=True),
            "hipaa-compliance": MagicMock(passed=True),
        }

        with patch("scripts.core.reporters.policy_reporter.write_policy_report"):
            with patch("scripts.core.reporters.policy_reporter.write_policy_json"):
                with patch(
                    "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                ):
                    result = cmd_report(args, mock_log_fn)

    # Should use env var policies (pci-dss, hipaa-compliance), not config (owasp-top-10)
    assert mock_eval.called
    call_args = mock_eval.call_args
    assert "pci-dss" in call_args[0][1]
    assert "hipaa-compliance" in call_args[0][1]
    assert result == 0


def test_report_combined_exit_code(tmp_path, sample_findings, mock_log_fn):
    """Test that both severity threshold and policy violations combine exit codes."""
    from scripts.cli.report_orchestrator import cmd_report

    jmo_yml = tmp_path / "jmo.yml"
    jmo_yml.write_text(
        """
policy:
  enabled: true
  auto_evaluate: true
  default_policies:
    - zero-secrets
  fail_on_violation: true
fail_on: HIGH
outputs:
  - json
""",
        encoding="utf-8",
    )

    # Findings include HIGH severity (should trigger fail_on threshold)
    results_dir = write_findings_json(tmp_path, sample_findings)

    args = argparse.Namespace(
        config=str(jmo_yml),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        results_dir=str(results_dir),
        out=None,
        profile=False,
        threads=None,
        fail_on=None,  # Use config fail_on
        policies=None,
        store_history=False,
    )

    # Mock policy failure
    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        mock_eval.return_value = {
            "zero-secrets": MagicMock(passed=False)  # Policy FAILED
        }

        with patch("scripts.core.reporters.policy_reporter.write_policy_report"):
            with patch("scripts.core.reporters.policy_reporter.write_policy_json"):
                with patch(
                    "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                ):
                    result = cmd_report(args, mock_log_fn)

    # Should return 1 (both severity threshold and policy violation triggered)
    assert result == 1


# ========== COVERAGE TARGET: ≥90% ====================
# Run: pytest tests/unit/test_report_orchestrator_policy.py -v --cov=scripts.cli.report_orchestrator --cov-report=term-missing
