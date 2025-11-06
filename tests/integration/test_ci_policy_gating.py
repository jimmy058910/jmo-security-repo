#!/usr/bin/env python3
"""
Integration tests for CI mode policy gating (Phase 5.1).

This test suite verifies that:
1. CI mode evaluates policies when --policy flag provided
2. CI mode fails (exit code 1) when --fail-on-policy-violation set and policies fail
3. CI mode warns but succeeds (exit code 0) without --fail-on-policy-violation
4. CLI policy flags override config defaults
5. Config fail_on_violation works correctly

Target Coverage: CI mode policy integration.
"""

import argparse
import json
from unittest.mock import patch

import pytest


@pytest.fixture
def sample_findings_with_violations():
    """Sample findings that will trigger policy violations."""
    return {
        "meta": {},
        "findings": [
            {
                "schemaVersion": "1.2.0",
                "id": "finding-secret-1",
                "ruleId": "secret-001",
                "severity": "HIGH",
                "tool": {"name": "trufflehog", "version": "3.0.0"},
                "location": {"path": "config.py", "startLine": 10},
                "message": "Hardcoded API key detected",
                "verified": True,
            },
            {
                "schemaVersion": "1.2.0",
                "id": "finding-xss-1",
                "ruleId": "xss-001",
                "severity": "HIGH",
                "tool": {"name": "semgrep", "version": "1.0.0"},
                "location": {"path": "app.py", "startLine": 20},
                "message": "XSS vulnerability",
                "compliance": {"owaspTop10_2021": ["A03:2021"]},
            },
        ],
    }


@pytest.fixture
def sample_findings_no_violations():
    """Sample findings with no policy violations."""
    return {
        "meta": {},
        "findings": [
            {
                "schemaVersion": "1.2.0",
                "id": "finding-info-1",
                "ruleId": "info-001",
                "severity": "INFO",
                "tool": {"name": "semgrep", "version": "1.0.0"},
                "location": {"path": "test.py", "startLine": 1},
                "message": "Code smell detected",
            }
        ],
    }


def test_ci_mode_fails_on_policy_violation_with_flag(
    tmp_path, sample_findings_with_violations
):
    """Test CI mode fails when policy violations found and --fail-on-policy-violation set."""
    from scripts.cli.report_orchestrator import cmd_report
    from scripts.core.policy_engine import PolicyResult

    # Create findings.json with violations
    results_dir = tmp_path / "results"
    summaries_dir = results_dir / "summaries"
    summaries_dir.mkdir(parents=True, exist_ok=True)
    (summaries_dir / "findings.json").write_text(
        json.dumps(sample_findings_with_violations), encoding="utf-8"
    )

    # Create jmo.yml with policy enabled
    jmo_yml = tmp_path / "jmo.yml"
    jmo_yml.write_text(
        """
policy:
  enabled: true
  auto_evaluate: true
  default_policies:
    - zero-secrets
  fail_on_violation: false  # Config is false, but CLI flag should override
outputs:
  - json
""",
        encoding="utf-8",
    )

    # Create args for CI mode with --fail-on-policy-violation
    args = argparse.Namespace(
        results_dir=str(results_dir),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        out=None,
        config=str(jmo_yml),
        profile=False,
        threads=None,
        fail_on=None,
        policies=["zero-secrets"],
        fail_on_policy_violation=True,  # CLI flag set
        store_history=False,
    )

    def mock_log_fn(args, level, message):
        print(f"[{level}] {message}")

    # Mock policy evaluation to return failure
    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        mock_eval.return_value = {
            "zero-secrets": PolicyResult(
                policy_name="zero-secrets",
                passed=False,
                violations=[{"category": "SECRET", "message": "API key detected"}],
            )
        }

        with patch("scripts.core.reporters.policy_reporter.write_policy_report"):
            with patch("scripts.core.reporters.policy_reporter.write_policy_json"):
                with patch(
                    "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                ):
                    result = cmd_report(args, mock_log_fn)

    # Should exit 1 due to --fail-on-policy-violation flag
    assert result == 1


def test_ci_mode_warns_on_policy_violation_without_flag(
    tmp_path, sample_findings_with_violations
):
    """Test CI mode warns but doesn't fail without --fail-on-policy-violation."""
    from scripts.cli.report_orchestrator import cmd_report
    from scripts.core.policy_engine import PolicyResult

    # Create findings.json with violations
    results_dir = tmp_path / "results"
    summaries_dir = results_dir / "summaries"
    summaries_dir.mkdir(parents=True, exist_ok=True)
    (summaries_dir / "findings.json").write_text(
        json.dumps(sample_findings_with_violations), encoding="utf-8"
    )

    # Create jmo.yml with policy enabled but fail_on_violation=false
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

    # Create args for CI mode WITHOUT --fail-on-policy-violation
    args = argparse.Namespace(
        results_dir=str(results_dir),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        out=None,
        config=str(jmo_yml),
        profile=False,
        threads=None,
        fail_on=None,
        policies=["zero-secrets"],
        fail_on_policy_violation=False,  # CLI flag not set
        store_history=False,
    )

    def mock_log_fn(args, level, message):
        print(f"[{level}] {message}")

    # Mock policy evaluation to return failure
    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        mock_eval.return_value = {
            "zero-secrets": PolicyResult(
                policy_name="zero-secrets",
                passed=False,
                violations=[{"category": "SECRET", "message": "API key detected"}],
            )
        }

        with patch("scripts.core.reporters.policy_reporter.write_policy_report"):
            with patch("scripts.core.reporters.policy_reporter.write_policy_json"):
                with patch(
                    "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                ):
                    result = cmd_report(args, mock_log_fn)

    # Should exit 0 (warn only, no failure)
    assert result == 0


def test_ci_mode_config_fail_on_violation_works(
    tmp_path, sample_findings_with_violations
):
    """Test CI mode respects config fail_on_violation=true."""
    from scripts.cli.report_orchestrator import cmd_report
    from scripts.core.policy_engine import PolicyResult

    # Create findings.json with violations
    results_dir = tmp_path / "results"
    summaries_dir = results_dir / "summaries"
    summaries_dir.mkdir(parents=True, exist_ok=True)
    (summaries_dir / "findings.json").write_text(
        json.dumps(sample_findings_with_violations), encoding="utf-8"
    )

    # Create jmo.yml with fail_on_violation=true in config
    jmo_yml = tmp_path / "jmo.yml"
    jmo_yml.write_text(
        """
policy:
  enabled: true
  auto_evaluate: true
  default_policies:
    - zero-secrets
  fail_on_violation: true  # Config set to true
outputs:
  - json
""",
        encoding="utf-8",
    )

    # Create args WITHOUT CLI flag (should use config)
    args = argparse.Namespace(
        results_dir=str(results_dir),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        out=None,
        config=str(jmo_yml),
        profile=False,
        threads=None,
        fail_on=None,
        policies=None,  # Use config default policies
        fail_on_policy_violation=False,  # CLI flag not set
        store_history=False,
    )

    def mock_log_fn(args, level, message):
        print(f"[{level}] {message}")

    # Mock policy evaluation to return failure
    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        mock_eval.return_value = {
            "zero-secrets": PolicyResult(
                policy_name="zero-secrets",
                passed=False,
                violations=[{"category": "SECRET", "message": "API key detected"}],
            )
        }

        with patch("scripts.core.reporters.policy_reporter.write_policy_report"):
            with patch("scripts.core.reporters.policy_reporter.write_policy_json"):
                with patch(
                    "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                ):
                    result = cmd_report(args, mock_log_fn)

    # Should exit 1 due to config fail_on_violation=true
    assert result == 1


def test_ci_mode_passes_when_policies_pass(tmp_path, sample_findings_no_violations):
    """Test CI mode succeeds when all policies pass."""
    from scripts.cli.report_orchestrator import cmd_report
    from scripts.core.policy_engine import PolicyResult

    # Create findings.json without violations
    results_dir = tmp_path / "results"
    summaries_dir = results_dir / "summaries"
    summaries_dir.mkdir(parents=True, exist_ok=True)
    (summaries_dir / "findings.json").write_text(
        json.dumps(sample_findings_no_violations), encoding="utf-8"
    )

    # Create jmo.yml
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

    # Create args with --fail-on-policy-violation
    args = argparse.Namespace(
        results_dir=str(results_dir),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        out=None,
        config=str(jmo_yml),
        profile=False,
        threads=None,
        fail_on=None,
        policies=["zero-secrets"],
        fail_on_policy_violation=True,
        store_history=False,
    )

    def mock_log_fn(args, level, message):
        print(f"[{level}] {message}")

    # Mock policy evaluation to return success
    with patch("scripts.core.reporters.policy_reporter.evaluate_policies") as mock_eval:
        mock_eval.return_value = {
            "zero-secrets": PolicyResult(
                policy_name="zero-secrets", passed=True, violations=[]
            )
        }

        with patch("scripts.core.reporters.policy_reporter.write_policy_report"):
            with patch("scripts.core.reporters.policy_reporter.write_policy_json"):
                with patch(
                    "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                ):
                    result = cmd_report(args, mock_log_fn)

    # Should exit 0 (all policies passed)
    assert result == 0


def test_ci_orchestrator_passes_policy_args_to_report(tmp_path):
    """Test that ci_orchestrator properly passes policy args to report phase."""
    from scripts.cli.ci_orchestrator import cmd_ci

    # Create mock args for CI command
    args = argparse.Namespace(
        repo=None,
        repos_dir=None,
        targets=None,
        image=None,
        images_file=None,
        terraform_state=None,
        cloudformation=None,
        k8s_manifest=None,
        url=None,
        urls_file=None,
        api_spec=None,
        gitlab_url=None,
        gitlab_token=None,
        gitlab_group=None,
        gitlab_repo=None,
        k8s_context=None,
        k8s_namespace=None,
        k8s_all_namespaces=False,
        results_dir="results",
        config="jmo.yml",
        tools=None,
        timeout=600,
        threads=None,
        allow_missing_tools=False,
        profile_name=None,
        log_level=None,
        human_logs=False,
        store_history=False,
        history_db=None,
        fail_on=None,
        profile=False,
        policies=["zero-secrets", "owasp-top-10"],
        fail_on_policy_violation=True,
    )

    # Mock scan and report functions
    def mock_scan(args):
        return 0

    def mock_report(args, log_fn):
        # Verify that policy args were passed
        assert hasattr(args, "policies")
        assert hasattr(args, "fail_on_policy_violation")
        assert args.policies == ["zero-secrets", "owasp-top-10"]
        assert args.fail_on_policy_violation is True
        return 0

    # Run CI orchestrator
    exit_code = cmd_ci(args, mock_scan, mock_report)

    assert exit_code == 0


# ========== CI POLICY GATING TEST COVERAGE ====================
# These tests verify CI mode policy integration:
# 1. --fail-on-policy-violation causes exit code 1 on violations
# 2. Without flag, violations warn but exit code 0
# 3. Config fail_on_violation=true works correctly
# 4. All policies passing results in exit code 0
# 5. ci_orchestrator passes policy args to report phase
#
# Run: pytest tests/integration/test_ci_policy_gating.py -v
