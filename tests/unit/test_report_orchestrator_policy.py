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
from unittest.mock import MagicMock, patch

import pytest


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
    # A target folder, as a scan leaves: `cmd_report` refuses a directory
    # holding no scan output.
    (results_dir / "individual-repos" / "repo").mkdir(parents=True, exist_ok=True)
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


# --- Fail closed: an enforced policy with no verdict is not a pass ----------
#
# With enforcement on, every requested policy that produced no verdict used to
# log a warning and exit 0: OPA missing, a name matching no policy, an
# evaluation error. Measured from an installed v1.1.1 wheel, which shipped no
# policy at all, a verified secret under `zero-secrets` exited 0. These run the
# real `evaluate_policies` where they can, so the reason it records is the one
# the user reads.


def _policy_args(tmp_path, findings, *, enforce, policies):
    jmo_yml = tmp_path / "jmo.yml"
    jmo_yml.write_text(
        "policy:\n  enabled: true\noutputs:\n  - json\n", encoding="utf-8"
    )
    results_dir = write_findings_json(tmp_path, findings)
    return argparse.Namespace(
        config=str(jmo_yml),
        results_dir_pos=str(results_dir),
        results_dir_opt=None,
        results_dir=str(results_dir),
        out=None,
        profile=False,
        threads=None,
        fail_on=None,
        policies=policies,
        fail_on_policy_violation=enforce,
        store_history=False,
    )


class _Log:
    """A `_log_fn` that keeps what it was given."""

    def __init__(self):
        self.lines = []

    def __call__(self, args, level, message):
        self.lines.append((level, message))

    def at(self, level):
        return [m for lv, m in self.lines if lv == level]


@pytest.fixture
def no_user_policies(tmp_path, monkeypatch):
    """Keep the developer's ~/.jmo/policies out of discovery."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))


def _engine(evaluate):
    """A PolicyEngine stand-in: OPA is not needed to reach the verdict logic."""
    engine = MagicMock()
    engine.evaluate.side_effect = evaluate
    return MagicMock(return_value=engine)


def test_enforced_report_fails_when_opa_is_missing(
    tmp_path, sample_findings, no_user_policies
):
    from scripts.cli.report_orchestrator import cmd_report
    from scripts.core.exceptions import OPANotFoundException

    args = _policy_args(
        tmp_path, sample_findings, enforce=True, policies=["zero-secrets"]
    )
    log = _Log()
    with patch(
        "scripts.core.reporters.policy_reporter.PolicyEngine",
        side_effect=OPANotFoundException(),
    ):
        result = cmd_report(args, log)

    assert result == 2
    errors = log.at("ERROR")
    assert any("'zero-secrets' could not be evaluated" in e for e in errors), errors
    assert any("OPA not installed" in e for e in errors), errors


def test_enforced_report_fails_on_a_policy_name_that_matches_nothing(
    tmp_path, sample_findings, no_user_policies
):
    from scripts.cli.report_orchestrator import cmd_report

    args = _policy_args(
        tmp_path, sample_findings, enforce=True, policies=["zero-secret"]
    )
    log = _Log()
    with patch("scripts.core.reporters.policy_reporter.PolicyEngine", _engine(None)):
        result = cmd_report(args, log)

    assert result == 2
    errors = log.at("ERROR")
    assert any(
        "'zero-secret' could not be evaluated: no such policy" in e for e in errors
    ), errors
    # The reason lists what would have worked, so the missing "s" is visible.
    assert any("zero-secrets" in e for e in errors), errors


def test_enforced_report_fails_when_one_of_two_policies_errors(
    tmp_path, sample_findings, no_user_policies
):
    """The other policy ran and passed; that must not carry the pair."""
    from scripts.cli.report_orchestrator import cmd_report
    from scripts.core.policy_engine import PolicyResult

    def evaluate(findings, policy_path):
        if policy_path.stem == "owasp-top-10":
            raise RuntimeError("Policy evaluation error: rego_parse_error")
        return PolicyResult(policy_name=policy_path.stem, passed=True)

    args = _policy_args(
        tmp_path,
        sample_findings,
        enforce=True,
        policies=["zero-secrets", "owasp-top-10"],
    )
    log = _Log()
    with patch(
        "scripts.core.reporters.policy_reporter.PolicyEngine", _engine(evaluate)
    ):
        result = cmd_report(args, log)

    assert result == 2
    errors = log.at("ERROR")
    assert any(
        "'owasp-top-10' could not be evaluated" in e and "rego_parse_error" in e
        for e in errors
    ), errors
    assert not any("'zero-secrets' could not" in e for e in errors), errors


def test_enforced_failed_verdict_survives_a_report_that_cannot_be_written(
    tmp_path, sample_findings, no_user_policies
):
    """The reports were written before the verdict was read, so an OSError on
    the write skipped the verdict and a FAILED policy exited 0."""
    from scripts.cli.report_orchestrator import cmd_report
    from scripts.core.policy_engine import PolicyResult

    def evaluate(findings, policy_path):
        return PolicyResult(policy_name=policy_path.stem, passed=False)

    args = _policy_args(
        tmp_path, sample_findings, enforce=True, policies=["zero-secrets"]
    )
    with (
        patch("scripts.core.reporters.policy_reporter.PolicyEngine", _engine(evaluate)),
        patch(
            "scripts.core.reporters.policy_reporter.write_policy_report",
            side_effect=PermissionError("read-only summaries"),
        ),
    ):
        result = cmd_report(args, _Log())

    assert result == 1


def test_without_enforcement_missing_opa_only_warns(
    tmp_path, sample_findings, no_user_policies
):
    """The other half of the contract, kept from before: warn and exit 0."""
    from scripts.cli.report_orchestrator import cmd_report
    from scripts.core.exceptions import OPANotFoundException

    args = _policy_args(
        tmp_path, sample_findings, enforce=False, policies=["zero-secrets"]
    )
    log = _Log()
    with patch(
        "scripts.core.reporters.policy_reporter.PolicyEngine",
        side_effect=OPANotFoundException(),
    ):
        result = cmd_report(args, log)

    assert result == 0
    assert any("Policy evaluation skipped" in w for w in log.at("WARN")), log.lines
    assert not log.at("ERROR"), log.lines


def test_without_enforcement_an_unknown_policy_name_only_warns(
    tmp_path, sample_findings, no_user_policies, caplog
):
    from scripts.cli.report_orchestrator import cmd_report

    args = _policy_args(
        tmp_path, sample_findings, enforce=False, policies=["no-such-policy"]
    )
    log = _Log()
    with (
        caplog.at_level("WARNING"),
        patch("scripts.core.reporters.policy_reporter.PolicyEngine", _engine(None)),
    ):
        result = cmd_report(args, log)

    assert result == 0
    assert "Policy 'no-such-policy' not found" in caplog.text
    assert not log.at("ERROR"), log.lines
