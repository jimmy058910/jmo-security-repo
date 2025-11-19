"""Tests for policy flow module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest


def test_policy_flow_module_imports():
    """Test that policy_flow module can be imported."""
    try:
        from scripts.cli.wizard_flows import policy_flow

        assert policy_flow is not None
    except ImportError as e:
        pytest.fail(f"Failed to import policy_flow: {e}")


def test_policy_evaluation_menu_function_exists():
    """Test that policy_evaluation_menu function exists."""
    from scripts.cli.wizard_flows.policy_flow import policy_evaluation_menu

    assert callable(policy_evaluation_menu)


def test_display_policy_violations_interactive_exists():
    """Test that display_policy_violations_interactive function exists."""
    from scripts.cli.wizard_flows.policy_flow import (
        display_policy_violations_interactive,
    )

    assert callable(display_policy_violations_interactive)


@patch("scripts.cli.wizard_flows.policy_flow.PolicyEngine")
@patch("scripts.cli.wizard_flows.policy_flow.Path")
def test_policy_evaluation_menu_no_opa(mock_path, mock_engine_cls, tmp_path):
    """Test policy evaluation when OPA is unavailable."""
    from scripts.cli.wizard_flows.policy_flow import policy_evaluation_menu

    # Mock OPA unavailable
    mock_engine_cls.side_effect = RuntimeError("OPA not found")

    results_dir = tmp_path / "results"
    findings = []

    result = policy_evaluation_menu(
        results_dir, "balanced", findings, non_interactive=True
    )

    assert result == {}


@patch("scripts.cli.wizard_flows.policy_flow.PolicyEngine")
@patch("builtins.print")
def test_policy_evaluation_menu_non_interactive(mock_print, mock_engine_cls, tmp_path):
    """Test policy evaluation in non-interactive mode."""
    from scripts.cli.wizard_flows.policy_flow import policy_evaluation_menu

    # Mock PolicyEngine
    mock_engine = MagicMock()
    mock_engine_cls.return_value = mock_engine

    # Mock policy result
    mock_result = MagicMock()
    mock_result.passed = True
    mock_result.violation_count = 0
    mock_engine.evaluate.return_value = mock_result

    # Mock builtin_dir to return empty list (no policies)
    with patch("scripts.cli.wizard_flows.policy_flow.Path") as mock_path_cls:
        mock_builtin_dir = MagicMock()
        mock_builtin_dir.glob.return_value = []
        mock_path_cls.return_value.parent.parent.parent.parent = MagicMock()
        mock_path_cls.return_value.parent.parent.parent.parent.__truediv__ = (
            lambda self, x: mock_builtin_dir
        )

        results_dir = tmp_path / "results"
        findings = []

        result = policy_evaluation_menu(
            results_dir, "balanced", findings, non_interactive=True
        )

        # With no policies, should return empty dict
        assert isinstance(result, dict)


def test_detect_recommended_policies_function():
    """Test _detect_recommended_policies helper function."""
    from scripts.cli.wizard_flows.policy_flow import _detect_recommended_policies

    findings = [
        {
            "tool": {"name": "trufflehog"},
            "verified": True,
            "compliance": {"owaspTop10_2021": ["A02:2021"]},
        }
    ]

    # Mock policies_with_metadata
    mock_policy_path = MagicMock()
    mock_policy_path.stem = "zero-secrets"
    policies = [(mock_policy_path, {"name": "zero-secrets"})]

    recommended = _detect_recommended_policies(findings, "balanced", policies)

    assert isinstance(recommended, list)


def test_display_scan_summary_function():
    """Test _display_scan_summary helper function."""
    from scripts.cli.wizard_flows.policy_flow import _display_scan_summary

    findings = [
        {"severity": "HIGH", "tool": {"name": "semgrep"}},
        {"severity": "CRITICAL", "tool": {"name": "trivy"}},
    ]

    # Should not raise exception
    _display_scan_summary(findings)


def test_parse_policy_choice_skip():
    """Test _parse_policy_choice with skip option."""
    from scripts.cli.wizard_flows.policy_flow import _parse_policy_choice

    result = _parse_policy_choice("s", [], [])
    assert result == []


def test_parse_policy_choice_all():
    """Test _parse_policy_choice with select all option."""
    from scripts.cli.wizard_flows.policy_flow import _parse_policy_choice

    mock_path1 = MagicMock()
    mock_path2 = MagicMock()
    recommended = [mock_path1, mock_path2]

    result = _parse_policy_choice("a", [], recommended)
    assert result == recommended


@patch("builtins.open", new_callable=mock_open)
def test_export_violations_json(mock_file):
    """Test _export_violations_json function."""
    from scripts.cli.wizard_flows.policy_flow import _export_violations_json

    mock_result = MagicMock()
    mock_result.passed = False
    mock_result.violation_count = 2
    mock_result.violations = [{"message": "test"}]
    mock_result.warnings = []
    mock_result.message = "Policy failed"

    _export_violations_json("test-policy", mock_result)

    assert mock_file.called


@patch("builtins.open", new_callable=mock_open)
def test_export_violations_markdown(mock_file):
    """Test _export_violations_markdown function."""
    from scripts.cli.wizard_flows.policy_flow import _export_violations_markdown

    mock_result = MagicMock()
    mock_result.passed = False
    mock_result.violation_count = 2
    mock_result.violations = [
        {"category": "secrets", "message": "test violation", "severity": "HIGH"}
    ]
    mock_result.message = "Policy failed"

    _export_violations_markdown("test-policy", mock_result)

    assert mock_file.called
