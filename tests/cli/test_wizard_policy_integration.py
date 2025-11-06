#!/usr/bin/env python3
"""
Unit tests for wizard policy integration (Phase 2.5).

This test suite verifies that:
1. Interactive policy selection menu works correctly
2. Auto-detection recommends appropriate policies
3. Non-interactive mode uses profile defaults
4. Policy choice parsing handles all input types
5. Violation display and export functions work
6. CLI integration with --policies and --skip-policies flags

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
            "verified": True,  # Verified secret
        },
        {
            "schemaVersion": "1.2.0",
            "id": "finding-2",
            "ruleId": "xss-001",
            "severity": "MEDIUM",
            "tool": {"name": "semgrep", "version": "1.0.0"},
            "location": {"path": "app.py", "startLine": 20},
            "message": "Potential XSS vulnerability",
            "compliance": {
                "owaspTop10_2021": ["A03:2021"],  # OWASP Top 10 violation
            },
        },
        {
            "schemaVersion": "1.2.0",
            "id": "finding-3",
            "ruleId": "critical-001",
            "severity": "CRITICAL",
            "tool": {"name": "trivy", "version": "0.68.0"},
            "location": {"path": "Dockerfile", "startLine": 5},
            "message": "Critical vulnerability",
        },
    ]


@pytest.fixture
def sample_policy_metadata():
    """Sample policy metadata for testing."""
    from scripts.core.policy_engine import PolicyMetadata

    return [
        PolicyMetadata(
            name="zero-secrets",
            version="1.0.0",
            description="Block ANY verified secrets",
        ),
        PolicyMetadata(
            name="owasp-top-10",
            version="1.0.0",
            description="Enforce OWASP Top 10 2021 compliance",
        ),
        PolicyMetadata(
            name="pci-dss",
            version="1.0.0",
            description="PCI DSS 4.0 compliance requirements",
        ),
        PolicyMetadata(
            name="production-hardening",
            version="1.0.0",
            description="Production security best practices",
        ),
        PolicyMetadata(
            name="hipaa-compliance",
            version="1.0.0",
            description="HIPAA Security Rule compliance",
        ),
    ]


@pytest.fixture
def mock_policy_engine(sample_policy_metadata):
    """Mock PolicyEngine for testing."""
    from scripts.core.policy_engine import PolicyResult

    mock_engine = MagicMock()

    # Mock get_metadata to return sample metadata
    mock_engine.get_metadata.side_effect = sample_policy_metadata

    # Mock evaluate_policy to return successful results
    mock_engine.evaluate_policy.return_value = PolicyResult(
        policy_name="test-policy",
        passed=True,
        violations=[],
        warnings=[],
        message="",
    )

    return mock_engine


# ========== AUTO-DETECTION TESTS ====================


def test_detect_recommended_policies_fast_profile(sample_findings):
    """Test auto-detection for fast profile (zero-secrets only)."""
    from scripts.cli.wizard_flows.policy_flow import _detect_recommended_policies

    # Create mock policies with proper metadata (as dicts, not PolicyMetadata objects)
    policies_with_metadata = [
        (Path("zero-secrets.rego"), {"name": "zero-secrets", "version": "1.0.0", "description": "Block secrets"}),
        (Path("owasp-top-10.rego"), {"name": "owasp-top-10", "version": "1.0.0", "description": "OWASP Top 10"}),
    ]

    # Use findings without OWASP violations to test pure fast profile
    findings_no_owasp = [
        f for f in sample_findings
        if not f.get("compliance", {}).get("owaspTop10_2021")
    ]

    recommended = _detect_recommended_policies(findings_no_owasp, "fast", policies_with_metadata)

    # Fast profile should recommend zero-secrets only
    assert len(recommended) == 1
    assert "zero-secrets" in str(recommended[0])


def test_detect_recommended_policies_balanced_profile(sample_findings):
    """Test auto-detection for balanced profile (owasp + zero-secrets)."""
    from scripts.cli.wizard_flows.policy_flow import _detect_recommended_policies

    policies_with_metadata = [
        (Path("zero-secrets.rego"), {"name": "zero-secrets", "version": "1.0.0", "description": "Block secrets"}),
        (Path("owasp-top-10.rego"), {"name": "owasp-top-10", "version": "1.0.0", "description": "OWASP Top 10"}),
        (Path("pci-dss.rego"), {"name": "pci-dss", "version": "1.0.0", "description": "PCI DSS"}),
    ]

    recommended = _detect_recommended_policies(sample_findings, "balanced", policies_with_metadata)

    # Balanced profile should recommend owasp-top-10 + zero-secrets
    assert len(recommended) == 2
    assert any("zero-secrets" in str(p) for p in recommended)
    assert any("owasp-top-10" in str(p) for p in recommended)


def test_detect_recommended_policies_deep_profile(sample_findings, sample_policy_metadata):
    """Test auto-detection for deep profile (all policies)."""
    from scripts.cli.wizard_flows.policy_flow import _detect_recommended_policies

    # Convert PolicyMetadata objects to dicts
    policies_with_metadata = [
        (Path(f"{meta.name}.rego"), {"name": meta.name, "version": meta.version, "description": meta.description})
        for meta in sample_policy_metadata
    ]

    recommended = _detect_recommended_policies(sample_findings, "deep", policies_with_metadata)

    # Deep profile should recommend all 5 policies
    assert len(recommended) == 5


def test_detect_recommended_policies_with_verified_secrets():
    """Test auto-detection recommends zero-secrets when verified secrets found."""
    from scripts.cli.wizard_flows.policy_flow import _detect_recommended_policies

    findings_with_secrets = [
        {
            "tool": {"name": "trufflehog"},
            "verified": True,
            "severity": "HIGH",
        }
    ]

    policies_with_metadata = [
        (Path("zero-secrets.rego"), {"name": "zero-secrets", "version": "1.0.0", "description": "Block secrets"}),
        (Path("owasp-top-10.rego"), {"name": "owasp-top-10", "version": "1.0.0", "description": "OWASP Top 10"}),
    ]

    recommended = _detect_recommended_policies(findings_with_secrets, "fast", policies_with_metadata)

    # Should recommend zero-secrets due to verified secrets
    assert any("zero-secrets" in str(p) for p in recommended)


def test_detect_recommended_policies_with_owasp_violations():
    """Test auto-detection recommends owasp-top-10 when OWASP violations found."""
    from scripts.cli.wizard_flows.policy_flow import _detect_recommended_policies

    findings_with_owasp = [
        {
            "tool": {"name": "semgrep"},
            "severity": "MEDIUM",
            "compliance": {"owaspTop10_2021": ["A03:2021"]},
        }
    ]

    policies_with_metadata = [
        (Path("zero-secrets.rego"), {"name": "zero-secrets", "version": "1.0.0", "description": "Block secrets"}),
        (Path("owasp-top-10.rego"), {"name": "owasp-top-10", "version": "1.0.0", "description": "OWASP Top 10"}),
    ]

    recommended = _detect_recommended_policies(findings_with_owasp, "fast", policies_with_metadata)

    # Should recommend owasp-top-10 due to OWASP violations
    assert any("owasp-top-10" in str(p) for p in recommended)


def test_detect_recommended_policies_with_pci_violations():
    """Test auto-detection recommends pci-dss when PCI violations found."""
    from scripts.cli.wizard_flows.policy_flow import _detect_recommended_policies

    findings_with_pci = [
        {
            "tool": {"name": "checkov"},
            "severity": "HIGH",
            "compliance": {"pciDss4_0": [{"requirement": "3.4"}]},
        }
    ]

    policies_with_metadata = [
        (Path("zero-secrets.rego"), {"name": "zero-secrets", "version": "1.0.0", "description": "Block secrets"}),
        (Path("pci-dss.rego"), {"name": "pci-dss", "version": "1.0.0", "description": "PCI DSS"}),
    ]

    recommended = _detect_recommended_policies(findings_with_pci, "fast", policies_with_metadata)

    # Should recommend pci-dss due to PCI violations
    assert any("pci-dss" in str(p) for p in recommended)


# ========== POLICY CHOICE PARSING TESTS ====================


def test_parse_policy_choice_skip(sample_policy_metadata):
    """Test parsing 's' (skip) choice."""
    from scripts.cli.wizard_flows.policy_flow import _parse_policy_choice

    # Convert PolicyMetadata objects to dicts
    policies_with_metadata = [
        (Path(f"{meta.name}.rego"), {"name": meta.name, "version": meta.version, "description": meta.description})
        for meta in sample_policy_metadata
    ]

    result = _parse_policy_choice("s", policies_with_metadata, [])

    assert result == []


def test_parse_policy_choice_recommended(sample_policy_metadata):
    """Test parsing 'a' (all recommended) choice."""
    from scripts.cli.wizard_flows.policy_flow import _parse_policy_choice

    # Convert PolicyMetadata objects to dicts
    policies_with_metadata = [
        (Path(f"{meta.name}.rego"), {"name": meta.name, "version": meta.version, "description": meta.description})
        for meta in sample_policy_metadata
    ]
    recommended = [policies_with_metadata[0][0], policies_with_metadata[1][0]]

    result = _parse_policy_choice("a", policies_with_metadata, recommended)

    assert result == recommended


def test_parse_policy_choice_all_policies(sample_policy_metadata):
    """Test parsing 'r' (all policies) choice."""
    from scripts.cli.wizard_flows.policy_flow import _parse_policy_choice

    # Convert PolicyMetadata objects to dicts
    policies_with_metadata = [
        (Path(f"{meta.name}.rego"), {"name": meta.name, "version": meta.version, "description": meta.description})
        for meta in sample_policy_metadata
    ]

    result = _parse_policy_choice("r", policies_with_metadata, [])

    assert len(result) == 5
    assert result == [path for path, _ in policies_with_metadata]


def test_parse_policy_choice_single_number(sample_policy_metadata):
    """Test parsing single policy number (e.g., '1')."""
    from scripts.cli.wizard_flows.policy_flow import _parse_policy_choice

    # Convert PolicyMetadata objects to dicts
    policies_with_metadata = [
        (Path(f"{meta.name}.rego"), {"name": meta.name, "version": meta.version, "description": meta.description})
        for meta in sample_policy_metadata
    ]

    result = _parse_policy_choice("1", policies_with_metadata, [])

    assert len(result) == 1
    assert "zero-secrets" in str(result[0])


def test_parse_policy_choice_invalid_number(sample_policy_metadata):
    """Test parsing invalid policy number returns empty list."""
    from scripts.cli.wizard_flows.policy_flow import _parse_policy_choice

    # Convert PolicyMetadata objects to dicts
    policies_with_metadata = [
        (Path(f"{meta.name}.rego"), {"name": meta.name, "version": meta.version, "description": meta.description})
        for meta in sample_policy_metadata
    ]

    result = _parse_policy_choice("99", policies_with_metadata, [])

    assert result == []


def test_parse_policy_choice_invalid_choice(sample_policy_metadata):
    """Test parsing invalid choice returns empty list."""
    from scripts.cli.wizard_flows.policy_flow import _parse_policy_choice

    # Convert PolicyMetadata objects to dicts
    policies_with_metadata = [
        (Path(f"{meta.name}.rego"), {"name": meta.name, "version": meta.version, "description": meta.description})
        for meta in sample_policy_metadata
    ]

    result = _parse_policy_choice("invalid", policies_with_metadata, [])

    assert result == []


# ========== DISPLAY FUNCTIONS TESTS ====================


def test_display_scan_summary(sample_findings, capsys):
    """Test display_scan_summary shows correct counts."""
    from scripts.cli.wizard_flows.policy_flow import _display_scan_summary

    _display_scan_summary(sample_findings)

    captured = capsys.readouterr()
    assert "1 CRITICAL findings" in captured.out
    assert "1 HIGH findings" in captured.out
    assert "1 verified secrets" in captured.out
    assert "1 OWASP Top 10 vulnerabilities" in captured.out


def test_display_scan_summary_no_findings(capsys):
    """Test display_scan_summary with no findings."""
    from scripts.cli.wizard_flows.policy_flow import _display_scan_summary

    _display_scan_summary([])

    captured = capsys.readouterr()
    # Should still display header
    assert "Your scan found:" in captured.out


# ========== EXPORT FUNCTIONS TESTS ====================


def test_export_violations_json(tmp_path):
    """Test exporting violations to JSON file."""
    from scripts.core.policy_engine import PolicyResult
    from scripts.cli.wizard_flows.policy_flow import _export_violations_json

    result = PolicyResult(
        policy_name="zero-secrets",
        passed=False,
        violations=[
            {"category": "SECRET", "message": "Hardcoded password", "severity": "HIGH"}
        ],
        warnings=["Warning 1"],
        message="Policy failed",
    )

    # Change to tmp_path before exporting
    import os
    original_dir = os.getcwd()
    try:
        os.chdir(tmp_path)
        _export_violations_json("zero-secrets", result)

        # Check file was created
        output_file = tmp_path / "policy_violations_zero-secrets.json"
        assert output_file.exists()

        # Check file contents
        data = json.loads(output_file.read_text())
        assert data["policy"] == "zero-secrets"
        assert data["passed"] is False
        assert data["violation_count"] == 1
        assert len(data["violations"]) == 1
    finally:
        os.chdir(original_dir)


def test_export_violations_markdown(tmp_path):
    """Test exporting violations to Markdown file."""
    from scripts.core.policy_engine import PolicyResult
    from scripts.cli.wizard_flows.policy_flow import _export_violations_markdown

    result = PolicyResult(
        policy_name="owasp-top-10",
        passed=False,
        violations=[
            {
                "category": "XSS",
                "message": "Cross-site scripting vulnerability",
                "severity": "MEDIUM",
                "tool": {"name": "semgrep"},
                "path": "app.py",
            }
        ],
        message="OWASP violations detected",
    )

    import os
    original_dir = os.getcwd()
    try:
        os.chdir(tmp_path)
        _export_violations_markdown("owasp-top-10", result)

        # Check file was created
        output_file = tmp_path / "policy_violations_owasp-top-10.md"
        assert output_file.exists()

        # Check file contents
        content = output_file.read_text()
        assert "# Policy Violations: owasp-top-10" in content
        assert "❌ FAILED" in content
        assert "**Violations:** 1" in content
        assert "XSS" in content
    finally:
        os.chdir(original_dir)


# ========== POLICY EVALUATION MENU TESTS ====================


@patch("scripts.cli.wizard_flows.policy_flow.PolicyEngine")
def test_policy_evaluation_menu_opa_unavailable(mock_engine_class, tmp_path, sample_findings, capsys):
    """Test graceful handling when OPA unavailable."""
    from scripts.cli.wizard_flows.policy_flow import policy_evaluation_menu

    # Mock OPA unavailable
    mock_engine_class.side_effect = RuntimeError("OPA binary not found")

    results = policy_evaluation_menu(tmp_path, "balanced", sample_findings, non_interactive=True)

    assert results == {}
    captured = capsys.readouterr()
    assert "Policy evaluation unavailable" in captured.out


@patch("scripts.cli.wizard_flows.policy_flow.Path.glob")
@patch("scripts.cli.wizard_flows.policy_flow.PolicyEngine")
def test_policy_evaluation_menu_no_policies(mock_engine_class, mock_glob, tmp_path, sample_findings, capsys):
    """Test graceful handling when no built-in policies found."""
    from scripts.cli.wizard_flows.policy_flow import policy_evaluation_menu

    # Mock PolicyEngine to work
    mock_engine = MagicMock()
    mock_engine_class.return_value = mock_engine

    # Mock empty policy directory (no .rego files found)
    mock_glob.return_value = []

    results = policy_evaluation_menu(tmp_path, "balanced", sample_findings, non_interactive=True)

    assert results == {}
    captured = capsys.readouterr()
    assert "No built-in policies found" in captured.out


# ========== METADATA FALLBACK TESTS ====================


@patch("scripts.cli.wizard_flows.policy_flow.Path.glob")
@patch("scripts.cli.wizard_flows.policy_flow.PolicyEngine")
def test_policy_evaluation_menu_metadata_fallback(mock_engine_class, mock_glob, tmp_path, sample_findings, capsys):
    """Test fallback metadata when get_metadata() fails."""
    from scripts.cli.wizard_flows.policy_flow import policy_evaluation_menu
    from scripts.core.policy_engine import PolicyResult

    # Mock PolicyEngine
    mock_engine = MagicMock()
    mock_engine_class.return_value = mock_engine

    # Mock policy files
    mock_policy_files = [
        Path("policies/builtin/zero-secrets.rego"),
    ]
    mock_glob.return_value = mock_policy_files

    # Mock get_metadata to raise exception (triggers fallback)
    mock_engine.get_metadata.side_effect = Exception("Metadata parsing failed")

    # Mock evaluate_policy
    mock_engine.evaluate_policy.return_value = PolicyResult(
        policy_name="zero-secrets",
        passed=True,
        violations=[],
    )

    # Create findings.json
    findings_dir = tmp_path / "summaries"
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / "findings.json").write_text(json.dumps(sample_findings))

    results = policy_evaluation_menu(tmp_path, "fast", sample_findings, non_interactive=True)

    # Should use fallback metadata and still evaluate policy
    assert len(results) == 1
    assert "zero-secrets" in results


# ========== CUSTOM POLICY SELECTION TESTS ====================


def test_parse_policy_choice_custom_selection(sample_policy_metadata):
    """Test parsing custom selection (e.g., '1,3,5')."""
    from scripts.cli.wizard_flows.policy_flow import _parse_policy_choice
    from unittest.mock import patch

    # Convert PolicyMetadata objects to dicts
    policies_with_metadata = [
        (Path(f"{meta.name}.rego"), {"name": meta.name, "version": meta.version, "description": meta.description})
        for meta in sample_policy_metadata
    ]

    # Mock input to simulate custom selection
    with patch("builtins.input", return_value="1,3,5"):
        result = _parse_policy_choice("c", policies_with_metadata, [])

    # Should return policies at indices 0, 2, 4 (zero-indexed)
    assert len(result) == 3
    assert "zero-secrets" in str(result[0])
    assert "pci-dss" in str(result[1])
    assert "hipaa-compliance" in str(result[2])


# ========== INTERACTIVE VIOLATION VIEWER TESTS ====================


def test_display_policy_violations_interactive_all_passed():
    """Test violation viewer with all policies passed."""
    from scripts.cli.wizard_flows.policy_flow import display_policy_violations_interactive
    from scripts.core.policy_engine import PolicyResult

    results = {
        "zero-secrets": PolicyResult(policy_name="zero-secrets", passed=True, violations=[]),
        "owasp-top-10": PolicyResult(policy_name="owasp-top-10", passed=True, violations=[]),
    }

    # Should print success message
    import sys
    from io import StringIO
    captured_output = StringIO()
    sys.stdout = captured_output

    display_policy_violations_interactive(results)

    sys.stdout = sys.__stdout__
    output = captured_output.getvalue()

    assert "All policies passed" in output


def test_display_policy_violations_interactive_navigation(capsys):
    """Test violation viewer navigation between policies."""
    from scripts.cli.wizard_flows.policy_flow import display_policy_violations_interactive
    from scripts.core.policy_engine import PolicyResult
    from unittest.mock import patch

    results = {
        "zero-secrets": PolicyResult(
            policy_name="zero-secrets",
            passed=False,
            violations=[{"category": "SECRET", "message": "Hardcoded password", "severity": "HIGH"}],
        ),
        "owasp-top-10": PolicyResult(
            policy_name="owasp-top-10",
            passed=False,
            violations=[{"category": "XSS", "message": "Cross-site scripting", "severity": "MEDIUM"}],
        ),
    }

    # Mock input to navigate: view next policy (3), then exit (5)
    with patch("builtins.input", side_effect=["3", "5"]):
        display_policy_violations_interactive(results)

    captured = capsys.readouterr()
    # Should display both policy names
    assert "zero-secrets" in captured.out
    assert "owasp-top-10" in captured.out


def test_display_violation():
    """Test _display_violation function."""
    from scripts.cli.wizard_flows.policy_flow import _display_violation
    import sys
    from io import StringIO

    violation = {
        "category": "SECRET",
        "message": "Hardcoded API key",
        "finding_id": "finding-123",
        "severity": "CRITICAL",
        "tool": "trufflehog",
        "path": "config.py",
    }

    captured_output = StringIO()
    sys.stdout = captured_output

    _display_violation(1, violation)

    sys.stdout = sys.__stdout__
    output = captured_output.getvalue()

    assert "SECRET" in output
    assert "Hardcoded API key" in output
    assert "finding-123" in output
    assert "CRITICAL" in output
    assert "trufflehog" in output
    assert "config.py" in output


# ========== INTERACTIVE MODE TESTS ====================


@patch("scripts.cli.wizard_flows.policy_flow.Path.glob")
@patch("scripts.cli.wizard_flows.policy_flow.PolicyEngine")
def test_policy_evaluation_menu_interactive_skip(mock_engine_class, mock_glob, tmp_path, sample_findings, capsys):
    """Test interactive mode with user choosing to skip."""
    from scripts.cli.wizard_flows.policy_flow import policy_evaluation_menu
    from unittest.mock import patch

    # Mock PolicyEngine
    mock_engine = MagicMock()
    mock_engine_class.return_value = mock_engine

    # Mock policy files
    mock_policy_files = [Path("policies/builtin/zero-secrets.rego")]
    mock_glob.return_value = mock_policy_files

    # Mock get_metadata to return dict (not PolicyMetadata)
    mock_engine.get_metadata.return_value = {
        "name": "zero-secrets", "version": "1.0.0", "description": "Block secrets"
    }

    # Mock user input: choose 's' (skip)
    with patch("builtins.input", return_value="s"):
        results = policy_evaluation_menu(tmp_path, "fast", sample_findings, non_interactive=False)

    assert results == {}
    captured = capsys.readouterr()
    assert "Skipping policy evaluation" in captured.out


@patch("scripts.cli.wizard_flows.policy_flow.Path.glob")
@patch("scripts.cli.wizard_flows.policy_flow.PolicyEngine")
def test_policy_evaluation_menu_interactive_view_violations(mock_engine_class, mock_glob, tmp_path, sample_findings, capsys):
    """Test interactive mode with viewing violations."""
    from scripts.cli.wizard_flows.policy_flow import policy_evaluation_menu
    from scripts.core.policy_engine import PolicyResult
    from unittest.mock import patch

    # Mock PolicyEngine
    mock_engine = MagicMock()
    mock_engine_class.return_value = mock_engine

    # Mock policy files
    mock_policy_files = [Path("policies/builtin/zero-secrets.rego")]
    mock_glob.return_value = mock_policy_files

    # Mock get_metadata to return dict (not PolicyMetadata)
    mock_engine.get_metadata.return_value = {
        "name": "zero-secrets", "version": "1.0.0", "description": "Block secrets"
    }

    # Mock evaluate_policy to return failed result
    mock_engine.evaluate_policy.return_value = PolicyResult(
        policy_name="zero-secrets",
        passed=False,
        violations=[{"category": "SECRET", "message": "Hardcoded password"}],
    )

    # Create findings.json
    findings_dir = tmp_path / "summaries"
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / "findings.json").write_text(json.dumps(sample_findings))

    # Mock user input: choose 'a' (recommended), then 'n' (don't view violations)
    with patch("builtins.input", side_effect=["a", "n"]):
        results = policy_evaluation_menu(tmp_path, "fast", sample_findings, non_interactive=False)

    assert len(results) == 1
    assert "zero-secrets" in results


def test_display_policy_violations_interactive_export_json(tmp_path, capsys):
    """Test violation viewer with JSON export action."""
    from scripts.cli.wizard_flows.policy_flow import display_policy_violations_interactive
    from scripts.core.policy_engine import PolicyResult
    from unittest.mock import patch
    import os

    results = {
        "zero-secrets": PolicyResult(
            policy_name="zero-secrets",
            passed=False,
            violations=[{"category": "SECRET", "message": "Hardcoded password", "severity": "HIGH"}],
        ),
    }

    # Change to tmp_path for export
    original_dir = os.getcwd()
    try:
        os.chdir(tmp_path)
        # Mock input: export as JSON (1), then exit (5)
        with patch("builtins.input", side_effect=["1", "5"]):
            display_policy_violations_interactive(results)

        # Check JSON file was created
        json_file = tmp_path / "policy_violations_zero-secrets.json"
        assert json_file.exists()
    finally:
        os.chdir(original_dir)


def test_display_policy_violations_interactive_export_markdown(tmp_path, capsys):
    """Test violation viewer with Markdown export action."""
    from scripts.cli.wizard_flows.policy_flow import display_policy_violations_interactive
    from scripts.core.policy_engine import PolicyResult
    from unittest.mock import patch
    import os

    results = {
        "owasp-top-10": PolicyResult(
            policy_name="owasp-top-10",
            passed=False,
            violations=[{"category": "XSS", "message": "Cross-site scripting", "severity": "MEDIUM"}],
            message="Policy failed",
        ),
    }

    # Change to tmp_path for export
    original_dir = os.getcwd()
    try:
        os.chdir(tmp_path)
        # Mock input: export as Markdown (2), then exit (5)
        with patch("builtins.input", side_effect=["2", "5"]):
            display_policy_violations_interactive(results)

        # Check Markdown file was created
        md_file = tmp_path / "policy_violations_owasp-top-10.md"
        assert md_file.exists()

        # Check content includes message
        content = md_file.read_text()
        assert "Policy failed" in content
    finally:
        os.chdir(original_dir)


def test_display_policy_violations_interactive_more_than_10_violations(capsys):
    """Test violation viewer with >10 violations showing truncation."""
    from scripts.cli.wizard_flows.policy_flow import display_policy_violations_interactive
    from scripts.core.policy_engine import PolicyResult
    from unittest.mock import patch

    # Create 15 violations
    violations = [
        {"category": "SECRET", "message": f"Finding {i}", "severity": "HIGH"}
        for i in range(15)
    ]

    results = {
        "zero-secrets": PolicyResult(
            policy_name="zero-secrets",
            passed=False,
            violations=violations,
        ),
    }

    # Mock input: exit immediately (5)
    with patch("builtins.input", return_value="5"):
        display_policy_violations_interactive(results)

    captured = capsys.readouterr()
    # Should show "... and 5 more violations"
    assert "... and 5 more violations" in captured.out


def test_display_policy_violations_interactive_invalid_choice(capsys):
    """Test violation viewer with invalid choice input."""
    from scripts.cli.wizard_flows.policy_flow import display_policy_violations_interactive
    from scripts.core.policy_engine import PolicyResult
    from unittest.mock import patch

    results = {
        "zero-secrets": PolicyResult(
            policy_name="zero-secrets",
            passed=False,
            violations=[{"category": "SECRET", "message": "Hardcoded password"}],
        ),
    }

    # Mock input: invalid choice (99), then exit (5)
    with patch("builtins.input", side_effect=["99", "5"]):
        display_policy_violations_interactive(results)

    captured = capsys.readouterr()
    assert "Invalid choice: 99" in captured.out


def test_display_policy_violations_interactive_previous_navigation(capsys):
    """Test violation viewer navigation to previous policy."""
    from scripts.cli.wizard_flows.policy_flow import display_policy_violations_interactive
    from scripts.core.policy_engine import PolicyResult
    from unittest.mock import patch

    results = {
        "policy-1": PolicyResult(
            policy_name="policy-1",
            passed=False,
            violations=[{"category": "ISSUE1", "message": "Problem 1"}],
        ),
        "policy-2": PolicyResult(
            policy_name="policy-2",
            passed=False,
            violations=[{"category": "ISSUE2", "message": "Problem 2"}],
        ),
    }

    # Mock input: next (3), previous (4), exit (5)
    with patch("builtins.input", side_effect=["3", "4", "5"]):
        display_policy_violations_interactive(results)

    captured = capsys.readouterr()
    # Should display both policies during navigation
    assert "policy-1" in captured.out
    assert "policy-2" in captured.out


# ========== NON-INTERACTIVE MODE TESTS ====================


@patch("scripts.cli.wizard_flows.policy_flow.PolicyEngine")
@patch("scripts.cli.wizard_flows.policy_flow.Path.glob")
def test_policy_evaluation_menu_noninteractive_mode(mock_glob, mock_engine_class, tmp_path, sample_findings, capsys):
    """Test non-interactive mode uses profile defaults."""
    from scripts.cli.wizard_flows.policy_flow import policy_evaluation_menu
    from scripts.core.policy_engine import PolicyResult

    # Mock PolicyEngine
    mock_engine = MagicMock()
    mock_engine_class.return_value = mock_engine

    # Mock policy files
    mock_policy_files = [
        Path("policies/builtin/zero-secrets.rego"),
        Path("policies/builtin/owasp-top-10.rego"),
    ]
    mock_glob.return_value = mock_policy_files

    # Mock get_metadata to return dicts (not PolicyMetadata)
    mock_engine.get_metadata.side_effect = [
        {"name": "zero-secrets", "version": "1.0.0", "description": "Block secrets"},
        {"name": "owasp-top-10", "version": "1.0.0", "description": "OWASP Top 10"},
    ]

    # Mock evaluate_policy
    mock_engine.evaluate_policy.return_value = PolicyResult(
        policy_name="test",
        passed=True,
        violations=[],
    )

    # Create findings.json
    findings_dir = tmp_path / "summaries"
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / "findings.json").write_text(json.dumps(sample_findings))

    results = policy_evaluation_menu(tmp_path, "balanced", sample_findings, non_interactive=True)

    # Should evaluate 2 policies (balanced profile defaults)
    assert len(results) == 2
    captured = capsys.readouterr()
    assert "Non-interactive mode" in captured.out


# ========== COVERAGE TARGET: ≥90% ====================
# Run: pytest tests/cli/test_wizard_policy_integration.py -v --cov=scripts.cli.wizard_flows.policy_flow --cov-report=term-missing
