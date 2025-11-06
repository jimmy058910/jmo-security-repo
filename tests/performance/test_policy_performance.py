#!/usr/bin/env python3
"""
Performance benchmarks for policy evaluation.

Target: <100ms per policy evaluation
"""

import json
import shutil
import time
from pathlib import Path

import pytest

from scripts.core.reporters.policy_reporter import evaluate_policies


def opa_available() -> bool:
    """Check if OPA binary is available in PATH."""
    return shutil.which("opa") is not None


@pytest.fixture
def builtin_dir():
    """Path to built-in policies directory."""
    return Path(__file__).parent.parent.parent / "policies" / "builtin"


@pytest.fixture
def user_dir():
    """Path to user policies directory."""
    return Path.home() / ".jmo" / "policies"


@pytest.fixture
def builtin_policies(builtin_dir):
    """List all built-in policy names (stems only)."""
    return [p.stem for p in builtin_dir.glob("*.rego")]


@pytest.fixture
def sample_findings_clean():
    """Small finding set with no policy violations."""
    return [
        {
            "schemaVersion": "1.2.0",
            "id": "finding-1",
            "ruleId": "info-001",
            "severity": "INFO",
            "tool": {"name": "semgrep", "version": "1.0.0"},
            "location": {"path": "test.py", "startLine": 1},
            "message": "Code smell",
        },
        {
            "schemaVersion": "1.2.0",
            "id": "finding-2",
            "ruleId": "low-002",
            "severity": "LOW",
            "tool": {"name": "bandit", "version": "1.0.0"},
            "location": {"path": "app.py", "startLine": 10},
            "message": "Minor issue",
        },
    ]


@pytest.fixture
def sample_findings_large_set():
    """Large finding set with 1000 findings (mix of severities)."""
    findings = []
    for i in range(1000):
        severity = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 5]
        findings.append(
            {
                "schemaVersion": "1.2.0",
                "id": f"finding-{i}",
                "ruleId": f"rule-{i % 50}",
                "severity": severity,
                "tool": {"name": "semgrep", "version": "1.0.0"},
                "location": {"path": f"file{i % 100}.py", "startLine": i % 500 + 1},
                "message": f"Test finding {i}",
            }
        )
    return findings


@pytest.mark.skipif(not opa_available(), reason="OPA binary not found in PATH")
def test_policy_evaluation_performance_small(
    sample_findings_clean, builtin_dir, user_dir
):
    """Test policy evaluation with small finding set (<100ms target)."""
    policy_name = "zero-secrets"

    start = time.perf_counter()
    results = evaluate_policies(
        sample_findings_clean, [policy_name], builtin_dir, user_dir
    )
    elapsed_ms = (time.perf_counter() - start) * 1000

    # Should have evaluated the policy
    assert policy_name in results
    assert results[policy_name].policy_name == policy_name

    # Performance check
    assert (
        elapsed_ms < 100
    ), f"Policy evaluation took {elapsed_ms:.2f}ms (target: <100ms)"


@pytest.mark.skipif(not opa_available(), reason="OPA binary not found in PATH")
def test_policy_evaluation_performance_large(
    sample_findings_large_set, builtin_dir, user_dir
):
    """Test policy evaluation with large finding set (1000 findings)."""
    policy_name = "owasp-top-10"

    start = time.perf_counter()
    results = evaluate_policies(
        sample_findings_large_set, [policy_name], builtin_dir, user_dir
    )
    elapsed_ms = (time.perf_counter() - start) * 1000

    # Should have evaluated the policy
    assert policy_name in results
    assert results[policy_name].policy_name == policy_name

    # Performance check - allow slightly more time for large sets
    assert (
        elapsed_ms < 500
    ), f"Policy evaluation (1000 findings) took {elapsed_ms:.2f}ms (target: <500ms)"


@pytest.mark.skipif(not opa_available(), reason="OPA binary not found in PATH")
def test_all_policies_performance(
    sample_findings_clean, builtin_policies, builtin_dir, user_dir
):
    """Benchmark all built-in policies."""
    if not builtin_policies:
        pytest.skip("No built-in policies found")

    timings = {}
    for policy_name in builtin_policies:
        start = time.perf_counter()
        results = evaluate_policies(
            sample_findings_clean, [policy_name], builtin_dir, user_dir
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        timings[policy_name] = elapsed_ms

    # Print timings
    print("\nPolicy Evaluation Performance:")
    for policy, ms in sorted(timings.items(), key=lambda x: x[1], reverse=True):
        print(f"  {policy:25} {ms:6.2f}ms")

    # Calculate average
    avg_ms = sum(timings.values()) / len(timings)
    print(f"\nAverage: {avg_ms:.2f}ms")

    # All policies should be under 100ms
    slowest = max(timings.values())
    slowest_policy = max(timings.items(), key=lambda x: x[1])[0]
    assert (
        slowest < 100
    ), f"Slowest policy ({slowest_policy}): {slowest:.2f}ms (target: <100ms)"


@pytest.mark.skipif(not opa_available(), reason="OPA binary not found in PATH")
def test_policy_evaluation_with_violations_performance(builtin_dir, user_dir):
    """Test performance when policy violations are found."""
    findings_with_secrets = [
        {
            "schemaVersion": "1.2.0",
            "id": "finding-secret-1",
            "ruleId": "secret-001",
            "severity": "HIGH",
            "tool": {"name": "trufflehog", "version": "3.0.0"},
            "location": {"path": "config.py", "startLine": 10},
            "message": "Hardcoded API key",
            "raw": {"verified": True},  # Policy checks finding.raw.verified
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
    ]

    policy_name = "zero-secrets"

    start = time.perf_counter()
    results = evaluate_policies(
        findings_with_secrets, [policy_name], builtin_dir, user_dir
    )
    elapsed_ms = (time.perf_counter() - start) * 1000

    # Should have found violations
    assert policy_name in results
    assert not results[policy_name].passed
    assert len(results[policy_name].violations) > 0

    # Performance check
    assert (
        elapsed_ms < 100
    ), f"Policy evaluation with violations took {elapsed_ms:.2f}ms (target: <100ms)"


# ==================== RUN PERFORMANCE TESTS ====================
# pytest tests/performance/test_policy_performance.py -v -s
