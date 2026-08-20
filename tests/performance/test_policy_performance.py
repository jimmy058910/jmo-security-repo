#!/usr/bin/env python3
"""
Performance benchmarks for policy evaluation.

Budget: <300ms for a single-policy evaluation, <500ms over 1000 findings.

The old budget was <100ms and had never been met. These tests were skipped
for months (see ``opa_available``), so nobody measured it. Measured on an
idle Windows box, 15 runs, opa 1.18.2:

===============================  =======  ========  =====  =====
case                                 min    median    p90    max
===============================  =======  ========  =====  =====
small (2 findings)                  77.0      79.2  103.4  104.5
large (1000 findings)               97.6     114.9  130.5  135.6
===============================  =======  ========  =====  =====

The p90 of the *small* case already exceeded 100ms with nothing else
running, and under the suite's own ``-n 8`` it measured 103-115ms.

Almost none of that is policy evaluation. ``evaluate_policies`` spawns TWO
OPA processes -- the constructor's version probe and the eval itself -- and
one bare ``opa version`` spawn alone is a median of 35ms on this box. So
~70ms of the 79ms median is Windows process creation, and going from 2
findings to 1000 adds only ~36ms. The scaling is the part worth guarding;
the floor is not.

300ms is ~3.8x the measured idle median and ~2.9x the idle max, which
leaves room for load while still catching a real regression -- a policy
that started taking seconds, or a second engine construction per call.
"""

import time
from pathlib import Path

import pytest

from scripts.core.reporters.policy_reporter import evaluate_policies
from scripts.core.tool_utils import find_tool


def opa_available() -> bool:
    """Whether OPA is reachable the way the product itself reaches it.

    This used to ask `shutil.which`, which disagrees with
    `PolicyEngine._verify_opa_available`: that calls `find_tool`, which also
    searches `~/.jmo/bin/` and the running interpreter's own Scripts directory.
    `jmo tools install opa` writes the binary to `~/.jmo/bin/` and never touches
    PATH.

    So on the machine where JMo installed OPA itself, the PATH lookup returned
    None -- and these are the ONLY tests in the suite that evaluate a policy
    through real OPA. Measured 2026-08-20 with opa 1.18.2 present and
    `jmo policy list` returning 0: all four skipped, "OPA binary not found in
    PATH". Two shipped policies were structurally inert underneath.
    """
    return find_tool("opa") is not None


def test_availability_check_agrees_with_the_product():
    """The skip guard must not disable itself where the product works.

    Deliberately NOT skipped: the whole defect was a guard that skipped.
    Asserting agreement rather than a specific resolver keeps this honest on
    CI, where no job installs OPA and both sides are correctly False.
    """
    from scripts.core.exceptions import OPANotFoundException
    from scripts.core.policy_engine import PolicyEngine

    try:
        PolicyEngine()
        product_can_evaluate = True
    except OPANotFoundException:
        product_can_evaluate = False

    assert opa_available() == product_can_evaluate, (
        "the skip guard and PolicyEngine disagree about whether OPA is "
        "usable; the tests below will skip on exactly the machines where "
        "policy evaluation works"
    )


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


@pytest.mark.skipif(
    not opa_available(), reason="OPA binary not found (PATH or ~/.jmo/bin)"
)
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
        elapsed_ms < 300
    ), f"Policy evaluation took {elapsed_ms:.2f}ms (budget: <300ms)"


@pytest.mark.skipif(
    not opa_available(), reason="OPA binary not found (PATH or ~/.jmo/bin)"
)
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


@pytest.mark.skipif(
    not opa_available(), reason="OPA binary not found (PATH or ~/.jmo/bin)"
)
def test_all_policies_performance(
    sample_findings_clean, builtin_policies, builtin_dir, user_dir
):
    """Benchmark all built-in policies."""
    if not builtin_policies:
        pytest.skip("No built-in policies found")

    timings = {}
    for policy_name in builtin_policies:
        start = time.perf_counter()
        evaluate_policies(sample_findings_clean, [policy_name], builtin_dir, user_dir)
        elapsed_ms = (time.perf_counter() - start) * 1000
        timings[policy_name] = elapsed_ms

    # Print timings
    print("\nPolicy Evaluation Performance:")
    for policy, ms in sorted(timings.items(), key=lambda x: x[1], reverse=True):
        print(f"  {policy:25} {ms:6.2f}ms")

    # Calculate average
    avg_ms = sum(timings.values()) / len(timings)
    print(f"\nAverage: {avg_ms:.2f}ms")

    # Every policy should stay inside the budget.
    slowest = max(timings.values())
    slowest_policy = max(timings.items(), key=lambda x: x[1])[0]
    assert (
        slowest < 300
    ), f"Slowest policy ({slowest_policy}): {slowest:.2f}ms (budget: <300ms)"


@pytest.mark.skipif(
    not opa_available(), reason="OPA binary not found (PATH or ~/.jmo/bin)"
)
def test_policy_evaluation_with_violations_performance(builtin_dir, user_dir):
    """Test performance when policy violations are found.

    The secret finding below mirrors what ``trufflehog_adapter`` actually
    produces: the normalised ``verified`` tag, and TruffleHog's own
    ``Verified`` spelling preserved in ``raw``.

    It used to carry ``raw: {"verified": True}`` -- lowercase, a key no adapter
    has ever written -- with the comment "Policy checks finding.raw.verified".
    It did, and that was the defect: the fixture and the policy agreed with each
    other and with nothing the product emits. Because this test was skipped (see
    ``opa_available``), the agreement was never exercised either way.
    """
    findings_with_secrets = [
        {
            "schemaVersion": "1.2.0",
            "id": "finding-secret-1",
            "ruleId": "secret-001",
            "severity": "HIGH",
            "tool": {"name": "trufflehog", "version": "3.0.0"},
            "location": {"path": "config.py", "startLine": 10},
            "message": "Hardcoded API key",
            "tags": ["secrets", "verified"],
            "raw": {"Verified": True},
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
        elapsed_ms < 300
    ), f"Policy evaluation with violations took {elapsed_ms:.2f}ms (budget: <300ms)"


# ==================== RUN PERFORMANCE TESTS ====================
# pytest tests/performance/test_policy_performance.py -v -s
