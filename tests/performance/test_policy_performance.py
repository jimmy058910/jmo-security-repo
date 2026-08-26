#!/usr/bin/env python3
"""
Performance benchmarks for policy evaluation.

Budget: <500ms median-of-3 for a single-policy, 2-finding evaluation;
<600ms median-of-3 for a 1000-finding evaluation. #973.

The old budget was <100ms and had never been met (this file's tests were
skipped for months -- see ``opa_available``). A first revision measured a
single sample per test and set 300/500ms; #973 caught that flaking too:
1608.75ms on the large case (3.2x over). Re-measured on this box (6 trials
each, opa 1.18.2, ``scripts/core/policy_engine.py``):

idle (nothing else running):

===============================  =======  ========  =====  =====
case                                 min    median    p90    max
===============================  =======  ========  =====  =====
bare `opa version` spawn            31.9      34.5   60.0   60.0
PolicyEngine() ctor                 36.5      38.3   42.2   42.2
small (2 findings)                  76.9      79.3   97.5   97.5
large (1000 findings)              103.8     108.9  115.3  115.3
===============================  =======  ========  =====  =====

same measurement with a self-generated ``pytest tests/unit -n 8`` running
concurrently as a background load:

===============================  =======  ========  =====  =====
case                                 min    median    p90    max
===============================  =======  ========  =====  =====
bare `opa version` spawn            40.2      44.4   57.4   57.4
PolicyEngine() ctor                 43.3      50.4   64.9   64.9
small (2 findings)                  87.7      96.1  112.0  112.0
large (1000 findings)              110.5     127.4  147.0  147.0
===============================  =======  ========  =====  =====

Both regimes agree with the original diagnosis: ``evaluate_policies``
spawns TWO OPA processes per call (the constructor's version probe, then
the eval itself), a bare ``opa version`` spawn alone is a ~35-44ms median,
and going from 2 findings to 1000 adds tens of ms, not hundreds. Neither
run reproduced the 1.5s-class stall #973 measured under a full local suite
half -- that needed heavier contention than one extra ``-n 8`` directory
generates.

That stall is why the budget is a MEDIAN of 3 trials, not a single sample,
and why it is an absolute cap per call rather than a large-minus-small
difference. #973's two observed flakes were 1575ms (on the *small* test)
and 1608ms (on the *large* test), in different runs -- close to EACH
OTHER, not to either budget. That is the signature of a stall on ONE
subprocess spawn landing wherever it happens to be unlucky (OS process
creation / AV-scan queueing under 8-way contention), not a cost that
scales with input size -- so it is not cancelled by differencing a small
call against a large one; the two calls' spawns are independent events,
and either one alone can eat the tax. A median of 3 independent trials
defends against it instead: a lone stalled trial cannot move the median
without a second, independent trial ALSO stalling, which is a much rarer
joint event. ``test_all_policies_performance`` loops over 5 builtin
policies -- 5x the single-spawn exposure of the others -- so each policy's
number is defended by its own median-of-3 before the slowest is taken.

500ms is ~6.3x the idle median and ~5.2x the loaded median for the
small-shaped calls (small / all_policies / with_violations -- all the same
2-finding shape). 600ms for the large call is ~5.5x its idle median and
~4.7x its loaded median. Every test below logs its observed samples on
every run (visible with ``-v -s``, or always on failure) so drift is
visible before it hits the cap.
"""

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from scripts.core.reporters.policy_reporter import evaluate_policies
from scripts.core.tool_utils import find_tool


def _median_call(
    fn: Callable[..., Any], *args: Any, trials: int = 3, **kwargs: Any
) -> tuple[float, list[float], Any]:
    """Call ``fn(*args, **kwargs)`` ``trials`` times; return the median.

    Returns ``(median_ms, sorted_samples_ms, last_result)``. See the module
    docstring for why the median of independent trials, not a single
    sample, is what defends these tests against a one-off subprocess-spawn
    stall.
    """
    samples_ms = []
    result = None
    for _ in range(trials):
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        samples_ms.append((time.perf_counter() - start) * 1000)
    samples_ms.sort()
    return samples_ms[len(samples_ms) // 2], samples_ms, result


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
    """Test policy evaluation with small finding set.

    See the module docstring for the measured idle/loaded medians (79.3ms /
    96.1ms) and why 500ms median-of-3 is the budget.
    """
    policy_name = "zero-secrets"

    median_ms, samples_ms, results = _median_call(
        evaluate_policies, sample_findings_clean, [policy_name], builtin_dir, user_dir
    )
    print(
        f"\n[perf] small: median={median_ms:.2f}ms "
        f"samples={[f'{s:.1f}' for s in samples_ms]}"
    )

    # Should have evaluated the policy
    assert policy_name in results
    assert results[policy_name].policy_name == policy_name

    # Performance check
    assert median_ms < 500, (
        f"Policy evaluation median took {median_ms:.2f}ms over 3 trials "
        f"{samples_ms} (budget: <500ms median)"
    )


@pytest.mark.skipif(
    not opa_available(), reason="OPA binary not found (PATH or ~/.jmo/bin)"
)
def test_policy_evaluation_performance_large(
    sample_findings_large_set, builtin_dir, user_dir
):
    """Test policy evaluation with large finding set (1000 findings).

    See the module docstring for the measured idle/loaded medians (108.9ms
    / 127.4ms) and why 600ms median-of-3 is the budget.
    """
    policy_name = "owasp-top-10"

    median_ms, samples_ms, results = _median_call(
        evaluate_policies,
        sample_findings_large_set,
        [policy_name],
        builtin_dir,
        user_dir,
    )
    print(
        f"\n[perf] large: median={median_ms:.2f}ms "
        f"samples={[f'{s:.1f}' for s in samples_ms]}"
    )

    # Should have evaluated the policy
    assert policy_name in results
    assert results[policy_name].policy_name == policy_name

    # Performance check - allow slightly more time for large sets
    assert median_ms < 600, (
        f"Policy evaluation (1000 findings) median took {median_ms:.2f}ms "
        f"over 3 trials {samples_ms} (budget: <600ms median)"
    )


@pytest.mark.skipif(
    not opa_available(), reason="OPA binary not found (PATH or ~/.jmo/bin)"
)
def test_all_policies_performance(
    sample_findings_clean, builtin_policies, builtin_dir, user_dir
):
    """Benchmark all built-in policies.

    Each policy's cost is the median of 3 trials (see ``_median_call`` and
    the module docstring) -- looping over every builtin policy multiplies
    the single-spawn stall exposure by the policy count, so each one is
    defended independently before the slowest is taken.
    """
    if not builtin_policies:
        pytest.skip("No built-in policies found")

    timings = {}
    all_samples = {}
    for policy_name in builtin_policies:
        median_ms, samples_ms, _ = _median_call(
            evaluate_policies,
            sample_findings_clean,
            [policy_name],
            builtin_dir,
            user_dir,
        )
        timings[policy_name] = median_ms
        all_samples[policy_name] = samples_ms

    # Print timings
    print("\nPolicy Evaluation Performance (median of 3 trials):")
    for policy, ms in sorted(timings.items(), key=lambda x: x[1], reverse=True):
        samples_str = [f"{s:.1f}" for s in all_samples[policy]]
        print(f"  {policy:25} {ms:6.2f}ms  samples={samples_str}")

    # Calculate average
    avg_ms = sum(timings.values()) / len(timings)
    print(f"\nAverage: {avg_ms:.2f}ms")

    # Every policy should stay inside the budget. Same 500ms budget and
    # rationale as test_policy_evaluation_performance_small: same shape,
    # a 2-finding set evaluated against a single policy.
    slowest = max(timings.values())
    slowest_policy = max(timings.items(), key=lambda x: x[1])[0]
    assert slowest < 500, (
        f"Slowest policy ({slowest_policy}): {slowest:.2f}ms median "
        f"(budget: <500ms median)"
    )


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

    median_ms, samples_ms, results = _median_call(
        evaluate_policies, findings_with_secrets, [policy_name], builtin_dir, user_dir
    )
    print(
        f"\n[perf] violations: median={median_ms:.2f}ms "
        f"samples={[f'{s:.1f}' for s in samples_ms]}"
    )

    # Should have found violations
    assert policy_name in results
    assert not results[policy_name].passed
    assert len(results[policy_name].violations) > 0

    # Performance check. Same 500ms budget and rationale as
    # test_policy_evaluation_performance_small: same shape, a 2-finding set.
    assert median_ms < 500, (
        f"Policy evaluation with violations median took {median_ms:.2f}ms "
        f"over 3 trials {samples_ms} (budget: <500ms median)"
    )


# ==================== RUN PERFORMANCE TESTS ====================
# pytest tests/performance/test_policy_performance.py -v -s
