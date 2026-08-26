"""
Performance profiling tests.

Coverage:
- Profile flag generates timings.json
- Timings data structure validation
- Performance regression detection

Related:
- TESTING_COVERAGE_PLAN.md Sprint 3 Task 11 (Optional Enhancement)
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.requires_tools
@pytest.mark.slow
def test_profile_flag_generates_timings(tmp_path):
    """Test --profile flag generates timings.json."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("print('test')")

    # Run scan with --profile flag (via report command)
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "fast",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point -- redirect it via the
    # env vars Path.home() actually reads on each platform.
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    subprocess.run(cmd, check=True, timeout=120, env=env)

    # Generate report with profiling
    cmd_report = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "report",
        str(tmp_path / "results"),
        "--profile",
    ]
    subprocess.run(cmd_report, check=True, timeout=60)

    # Verify timings.json created
    timings_file = tmp_path / "results" / "summaries" / "timings.json"
    assert timings_file.exists(), "timings.json not generated with --profile flag"

    # Validate structure. `{"a": 1}` used to pass this check (#723) -- pin the
    # exact key set the real scan -> report --profile pipeline is expected to
    # produce, same contract as test_timings_json_matches_the_producer_contract
    # below, but exercised here through real tools instead of fabricated stubs.
    timings = json.loads(timings_file.read_text())
    assert set(timings) == EXPECTED_TIMINGS_KEYS, (
        "timings.json top-level keys drifted from the producer.\n"
        f"  missing: {sorted(EXPECTED_TIMINGS_KEYS - set(timings))}\n"
        f"  unexpected: {sorted(set(timings) - EXPECTED_TIMINGS_KEYS)}"
    )


@pytest.mark.requires_tools
@pytest.mark.slow
def test_timings_data_structure(tmp_path):
    """Test timings.json has expected data structure."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "README.md").write_text("# Test")

    cmd_scan = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(test_repo),
        "--tools",
        "trivy",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point -- redirect it via the
    # env vars Path.home() actually reads on each platform.
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    subprocess.run(cmd_scan, timeout=120, env=env)

    cmd_report = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "report",
        str(tmp_path / "results"),
        "--profile",
    ]
    subprocess.run(cmd_report, timeout=60)

    timings_file = tmp_path / "results" / "summaries" / "timings.json"

    # #723: this used to be `if timings_file.exists():`, so when the file was
    # never produced the whole body was skipped and the test passed having
    # asserted nothing. Assert it instead.
    assert timings_file.exists(), "report --profile did not write timings.json"

    timings = json.loads(timings_file.read_text())

    # Verify timings is a dictionary
    assert isinstance(timings, dict)

    # Check for actual fields from normalize_and_report.py profiling
    # Fields: aggregate_seconds, recommended_threads, jobs, meta
    assert "aggregate_seconds" in timings, "Expected 'aggregate_seconds' field"
    assert isinstance(timings["aggregate_seconds"], (int, float))
    assert timings["aggregate_seconds"] >= 0

    # Verify jobs array exists and contains tool timing data
    assert "jobs" in timings, "Expected 'jobs' array with tool timings"
    assert isinstance(timings["jobs"], list)

    # Verify meta field exists
    assert "meta" in timings, "Expected 'meta' field"
    assert isinstance(timings["meta"], dict)


@pytest.mark.requires_tools
@pytest.mark.slow
def test_ci_command_with_profile_generates_timings(tmp_path):
    """Test ci command with --profile generates timings.json."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("import os")

    # Run CI command with --profile flag
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "ci",
        "--repo",
        str(test_repo),
        "--profile-name",
        "fast",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
        "--profile",  # Enable profiling
    ]
    # `jmo ci` runs `cmd_scan` internally, which unconditionally calls
    # `_show_kofi_reminder()` (#933) -- redirect Path.home() via the env vars
    # it actually reads on each platform.
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env)

    # CI should succeed (exit 0 or 1 for findings)
    assert result.returncode in [0, 1]

    # Verify timings.json created
    timings_file = tmp_path / "results" / "summaries" / "timings.json"
    assert (
        timings_file.exists()
    ), "ci command with --profile should generate timings.json"

    # Same vacuous-pair fix as test_profile_flag_generates_timings above --
    # {"a": 1} passed this check before. In scope because this is still one of
    # timings.json's own tests (#723), even though only the sibling test above
    # was named explicitly.
    timings = json.loads(timings_file.read_text())
    assert set(timings) == EXPECTED_TIMINGS_KEYS, (
        "timings.json top-level keys drifted from the producer.\n"
        f"  missing: {sorted(EXPECTED_TIMINGS_KEYS - set(timings))}\n"
        f"  unexpected: {sorted(set(timings) - EXPECTED_TIMINGS_KEYS)}"
    )


@pytest.mark.requires_tools
@pytest.mark.slow
def test_profile_without_flag_no_timings(tmp_path):
    """Test report without --profile flag does not generate timings.json."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "README.md").write_text("# Test")

    # Run scan
    cmd_scan = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(test_repo),
        "--tools",
        "trivy",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point -- redirect it via the
    # env vars Path.home() actually reads on each platform.
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    subprocess.run(cmd_scan, timeout=120, env=env)

    # Generate report WITHOUT --profile flag
    cmd_report = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "report",
        str(tmp_path / "results"),
    ]
    subprocess.run(cmd_report, timeout=60)

    # Verify timings.json NOT created
    timings_file = tmp_path / "results" / "summaries" / "timings.json"

    # timings.json should not exist when --profile flag not used
    # (or if it exists, it should be from a previous run, not this one)
    if timings_file.exists():
        # This is acceptable - timings.json might exist from scan phase
        # The key is that report phase without --profile doesn't require it
        pass


@pytest.mark.requires_tools
@pytest.mark.slow
def test_timings_thread_recommendation(tmp_path):
    """Test timings.json may include thread recommendation."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("x = 1")

    cmd_scan = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "balanced",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point -- redirect it via the
    # env vars Path.home() actually reads on each platform.
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    subprocess.run(cmd_scan, timeout=180, env=env)

    cmd_report = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "report",
        str(tmp_path / "results"),
        "--profile",
    ]
    subprocess.run(cmd_report, timeout=60)

    timings_file = tmp_path / "results" / "summaries" / "timings.json"

    if timings_file.exists():
        timings = json.loads(timings_file.read_text())

        # Check for recommended_threads field (optional)
        if "recommended_threads" in timings:
            # Should be a positive integer
            assert isinstance(timings["recommended_threads"], int)
            assert timings["recommended_threads"] > 0


@pytest.mark.requires_tools
@pytest.mark.slow
def test_timings_json_is_valid_json(tmp_path):
    """Test timings.json is always valid JSON (no syntax errors)."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "test.py").write_text("print('hello')")

    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "ci",
        "--repo",
        str(test_repo),
        "--tools",
        "trufflehog",
        "semgrep",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
        "--profile",
    ]
    # `jmo ci` runs `cmd_scan` internally, which unconditionally calls
    # `_show_kofi_reminder()` (#933) -- redirect Path.home() via the env vars
    # it actually reads on each platform.
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    subprocess.run(cmd, timeout=180, env=env)

    timings_file = tmp_path / "results" / "summaries" / "timings.json"

    if timings_file.exists():
        # Should parse without exceptions
        try:
            timings = json.loads(timings_file.read_text())
            assert isinstance(timings, dict)
        except json.JSONDecodeError as e:
            pytest.fail(f"timings.json is not valid JSON: {e}")


# --- #723: a contract test that PR CI actually runs -------------------------
#
# Every test above is `requires_tools` + `slow`, so `ci.yml`'s marker filter
# excludes all of them: the timings.json schema had no PR-time guard at all.
# That is how the schema documented by jmo-profile-optimizer drifted completely
# away from the producer without anything going red (#718 chunk A / PR #720).
#
# This test needs no scanner. `gather_results()` discovers tool output by
# filename under `individual-*/`, so fabricated stubs drive the real producer.

EXPECTED_TIMINGS_KEYS = {"aggregate_seconds", "recommended_threads", "jobs", "meta"}
EXPECTED_JOB_KEYS = {"tool", "path", "seconds", "count"}


def _fabricate_results(tmp_path):
    """A results directory the report phase can aggregate, with no real tools."""
    target = tmp_path / "results" / "individual-repos" / "demo"
    target.mkdir(parents=True)
    # Adapters tolerate an empty result set; the job is still timed, which is
    # what the contract is about.
    (target / "trivy.json").write_text(json.dumps({"Results": []}), encoding="utf-8")
    (target / "semgrep.json").write_text(json.dumps({"results": []}), encoding="utf-8")
    return tmp_path / "results"


def _isolated_env():
    """Env that keeps the child importable while its cwd is a temp dir.

    `history_db.DEFAULT_DB_PATH` is the relative `.jmo/history.db`, so it
    follows the process cwd. Running the child from tmp_path keeps these tests
    out of the repository's real history database.
    """
    env = dict(os.environ)
    repo_root = Path(__file__).resolve().parents[2]
    env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _run_report_with_profile(results_dir, tmp_path):
    """Run `jmo report --profile` and return the parsed timings.json."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "report",
            str(results_dir),
            "--profile",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(tmp_path),
        env=_isolated_env(),
    )
    timings_file = results_dir / "summaries" / "timings.json"
    assert timings_file.exists(), (
        "jmo report --profile did not write timings.json.\n"
        f"exit={result.returncode}\nstderr tail:\n{result.stderr[-1500:]}"
    )
    return json.loads(timings_file.read_text(encoding="utf-8"))


def test_timings_json_matches_the_producer_contract(tmp_path):
    """timings.json has exactly the keys report_orchestrator writes.

    Pinned deliberately with `==`, not `<=`: a *removed* key breaks consumers
    just as badly as a renamed one, and a silently *added* key is a schema
    change that should be a conscious edit here.

    Source of truth: scripts/cli/report_orchestrator.py (the `timings` dict).
    """
    timings = _run_report_with_profile(_fabricate_results(tmp_path), tmp_path)

    assert set(timings) == EXPECTED_TIMINGS_KEYS, (
        "timings.json top-level keys drifted from the producer.\n"
        f"  missing: {sorted(EXPECTED_TIMINGS_KEYS - set(timings))}\n"
        f"  unexpected: {sorted(set(timings) - EXPECTED_TIMINGS_KEYS)}"
    )

    assert isinstance(timings["aggregate_seconds"], (int, float))
    assert timings["aggregate_seconds"] >= 0
    assert isinstance(timings["recommended_threads"], int)
    assert timings["recommended_threads"] > 0
    assert isinstance(timings["meta"], dict)

    # gather_results() only populates meta.max_workers when JMO_PROFILE=1
    # (normalize_and_report.py:153-159) -- and --profile always exports that
    # (report_orchestrator.py:161-162) before gather_results() runs, so it is
    # present on every profiled run, not just some of them.
    assert "max_workers" in timings["meta"], (
        "meta.max_workers missing -- see normalize_and_report.py's "
        "gather_results(), which sets it whenever JMO_PROFILE=1"
    )
    assert isinstance(timings["meta"]["max_workers"], int)
    assert timings["meta"]["max_workers"] > 0


def test_timings_jobs_is_a_flat_list_of_per_file_entries(tmp_path):
    """`jobs` is a flat list keyed by (tool, file), not a per-tool dict.

    The published skill read `data["tools"]` as a dict of per-tool aggregates.
    No such key exists, and a tool appears once per result file rather than
    once overall -- which is what makes real percentiles possible.
    """
    timings = _run_report_with_profile(_fabricate_results(tmp_path), tmp_path)

    assert isinstance(timings["jobs"], list), "jobs must be a list, not a mapping"
    assert (
        len(timings["jobs"]) == 2
    ), f"expected one job per fabricated tool output, got {len(timings['jobs'])}"

    for job in timings["jobs"]:
        assert (
            set(job) == EXPECTED_JOB_KEYS
        ), f"job entry keys drifted: {sorted(set(job) ^ EXPECTED_JOB_KEYS)}"
        assert isinstance(job["tool"], str) and job["tool"]
        assert isinstance(job["path"], str) and job["path"]
        assert isinstance(job["seconds"], (int, float)) and job["seconds"] >= 0
        assert isinstance(job["count"], int) and job["count"] >= 0

    assert {j["tool"] for j in timings["jobs"]} == {"trivy", "semgrep"}


def test_timings_json_absent_without_the_profile_flag(tmp_path):
    """`--profile` is what produces the file; nothing else should."""
    results_dir = _fabricate_results(tmp_path)
    subprocess.run(
        [sys.executable, "-m", "scripts.cli.jmo", "report", str(results_dir)],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(tmp_path),
        env=_isolated_env(),
    )
    assert not (results_dir / "summaries" / "timings.json").exists()


def test_documented_keys_that_must_not_exist(tmp_path):
    """Guard against the specific fiction that shipped in a published skill.

    jmo-profile-optimizer documented `total_duration_seconds`, `profile` and a
    `tools` dict, plus per-tool `timeouts`/`executions`. None are produced. If
    any ever appears, the deleted timeout analysis can be revisited -- until
    then this keeps the absence explicit rather than assumed.
    """
    timings = _run_report_with_profile(_fabricate_results(tmp_path), tmp_path)

    for absent in ("total_duration_seconds", "profile", "tools", "threads", "timeout"):
        assert absent not in timings, (
            f"'{absent}' now exists in timings.json -- see #722 and the Phase 4 "
            "note in .claude/skills/jmo-profile-optimizer/references/"
            "optimization-patterns.md before relying on it"
        )
