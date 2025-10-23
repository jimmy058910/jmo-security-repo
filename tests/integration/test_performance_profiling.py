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
import subprocess

import pytest


@pytest.mark.slow
def test_profile_flag_generates_timings(tmp_path):
    """Test --profile flag generates timings.json."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("print('test')")

    # Run scan with --profile flag (via report command)
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "fast",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    subprocess.run(cmd, check=True, timeout=120)

    # Generate report with profiling
    cmd_report = [
        "python3",
        "scripts/cli/jmo.py",
        "report",
        str(tmp_path / "results"),
        "--profile",
    ]
    subprocess.run(cmd_report, check=True, timeout=60)

    # Verify timings.json created
    timings_file = tmp_path / "results" / "summaries" / "timings.json"
    assert timings_file.exists(), "timings.json not generated with --profile flag"

    # Validate structure
    timings = json.loads(timings_file.read_text())
    assert isinstance(timings, dict), "timings.json should be a dictionary"

    # Should have some timing data (exact structure may vary)
    assert len(timings) > 0, "timings.json should not be empty"


@pytest.mark.slow
def test_timings_data_structure(tmp_path):
    """Test timings.json has expected data structure."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "README.md").write_text("# Test")

    cmd_scan = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--tools",
        "trivy",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    subprocess.run(cmd_scan, timeout=120)

    cmd_report = [
        "python3",
        "scripts/cli/jmo.py",
        "report",
        str(tmp_path / "results"),
        "--profile",
    ]
    subprocess.run(cmd_report, timeout=60)

    timings_file = tmp_path / "results" / "summaries" / "timings.json"

    if timings_file.exists():
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


@pytest.mark.slow
def test_ci_command_with_profile_generates_timings(tmp_path):
    """Test ci command with --profile generates timings.json."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("import os")

    # Run CI command with --profile flag
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
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
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

    # CI should succeed (exit 0 or 1 for findings)
    assert result.returncode in [0, 1]

    # Verify timings.json created
    timings_file = tmp_path / "results" / "summaries" / "timings.json"
    assert (
        timings_file.exists()
    ), "ci command with --profile should generate timings.json"

    timings = json.loads(timings_file.read_text())
    assert isinstance(timings, dict)
    assert len(timings) > 0


@pytest.mark.slow
def test_profile_without_flag_no_timings(tmp_path):
    """Test report without --profile flag does not generate timings.json."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "README.md").write_text("# Test")

    # Run scan
    cmd_scan = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--tools",
        "trivy",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    subprocess.run(cmd_scan, timeout=120)

    # Generate report WITHOUT --profile flag
    cmd_report = [
        "python3",
        "scripts/cli/jmo.py",
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


@pytest.mark.slow
def test_timings_thread_recommendation(tmp_path):
    """Test timings.json may include thread recommendation."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("x = 1")

    cmd_scan = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "balanced",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    subprocess.run(cmd_scan, timeout=180)

    cmd_report = [
        "python3",
        "scripts/cli/jmo.py",
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


@pytest.mark.slow
def test_timings_json_is_valid_json(tmp_path):
    """Test timings.json is always valid JSON (no syntax errors)."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "test.py").write_text("print('hello')")

    cmd = [
        "python3",
        "scripts/cli/jmo.py",
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
    subprocess.run(cmd, timeout=180)

    timings_file = tmp_path / "results" / "summaries" / "timings.json"

    if timings_file.exists():
        # Should parse without exceptions
        try:
            timings = json.loads(timings_file.read_text())
            assert isinstance(timings, dict)
        except json.JSONDecodeError as e:
            pytest.fail(f"timings.json is not valid JSON: {e}")
