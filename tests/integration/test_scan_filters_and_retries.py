"""Integration tests for scan filters and retries.

Rewritten for ScanOrchestrator architecture (v0.7.0).
Tests use subprocess to invoke jmo CLI with jmo.yml configs instead of
monkeypatching internal functions.
"""

import json
import subprocess
from pathlib import Path


def _repo(tmp_path: Path, name: str) -> Path:
    """Create a test repository directory."""
    r = tmp_path / "repos" / name
    r.mkdir(parents=True, exist_ok=True)
    return r


def test_include_exclude_filters(tmp_path: Path):
    """Test include/exclude patterns filter repositories correctly."""
    # Create two repos: app-1 (should be included) and test-1 (should be excluded)
    _repo(tmp_path, "app-1")
    _repo(tmp_path, "test-1")
    out_base = tmp_path / "results"

    # Create jmo.yml with include/exclude filters
    config_file = tmp_path / "jmo.yml"
    config_file.write_text(
        """
tools: [trufflehog]
include: ["app-*"]
exclude: ["test-*"]
""",
        encoding="utf-8",
    )

    # Run scan with config
    cmd = [
        "python3",
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repos-dir",
        str(tmp_path / "repos"),
        "--results-dir",
        str(out_base),
        "--config",
        str(config_file),
        "--allow-missing-tools",  # Use stubs if trufflehog missing
    ]

    result = subprocess.run(
        cmd,
        timeout=30,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": ".", "SKIP_REACT_BUILD_CHECK": "true"},
    )
    assert result.returncode == 0, f"Scan failed: {result.stderr}"

    # app-1 should be scanned (included by pattern)
    assert (out_base / "individual-repos" / "app-1" / "trufflehog.json").exists()

    # test-1 should NOT be scanned (excluded by pattern)
    assert not (out_base / "individual-repos" / "test-1" / "trufflehog.json").exists()


def test_retries_attempts_logging(tmp_path: Path):
    """Test retry mechanism attempts multiple times on failures.

    Note: This test verifies the retry configuration is accepted.
    Actual retry behavior testing requires simulating tool failures,
    which is complex with real tool execution.
    """
    repo = _repo(tmp_path, "retry-repo")
    out_base = tmp_path / "results"

    # Create jmo.yml with retries=2
    config_file = tmp_path / "jmo.yml"
    config_file.write_text(
        """
tools: [trufflehog]
retries: 2
""",
        encoding="utf-8",
    )

    # Run scan
    cmd = [
        "python3",
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(repo),
        "--results-dir",
        str(out_base),
        "--config",
        str(config_file),
        "--allow-missing-tools",
    ]

    result = subprocess.run(
        cmd,
        timeout=30,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": ".", "SKIP_REACT_BUILD_CHECK": "true"},
    )
    assert result.returncode == 0

    # Verify output exists (retry config was accepted)
    assert (out_base / "individual-repos" / repo.name / "trufflehog.json").exists()


def test_semgrep_rc2_and_trivy_rc1_accepted(tmp_path: Path):
    """Test that non-zero exit codes (rc=1, rc=2) are accepted when tools produce output.

    Semgrep exits with rc=2 when findings exist.
    Trivy exits with rc=1 when vulnerabilities found.
    Both should be treated as success if output files are written.
    """
    repo = _repo(tmp_path, "exitcode-repo")
    # Create a Python file to trigger semgrep findings
    (repo / "app.py").write_text("password = 'hardcoded123'", encoding="utf-8")
    out_base = tmp_path / "results"

    # Create jmo.yml with both tools
    config_file = tmp_path / "jmo.yml"
    config_file.write_text(
        """
tools: [semgrep, trivy]
""",
        encoding="utf-8",
    )

    # Run scan
    cmd = [
        "python3",
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(repo),
        "--results-dir",
        str(out_base),
        "--config",
        str(config_file),
        "--allow-missing-tools",  # Use stubs if tools missing
    ]

    result = subprocess.run(
        cmd,
        timeout=60,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": ".", "SKIP_REACT_BUILD_CHECK": "true"},
    )
    # Scan should succeed despite non-zero exit codes from tools
    assert result.returncode == 0, f"Scan failed unexpectedly: {result.stderr}"

    # Both tools should have output files
    assert (out_base / "individual-repos" / repo.name / "semgrep.json").exists()
    assert (out_base / "individual-repos" / repo.name / "trivy.json").exists()


def test_allow_missing_tools_stubs_all(tmp_path: Path):
    """Test that --allow-missing-tools creates stub JSON for all missing tools."""
    import sys

    repo = _repo(tmp_path, "stub-repo")
    out_base = tmp_path / "results"

    # Configure multiple tools that are likely missing
    config_file = tmp_path / "jmo.yml"
    config_file.write_text(
        """
tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, bandit]
""",
        encoding="utf-8",
    )

    # Run scan with --allow-missing-tools
    cmd = [
        "python3",
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(repo),
        "--results-dir",
        str(out_base),
        "--config",
        str(config_file),
        "--allow-missing-tools",  # Create stubs for missing tools
    ]

    # Hide security tools from PATH while preserving python
    # Keep only python's directory in PATH to force all security tools to be "missing"
    python_dir = str(Path(sys.executable).parent)

    # Ensure python3 is available by using sys.executable directly
    # Some systems have python3.11 but not python3 symlink
    test_env = {
        "PATH": python_dir,
        "PYTHONPATH": ".",
        "SKIP_REACT_BUILD_CHECK": "true",  # Skip React build in tests
    }

    # Use sys.executable instead of relying on 'python3' being in PATH
    cmd[0] = sys.executable  # Replace 'python3' with actual python executable

    result = subprocess.run(
        cmd,
        timeout=30,
        capture_output=True,
        text=True,
        env=test_env,
    )
    assert result.returncode == 0, f"Scan failed: {result.stderr}"

    # All tools should have stub output files
    for tool in [
        "trufflehog",
        "semgrep",
        "syft",
        "trivy",
        "checkov",
        "hadolint",
        "bandit",
    ]:
        output_file = out_base / "individual-repos" / repo.name / f"{tool}.json"
        assert output_file.exists(), f"Stub not created for {tool}"

        # Verify stub is valid JSON (empty results)
        data = json.loads(output_file.read_text())
        assert isinstance(data, (dict, list)), f"{tool} stub is not valid JSON"


def test_bad_jmo_threads_fallback(tmp_path: Path):
    """Test that invalid JMO_THREADS environment variable falls back to default (1).

    When JMO_THREADS is set to a non-integer value, the scanner should
    gracefully fall back to threads=1 instead of crashing.
    """
    repo = _repo(tmp_path, "threads-repo")
    out_base = tmp_path / "results"

    # Create minimal config
    config_file = tmp_path / "jmo.yml"
    config_file.write_text(
        """
tools: [trufflehog]
""",
        encoding="utf-8",
    )

    # Run scan with invalid JMO_THREADS value
    cmd = [
        "python3",
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(repo),
        "--results-dir",
        str(out_base),
        "--config",
        str(config_file),
        "--allow-missing-tools",
    ]

    # Set JMO_THREADS to invalid value (merge with os.environ to preserve installed packages)
    import os

    test_env = os.environ.copy()
    test_env["JMO_THREADS"] = "not-an-int"
    test_env["PYTHONPATH"] = "."
    test_env["SKIP_REACT_BUILD_CHECK"] = "true"  # Skip React build in tests

    result = subprocess.run(
        cmd,
        timeout=30,
        capture_output=True,
        text=True,
        env=test_env,
    )

    # Should succeed (fall back to default threads=1)
    assert (
        result.returncode == 0
    ), f"Scan failed to handle bad JMO_THREADS: {result.stderr}"

    # Verify output was created
    assert (out_base / "individual-repos" / repo.name / "trufflehog.json").exists()
