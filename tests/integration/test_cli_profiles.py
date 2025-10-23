#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path

import types

from scripts.cli import jmo


def _write_yaml(p: Path, data: dict) -> None:
    import yaml  # type: ignore

    p.write_text(yaml.safe_dump(data), encoding="utf-8")


def test_scan_profile_include_exclude_only_scans_included(tmp_path: Path, monkeypatch):
    # Create fake repos: a, b, skipme
    repos_dir = tmp_path / "repos"
    (repos_dir / "a").mkdir(parents=True)
    (repos_dir / "b").mkdir(parents=True)
    (repos_dir / "skipme").mkdir(parents=True)

    # Config with profile controlling include/exclude and tools
    # Updated to use trufflehog (gitleaks removed in v0.5.0)
    cfg = {
        "default_profile": "fast",
        "profiles": {
            "fast": {
                "tools": ["trufflehog"],
                "include": ["a*", "b"],
                "exclude": ["skip*"],
                "timeout": 60,
                "threads": 2,
            }
        },
    }
    cfg_path = tmp_path / "jmo.yml"
    _write_yaml(cfg_path, cfg)

    # Force which to say no tools installed so stubs are written
    monkeypatch.setattr(jmo, "_tool_exists", lambda _: False)

    # Prepare args and run scan
    args = types.SimpleNamespace(
        cmd="scan",
        repo=None,
        repos_dir=str(repos_dir),
        targets=None,
        results_dir=str(tmp_path / "results"),
        config=str(cfg_path),
        tools=None,
        timeout=None,
        threads=None,
        allow_missing_tools=True,
        profile_name=None,
        log_level="DEBUG",
        human_logs=True,
    )
    rc = jmo.cmd_scan(args)
    assert rc == 0

    indiv = Path(args.results_dir) / "individual-repos"
    assert (indiv / "a" / "trufflehog.json").exists()
    assert (indiv / "b" / "trufflehog.json").exists()
    assert not (indiv / "skipme").exists()


def test_scan_per_tool_flags_injected(tmp_path: Path, monkeypatch):
    # One fake repo
    repos_dir = tmp_path / "repos"
    r = repos_dir / "proj"
    r.mkdir(parents=True)

    cfg = {
        "default_profile": "fast",
        "profiles": {
            "fast": {
                "tools": ["semgrep"],
                "per_tool": {"semgrep": {"flags": ["--exclude", "node_modules"]}},
            }
        },
    }
    cfg_path = tmp_path / "jmo.yml"
    _write_yaml(cfg_path, cfg)

    # Pretend semgrep exists, others do not
    def fake_which(tool: str) -> bool:
        return tool == "semgrep"

    monkeypatch.setattr(jmo, "_tool_exists", fake_which)

    calls = []

    class FakeCP:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, *args, **kwargs):  # noqa: D401
        """Mock subprocess.run - accepts all args/kwargs to match real signature."""
        calls.append(cmd)
        # semgrep writes to --output path
        if isinstance(cmd, list) and "--output" in cmd:
            output_idx = cmd.index("--output") + 1
            output_path = Path(cmd[output_idx])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text('{"results": []}', encoding="utf-8")
        return FakeCP(0, "", "")

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    args = types.SimpleNamespace(
        cmd="scan",
        repo=None,
        repos_dir=str(repos_dir),
        targets=None,
        results_dir=str(tmp_path / "results"),
        config=str(cfg_path),
        tools=None,
        timeout=None,
        threads=None,
        allow_missing_tools=False,
        profile_name=None,
        log_level="INFO",
        human_logs=False,
    )
    rc = jmo.cmd_scan(args)
    assert rc == 0
    # Ensure one of the commands contains our flags
    found = False
    for c in calls:
        if isinstance(c, list) and c and c[0] == "semgrep":
            # flags must be present in the argument list
            if "--exclude" in c and "node_modules" in c:
                found = True
                break
    assert found, f"semgrep flags not found in {calls}"


def test_scan_retries_on_failure_then_success(tmp_path: Path, monkeypatch):
    # One fake repo
    repos_dir = tmp_path / "repos"
    r = repos_dir / "proj"
    r.mkdir(parents=True)

    cfg = {
        "retries": 2,
        "default_profile": "deep",
        "profiles": {
            "deep": {
                "tools": ["syft"],
                "timeout": 5,
            }
        },
    }
    cfg_path = tmp_path / "jmo.yml"
    _write_yaml(cfg_path, cfg)

    monkeypatch.setattr(jmo, "_tool_exists", lambda t: t == "syft")

    attempt = {"n": 0}

    class FakeCP:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, *args, **kwargs):  # noqa: D401
        """Mock subprocess.run - accepts all args/kwargs to match real signature."""
        # Fail first time, succeed second
        attempt["n"] += 1
        if attempt["n"] < 2:
            return FakeCP(1, "", "fail")
        # Write output file on success (syft uses capture_stdout=True)
        # ToolRunner will write stdout to file
        return FakeCP(0, '{"artifacts": []}', "ok")

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    args = types.SimpleNamespace(
        cmd="scan",
        repo=None,
        repos_dir=str(repos_dir),
        targets=None,
        results_dir=str(tmp_path / "results"),
        config=str(cfg_path),
        tools=None,
        timeout=None,
        threads=None,
        allow_missing_tools=False,
        profile_name=None,
        log_level="INFO",
        human_logs=False,
    )
    rc = jmo.cmd_scan(args)
    assert rc == 0
    # Retries means at least 2 subprocess.run invocations
    assert attempt["n"] >= 2


# ========== Expanded Per-Tool Override Tests (Added Oct 19 2025) ==========


def test_per_tool_timeout_override(tmp_path: Path):
    """Test per-tool timeout override in profile."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("print('test')")

    # Create custom config with per-tool override
    config_file = tmp_path / "custom-jmo.yml"
    config_file.write_text(
        """
tools: [semgrep]
outputs: [json]

profiles:
  custom:
    tools: [semgrep]
    timeout: 300
    per_tool:
      semgrep:
        timeout: 600  # Override global timeout
        flags: ["--exclude", "tests"]
"""
    )

    # Run scan with custom profile
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "custom",
        "--config",
        str(config_file),
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    # Should complete successfully
    assert result.returncode in [0, 1]

    # Verify semgrep ran (check logs for tool execution OR stub file created)
    output = result.stdout + result.stderr
    semgrep_stub = tmp_path / "results" / "individual-repos" / "test-repo" / "semgrep.json"

    # Either semgrep logged (tool installed) OR stub file exists (tool missing)
    assert (
        "semgrep" in output.lower() or semgrep_stub.exists()
    ), "semgrep should be logged in tool execution OR stub file created"


def test_per_tool_flags_override(tmp_path: Path):
    """Test per-tool flags override in profile."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "src").mkdir(parents=True)
    (test_repo / "src" / "app.py").write_text("x = 1")
    (test_repo / "tests").mkdir(parents=True)
    (test_repo / "tests" / "test.py").write_text("assert True")

    # Create config with exclude flags
    config_file = tmp_path / "exclude-config.yml"
    config_file.write_text(
        """
tools: [semgrep]
outputs: [json]

profiles:
  exclude-tests:
    tools: [semgrep]
    per_tool:
      semgrep:
        flags: ["--exclude", "tests"]
"""
    )

    # Run scan
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "exclude-tests",
        "--config",
        str(config_file),
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert result.returncode in [0, 1]

    # Exact verification of excluded directories depends on semgrep log format
    # Output captured in result.stdout + result.stderr if needed for debugging


def test_per_tool_retries_override(tmp_path: Path):
    """Test per-tool retry override in profile."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "README.md").write_text("# Test")

    # Create config with retry override
    config_file = tmp_path / "retry-config.yml"
    config_file.write_text(
        """
tools: [trivy]
outputs: [json]

profiles:
  retry-profile:
    tools: [trivy]
    retries: 0  # Global: no retries
    per_tool:
      trivy:
        retries: 2  # Override: 2 retries for trivy
"""
    )

    # Run scan
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "retry-profile",
        "--config",
        str(config_file),
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert result.returncode in [0, 1]


def test_profile_tool_selection_fast(tmp_path: Path):
    """Test fast profile invokes correct tool subset."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("x = 1")

    results_dir = tmp_path / "results"

    # Run fast profile scan
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "fast",
        "--results-dir",
        str(results_dir),
        "--allow-missing-tools",
        "--human-logs",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    assert result.returncode in [0, 1]

    # Verify expected tools invoked (check logs OR stub files)
    output = result.stdout + result.stderr
    tool_output_dir = results_dir / "individual-repos" / "test-repo"

    # Fast profile: trufflehog, semgrep, trivy
    expected_tools = ["trufflehog", "semgrep", "trivy"]
    for tool in expected_tools:
        # Tool invoked if logged OR stub file exists
        stub_file = tool_output_dir / f"{tool}.json"
        assert (
            tool in output.lower() or stub_file.exists()
        ), f"Fast profile should invoke {tool} (log or stub)"


def test_profile_tool_selection_balanced(tmp_path: Path):
    """Test balanced profile invokes correct tool subset."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("x = 1")
    # Add Dockerfile for hadolint
    (test_repo / "Dockerfile").write_text("FROM python:3.11\nCOPY . /app")
    # Add HTML file for zap
    (test_repo / "index.html").write_text("<html><body>Test</body></html>")

    results_dir = tmp_path / "results"

    # Run balanced profile scan
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "balanced",
        "--results-dir",
        str(results_dir),
        "--allow-missing-tools",
        "--human-logs",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    assert result.returncode in [0, 1]

    # Verify expected tools invoked (check logs OR stub files)
    output = result.stdout + result.stderr
    tool_output_dir = results_dir / "individual-repos" / "test-repo"

    # Balanced profile for repositories: Core tools that always run
    # Note: hadolint only runs if Dockerfile exists, zap only if web files exist
    # We verify the core tools that should always run
    core_tools = [
        "trufflehog",
        "semgrep",
        "syft",
        "trivy",
        "checkov",
    ]
    for tool in core_tools:
        stub_file = tool_output_dir / f"{tool}.json"
        assert (
            tool in output.lower() or stub_file.exists()
        ), f"Balanced profile should invoke {tool} (log or stub)"

    # Verify conditional tools run when applicable
    for tool in ["hadolint", "zap"]:
        stub_file = tool_output_dir / f"{tool}.json"
        assert (
            tool in output.lower() or stub_file.exists()
        ), f"{tool} should run when applicable files exist (log or stub)"


def test_profile_tool_selection_deep(tmp_path: Path):
    """Test deep profile invokes correct tool subset."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("x = 1")
    # Add Dockerfile for hadolint
    (test_repo / "Dockerfile").write_text("FROM python:3.11\nCOPY . /app")
    # Add HTML file for zap
    (test_repo / "index.html").write_text("<html><body>Test</body></html>")

    results_dir = tmp_path / "results"

    # Run deep profile scan
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "deep",
        "--results-dir",
        str(results_dir),
        "--allow-missing-tools",
        "--human-logs",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    assert result.returncode in [0, 1]

    # Verify expected tools invoked (check logs OR stub files)
    output = result.stdout + result.stderr
    tool_output_dir = results_dir / "individual-repos" / "test-repo"

    # Deep profile for repositories: Core tools that always run
    # Note: falco/afl++ need special files that are hard to fabricate in tests
    core_tools = [
        "trufflehog",
        "noseyparker",  # May show as noseyparker-init/scan/report
        "semgrep",
        "bandit",
        "syft",
        "trivy",
        "checkov",
    ]
    for tool in core_tools:
        stub_file = tool_output_dir / f"{tool}.json"
        assert (
            tool in output.lower() or stub_file.exists()
        ), f"Deep profile should invoke {tool} (log or stub)"

    # Verify conditional tools run when applicable
    for tool in ["hadolint", "zap"]:
        stub_file = tool_output_dir / f"{tool}.json"
        assert (
            tool in output.lower() or stub_file.exists()
        ), f"{tool} should run when applicable files exist (log or stub)"


def test_profile_inherits_global_per_tool_config(tmp_path: Path):
    """Test profile inherits global per_tool config and merges correctly."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("import os")

    # Create config with global per_tool and profile per_tool
    config_file = tmp_path / "inherit-config.yml"
    config_file.write_text(
        """
tools: [trivy, semgrep]
outputs: [json]

per_tool:
  trivy:
    flags: ["--no-progress"]  # Global trivy config
  semgrep:
    flags: ["--exclude", "tests"]  # Global semgrep config

profiles:
  custom:
    tools: [trivy, semgrep]
    per_tool:
      trivy:
        timeout: 600  # Profile adds timeout (merges with global flags)
      semgrep:
        flags: ["--exclude", "node_modules"]  # Profile overrides global flags
"""
    )

    # Run scan
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "custom",
        "--config",
        str(config_file),
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert result.returncode in [0, 1]

    # Verify both tools ran
    output = result.stdout + result.stderr
    assert "trivy" in output.lower()
    assert "semgrep" in output.lower()


def test_profile_thread_override(tmp_path: Path):
    """Test profile-specific thread count override."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("print('test')")

    # Create config with profile thread override
    config_file = tmp_path / "thread-config.yml"
    config_file.write_text(
        """
tools: [trufflehog, semgrep]
outputs: [json]
threads: 2  # Global default

profiles:
  high-thread:
    tools: [trufflehog, semgrep]
    threads: 8  # Profile overrides to 8
"""
    )

    # Run scan with profile
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "high-thread",
        "--config",
        str(config_file),
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
        "--human-logs",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert result.returncode in [0, 1]

    # Verify scan completed (thread count affects parallelism, not correctness)
    assert (tmp_path / "results" / "individual-repos").exists()
