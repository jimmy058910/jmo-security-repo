#!/usr/bin/env python3
from __future__ import annotations

import types
from pathlib import Path

import pytest

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

    # Mock tool availability check to pretend trufflehog is installed
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    # Set CI=true to skip interactive prompts
    monkeypatch.setenv("CI", "true")
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

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
        # `--skip-tools semgrep` used to be required here, and the comment it
        # replaced explained why: `profiles.fast.tools: [trufflehog]` above was
        # dead config, so the built-in `fast` list ran regardless -- including
        # semgrep, resolved for real and fetching its ruleset over the network
        # (#907). The config now does what it says (#975), so the workaround is
        # gone and this test exercises the key it was always relying on.
        skip_tools=None,
    )
    rc = jmo.cmd_scan(args)
    assert rc == 0

    indiv = Path(args.results_dir) / "individual-repos"
    assert (indiv / "a" / "trufflehog.json").exists()
    assert (indiv / "b" / "trufflehog.json").exists()
    assert not (indiv / "skipme").exists()

    # The negative half, which is what #975 asks for and what this test's shape
    # could never catch: a tool the configuration excludes must not run.
    # Asserting the included tool appears says nothing about the eight that
    # also did.
    # `scan-timings.json` is the scan phase's own diagnostic, not a tool's
    # output -- every target gets one whatever ran.
    not_a_tool_output = {"trufflehog.json", "scan-timings.json"}
    for scanned in ("a", "b"):
        stray = sorted(
            p.name
            for p in (indiv / scanned).iterdir()
            if p.name not in not_a_tool_output
        )
        assert stray == [], (
            f"`profiles.fast.tools: [trufflehog]` excluded these, and they ran "
            f"anyway in {scanned}: {stray}"
        )


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

    # Mock _check_scan_tools to skip tool availability checks
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))

    # Mock shutil.which to simulate semgrep being installed
    import shutil

    def fake_which(tool: str):
        return "/usr/bin/semgrep" if tool == "semgrep" else None

    monkeypatch.setattr(shutil, "which", fake_which)

    calls = []

    class FakeCP:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, *args, **kwargs):
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
    # The scan path runs tools through tool_runner._run_bounded (Popen plus a
    # tree kill on timeout), not subprocess.run - patching only the latter
    # records the version probes and none of the scan commands.
    monkeypatch.setattr("scripts.core.tool_runner._run_bounded", fake_run)
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

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
        if isinstance(c, list) and c and "semgrep" in Path(c[0]).name:
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

    # Mock shutil.which to simulate syft being installed
    import shutil

    monkeypatch.setattr(
        shutil, "which", lambda tool: "/usr/bin/syft" if tool == "syft" else None
    )

    attempt = {"n": 0}

    class FakeCP:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, *args, **kwargs):
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
    # The scan path runs tools through tool_runner._run_bounded (Popen plus a
    # tree kill on timeout), not subprocess.run - patching only the latter
    # records the version probes and none of the scan commands.
    monkeypatch.setattr("scripts.core.tool_runner._run_bounded", fake_run)
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

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


@pytest.mark.requires_tools
def test_per_tool_timeout_override(tmp_path: Path):
    """Test per-tool timeout override in profile."""
    import os
    import subprocess
    import sys

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("print('test')")

    # Create custom config with per-tool override
    config_file = tmp_path / "custom-jmo.yml"
    config_file.write_text("""
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
""")

    # Run scan with custom profile
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        # The history db path is CWD-relative, so the
        # HOME/USERPROFILE redirect below does not reach
        # it. Without this the scan lands in the repo's
        # real .jmo/history.db (measured: 2470 -> 2471).
        "--history-db",
        str(tmp_path / "history.db"),
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
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point. monkeypatch cannot
    # reach across this subprocess boundary, so redirect it via the env vars
    # Path.home() actually reads: USERPROFILE on Windows (ntpath.expanduser),
    # HOME on Linux/macOS (posixpath.expanduser).
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)

    # Should complete successfully
    assert result.returncode in [0, 1]

    # Verify semgrep ran (check logs for tool execution OR stub file created)
    output = result.stdout + result.stderr
    semgrep_stub = (
        tmp_path / "results" / "individual-repos" / "test-repo" / "semgrep.json"
    )

    # Either semgrep logged (tool installed) OR stub file exists (tool missing)
    assert (
        "semgrep" in output.lower() or semgrep_stub.exists()
    ), "semgrep should be logged in tool execution OR stub file created"


def test_per_tool_flags_override(tmp_path: Path):
    """Test per-tool flags override in profile."""
    import os
    import subprocess
    import sys

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "src").mkdir(parents=True)
    (test_repo / "src" / "app.py").write_text("x = 1")
    (test_repo / "tests").mkdir(parents=True)
    (test_repo / "tests" / "test.py").write_text("assert True")

    # #907: semgrep's production default (`--config auto`) fetches its
    # ruleset from semgrep.dev over the network -- this test's own point is
    # that a per_tool `flags` override reaches the real semgrep invocation,
    # which needs semgrep genuinely resolved and run, so (unlike a plumbing
    # test) skip-tools would defeat the point entirely. Route it through the
    # same `per_tool.configs` hook instead, so when this test runs on a
    # machine where semgrep actually is on PATH, it stays offline.
    offline_semgrep_rule = tmp_path / "offline-semgrep-rule.yml"
    offline_semgrep_rule.write_text(
        "rules:\n"
        "  - id: jmo-offline-flags-override-rule\n"
        "    languages: [generic]\n"
        "    message: offline rule for #907 test coverage, matches nothing real\n"
        "    severity: INFO\n"
        "    pattern: jmo-offline-flags-override-rule-never-matches-anything\n",
        encoding="utf-8",
    )

    # Create config with exclude flags
    config_file = tmp_path / "exclude-config.yml"
    config_file.write_text(f"""
tools: [semgrep]
outputs: [json]

profiles:
  exclude-tests:
    tools: [semgrep]
    per_tool:
      semgrep:
        flags: ["--exclude", "tests"]
        configs: ["{offline_semgrep_rule.as_posix()}"]
""")

    # Run scan
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        # The history db path is CWD-relative, so the
        # HOME/USERPROFILE redirect below does not reach
        # it. Without this the scan lands in the repo's
        # real .jmo/history.db (measured: 2470 -> 2471).
        "--history-db",
        str(tmp_path / "history.db"),
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
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point. monkeypatch cannot
    # reach across this subprocess boundary, so redirect it via the env vars
    # Path.home() actually reads: USERPROFILE on Windows (ntpath.expanduser),
    # HOME on Linux/macOS (posixpath.expanduser) -- each platform consults
    # only its own var, so setting just one leaves the other exposed.
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    assert result.returncode in [0, 1]

    # Exact verification of excluded directories depends on semgrep log format
    # Output captured in result.stdout + result.stderr if needed for debugging


def test_per_tool_retries_override(tmp_path: Path):
    """Test per-tool retry override in profile."""
    import os
    import subprocess
    import sys

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "README.md").write_text("# Test")

    # Create config with retry override
    config_file = tmp_path / "retry-config.yml"
    config_file.write_text("""
tools: [trivy]
outputs: [json]

profiles:
  retry-profile:
    tools: [trivy]
    retries: 0  # Global: no retries
    per_tool:
      trivy:
        retries: 2  # Override: 2 retries for trivy
""")

    # Run scan
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        # The history db path is CWD-relative, so the
        # HOME/USERPROFILE redirect below does not reach
        # it. Without this the scan lands in the repo's
        # real .jmo/history.db (measured: 2470 -> 2471).
        "--history-db",
        str(tmp_path / "history.db"),
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
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point. monkeypatch cannot
    # reach across this subprocess boundary, so redirect it via the env vars
    # Path.home() actually reads: USERPROFILE on Windows (ntpath.expanduser),
    # HOME on Linux/macOS (posixpath.expanduser) -- each platform consults
    # only its own var, so setting just one leaves the other exposed.
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    assert result.returncode in [0, 1]


@pytest.mark.requires_tools
def test_profile_tool_selection_fast(tmp_path: Path):
    """Test fast profile invokes correct tool subset."""
    import os
    import subprocess
    import sys

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("x = 1")

    results_dir = tmp_path / "results"

    # Run fast profile scan
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        # The history db path is CWD-relative, so the
        # HOME/USERPROFILE redirect below does not reach
        # it. Without this the scan lands in the repo's
        # real .jmo/history.db (measured: 2470 -> 2471).
        "--history-db",
        str(tmp_path / "history.db"),
        "--repo",
        str(test_repo),
        "--profile-name",
        "fast",
        "--results-dir",
        str(results_dir),
        "--allow-missing-tools",
        "--human-logs",
    ]
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point. monkeypatch cannot
    # reach across this subprocess boundary, so redirect it via the env vars
    # Path.home() actually reads: USERPROFILE on Windows (ntpath.expanduser),
    # HOME on Linux/macOS (posixpath.expanduser).
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240, env=env)
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


@pytest.mark.requires_tools
def test_profile_tool_selection_balanced(tmp_path: Path):
    """Test balanced profile invokes correct tool subset."""
    import os
    import subprocess
    import sys

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
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        # The history db path is CWD-relative, so the
        # HOME/USERPROFILE redirect below does not reach
        # it. Without this the scan lands in the repo's
        # real .jmo/history.db (measured: 2470 -> 2471).
        "--history-db",
        str(tmp_path / "history.db"),
        "--repo",
        str(test_repo),
        "--profile-name",
        "balanced",
        "--results-dir",
        str(results_dir),
        "--allow-missing-tools",
        "--human-logs",
    ]
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point. monkeypatch cannot
    # reach across this subprocess boundary, so redirect it via the env vars
    # Path.home() actually reads: USERPROFILE on Windows (ntpath.expanduser),
    # HOME on Linux/macOS (posixpath.expanduser).
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240, env=env)
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


@pytest.mark.requires_tools
def test_profile_tool_selection_deep(tmp_path: Path):
    """Test deep profile invokes correct tool subset."""
    import os
    import subprocess
    import sys

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
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        # The history db path is CWD-relative, so the
        # HOME/USERPROFILE redirect below does not reach
        # it. Without this the scan lands in the repo's
        # real .jmo/history.db (measured: 2470 -> 2471).
        "--history-db",
        str(tmp_path / "history.db"),
        "--repo",
        str(test_repo),
        "--profile-name",
        "deep",
        "--results-dir",
        str(results_dir),
        "--allow-missing-tools",
        "--human-logs",
    ]
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point. monkeypatch cannot
    # reach across this subprocess boundary, so redirect it via the env vars
    # Path.home() actually reads: USERPROFILE on Windows (ntpath.expanduser),
    # HOME on Linux/macOS (posixpath.expanduser).
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240, env=env)
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


@pytest.mark.requires_tools
def test_profile_inherits_global_per_tool_config(tmp_path: Path):
    """Test profile inherits global per_tool config and merges correctly."""
    import os
    import subprocess
    import sys

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("import os")

    # Create config with global per_tool and profile per_tool
    config_file = tmp_path / "inherit-config.yml"
    config_file.write_text("""
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
""")

    # Run scan
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        # The history db path is CWD-relative, so the
        # HOME/USERPROFILE redirect below does not reach
        # it. Without this the scan lands in the repo's
        # real .jmo/history.db (measured: 2470 -> 2471).
        "--history-db",
        str(tmp_path / "history.db"),
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
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point. monkeypatch cannot
    # reach across this subprocess boundary, so redirect it via the env vars
    # Path.home() actually reads: USERPROFILE on Windows (ntpath.expanduser),
    # HOME on Linux/macOS (posixpath.expanduser).
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    assert result.returncode in [0, 1]

    # Verify both tools ran (check logs OR stub files)
    output = result.stdout + result.stderr
    results_dir = tmp_path / "results"
    tool_output_dir = results_dir / "individual-repos" / "test-repo"

    for tool in ["trivy", "semgrep"]:
        stub_file = tool_output_dir / f"{tool}.json"
        assert (
            tool in output.lower() or stub_file.exists()
        ), f"{tool} should run (log or stub)"


@pytest.mark.requires_tools
def test_profile_thread_override(tmp_path: Path):
    """Test profile-specific thread count override."""
    import os
    import subprocess
    import sys

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("print('test')")

    # Create config with profile thread override
    config_file = tmp_path / "thread-config.yml"
    config_file.write_text("""
tools: [trufflehog, semgrep]
outputs: [json]
threads: 2  # Global default

profiles:
  high-thread:
    tools: [trufflehog, semgrep]
    threads: 8  # Profile overrides to 8
""")

    # Run scan with profile
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        # The history db path is CWD-relative, so the
        # HOME/USERPROFILE redirect below does not reach
        # it. Without this the scan lands in the repo's
        # real .jmo/history.db (measured: 2470 -> 2471).
        "--history-db",
        str(tmp_path / "history.db"),
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
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point. monkeypatch cannot
    # reach across this subprocess boundary, so redirect it via the env vars
    # Path.home() actually reads: USERPROFILE on Windows (ntpath.expanduser),
    # HOME on Linux/macOS (posixpath.expanduser).
    env = {**os.environ, "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    assert result.returncode in [0, 1]

    # Verify scan completed (thread count affects parallelism, not correctness)
    assert (tmp_path / "results" / "individual-repos").exists()


def test_scan_startup_does_not_version_check_unrequested_tools(
    tmp_path: Path, monkeypatch
):
    """Scan startup cost must scale with the tools asked for, not the profile.

    Measured on this machine, `deep` profile, terragoat:
        22-tool scan   Scan targets -> Starting scan = 23.3s
         3-tool scan   Scan targets -> Starting scan = 20.8s

    Nearly identical, because `cmd_scan` calls `ToolManager.get_tool_summary(
    profile)` purely to render the `X/Y` number in one INFO line, and that
    sweeps every platform-applicable tool in the profile, spawning a
    `--version` subprocess for each.

    That flat ~21s tax is what breaks
    tests/security/test_input_validation.py's two 30-second subprocess caps on
    a machine that actually has tools installed - they passed only because the
    machine was tool-deprived, so this is also a green-in-CI / red-for-users
    coverage illusion.
    """
    repos_dir = tmp_path / "repos"
    (repos_dir / "proj").mkdir(parents=True)

    cfg = {
        "default_profile": "fast",
        "profiles": {"fast": {"tools": ["trufflehog"], "timeout": 60, "threads": 1}},
    }
    cfg_path = tmp_path / "jmo.yml"
    _write_yaml(cfg_path, cfg)

    checked: list[str] = []

    from scripts.cli import tool_manager as tm_module

    real_check = tm_module.ToolManager.check_tool

    def _counting_check(self, name, *a, **kw):
        checked.append(name)
        return real_check(self, name, *a, **kw)

    monkeypatch.setattr(tm_module.ToolManager, "check_tool", _counting_check)
    monkeypatch.setenv("CI", "true")
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    args = types.SimpleNamespace(
        cmd="scan",
        repo=None,
        repos_dir=str(repos_dir),
        targets=None,
        results_dir=str(tmp_path / "results"),
        config=str(cfg_path),
        tools=["trufflehog"],
        timeout=None,
        threads=None,
        allow_missing_tools=True,
        profile_name="fast",
        log_level="INFO",
        human_logs=True,
    )
    # Not `== 0`. Whether the scan succeeds depends on which tools happen to be
    # installed on the box, and this test is about startup's probing behaviour,
    # not about the outcome of the scan. Asserting 0 made it pass here (22
    # tools installed) and fail on every CI runner (none) - the distribution,
    # not the invariant.
    rc = jmo.cmd_scan(args)
    assert rc in (0, 1), f"cmd_scan returned {rc}, which is neither outcome"

    # Liveness: `checked` being empty would satisfy the assertion below without
    # proving anything, so pin that startup really did probe.
    assert "trufflehog" in checked, (
        "startup never probed the one tool that was requested, so the "
        "assertion below would pass vacuously"
    )

    unrequested = sorted(set(checked) - {"trufflehog"})
    assert not unrequested, (
        f"scan startup version-checked {len(unrequested)} tool(s) nobody asked "
        f"for: {unrequested}. Each is a subprocess spawn; on the deep profile "
        f"this costs ~21s before any scanning begins."
    )


def test_scan_startup_probes_each_tool_at_most_once(tmp_path: Path, monkeypatch):
    """Startup must not re-probe a tool it has already inspected.

    Measured: `ToolManager.check_tool("checkov")` costs 4.23s on the first call
    and 3.08s on the second - there is no caching, and a `--version` probe of a
    Python-based tool is genuinely that slow on Windows. A full `balanced`
    sweep is 16.4s.

    Scan startup performs that sweep three times, against three separate
    ToolManager instances: the critical-update warning, the missing-tool
    pre-flight, and the summary used for one log line. Nothing can change on
    disk between them, so two of the three are pure waste - and together they
    are what pushes an empty-directory scan past the 30s subprocess cap in
    tests/security/test_input_validation.py.
    """
    repos_dir = tmp_path / "repos"
    (repos_dir / "proj").mkdir(parents=True)

    # #907: semgrep's production default (`--config auto`) fetches its
    # ruleset from semgrep.dev over the network. This test's own point is
    # resolution/probe *counting*, which needs semgrep to actually be
    # resolved (removing it from `tools` would just make the test say
    # nothing about it) -- so instead of skipping it, give it a fully
    # offline, filesystem-only ruleset via the `per_tool.configs` hook
    # `repository_scanner.py` already supports, precisely so a scan that
    # does run to completion here never reaches the network.
    offline_semgrep_rule = tmp_path / "offline-semgrep-rule.yml"
    offline_semgrep_rule.write_text(
        "rules:\n"
        "  - id: jmo-offline-probe-rule\n"
        "    languages: [generic]\n"
        "    message: offline rule for #907 test coverage, matches nothing real\n"
        "    severity: INFO\n"
        "    pattern: jmo-offline-probe-rule-never-matches-anything\n",
        encoding="utf-8",
    )

    cfg = {
        "default_profile": "fast",
        "profiles": {
            "fast": {
                "tools": ["trufflehog", "semgrep", "trivy"],
                "timeout": 60,
                "threads": 1,
                "per_tool": {"semgrep": {"configs": [str(offline_semgrep_rule)]}},
            }
        },
    }
    cfg_path = tmp_path / "jmo.yml"
    _write_yaml(cfg_path, cfg)

    probed: list[str] = []

    from scripts.cli import tool_manager as tm_module

    # Count binary *resolutions*, not calls to check_tool. `check_tool` is
    # memoised per ToolManager (`_status_cache`), so a repeat call on one
    # instance costs nothing and counting calls would measure a proxy. A
    # resolution happens exactly once per (tool, ToolManager instance), which
    # is precisely the defect: three instances sweeping the same tools.
    #
    # The earlier version of this test counted `_get_tool_version` instead.
    # That reads better - the `--version` spawn is the thing that costs
    # seconds - but `check_tool` only reaches it `if binary_path`, so on a
    # runner with no tools installed nothing was ever counted and the
    # assertion below passed vacuously. `_find_binary` is called
    # unconditionally, so this measures the same sweeps on any machine.
    real_find = tm_module.ToolManager._find_binary

    def _counting_find(self, binary_name, *a, **kw):
        probed.append(binary_name)
        return real_find(self, binary_name, *a, **kw)

    monkeypatch.setattr(tm_module.ToolManager, "_find_binary", _counting_find)
    monkeypatch.setenv("CI", "true")
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    args = types.SimpleNamespace(
        cmd="scan",
        repo=None,
        repos_dir=str(repos_dir),
        targets=None,
        results_dir=str(tmp_path / "results"),
        config=str(cfg_path),
        tools=["trufflehog", "semgrep", "trivy"],
        timeout=None,
        threads=None,
        allow_missing_tools=True,
        profile_name="fast",
        log_level="INFO",
        human_logs=True,
    )
    # Not `== 0` - see the sibling test above. The scan's outcome depends on
    # which tools the machine happens to have; the probing behaviour does not.
    rc = jmo.cmd_scan(args)
    assert rc in (0, 1), f"cmd_scan returned {rc}, which is neither outcome"

    # Liveness: an empty `probed` satisfies the assertion below while proving
    # nothing, which is exactly how the previous instrument failed.
    assert probed, "startup resolved no binaries at all - nothing was measured"

    repeated = {n: probed.count(n) for n in set(probed) if probed.count(n) > 1}
    assert not repeated, (
        f"startup re-resolved these tools once per extra sweep: {repeated}. "
        f"Each sweep re-probes the filesystem and then spawns `--version` for "
        f"whatever it finds (checkov: 4.23s then 3.08s), and nothing on disk "
        f"can change between them."
    )
