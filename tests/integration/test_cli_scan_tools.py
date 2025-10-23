import json
import types
from pathlib import Path

from scripts.cli import jmo


def _repo(tmp_path: Path) -> Path:
    r = tmp_path / "repos" / "one"
    r.mkdir(parents=True, exist_ok=True)
    # Add a minimal Dockerfile to exercise hadolint path
    (r / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
    return r


def test_scan_each_tool_happy_paths(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path)
    out_base = tmp_path / "results"

    # Active tools only (v0.5.0+)
    # Removed: gitleaks, noseyparker, tfsec (deprecated/not implemented)
    tools = [
        "trufflehog",
        "semgrep",
        "syft",
        "trivy",
        "hadolint",
        "checkov",
        "bandit",
    ]

    # Pretend only the current tool exists
    def tool_exists_factory(current: str):
        def _tool_exists(name: str) -> bool:
            return name == current

        return _tool_exists

    import subprocess
    from unittest.mock import MagicMock

    for t in tools:

        def make_mock_run(tool_name):
            """Create subprocess.run mock for specific tool."""

            def mock_run(cmd, *args, **kwargs):
                prog = cmd[0]
                result = MagicMock()
                result.returncode = 0
                result.stderr = ""

                # Tools with --output or -o flags (write to file)
                if prog == "semgrep" and "--output" in cmd:
                    p = Path(cmd[cmd.index("--output") + 1])
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps({"results": []}), encoding="utf-8")
                    result.stdout = ""
                elif prog == "trivy" and "-o" in cmd:
                    p = Path(cmd[cmd.index("-o") + 1])
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps({"Results": []}), encoding="utf-8")
                    result.stdout = ""
                elif prog == "bandit" and "-o" in cmd:
                    p = Path(cmd[cmd.index("-o") + 1])
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps({"results": []}), encoding="utf-8")
                    result.stdout = ""
                # Tools with capture_stdout (return JSON in stdout)
                elif prog == "trufflehog":
                    result.stdout = ""  # No findings
                elif prog == "syft":
                    result.stdout = json.dumps({"artifacts": []})
                elif prog == "hadolint":
                    result.stdout = json.dumps([])
                elif prog == "checkov":
                    result.stdout = json.dumps({"results": {"failed_checks": []}})
                else:
                    result.stdout = ""

                return result

            return mock_run

        monkeypatch.setattr(jmo, "_tool_exists", tool_exists_factory(t))
        monkeypatch.setattr(subprocess, "run", make_mock_run(t))

        args = types.SimpleNamespace(
            cmd="scan",
            repo=str(repo),
            repos_dir=None,
            targets=None,
            results_dir=str(out_base),
            config=str(tmp_path / "no.yml"),
            tools=[t],
            timeout=10,
            threads=1,
            allow_missing_tools=False,
            profile_name=None,
            log_level=None,
            human_logs=False,
        )
        rc = jmo.cmd_scan(args)
        assert rc == 0
        out = out_base / "individual-repos" / repo.name / f"{t}.json"
        assert out.exists(), f"expected output for {t} to exist: {out}"


def test_noseyparker_docker_fallback(tmp_path: Path):
    """
    Test noseyparker stub creation when binary and Docker are unavailable.

    Noseyparker has two strategies:
    1. Local binary execution (3-phase: init, scan, report)
    2. Docker fallback (via run_noseyparker_docker.sh)
    3. Stub generation when both are unavailable

    This test verifies strategy #3 by hiding both noseyparker binary and docker.
    """
    import subprocess
    import sys
    import os

    # Create minimal PATH with ONLY python3 (exclude bash/docker/noseyparker)
    minimal_bin = tmp_path / "minimal-bin"
    minimal_bin.mkdir()
    os.symlink(sys.executable, str(minimal_bin / "python3"))

    # Create test repo
    repo = tmp_path / "test-repo"
    repo.mkdir()
    (repo / "app.py").write_text("password = 'hardcoded123'", encoding="utf-8")

    # Run scan with noseyparker (should create stub)
    out_base = tmp_path / "results"
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(repo),
        "--results-dir",
        str(out_base),
        "--tools",
        "noseyparker",
        "--allow-missing-tools",  # Creates stub when tool unavailable
    ]

    result = subprocess.run(
        cmd,
        timeout=120,
        capture_output=True,
        text=True,
        env={"PATH": str(minimal_bin), "PYTHONPATH": "."},
    )
    assert result.returncode == 0, f"Scan failed: {result.stderr}"

    # Verify stub file exists
    noseyparker_out = out_base / "individual-repos" / repo.name / "noseyparker.json"
    assert noseyparker_out.exists(), "Stub should be created when tool unavailable"
