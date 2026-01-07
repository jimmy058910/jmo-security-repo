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

    import subprocess
    import shutil
    from unittest.mock import MagicMock

    for t in tools:
        # Mock shutil.which to simulate tool being installed
        def fake_which_factory(current: str):
            def _fake_which(name: str):
                return f"/usr/bin/{name}" if name == current else None

            return _fake_which

        monkeypatch.setattr(shutil, "which", fake_which_factory(t))

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

        # Note: _tool_exists removed in v0.9.0 - tool discovery handled by scanners
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


def test_scan_fails_when_only_requested_tool_missing(tmp_path: Path, monkeypatch):
    """
    Test that scan fails appropriately when the only requested tool is unavailable.

    v1.0.0 Architecture:
    - With allow_missing_tools=True: scan continues with available tools
    - If ALL requested tools are missing, scan fails with exit code 1
    - No stub files are created for unavailable tools

    This test verifies the failure behavior when requesting only an unavailable tool.
    """
    # Set CI=true to skip interactive prompts
    monkeypatch.setenv("CI", "true")

    # Create test repo
    repo = tmp_path / "test-repo"
    repo.mkdir()
    (repo / "app.py").write_text("password = 'hardcoded123'", encoding="utf-8")

    # Run scan requesting only noseyparker (which is typically not installed)
    # Note: This uses in-process call to avoid subprocess environment issues
    out_base = tmp_path / "results"

    class Args:
        def __init__(self):
            self.repo = str(repo)
            self.repos_dir = None
            self.targets = None
            self.results_dir = str(out_base)
            self.config = str(tmp_path / "no.yml")
            self.tools = ["noseyparker"]  # Request tool that's likely not installed
            self.timeout = 30
            self.threads = 1
            self.allow_missing_tools = True  # But it's the only tool requested

    rc = jmo.cmd_scan(Args())

    # When the only requested tool is missing:
    # - Scan should return 1 (no tools available to run)
    # - OR return 0 if tool happens to be installed on this system
    # Either outcome is valid depending on tool installation
    if rc == 0:
        # Tool was installed - verify output exists
        noseyparker_out = out_base / "individual-repos" / repo.name / "noseyparker.json"
        assert noseyparker_out.exists(), "Output should exist when tool is available"
    else:
        # Tool was missing - scan fails because no tools available
        assert rc == 1, f"Expected exit code 1 when tool missing, got {rc}"
        # No stub files should be created
        noseyparker_out = out_base / "individual-repos" / repo.name / "noseyparker.json"
        assert (
            not noseyparker_out.exists()
        ), "Stub should NOT be created in v1.0.0 architecture"
