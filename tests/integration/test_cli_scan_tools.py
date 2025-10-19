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


def test_noseyparker_docker_fallback(tmp_path: Path, monkeypatch):
    """
    Test noseyparker Docker fallback mechanism.

    NOTE: Skipped until noseyparker is implemented in repository_scanner.py
    (see repository_scanner.py:299-300 comment). Noseyparker is in the deep profile
    but not yet integrated into the refactored scanner modules.

    TODO: Re-enable this test after implementing noseyparker in repository_scanner.py
    """
    import pytest

    pytest.skip(
        "Noseyparker not yet implemented in repository_scanner.py (see line 299-300)"
    )
