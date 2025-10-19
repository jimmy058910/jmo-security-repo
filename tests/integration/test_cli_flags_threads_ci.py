import json
import types
from pathlib import Path
from unittest.mock import MagicMock

from scripts.cli import jmo


def test_per_tool_flags_passed_semgrep(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    out_base = tmp_path / "results"

    def eff(_):
        return {
            "tools": ["semgrep"],
            "threads": 1,
            "timeout": 10,
            "include": [],
            "exclude": [],
            "retries": 0,
            "per_tool": {
                "semgrep": {"flags": ["--severity", "ERROR", "--timeout", "5"]}
            },
        }

    seen = {"cmd": None}

    # Mock subprocess.run to capture command (used by ToolRunner)
    import subprocess

    def mock_run(cmd, *args, **kwargs):
        seen["cmd"] = cmd
        # semgrep writes to --output path
        if "--output" in cmd:
            p = Path(cmd[cmd.index("--output") + 1])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"results": []}), encoding="utf-8")
        # Return successful result
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        return result

    monkeypatch.setattr(jmo, "_effective_scan_settings", eff)
    monkeypatch.setattr(jmo, "_tool_exists", lambda n: n == "semgrep")
    monkeypatch.setattr(subprocess, "run", mock_run)

    args = types.SimpleNamespace(
        cmd="scan",
        repo=str(repo),
        repos_dir=None,
        targets=None,
        results_dir=str(out_base),
        config=str(tmp_path / "cfg.yml"),
        tools=None,
        timeout=None,
        threads=1,
        allow_missing_tools=False,
        profile_name=None,
        log_level=None,
        human_logs=False,
    )

    rc = jmo.cmd_scan(args)
    assert rc == 0
    # Ensure flags are present in command
    cmd = seen["cmd"]
    assert cmd is not None, "No command was captured"
    assert "--severity" in cmd and "ERROR" in cmd and "--timeout" in cmd and "5" in cmd


def test_threads_env_then_config(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    out_base = tmp_path / "results"

    # Force no threads in eff to defer to env, else to config
    def eff(_):
        return {
            "tools": ["gitleaks"],
            "threads": None,
            "timeout": 10,
            "include": [],
            "exclude": [],
            "retries": 0,
            "per_tool": {},
        }

    # pretend config.threads = 3 by monkeypatching load_config return object
    class Cfg:
        threads = 3

    monkeypatch.setattr(jmo, "_effective_scan_settings", eff)
    monkeypatch.setattr(jmo, "load_config", lambda p: Cfg())
    monkeypatch.setattr(jmo, "_tool_exists", lambda n: False)

    # Case 1: env set
    monkeypatch.setenv("JMO_THREADS", "2")
    rc = jmo.cmd_scan(
        types.SimpleNamespace(
            cmd="scan",
            repo=str(repo),
            repos_dir=None,
            targets=None,
            results_dir=str(out_base),
            config=str(tmp_path / "cfg.yml"),
            tools=None,
            timeout=None,
            threads=None,
            allow_missing_tools=True,
            profile_name=None,
            log_level=None,
            human_logs=False,
        )
    )
    assert rc == 0

    # Case 2: env cleared, fallback to config
    monkeypatch.delenv("JMO_THREADS", raising=False)
    rc = jmo.cmd_scan(
        types.SimpleNamespace(
            cmd="scan",
            repo=str(repo),
            repos_dir=None,
            targets=None,
            results_dir=str(out_base),
            config=str(tmp_path / "cfg.yml"),
            tools=None,
            timeout=None,
            threads=None,
            allow_missing_tools=True,
            profile_name=None,
            log_level=None,
            human_logs=False,
        )
    )
    assert rc == 0


def test_cmd_ci_wiring_and_threshold(tmp_path: Path, monkeypatch):
    # Build a minimal results directory with a finding to trigger fail_on
    results = tmp_path / "results"
    indiv = results / "individual-repos" / "r1"
    indiv.mkdir(parents=True, exist_ok=True)
    (indiv / "trufflehog.json").write_text(
        json.dumps([{"RuleID": "R", "File": "a", "StartLine": 1}]), encoding="utf-8"
    )

    # Make cmd_scan a no-op (we pre-created outputs)
    monkeypatch.setattr(jmo, "cmd_scan", lambda a: 0)

    # cmd_ci should call cmd_report with normalized results_dir fields; fail_on=INFO -> non-zero
    args = types.SimpleNamespace(
        repo=None,
        repos_dir=None,
        targets=None,
        results_dir=str(results),
        config=str(tmp_path / "no.yml"),
        tools=None,
        timeout=None,
        threads=None,
        allow_missing_tools=True,
        profile_name=None,
        fail_on="INFO",
        profile=True,
        log_level=None,
        human_logs=False,
    )

    rc = jmo.cmd_ci(args)
    assert rc == 1
