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
    cfg = {
        "default_profile": "fast",
        "profiles": {
            "fast": {
                "tools": ["gitleaks"],
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
    assert (indiv / "a" / "gitleaks.json").exists()
    assert (indiv / "b" / "gitleaks.json").exists()
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
                "per_tool": {
                    "semgrep": {"flags": ["--exclude", "node_modules"]}
                },
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

    def fake_run(cmd, stdout=None, stderr=None, text=None, timeout=None):  # noqa: D401
        calls.append(cmd)
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

    def fake_run(cmd, stdout=None, stderr=None, text=None, timeout=None):  # noqa: D401
        # Fail first time, succeed second
        attempt["n"] += 1
        if attempt["n"] < 2:
            return FakeCP(1, "", "fail")
        return FakeCP(0, "", "ok")

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
