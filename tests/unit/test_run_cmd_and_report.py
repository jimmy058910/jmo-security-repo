import json
import types
from pathlib import Path

import subprocess

from scripts.cli import jmo


class _CP:
    def __init__(self, rc=0, out="", err=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


def test_run_cmd_ok_rcs_and_retries(monkeypatch):
    calls = {"n": 0}

    def fake_run(cmd, stdout=None, stderr=None, text=None, timeout=None):  # noqa: ARG001
        calls["n"] += 1
        # First attempt: returncode 2 (not ok); then 1 (ok because in ok_rcs)
        if calls["n"] == 1:
            return _CP(2, "", "e")
        return _CP(1, "out", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc, out, err, used = jmo._run_cmd(
        ["tool"], timeout=1, retries=1, capture_stdout=True, ok_rcs=(0, 1)
    )
    assert rc == 1 and out == "out" and used == 2


def test_run_cmd_timeout_then_fail(monkeypatch):
    calls = {"n": 0}

    def fake_run(cmd, stdout=None, stderr=None, text=None, timeout=None):  # noqa: ARG001
        calls["n"] += 1
        # Always timeout
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout or 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc, out, err, used = jmo._run_cmd(
        ["tool"], timeout=1, retries=1, capture_stdout=True
    )
    assert rc == 124 and used >= 1


def _write(p: Path, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data), encoding="utf-8")


def test_cmd_report_profile_and_outputs(tmp_path: Path):
    # Create a minimal results dir with one finding (gitleaks)
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"
    _write(repo / "gitleaks.json", [{"RuleID": "R1", "File": "a.txt", "StartLine": 1}])

    args = types.SimpleNamespace(
        cmd="report",
        results_dir=None,
        results_dir_pos=str(root),
        results_dir_opt=None,
        out=None,
        config=str(tmp_path / "no.yml"),
        fail_on="INFO",
        profile=True,
        threads=2,
        log_level=None,
        human_logs=False,
        allow_missing_tools=True,
    )

    rc = jmo.cmd_report(args)
    # Since fail_on=INFO and we have one finding, rc should be 1
    assert rc == 1
    out_dir = root / "summaries"
    assert (out_dir / "findings.json").exists()
    assert (out_dir / "SUMMARY.md").exists()
    assert (out_dir / "dashboard.html").exists()
    # timings.json should be written when profile=True
    assert (out_dir / "timings.json").exists()
