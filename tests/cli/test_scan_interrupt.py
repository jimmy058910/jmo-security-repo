"""Ctrl-C stops `jmo scan` and leaves no process behind (v2.0.0 Phase 7, B4).

Measured before this (app B, default matrix): a SIGINT 3 s into the scan phase
was only logged ("Received stop signal..."); 5 s later jmo and 5 scanner
processes were still running, and the scan finished, wrote its report and
history, and exited 0. The scanners run in sessions of their own, so a
terminal's Ctrl-C never reaches them: JMo has to stop them.

Decided 2026-11-05: after Ctrl-C jmo exits 130 with no report, and the session
is saved for `jmo scan --resume`.

The tools here are stand-ins in a home of the test's own: each answers its
version probe, then starts a sleeping child and waits, as a scanner working in
a grandchild does. The signal goes to jmo's process group, as a terminal sends
it.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX process groups and signals"
)

ROOT = Path(__file__).resolve().parents[2]

STAND_IN = """#!/bin/bash
case "$1" in
  --version|-version|-v|-V) echo '{banner}'; exit 0 ;;
esac
sleep 300 &
echo $! > "$JMO_TEST_PIDS/{name}.child"
echo $$ > "$JMO_TEST_PIDS/{name}.tool"
wait
"""
# Tools nothing else on a machine provides: shellcheck is often on PATH (CI's
# image has one), and was found there instead of its stand-in.
BANNERS = {
    "trivy": "Version: 0.74.0",
    "hadolint": "Haskell Dockerfile Linter 2.15.1",
}


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.fixture
def scan(tmp_path):
    home = tmp_path / "home"
    bin_dir = home / ".jmo" / "bin"
    bin_dir.mkdir(parents=True)
    for name, banner in BANNERS.items():
        tool = bin_dir / name
        tool.write_bytes(STAND_IN.format(name=name, banner=banner).encode())
        tool.chmod(0o755)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_bytes(b"FROM ubuntu:24.04\n")
    pids = tmp_path / "pids"
    pids.mkdir()
    env = {
        **os.environ,
        "HOME": str(home),
        "JMO_TEST_PIDS": str(pids),
        "PYTHONPATH": str(ROOT),
    }
    env.pop("JMO_NON_INTERACTIVE", None)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "scan",
            "--repo",
            str(repo),
            "--tools",
            *BANNERS,
            "--results-dir",
            str(tmp_path / "results"),
            "--history-db",
            str(tmp_path / "history.db"),
            "--allow-missing-tools",
        ],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    yield proc, pids, tmp_path
    # Whatever the outcome, leave nothing behind.
    for pid_file in pids.glob("*"):
        try:
            os.kill(int(pid_file.read_bytes()), signal.SIGKILL)
        except (ValueError, ProcessLookupError):
            pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.communicate(timeout=30)


def _wait_for(predicate, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


def test_ctrl_c_stops_the_scan_and_leaves_no_process(scan) -> None:
    proc, pids, tmp_path = scan
    every = [f"{name}.{kind}" for name in BANNERS for kind in ("tool", "child")]
    started = _wait_for(lambda: all((pids / f).exists() for f in every), 60)
    assert started, (proc.poll(), sorted(p.name for p in pids.iterdir()))

    os.killpg(proc.pid, signal.SIGINT)

    exited = _wait_for(lambda: proc.poll() is not None, 5)
    stopped = [int((pids / f).read_bytes()) for f in every]
    left = _wait_for(lambda: not any(_alive(pid) for pid in stopped), 5)
    assert exited, "jmo was still running 5 s after Ctrl-C"
    assert proc.returncode == 130
    assert left, [pid for pid in stopped if _alive(pid)]
    # No report for a stopped scan; the session is kept for --resume.
    assert not (tmp_path / "results" / "summaries").exists()
    assert (tmp_path / ".jmo" / "scan-session.json").exists()
