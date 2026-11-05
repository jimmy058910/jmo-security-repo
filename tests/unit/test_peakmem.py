"""The Phase 7 memory sampler measures what it claims (scripts/dev/peakmem.py).

It is the before/after instrument for the scheduler: a sampler that missed a
grandchild, or an orphan left by a Ctrl-C, would report a fix that did not
happen. Each test runs it as a subprocess, since it makes itself a child
subreaper, which the pytest worker must not become.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="peakmem.py reads /proc (Linux only)"
)

SAMPLER = Path(__file__).resolve().parents[2] / "scripts" / "dev" / "peakmem.py"


def _sample(tmp_path: Path, *options: str, command: str) -> dict:
    out = tmp_path / "mem.json"
    subprocess.run(
        [sys.executable, str(SAMPLER), *options, str(out), "--", "bash", "-c", command],
        check=True,
        capture_output=True,
        timeout=60,
    )
    return json.loads(out.read_bytes())


def _killed(pid: int) -> bool:
    """Gone, or a zombie: dead, and waiting only for init to reap it once the
    sampler, its parent as subreaper, has exited. Polled, since that reaping
    lags under load (a sweep's `-n 4` caught one alive)."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        try:
            stat = Path(f"/proc/{pid}/stat").read_bytes()
        except OSError:
            return True
        if stat[stat.rindex(b")") + 2 :].startswith(b"Z"):
            return True
        time.sleep(0.05)
    return False


def test_a_grandchilds_memory_is_counted(tmp_path):
    """A shell whose child holds 200 MB: the tree's peak holds it, and names it."""
    record = _sample(
        tmp_path,
        command=f"{sys.executable} -c 'x = bytearray(200_000_000); import time; "
        "time.sleep(1.5)'; true",
    )

    assert record["peak"]["rss_kb"] > 150 * 1024
    assert any(p["rss_kb"] > 150 * 1024 for p in record["peak"]["processes"])
    assert record["returncode"] == 0


def test_a_process_that_escapes_the_ctrl_c_is_left_and_counted(tmp_path):
    """SIGINT goes to the command's process group, as a terminal's does: a
    child that called setsid() is not in it, survives, and must be counted
    after its parent died, then killed by the sampler."""
    record = _sample(
        tmp_path,
        "--sigint-at",
        "0.5",
        "--after",
        "1",
        # Its own stdio: holding the sampler's pipe, it kept `subprocess.run`
        # waiting until it ended by itself, and a sampler that never killed it
        # passed.
        command=(
            f"setsid sleep 30 </dev/null >/dev/null 2>&1 & "
            f"echo $! > {tmp_path / 'pid'}; sleep 30"
        ),
    )

    left = record["sigint"]["at_after"]
    assert left["command_alive"] is False
    assert [p["name"] for p in left["processes"]] == ["sleep"]
    pid = int((tmp_path / "pid").read_bytes())
    assert _killed(pid), f"the escaped process {pid} was left running"


def test_nothing_left_reads_as_zero_not_unknown(tmp_path):
    record = _sample(tmp_path, "--sigint-at", "0.3", "--after", "5", command="sleep 30")

    assert record["sigint"]["at_after"] == {"command_alive": False, "processes": []}
    assert record["sigint"]["command_exited_after_s"] is not None


def test_the_ctrl_c_waits_for_the_armed_command_line(tmp_path):
    """`--arm-cmd`: the startup probe runs scanners by the same name, so the
    signal is counted from a process whose command line holds the text."""
    record = _sample(
        tmp_path,
        "--arm-cmd",
        "marker-arm-xyz",
        "--sigint-at",
        "0.2",
        "--after",
        "0.5",
        # A child of its own: the command's own process is never what arms it.
        command="sleep 1.2; (exec -a marker-arm-xyz sleep 30)",
    )

    assert record["sigint"]["armed_at_s"] >= 1.0
    assert record["sigint"]["sent_at_s"] >= 1.2
