"""On Windows every process jmo starts dies with it (v2.0.0 Phase 7, B3).

Windows does not kill a process's children when it dies, and `taskkill /T`
runs only on a timeout or Ctrl-C: a jmo killed any other way (a closed
console, Task Manager, a crash) left its scanners running. jmo now puts itself
in a Job Object that kills every process in it when its last handle closes.

Each case runs a parent process that starts a sleeping child, then kills the
parent and watches the child. The control shows the job is what kills it.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Objects")

ROOT = Path(__file__).resolve().parents[2]

PARENT = b"""
import subprocess, sys, time
if sys.argv[1] == "contain":
    from scripts.core.tool_runner import contain_process_tree
    assert contain_process_tree()
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
open(sys.argv[2], "w").write(str(child.pid))
time.sleep(120)
"""


def _alive(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    handle = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    code = wintypes.DWORD()
    try:
        kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259  # STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


@pytest.mark.parametrize(
    ("mode", "dies"), [("contain", True), ("plain", False)], ids=["job", "control"]
)
def test_a_killed_jmo_takes_its_children_with_it(tmp_path, mode, dies) -> None:
    script = tmp_path / "parent.py"
    script.write_bytes(PARENT)
    pid_file = tmp_path / "child.pid"
    parent = subprocess.Popen(
        [sys.executable, str(script), mode, str(pid_file)],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    deadline = time.monotonic() + 30
    # Until it holds the pid: the file exists before the write lands.
    while time.monotonic() < deadline and not (
        pid_file.exists() and pid_file.read_bytes().strip()
    ):
        time.sleep(0.1)
    assert pid_file.exists(), "the parent never started its child"
    child = int(pid_file.read_bytes())

    parent.kill()
    parent.wait(timeout=30)
    deadline = time.monotonic() + 5
    while _alive(child) and time.monotonic() < deadline:
        time.sleep(0.1)
    alive = _alive(child)
    if alive:
        os.kill(child, signal.SIGTERM)  # TerminateProcess on Windows

    assert alive is not dies
