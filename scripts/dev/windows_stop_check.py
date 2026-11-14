"""Windows: Ctrl-C stops `jmo scan` and leaves no process behind, and killing
jmo outright takes its scanners with it (v2.0.0 Phase 7, B3/B4).

CI cannot send a console Ctrl-C, so this runs on a Windows machine with JMo's
tools installed. Run it from a console window (cmd.exe, PowerShell or Windows
Terminal; not Git Bash's mintty, which is not a Windows console), in the
checkout, on the branch under test:

    .venv\\Scripts\\python.exe windows_stop_check.py C:\\path\\to\\a\\repository

Two checks, each on a fresh scan of that repository (the default matrix;
missing tools are skipped):

1. Ctrl-C, sent to the console 3 s after the first scanner starts: jmo exits
   130 within 10 s, and 5 s later none of the processes it started is alive.
2. jmo killed outright (TerminateProcess, as Task Manager does; no `/T`) 3 s
   after the first scanner starts: 5 s later none of them is alive. That is
   the Job Object's KILL_ON_JOB_CLOSE.

Every process under jmo is recorded while the scan runs, from
Win32_Process's ParentProcessId, so a scanner's own children count too.
Prints one line per check and exits 0 when both pass.
"""

from __future__ import annotations

import csv
import ctypes
import io
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

STILL_ACTIVE = 259
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
# Windows only; elsewhere `main` says so before anything uses it.
kernel32: Any = None
if sys.platform == "win32":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


def processes() -> dict[int, tuple[int, str, str]]:
    """pid -> (parent pid, name, command line) of every process."""
    out = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            # UTF-8 out: piped, PowerShell writes the console's OEM codepage.
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,ParentProcessId,Name,CommandLine | "
            "ConvertTo-Csv -NoTypeInformation",
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    ).stdout
    table = {}
    for row in csv.DictReader(io.StringIO(out)):
        table[int(row["ProcessId"])] = (
            int(row["ParentProcessId"]),
            row["Name"],
            row["CommandLine"] or "",
        )
    return table


def descendants(root: int, table: dict[int, tuple[int, str, str]]) -> dict[int, str]:
    children: dict[int, list[int]] = {}
    for pid, (ppid, _name, _cmd) in table.items():
        children.setdefault(ppid, []).append(pid)
    found, stack = {}, [root]
    while stack:
        for child in children.get(stack.pop(), []):
            if child not in found:
                found[child] = table[child][1]
                stack.append(child)
    return found


def alive(pid: int) -> bool:
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def scan(repo: Path, work: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "scan",
            "--repo",
            str(repo),
            "--results-dir",
            str(work / "results"),
            "--history-db",
            str(work / "history.db"),
            "--allow-missing-tools",
        ],
        stdout=subprocess.DEVNULL,
        stderr=open(work / "stderr.log", "wb"),
    )


def watch_until_scanning(proc: subprocess.Popen, seen: dict[int, str]) -> bool:
    """Record jmo's descendants until a scanner has run for 3 s; False if
    jmo ended first. A scanner is a process whose command line names
    `individual-repos`, the scan phase's output folder: the startup version
    probes run the same programs."""
    first = None
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline and proc.poll() is None:
        table = processes()
        now = descendants(proc.pid, table)
        seen.update(now)
        if first is None and any("individual-repos" in table[p][2] for p in now):
            first = time.monotonic()
        if first is not None and time.monotonic() - first >= 3:
            return True
        time.sleep(0.5)
    return False


def check(name: str, repo: Path, stop) -> tuple[bool, str]:
    work = Path(tempfile.mkdtemp(prefix=f"jmo-{name}-"))
    proc = scan(repo, work)
    seen: dict[int, str] = {}
    if not watch_until_scanning(proc, seen):
        proc.kill()
        return (
            False,
            f"jmo ended before a scanner ran 3 s (rc {proc.poll()}); see {work}",
        )
    seen.update(descendants(proc.pid, processes()))
    stop(proc)
    try:
        rc = proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        rc = None
    time.sleep(5)
    left = {pid: n for pid, n in seen.items() if alive(pid)}
    for pid in left:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, timeout=30
        )
    detail = (
        f"jmo rc {rc}; {len(seen)} process(es) under it, {len(left)} alive 5 s later"
        + (f": {sorted(set(left.values()))}" if left else "")
    )
    return rc is not None and not left, detail


def ctrl_c(proc: subprocess.Popen) -> None:
    # The console's Ctrl-C reaches every process on it, this one included.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    kernel32.GenerateConsoleCtrlEvent(0, 0)  # CTRL_C_EVENT to the whole console


def kill_outright(proc: subprocess.Popen) -> None:
    proc.kill()  # TerminateProcess on jmo alone


def main() -> int:
    if sys.platform != "win32":
        print("windows_stop_check.py checks Windows behaviour; run it there")
        return 2
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_dir():
        print(__doc__)
        return 2
    repo = Path(sys.argv[1]).resolve()
    os.environ.pop("JMO_NON_INTERACTIVE", None)
    results = []
    ok, detail = check("ctrl-c", repo, ctrl_c)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    results.append(ok and "rc 130" in detail)
    print(f"{'PASS' if results[-1] else 'FAIL'} Ctrl-C: {detail}")
    ok, detail = check("kill", repo, kill_outright)
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'} jmo killed outright: {detail}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
