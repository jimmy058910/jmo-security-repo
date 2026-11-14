#!/usr/bin/env python3
"""Peak memory of a command's whole process tree, and what a SIGINT leaves.

Runs a command (`jmo scan ...`) and samples every process under it a few times
a second: `jmo` and every scanner child and grandchild. The v2.0.0 Phase 7 plan's
numbers come from it (`docs/superpowers/plans/2026-11-05-phase-7-scheduler.md`):
1,314 MB peak on app B's default matrix, and 6 processes alive 5 s after a
Ctrl-C.

How it measures, and why:

- **Tree RSS**, from `/proc/<pid>/statm`, summed over the tree; with `--pss`,
  also PSS from `smaps_rollup`, which splits shared pages (measured within 4% of
  RSS for JMo's scanners, which are mostly static Go binaries).
- **A child subreaper** (`PR_SET_CHILD_SUBREAPER`): a process orphaned when its
  parent dies is re-parented here, not to init, so it stays in the tree and is
  counted. That is what makes "processes left after Ctrl-C" countable at all.
- **Ctrl-C as a terminal sends it**: the command runs in its own process group
  and SIGINT goes to the group. A scanner that called setsid() is not in it,
  exactly as from a shell. `--arm-cmd TEXT` waits for a process whose command
  line holds TEXT (`individual-repos`, a scan-phase path) before counting
  `--sigint-at` seconds: a scanner's name alone also matches the startup
  version probe.
- **Not seen**: files a tool writes to a tmpfs `/tmp` are RAM no process's RSS
  shows (trufflehog's history clone of app B: 329 MB in `$TMPDIR`). Measure those
  with `du` on `$TMPDIR` beside this.

Linux only (`/proc`, `prctl`). At the end it kills whatever of the tree is
left, so a run never leaks processes.

Usage:
    peakmem.py OUT.json -- jmo scan --repo ...
    peakmem.py --pss OUT.json -- jmo scan --repo ...
    peakmem.py --arm-cmd individual-repos --sigint-at 3 --after 5 --observe 150 \\
        OUT.json -- jmo scan --repo ...

Exit code 0 when it measured (whatever the command's own code, which is in the
JSON), 2 when it cannot run here.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import subprocess  # nosec B404 - runs the command it is given, list argv
import sys
import time
from pathlib import Path
from typing import Any

PR_SET_CHILD_SUBREAPER = 36
PAGE_KB = os.sysconf("SC_PAGE_SIZE") // 1024 if hasattr(os, "sysconf") else 4


def snapshot() -> tuple[dict[int, tuple[int, str]], list[tuple[int, int]]]:
    """pid -> (ppid, name) of every live process, and the (pid, ppid) of each
    zombie. A zombie holds no memory and is not running, so it is not counted."""
    live: dict[int, tuple[int, str]] = {}
    zombies: list[tuple[int, int]] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            raw = Path(f"/proc/{entry}/stat").read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        # The name is in parentheses and may hold spaces or parentheses itself.
        name = raw[raw.index("(") + 1 : raw.rindex(")")]
        state, ppid = raw[raw.rindex(")") + 2 :].split()[:2]
        if state == "Z":
            zombies.append((int(entry), int(ppid)))
        else:
            live[int(entry)] = (int(ppid), name)
    return live, zombies


def descendants(root: int, live: dict[int, tuple[int, str]]) -> list[int]:
    children: dict[int, list[int]] = {}
    for pid, (ppid, _name) in live.items():
        children.setdefault(ppid, []).append(pid)
    found: list[int] = []
    stack = [root]
    while stack:
        for child in children.get(stack.pop(), []):
            found.append(child)
            stack.append(child)
    return found


def rss_kb(pid: int) -> int:
    try:
        return int(Path(f"/proc/{pid}/statm").read_bytes().split()[1]) * PAGE_KB
    except (OSError, IndexError, ValueError):
        return 0


def pss_kb(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/smaps_rollup").read_bytes().splitlines():
            if line.startswith(b"Pss:"):
                return int(line.split()[1])
    except (OSError, IndexError, ValueError):
        pass
    return 0


def cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\0", b" ").decode("utf-8", "replace").strip()


def measure(args: argparse.Namespace) -> dict[str, Any]:
    me = os.getpid()
    start = time.perf_counter()
    # Its own process group, as a shell gives a foreground job.
    proc = subprocess.Popen(args.cmd, process_group=0)  # nosec B603 - the user's argv
    samples: list[dict[str, Any]] = []
    peak: dict[str, Any] = {"rss_kb": 0}
    by_name: dict[str, int] = {}
    armed: float | None = None
    sent: float | None = None
    at_sigint: list[dict[str, Any]] = []
    after: dict[str, Any] | None = None
    exited_after: float | None = None
    while True:
        now = time.perf_counter() - start
        live, zombies = snapshot()
        for pid, ppid in zombies:
            # Reap the orphans re-parented here; `proc` is Popen's to reap.
            if ppid == me and pid != proc.pid:
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
        tree = [pid for pid in descendants(me, live) if pid in live]
        per = [(pid, live[pid][1], rss_kb(pid)) for pid in tree]
        total = sum(kb for _pid, _name, kb in per)
        pss = sum(pss_kb(pid) for pid in tree) if args.pss else None
        samples.append(
            {"t": round(now, 2), "n": len(per), "rss_kb": total, "pss_kb": pss}
        )
        for _pid, name, kb in per:
            by_name[name] = max(by_name.get(name, 0), kb)
        if total > peak["rss_kb"]:
            peak = {
                "t": round(now, 2),
                "rss_kb": total,
                "pss_kb": pss,
                "processes": sorted(
                    (
                        {
                            "pid": pid,
                            "name": name,
                            "rss_kb": kb,
                            "cmd": cmdline(pid)[:300],
                        }
                        for pid, name, kb in per
                    ),
                    key=lambda p: -p["rss_kb"],
                ),
            }
        if args.sigint_at is not None:
            if armed is None and (
                not args.arm_cmd
                or any(args.arm_cmd in cmdline(pid) for pid in tree if pid != proc.pid)
            ):
                armed = now
            if armed is not None and sent is None and now >= armed + args.sigint_at:
                os.killpg(proc.pid, signal.SIGINT)
                sent = now
                at_sigint = [
                    {"pid": p, "name": n, "cmd": cmdline(p)[:300]} for p, n, _ in per
                ]
            if sent is not None:
                if after is None and now >= sent + args.after:
                    after = {
                        "command_alive": proc.poll() is None,
                        "processes": [
                            {"pid": p, "name": n, "cmd": cmdline(p)[:300]}
                            for p, n, _ in per
                        ],
                    }
                if exited_after is None and proc.poll() is not None:
                    exited_after = round(now - sent, 2)
                if now >= sent + max(args.after, args.observe):
                    break
        if proc.poll() is not None and not tree:
            if sent is not None and after is None:
                # Everything exited before the mark: nothing was left.
                after = {"command_alive": False, "processes": []}
            if sent is not None and exited_after is None:
                exited_after = round(now - sent, 2)
            break
        time.sleep(args.interval)

    result: dict[str, Any] = {
        "command": args.cmd,
        "wall_s": round(time.perf_counter() - start, 1),
        "returncode": proc.poll(),
        "peak": peak,
        "max_rss_kb_by_name": dict(sorted(by_name.items(), key=lambda kv: -kv[1])),
        "samples": samples,
    }
    if sent is not None:
        result["sigint"] = {
            "armed_at_s": armed,
            "sent_at_s": round(sent, 2),
            "tree_at_sigint": at_sigint,
            "after_s": args.after,
            "at_after": after,
            "command_exited_after_s": exited_after,
        }
    # Leave nothing behind.
    live, _zombies = snapshot()
    for pid in descendants(me, live):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("out", help="where the JSON record goes")
    parser.add_argument(
        "--interval", type=float, default=0.25, help="seconds between samples"
    )
    parser.add_argument("--pss", action="store_true", help="also sample PSS (slower)")
    parser.add_argument(
        "--sigint-at", type=float, help="send SIGINT this many seconds in"
    )
    parser.add_argument(
        "--arm-cmd",
        help="count --sigint-at from a process whose command line holds this",
    )
    parser.add_argument(
        "--after",
        type=float,
        default=5.0,
        help="seconds after SIGINT to count what is left",
    )
    parser.add_argument(
        "--observe",
        type=float,
        default=0.0,
        help="seconds after SIGINT to keep watching",
    )
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="-- then the command")
    args = parser.parse_args(argv)
    args.cmd = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
    if not args.cmd:
        parser.error("no command: put it after --")
    if sys.platform != "linux":
        print("peakmem.py reads /proc and needs Linux", file=sys.stderr)
        return 2
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        print("prctl(PR_SET_CHILD_SUBREAPER) failed", file=sys.stderr)
        return 2

    result = measure(args)
    Path(args.out).write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    peak = result["peak"]
    pss = f" PSS {peak['pss_kb'] // 1024} MB" if peak.get("pss_kb") else ""
    print(
        f"wall {result['wall_s']} s, rc {result['returncode']}, "
        f"peak RSS {peak['rss_kb'] // 1024} MB{pss} at {peak.get('t')} s"
    )
    sigint = result.get("sigint")
    if sigint:
        at = sigint["at_after"] or {}
        left = at.get("processes", [])
        print(
            f"SIGINT at {sigint['sent_at_s']} s; {sigint['after_s']} s later: "
            f"command alive {at.get('command_alive')}, {len(left)} process(es) in the tree; "
            f"command exited {sigint['command_exited_after_s']} s after SIGINT"
        )
        for p in left:
            print(f"  {p['pid']} {p['name']} {p['cmd'][:100]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
