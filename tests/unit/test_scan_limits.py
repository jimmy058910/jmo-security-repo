"""The scan's memory gate and CPU slots (v2.0.0 Phase 7, B2).

Measured on app B before the gate: 1,314 MB peak tree memory on the default
matrix, because each target's `ToolRunner` ran 4 tools at once and `threads`
targets ran together, whatever each tool costs. Now one gate per scan admits a
run while the running total plus its cost (`ToolDefinition.memory_mb`, from the
descriptor) fits the budget, or when nothing else runs; first come, first
served. A second limit, `threads` CPU slots, bounds how many run at once.

The runs here are stand-ins that only sleep. One that must not overlap another
holds a lock directory and exits 7 if it is already held; one that must overlap
waits for its partner's marker and exits 3 if it never appears.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

from scripts.core import tool_runner
from scripts.core.tool_runner import ToolDefinition, ToolResult, ToolRunner, scan_limits

ALONE = (
    "import os, sys, time\n"
    "try:\n"
    "    os.mkdir(sys.argv[1])\n"
    "except FileExistsError:\n"
    "    sys.exit(7)\n"
    "time.sleep(0.5)\n"
    "os.rmdir(sys.argv[1])\n"
)
TOGETHER = (
    "import os, sys, time\n"
    "open(sys.argv[1], 'w').close()\n"
    "deadline = time.monotonic() + 5\n"
    "while not os.path.exists(sys.argv[2]):\n"
    "    if time.monotonic() > deadline:\n"
    "        sys.exit(3)\n"
    "    time.sleep(0.05)\n"
)


def _tool(name: str, memory_mb: int, *argv: str) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        command=[sys.executable, "-c", *argv],
        output_file=None,
        timeout=30,
        ok_return_codes=(0,),
        capture_stdout=True,
        memory_mb=memory_mb,
    )


def _alone(tmp_path: Path, *costs: int) -> list[ToolDefinition]:
    lock = str(tmp_path / "in-use")
    return [_tool(f"t{i}", mb, ALONE, lock) for i, mb in enumerate(costs)]


def _together(tmp_path: Path, a: int, b: int) -> list[ToolDefinition]:
    one, two = str(tmp_path / "one"), str(tmp_path / "two")
    return [_tool("a", a, TOGETHER, one, two), _tool("b", b, TOGETHER, two, one)]


def _run_at_once(tools: list[ToolDefinition]) -> list[ToolResult]:
    """Each tool on a runner of its own, as each target has one."""
    results: list[ToolResult] = []
    threads = [
        threading.Thread(target=lambda t=t: results.append(ToolRunner([t]).run_tool(t)))
        for t in tools
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    return results


def _codes(results: list[ToolResult]) -> list[int]:
    return sorted(r.returncode for r in results)


def test_two_runs_that_do_not_fit_together_never_overlap(tmp_path) -> None:
    with scan_limits(budget_mb=600, slots=4):
        results = _run_at_once(_alone(tmp_path, 550, 550))
    assert _codes(results) == [0, 0], results


def test_two_runs_that_fit_together_do_overlap(tmp_path) -> None:
    with scan_limits(budget_mb=600, slots=4):
        results = _run_at_once(_together(tmp_path, 100, 100))
    assert _codes(results) == [0, 0], results


def test_the_stand_ins_tell_overlap_from_none(tmp_path) -> None:
    """The control: with no limits two `ALONE` runs collide."""
    assert _codes(_run_at_once(_alone(tmp_path, 550, 550))) == [0, 7]


def test_a_run_larger_than_the_budget_runs_alone_and_finishes(tmp_path) -> None:
    with scan_limits(budget_mb=600, slots=4):
        results = _run_at_once(_alone(tmp_path, 900, 100))
    assert _codes(results) == [0, 0], results


def test_cpu_slots_bound_the_count_whatever_the_budget(tmp_path) -> None:
    with scan_limits(budget_mb=100_000, slots=1):
        results = _run_at_once(_alone(tmp_path, 10, 10))
    assert _codes(results) == [0, 0], results


def test_first_come_first_served() -> None:
    """A large run waiting is not passed by a small one that would fit."""
    order: list[str] = []

    def until(condition, what: str) -> None:
        deadline = time.monotonic() + 5
        while not condition():
            assert time.monotonic() < deadline, what
            time.sleep(0.01)

    with scan_limits(budget_mb=600, slots=4) as limits:
        assert limits.admit(400)

        def wait(name: str, mb: int) -> None:
            if limits.admit(mb):
                order.append(name)

        large = threading.Thread(target=wait, args=("large", 550))
        small = threading.Thread(target=wait, args=("small", 100))
        try:
            large.start()
            until(lambda: len(limits._queue) == 1, "the large run never queued")
            small.start()
            until(lambda: len(limits._queue) == 2, "the small run never queued")
            time.sleep(0.3)
            assert order == [], "the small run went past the large one"
            limits.release(400)
            until(lambda: order == ["large"], "the large run was not admitted")
            time.sleep(0.3)
            assert order == ["large"], "the small run fits beside neither"
            limits.release(550)
            until(lambda: order == ["large", "small"], "the small run never ran")
            limits.release(100)
        finally:
            # A failed assert must not leave a waiter blocking pytest's exit.
            tool_runner.request_stop()
            large.join(timeout=5)
            small.join(timeout=5)
            tool_runner.clear_stop()


def test_ctrl_c_wakes_a_waiting_run_and_it_never_starts(tmp_path) -> None:
    marker = tmp_path / "started"
    tool = _tool("waits", 550, f"open({str(marker)!r}, 'w')")
    results: list[ToolResult] = []
    with scan_limits(budget_mb=600, slots=4) as limits:
        assert limits.admit(550)
        waiter = threading.Thread(
            target=lambda: results.append(ToolRunner([tool]).run_tool(tool))
        )
        try:
            waiter.start()
            time.sleep(0.5)
            assert waiter.is_alive(), "the run did not wait for the gate"
            tool_runner.request_stop()
            waiter.join(timeout=5)
            assert not waiter.is_alive(), "Ctrl-C did not wake it"
        finally:
            tool_runner.clear_stop()
            limits.release(550)
            waiter.join(timeout=5)
    assert results[0].failure == "interrupted"
    assert not marker.exists()


def test_limits_last_only_for_their_scan() -> None:
    with scan_limits(budget_mb=700, slots=2) as limits:
        assert tool_runner.current_scan_limits() is limits
        assert (limits.budget_mb, limits.slots) == (700, 2)
    assert tool_runner.current_scan_limits() is None


@pytest.mark.parametrize(("budget", "slots"), [(0, 1), (700, 0)])
def test_a_limit_below_one_is_refused(budget: int, slots: int) -> None:
    with pytest.raises(ValueError):
        with scan_limits(budget_mb=budget, slots=slots):
            pass


class TestTheDefaultBudgetSeesAContainersLimit:
    """psutil reads `/proc/meminfo`, which in a container shows the host: a
    `--memory 2g` container on a 64 GB host got a 30 GB budget and the gate
    bounded nothing (review of PR 7b). The default budget takes the smaller of
    the memory free and what the cgroup's limit leaves."""

    @staticmethod
    def _budget(monkeypatch, tmp_path, free_mb: int, files: dict[str, str]) -> int:
        import types

        from scripts.cli.scan_utils import default_memory_budget_mb

        for rel, text in files.items():
            (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / rel).write_bytes(text.encode())
        monkeypatch.setattr(
            "psutil.virtual_memory",
            lambda: types.SimpleNamespace(available=free_mb * 1024 * 1024),
        )
        return default_memory_budget_mb(cgroup_root=tmp_path)

    MB = 1024 * 1024

    def test_cgroup_v2_limit(self, monkeypatch, tmp_path):
        files = {
            "memory.max": f"{2048 * self.MB}\n",
            "memory.current": f"{512 * self.MB}\n",
        }
        assert self._budget(monkeypatch, tmp_path, 30_000, files) == 768

    def test_cgroup_v1_limit(self, monkeypatch, tmp_path):
        files = {
            "memory/memory.limit_in_bytes": f"{4096 * self.MB}\n",
            "memory/memory.usage_in_bytes": f"{1024 * self.MB}\n",
        }
        assert self._budget(monkeypatch, tmp_path, 30_000, files) == 1536

    def test_no_limit_leaves_the_free_memory(self, monkeypatch, tmp_path):
        files = {"memory.max": "max\n", "memory.current": f"{512 * self.MB}\n"}
        assert self._budget(monkeypatch, tmp_path, 4000, files) == 2000

    def test_v1s_no_limit_value_leaves_the_free_memory(self, monkeypatch, tmp_path):
        files = {
            "memory/memory.limit_in_bytes": "9223372036854771712\n",
            "memory/memory.usage_in_bytes": f"{1024 * self.MB}\n",
        }
        assert self._budget(monkeypatch, tmp_path, 4000, files) == 2000

    def test_no_cgroup_files_leave_the_free_memory(self, monkeypatch, tmp_path):
        assert self._budget(monkeypatch, tmp_path, 4000, {}) == 2000

    def test_a_full_container_still_gets_700(self, monkeypatch, tmp_path):
        files = {
            "memory.max": f"{1024 * self.MB}\n",
            "memory.current": f"{1000 * self.MB}\n",
        }
        assert self._budget(monkeypatch, tmp_path, 30_000, files) == 700


def test_a_run_waiting_on_the_gate_is_not_shown_running(tmp_path) -> None:
    """`run_all_parallel` signalled "start" for every tool before any was
    admitted, so a run waiting on the gate showed as running, its clock
    ticking (review of PR 7b). "start" now comes when a run is admitted: when
    the second run says it, the first has already ended. (Its "success" is sent
    by the pool's collecting thread, which may come after; the full suite
    caught a test that assumed otherwise.)"""
    finish = ALONE + "open(sys.argv[2], 'w').close()\n"
    lock = str(tmp_path / "in-use")
    tools = [
        _tool(name, 550, finish, lock, str(tmp_path / f"done-{name}")) for name in "ab"
    ]
    ended_at_start: list[int] = []

    def callback(name, status, *_args, **_kwargs):
        if status == "start":
            ended_at_start.append(len(list(tmp_path.glob("done-*"))))

    with scan_limits(budget_mb=600, slots=4):
        runner = ToolRunner(tools, progress_callback=callback, max_workers=2)
        results = runner.run_all_parallel()

    assert _codes(results) == [0, 0], results
    assert ended_at_start == [0, 1], ended_at_start
