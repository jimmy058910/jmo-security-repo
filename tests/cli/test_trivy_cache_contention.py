"""Two image targets scanned at once must not lose their trivy rows (#1717).

Every trivy run shares one cache directory. An image run locks the cache's
`fanal/` for its whole run, and another that waits ~5 s exits 1 with no output:
"unable to initialize fs cache: cache may be in use by another process:
timeout". `jmo scan --images-file six.txt --tools trivy --threads 6` on a cold
cache lost 5 of 6 rows that way (measured, trivy 0.74.0). And JMo kept none of
what trivy said: the row's detail read only "no output".

These go through what a scan runs, `scan_image` and the real `ToolRunner`, from
each target's thread. Only the process launch is a stand-in, which counts how
many trivy runs are inside it at once.
"""

from __future__ import annotations

import subprocess
import threading
from pathlib import Path

import pytest

from scripts.cli.scan_jobs.image_scanner import scan_image
from scripts.core.scan_timings import Reason, State, ToolRun

LOCK_TIMEOUT = (
    "FATAL\tFatal error\trun error: image scan error: scan error: unable to "
    "initialize a scan service: unable to initialize cache: unable to initialize "
    "fs cache: cache may be in use by another process: timeout"
)


def _output_of(command: list[str]) -> Path:
    return Path(command[command.index("-o") + 1])


def _scan(results: Path, image: str, name: str):
    return scan_image(
        image=image,
        results_dir=results,
        tools=["trivy"],
        timeout=60,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        find_tool_func=lambda tool: f"/opt/bin/{tool}",
        result_name=name,
    )


def test_two_image_targets_never_run_trivy_at_once(tmp_path, monkeypatch):
    """The first run stays in until the second target's run reaches the launch
    or a second has passed. Nothing serialising them, the second gets in."""
    guard = threading.Lock()
    inside = 0
    most = 0
    first_in = threading.Event()
    second_in = threading.Event()

    def launch(command, **_kwargs):
        nonlocal inside, most
        with guard:
            inside += 1
            most = max(most, inside)
            first = not first_in.is_set()
            (first_in if first else second_in).set()
        try:
            if first:
                second_in.wait(timeout=1.0)
            _output_of(command).write_bytes(b'{"Results": []}')
            return subprocess.CompletedProcess(command, 0, "", "")
        finally:
            with guard:
                inside -= 1

    monkeypatch.setattr("scripts.core.tool_runner._run_bounded", launch)
    rows: dict[str, ToolRun] = {}

    def target(image: str, name: str, after: threading.Event | None) -> None:
        if after is not None:
            after.wait(timeout=10)
        rows[name] = _scan(tmp_path, image, name)[1]["trivy"]

    threads = [
        threading.Thread(target=target, args=("alpine:3.19", "alpine", None)),
        threading.Thread(target=target, args=("busybox:latest", "busybox", first_in)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not any(thread.is_alive() for thread in threads)
    assert first_in.is_set() and second_in.is_set(), "both runs should launch"
    assert most == 1, f"{most} trivy runs were inside the launch at once"
    assert {name: row.state for name, row in rows.items()} == {
        "alpine": State.RAN,
        "busybox": State.RAN,
    }


@pytest.mark.parametrize("returncode", [1, 2])
def test_a_failed_trivy_row_keeps_what_trivy_said(tmp_path, monkeypatch, returncode):
    """rc 1 is an accepted code, so the row is `no output`; rc 2 is a failure
    exit. Either way trivy's fatal line is the why, and the row keeps it."""

    def launch(command, **_kwargs):
        stderr = f"2026-11-25T10:14:31-05:00\t{LOCK_TIMEOUT}\n"
        return subprocess.CompletedProcess(command, returncode, "", stderr)

    monkeypatch.setattr("scripts.core.tool_runner._run_bounded", launch)

    row = _scan(tmp_path, "nginx:latest", "nginx")[1]["trivy"]

    assert row.state is State.FAILED
    assert row.reason is (Reason.NO_OUTPUT if returncode == 1 else Reason.EXIT_CODE)
    assert row.detail is not None
    assert "cache may be in use by another process: timeout" in row.detail
    # What JMo saw comes first, then what trivy said.
    assert row.detail.index("stderr: ") > 0
