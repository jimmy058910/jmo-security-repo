"""A run's temporary files on disk, under the scan's results (Phase 7, B2).

trufflehog's history run clones the repository into `$TMPDIR`: 329 MB for app B
(measured). On a tmpfs `/tmp` that is memory no process's RSS shows, so the
scan's memory gate could not count it. That run now gets a folder of its own
under its target's results, as `TMPDIR` (and `TMP`/`TEMP`, which Windows reads),
made before the run and removed after it, a killed run included.
"""

from __future__ import annotations

import sys
from pathlib import Path

from scripts.core.tool_descriptors import DESCRIPTORS, ScanContext
from scripts.core.tool_runner import ToolDefinition, ToolRunner

SEES = (
    "import os, sys, time\n"
    "names = ('TMPDIR', 'TMP', 'TEMP')\n"
    "seen = [os.environ.get(n, '') for n in names]\n"
    "line = '|'.join(seen + [str(os.path.isdir(seen[0]))])\n"
    "open(sys.argv[1], 'w').write(line)\n"
    "time.sleep(float(sys.argv[2]))\n"
)


def _run(tmp_path: Path, sleep: float, timeout: int) -> tuple[list[str], Path]:
    temp = tmp_path / "results" / ".tmp-x"
    record = tmp_path / "seen"
    tool = ToolDefinition(
        name="x",
        command=[sys.executable, "-c", SEES, str(record), str(sleep)],
        output_file=None,
        timeout=timeout,
        ok_return_codes=(0,),
        capture_stdout=True,
        temp_dir=temp,
    )
    (tmp_path / "results").mkdir()
    ToolRunner([tool]).run_tool(tool)
    return record.read_text(encoding="utf-8").split("|"), temp


def test_a_run_has_its_temp_dir_and_it_is_removed_after(tmp_path) -> None:
    seen, temp = _run(tmp_path, sleep=0, timeout=30)
    assert seen == [str(temp)] * 3 + ["True"]
    assert not temp.exists()


def test_a_timed_out_run_leaves_no_temp_dir(tmp_path) -> None:
    seen, temp = _run(tmp_path, sleep=30, timeout=2)
    assert seen[0] == str(temp)
    assert not temp.exists()


def test_trufflehogs_history_run_clones_under_its_results(tmp_path) -> None:
    ctx = ScanContext(
        tool="trufflehog",
        target_type="repo",
        target=tmp_path / "repo",
        out_dir=tmp_path / "out",
        binary="trufflehog",
        history=True,
    )
    tree, history = DESCRIPTORS["trufflehog"].invocations["repo"](ctx)
    assert tree.temp_dir is None
    assert history.temp_dir is not None
    assert history.temp_dir.parent == ctx.out_dir
    # Dot-prefixed scratch, as `.zap-plan.yaml`: the report reads none of it.
    assert history.temp_dir.name.startswith(".")
