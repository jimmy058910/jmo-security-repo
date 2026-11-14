"""A run's temporary files on disk, under `~/.jmo/tmp` (Phase 7, B2).

trufflehog's history run clones the repository into `$TMPDIR`: 329 MB for app B
(measured). On a tmpfs `/tmp` that is memory no process's RSS shows, so the
scan's memory gate could not count it. That run now gets a folder of its own
under `~/.jmo/tmp`, as `TMPDIR` (and `TMP`/`TEMP`, which Windows reads), made
before the run and removed after it, a killed run included; what a killed jmo
left is swept at the next scan's start.
"""

from __future__ import annotations

import logging
import os
import stat
import subprocess
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


def test_trufflehogs_history_run_clones_into_jmos_own_temp(
    tmp_path, monkeypatch
) -> None:
    """Not under the results, which CI uploads whole: a clone left by a
    second Ctrl-C or a killed jmo carries the history's secrets (review of
    PR 7b). One folder per jmo and target, so two targets never share one."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    def history(out_dir: Path):
        ctx = ScanContext(
            tool="trufflehog",
            target_type="repo",
            target=tmp_path / "repo",
            out_dir=out_dir,
            binary="trufflehog",
            history=True,
        )
        tree, run = DESCRIPTORS["trufflehog"].invocations["repo"](ctx)
        assert tree.temp_dir is None
        return run.temp_dir

    one, two = history(tmp_path / "out" / "a"), history(tmp_path / "out" / "b")
    assert one is not None and two is not None and one != two
    assert one.parent == two.parent == tmp_path / ".jmo" / "tmp"
    assert one.name.startswith(f"{os.getpid()}-")
    assert (tmp_path / "out") not in one.parents


def test_a_dead_jmos_temp_folders_are_swept(tmp_path, monkeypatch) -> None:
    """What a killed jmo left (a second Ctrl-C exits at once; an OOM kill
    runs nothing) goes at the next scan's start. A live jmo's folders stay."""
    from scripts.core.tool_runner import sweep_stale_temp_dirs

    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    gone = subprocess.Popen([sys.executable, "-c", "pass"])
    gone.wait(timeout=30)
    root = tmp_path / ".jmo" / "tmp"
    stale = root / f"{gone.pid}-abc-trufflehog-git"
    mine = root / f"{os.getpid()}-def-trufflehog-git"
    other = root / "not-a-run"
    for folder in (stale, mine, other):
        (folder / "objects").mkdir(parents=True)
        (folder / "objects" / "pack").write_bytes(b"x")

    sweep_stale_temp_dirs()

    assert not stale.exists()
    assert mine.exists() and other.exists()


def test_a_cleanup_that_fails_is_a_warning_not_an_error(tmp_path, caplog) -> None:
    """`_remove_tree` runs in a `finally` after the run: an error there would
    replace a finished run's result."""
    from scripts.core.tool_runner import _remove_tree

    not_a_dir = tmp_path / "file"
    not_a_dir.write_bytes(b"x")
    with caplog.at_level(logging.WARNING):
        _remove_tree(not_a_dir)
    assert str(not_a_dir) in caplog.text


def test_read_only_files_are_removed(tmp_path) -> None:
    """git makes its objects read-only, which Windows will not delete as
    they are."""
    from scripts.core.tool_runner import _remove_tree

    folder = tmp_path / "clone"
    (folder / "objects").mkdir(parents=True)
    pack = folder / "objects" / "pack"
    pack.write_bytes(b"x")
    pack.chmod(stat.S_IREAD)
    _remove_tree(folder)
    assert not folder.exists()
