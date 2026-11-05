#!/usr/bin/env python3
"""Guard: an empty parametrize list must fail collection, not skip (#1061).

A test parametrized over the constant it checks cannot fail when that constant
empties. pytest's default for an empty parameter set is one SKIPPED test and
exit 0, measured on pytest 9.1.1::

    test_content_of_each[NOTSET] SKIPPED [100%]
    1 skipped in 0.21s          # exit 0

so the content test goes quiet, and the suite-level "passed" signal does not
change. `pyproject.toml` sets ``empty_parameter_set_mark = "fail_at_collect"``,
which turns every such case into a collection error repo-wide.

This asserts the property rather than the setting: it runs a throwaway test
file under the repository's own pytest configuration and requires the empty
case to fail at collection. A control run with a one-item list must pass, so
a subprocess that fails for an unrelated reason cannot pass for the guard.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"

_TEST_BODY = """\
import pytest

VALUES = {values}


@pytest.mark.parametrize("value", list(VALUES))
def test_each(value):
    assert value
"""


def _run_pytest(tmp_path: Path, values: str) -> subprocess.CompletedProcess[str]:
    test_file = tmp_path / "test_throwaway.py"
    test_file.write_bytes(_TEST_BODY.format(values=values).encode("utf-8"))
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(test_file),
            # The repository's configuration, not whatever pytest would find
            # walking up from tmp_path.
            "-c",
            str(PYPROJECT),
            "--rootdir",
            str(tmp_path),
            # Collect nothing above tmp_path: without it the child listed every
            # directory up to the system temp directory, where another xdist
            # worker's temp directory could vanish under it (#1306).
            "--confcutdir",
            str(tmp_path),
            "-q",
            "-p",
            "no:cacheprovider",
            # Keep the child out of any xdist worker pool the parent is in.
            "-p",
            "no:xdist",
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        cwd=tmp_path,
        # The options above and no others: a `--basetemp` the parent took from
        # PYTEST_ADDOPTS holds this cwd, and the child refused it (#1501).
        env={k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"},
    )


def test_empty_parameter_set_is_a_collection_error(tmp_path: Path) -> None:
    result = _run_pytest(tmp_path, "[]")
    output = result.stdout + result.stderr
    # 2 is pytest's "interrupted" exit code, which is what a collection error
    # produces. 0 is the default behaviour this guards against.
    assert result.returncode == 2, output
    assert "Empty parameter set" in output, output
    assert "skipped" not in output.lower(), output


def test_non_empty_parameter_set_still_runs(tmp_path: Path) -> None:
    result = _run_pytest(tmp_path, '["present"]')
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "1 passed" in output, output


def test_the_child_ignores_the_parents_pytest_addopts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1501: a `--basetemp` the parent took from PYTEST_ADDOPTS reached the
    child too, whose working directory (this tmp_path) lies inside it, and
    pytest refused it, failing both tests above."""
    monkeypatch.setenv("PYTEST_ADDOPTS", f"--basetemp={tmp_path.parent}")

    result = _run_pytest(tmp_path, '["present"]')

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "1 passed" in output, output


_LISTING_HOOK = """\
import os
import sys

def _audit(event, args):
    # A path, never an fd: os.fsdecode(int) would raise inside the child.
    if event == "os.scandir" and args and isinstance(args[0], (str, bytes, os.PathLike)):
        with open({log!r}, "a", encoding="utf-8") as listed:
            listed.write(os.path.abspath(os.fsdecode(args[0])) + "\\n")

sys.addaudithook(_audit)
"""


def test_the_child_lists_no_directory_outside_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1306: the child listed every directory above its tmp_path, the system
    temp directory included, and under `-n 8` another worker's temp
    directory vanished between the listing and its lstat, failing the
    collection. An audit hook in the child records each directory it lists."""
    hook = tmp_path / "hook"
    hook.mkdir()
    log = tmp_path / "listed.txt"
    (hook / "sitecustomize.py").write_bytes(
        _LISTING_HOOK.format(log=str(log)).encode("utf-8")
    )
    monkeypatch.setenv(
        "PYTHONPATH",
        os.pathsep.join(filter(None, [str(hook), os.environ.get("PYTHONPATH")])),
    )

    result = _run_pytest(tmp_path, '["present"]')

    assert result.returncode == 0, result.stdout + result.stderr
    listed = {
        Path(p).resolve() for p in log.read_text(encoding="utf-8").split("\n") if p
    }
    root = tmp_path.resolve()
    assert root in listed  # the hook ran, and saw the collection
    assert sorted(str(p) for p in listed if not p.is_relative_to(root)) == []
