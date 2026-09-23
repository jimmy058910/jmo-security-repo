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

import subprocess
import sys
from pathlib import Path

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
