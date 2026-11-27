"""The nightly test jobs rerun a flaky test and still name it (#1663).

ci.yml's Ubuntu and macOS shards pass `--reruns 2 --reruns-delay 2`; the
nightly passed none, so one flaky test turned it red and filed an issue (the
nights of 2026-11-15, #1634, and 2026-11-16, #1623, were one flake each). It
now reruns as the shards do, Windows still excepted, and a step lists every
test that needed a rerun as a warning, so a flake shows on a green run.
Nightly Extended Tests, the Ubuntu job that runs all of `tests/`, was left
without reruns (found 2026-11-18) and now has the same pair of steps.

These read the job from scheduled.yml and run its listing step's own script,
fed by a real pytest-rerunfailures run, as GitHub runs a step.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "scheduled.yml"
LOG = "nightly-pytest.log"
LISTING = "List the tests that passed only on a rerun"
# Each job with reruns, and the name of its last test step.
JOBS = {
    "nightly-cross-platform": "Run CLI tests",
    "nightly-extended-tests": "Run full test suite (including slow tests)",
}

needs_bash = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None,
    reason="the step runs as bash -eo pipefail",
)


def _steps(job: str = "nightly-cross-platform") -> list[dict]:
    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    return jobs[job]["steps"]


def _pytest_steps() -> list[dict]:
    return [s for s in _steps() if "pytest tests/" in s.get("run", "")]


def test_both_test_steps_rerun_off_windows_and_keep_their_exit_code() -> None:
    steps = _pytest_steps()
    assert [s["name"] for s in steps] == ["Run unit tests", "Run CLI tests"]
    for step in steps:
        flags = step["env"]["RERUN_FLAGS"]
        # ci.yml's macOS step pairs --reruns with -p no:xdist; Windows reruns
        # nothing there on purpose, and nothing here.
        assert "--reruns 2 --reruns-delay 2 -p no:xdist" in flags
        assert "matrix.os != 'windows-latest'" in flags
        assert '"${rerun_flags[@]}"' in step["run"]
        assert "-rfER" in step["run"], "without R a rerun has no id in the log"
        assert f"| tee -a {LOG}" in step["run"]
        # The pipe into tee fails the step on pytest's exit code only under
        # pipefail, which GitHub's `shell: bash` sets and its default sh does not.
        assert step["shell"] == "bash", step["name"]


def test_the_extended_suite_reruns_and_keeps_its_exit_code() -> None:
    job = "nightly-extended-tests"
    (step,) = [s for s in _steps(job) if s.get("name") == JOBS[job]]
    # One runner, Ubuntu, so the flags are written out rather than chosen by OS.
    assert "--reruns 2 --reruns-delay 2 -p no:xdist" in step["run"]
    assert "-rfER" in step["run"], "without R a rerun has no id in the log"
    assert f"| tee -a {LOG}" in step["run"]
    assert step["shell"] == "bash"


@pytest.mark.parametrize("job,last_test_step", JOBS.items())
def test_the_listing_step_runs_after_the_tests_whatever_they_did(
    job: str, last_test_step: str
) -> None:
    names = [s.get("name") for s in _steps(job)]
    listing = _steps(job)[names.index(LISTING)]
    assert names.index(LISTING) > names.index(last_test_step)
    assert listing["if"] == "always()"
    assert listing["shell"] == "bash"  # it runs on windows-latest too


def test_both_jobs_list_reruns_with_the_same_script() -> None:
    """The behavioural tests below run the cross-platform job's copy; this
    keeps the extended job's copy the same script."""
    scripts = {
        job: next(s["run"] for s in _steps(job) if s.get("name") == LISTING)
        for job in JOBS
    }
    assert len(set(scripts.values())) == 1, scripts


def _list(tmp_path: Path, log: bytes | None) -> subprocess.CompletedProcess:
    (step,) = [s for s in _steps() if s.get("name") == LISTING]
    script = tmp_path / "step.sh"
    script.write_bytes(step["run"].encode())
    if log is not None:
        (tmp_path / LOG).write_bytes(log)
    summary = tmp_path / "summary.md"
    summary.write_bytes(b"")
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        cwd=tmp_path,
        env={**os.environ, "GITHUB_STEP_SUMMARY": str(summary)},
        capture_output=True,
        text=True,
        timeout=60,
    )


FLAKY = """\
import pathlib

def test_flaky(tmp_path_factory):
    flag = pathlib.Path(__file__).with_name("tried")
    if not flag.exists():
        flag.write_bytes(b"")
        raise AssertionError("first try")

def test_steady():
    pass
"""


@needs_bash
def test_a_test_that_passed_on_a_rerun_is_a_warning(tmp_path) -> None:
    # The log comes from pytest-rerunfailures itself, with the step's flags, so
    # a change in how it prints a rerun fails here rather than going quiet.
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "test_flaky.py").write_bytes(FLAKY.encode())
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(suite / "test_flaky.py"),
            "-v",
            "-rfER",
            "--reruns",
            "2",
            "--reruns-delay",
            "0",
            "-p",
            "no:xdist",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            f"--basetemp={tmp_path / 'bt'}",
        ],
        capture_output=True,
        timeout=120,
    )
    assert run.returncode == 0, run.stdout.decode() + run.stderr.decode()

    done = _list(tmp_path, run.stdout + run.stderr)

    assert done.returncode == 0, done.stdout + done.stderr
    warnings = [ln for ln in done.stdout.splitlines() if ln.startswith("::warning")]
    assert len(warnings) == 1, done.stdout
    assert warnings[0].endswith("test_flaky.py::test_flaky")
    assert "test_steady" not in done.stdout
    assert "1 test(s) needed a rerun" in (tmp_path / "summary.md").read_text("utf-8")


@needs_bash
def test_a_night_with_no_rerun_passes_quietly(tmp_path) -> None:
    # grep finding nothing exits 1, which bash -e would make the step's failure.
    done = _list(tmp_path, b"tests/unit/test_a.py::test_x PASSED\n1 passed\n")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "No test needed a rerun." in done.stdout
    assert "::warning" not in done.stdout


@needs_bash
def test_no_log_at_all_passes_and_says_so(tmp_path) -> None:
    # The test steps never ran (an install failed); that failure is theirs.
    done = _list(tmp_path, None)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "did not run" in done.stdout
