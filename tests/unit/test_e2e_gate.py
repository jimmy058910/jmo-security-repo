"""The scheduled e2e gate fails a run whose suites errored (#1502).

e2e-ubuntu and e2e-macos run pytest under `continue-on-error: true`, so their
jobs read green whatever pytest found, and `e2e-summary`'s two steps are the
gate: one sums each suite's `pytest-report.json`, the next fails the run. It
summed `summary.failed` only, so the nightly at c05aef28 printed "reported zero
failures" over 7 + 4 errors (#1502); ceebae79 (#1548) added `summary.error`.
Nothing tested the gate. These run the two steps' own scripts, read from
scheduled.yml, as GitHub runs a step (`bash -eo pipefail`).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "scheduled.yml"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32"
    or shutil.which("bash") is None
    or not shutil.which("python3"),
    reason="the gate runs on ubuntu-latest, as bash calling python3",
)


def _step(name: str) -> dict:
    jobs = yaml.safe_load(WORKFLOW.read_bytes())["jobs"]
    (step,) = [s for s in jobs["e2e-summary"]["steps"] if s.get("name") == name]
    return step


def _run(step: dict, tmp_path: Path, env: dict[str, str]):
    script = tmp_path / "step.sh"
    script.write_bytes(step["run"].encode())
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        cwd=tmp_path,
        env={**os.environ, **step.get("env", {}), **env},
        capture_output=True,
        text=True,
        timeout=60,
    )


def _gate(tmp_path: Path, reports: dict[str, dict]):
    """Write one pytest-report.json per suite, run the summary step, then the
    gate with what the summary wrote to GITHUB_ENV."""
    for suite, summary in reports.items():
        out = tmp_path / "test-results" / f"e2e-{suite}-results-1"
        out.mkdir(parents=True)
        (out / "pytest-report.json").write_bytes(
            json.dumps({"summary": summary}).encode()
        )
    github_env = tmp_path / "github_env"
    github_env.write_bytes(b"")
    files = {
        "GITHUB_ENV": str(github_env),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "s.md"),
    }

    summed = _run(_step("Aggregate results"), tmp_path, files)
    assert summed.returncode == 0, summed.stderr
    written = dict(
        line.split("=", 1) for line in github_env.read_bytes().decode().splitlines()
    )
    return _run(_step("Fail the run if any e2e test failed"), tmp_path, written)


CLEAN = {"total": 30, "passed": 25, "skipped": 5}


def test_two_clean_suites_pass(tmp_path) -> None:
    done = _gate(tmp_path, {"ubuntu": CLEAN, "macos": CLEAN})
    assert done.returncode == 0, done.stdout + done.stderr
    assert "zero failures and zero errors" in done.stdout


def test_one_error_and_no_failure_fails_the_run(tmp_path) -> None:
    # #1502: an errored test never reached a verdict, and 11 of them read as 0.
    errored = {"total": 30, "passed": 24, "skipped": 5, "error": 1}
    done = _gate(tmp_path, {"ubuntu": errored, "macos": CLEAN})
    assert done.returncode == 1
    assert "1 e2e test(s) errored" in done.stdout


def test_one_failure_fails_the_run(tmp_path) -> None:
    failed = {"total": 30, "passed": 24, "skipped": 5, "failed": 1}
    done = _gate(tmp_path, {"ubuntu": CLEAN, "macos": failed})
    assert done.returncode == 1
    assert "1 e2e test(s) failed" in done.stdout


def test_a_suite_with_no_report_fails_the_run(tmp_path) -> None:
    done = _gate(tmp_path, {"ubuntu": CLEAN})
    assert done.returncode == 1
    assert "macos" in done.stdout
