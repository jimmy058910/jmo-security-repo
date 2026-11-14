"""The scheduled e2e gate fails a run whose suites errored (#1502).

e2e-ubuntu and e2e-macos run pytest under `continue-on-error: true`, so their
jobs read green whatever pytest found, and `e2e-summary`'s two steps are the
gate: one sums each suite's `pytest-report.json`, the next fails the run. It
summed `summary.failed` only, so the nightly at c05aef28 printed "reported zero
failures" over 7 + 4 errors (#1502); ceebae79 (#1548) added `summary.error`.
Nothing tested the gate. These run the two steps' own scripts, read from
scheduled.yml, as GitHub runs a step (`bash -eo pipefail`).

The reports say nothing about a job that wrote none, so a third step fails the
summary unless every job it needs succeeded (#1565), and the same reading of a
result guards validation-summary.
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


def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_bytes())["jobs"]


def _step(name: str, job: str = "e2e-summary") -> dict:
    (step,) = [s for s in _jobs()[job]["steps"] if s.get("name") == name]
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


# A job that hits its timeout-minutes ends `cancelled`, which the notify job's
# failure() does not see, and the report gate above reads only the two suites'
# pytest-report.json. Run 41627396139 cancelled Tool Output Contract Tests at
# its limit and filed no issue (#1565).
JOBS_GATE = "Fail the run if an e2e job did not succeed"


def _needs(**overrides: str) -> str:
    needs = dict.fromkeys(_jobs()["e2e-summary"]["needs"], "success")
    needs.update(overrides)
    return json.dumps({job: {"result": r, "outputs": {}} for job, r in needs.items()})


def test_the_jobs_gate_reads_every_job_the_summary_needs() -> None:
    step = _step(JOBS_GATE)
    assert step["env"]["NEEDS"] == "${{ toJSON(needs) }}"
    # The report gate before it exits 1 on a failed suite; this one still runs.
    assert step["if"] == "always()"
    assert set(_jobs()["e2e-summary"]["needs"]) >= {
        "e2e-ubuntu",
        "e2e-macos",
        "tool-contract-tests",
    }


def test_every_job_succeeding_passes(tmp_path) -> None:
    done = _run(_step(JOBS_GATE), tmp_path, {"NEEDS": _needs()})
    assert done.returncode == 0, done.stdout + done.stderr
    assert "e2e jobs succeeded" in done.stdout


@pytest.mark.parametrize("result", ["cancelled", "failure", "skipped"])
def test_a_job_that_did_not_succeed_fails_the_run(tmp_path, result) -> None:
    done = _run(
        _step(JOBS_GATE), tmp_path, {"NEEDS": _needs(**{"tool-contract-tests": result})}
    )
    assert done.returncode == 1
    assert f"tool-contract-tests ended {result}, not success" in done.stdout


def test_no_needs_read_fails_the_run(tmp_path) -> None:
    done = _run(_step(JOBS_GATE), tmp_path, {"NEEDS": "{}"})
    assert done.returncode == 1
    assert "read no result" in done.stdout


@pytest.mark.parametrize(
    ("result", "rc"), [("success", 0), ("cancelled", 1), ("failure", 1)]
)
def test_the_image_validation_summary_fails_unless_validation_succeeded(
    tmp_path, result, rc
) -> None:
    step = _step("Check validation results", job="validation-summary")
    done = _run(step, tmp_path, {"RESULT": result})
    assert done.returncode == rc, done.stdout + done.stderr


def test_the_notify_job_files_for_the_default_branch_and_for_a_timeout() -> None:
    """A branch dispatch filed #1549 and #1600 (#1559); a timed-out job filed
    nothing (#1565). GitHub evaluates the expression, so this reads it."""
    condition = " ".join(_jobs()["nightly-notify-failure"]["if"].split())
    assert "github.event.repository.default_branch" in condition
    assert "github.event_name == 'schedule'" in condition
    assert "contains(needs.*.result, 'cancelled')" in condition
    # always(): with the default success() or !cancelled() in front, whether a
    # timed-out job still files would rest on how GitHub sets cancelled().
    assert condition.startswith("always() && ")
