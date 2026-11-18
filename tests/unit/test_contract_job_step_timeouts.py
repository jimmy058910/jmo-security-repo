"""A hang in Tool Output Contract Tests ends a step, not the job (#1631).

Run 41627396139 (2026-11-03) hung in the contract tests' pytest step for 45
minutes, reached the job's timeout-minutes and ended `cancelled`, and GitHub
kept no log of it (BlobNotFound). A step's own timeout-minutes ends it as a
failed step inside a job that still runs to the end, so the job's later steps
and its log upload happen. That only works while every long step's limit sits
inside the job's: if they add up past it, a slow step can still run the job out.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "scheduled.yml"

# The slowest of the six green runs before 2026-11-17 (44166694920 back to
# 42020822764), in seconds, read from each job's step timings.
SLOWEST_GREEN_S = {
    "Run tool contract tests": 308,
    "Re-capture every golden fixture through jmo scan": 115,
    "Run the answer-key tests": 941,
}


def _job() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"][
        "tool-contract-tests"
    ]


def _long_steps(job: dict) -> list[dict]:
    """The steps that run the suites or the scans: the ones that can hang."""
    return [
        s
        for s in job["steps"]
        if "pytest " in s.get("run", "") or "generate_golden.py" in s.get("run", "")
    ]


def test_the_long_steps_are_found() -> None:
    names = {s["name"] for s in _long_steps(_job())}
    assert names == set(SLOWEST_GREEN_S), names


def test_every_long_step_has_a_limit_with_room_over_its_slowest_green_run() -> None:
    for step in _long_steps(_job()):
        limit_s = step.get("timeout-minutes", 0) * 60
        slowest = SLOWEST_GREEN_S[step["name"]]
        # Twice the slowest: runner speed alone moved one tree's windows-2022
        # step from 633 s to 872 s (#1637), and a limit that cuts a healthy run
        # off is a red nightly for nothing.
        assert limit_s >= 2 * slowest, (step["name"], limit_s, slowest)


def test_the_step_limits_fit_inside_the_job_limit() -> None:
    job = _job()
    total = sum(s["timeout-minutes"] for s in _long_steps(job))
    # The installs and fetches before them take about two minutes; ten is room.
    assert total + 10 <= job["timeout-minutes"], (total, job["timeout-minutes"])
