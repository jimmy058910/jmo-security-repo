"""Guards on the weekly maintenance automation's GitHub-side configuration.

The weekly tool-update PR used to target `main` and be merged by a 6-hourly
"soak" cron job once the PR was 24h old. A PR opened with `GITHUB_TOKEN` gets no
CI run, and `dev` has no required checks, so on `dev` that same cron would merge
an unverified bot PR blind. The merge now belongs to the weekly maintenance
routine, which merges only after a CI run it dispatched is green. These tests
keep the workflow from drifting back.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
MAINTENANCE_YML = REPO_ROOT / ".github" / "workflows" / "maintenance.yml"
DEPENDABOT_YML = REPO_ROOT / ".github" / "dependabot.yml"


def _job_steps(job_id: str) -> list[dict]:
    """The `steps:` of one job in maintenance.yml, parsed (comments dropped)."""
    workflow = yaml.safe_load(MAINTENANCE_YML.read_text(encoding="utf-8"))
    return workflow["jobs"][job_id]["steps"]


def _dependabot(*ecosystems: str) -> list[dict]:
    """The `updates:` blocks of dependabot.yml for the named package ecosystems."""
    config = yaml.safe_load(DEPENDABOT_YML.read_text(encoding="utf-8"))
    return [u for u in config["updates"] if u["package-ecosystem"] in ecosystems]


def test_no_workflow_merges_the_weekly_tool_pr() -> None:
    """Nothing in maintenance.yml may merge the bot PR on a schedule.

    On `dev` there are no required checks, and a PR opened by `GITHUB_TOKEN` runs
    no CI, so a cron merger would merge a CI-less bot PR blind. The check is on
    the raw text, comments included: a leftover mention of the old merger is how
    it gets re-wired by someone following the comment.
    """
    text = MAINTENANCE_YML.read_text(encoding="utf-8")

    assert "gh pr merge" not in text
    assert "auto_merge_tool_bumps" not in text


def test_weekly_tool_pr_targets_dev() -> None:
    """The weekly PR is opened against `dev`, and by exactly one command.

    Bot PRs against `main` widen a divergence the release must cross; the
    routine merges into `dev` and Jimmy owns the `dev` to `main` sync. Steps are
    matched on `gh pr create` at the start of a line, because other steps quote
    the command inside a warning message and in comments.
    """
    create = [
        step["run"]
        for step in _job_steps("auto-update-tools")
        if re.search(r"^\s*gh pr create\b", step.get("run", ""), re.MULTILINE)
    ]

    assert len(create) == 1
    assert "--base dev" in create[0]


def test_weekly_tool_branch_is_built_from_dev() -> None:
    """The weekly branch is cut from `dev`, the branch its PR targets.

    A checkout with no `ref:` gets the default branch on a scheduled run and on
    the documented `--ref main` dispatch. The tool edits would then be computed
    against `main`'s `versions.yaml`, `.pre-commit-config.yaml` and `uv.lock`
    while the PR lands on `dev`, which is normally ahead of `main`: the PR could
    drag `main`-only commits into `dev`, and the CI run dispatched against it
    would test the wrong tree.
    """
    checkout = next(
        step
        for step in _job_steps("auto-update-tools")
        if step.get("uses", "").startswith("actions/checkout@")
    )

    assert checkout.get("with", {}).get("ref") == "dev"
