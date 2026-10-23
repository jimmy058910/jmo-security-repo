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


def test_every_step_that_looks_up_releases_has_a_github_token() -> None:
    """Each tool-update step that asks GitHub for a release carries GH_TOKEN.

    `update_versions.py` looks up GitHub-hosted tools with `gh api`, and `gh`
    refuses to run in Actions without GH_TOKEN (exit 4). The lookup reports that
    as "Failed to check latest version", so the job still succeeds and its PR
    still looks complete: 13 tools failed this way on the 2026-10-18 and
    2026-10-23 runs, and only PyPI tools ever moved. The token belongs on each
    step, not on the job, because the job also runs third-party pre-commit hooks.
    `--sync` reads versions.yaml only and needs no token.
    """
    lookups = [
        step
        for step in _job_steps("auto-update-tools")
        if re.search(
            r"update_versions\.py --(check-latest|classify|update-all)\b",
            step.get("run", ""),
        )
    ]

    assert len(lookups) >= 3, [step.get("name") for step in lookups]
    for step in lookups:
        assert "GH_TOKEN" in step.get("env", {}), step["name"]


def test_only_the_weekly_job_moves_ruff_mypy_and_bandit() -> None:
    """Dependabot must leave the pin pair to the weekly tool-update job (#1435).

    `test_toolchain_version_agreement.py` compares every pre-commit hook whose
    `id` is also a package in `uv.lock`: today ruff, mypy and bandit. A Dependabot
    PR that moves one side (the lock through `uv`, or the hook rev through
    `pre-commit`) fails that guard until the other side is moved by hand. The weekly
    job moves both together, so it is the only lane allowed to touch them. The
    pre-commit names are repo URLs because that is how Dependabot titles those PRs
    (#1451, #1360).
    """
    names = {
        "uv": {"ruff", "mypy", "bandit"},
        "pre-commit": {
            "https://github.com/astral-sh/ruff-pre-commit",
            "https://github.com/pre-commit/mirrors-mypy",
            "https://github.com/PyCQA/bandit",
        },
    }

    for ecosystem, expected in names.items():
        (eco,) = _dependabot(ecosystem)
        ignored = {i["dependency-name"] for i in eco.get("ignore", [])}
        assert expected <= ignored, (ecosystem, sorted(expected - ignored))


def test_superseded_prs_are_closed_after_the_new_one_opens() -> None:
    """Last week's PR is closed only once this week's PR exists.

    Closing first leaves no open tool PR at all when `gh pr create` fails. The
    orphan-branch cleanup must also come before the close step: it fires on any
    earlier failure and deletes the new branch, which would take the new PR with
    it if a failure inside the close step could reach it.
    """
    runs = [step.get("run", "") for step in _job_steps("auto-update-tools")]
    create = next(
        i
        for i, run in enumerate(runs)
        if re.search(r"^\s*gh pr create\b", run, re.MULTILINE)
    )
    cleanup = next(i for i, run in enumerate(runs) if "git push origin --delete" in run)
    close = next(i for i, run in enumerate(runs) if "gh pr close" in run)

    assert create < cleanup < close
