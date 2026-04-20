#!/usr/bin/env python3
"""
Soak-window auto-merge for tool-version bump PRs.

This script is Layer 3 of the tool-version automation stack (Layer 1 = exit-0
on outdated, Layer 2 = --create-issues dashboard, Layer 3 = auto-PR + soak
auto-merge). It runs on a cron schedule every 6 hours and takes three actions:

  * merge — PR is >= min_age_hours old, has label auto-merge-ok, and all
    required status checks are green. Squash-merge it.
  * flip  — PR has label auto-merge-ok but a required status check failed.
    Remove auto-merge-ok, add needs-review, post an explanatory comment so
    the maintainer sees the failed check on the next dashboard scan.
  * defer — Everything else: still in soak window, checks still running,
    maintainer already intervened. Leave the PR alone.

The decision logic is isolated in the pure `should_merge()` function — it
takes a parsed PR dict + current time + soak window and returns an action.
That isolation is load-bearing for testability: the unit tests can fabricate
PR payloads and assert decisions without touching the GitHub API.

Usage:
  python3 scripts/dev/auto_merge_tool_bumps.py [--min-age-hours N] [--dry-run]

Required env: GH_TOKEN (provided automatically in GitHub Actions).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from typing import Literal

Action = Literal["merge", "defer", "flip"]

# Conclusions that mean "this check definitively failed". We treat all of
# these as blocking — a cancelled or timed-out required check is just as
# much a regression signal as an outright FAILURE.
_FAILED_CONCLUSIONS = frozenset(
    {"FAILURE", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED", "STARTUP_FAILURE"}
)

# Conclusions that count as "green" for merge purposes. SKIPPED and NEUTRAL
# are explicitly green — the contract-tests job SKIPs install+pytest when no
# versions.yaml/Dockerfile.* change; that's still a pass.
_GREEN_CONCLUSIONS = frozenset({"SUCCESS", "SKIPPED", "NEUTRAL"})

AUTO_MERGE_LABEL = "auto-merge-ok"
NEEDS_REVIEW_LABEL = "needs-review"


def _parse_iso(timestamp: str) -> datetime:
    """Parse the ISO-8601 UTC timestamp that `gh` returns for createdAt."""
    # `gh` emits "2026-04-19T00:00:00Z"; Python 3.11+ fromisoformat handles
    # the trailing Z since 3.11 but we normalize to +00:00 for 3.10 safety.
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def should_merge(pr: dict, now: datetime, min_age_hours: int) -> Action:
    """
    Decide what to do with a candidate PR.

    Args:
        pr: PR dict as emitted by `gh pr list --json createdAt,labels,statusCheckRollup`.
        now: Current time (UTC, tz-aware).
        min_age_hours: Minimum PR age before auto-merge is allowed.

    Returns:
        "merge" | "defer" | "flip"
    """
    labels = {label["name"] for label in pr.get("labels", [])}
    if AUTO_MERGE_LABEL not in labels:
        # Maintainer has already intervened (dropped the label) or it was
        # never added — leave the PR to the human.
        return "defer"

    checks = pr.get("statusCheckRollup") or []

    # Fail-fast: any definitively-failed required check flips the label to
    # needs-review. We do this BEFORE the age check so a PR with an obvious
    # failure gets a comment and relabel immediately instead of waiting 24h.
    for check in checks:
        if check.get("conclusion") in _FAILED_CONCLUSIONS:
            return "flip"

    age_hours = (now - _parse_iso(pr["createdAt"])).total_seconds() / 3600.0
    if age_hours < min_age_hours:
        return "defer"

    # Still in the soak window cleared. Every check must be green (SUCCESS /
    # SKIPPED / NEUTRAL) — checks still running mean we wait another cycle.
    if not checks:
        # No checks reported yet — too early, even if the PR is old.
        return "defer"
    for check in checks:
        if check.get("conclusion") not in _GREEN_CONCLUSIONS:
            return "defer"

    return "merge"


def list_candidate_prs() -> list[dict]:
    """Fetch open PRs labeled `auto-merge-ok` + `automated` from the repo."""
    proc = subprocess.run(
        [
            "gh",
            "pr",
            "list",
            "--state",
            "open",
            "--label",
            AUTO_MERGE_LABEL,
            "--label",
            "automated",
            "--json",
            "number,createdAt,labels,statusCheckRollup,title",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    data: list[dict] = json.loads(proc.stdout or "[]")
    return data


def merge_pr(number: int, dry_run: bool) -> None:
    print(f"[auto-merge] PR #{number}: merge (squash)")
    if dry_run:
        return
    subprocess.run(
        ["gh", "pr", "merge", str(number), "--squash", "--delete-branch"],
        check=True,
    )


def flip_pr_label(number: int, failed_checks: list[str], dry_run: bool) -> None:
    names = ", ".join(f"`{n}`" for n in failed_checks) or "(unknown)"
    comment = (
        f"Auto-merge blocked: one or more required checks failed ({names}). "
        f"Label flipped from `{AUTO_MERGE_LABEL}` to `{NEEDS_REVIEW_LABEL}`. "
        "Investigate the failure, push a fix, and re-add `auto-merge-ok` to "
        "resume the soak window."
    )
    print(f"[auto-merge] PR #{number}: flip label (failed: {names})")
    if dry_run:
        return
    subprocess.run(
        [
            "gh",
            "pr",
            "edit",
            str(number),
            "--remove-label",
            AUTO_MERGE_LABEL,
            "--add-label",
            NEEDS_REVIEW_LABEL,
        ],
        check=True,
    )
    subprocess.run(
        ["gh", "pr", "comment", str(number), "--body", comment],
        check=True,
    )


def _failed_check_names(pr: dict) -> list[str]:
    return [
        check.get("name", "<unnamed>")
        for check in pr.get("statusCheckRollup") or []
        if check.get("conclusion") in _FAILED_CONCLUSIONS
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--min-age-hours",
        type=int,
        default=24,
        help="Minimum PR age (hours) before auto-merge may fire. Default: 24.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print intended actions without calling gh pr merge / edit / comment.",
    )
    args = parser.parse_args()

    try:
        prs = list_candidate_prs()
    except subprocess.CalledProcessError as exc:
        print(f"[auto-merge] gh pr list failed: {exc}", file=sys.stderr)
        return 1

    if not prs:
        # Silent exit — cron runs every 6h and most runs will find nothing.
        return 0

    now = datetime.now(timezone.utc)
    for pr in prs:
        action = should_merge(pr, now, args.min_age_hours)
        number = int(pr["number"])
        if action == "merge":
            merge_pr(number, dry_run=args.dry_run)
        elif action == "flip":
            flip_pr_label(number, _failed_check_names(pr), dry_run=args.dry_run)
        else:
            print(f"[auto-merge] PR #{number}: defer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
