"""Unit tests for should_merge() in scripts/dev/auto_merge_tool_bumps.py.

The soak-window logic is the safety seam between "auto-PR was opened" and
"auto-PR silently merges into main". It must:

  * Never merge before the soak window elapses (default 24h).
  * Flip a PR to needs-review as soon as any required check fails, even
    inside the soak window — quicker feedback to the maintainer.
  * Respect maintainer intervention — if the auto-merge-ok label has been
    removed, defer forever.

Getting any of these three wrong produces either surprise merges or stuck
PRs, so the fabricated-PR test suite covers each axis explicitly.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest


def _load_module():
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "dev"
        / "auto_merge_tool_bumps.py"
    )
    spec = importlib.util.spec_from_file_location("auto_merge_tool_bumps", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


auto_merge = _load_module()
should_merge = auto_merge.should_merge


NOW = datetime(2026, 4, 20, 12, 0, 0, tzinfo=timezone.utc)


def _pr(
    *,
    age_hours: float,
    labels: list[str],
    checks: list[dict[str, str]],
    number: int = 42,
) -> dict[str, Any]:
    created_at = (NOW - timedelta(hours=age_hours)).isoformat().replace("+00:00", "Z")
    return {
        "number": number,
        "createdAt": created_at,
        "labels": [{"name": label} for label in labels],
        "statusCheckRollup": checks,
    }


def test_defers_when_auto_merge_label_missing() -> None:
    """Maintainer removed the auto-merge-ok label → never merge."""
    pr = _pr(
        age_hours=48,
        labels=["dependencies", "automated"],
        checks=[{"name": "ci", "conclusion": "SUCCESS"}],
    )
    assert should_merge(pr, NOW, min_age_hours=24) == "defer"


def test_defers_inside_soak_window() -> None:
    """Green checks but PR is too young → defer."""
    pr = _pr(
        age_hours=12,
        labels=["auto-merge-ok"],
        checks=[{"name": "ci", "conclusion": "SUCCESS"}],
    )
    assert should_merge(pr, NOW, min_age_hours=24) == "defer"


def test_merges_when_soak_elapsed_and_green() -> None:
    pr = _pr(
        age_hours=25,
        labels=["auto-merge-ok"],
        checks=[
            {"name": "quick-checks", "conclusion": "SUCCESS"},
            {"name": "tool-contract-tests", "conclusion": "SUCCESS"},
        ],
    )
    assert should_merge(pr, NOW, min_age_hours=24) == "merge"


def test_skipped_and_neutral_count_as_green() -> None:
    """A contract-tests job that SKIPped install+pytest is still a pass."""
    pr = _pr(
        age_hours=25,
        labels=["auto-merge-ok"],
        checks=[
            {"name": "quick-checks", "conclusion": "SUCCESS"},
            {"name": "tool-contract-tests", "conclusion": "SKIPPED"},
            {"name": "lint-quick", "conclusion": "NEUTRAL"},
        ],
    )
    assert should_merge(pr, NOW, min_age_hours=24) == "merge"


def test_flips_on_failed_check_even_inside_soak() -> None:
    """A FAILURE inside the soak window still triggers the flip — faster feedback."""
    pr = _pr(
        age_hours=2,
        labels=["auto-merge-ok"],
        checks=[
            {"name": "quick-checks", "conclusion": "SUCCESS"},
            {"name": "tool-contract-tests", "conclusion": "FAILURE"},
        ],
    )
    assert should_merge(pr, NOW, min_age_hours=24) == "flip"


def test_flips_on_cancelled_required_check() -> None:
    pr = _pr(
        age_hours=30,
        labels=["auto-merge-ok"],
        checks=[
            {"name": "ci", "conclusion": "SUCCESS"},
            {"name": "tool-contract-tests", "conclusion": "CANCELLED"},
        ],
    )
    assert should_merge(pr, NOW, min_age_hours=24) == "flip"


def test_flips_on_timed_out_check() -> None:
    pr = _pr(
        age_hours=30,
        labels=["auto-merge-ok"],
        checks=[{"name": "tool-contract-tests", "conclusion": "TIMED_OUT"}],
    )
    assert should_merge(pr, NOW, min_age_hours=24) == "flip"


def test_defers_when_checks_still_running() -> None:
    """PR is old enough but some required check hasn't reported yet → defer."""
    pr = _pr(
        age_hours=25,
        labels=["auto-merge-ok"],
        checks=[
            {"name": "quick-checks", "conclusion": "SUCCESS"},
            {"name": "tool-contract-tests", "conclusion": ""},  # in progress
        ],
    )
    assert should_merge(pr, NOW, min_age_hours=24) == "defer"


def test_defers_when_no_checks_reported() -> None:
    """Brand-new PR, checks haven't started yet — don't treat empty as green."""
    pr = _pr(
        age_hours=25,
        labels=["auto-merge-ok"],
        checks=[],
    )
    assert should_merge(pr, NOW, min_age_hours=24) == "defer"


def test_zero_soak_window_merges_immediately() -> None:
    """--min-age-hours=0 is the verification mode — merges as soon as checks are green."""
    pr = _pr(
        age_hours=0.1,
        labels=["auto-merge-ok"],
        checks=[{"name": "ci", "conclusion": "SUCCESS"}],
    )
    assert should_merge(pr, NOW, min_age_hours=0) == "merge"


# --- merge_pr() outcome handling ------------------------------------------
#
# should_merge() decides intent from the status rollup, but whether the merge
# actually lands is only knowable at `gh pr merge` time: a required check that
# never ran (the personal-repo GITHUB_TOKEN constraint) isn't in the rollup, so
# the rollup looks green yet the merge is refused. merge_pr() must distinguish
# that permanent block (surface for manual admin-merge, keep the cron green)
# from a transient failure (re-raise so the next cron cycle retries).


def _completed(returncode: int, *, stderr: str = "", stdout: str = ""):
    return subprocess.CompletedProcess(
        args=["gh", "pr", "merge"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_merge_pr_dry_run_reports_merged_without_calling_gh() -> None:
    with patch("subprocess.run") as mock_run:
        assert auto_merge.merge_pr(42, dry_run=True) == "merged"
    mock_run.assert_not_called()


def test_merge_pr_success_returns_merged() -> None:
    with patch("subprocess.run", return_value=_completed(0)) as mock_run:
        assert auto_merge.merge_pr(42, dry_run=False) == "merged"
    mock_run.assert_called_once()


@pytest.mark.parametrize(
    "stderr",
    [
        "Pull request is not mergeable: the base branch policy prohibits the merge.",
        "GraphQL: Changes must be made through a pull request. (mergePullRequest)",
        "1 required status check is expected. (quick-checks)",
        "merge is blocked by branch protection rules",
        "At least 1 approving review is required by reviewers with write access.",
    ],
)
def test_merge_pr_permanent_block_returns_blocked(stderr: str) -> None:
    """Branch-protection refusals are classified as 'blocked', not raised."""
    with patch("subprocess.run", return_value=_completed(1, stderr=stderr)):
        assert auto_merge.merge_pr(42, dry_run=False) == "blocked"


@pytest.mark.parametrize(
    "stderr",
    [
        "error connecting to api.github.com: timeout",
        "HTTP 502: Bad Gateway",
        "",  # opaque non-zero exit with no recognizable marker → transient
    ],
)
def test_merge_pr_transient_failure_reraises(stderr: str) -> None:
    """Unknown/transient failures must re-raise so the next cron cycle retries."""
    with patch("subprocess.run", return_value=_completed(1, stderr=stderr)):
        with pytest.raises(subprocess.CalledProcessError):
            auto_merge.merge_pr(42, dry_run=False)


def test_flip_blocked_pr_removes_label_and_comments() -> None:
    """A blocked PR self-heals the label, relabels needs-review, and comments."""
    with patch("subprocess.run", return_value=_completed(0)) as mock_run:
        auto_merge.flip_blocked_pr(494, dry_run=False)
    # Three gh calls: ensure-label (self-heal), edit (relabel), comment.
    assert mock_run.call_count == 3
    create_args = mock_run.call_args_list[0].args[0]
    assert create_args[:3] == ["gh", "label", "create"]
    assert auto_merge.NEEDS_REVIEW_LABEL in create_args
    assert "--force" in create_args  # idempotent upsert, never the red-maker
    edit_args = mock_run.call_args_list[1].args[0]
    assert "edit" in edit_args
    assert "--remove-label" in edit_args
    assert auto_merge.AUTO_MERGE_LABEL in edit_args
    assert auto_merge.NEEDS_REVIEW_LABEL in edit_args
    comment_body = mock_run.call_args_list[2].args[0][-1]
    # Comment must hand the maintainer the exact admin-merge command.
    assert "gh pr merge 494 --squash --admin" in comment_body


def test_ensure_label_never_raises_on_failure() -> None:
    """Label bookkeeping must never be the thing that crashes the cron."""
    # check=False means a non-zero `gh label create` is swallowed, not raised.
    with patch("subprocess.run", return_value=_completed(1, stderr="boom")):
        auto_merge._ensure_label("needs-review", "d93f0b", "desc")  # no exception


def test_flip_blocked_pr_dry_run_makes_no_gh_calls() -> None:
    with patch("subprocess.run") as mock_run:
        auto_merge.flip_blocked_pr(494, dry_run=True)
    mock_run.assert_not_called()
