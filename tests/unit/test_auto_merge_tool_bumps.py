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
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


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
