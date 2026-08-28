#!/usr/bin/env python3
"""Guard: the remedy `dashboard-smoke` prints must be written down somewhere.

Regression for #1036.

Phase 7 (#862) started tracking `scripts/dashboard/dist/index.html` and gave
`dashboard-smoke` a freshness gate. `package.json` and `package-lock.json` are
build inputs inside that gate's paths filter, deliberately -- a dependency
change can invalidate a bundle exactly as a source change does. So a dependency
bump can turn the job red, and the only fix is a human running `npm run build`
and committing the artifact, because Dependabot cannot.

The job already prints that remedy on failure. What was missing is that it
existed **nowhere a person looks before the failure**, which matters because
`dashboard-smoke` is advisory today and is planned for promotion to required.

## What is asserted

That the command and directory CI names in its own error message are the same
ones `.claude/rules/release.rules.md` names. Both are *derived*, not restated:
the expectation is read out of `ci.yml`, so changing the remedy there and not
the docs reddens this, and so does the reverse.

`release.rules.md` is tracked, so a contributor receives it. The
weekly-maintenance routine that also carries this is maintainer-local and
untracked, and is deliberately NOT referenced here -- a tracked file naming an
untracked path is what `scripts/dev/check_doc_links.py` exists to reject.

## What is NOT asserted

Whether a given bump actually requires a rebuild. It often does not: measured on
#1025, `lucide-react` 1.33.0 -> 1.34.0 plus a types-only bump rebuilt
byte-identically, because the release only added an icon the dashboard does not
import. The gate is the oracle for that question; this guard only ensures the
answer to "it went red, now what?" is written down.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_RULES = REPO_ROOT / ".claude" / "rules" / "release.rules.md"

# `echo "Run 'npm run build' in scripts/dashboard/ and commit the result."`
#
# Anchored on the quoted command so the directory is captured separately. Both
# halves matter to a reader: the wrong directory is as unhelpful as the wrong
# command, and `npm run build` alone appears in several unrelated places.
_REMEDY = re.compile(r"Run '([^']+)' in (\S+?)/? and commit")


@pytest.fixture(scope="module")
def remedy() -> tuple[str, str]:
    """The (command, directory) `dashboard-smoke` tells a human to run.

    Fails rather than skips when it cannot find one. An extractor that silently
    returns nothing satisfies every assertion built on it, which is how a guard
    ends up green over the thing it was written to catch.
    """
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    matches = _REMEDY.findall(text)
    assert matches, (
        "no `Run '<cmd>' in <dir> and commit` remedy found in ci.yml. Either the "
        "dashboard freshness gate was removed -- in which case delete this guard "
        "deliberately -- or its error message was reworded and this extractor is "
        "now blind, which is the failure it must not have."
    )
    assert len(matches) == 1, f"expected one remedy message, found {len(matches)}"
    return matches[0]


def test_ci_still_prints_the_remedy_this_guard_derives_from(
    remedy: tuple[str, str],
) -> None:
    """Meta-guard: pin what was extracted, so a silent reword is visible."""
    command, directory = remedy
    assert command == "npm run build"
    assert directory == "scripts/dashboard"


def test_release_rules_documents_the_remedy(remedy: tuple[str, str]) -> None:
    """The tracked rules file must name the same command and directory."""
    command, directory = remedy
    docs = RELEASE_RULES.read_text(encoding="utf-8")
    assert command in docs, (
        f"`release.rules.md` does not name {command!r}, which is what "
        "`dashboard-smoke` tells a human to run when the bundle is stale"
    )
    assert directory in docs, (
        f"`release.rules.md` does not name {directory!r}, the directory the "
        "rebuild has to happen in"
    )


def test_the_documented_remedy_names_the_bundle_it_repairs() -> None:
    """The path a reader has to commit, not just the command they run.

    Derived from the gate's own subject rather than restated: `ci.yml` names
    this file in the step that fails, so the docs must too.
    """
    bundle = "scripts/dashboard/dist/index.html"
    assert bundle in CI_WORKFLOW.read_text(
        encoding="utf-8"
    ), "ci.yml no longer names the tracked bundle; this guard's premise moved"
    assert bundle in RELEASE_RULES.read_text(encoding="utf-8")


def test_the_remedy_is_documented_in_a_tracked_file() -> None:
    """A remedy in an untracked file is a remedy no contributor receives.

    `.claude/` is a mixed surface: some of it ships and most of it does not, by
    an explicit per-skill allowlist in `.gitignore`. `release.rules.md` is on
    the tracked side; the weekly-maintenance routine that carries the same note
    is not, which is why the note had to land here as well.
    """
    import subprocess

    proc = subprocess.run(
        [
            "git",
            "ls-files",
            "--error-unmatch",
            str(RELEASE_RULES.relative_to(REPO_ROOT)),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, (
        f"{RELEASE_RULES.relative_to(REPO_ROOT)} is not tracked, so a clone does "
        "not receive the remedy this guard asserts is documented"
    )
