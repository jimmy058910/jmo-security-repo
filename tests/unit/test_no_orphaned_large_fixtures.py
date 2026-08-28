#!/usr/bin/env python3
"""Guard: a large tracked fixture must be named by something that reads it.

Regression for #1032.

Three vendored dashboard builds accumulated under `tests/fixtures/dashboard/`,
each a one-off artifact from a debugging session that nobody regenerated and
nothing checked:

    test-inline-dashboard.html     697 KB  deleted in Phase 7 (#864)
    test-external-dashboard.html   624 KB  deleted here (#1032)
    test_trend_report.html         6.6 KB  deleted here -- #1032 called it
                                           "not audited"; audited, 0 consumers

`test-inline-dashboard.html` was at least reachable once: `write_html` used to
fall back to it when `scripts/dashboard/dist/` was gitignored. #862 tracked the
real bundle, that rung disappeared, and the artifact stayed. The other two were
never read by any test, workflow or module -- every reference is prose under
`dev-only/archive/1.0.0/`, which a clone does not receive.

## What is asserted

Every tracked file under `tests/fixtures/` above `SIZE_FLOOR` must have its
basename mentioned in some other tracked file. That is a weak test of "is
read" -- a fixture reached by a constructed path or a directory glob would be
a false positive -- and it is deliberately weak, because the failure it catches
is not subtle: 624 KB in every clone that nothing anywhere names.

The floor exists so this cannot become a general orphan hunt over 20 small
sample files, which is a different and much noisier question.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = "tests/fixtures"

# 50 KB. The three deleted artifacts were 697, 624 and 6.6 KB; the largest
# legitimate fixture is `schemas/sarif-2.1.0.json` at 113 KB, which four tracked
# files name. So the floor separates "a vendored build" from "a big schema" by
# reference, not by size -- size only bounds how much work the check does.
SIZE_FLOOR = 50 * 1024


def _tracked(pathspec: str) -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files", pathspec],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, f"git ls-files failed: {proc.stderr}"
    return [line for line in proc.stdout.splitlines() if line.strip()]


def _named_by_any_tracked_file(basename: str, exclude: str) -> list[str]:
    """Tracked files whose contents mention `basename`, excluding the fixture."""
    proc = subprocess.run(
        ["git", "grep", "-l", "--fixed-strings", basename],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    # rc 1 means "no matches", which is the interesting answer, not an error.
    if proc.returncode not in (0, 1):  # pragma: no cover - a git failure
        pytest.fail(f"git grep failed: {proc.stderr}")
    return [f for f in proc.stdout.splitlines() if f.strip() and f != exclude]


def orphans(sizes: dict[str, int], is_referenced, floor: int = SIZE_FLOOR) -> list[str]:
    """Files at or above `floor` whose basename nothing else names.

    Extracted as a pure rule so it can be exercised on inputs that trigger it.
    The repository currently contains no orphan -- that is the fix -- so every
    assertion made only against the real tree is satisfied by an empty
    population, which is the shape that asserts nothing.
    """
    return sorted(
        path
        for path, size in sizes.items()
        if size >= floor and not is_referenced(Path(path).name, path)
    )


def _large_fixtures() -> list[str]:
    return [
        p
        for p in _tracked(FIXTURES)
        if (REPO_ROOT / p).exists() and (REPO_ROOT / p).stat().st_size >= SIZE_FLOOR
    ]


def test_the_scan_found_the_fixture_tree() -> None:
    """Meta-guard.

    `git ls-files tests/fixtures` returning nothing satisfies the assertion
    below by emptiness, and that is exactly what a moved directory or a broken
    pathspec produces.
    """
    tracked = _tracked(FIXTURES)
    assert len(tracked) >= 10, f"only {len(tracked)} tracked files under {FIXTURES}"


def test_no_large_fixture_is_unreferenced() -> None:
    """The defect, against the real tree: a big tracked artifact nothing names."""
    sizes = {p: (REPO_ROOT / p).stat().st_size for p in _large_fixtures()}
    found = orphans(
        sizes,
        lambda name, path: bool(_named_by_any_tracked_file(name, exclude=path)),
    )
    assert not found, (
        "large tracked fixture(s) that no other tracked file names -- every "
        "clone carries them and nothing reads them:\n  "
        + "\n  ".join(f"{p} ({sizes[p]:,} bytes)" for p in found)
    )


# --------------------------------------------------------------------------
# The rule itself, on inputs the repository no longer has
# --------------------------------------------------------------------------


class TestOrphanRule:
    """The three real artifacts, reconstructed at their measured sizes.

    Without these the assertion above is green over an EMPTY population and
    cannot distinguish a working rule from one that returns nothing.
    """

    REFERENCED = {"tests/fixtures/schemas/sarif-2.1.0.json": 112_768}
    DELETED = {
        "tests/fixtures/dashboard/test-inline-dashboard.html": 697_000,
        "tests/fixtures/dashboard/test-external-dashboard.html": 624_154,
    }

    @staticmethod
    def _refs(known: set[str]):
        return lambda name, path: name in known

    def test_a_large_unreferenced_file_is_reported(self) -> None:
        found = orphans(self.DELETED, self._refs(set()))
        assert found == sorted(self.DELETED)

    def test_a_large_referenced_file_is_not_reported(self) -> None:
        """`sarif-2.1.0.json` is 113 KB and four tracked files name it."""
        found = orphans(self.REFERENCED, self._refs({"sarif-2.1.0.json"}))
        assert found == []

    def test_a_small_unreferenced_file_is_below_the_floor(self) -> None:
        """`test_trump_report.html`-sized orphans are out of scope on purpose.

        The floor keeps this from becoming a noisy orphan hunt over 20 small
        sample files, which is a different question. It is a scoping choice,
        and it is asserted so that raising it silently is visible.
        """
        found = orphans({"tests/fixtures/tiny.html": 6_658}, self._refs(set()))
        assert found == []

    def test_a_file_naming_only_itself_is_still_an_orphan(self) -> None:
        """The self-reference exclusion.

        Every file contains its own name in `git grep -l` output, so without
        excluding the path itself every fixture looks referenced and the rule
        reports nothing, forever.
        """
        sizes = {"tests/fixtures/dashboard/test-external-dashboard.html": 624_154}
        only_itself = lambda name, path: path != path  # noqa: E731 - never true
        assert orphans(sizes, only_itself) == sorted(sizes)


def test_the_dashboard_fixture_directory_is_gone() -> None:
    """Pins the deletion, so a fourth vendored build is a deliberate act.

    A bundle belongs at `scripts/dashboard/dist/index.html`, which is tracked,
    rebuilt by `npm run build` and freshness-gated by `dashboard-smoke` (#862).
    A second copy under `tests/` has no way to stay true.
    """
    assert not _tracked("tests/fixtures/dashboard"), (
        "tests/fixtures/dashboard/ is back. The tracked bundle is "
        "scripts/dashboard/dist/index.html; a vendored copy under tests/ is "
        "the shape #864 and #1032 removed."
    )
