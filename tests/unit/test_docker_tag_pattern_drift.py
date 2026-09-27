#!/usr/bin/env python3
"""Drift guard for Docker tag references GHCR does not publish.

Since v2.0.0 there is one image, and the `docker/metadata-action` config in
`.github/workflows/release.yml` tags it two ways only:

    :latest
    :<X>.<Y>.<Z>

v1.x published four variants as `:deep`, `:balanced`, `:slim` and `:fast` (with
`:full` a legacy alias for deep), plus `:<X>.<Y>.<Z>-<variant>`. Those tags
still exist on GHCR, frozen, so a reference to one does not fail: it pulls a
v1.x image and runs old code without a word. `:latest-<variant>` never existed
at all, and pulls of it fail with "manifest unknown".

This test catches references to any of those forms BEFORE they ship. It began
with `:latest-<variant>`, after three such bugs slipped through despite
documentation in `.claude/rules/docker.rules.md` saying "DON'T use these" — that
doc-only approach didn't catch the actual regressions in `TEST.md`,
`tests/e2e/README.md`, and `docs/SCHEDULE_GUIDE.md`.

Allowlist: certain files legitimately reference forbidden patterns as
documentation or historical record:
- `CHANGELOG.md` — frozen historical entries
- This test file itself — names the patterns it tests for
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Files that legitimately reference the forbidden full-URL pattern as
# historical record. Paths are relative to REPO_ROOT and use forward slashes.
# Note: rule docs (.claude/rules/*.md) and release.yml comments use bare
# `:latest-deep` references (no `ghcr.io/...` prefix) so they don't match
# the FORBIDDEN_TAG_PATTERN regex and don't need allowlisting.
ALLOWLISTED_PATHS: set[str] = {
    "CHANGELOG.md",
    "tests/unit/test_docker_tag_pattern_drift.py",
}

# File extensions to scan. Matches what user-facing docs and CI surfaces use.
SCAN_EXTENSIONS: set[str] = {".md", ".yml", ".yaml", ".py", ".sh", ".json"}

# Directories to skip entirely (no point scanning vendored/generated code or
# internal-only archives that aren't published to users).
SKIP_DIR_NAMES: set[str] = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "build",
    "dist",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "htmlcov",
    "dev-only",  # Internal archive, explicitly not published per CLAUDE.md
    # Gitignored (`/metrics/`): dated Docker Hub API snapshots on the
    # maintainer's machine, each a frozen copy of the Hub description. Not
    # repository content, and absent from a clone.
    "metrics",
    # A nested git worktree is a *second checkout*, not repository content.
    # `.claude/worktrees/release-v107` held a pre-squash copy of CHANGELOG.md
    # whose historical `:latest-full` / `:latest-slim` references tripped this
    # test against a file that is not part of the tree under review. Previously
    # invisible: the walk died in node_modules before ever reaching it.
    "worktrees",
}

# The forbidden pattern: any GHCR jmo-security image tagged with a variant name,
# bare (`:slim`), after `latest-` (`:latest-slim`) or after a semver
# (`:1.1.1-slim`). The two published forms, `:latest` and a bare semver, carry
# no variant name and never match. The `\b` ensures we don't match
# `:latest-special-foo` etc.
FORBIDDEN_TAG_PATTERN = re.compile(
    r"ghcr\.io/[^/\s]+/jmo-security:"
    r"(?:latest-|v?\d+\.\d+\.\d+-)?(deep|balanced|slim|fast|full)\b"
)


def _iter_scannable_files() -> list[Path]:
    """Walk REPO_ROOT and yield files we should scan.

    Pruning happens *during* traversal. The previous `rglob("*")` form descended
    into `node_modules` regardless of `SKIP_DIR_NAMES` and stat-ed every file it
    yielded, which failed differently on each platform and so read as a platform
    quirk on both: `OSError [WinError 1920]` on the pnpm symlink farm under
    Windows, and a plain pytest **timeout** under WSL, where stat-ing tens of
    thousands of vendored files across `/mnt/c` is glacial.
    """
    from tests.conftest import iter_repo_files

    return iter_repo_files(REPO_ROOT, SKIP_DIR_NAMES, SCAN_EXTENSIONS)


def _relative_posix(path: Path) -> str:
    """Convert path to repo-relative POSIX-style string for cross-platform allowlist match."""
    return str(path.relative_to(REPO_ROOT)).replace("\\", "/")


def test_no_variant_tags_outside_allowlist() -> None:
    """No file outside the documentation allowlist may reference a variant tag.

    GHCR publishes `:latest` and `:<X>.<Y>.<Z>` only. A `:latest-<variant>`
    reference fails at `docker pull` time with "manifest unknown"; a
    `:<variant>` or `:<X>.<Y>.<Z>-<variant>` reference pulls a frozen v1.x
    image and fails nowhere, which is worse.

    See `.claude/rules/docker.rules.md` "Published Tag Schema" for the
    canonical list of supported tags.
    """
    violations: list[str] = []
    for path in _iter_scannable_files():
        rel = _relative_posix(path)
        if rel in ALLOWLISTED_PATHS:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable; skip
        for match in FORBIDDEN_TAG_PATTERN.finditer(text):
            line_num = text[: match.start()].count("\n") + 1
            violations.append(f"{rel}:{line_num} - {match.group(0)}")

    assert not violations, (
        "Found references to Docker tags GHCR does not publish. Since v2.0.0 "
        "there is one image, tagged `:latest` and `:<X>.<Y>.<Z>` only; the "
        "v1.x variant tags still exist, frozen, so pinning one runs a v1.x "
        "image without any error. Replace `:<variant>`, `:latest-<variant>` "
        "and `:<X>.<Y>.<Z>-<variant>` with `:latest` or the bare semver.\n"
        "Violations:\n  " + "\n  ".join(violations) + "\n\n"
        "See .claude/rules/docker.rules.md 'Published Tag Schema' for the "
        "canonical tag list. If a NEW file legitimately needs to mention "
        "the forbidden pattern (e.g., for documentation), add it to "
        "ALLOWLISTED_PATHS in this test."
    )


def test_allowlist_paths_actually_exist() -> None:
    """Every path in ALLOWLISTED_PATHS must point to a real file.

    Catches drift where a file was renamed/moved without updating the allowlist.
    Stale allowlist entries silently weaken the drift guard.
    """
    missing = [p for p in ALLOWLISTED_PATHS if not (REPO_ROOT / p).is_file()]
    assert not missing, (
        f"ALLOWLISTED_PATHS contains paths that don't exist: {missing}. "
        f"Either remove them from the set or fix the path."
    )


@pytest.mark.parametrize(
    "allowed_path",
    sorted(ALLOWLISTED_PATHS - {"tests/unit/test_docker_tag_pattern_drift.py"}),
)
def test_allowlist_paths_actually_contain_forbidden_pattern(allowed_path: str) -> None:
    """Allowlisted files should contain at least one forbidden pattern.

    If a file is on the allowlist but doesn't actually need to be (no
    forbidden references inside), remove it. Stale allowlist entries
    weaken the drift guard for future PRs.
    """
    text = (REPO_ROOT / allowed_path).read_text(encoding="utf-8")
    assert FORBIDDEN_TAG_PATTERN.search(text) is not None, (
        f"{allowed_path} is in ALLOWLISTED_PATHS but contains no forbidden "
        f"tag pattern. Remove it from the allowlist."
    )


@pytest.mark.parametrize(
    ("reference", "forbidden"),
    [
        ("ghcr.io/o/jmo-security:latest", False),
        ("ghcr.io/o/jmo-security:2.0.0", False),
        ("ghcr.io/o/jmo-security:latest-special-foo", False),
        ("ghcr.io/o/jmo-security:deep", True),
        ("ghcr.io/o/jmo-security:slim", True),
        ("ghcr.io/o/jmo-security:full", True),
        ("ghcr.io/o/jmo-security:1.1.1-balanced", True),
        ("ghcr.io/o/jmo-security:latest-fast", True),
    ],
)
def test_pattern_separates_published_tags_from_variant_tags(
    reference: str, forbidden: bool
) -> None:
    """The pattern rejects every variant form and accepts both published tags.

    The scan above passes whenever the pattern matches nothing, so a pattern
    that matched nothing at all would pass it too. These fix what it must match
    and what it must leave alone.
    """
    assert (FORBIDDEN_TAG_PATTERN.search(reference) is not None) is forbidden
