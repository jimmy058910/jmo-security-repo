#!/usr/bin/env python3
"""Drift guard for invalid Docker tag references in docs, scripts, and tests.

GHCR publishes a specific set of tag patterns per `docker/metadata-action`
config in `.github/workflows/release.yml`. The canonical schema is:

    :latest                       (deep only — bare, no variant suffix)
    :<variant>                    (deep, balanced, slim, fast)
    :<X>.<Y>.<Z>                  (deep only — bare semver)
    :<X>.<Y>.<Z>-<variant>        (deep, balanced, slim, fast)
    :full                         (legacy alias for deep, one-cycle backward-compat)

There is intentionally NO `:latest-deep`, `:latest-balanced`, `:latest-slim`,
`:latest-fast`, or `:latest-full`. Pulls of those will fail with "manifest
unknown".

This test catches references to forbidden tag patterns BEFORE they ship
to user-facing docs. Three such bugs slipped through despite documentation
in `.claude/rules/docker.rules.md` saying "DON'T use these" — that doc-only
approach didn't catch the actual regressions in `TEST.md`, `tests/e2e/README.md`,
and `docs/SCHEDULE_GUIDE.md` (all fixed in this PR).

Allowlist: certain files legitimately reference forbidden patterns as
documentation or historical record:
- `CHANGELOG.md` — frozen historical entries
- `.claude/rules/*.md` — explicit "DON'T use these" warnings
- `.github/workflows/release.yml` — comments explaining the workaround
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
}

# The forbidden pattern: any GHCR jmo-security image with a `:latest-<suffix>` tag.
# Matches `ghcr.io/<owner>/jmo-security:latest-<anything>` where suffix is one of
# the variant names. The `\b` ensures we don't match `:latest-special-foo` etc.
FORBIDDEN_TAG_PATTERN = re.compile(
    r"ghcr\.io/[^/\s]+/jmo-security:latest-(deep|balanced|slim|fast|full)\b"
)


def _iter_scannable_files() -> list[Path]:
    """Walk REPO_ROOT and yield files we should scan."""
    out: list[Path] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in SCAN_EXTENSIONS:
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        out.append(path)
    return out


def _relative_posix(path: Path) -> str:
    """Convert path to repo-relative POSIX-style string for cross-platform allowlist match."""
    return str(path.relative_to(REPO_ROOT)).replace("\\", "/")


def test_no_forbidden_latest_variant_tags_outside_allowlist() -> None:
    """No file outside the documentation allowlist may reference a `:latest-<variant>` tag.

    GHCR doesn't publish `:latest-deep`, `:latest-balanced`, `:latest-slim`,
    `:latest-fast`, or `:latest-full`. Any such reference in user-facing docs
    or CI scripts will fail at `docker pull` time with "manifest unknown".

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
        "Found references to forbidden Docker tag patterns. GHCR does not "
        "publish `:latest-<variant>` tags — `:latest` is bare (deep only) "
        "and bare variants are `:deep`, `:balanced`, `:slim`, `:fast`. "
        "Replace `:latest-deep` / `:latest-full` → `:latest`, and "
        "`:latest-<other>` → `:<other>`.\n"
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
