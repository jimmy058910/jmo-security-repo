#!/usr/bin/env python3
"""Guard: an npm `overrides` entry must be a floor, never an exact version.

Regression for #900.

An exact pin added to clear one advisory becomes the reason the NEXT advisory in
that package cannot be fixed, and the mechanism is invisible:

* `npm update <pkg>` is a no-op against it. Measured on `js-yaml`: the tree
  stayed at 3.15.0 and the command reported `up to date in 294ms` while doing
  nothing -- it also stripped 48 lines of `libc` lockfile metadata as
  collateral.
* **Dependabot never edits an `overrides` block**, so no PR is ever opened.
  Alert #156 sat open with nothing attached, and that is why.

A floor (`>=` or `^`) has neither problem.

Measured before this fix: `npm audit` in `scripts/dashboard` reported **2 high**
(`brace-expansion` pinned at 1.1.16 and 2.1.2 against patched 1.1.18 and 2.1.4).
Converting both to `^` floors resolved them to the patched versions and audit
reports **0**.

## Why `^` and not `>=`

`>=` is a floor with no ceiling, and a major can break the requirer. The worked
example is in the block itself: `js-yaml@3` at `>=3.15.1` resolves to 5.3.0 and
breaks `@istanbuljs/load-nyc-config`, which calls `yaml.safeLoad`. The `@1` /
`@2` selectors already scope which major is being overridden, so `^` inside them
says the same thing twice on purpose.

Both forms are accepted here. What is rejected is a bare version.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Every package.json in the repo that could grow an overrides block.
MANIFESTS = ("scripts/dashboard/package.json", "scripts/api/package.json")

# A range, not a version: it must start with a comparator or be a wildcard.
_RANGE = re.compile(r"^\s*(?:[\^~]|>=?|<=?|\*|x|\d+\.x|latest)")


def _manifests() -> list[tuple[str, dict]]:
    out = []
    for rel in MANIFESTS:
        path = REPO_ROOT / rel
        if path.exists():
            out.append((rel, json.loads(path.read_text(encoding="utf-8"))))
    return out


def _override_entries() -> list[tuple[str, str, str]]:
    """(manifest, selector, specifier), flattened through nested overrides."""
    entries: list[tuple[str, str, str]] = []

    def walk(rel: str, block: dict, prefix: str = "") -> None:
        for selector, value in block.items():
            name = f"{prefix}{selector}"
            if isinstance(value, dict):
                walk(rel, value, prefix=f"{name}.")
            elif isinstance(value, str):
                entries.append((rel, name, value))

    for rel, data in _manifests():
        walk(rel, data.get("overrides") or {})
    return entries


def test_the_manifests_were_found() -> None:
    """Meta-guard: a moved package.json makes every assertion below vacuous."""
    found = [rel for rel, _ in _manifests()]
    assert "scripts/dashboard/package.json" in found, f"only found {found}"


def test_the_dashboard_still_has_overrides_to_check() -> None:
    """Second meta-guard, in the other direction.

    An empty `overrides` block satisfies the rule by having nothing in it, and
    that is exactly what deleting the block would produce.
    """
    entries = [
        e for e in _override_entries() if e[0].endswith("dashboard/package.json")
    ]
    assert len(entries) >= 5, f"only {len(entries)} overrides parsed: {entries}"


@pytest.mark.parametrize(
    ("manifest", "selector", "specifier"),
    _override_entries(),
    ids=[f"{s}" for _, s, _ in _override_entries()],
)
def test_every_override_is_a_range_not_an_exact_version(
    manifest: str, selector: str, specifier: str
) -> None:
    """The defect: `"brace-expansion@1": "1.1.16"`."""
    assert _RANGE.match(specifier), (
        f"{manifest} pins `{selector}` to the exact version {specifier!r}. "
        f"Use a floor (`^{specifier}` normally, `>=` when no major can break "
        f"the requirer). An exact pin cannot be updated by `npm update` and "
        f"Dependabot will never open a PR for it, so it becomes the reason the "
        f"next advisory in this package goes unfixed (#900)."
    )


def test_the_block_says_why_out_loud() -> None:
    """The comment is part of the fix, not decoration.

    The file will otherwise re-acquire an exact pin the next time somebody
    clears an advisory in a hurry -- which is how it acquired two.
    """
    data = json.loads(
        (REPO_ROOT / "scripts/dashboard/package.json").read_text(encoding="utf-8")
    )
    comment = data.get("_overrides_comment", "")
    assert "exact" in comment.lower(), (
        "scripts/dashboard/package.json lost the note explaining why overrides "
        "must be floors"
    )
    assert "#900" in comment, "the note should cite the issue that measured this"
