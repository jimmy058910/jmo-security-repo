#!/usr/bin/env python3
"""Guard: a Makefile target that builds a distribution must clean first.

Regression for #1031.

setuptools keeps two caches `uv build` never invalidates, and they drift in
opposite directions:

* **`build/lib/` is never pruned**, so a wheel ships modules deleted from the
  tree. Reproduced by planting a file that exists in no source tree and is
  tracked nowhere: the wheel contained it. **198 entries stale against 197
  clean.**
* **`*.egg-info/SOURCES.txt` is re-read** under `include-package-data`, so a
  wheel ships files whose `package-data` declaration was deleted. That half is
  worse, because it makes a packaging gate **vacuous** -- Phase 7's dashboard
  wheel check passed against a `pyproject.toml` that no longer declared the
  artifact it was checking for.

Both directories are gitignored, so nothing surfaces the drift. Releases build
on a fresh checkout and are safe; LOCAL verification is not, and local
verification is what decides whether a release goes out.

`ci.yml` already cleans before its wheel check. This asserts the local path
does too, so the two cannot diverge silently.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"

# Commands that produce a distribution from the setuptools backend.
_BUILD_COMMANDS = ("uv build", "python -m build", "-m build")

# What counts as invalidating the caches. `dist-clean` is the named target;
# the literal `rm -rf` form is accepted for a target that inlines it.
_CLEAN_PREREQ = "dist-clean"
_CLEAN_INLINE = re.compile(r"rm\s+-rf\b[^\n]*\bbuild/")


def _targets() -> dict[str, tuple[list[str], str]]:
    """`{target: (prerequisites, recipe)}` for every Makefile rule."""
    text = MAKEFILE.read_text(encoding="utf-8")
    rules: dict[str, tuple[list[str], str]] = {}
    current: str | None = None
    prereqs: list[str] = []
    recipe: list[str] = []
    for line in text.splitlines():
        if line.startswith("\t") and current:
            recipe.append(line)
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*:(?!=)\s*(.*)$", line)
        if match:
            if current:
                rules[current] = (prereqs, "\n".join(recipe))
            current = match.group(1)
            prereqs = match.group(2).split()
            recipe = []
        elif current and not line.startswith("\t") and line.strip():
            rules[current] = (prereqs, "\n".join(recipe))
            current, prereqs, recipe = None, [], []
    if current:
        rules[current] = (prereqs, "\n".join(recipe))
    return rules


def commands_only(recipe: str) -> str:
    """The recipe with Makefile comment lines removed.

    A recipe line beginning `@#` or `#` (after the leading tab and any `@`/`-`
    prefix) is a comment, and prose about a command is not the command. Without
    this, a comment explaining why `pip install` was REMOVED reads as a
    `pip install` -- which is what the first version of this guard did.
    """
    kept = []
    for line in recipe.splitlines():
        body = line.lstrip("\t").lstrip("@-").lstrip()
        if body.startswith("#"):
            continue
        kept.append(line)
    return "\n".join(kept)


def _building_targets() -> dict[str, tuple[list[str], str]]:
    return {
        name: rule
        for name, rule in _targets().items()
        if any(cmd in commands_only(rule[1]) for cmd in _BUILD_COMMANDS)
    }


def test_the_makefile_parser_found_the_build_targets() -> None:
    """Meta-guard.

    A parser that finds no rules, or no building rules, satisfies the assertion
    below by emptiness -- which is what a Makefile reformat would produce.
    """
    rules = _targets()
    assert len(rules) >= 20, f"only {len(rules)} Makefile rules parsed"
    assert _CLEAN_PREREQ in rules, f"no `{_CLEAN_PREREQ}` target found"

    building = _building_targets()
    assert building, "no Makefile target appears to build a distribution"
    assert (
        "dist" in building
    ), f"`dist` is not among the building targets: {sorted(building)}"


def test_every_build_target_invalidates_the_setuptools_caches() -> None:
    """The defect: a build that reuses `build/lib` and `SOURCES.txt`."""
    offenders = []
    for name, (prereqs, recipe) in sorted(_building_targets().items()):
        cleans = _CLEAN_PREREQ in prereqs or bool(
            _CLEAN_INLINE.search(commands_only(recipe))
        )
        if not cleans:
            offenders.append(name)

    assert not offenders, (
        f"Makefile target(s) build a distribution without first removing "
        f"build/ and *.egg-info/: {offenders}. setuptools reuses both, so the "
        f"wheel can ship deleted modules AND satisfy a package-data "
        f"declaration that no longer exists (#1031)."
    )


def test_the_local_build_uses_a_tool_this_project_actually_has() -> None:
    """`make dist` used `python -m build` in a venv with no pip.

    uv-created venvs ship no pip, so `pip install --quiet build || true` failed
    silently and `python -m build` then died with `No module named build`. The
    target could not work in the environment CONTRIBUTING.md tells a
    contributor to create, which is a different failure from the cache one and
    was found while fixing it.
    """
    _, recipe = _targets()["dist"]
    commands = commands_only(recipe)
    assert "uv build" in commands, "`make dist` no longer builds with uv"
    assert "pip install" not in commands, (
        "`make dist` reintroduced a pip install; this project's venv is created "
        "by uv and ships no pip, so it fails silently and the build dies after it"
    )
