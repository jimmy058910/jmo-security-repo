"""A tool that both pre-commit and uv.lock provide must be pinned once (#1015).

`.github/dependabot.yml` declared five ecosystems and no `pre-commit` entry, so
`.pre-commit-config.yaml`'s ten hook revs were updated only by hand. Nine of the
ten measured current, so this was never rot -- the symptom is narrower and
sharper.

Measured 2026-08-27, after #990 bumped ruff in `uv.lock`:

    pre-commit hook (commit-time --fix)  0.16.3
    uv.lock / `make lint` / CI           0.16.4
    upstream latest                      0.16.5

`.pre-commit-config.yaml` runs `ruff --fix`, so a developer's commit hook
**rewrote code** with 0.16.3 while `make lint` and CI **checked** it with
0.16.4. That is the documented "pre-commit's Black is not `.venv`'s Black" trap
with the versions actually different rather than merely the environments.

CI cannot see it by design: `ci.yml` runs pre-commit with
`SKIP: black,ruff,bandit,mypy` and lints from the uv-synced venv instead, so it
never runs the hook version at all.

Dependabot alone does not close this. It would have opened a PR for v0.16.5
without ever noticing the 0.16.3/0.16.4 split -- it compares each manifest
against upstream, never against the other manifest. This guard is the part that
does, and it is derived from both files rather than restating either: the hook
`id` is the PyPI distribution name for every tool the two share, so the
intersection needs no hand-maintained mapping.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def _hook_revs() -> dict[str, str]:
    """{hook id: normalised rev} for every non-local pre-commit repo.

    Keyed on the hook `id`, not the repo slug: `astral-sh/ruff-pre-commit`
    provides the hook `ruff`, `pre-commit/mirrors-mypy` provides `mypy`, and the
    id is the distribution name in both cases. Keying on the slug would need a
    hand-written mapping, which is the failure mode this repo keeps finding.
    """
    config = yaml.safe_load(
        (REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    )
    revs: dict[str, str] = {}
    for repo in config["repos"]:
        if repo.get("repo") == "local":
            continue
        rev = str(repo.get("rev", ""))
        for hook in repo.get("hooks", []):
            revs[str(hook["id"])] = re.sub(r"^v", "", rev)
    return revs


def _lock_versions() -> dict[str, str]:
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    return {str(p["name"]): str(p["version"]) for p in lock["package"]}


def _shared() -> dict[str, tuple[str, str]]:
    """{tool: (hook rev, lock version)} for tools both files pin."""
    hooks, lock = _hook_revs(), _lock_versions()
    return {name: (rev, lock[name]) for name, rev in hooks.items() if name in lock}


# ---------------------------------------------------------------------------
# The guard.
# ---------------------------------------------------------------------------


def test_a_tool_pinned_in_both_places_is_pinned_to_the_same_version() -> None:
    """The split the issue is about, stated as a property.

    Applies to every tool the two files share, not just ruff -- black, bandit
    and mypy are pinned in both today and would drift the same way.
    """
    disagreements = {
        name: versions
        for name, versions in _shared().items()
        if versions[0] != versions[1]
    }

    assert not disagreements, (
        "pre-commit and uv.lock disagree on "
        + ", ".join(
            f"{name} (hook {hook}, lock {lock})"
            for name, (hook, lock) in sorted(disagreements.items())
        )
        + ". A hook that rewrites code at a different version from the one CI "
        "checks it with is the trap this guard exists for."
    )


# ---------------------------------------------------------------------------
# Meta-guards: a derivation that finds nothing asserts nothing.
# ---------------------------------------------------------------------------


def test_the_extractors_found_the_tools_they_must_find() -> None:
    """Floor plus named members, on both sides and on the intersection.

    Without this, a renamed hook id or a uv.lock schema change would empty the
    intersection and the assertion above would pass vacuously -- which is
    exactly the shape (an instrument that cannot disagree out loud) that put
    this issue in the instruments slot.
    """
    hooks, lock, shared = _hook_revs(), _lock_versions(), _shared()

    assert len(hooks) >= 8, f"hook extractor found only {sorted(hooks)}"
    assert {"ruff", "black", "mypy", "bandit"} <= set(hooks), sorted(hooks)

    assert len(lock) >= 50, f"lock extractor found only {len(lock)} packages"
    assert {"ruff", "black", "mypy", "bandit"} <= set(lock)

    assert {"ruff", "black", "mypy", "bandit"} <= set(shared), (
        f"the intersection is {sorted(shared)}; if a tool dropped out of it "
        f"the agreement check silently stopped covering that tool"
    )


def test_a_tool_pinned_in_only_one_place_is_not_compared() -> None:
    """The other direction: the guard must not invent a disagreement.

    `yamllint`, `shellcheck` and `shfmt` are pre-commit hooks with no uv.lock
    entry -- nothing in the project imports or runs them from the venv -- so
    there is no second pin to agree with. A guard that flagged those would be
    noise and would be silenced, taking the real check with it.
    """
    hooks, lock, shared = _hook_revs(), _lock_versions(), _shared()

    assert "yamllint" in hooks
    assert "yamllint" not in lock
    assert "yamllint" not in shared


# ---------------------------------------------------------------------------
# The other half of the acceptance criterion.
# ---------------------------------------------------------------------------


def _dependabot() -> dict:
    return yaml.safe_load(
        (REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    )


def test_dependabot_covers_the_pre_commit_ecosystem() -> None:
    """Ten pinned hook revs were updated only by hand."""
    ecosystems = {u["package-ecosystem"] for u in _dependabot()["updates"]}

    assert "pre-commit" in ecosystems, sorted(ecosystems)


def test_the_pre_commit_entry_targets_dev_like_its_five_siblings() -> None:
    """Every bot PR against `main` widens a divergence the release must cross.

    All five existing blocks carry `target-branch: dev` for the v1.1.0 campaign;
    a sixth that did not would reintroduce exactly what they were retargeted to
    avoid.

    Note the standing caveat: Dependabot reads this file from the **default**
    branch, so a `target-branch` added on `dev` is inert until `dev` reaches
    `main`. That is a property of the retarget, not of this entry.
    """
    updates = _dependabot()["updates"]
    targets = {u["package-ecosystem"]: u.get("target-branch") for u in updates}

    assert targets.get("pre-commit") == "dev", targets
    assert set(targets.values()) == {
        "dev"
    }, f"ecosystems disagree on target-branch: {targets}"


@pytest.mark.parametrize("key", ["directory", "schedule"])
def test_the_pre_commit_entry_is_complete(key: str) -> None:
    """A block missing `directory` or `schedule` is silently never scheduled."""
    entry = next(
        u for u in _dependabot()["updates"] if u["package-ecosystem"] == "pre-commit"
    )

    assert key in entry, f"pre-commit block is missing {key!r}: {entry}"
