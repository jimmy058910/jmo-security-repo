"""Every `versions.yaml` entry must be reachable by `update_versions.py --sync`.

The defect this guards against is not "a pin went stale" — it is **`--sync`
reporting success while a pin is stale**. `sync_dockerfiles` derived its match
pattern from the registry key (`key.upper() + "_VERSION"`) and had a second,
pip-only path gated on a hardcoded four-tool allowlist. Anything that did not
uppercase cleanly onto its pin, or was not one of those four, was silently
skipped and the file reported "already in sync".

Measured cost of that: `prowler` shipped **5.18.2 in the slim, balanced and deep
images while `versions.yaml` declared 5.36.0** — eighteen minor versions, on a
CSPM scanner (#797). `osv-scanner`'s pin went stale the same way first (#702).
Five further tools were unreachable and correct only by coincidence.

So this asserts **coverage**, not equality: `--sync` already fails loudly when a
reachable pin disagrees. What it could not previously notice is an entry it
never looked at.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from scripts.dev.update_versions import UNPINNED_BY_DESIGN, VERSION_VAR_ALIASES

REPO_ROOT = Path(__file__).resolve().parents[2]
PINNED_SECTIONS = ("python_tools", "binary_tools", "special_tools")


def _registry() -> dict[str, dict]:
    data = yaml.safe_load((REPO_ROOT / "versions.yaml").read_text(encoding="utf-8"))
    return {
        tool: info
        for section in PINNED_SECTIONS
        for tool, info in (data.get(section) or {}).items()
    }


def _searchable_text() -> str:
    """Every file `--sync` rewrites, concatenated."""
    parts = [p.read_text(encoding="utf-8") for p in REPO_ROOT.glob("Dockerfile.*")]
    workflows = REPO_ROOT / ".github" / "workflows"
    if workflows.exists():
        parts += [p.read_text(encoding="utf-8") for p in workflows.glob("*.yml")]
    return "\n".join(parts)


def _pin_patterns(tool: str, info: dict) -> list[str]:
    """The pin forms `--sync` knows how to rewrite, for one registry entry."""
    var_stem = VERSION_VAR_ALIASES.get(tool, tool.upper())
    patterns = [
        rf'{re.escape(var_stem)}_VERSION="[0-9.]+"',  # Dockerfile shell var
        rf'{re.escape(var_stem)}_VERSION:\s+"[0-9.]+"',  # workflow env: block
    ]
    pkg = info.get("pypi_package")
    if isinstance(pkg, str) and pkg:
        # npm scoped packages pin as `@scope/name@X.Y.Z`, pip as `name==X.Y.Z`.
        sep = "@" if pkg.startswith("@") else "=="
        patterns.append(rf"{re.escape(pkg)}{re.escape(sep)}[0-9][0-9.]*")
    return patterns


@pytest.mark.parametrize("tool", sorted(_registry()))
def test_every_registry_entry_is_reachable_by_sync(tool: str):
    """Regression for #702 and #797.

    An entry matching nothing is one `--sync` can never update, and it will say
    "already in sync" forever while the shipped version drifts.
    """
    if tool in UNPINNED_BY_DESIGN:
        pytest.skip(f"{tool} is deliberately not shipped in any image")

    info = _registry()[tool]
    text = _searchable_text()
    if any(re.search(p, text) for p in _pin_patterns(tool, info)):
        return

    pytest.fail(
        f"'{tool}' matches no pin in any Dockerfile or workflow, so "
        f"`update_versions.py --sync` can never update it and will report "
        f"success while it drifts. Tried: {_pin_patterns(tool, info)}. "
        f"Add the pin, add a VERSION_VAR_ALIASES entry, or add '{tool}' to "
        f"UNPINNED_BY_DESIGN if it is genuinely not shipped."
    )


def test_unpinned_by_design_entries_really_are_absent():
    """The exemption list must not become a place to hide a broken mapping.

    If one of these acquires a pin, it is shipped after all and belongs under
    the coverage assertion above.
    """
    registry = _registry()
    text = _searchable_text()
    wrongly_exempt = sorted(
        tool
        for tool in UNPINNED_BY_DESIGN
        if tool in registry
        and any(re.search(p, text) for p in _pin_patterns(tool, registry[tool]))
    )
    assert not wrongly_exempt, (
        f"{wrongly_exempt} are listed UNPINNED_BY_DESIGN but do have a pin. "
        "Remove them from the exemption so --sync keeps them current."
    )


def test_prowler_pin_matches_the_registry():
    """Named explicitly: this is the drift that was actually shipping (#797).

    Verified before bumping that `prowler==5.36.0` installs on `ubuntu:24.04`
    with `--break-system-packages` and that its CLI runs, which is the exact
    context the Dockerfiles use.
    """
    declared = _registry()["prowler"]["version"]
    pinned = set(re.findall(r"prowler==([0-9][0-9.]*)", _searchable_text()))
    assert pinned, "no prowler pin found at all -- did the install line move?"
    assert pinned == {declared}, (
        f"prowler pinned at {sorted(pinned)} but versions.yaml declares "
        f"{declared}. Run `python scripts/dev/update_versions.py --sync`."
    )
