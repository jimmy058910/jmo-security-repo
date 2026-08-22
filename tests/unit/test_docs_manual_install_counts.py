#!/usr/bin/env python3
"""Guard: public docs must state the real Docker-ready / manual-install split.

``scripts/core/tool_registry.py`` is the source of truth. ``PROFILE_TOOLS["deep"]``
holds 28 tools, 4 of which are in ``MANUAL_INSTALL_TOOLS`` (``afl++``, ``akto``,
``falco``, ``mobsf``) and are deliberately not baked into any image -- so a deep
image ships 24.

Every public doc said **25 Docker-ready + 3 manual** and named only AFL++, MobSF
and Akto. **Falco was missing from all of them**, including
``docs/MANUAL_INSTALLATION.md`` -- the guide a user consults precisely because a
tool is not in the image. That doc discussed Falco's platform support on one line
and then omitted it from its own summary count on another.

Falco is easy to get wrong: ``falcoctl`` *is* installed by ``Dockerfile.deep``,
and it is a different binary from ``falco``.

A second, older shape had drifted independently: ``docs/DOCKER_README.md`` also
claimed "29 tools, 26 Docker-ready", stale since ``bearer`` left PROFILE_TOOLS.
A literal grep for the first wording never found it, which is why this guard
matches the *shape* of the claim rather than any one sentence.

Companion to ``test_profile_tools_count_drift.py``, which guards the same
registry against the test and workflow constants instead of the docs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from scripts.core.tool_registry import MANUAL_INSTALL_TOOLS, PROFILE_TOOLS

REPO_ROOT = Path(__file__).resolve().parents[2]

# The advertised surface: docs a user reads before pulling an image.
ADVERTISED_DOCS = [
    "CONTRIBUTING.md",
    "DOCKER_HUB_README.md",
    "SECURITY.md",
    "docs/DOCKER_README.md",
    "docs/MANUAL_INSTALLATION.md",
]

# Display names as the docs spell them, keyed by registry name.
MANUAL_DISPLAY_NAMES = {
    "afl++": "AFL++",
    "akto": "Akto",
    "falco": "Falco",
    "mobsf": "MobSF",
}

_DOCKER_READY = re.compile(r"(\d+)\s+Docker-ready", re.IGNORECASE)
_MANUAL_COUNT = re.compile(
    r"(\d+)\s+(?:manual install\b|manual\b|deep profile tools require manual)",
    re.IGNORECASE,
)


def expected_docker_ready() -> int:
    deep = set(PROFILE_TOOLS["deep"])
    return len(deep) - len(MANUAL_INSTALL_TOOLS & deep)


def expected_manual() -> int:
    return len(MANUAL_INSTALL_TOOLS & set(PROFILE_TOOLS["deep"]))


def test_manual_display_names_cover_the_registry() -> None:
    """The name map must not fall behind MANUAL_INSTALL_TOOLS.

    Without this, adding a fifth manual tool would leave the enumeration test
    below silently checking only the four it already knew about.
    """
    assert set(MANUAL_DISPLAY_NAMES) == set(MANUAL_INSTALL_TOOLS), (
        f"MANUAL_DISPLAY_NAMES is out of step with MANUAL_INSTALL_TOOLS: "
        f"{set(MANUAL_INSTALL_TOOLS) ^ set(MANUAL_DISPLAY_NAMES)}"
    )


@pytest.mark.parametrize("rel", ADVERTISED_DOCS)
def test_docker_ready_count_is_correct(rel: str) -> None:
    """Any '<N> Docker-ready' claim must equal the derived count."""
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    want = expected_docker_ready()
    bad = [int(m) for m in _DOCKER_READY.findall(text) if int(m) != want]
    assert not bad, (
        f"{rel} claims {bad} Docker-ready tools; "
        f"PROFILE_TOOLS['deep'] - MANUAL_INSTALL_TOOLS = {want}"
    )


@pytest.mark.parametrize("rel", ADVERTISED_DOCS)
def test_manual_install_count_is_correct(rel: str) -> None:
    """Any '<N> manual install' claim must equal len(MANUAL_INSTALL_TOOLS)."""
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    want = expected_manual()
    bad = [int(m) for m in _MANUAL_COUNT.findall(text) if int(m) != want]
    assert not bad, (
        f"{rel} claims {bad} manual-install tools; MANUAL_INSTALL_TOOLS "
        f"restricted to PROFILE_TOOLS['deep'] has {want} "
        f"({sorted(MANUAL_INSTALL_TOOLS)})"
    )


def _lines_listing_manual_tools(text: str) -> list[tuple[int, str]]:
    """Lines that state a manual-install count AND enumerate tool names.

    Scoping to the line is what makes this checkable. A first version of this
    guard searched the WHOLE FILE for each name and passed on the very defect it
    was written to catch: every one of these docs mentions Falco somewhere -- in
    a tool table or a platform matrix -- while the specific list beside the count
    omitted it. A file-wide substring search cannot see that. Measured, not
    assumed: the file-wide form returned 0 failures against the shipped docs.
    """
    out: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if not _MANUAL_COUNT.search(line):
            continue
        named = sum(1 for name in MANUAL_DISPLAY_NAMES.values() if name in line)
        if named >= 2:  # a list, not a passing mention
            out.append((i, line))
    return out


@pytest.mark.parametrize("rel", ADVERTISED_DOCS)
def test_manual_tool_lists_name_all_of_them(rel: str) -> None:
    """A line stating the count and listing the tools must list them all.

    The count and the list drifted together: several docs said "3" *and* named
    three, so a count-only guard would catch one half of the error and leave a
    reader with an incomplete list of what they must install by hand.
    """
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    lines = _lines_listing_manual_tools(text)
    if not lines:
        pytest.skip(f"{rel} states no manual-install count beside a tool list")
    for lineno, line in lines:
        missing = sorted(
            n for n, disp in MANUAL_DISPLAY_NAMES.items() if disp not in line
        )
        assert not missing, (
            f"{rel}:{lineno} lists manual-install tools but omits "
            f"{[MANUAL_DISPLAY_NAMES[m] for m in missing]}:\n  {line.strip()}\n"
            f"Falco is the one missed before -- `falcoctl` IS in Dockerfile.deep, "
            f"`falco` is not."
        )


# docs/MANUAL_INSTALLATION.md carries a per-variant table of bare numbers. The
# prose regexes above cannot see it -- a row like `| **Slim** | 14 | 0 |` states
# a count with no nearby word to anchor on -- so it needs its own parser. That
# blind spot was not theoretical: with only the prose guards in place, THREE of
# this table's four rows were wrong (balanced 18, slim 14, fast 8, against a
# measured 17 / 13 / 9) and nothing failed.
_TABLE_ROW = re.compile(
    r"^\|\s*\*\*(?P<variant>[A-Za-z/]+)\*\*\s*\|\s*(?P<ready>\d+)\s*\|\s*(?P<manual>\d+)"
)
# The table labels the deep variant "Deep/Full"; PROFILE_TOOLS calls it "deep".
_TABLE_VARIANT_ALIASES = {"deep/full": "deep"}


def _tool_count_table_rows() -> list[tuple[str, int, int]]:
    text = (REPO_ROOT / "docs/MANUAL_INSTALLATION.md").read_text(encoding="utf-8")
    rows: list[tuple[str, int, int]] = []
    for line in text.splitlines():
        m = _TABLE_ROW.match(line)
        if not m:
            continue
        raw = m.group("variant").lower()
        variant = _TABLE_VARIANT_ALIASES.get(raw, raw)
        if variant in PROFILE_TOOLS:
            rows.append((variant, int(m.group("ready")), int(m.group("manual"))))
    return rows


def test_tool_count_table_covers_every_variant() -> None:
    """No vacuous pass: the parser must find all four rows."""
    found = {v for v, _, _ in _tool_count_table_rows()}
    assert found == set(PROFILE_TOOLS), (
        f"the Docker Image Tool Counts table parsed as {sorted(found)}; "
        f"expected {sorted(PROFILE_TOOLS)}. The table format probably changed."
    )


@pytest.mark.parametrize("variant", sorted(PROFILE_TOOLS))
def test_tool_count_table_row_is_correct(variant: str) -> None:
    """Each row's Docker-Ready and Manual counts must match the registry."""
    rows = {v: (r, m) for v, r, m in _tool_count_table_rows()}
    ready, manual = rows[variant]
    profile = set(PROFILE_TOOLS[variant])
    want_manual = len(MANUAL_INSTALL_TOOLS & profile)
    want_ready = len(profile) - want_manual
    assert (ready, manual) == (want_ready, want_manual), (
        f"docs/MANUAL_INSTALLATION.md's tool-count table says {variant} has "
        f"{ready} Docker-ready / {manual} manual; the registry gives "
        f"{want_ready} / {want_manual}"
    )


def test_guard_sees_a_non_trivial_number_of_claims() -> None:
    """No vacuous pass: the docs must actually contain claims to check.

    If the wording changes so the regexes stop matching, every parametrised test
    above would pass on zero matches and look like a clean surface.
    """
    total = 0
    for rel in ADVERTISED_DOCS:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        total += len(_DOCKER_READY.findall(text)) + len(_MANUAL_COUNT.findall(text))
    assert total >= 6, (
        f"only {total} count-claims matched across {len(ADVERTISED_DOCS)} docs; "
        f"the regexes have probably fallen behind the wording"
    )


def test_detector_flags_the_shape_that_shipped() -> None:
    """Positive control, using the exact sentence that was wrong."""
    shipped = (
        "- **28 total tools**: 25 Docker-ready (automatically included), "
        "3 manual install (AFL++, MobSF, Akto)"
    )
    assert [int(m) for m in _DOCKER_READY.findall(shipped)] == [25]
    assert [int(m) for m in _MANUAL_COUNT.findall(shipped)] == [3]
    # ...and the older, independently-drifted shape.
    stale = "# Deep - Maximum coverage (29 tools, 26 Docker-ready)"
    assert [int(m) for m in _DOCKER_READY.findall(stale)] == [26]
