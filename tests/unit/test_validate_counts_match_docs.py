"""The check counts `jmo validate` advertises must match what it runs.

`jmo validate --help` claimed **176** quick-tier checks and **207** with
`--tier full`. A real run produced **252** and **283**. Both advertised numbers
were internally consistent -- they were the sum of the four validators'
docstring claims -- so nothing in the codebase disagreed with them, and
`docs/CLI_REFERENCE.md` said "Runs 207 checks" in prose while its own category
table summed to 253 three lines below.

Two numbers that agree with each other and with nothing that runs is the shape
this guards against. Everything here is derived or cross-checked; no count is
restated in two places without something asserting they match.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from scripts.cli.jmo import build_parser
from scripts.core.validators.cli_validator import (
    _FIXED_QUICK_COUNT,
    _FULL_TIER_COUNT,
    derive_surface,
)

REPO = Path(__file__).resolve().parents[2]
CLI_REFERENCE = REPO / "docs" / "CLI_REFERENCE.md"


def _doc_table() -> dict[str, tuple[int, int]]:
    """Parse the `jmo validate` category table out of CLI_REFERENCE.md."""
    text = CLI_REFERENCE.read_text(encoding="utf-8")
    section = text[text.index("### jmo validate") :]
    section = section[: section.index("**Exit codes:**")]

    rows: dict[str, tuple[int, int]] = {}
    for line in section.splitlines():
        match = re.match(
            r"\|\s*(?:\*\*)?([A-Za-z][A-Za-z \-]*?)(?:\*\*)?\s*\|"
            r"\s*(?:\*\*)?(\d+)(?:\*\*)?\s*\|"
            r"\s*(?:\*\*)?(\d+)(?:\*\*)?\s*\|",
            line,
        )
        if match:
            rows[match.group(1).strip()] = (int(match.group(2)), int(match.group(3)))
    return rows


def _help_epilog_counts() -> tuple[int, int]:
    """Read the two counts out of `jmo validate --help`."""
    top = build_parser()._subparsers._group_actions[0].choices
    epilog = top["validate"].description or ""
    quick = re.search(r"Quick validation \((\d+) checks\)", epilog)
    full = re.search(r"Full validation \((\d+) checks\)", epilog)
    assert quick and full, "the --help epilog no longer states its check counts"
    return int(quick.group(1)), int(full.group(1))


def test_doc_table_parses():
    """Meta-guard: an extractor that finds nothing passes everything built on it."""
    rows = _doc_table()
    assert set(rows) >= {
        "CLI Completeness",
        "Scan Correctness",
        "Cross-Platform",
        "Release Artifacts",
        "Total",
    }, sorted(rows)


def test_cli_row_matches_the_parser():
    """The CLI Completeness row is sized by the parser, so derive it.

    This is the row that drifts: it grows whenever a subcommand is added.
    `MAIN_SUBCOMMANDS` covered 13 of 20 (#783) and the docs recorded the
    resulting undercount as fact.
    """
    main, nested = derive_surface(build_parser())
    quick = len(main) + sum(len(v) for v in nested.values()) + _FIXED_QUICK_COUNT
    full = quick + _FULL_TIER_COUNT

    doc_quick, doc_full = _doc_table()["CLI Completeness"]
    assert (doc_quick, doc_full) == (quick, full), (
        f"docs say CLI Completeness is {doc_quick}/{doc_full}; "
        f"the parser makes it {quick}/{full}"
    )


def test_doc_total_row_is_the_sum_of_its_own_rows():
    """The table must add up. Its prose used to contradict it by 46."""
    rows = _doc_table()
    total = rows["Total"]
    parts = [v for k, v in rows.items() if k != "Total"]
    assert total == (sum(q for q, _ in parts), sum(f for _, f in parts))


def test_help_epilog_matches_the_doc_total():
    """`--help` and CLI_REFERENCE.md must state the same number."""
    assert _help_epilog_counts() == _doc_table()["Total"]


def test_prose_sentence_matches_the_table():
    """The "Runs N checks" sentence said 207 while the table below summed to 253."""
    text = CLI_REFERENCE.read_text(encoding="utf-8")
    section = text[text.index("### jmo validate") :][:600]
    match = re.search(r"Runs (\d+) checks", section)
    assert match, "the jmo validate section no longer states a headline count"
    assert int(match.group(1)) == _doc_table()["Total"][0]


@pytest.mark.parametrize("variant", ["fast", "slim", "balanced", "deep"])
def test_build_help_tool_counts_match_profile_tools(variant):
    """`jmo build --help` listed 8/14/18/28 tools; PROFILE_TOOLS has 9/13/17/28."""
    from scripts.cli.tool_manager import PROFILE_TOOLS

    top = build_parser()._subparsers._group_actions[0].choices
    epilog = top["build"].description or ""
    match = re.search(rf"^\s*{variant}\s+(\d+) tools", epilog, re.MULTILINE)
    assert match, f"`jmo build --help` no longer lists a tool count for {variant}"
    assert int(match.group(1)) == len(PROFILE_TOOLS[variant])
