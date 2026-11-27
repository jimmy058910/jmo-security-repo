#!/usr/bin/env python3
"""Fail a suite whose skipped tests are not exactly the ones it may skip.

    python scripts/dev/check_skip_set.py <pytest-report.json> \\
        --expected tests/e2e/expected-skips.yml --suite ubuntu

The scheduled e2e gate counted failures and errors, never skips, so a test that
began to skip read as a pass: on 2026-11-25 the Ubuntu suite skipped 9 tests
and a module and the macOS suite 16 and a module, and nothing said which. A
count cannot answer that either, since one new skip and one fixed one leave it
unchanged; this compares the node ids.

It reads a pytest-json-report file: every test whose outcome is `skipped`, and
every collector that skipped (a module that skips at import names no test).
The expected file maps each suite to the ids it may skip and why. The check
fails on

- a skip the file does not list: it checked nothing, and no one decided it may;
- a listed id that did not skip: it ran, or is no longer collected. The list
  must stay true, or a later skip of that id would pass unread.

A missing report or suite fails too: no evidence is not a pass.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml


def skipped_ids(report: dict) -> set[str]:
    """The node ids that skipped: tests, and collectors that skipped whole."""
    tests = {t["nodeid"] for t in report.get("tests", []) if t["outcome"] == "skipped"}
    collectors = {
        c["nodeid"]
        for c in report.get("collectors", [])
        if c.get("outcome") == "skipped" and c.get("nodeid")
    }
    return tests | collectors


def expected_ids(expected: dict, suite: str) -> dict[str, str]:
    """The ids `suite` may skip, each with its reason."""
    if suite not in expected:
        raise SystemExit(
            f"{suite!r} is not a suite in the expected file; it has {sorted(expected)}"
        )
    entries = expected[suite] or {}
    unexplained = sorted(i for i, why in entries.items() if not str(why or "").strip())
    if unexplained:
        raise SystemExit(f"entries with no reason for {suite!r}: {unexplained}")
    return dict(entries)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("report", type=Path, help="pytest-json-report's file")
    ap.add_argument("--expected", type=Path, required=True, help="the expected skips")
    ap.add_argument("--suite", required=True, help="the suite's key in that file")
    args = ap.parse_args(argv)

    if not args.report.is_file():
        print(f"no pytest report at {args.report}: nothing ran, which is not a pass")
        return 1
    report = json.loads(args.report.read_bytes())
    expected = expected_ids(
        yaml.safe_load(args.expected.read_bytes()) or {}, args.suite
    )
    skipped = skipped_ids(report)

    unexpected = sorted(skipped - set(expected))
    stale = sorted(set(expected) - skipped)
    for node in unexpected:
        print(f"::error::{node} skipped, and {args.expected} does not list it")
    for node in stale:
        print(
            f"::error::{node} is listed to skip ({expected[node]}) and did not: "
            f"it ran or is gone, so remove it from {args.expected}"
        )
    print(
        f"{args.suite}: {len(skipped)} skipped, {len(expected)} expected, "
        f"{len(unexpected)} unexpected, {len(stale)} listed but not skipped"
    )
    return 1 if unexpected or stale else 0


if __name__ == "__main__":
    sys.exit(main())
