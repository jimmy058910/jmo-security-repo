#!/usr/bin/env python3
"""Fail a CI step whose pytest run passed fewer tests than it must.

    python scripts/dev/require_passed.py <junit.xml> [--min N] [--max-skipped M]

pytest exits 0 for a run of skips, so a job whose every test skips reads green:
the juice-shop smoke job reported 22 or 24 skipped and 0 passed for months
(#1349). Run this after a pytest step that writes `--junitxml`. A missing report
fails too: no evidence is not a pass.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET  # nosec B405 - pytest's own report, not untrusted input
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("report", type=Path, help="pytest's --junitxml file")
    ap.add_argument("--min", type=int, default=1, help="tests that must pass")
    ap.add_argument(
        "--max-skipped", type=int, default=None, help="skips allowed (default: any)"
    )
    args = ap.parse_args(argv)

    if not args.report.is_file():
        print(f"no pytest report at {args.report}: nothing ran, which is not a pass")
        return 1
    root = ET.parse(args.report).getroot()  # nosec B314
    counts = {"passed": 0, "skipped": 0, "xfailed": 0, "failed": 0, "errors": 0}
    for case in root.iter("testcase"):
        if case.find("error") is not None:
            counts["errors"] += 1
        elif case.find("failure") is not None:
            counts["failed"] += 1
        elif (skip := case.find("skipped")) is not None:
            # junit has no xfail: pytest writes one as a skip of this type.
            counts["xfailed" if skip.get("type") == "pytest.xfail" else "skipped"] += 1
        else:
            counts["passed"] += 1
    passed = counts["passed"]
    print(
        ", ".join(f"{n} {k}" for k, n in counts.items())
        + f" (at least {args.min} must pass)"
    )
    too_many_skips = (
        args.max_skipped is not None and counts["skipped"] > args.max_skipped
    )
    if too_many_skips:
        print(f"at most {args.max_skipped} may skip: a skipped test checked nothing")
    return 0 if passed >= args.min and not too_many_skips else 1


if __name__ == "__main__":
    sys.exit(main())
