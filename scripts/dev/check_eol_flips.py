#!/usr/bin/env python3
"""Fail when a change converts a file's line endings.

This repository stores line endings byte-for-byte and they are mixed per file,
so rewriting a CRLF file as LF (or the reverse) turns a small edit into a
whole-file diff. The `mixed-line-ending` hook cannot see it: a converted file is
perfectly consistent, just consistently different.

The check compares `git diff --numstat` with `git diff --numstat
--ignore-cr-at-eol` over the WHOLE diff, with rename detection on. Checking one
path at a time (`git diff ... -- <path>`) cannot pair a rename, so a renamed
file whose endings flipped reads as a delete plus an add, and both agree with and
without `--ignore-cr-at-eol`. Measured 2026-09-24: a per-file loop reported 0
flips on the v2.0.0 Phase 2 tree while this comparison found a CRLF test file
renamed and rewritten as LF (+669/-1027 raw, +94/-452 ignoring CR).

Usage:
    check_eol_flips.py --cached              # pre-commit: the index against HEAD
    check_eol_flips.py --base HEAD^1         # CI: the checked-out tree against its base
    check_eol_flips.py --base origin/dev     # before pushing: the tree against a branch
    check_eol_flips.py ... --allow PATH      # a deliberate conversion (repeatable)

An untracked file is not in `git diff`; `git add` it first. Locally, pre-commit's
own `SKIP=eol-flips` also bypasses the hook.

Exit code 0 = no flips, 1 = flips found, 2 = git failed.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

GIT_TIMEOUT_S = 120


def numstat(extra: list[str]) -> dict[str, tuple[str, str, str]]:
    """Return {new path: (label, added, deleted)} for `git diff -M --numstat -z`.

    `-z` gives a rename as separate old and new paths instead of the
    `dir/{old => new}` display form, and never quotes a path.
    """
    proc = subprocess.run(
        ["git", "diff", "-M", "--numstat", "-z", *extra],
        capture_output=True,
        timeout=GIT_TIMEOUT_S,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", errors="replace"))
        raise SystemExit(2)
    fields = proc.stdout.split(b"\0")
    stats: dict[str, tuple[str, str, str]] = {}
    i = 0
    while i < len(fields) and fields[i]:
        added, deleted, path = (
            fields[i].decode("utf-8", errors="replace").split("\t", 2)
        )
        if path:
            new = label = path
            i += 1
        else:  # rename or copy: the old and new paths are the next two fields
            old = fields[i + 1].decode("utf-8", errors="replace")
            new = fields[i + 2].decode("utf-8", errors="replace")
            label = f"{old} -> {new}"
            i += 3
        stats[new] = (label, added, deleted)
    return stats


def find_flips(extra: list[str]) -> list[tuple[str, str]]:
    """Return [(new path, description)] for every file whose counts differ."""
    raw = numstat(extra)
    ignoring_cr = numstat([*extra, "--ignore-cr-at-eol"])
    flips = []
    for new, (label, added, deleted) in sorted(raw.items()):
        _, eol_added, eol_deleted = ignoring_cr.get(new, (label, "0", "0"))
        if (added, deleted) != (eol_added, eol_deleted):
            flips.append(
                (
                    new,
                    f"{label}: +{added}/-{deleted} raw, "
                    f"+{eol_added}/-{eol_deleted} ignoring CR",
                )
            )
    return flips


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cached", action="store_true", help="diff the index")
    parser.add_argument("--base", help="diff against this ref (default: HEAD / index)")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="PATH",
        help="a path whose conversion is deliberate (its new path, if renamed)",
    )
    args = parser.parse_args(argv)

    extra = (["--cached"] if args.cached else []) + ([args.base] if args.base else [])
    allowed = set(args.allow)
    flips = [desc for path, desc in find_flips(extra) if path not in allowed]
    if not flips:
        return 0
    print(f"{len(flips)} file(s) changed line endings, not only content:")
    for desc in flips:
        print(f"  {desc}")
    print(
        "Restore each file's original endings (convert its bytes back; the Edit tool\n"
        "keeps endings, but a file the Write tool or a script creates is LF), or pass\n"
        "--allow PATH for a deliberate conversion. See\n"
        ".claude/rules/windows-encoding.rules.md, 'Line Endings on Windows'."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
