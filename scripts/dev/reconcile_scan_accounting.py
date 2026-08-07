#!/usr/bin/env python3
"""Reconcile a scan: every declared tool must land in exactly one state.

Acceptance is NEVER "the scan exited 0". That is the failure this exists to
catch: on a deliberately-vulnerable repository, a run once reported
``Policy evaluation complete: 2/2 passed`` and exit 0 while three tools had
failed and written nothing at all.

Each of the profile's declared tools must be in exactly one of:

===============  ==========================================================
``output``       produced a parseable output file
``no_output``    ran, returned an accepted code, wrote nothing -> reported
``failed``       ran and failed or timed out -> reported with its cause
``unrouted``     not applicable to any target type in this scan -> reported
``unresolved``   implemented, executable not found -> reported
``not_impl``     requested, no code path for this target type -> reported
``idle``         implemented and installed, no matching files -> reported
===============  ==========================================================

Anything in zero states is UNACCOUNTED (a silent omission).
Anything in two or more states is CONTRADICTORY (the diagnostics disagree).
Both are bugs.

``manual`` (a MANUAL_INSTALL_TOOLS member) is a property of the *tool*, not an
account of what happened to it, so it never satisfies the invariant on its own
and never counts toward a contradiction.

The invariant is environment-independent: it holds with zero tools installed
(everything ``unresolved``), with a full local install (mixed), and inside a
Docker image (mostly ``output``). Only the distribution moves. Measured on the
same fixture repo: 28/28 accounted with 22 tools installed, and 28/28 accounted
with ``HOME`` and ``PATH`` stripped. Assert the invariant, never a distribution.

Usage::

    python scripts/dev/reconcile_scan_accounting.py <results-dir> <stderr-log> \\
        [--label NAME] [--profile deep]

Exits non-zero if any declared tool is in zero or two states.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Importable as `scripts.dev.reconcile_scan_accounting` (pytest sets
# pythonpath=["."]), and runnable as a plain script from anywhere. The repo root
# is derived from __file__ rather than hardcoded, so this works in a worktree,
# a checkout under a different name, or on another machine.
if __package__ in (None, ""):  # pragma: no cover - only on direct execution
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.core.tool_registry import (
    MANUAL_INSTALL_TOOLS,
    PROFILE_TOOLS,
)

# Ways a tool can be accounted for. "manual" is deliberately absent: see module
# docstring. Order is presentation only.
ACCOUNTED_STATES = (
    "output",
    "no_output",
    "failed",
    "unrouted",
    "skipped",
    "unresolved",
    "not_impl",
    "idle",
)


@dataclass(frozen=True)
class Diagnostics:
    """What the scanner said about each tool, on its own streams."""

    unresolved: frozenset[str] = frozenset()
    not_impl: frozenset[str] = frozenset()
    idle: frozenset[str] = frozenset()
    no_output: frozenset[str] = frozenset()
    failed: frozenset[str] = frozenset()
    unrouted: frozenset[str] = frozenset()

    # Dropped by --skip-tools. Deliberately NOT folded into `unresolved`:
    # "the operator asked me not to run this" and "I could not find it" are
    # different facts, and reporting the first as the second is the kind of
    # near-enough accounting this instrument exists to catch.
    skipped: frozenset[str] = frozenset()

    # Transient progress glyphs. NOT a durable account - a non-TTY run may never
    # render these - but they distinguish "failed with no explanation" from
    # "never mentioned at all", which are different bugs.
    tick_ok: frozenset[str] = frozenset()
    tick_fail: frozenset[str] = frozenset()


@dataclass
class Reconciliation:
    """Per-tool states plus every way this scan failed to account for itself."""

    states: dict[str, list[str]] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)
    unaccounted: list[str] = field(default_factory=list)
    contradictory: list[str] = field(default_factory=list)
    silent_fail: list[str] = field(default_factory=list)
    never_mentioned: list[str] = field(default_factory=list)
    stray_reported: list[str] = field(default_factory=list)
    stray_output: list[str] = field(default_factory=list)
    unparseable: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True only if the scan fully accounted for itself."""
        return not (
            self.silent_fail
            or self.never_mentioned
            or self.contradictory
            or self.stray_reported
            or self.stray_output
            or self.unparseable
        )


def _states_by_name(diags: Diagnostics) -> dict[str, frozenset[str]]:
    """Map state name -> the tools the scanner placed in it.

    Written out rather than reached via ``getattr(diags, state)``: a dynamic
    attribute lookup is invisible to mypy, which is how the ``threads: auto``
    crash reached a release. If a field is renamed, this stops type-checking.
    """
    return {
        "no_output": diags.no_output,
        "failed": diags.failed,
        "unrouted": diags.unrouted,
        "skipped": diags.skipped,
        "unresolved": diags.unresolved,
        "not_impl": diags.not_impl,
        "idle": diags.idle,
    }


def parse_log(log_text: str) -> Diagnostics:
    """Pull the scanner's own diagnostics out of the stderr stream.

    Scans the whole text rather than iterating JSON lines. Rich writes progress
    frames to stderr without newlines, so a real run puts hundreds of in-place
    spinner frames and then a JSON diagnostic on one physical line; line-wise
    JSON parsing drops that diagnostic and reports its tool as unaccounted.
    """
    unresolved: set[str] = set()
    not_impl: set[str] = set()
    idle: set[str] = set()
    no_output: set[str] = set()
    failed: set[str] = set()
    unrouted: set[str] = set()
    skipped: set[str] = set()
    tick_ok: set[str] = set()
    tick_fail: set[str] = set()

    for m in re.finditer(
        r"(\w[\w+.-]*): requested but its (?:executable|dependency [`\\]*\S+?[`\\]*) "
        r"could not be found",
        log_text,
    ):
        unresolved.add(m.group(1))

    # Reported at run time by the result loop.
    for m in re.finditer(
        r"(\w[\w+.-]*): its executable was not found at run time", log_text
    ):
        unresolved.add(m.group(1))

    for m in re.finditer(
        r"(\w[\w+.-]*): it exited with an accepted code but wrote no output", log_text
    ):
        no_output.add(m.group(1))

    for m in re.finditer(
        r"(\w[\w+.-]*): it (?:failed|timed out) - it did NOT", log_text
    ):
        failed.add(m.group(1))

    for m in re.finditer(
        r"applicable to no target type in this scan[^:]*: (.+?)(?:\"|$)",
        log_text,
        re.MULTILINE,
    ):
        unrouted.update(t.strip() for t in m.group(1).split(","))

    # Pre-flight drop, emitted by jmo.py's JSON logger before scan_repository.
    for m in re.finditer(r'"msg": "Skipping \d+ missing tool\(s\): ([^"]+)"', log_text):
        unresolved.update(t.strip() for t in m.group(1).split(","))

    # Dropped by --skip-tools. Kept apart from the "missing" case above: this
    # one is the operator's choice, not a resolution failure. Before jmo.py
    # logged it at all, a skipped tool appeared in no stream and no artifact -
    # NEVER MENTIONED, the same shape as the silently filtered nuclei/lynis.
    for m in re.finditer(
        r'"msg": "Skipping \d+ tool\(s\) at user request \(--skip-tools\): ([^"]+)"',
        log_text,
    ):
        skipped.update(t.strip() for t in m.group(1).split(","))

    for m in re.finditer(
        r"no repository implementation\): (.+?)(?:\"|$)", log_text, re.MULTILINE
    ):
        not_impl.update(t.strip() for t in m.group(1).split(","))

    for m in re.finditer(
        r"No matching files in \S+ for: (.+?)(?:\"|$)", log_text, re.MULTILINE
    ):
        idle.update(t.strip() for t in m.group(1).split(","))

    # Same event as above, in --human-logs rendering.
    for m in re.finditer(
        r"\[ERROR\] (\S+): exited with an accepted code but wrote no output", log_text
    ):
        no_output.add(m.group(1))

    for m in re.finditer(r"\[\d+/\d+\] ✓ (\S+) ", log_text):
        tick_ok.add(m.group(1))
    for m in re.finditer(r"\[\d+/\d+\] ✗ (\S+) ", log_text):
        tick_fail.add(m.group(1))

    return Diagnostics(
        unresolved=frozenset(unresolved),
        not_impl=frozenset(not_impl),
        idle=frozenset(idle),
        no_output=frozenset(no_output),
        failed=frozenset(failed),
        unrouted=frozenset(unrouted),
        skipped=frozenset(skipped),
        tick_ok=frozenset(tick_ok),
        tick_fail=frozenset(tick_fail),
    )


# Filenames under `individual-*/<target>/` that are scan metadata rather than a
# tool's findings. Every other `*.json` there is mapped to a tool by its stem, so
# an unlisted artifact is reported as `stray_output` -- correctly, since that is
# the check that catches a tool nobody declared having written a file.
#
# Keep this an explicit allowlist, never a pattern. The invariant is worth more
# than the convenience: a new artifact should have to be named here on purpose,
# because the alternative is a rule loose enough to also swallow a real tool.
NON_TOOL_ARTIFACTS = frozenset({"scan-timings"})


def parse_outputs(results_dir: Path) -> tuple[dict[str, int], frozenset[str]]:
    """Map tool -> record count for every output file that actually parses."""
    counts: dict[str, int] = {}
    unparseable: set[str] = set()
    for target in sorted(results_dir.glob("individual-*/*")):
        if not target.is_dir():
            continue
        for f in sorted(target.glob("*.json")):
            tool = f.stem
            if tool in NON_TOOL_ARTIFACTS:
                continue
            raw = f.read_text(encoding="utf-8", errors="replace")
            n: int | None = None
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                # trufflehog emits NDJSON (one object per line), not an array.
                # Treating that as unparseable would report a working tool as
                # broken - the same false-diagnostic class this script exists
                # to catch, so it must not commit it itself.
                lines = [ln for ln in raw.splitlines() if ln.strip()]
                try:
                    for ln in lines:
                        json.loads(ln)
                    n = len(lines)
                except json.JSONDecodeError:
                    unparseable.add(tool)
                    continue
            if n is None:
                if isinstance(data, list):
                    n = len(data)
                elif isinstance(data, dict):
                    n = len(data.get("results") or data.get("findings") or data) or 0
                else:
                    n = 0
            counts[tool] = counts.get(tool, 0) + n
    return counts, frozenset(unparseable)


def reconcile(
    declared: list[str],
    diags: Diagnostics,
    output_counts: dict[str, int],
    unparseable: frozenset[str] = frozenset(),
    manual: frozenset[str] = frozenset(),
) -> Reconciliation:
    """Assign every declared tool its states and report every disagreement."""
    result = Reconciliation()
    by_state = _states_by_name(diags)

    for tool in declared:
        states: list[str] = []
        if tool in output_counts:
            states.append("output")
        states.extend(state for state, tools in by_state.items() if tool in tools)

        if tool in unparseable:
            result.notes[tool] = "UNPARSEABLE"
        elif tool in output_counts:
            result.notes[tool] = f"{output_counts[tool]} records"

        if not states:
            result.unaccounted.append(tool)
            # A tool whose only trace is a progress glyph did run and had its
            # failure discarded; one with no trace at all was dropped before it
            # ever ran. Different bugs, different fixes.
            if tool in diags.tick_fail:
                result.notes[tool] = "failed - progress glyph only, NO message"
                result.silent_fail.append(tool)
            else:
                result.notes[tool] = "never mentioned in any stream"
                result.never_mentioned.append(tool)
        elif len(states) > 1:
            result.contradictory.append(tool)

        if tool in manual:
            states.append("manual")
        result.states[tool] = states

    # Names the scanner reported on that are not profile tools at all. `docker`
    # and `zap-baseline.py` were once reported as tools with missing findings;
    # both are implementation details of zap.
    reported = (
        diags.unresolved
        | diags.not_impl
        | diags.idle
        | diags.failed
        | diags.unrouted
        | diags.skipped
        | diags.no_output
    )
    result.stray_reported = sorted(reported - set(declared))
    result.stray_output = sorted(set(output_counts) - set(declared))
    result.unparseable = sorted(unparseable)
    return result


def render(result: Reconciliation, declared: list[str], label: str) -> None:
    """Print the table and the verdict."""
    print(f"\n{'=' * 78}\nRECONCILIATION: {label}\n{'=' * 78}")
    print(f"{'tool':<20}{'state(s)':<34}note")
    print("-" * 78)
    for tool in declared:
        states = result.states.get(tool, [])
        rendered = ", ".join(states) if states else "*** UNACCOUNTED ***"
        print(f"{tool:<20}{rendered:<34}{result.notes.get(tool, '')}")

    counted: dict[str, list[str]] = {state: [] for state in ACCOUNTED_STATES}
    for tool, states in result.states.items():
        for state in states:
            if state in counted:
                counted[state].append(tool)

    print("-" * 78)
    print(f"declared          : {len(declared)}")
    for state in ACCOUNTED_STATES:
        print(f"{state:<18}: {len(counted[state])}  {sorted(counted[state])}")

    print()
    if result.silent_fail:
        print(
            f"FAIL  FAILED WITH NO EXPLANATION ({len(result.silent_fail)}): "
            f"{result.silent_fail}"
            "\n      (a transient progress glyph is the only trace; a non-TTY run"
            "\n       leaves no record at all)"
        )
    if result.never_mentioned:
        print(
            f"FAIL  NEVER MENTIONED ({len(result.never_mentioned)}): "
            f"{result.never_mentioned}"
            "\n      (declared in the profile and absent from every stream and artifact)"
        )
    if result.contradictory:
        print(
            f"FAIL  CONTRADICTORY ({len(result.contradictory)}): {result.contradictory}"
        )
    if result.stray_reported:
        print(
            f"FAIL  reported as tools but not in profile "
            f"({len(result.stray_reported)}): {result.stray_reported}"
        )
    if result.stray_output:
        print(f"FAIL  output files for non-profile names: {result.stray_output}")
    if result.unparseable:
        print(f"FAIL  unparseable output: {result.unparseable}")

    print(f"\nVERDICT: {'PASS' if result.ok else 'FAIL'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconcile a scan's declared tools against what it produced."
    )
    parser.add_argument("results_dir", type=Path, help="Scan results directory")
    parser.add_argument("log", type=Path, help="Captured stderr log from the scan")
    parser.add_argument("--label", default=None, help="Name for the report header")
    parser.add_argument(
        "--profile",
        default="deep",
        choices=sorted(PROFILE_TOOLS),
        help="Profile whose declared tools must be accounted for (default: deep)",
    )
    args = parser.parse_args(argv)

    declared = list(PROFILE_TOOLS[args.profile])
    diags = parse_log(args.log.read_text(encoding="utf-8", errors="replace"))
    counts, unparseable = parse_outputs(args.results_dir)
    result = reconcile(
        declared=declared,
        diags=diags,
        output_counts=counts,
        unparseable=unparseable,
        manual=frozenset(MANUAL_INSTALL_TOOLS),
    )
    render(result, declared, args.label or args.results_dir.name)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
