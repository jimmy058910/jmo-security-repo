#!/usr/bin/env python3
"""Reconcile a scan: every requested tool has exactly one row on every target.

Acceptance is NEVER "the scan exited 0". That is the failure this exists to
catch: on a deliberately-vulnerable repository, a run once reported
``Policy evaluation complete: 2/2 passed`` and exit 0 while three tools had
failed and written nothing at all.

Since v2.0.0 Phase 3 the scan writes the account itself: one row per requested
tool per target, ``ran``, ``skipped:<reason>`` or ``failed:<reason>``, in
``.scan_metadata.json``'s ``tool_runs`` and in each target's
``scan-timings.json``. This used to rebuild eight states by scraping log lines
out of stderr, because no artifact had them; now it checks the rows:

- every declared tool has **exactly one** row on every target (none missing,
  none twice), and no row names an undeclared tool;
- every row parses into a valid state and reason;
- a ``ran`` row has an output file that parses;
- each ``scan-timings.json`` names a target the metadata has rows for, no
  other document names it, and its row for every tool equals the metadata's.
  A target with rows and no document is fine: its scanner raised before
  writing one.

The invariant is environment-independent: it holds with no tools installed
(every row ``failed:not installed``), with a full install, and inside a Docker
image. Only the distribution moves. Assert the invariant, never a distribution.

Usage::

    python scripts/dev/reconcile_scan_accounting.py <results-dir> [--tools trivy semgrep ...]

Exits non-zero if the invariant does not hold.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Importable as `scripts.dev.reconcile_scan_accounting` (pytest sets
# pythonpath=["."]), and runnable as a plain script from anywhere.
if __package__ in (None, ""):  # pragma: no cover - only on direct execution
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.core.scan_timings import SCAN_TIMINGS_FILENAME, State, ToolRun

Key = tuple[str, str]  # (target_type, target)


@dataclass
class Reconciliation:
    """The rows by target, and every way they fail the invariant."""

    rows: dict[Key, dict[str, ToolRun]] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    duplicate: list[str] = field(default_factory=list)
    stray: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)
    no_output: list[str] = field(default_factory=list)
    timings_disagree: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (
            self.missing
            or self.duplicate
            or self.stray
            or self.invalid
            or self.no_output
            or self.timings_disagree
        )


def _parses(path: Path) -> bool:
    """JSON, or NDJSON (trufflehog, nuclei), or empty NDJSON."""
    raw = path.read_bytes().decode("utf-8", errors="replace")
    try:
        json.loads(raw)
        return True
    except json.JSONDecodeError:
        try:
            for line in raw.splitlines():
                if line.strip():
                    json.loads(line)
        except json.JSONDecodeError:
            return False
        return True


def _check_rows(
    result: Reconciliation, where: str, entries: list, declared: list[str]
) -> dict[str, ToolRun]:
    """One target's rows: parse them, and flag a missing, doubled or stray tool."""
    rows: dict[str, ToolRun] = {}
    for entry in entries:
        try:
            row = ToolRun.from_dict(entry)
        except (KeyError, TypeError, ValueError) as exc:
            result.invalid.append(f"{where}: {entry!r}: {exc}")
            continue
        if row.tool in rows:
            result.duplicate.append(f"{where}: {row.tool}")
        if row.tool not in declared:
            result.stray.append(f"{where}: {row.tool}")
        rows[row.tool] = row
    result.missing.extend(f"{where}: {t}" for t in declared if t not in rows)
    return rows


def reconcile(results_dir: Path, declared: list[str] | None = None) -> Reconciliation:
    """Check a finished scan's rows against the tools it was asked for.

    The metadata's rows are what history stores, and include a target whose
    scanner raised before writing anything. Each `scan-timings.json` is checked
    on its own too, and a `ran` row's output must sit beside it and parse.
    """
    result = Reconciliation()
    meta = json.loads((results_dir / ".scan_metadata.json").read_bytes())
    declared = list(declared or meta.get("tools") or [])

    by_target: dict[Key, list] = {}
    for entry in meta.get("tool_runs") or []:
        try:
            key: Key = (str(entry["target_type"]), str(entry["target"]))
        except (KeyError, TypeError) as exc:
            result.invalid.append(f"{entry!r}: {exc}")
            continue
        by_target.setdefault(key, []).append(entry)
    for key, entries in by_target.items():
        result.rows[key] = _check_rows(result, key[1], entries, declared)

    documents = sorted(results_dir.glob(f"individual-*/*/{SCAN_TIMINGS_FILENAME}"))
    named: dict[Key, str] = {}
    for timings in documents:
        folder = timings.parent
        where = f"{folder.parent.name}/{folder.name}"
        doc = json.loads(timings.read_bytes())
        rows = _check_rows(result, where, doc.get("tools") or [], declared)
        for tool, row in rows.items():
            if row.state is State.RAN:
                output = folder / f"{tool}.json"
                if not output.is_file() or not _parses(output):
                    result.no_output.append(f"{where}: {tool}")
        if rows:
            _compare(result, where, doc, rows, named)
    return result


def _compare(
    result: Reconciliation,
    where: str,
    doc: dict,
    rows: dict[str, ToolRun],
    named: dict[Key, str],
) -> None:
    """One timings document against the metadata's rows for the target it
    names: the same target, named once, with the same row for every tool."""
    key: Key = (str(doc.get("target_type")), str(doc.get("target")))
    if key in named:
        result.timings_disagree.append(
            f"{where}: names {key[0]} {key[1]}, as {named[key]} does"
        )
        return
    named[key] = where
    if key not in result.rows:
        result.timings_disagree.append(
            f"{where}: names {key[0]} {key[1]}, which .scan_metadata.json has no "
            "rows for"
        )
        return
    for tool, row in rows.items():
        meta_row = result.rows[key].get(tool)
        if meta_row is not None and meta_row.to_dict() != row.to_dict():
            result.timings_disagree.append(
                f"{where}: {tool} is {row.label} here, {meta_row.label} in "
                ".scan_metadata.json"
            )


def render(result: Reconciliation, label: str) -> None:
    """Print the table and the verdict."""
    print(f"\n{'=' * 78}\nRECONCILIATION: {label}\n{'=' * 78}")
    for (target_type, target), rows in sorted(result.rows.items()):
        print(f"\n{target_type}: {target}")
        for tool, row in rows.items():
            print(f"  {tool:<12}{row.label:<36}{row.seconds:8.2f}s")
    for name, items in (
        ("MISSING (declared, no row)", result.missing),
        ("DUPLICATE (two rows)", result.duplicate),
        ("STRAY (row for an undeclared tool)", result.stray),
        ("INVALID (row does not parse)", result.invalid),
        ("RAN WITHOUT OUTPUT", result.no_output),
        ("TIMINGS DISAGREE", result.timings_disagree),
    ):
        if items:
            print(f"\nFAIL  {name} ({len(items)}): {items}")
    print(f"\nVERDICT: {'PASS' if result.ok else 'FAIL'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check that a scan accounted for every requested tool."
    )
    parser.add_argument("results_dir", type=Path, help="Scan results directory")
    parser.add_argument(
        "--tools",
        nargs="+",
        default=None,
        help="Tools the scan declared (default: .scan_metadata.json's tools)",
    )
    args = parser.parse_args(argv)
    result = reconcile(args.results_dir, args.tools)
    render(result, args.results_dir.name)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
