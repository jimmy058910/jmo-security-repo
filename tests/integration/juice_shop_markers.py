"""juice-shop's own vulnerable-line markers, as an answer key for a full scan.

juice-shop marks each deliberately vulnerable line with an end-of-line comment:
``// vuln-code-snippet vuln-line <challenge> ...`` in TypeScript and Solidity,
``# vuln-code-snippet vuln-line <challenge> ...`` in YAML and Terraform. This
module reads those comments from a clone (``parse_markers``), looks up which
tools reported a finding on each marked line (``detection_table``), and records
the result in tests/integration/baselines/juice-shop.markers.json. The marker
test in test_baseline_validation.py fails when a line recorded as detected is
detected by nobody.

Nothing from juice-shop leaves the clone except (file, line, challenge) and the
names of the tools that detected a line. A marker has no text field on purpose:
two marked Terraform lines hold juice-shop's RSA private key, which no test
output, JSON file or commit may carry.

Re-record after a pin bump, or after a change that detects or loses a line, from
a clone at the pin and the results directory of a full scan of it::

    python -m tests.integration.juice_shop_markers record <clone> <results_dir>
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tests.integration.targets import (
    JUICE_SHOP_COMMIT,
    PINNED_TARGETS,
    PROJECT_ROOT,
    count_by_tool,
    finding_tools,
    load_findings,
)

MARKERS_FILE = (
    PROJECT_ROOT / "tests" / "integration" / "baselines" / "juice-shop.markers.json"
)

# One git call over a depth-1 clone.
GIT_TIMEOUT = 120

# The directive closes a code line: after ``vuln-line`` come challenge
# identifiers and nothing else. That is what keeps juice-shop's own marker
# reader (a regular expression that names the directive and is followed by
# more code) from counting as two marked lines.
_MARKER = re.compile(
    r"(?://|#)[ \t]*vuln-code-snippet[ \t]+vuln-line"
    r"((?:[ \t]+[A-Za-z_][A-Za-z0-9_]*)+)[ \t\r]*$"
)


@dataclass(frozen=True, order=True)
class Marker:
    """One challenge named on one vulnerable line. Position only, never text."""

    file: str  # repo-relative, POSIX separators
    line: int  # 1-based
    challenge: str


@dataclass(frozen=True)
class MarkedLine:
    """One vulnerable line: every challenge it names, every tool that found it."""

    file: str
    line: int
    challenges: tuple[str, ...]
    tools: tuple[str, ...]  # sorted; empty when no tool reported the line


def parse_markers(root: Path) -> list[Marker]:
    """Return the vulnerable-line markers of the files git tracks under ``root``.

    Lines are counted by ``\\n`` alone, as the scanners count them, so ``\\f``
    or U+2028 inside a line does not move a marker. A file that is not UTF-8, is
    a symlink (a clone chooses where its links point) or cannot be read is
    skipped. Sorted by file, line, then challenge.
    """
    listing = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
        timeout=GIT_TIMEOUT,
    ).stdout

    markers: list[Marker] = []
    for raw_name in listing.split(b"\0"):
        if not raw_name:
            continue
        try:
            name = raw_name.decode("utf-8")
            path = root / name
            if path.is_symlink():
                continue
            data = path.read_bytes()
            text = data.decode("utf-8") if b"vuln-code-snippet" in data else ""
        except (UnicodeDecodeError, OSError):  # a submodule, a deleted file, binary
            continue

        for number, line in enumerate(text.split("\n"), start=1):
            match = _MARKER.search(line)
            if match:
                markers.extend(Marker(name, number, c) for c in match.group(1).split())
    return sorted(markers)


def detection_table(
    markers: list[Marker], findings: list[dict[str, Any]]
) -> list[MarkedLine]:
    """Return one row per marked line with the tools that reported it.

    A finding detects a line when its ``location.path`` equals the marker's path
    and ``startLine <= line <= endLine`` (no ``endLine``: ``startLine``). The
    line's tools are the union over those findings of ``finding_tools``: the
    reporting tool plus every member of a cluster. Sorted by file and line.
    """
    ranges: dict[str, list[tuple[int, int, set[str]]]] = defaultdict(list)
    for found in findings:
        location = found.get("location")
        if not isinstance(location, dict):
            continue
        path, start = location.get("path"), location.get("startLine")
        if not isinstance(path, str) or not isinstance(start, int):
            continue
        end = location.get("endLine") or start
        ranges[path].append((start, end, finding_tools(found)))

    challenges: dict[tuple[str, int], list[str]] = {}
    for marker in sorted(markers):
        challenges.setdefault((marker.file, marker.line), []).append(marker.challenge)

    rows = []
    for (file, line), names in sorted(challenges.items()):
        tools: set[str] = set()
        for start, end, reported in ranges.get(file, ()):
            if start <= line <= end:
                tools |= reported
        rows.append(MarkedLine(file, line, tuple(names), tuple(sorted(tools))))
    return rows


def recall_by_type(rows: list[MarkedLine]) -> dict[str, dict[str, int]]:
    """Count marked and detected lines per file extension (a line, not a challenge)."""
    counts: dict[str, dict[str, int]] = {}
    for row in rows:
        kind = Path(row.file).suffix or "(none)"
        entry = counts.setdefault(kind, {"marked": 0, "detected": 0})
        entry["marked"] += 1
        entry["detected"] += bool(row.tools)
    return dict(sorted(counts.items()))


def table_json(rows: list[MarkedLine], tools_used: list[str], generated: str) -> bytes:
    """Render the recorded table: LF line endings, rows in the order given."""
    detected = sum(bool(row.tools) for row in rows)
    document = {
        "metadata": {
            "target": PINNED_TARGETS["juice-shop"].slug,
            "commit": JUICE_SHOP_COMMIT,
            "generated": generated,
            "tools_used": tools_used,
        },
        "lines": [
            {
                "file": row.file,
                "line": row.line,
                "challenges": list(row.challenges),
                "tools": list(row.tools),
            }
            for row in rows
        ],
        "recall_by_type": recall_by_type(rows),
        "recall_total": {"marked": len(rows), "detected": detected},
    }
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


def record(clone: Path, results_dir: Path, output: Path = MARKERS_FILE) -> bytes:
    """Grade the scan in ``results_dir`` against ``clone`` and write the table.

    The clone must be at the pinned commit: the table names that commit, and a
    table derived from another tree would be graded against this one.
    """
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=clone,
        check=True,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT,
    ).stdout.strip()
    if head != JUICE_SHOP_COMMIT:
        raise RuntimeError(f"{clone} is at {head}, not the pinned {JUICE_SHOP_COMMIT}")

    findings = load_findings(results_dir)
    rows = detection_table(parse_markers(clone), findings)
    raw = table_json(
        rows,
        sorted(count_by_tool(findings)),
        datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    output.write_bytes(raw)
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="juice-shop vulnerable-line markers")
    commands = parser.add_subparsers(dest="command", required=True)
    recording = commands.add_parser(
        "record", help="write the recorded table from a clone and a scan of it"
    )
    recording.add_argument("clone", type=Path, help="juice-shop checked out at the pin")
    recording.add_argument(
        "results_dir", type=Path, help="the scan's results directory"
    )
    args = parser.parse_args(argv)

    document = json.loads(record(args.clone, args.results_dir))
    total = document["recall_total"]
    print(f"wrote {MARKERS_FILE}")
    print(f"recall: {total['detected']} of {total['marked']} marked lines")
    for kind, counts in document["recall_by_type"].items():
        print(f"  {kind}: {counts['detected']} of {counts['marked']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
