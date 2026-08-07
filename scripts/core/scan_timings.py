"""Persist the per-tool measurements the scan phase already takes.

`ToolRunner` times every invocation with `perf_counter` and returns a
`ToolResult` carrying `duration`, `status`, `returncode` and `attempts`. Until
#722 nothing read those fields: each scan job iterated the results, kept
`.tool` and `.status`, and reduced them to a dict of booleans. The measurement
existed and was discarded one line before it could be recorded.

This module writes it out. It deliberately does no measuring of its own -- the
numbers here are the ones `ToolRunner` already produced.

Related:
- `scripts/cli/report_orchestrator.py` writes the sibling `timings.json`, which
  covers the **report** phase (how long adapters took to parse tool output).
  This file covers the **scan** phase (how long the tools took to run). They
  answer different questions and neither substitutes for the other.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from scripts.core.tool_runner import ToolResult

logger = logging.getLogger(__name__)

SCAN_TIMINGS_FILENAME = "scan-timings.json"

# Bumped when the document's shape changes. Consumers (jmo-profile-optimizer,
# any external tooling) can then refuse a shape they do not understand instead
# of silently misreading it -- which is exactly how the report-phase schema
# drifted for months without anything noticing (#718 chunk A).
SCAN_TIMINGS_SCHEMA_VERSION = 1


def build_scan_timings(
    results: list[ToolResult],
    *,
    target: str,
    target_type: str,
    wall_seconds: float,
) -> dict[str, Any]:
    """Build the scan-timings document for one target.

    Args:
        results: The `ToolResult` list `ToolRunner.run_all_parallel()` returned.
        target: Target identifier (repository name, image ref, URL, ...).
        target_type: One of 'repo', 'image', 'iac', 'url', 'k8s'.
        wall_seconds: Elapsed time of the parallel tool batch.

    Returns:
        A JSON-serializable dict.

    `wall_seconds` is recorded rather than derived because tools run
    concurrently: the per-tool durations sum to more than the elapsed time, so
    that sum is an invalid denominator for "what share of the scan was tool X".
    Keeping the real elapsed span removes the need to reconstruct it wrongly.
    """
    return {
        "schema_version": SCAN_TIMINGS_SCHEMA_VERSION,
        "target": target,
        "target_type": target_type,
        "wall_seconds": round(wall_seconds, 3),
        # `to_dict()` and never `dataclasses.asdict()`: the latter would include
        # `stdout` and `stderr`, and on a secret scanner stdout *is* the
        # secrets. This artifact is meant to be pasteable into an issue.
        "tools": [r.to_dict() for r in results],
    }


def write_scan_timings(
    out_dir: Path,
    results: list[ToolResult],
    *,
    target: str,
    target_type: str,
    wall_seconds: float,
) -> Path | None:
    """Write `scan-timings.json` into a target's output directory.

    Args:
        out_dir: The target's output directory (sibling of `trivy.json` etc.).
        results: The `ToolResult` list from `ToolRunner.run_all_parallel()`.
        target: Target identifier.
        target_type: One of 'repo', 'image', 'iac', 'url', 'k8s'.
        wall_seconds: Elapsed time of the parallel tool batch.

    Returns:
        The path written, or None if it could not be written.

    Never raises on a write failure. This runs after every tool has finished --
    up to 70 minutes on a `deep` profile -- so an unwritable diagnostic file
    must not discard a completed scan's results. The failure is logged instead,
    because an artifact that goes missing without saying so is the failure mode
    this repository keeps relearning.
    """
    path = out_dir / SCAN_TIMINGS_FILENAME
    document = build_scan_timings(
        results,
        target=target,
        target_type=target_type,
        wall_seconds=wall_seconds,
    )
    try:
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    except OSError as e:
        logger.warning(
            "Could not write %s to %s: %s", SCAN_TIMINGS_FILENAME, out_dir, e
        )
        return None
    return path
