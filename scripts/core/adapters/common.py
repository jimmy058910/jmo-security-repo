#!/usr/bin/env python3
"""
Common utilities for JMo Security adapters.

This module provides standardized JSON loading functions that replace
duplicated boilerplate across all adapter modules. Using these utilities
ensures consistent error handling and logging behavior.

v1.0.0: Initial implementation
- safe_load_json_file: Load regular JSON files
- safe_load_ndjson_file: Load newline-delimited JSON files
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger(__name__)


def safe_load_json_file(
    path: str | Path,
    default: Any = None,
    log_errors: bool = True,
) -> dict[str, Any] | list[Any] | None:
    """Safely load and parse a JSON file with consistent error handling.

    This function replaces the duplicated 7-line JSON loading pattern
    found across all adapters. It handles:
    - Missing files
    - Empty files
    - Invalid JSON
    - Encoding issues (uses utf-8 with errors='ignore')

    Args:
        path: Path to the JSON file to load.
        default: Value to return if loading fails. Defaults to None.
        log_errors: If True, report load failures. Defaults to True. Pass
            False from **speculative** callers -- ones probing a format they
            expect might not match -- so a successful probe of the other
            format does not emit a warning on every healthy run.

    Returns:
        Parsed JSON data (dict or list), or the default value if loading fails.

    Examples:
        >>> data = safe_load_json_file("results/tool.json", default={})
        >>> results = data.get("results", [])

        >>> data = safe_load_json_file("missing.json", default=None)
        >>> if data is None:
        ...     return []
    """
    p = Path(path)

    result_type = dict[str, Any] | list[Any] | None

    if not p.exists():
        if log_errors:
            logger.warning("JSON file does not exist: %s", p)
        return cast(result_type, default)

    try:
        raw = p.read_text(encoding="utf-8-sig", errors="ignore").strip()
    except OSError as e:
        if log_errors:
            logger.debug("Failed to read JSON file %s: %s", p, e)
        return cast(result_type, default)

    if not raw:
        if log_errors:
            logger.warning("JSON file is empty: %s", p)
        return cast(result_type, default)

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        if log_errors:
            # WARNING, matching the "missing" and "empty" branches above. This
            # function was inconsistent with itself: a file that is absent or
            # empty warned, while a file that is *present and unreadable*
            # whispered at DEBUG -- and `configure_scan_logging` sets the
            # `scripts` logger to WARNING, so that branch was invisible in every
            # normal run.
            #
            # Malformed is the most alarming of the three: the tool ran, exited
            # acceptably and wrote something JMo cannot read, so its findings are
            # absent from the report while the scan reports success. Measured on
            # #822: a `per_tool` flag making trivy emit a table instead of JSON
            # took a target from 2 findings to 0, rc=0, nothing on any stream.
            #
            # This is the layer that matters, because **no adapter raises
            # `AdapterParseException`** (0 of 27) -- they all route through here
            # and turn "unparseable" into "empty". One shared helper, so one fix
            # covers all 25 adapters that use it.
            #
            # Speculative callers -- ones that probe a format and expect to fail
            # -- must pass `log_errors=False`; see `prowler_adapter._load`.
            logger.warning(
                "Could not parse %s as JSON (%s at position %d) - any findings "
                "it contained are MISSING from this report",
                p,
                e.msg,
                e.pos,
            )
        return cast(result_type, default)

    # Parsed, but not into a structure any tool legitimately emits. `null`, a
    # bare string and a bare number all decode cleanly, so the branch above
    # cannot see them -- yet every adapter then fails its `isinstance(data,
    # dict)` guard and returns `[]`, which is indistinguishable from "the tool
    # found nothing". Measured in the chunk-5 sweep: `null`, `"a string"` and
    # `[]`-shaped junk produced 0 findings and **0 log records at any level**
    # across all 27 adapters.
    #
    # `{}` and `[]` are deliberately NOT flagged -- those are how a tool says
    # "no findings", which is the single most common healthy outcome.
    #
    # The value is still returned rather than replaced with `default`: every
    # adapter already rejects it, so this stays a pure diagnostic with no
    # behaviour change.
    if not isinstance(parsed, (dict, list)):
        if log_errors:
            logger.warning(
                "%s parsed as JSON but contained %s, not an object or array - "
                "no tool emits this, so any findings it should have carried "
                "are MISSING from this report",
                p,
                type(parsed).__name__,
            )

    return cast(result_type, parsed)


def safe_load_ndjson_file(
    path: str | Path,
    log_errors: bool = True,
) -> Iterator[dict[str, Any]]:
    """Safely load and parse a newline-delimited JSON (NDJSON) file.

    This function handles multiple JSON formats:
    1. Standard NDJSON (one JSON object per line)
    2. Regular JSON array (tries full parse first)
    3. Mixed content (skips malformed lines)

    The function yields dictionaries one at a time, making it memory-efficient
    for large files.

    Failure reporting matches `safe_load_json_file`: a missing, unreadable or
    empty file is a WARNING, and so is losing lines to malformed JSON. This
    function used to log **every** one of those at DEBUG while its sibling
    warned -- and `configure_scan_logging` sets the `scripts` logger to
    WARNING, so for the four NDJSON adapters (`falco`, `nuclei`, `prowler`,
    `trufflehog`) every failure mode was invisible in a normal run. That is the
    same inconsistency #830 fixed inside `safe_load_json_file`, which reached
    only the 23 adapters using it.

    The line-loss case is the worst of them, because it is **partial**:
    measured on a 10-line trufflehog stream with 4 truncated lines, the adapter
    returned 6 verified-secret findings, dropped 4, and emitted nothing at
    WARNING or above. A total failure at least yields an empty report; this one
    yields a populated report that is quietly short.

    Args:
        path: Path to the NDJSON file to load.
        log_errors: If True, report load failures. Defaults to True. Pass
            False from **speculative** callers probing one of several possible
            formats; see `prowler_adapter._iter_prowler_records`.

    Yields:
        Dictionary objects from each line/item in the file.

    Examples:
        >>> for finding in safe_load_ndjson_file("results/tool.ndjson"):
        ...     process(finding)

        >>> findings = list(safe_load_ndjson_file("results/tool.json"))
    """
    p = Path(path)

    if not p.exists():
        if log_errors:
            logger.warning("NDJSON file does not exist: %s", p)
        return

    try:
        raw = p.read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        if log_errors:
            logger.warning("Failed to read NDJSON file %s: %s", p, e)
        return

    if not raw.strip():
        if log_errors:
            logger.warning("NDJSON file is empty: %s", p)
        return

    # Try full JSON parse first (handles regular JSON arrays).
    #
    # This one stays DEBUG on purpose. A genuine multi-line NDJSON file is
    # never valid JSON, so this probe fails on every healthy trufflehog run --
    # promoting it would produce the always-fires warning #784 was about.
    try:
        data = json.loads(raw)
        # Yield items from the parsed data
        yield from _flatten_to_dicts(data)
        return
    except json.JSONDecodeError as e:
        if log_errors:
            logger.debug(
                "Falling back to NDJSON line-by-line parsing for %s: %s at position %d",
                p,
                e.msg,
                e.pos,
            )

    # Fall back to line-by-line NDJSON parsing.
    #
    # Skipped lines are counted and reported **once**, after the loop, rather
    # than one warning per line: a corrupt 10k-line stream would otherwise emit
    # 10k records, which hides the signal exactly as thoroughly as silence did.
    # The per-line detail stays at DEBUG for anyone who needs the line numbers.
    skipped = 0
    yielded = 0
    for line_num, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            skipped += 1
            if log_errors:
                logger.debug(
                    "Skipping malformed JSON at line %d in %s: %s at position %d",
                    line_num,
                    p,
                    e.msg,
                    e.pos,
                )
            continue
        for item in _flatten_to_dicts(obj):
            yielded += 1
            yield item

    # Reached only when the caller exhausts the generator. All four NDJSON
    # adapters iterate it to completion, so the summary always fires for them;
    # a future caller that breaks early would not see it.
    #
    # Deliberately NOT gated on `log_errors`. That flag exists for callers
    # probing whether a file is NDJSON at all, and this branch cannot fire on a
    # healthy file of either accepted shape: a valid JSON array returns from
    # the full-parse above without ever entering the loop, and a valid NDJSON
    # stream reaches the loop but loses no lines. Losing lines means real data
    # was destroyed, which is never something a probe should swallow --
    # measured on prowler, whose `log_errors=False` otherwise re-hid exactly
    # the partial loss this function was changed to expose.
    if skipped:
        logger.warning(
            "Could not parse %d line(s) of %s - any findings they contained "
            "are MISSING from this report (%d parsed successfully)",
            skipped,
            p,
            yielded,
        )


def _flatten_to_dicts(obj: Any) -> Iterator[dict[str, Any]]:
    """Recursively flatten nested structures to yield only dictionaries.

    This helper handles various JSON structures:
    - Single dict: yields the dict
    - List of dicts: yields each dict
    - Nested lists: recursively flattens

    Args:
        obj: Any JSON-parsed object (dict, list, or primitive).

    Yields:
        Dictionary objects found in the structure.
    """
    if obj is None:
        return
    if isinstance(obj, dict):
        yield obj
    elif isinstance(obj, list):
        for item in obj:
            yield from _flatten_to_dicts(item)
