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
from pathlib import Path
from typing import Any
from collections.abc import Iterator

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
        log_errors: If True, log errors at DEBUG level. Defaults to True.

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

    if not p.exists():
        if log_errors:
            logger.debug("JSON file does not exist: %s", p)
        return default

    try:
        raw = p.read_text(encoding="utf-8-sig", errors="ignore").strip()
    except OSError as e:
        if log_errors:
            logger.debug("Failed to read JSON file %s: %s", p, e)
        return default

    if not raw:
        if log_errors:
            logger.debug("JSON file is empty: %s", p)
        return default

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        if log_errors:
            logger.debug(
                "Failed to parse JSON file %s: %s at position %d", p, e.msg, e.pos
            )
        return default


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

    Args:
        path: Path to the NDJSON file to load.
        log_errors: If True, log errors at DEBUG level. Defaults to True.

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
            logger.debug("NDJSON file does not exist: %s", p)
        return

    try:
        raw = p.read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        if log_errors:
            logger.debug("Failed to read NDJSON file %s: %s", p, e)
        return

    if not raw.strip():
        if log_errors:
            logger.debug("NDJSON file is empty: %s", p)
        return

    # Try full JSON parse first (handles regular JSON arrays)
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

    # Fall back to line-by-line NDJSON parsing
    for line_num, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            yield from _flatten_to_dicts(obj)
        except json.JSONDecodeError as e:
            if log_errors:
                logger.debug(
                    "Skipping malformed JSON at line %d in %s: %s at position %d",
                    line_num,
                    p,
                    e.msg,
                    e.pos,
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
