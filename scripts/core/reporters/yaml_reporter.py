#!/usr/bin/env python3
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

# Imported at module scope on purpose. `schema_validator.SCHEMA_PATH` is a
# module-level constant built with `Path(...) / ... / ...`, so it is frozen
# at first import. A lazy import inside `write_yaml` put that first import
# inside whatever a caller had patched -- and one test patches
# `Path.__truediv__` itself, which is global to the class. `SCHEMA_PATH`
# then pointed at a pytest tmpdir stub schema for the REST OF THE SESSION,
# and every later validation passed against `{"type": "object"}`.
from scripts.core.schema_validator import (
    JSONSCHEMA_AVAILABLE,
    load_schema,
    validate_finding,
)

# Configure logging
logger = logging.getLogger(__name__)

try:
    import yaml
except ImportError as e:  # optional dependency
    logger.debug(f"YAML reporter unavailable: {e}")
    yaml = None  # type: ignore[assignment]  # Fallback when yaml not installed


def _validate_against_schema(findings: list[dict[str, Any]]) -> int:
    """Validate findings against CommonFinding, reporting failures at WARNING.

    Returns the number of findings that failed, so callers and tests can assert
    on it.

    This used to build its own schema path::

        Path(__file__).parent.parent.parent / "docs/schemas/common_finding.v1.json"

    which resolves to ``scripts/docs/schemas/...`` -- three parents from
    ``scripts/core/reporters/`` is ``scripts/``, not the repo root. The file
    never existed, the guarding ``if schema_path.exists()`` had no ``else``,
    and so **the report phase's only schema validation silently never ran**.
    A real scan wrote a finding with ``risk.cwe`` as a string where the schema
    requires an array, and logged nothing at any level.

    The path is now `schema_validator`'s, which lives one directory shallower
    and had the arithmetic right -- so there is one definition rather than two.
    """
    if not JSONSCHEMA_AVAILABLE:
        return 0
    try:
        schema = load_schema()
    except (FileNotFoundError, OSError, ValueError) as e:
        # Loudly, because being unable to validate is exactly the state that
        # went unnoticed before.
        logger.warning("Schema validation skipped -- schema unavailable: %s", e)
        return 0

    failures: list[str] = []
    for idx, finding in enumerate(findings):
        for message in validate_finding(finding, schema):
            failures.append(f"finding {idx}: {message}")

    if failures:
        # One aggregated record, not one per finding: a wholly invalid report
        # would otherwise emit thousands, and flooding hides a signal as
        # thoroughly as silence (the lesson from the NDJSON line-loss summary).
        preview = "; ".join(failures[:3])
        logger.warning(
            "%d of %d findings failed CommonFinding schema validation: %s%s",
            len({f.split(":")[0] for f in failures}),
            len(findings),
            preview,
            " ..." if len(failures) > 3 else "",
        )
    return len({f.split(":")[0] for f in failures})


def write_yaml(
    findings: list[dict[str, Any]],
    out_path: str | Path,
    metadata: dict[str, Any] | None = None,
    validate: bool = True,
) -> None:
    """Write findings to YAML file with metadata wrapper.

    Args:
        findings: List of CommonFinding dictionaries
        out_path: Output file path
        metadata: Optional metadata dict (will be auto-generated if not provided)
        validate: Whether to validate findings against CommonFinding schema (default: True)

    Raises:
        RuntimeError: If PyYAML is not installed
    """
    if yaml is None:
        raise RuntimeError("PyYAML not installed. Install with: pip install pyyaml")

    # Optional schema validation. Whether jsonschema is importable is
    # decided inside `_validate_against_schema`, by `schema_validator`'s
    # own flag. This module used to keep a SECOND `jsonschema` global and
    # gate on that -- so a test nulling it disabled validation through a
    # flag the validator never consults, and the guards below went quietly
    # vacuous on whichever xdist worker had run that test.
    if validate:
        _validate_against_schema(findings)

    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Generate default metadata if not provided
    if metadata is None:
        # Import here to avoid circular dependency
        from scripts.core.reporters.basic_reporter import _generate_metadata

        metadata = _generate_metadata(findings)

    # Wrap findings in metadata structure (matching findings.json format)
    output = {"meta": metadata, "findings": findings}

    p.write_text(yaml.safe_dump(output, sort_keys=False), encoding="utf-8")
