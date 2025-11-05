#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

# Configure logging
logger = logging.getLogger(__name__)

try:
    import yaml
except ImportError as e:  # optional dependency
    logger.debug(f"YAML reporter unavailable: {e}")
    yaml = None  # type: ignore[assignment]

try:
    import jsonschema
except ImportError:
    jsonschema = None


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

    # Optional schema validation
    if validate and jsonschema:
        schema_path = (
            Path(__file__).parent.parent.parent / "docs/schemas/common_finding.v1.json"
        )
        if schema_path.exists():
            try:
                with open(schema_path) as f:
                    schema = json.load(f)
                for idx, finding in enumerate(findings):
                    try:
                        jsonschema.validate(instance=finding, schema=schema)
                    except jsonschema.ValidationError as e:
                        logger.warning(
                            f"Finding {idx} failed schema validation: {e.message}"
                        )
            except Exception as e:
                logger.debug(f"Schema validation skipped: {e}")

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
