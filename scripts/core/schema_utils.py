#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import jsonschema
except Exception:  # pragma: no cover
    jsonschema = None

import json


def load_schema() -> Any:
    """Load JSON schema file for CommonFinding validation.

    Reads JSON schema from disk and returns parsed schema dictionary.
    Used for validating findings against CommonFinding schema v1.2.0.

    Args:
        None

    Returns:
        Any: Parsed JSON schema dictionary

    Raises:
        FileNotFoundError: If schema file does not exist
        json.JSONDecodeError: If schema file is invalid JSON

    Example:
        >>> schema = load_schema()
        >>> print(schema.get('schemaVersion'))
        1.2.0

    Note:
        Schema file path is hardcoded to docs/schemas/common_finding.v1.json.
        Schema must be valid JSON Schema Draft 7 format.

    """
    schema_path = Path("docs/schemas/common_finding.v1.json")
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate_findings(findings: list[dict]) -> bool:
    """Validate list of findings against CommonFinding JSON schema.

    Checks each finding for schema compliance and returns validation results.
    Used during report phase to ensure all findings conform to schema.

    Args:
        findings (list[dict]): List of finding dictionaries

    Returns:
        bool: True if all findings valid or jsonschema not installed, raises on errors

    Raises:
        jsonschema.ValidationError: If any finding fails schema validation
        json.JSONDecodeError: If schema file is invalid JSON

    Example:
        >>> findings = [{'schemaVersion': '1.2.0', 'id': 'abc123', ...}]
        >>> valid = validate_findings(findings)
        >>> print(valid)
        True

    Note:
        If jsonschema library not installed, returns True (skips validation).
        Automatically attempts Draft 7 schema fallback if validation fails.
        Validates each finding individually to provide clear error messages.

    """
    if jsonschema is None:
        # If jsonschema isn't installed, skip validation but return True
        return True
    schema = load_schema()
    # Try validating as-is; fall back to draft-07 if meta-scheme causes issues
    try:
        jsonschema.validate(
            instance=findings[0] if findings else {}, schema=schema
        )  # validate one sample
        for f in findings:
            jsonschema.validate(instance=f, schema=schema)
        return True
    except Exception:
        # Attempt draft-07 fallback
        schema["$schema"] = "http://json-schema.org/draft-07/schema#"
        for f in findings:
            jsonschema.validate(instance=f, schema=schema)
        return True
