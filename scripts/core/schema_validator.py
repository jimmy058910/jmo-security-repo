#!/usr/bin/env python3
"""
Schema validation utilities for CommonFinding JSON files.

This module provides functions to validate findings against the CommonFinding
JSON schema v1.2.0. It supports both individual finding validation and batch
validation of files containing findings.

The schema is loaded from docs/schemas/common_finding.v1.json which defines
the canonical CommonFinding structure.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger(__name__)

# Try importing jsonschema - validation will be skipped if not available
try:
    from jsonschema import Draft202012Validator, ValidationError

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    Draft202012Validator = None
    ValidationError = Exception

# Schema file path relative to project root
SCHEMA_PATH = (
    Path(__file__).parent.parent.parent / "docs" / "schemas" / "common_finding.v1.json"
)


def load_schema(schema_path: Path | None = None) -> dict[str, Any]:
    """Load the CommonFinding JSON schema.

    Args:
        schema_path: Optional path to schema file. Defaults to the standard
            location at docs/schemas/common_finding.v1.json

    Returns:
        Parsed JSON schema as a dictionary

    Raises:
        FileNotFoundError: If schema file does not exist
        json.JSONDecodeError: If schema file is invalid JSON
    """
    path = schema_path or SCHEMA_PATH
    if not path.exists():
        raise FileNotFoundError(f"Schema file not found: {path}")
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def validate_finding(
    finding: dict[str, Any], schema: dict[str, Any] | None = None
) -> list[str]:
    """Validate a single finding against the CommonFinding schema.

    Args:
        finding: Dictionary representing a CommonFinding
        schema: Optional pre-loaded schema. If None, loads from default location.

    Returns:
        List of error strings. Empty list indicates valid finding.
        If jsonschema is not installed, returns empty list (skips validation).
    """
    if not JSONSCHEMA_AVAILABLE:
        logger.debug("jsonschema not installed, skipping validation")
        return []

    if schema is None:
        try:
            schema = load_schema()
        except (FileNotFoundError, json.JSONDecodeError) as e:
            return [f"Failed to load schema: {e}"]

    errors: list[str] = []

    try:
        # Use Draft 2020-12 validator as per schema definition
        validator = Draft202012Validator(schema)
        for error in validator.iter_errors(finding):
            # Build a human-readable error message with path context
            path = (
                ".".join(str(p) for p in error.absolute_path)
                if error.absolute_path
                else "root"
            )
            errors.append(f"{path}: {error.message}")
    except Exception as e:
        errors.append(f"Validation error: {e}")

    return errors


def validate_findings(
    findings: list[dict[str, Any]], schema: dict[str, Any] | None = None
) -> dict[str, list[str]]:
    """Validate multiple findings against the CommonFinding schema.

    Args:
        findings: List of finding dictionaries
        schema: Optional pre-loaded schema. If None, loads from default location.

    Returns:
        Dictionary mapping finding index/id to list of errors.
        Only findings with errors are included. Empty dict means all valid.
    """
    if not JSONSCHEMA_AVAILABLE:
        logger.debug("jsonschema not installed, skipping validation")
        return {}

    if schema is None:
        try:
            schema = load_schema()
        except (FileNotFoundError, json.JSONDecodeError) as e:
            return {"schema_load_error": [str(e)]}

    errors_by_finding: dict[str, list[str]] = {}

    for i, finding in enumerate(findings):
        finding_errors = validate_finding(finding, schema)
        if finding_errors:
            # Use finding id if available, otherwise use index
            finding_id = finding.get("id", f"index_{i}")
            errors_by_finding[finding_id] = finding_errors

    return errors_by_finding


def validate_findings_file(file_path: Path) -> list[str]:
    """Validate a JSON file containing findings against the CommonFinding schema.

    Handles various file formats:
    - Array of findings: [finding1, finding2, ...]
    - Object with 'findings' key: {"findings": [...]}
    - Single finding object: {finding}

    Args:
        file_path: Path to JSON file containing findings

    Returns:
        List of error strings. Empty list indicates all findings are valid.
        Returns errors for file read issues as well as validation failures.
    """
    errors: list[str] = []

    # Read file
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return [f"Failed to read file {file_path}: {e}"]

    # Parse JSON
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON in {file_path}: {e}"]

    # Extract findings based on file structure
    findings: list[dict[str, Any]] = []

    if isinstance(data, list):
        # Array of findings
        findings = data
    elif isinstance(data, dict):
        if "findings" in data:
            # Object with findings key
            findings = data.get("findings", [])
        else:
            # Single finding
            findings = [data]
    else:
        return [f"Unexpected data type in {file_path}: {type(data).__name__}"]

    # Skip empty files
    if not findings:
        return []

    # Load schema once for efficiency
    try:
        schema = load_schema()
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return [f"Failed to load schema: {e}"]

    # Validate each finding
    validation_errors = validate_findings(findings, schema)
    for finding_id, finding_errors in validation_errors.items():
        for err in finding_errors:
            errors.append(f"{file_path}:{finding_id}: {err}")

    return errors


def validate_directory(
    dir_path: Path,
    glob_pattern: str = "**/*.json",
    exclude_patterns: list[str] | None = None,
) -> dict[str, list[str]]:
    """Validate all JSON files in a directory against the CommonFinding schema.

    Args:
        dir_path: Directory path to search for JSON files
        glob_pattern: Glob pattern for finding JSON files (default: **/*.json)
        exclude_patterns: List of patterns to exclude (substring match)

    Returns:
        Dictionary mapping file paths to lists of errors.
        Only files with errors are included.
    """
    if exclude_patterns is None:
        exclude_patterns = []

    errors_by_file: dict[str, list[str]] = {}

    if not dir_path.exists():
        return {str(dir_path): [f"Directory not found: {dir_path}"]}

    for json_file in dir_path.glob(glob_pattern):
        # Skip excluded files
        if any(pattern in str(json_file) for pattern in exclude_patterns):
            continue

        file_errors = validate_findings_file(json_file)
        if file_errors:
            errors_by_file[str(json_file)] = file_errors

    return errors_by_file


if __name__ == "__main__":
    # CLI usage for manual testing
    import sys

    if len(sys.argv) < 2:
        print("Usage: python schema_validator.py <file_or_directory>")
        sys.exit(1)

    target = Path(sys.argv[1])

    if target.is_file():
        errors = validate_findings_file(target)
        if errors:
            print(f"Validation errors in {target}:")
            for err in errors:
                print(f"  - {err}")
            sys.exit(1)
        else:
            print(f"OK: {target}")
    elif target.is_dir():
        all_errors = validate_directory(target)
        if all_errors:
            print(f"Validation errors in {target}:")
            for file_path, file_errors in all_errors.items():
                print(f"\n{file_path}:")
                for err in file_errors:
                    print(f"  - {err}")
            sys.exit(1)
        else:
            print(f"OK: All files in {target} valid")
    else:
        print(f"Error: {target} not found")
        sys.exit(1)
