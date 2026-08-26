#!/usr/bin/env python3
"""SARIF 2.1.0 reporter with enriched metadata.

Generates SARIF (Static Analysis Results Interchange Format) output
with code snippets, fix suggestions, and taxonomy mappings where available.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

# Configure logging
logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"

# The schema URI written into every document. The previous value,
# `https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json`,
# returns HTTP 403 -- it is the retired SchemaStore host, so any consumer that
# resolved `$schema` to validate the document got an error page.
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF requires `correlationGuid` to be a GUID. JMo's finding ids are 16-char
# fingerprints, and clustering rewrites them to `cluster-<fp>` (#847), so the
# value must be checked rather than assumed.
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}"
    r"-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


def _as_message_text(value: Any, default: str) -> str:
    """Coerce a value into a SARIF `multiformatMessageString.text`.

    SARIF requires a string. Several adapters put a **dict** in `remediation`
    (`{"fix": ..., "steps": [...]}`), which produced a schema-invalid document.
    """
    if isinstance(value, str) and value:
        return value
    if isinstance(value, dict):
        parts: list[str] = []
        fix = value.get("fix")
        if isinstance(fix, str) and fix.strip():
            parts.append(f"Suggested fix: {fix.strip()}")
        steps = value.get("steps")
        if isinstance(steps, list):
            parts.extend(str(s) for s in steps if s)
        if parts:
            return "\n".join(parts)
    return default


def _as_sarif_line(value: Any) -> int | None:
    """Return `value` as a SARIF line number, or None if it is not one.

    SARIF constrains `region.startLine`/`endLine` to `minimum: 1`, so 0, None,
    negatives and non-numeric values must be omitted rather than emitted.
    """
    if isinstance(value, bool):  # bool is an int subclass; not a line number
        return None
    if isinstance(value, int):
        return value if value >= 1 else None
    if isinstance(value, str):
        try:
            n = int(value.strip())
        except ValueError:
            return None
        return n if n >= 1 else None
    return None


def to_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert normalized findings to SARIF 2.1.0 format.

    Args:
        findings: List of CommonFinding dictionaries

    Returns:
        SARIF document as dict
    """
    rules: dict[str, dict[str, Any]] = {}
    results = []

    for idx, f in enumerate(findings):
        # Skip None or invalid findings (can happen with filtering)
        if not f or not isinstance(f, dict):
            logger.warning("Skipping invalid finding at index %d: %s", idx, type(f))
            continue
        rule_id = f.get("ruleId", "rule")

        # Enhanced rule metadata
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": f.get("title") or rule_id,
                "shortDescription": {"text": f.get("message", "")},
                "fullDescription": {"text": f.get("description", "")},
                "help": {
                    "text": _as_message_text(
                        f.get("remediation"), "See rule documentation"
                    ),
                    "markdown": _as_message_text(
                        f.get("remediation"), "See rule documentation"
                    ),
                },
                "properties": {
                    "tags": f.get("tags", []),
                    "precision": "high",
                },
            },
        )

        # Build location with optional snippet.
        #
        # SARIF constrains `region.startLine` to `minimum: 1`. Defaulting a
        # missing line to 0 made the document schema-invalid for every finding
        # that has no line number -- 93 of 242 on a real scan. A region is
        # optional, so omit what is not known rather than inventing line 0.
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": f.get("location", {}).get("path", "")},
        }
        region: dict[str, Any] = {}

        start_line = _as_sarif_line(f.get("location", {}).get("startLine"))
        if start_line is not None:
            region["startLine"] = start_line

        # End line if available (SARIF also requires endLine >= 1)
        end_line = _as_sarif_line(f.get("location", {}).get("endLine"))
        if end_line is not None and start_line is not None:
            region["endLine"] = max(end_line, start_line)

        # Add code snippet if available in context
        context = f.get("context") if f else None
        if context and isinstance(context, dict) and context.get("snippet"):
            region["snippet"] = {"text": str(context["snippet"])}

        if region:
            physical["region"] = region
        location_obj = {"physicalLocation": physical}

        result = {
            "ruleId": rule_id,
            "message": {"text": f.get("message", "")},
            "level": _severity_to_level(f.get("severity")),
            "locations": [location_obj],
        }

        # Add remediation guidance if available.
        #
        # This used to emit `result.fixes`, but a SARIF `fix` REQUIRES
        # `artifactChanges` -- an array of concrete, machine-applicable text
        # replacements. JMo's `remediation` is prose ("Use environment
        # variables or a secrets manager"), so every fix object it produced was
        # schema-invalid: 239 errors on a 242-finding scan. Synthesising an
        # artifactChange would mean inventing a replacement JMo does not have.
        # The prose goes in `properties` instead, which SARIF leaves free-form,
        # and it is still carried by `rules[].help.text` as before.
        remediation_text = _as_message_text(f.get("remediation"), "")
        if remediation_text:
            result.setdefault("properties", {})["remediation"] = remediation_text

        # Add CWE/OWASP/CVE taxonomy if present in tags
        taxa = []
        for tag in f.get("tags", []):
            tag_str = str(tag).upper()
            if tag_str.startswith("CWE-"):
                taxa.append(
                    {
                        "id": tag_str,
                        "toolComponent": {"name": "CWE"},
                    }
                )
            elif tag_str.startswith("OWASP-"):
                taxa.append(
                    {
                        "id": tag_str,
                        "toolComponent": {"name": "OWASP"},
                    }
                )
            elif tag_str.startswith("CVE-"):
                taxa.append(
                    {
                        "id": tag_str,
                        "toolComponent": {"name": "CVE"},
                    }
                )
        if taxa:
            result["taxa"] = taxa

        # Add CVSS score if present
        if f.get("cvss"):
            if "properties" not in result:
                result["properties"] = {}
            result["properties"]["cvss"] = f["cvss"]

        # v1.0.0: Add cross-tool consensus information
        detected_by = f.get("detected_by", [])
        if detected_by and len(detected_by) > 1:
            if "properties" not in result:
                result["properties"] = {}
            # Add consensus metadata
            result["properties"]["consensus"] = {
                "detectedByCount": len(detected_by),
                "tools": [
                    {"name": t.get("name", "unknown"), "version": t.get("version", "")}
                    for t in detected_by
                ],
            }
            # Add correlation IDs for cross-tool tracking.
            #
            # SARIF constrains `correlationGuid` to a GUID. JMo ids are 16-char
            # fingerprints, and clustering rewrites them to `cluster-<fp>`
            # (#847), so emitting one unconditionally made the document
            # invalid. Keep the id -- it is what correlates findings across
            # JMo's own artifacts -- but under a free-form property unless it
            # really is a GUID.
            finding_id = f.get("id", "")
            if isinstance(finding_id, str) and _GUID_RE.match(finding_id):
                result["correlationGuid"] = finding_id
            elif finding_id:
                result.setdefault("properties", {})["jmoFindingId"] = str(finding_id)

        results.append(result)

    # Read version from pyproject.toml if possible
    version = "1.0.2"  # Default
    try:
        import tomllib

        pyproject_path = Path(__file__).parent.parent.parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "rb") as fp:
                pyproject = tomllib.load(fp)
                version = pyproject.get("project", {}).get("version", version)
    except FileNotFoundError:
        # pyproject.toml missing - use default version
        logger.debug(f"pyproject.toml not found at {pyproject_path}")
    except (KeyError, ValueError) as e:
        # pyproject.toml invalid/missing version field
        logger.debug(f"Failed to parse version from pyproject.toml: {e}")

    tool = {
        "driver": {
            "name": "jmo-security",
            "informationUri": "https://github.com/jimmy058910/jmo-security-repo",
            "version": version,
            "rules": list(rules.values()),
        }
    }

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA_URI,
        "runs": [{"tool": tool, "results": results}],
    }


def _severity_to_level(sev: str | None) -> str:
    """Map severity to SARIF level.

    Args:
        sev: Severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO)

    Returns:
        SARIF level: error, warning, or note
    """
    s = (sev or "INFO").upper()
    if s in ("CRITICAL", "HIGH"):
        return "error"
    if s == "MEDIUM":
        return "warning"
    return "note"


def write_sarif(findings: list[dict[str, Any]], out_path: str | Path) -> None:
    """Write findings to SARIF 2.1.0 JSON file.

    Args:
        findings: List of normalized findings
        out_path: Output file path
    """
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Filter out None or invalid findings before converting to SARIF
    valid_findings = [f for f in findings if f and isinstance(f, dict)]
    sarif = to_sarif(valid_findings)
    p.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
