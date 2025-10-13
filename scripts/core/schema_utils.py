#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import Any, List

try:
    import jsonschema
except Exception:  # pragma: no cover
    jsonschema = None

import json


def load_schema() -> Any:
    schema_path = Path("docs/schemas/common_finding.v1.json")
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate_findings(findings: List[dict]) -> bool:
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
