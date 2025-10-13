#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

SARIF_VERSION = "2.1.0"


def to_sarif(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    rules = {}
    results = []
    for f in findings:
        rule_id = f.get("ruleId", "rule")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": f.get("title") or rule_id,
            "shortDescription": {"text": f.get("message", "")},
            "fullDescription": {"text": f.get("description", "")},
        })
        result = {
            "ruleId": rule_id,
            "message": {"text": f.get("message", "")},
            "level": _severity_to_level(f.get("severity")),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("location", {}).get("path", "")},
                        "region": {
                            "startLine": f.get("location", {}).get("startLine", 0),
                        },
                    }
                }
            ],
        }
        results.append(result)
    tool = {
        "driver": {
            "name": "jmo-security",
            "rules": list(rules.values()),
        }
    }
    return {
        "version": SARIF_VERSION,
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{"tool": tool, "results": results}],
    }


def _severity_to_level(sev: str | None) -> str:
    s = (sev or "INFO").upper()
    if s in ("CRITICAL", "HIGH"):
        return "error"
    if s == "MEDIUM":
        return "warning"
    return "note"


def write_sarif(findings: List[Dict[str, Any]], out_path: str | Path) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    sarif = to_sarif(findings)
    p.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
