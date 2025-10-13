#!/usr/bin/env python3
"""
Gitleaks adapter: normalize Gitleaks JSON to CommonFinding
Supports:
- Typical array of findings
- Object with 'findings' array (if present)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from scripts.core.common_finding import fingerprint, normalize_severity


def _iter_findings(obj: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                yield item
    elif isinstance(obj, dict):
        # Some formats may use 'findings' or 'leaks'
        for key in ("findings", "leaks", "results"):
            arr = obj.get(key)
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict):
                        yield item
                break


def load_gitleaks(path: str | Path) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    raw = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Not JSON or malformed
        return []

    out: List[Dict[str, Any]] = []
    for f in _iter_findings(data):
        rule_id = str(f.get("RuleID") or f.get("ruleID") or f.get("rule_id") or f.get("Description") or "GITLEAKS")
        file_path = (
            f.get("File")
            or f.get("FilePath")
            or (f.get("Location") or {}).get("file")
            or f.get("Path")
            or ""
        )
        start_line = None
        if isinstance(f.get("StartLine"), int):
            start_line = f["StartLine"]
        elif isinstance(f.get("Line"), int):
            start_line = f["Line"]
        msg = f.get("Description") or f.get("Rule") or f.get("Match") or "Possible secret detected"
        severity = normalize_severity(str(f.get("Severity") or "HIGH"))
        fid = fingerprint("gitleaks", rule_id, file_path, start_line, msg)
        out.append(
            {
                "schemaVersion": "1.0.0",
                "id": fid,
                "ruleId": rule_id,
                "title": f.get("Rule") or rule_id,
                "message": msg,
                "description": f.get("Description") or msg,
                "severity": severity,
                "tool": {"name": "gitleaks", "version": str(f.get("Version") or "unknown")},
                "location": {"path": file_path, "startLine": start_line or 0},
                "remediation": "Rotate credentials and remove secrets from history.",
                "tags": ["secrets"],
                "raw": f,
            }
        )
    return out
