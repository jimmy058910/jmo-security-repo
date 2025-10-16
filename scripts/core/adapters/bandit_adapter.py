#!/usr/bin/env python3
"""
Bandit adapter: normalize Bandit JSON to CommonFinding

Expected Bandit JSON shape (bandit -q -r <path> -f json):
{
  "results": [
    {
      "filename": "app.py",
      "line_number": 10,
      "issue_text": "Possible ...",
      "test_id": "B101",
      "test_name": "assert_used",
      "issue_severity": "LOW|MEDIUM|HIGH",
      "issue_confidence": "LOW|MEDIUM|HIGH"
    }, ...
  ],
  ...
}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def load_bandit(path: str | Path) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    raw = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    results = []
    arr = []
    version_hint = "unknown"
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        arr = data.get("results", [])
        # Bandit JSON includes metadata; version isn't explicit; keep unknown
    elif isinstance(data, list):
        arr = data

    for r in arr:
        if not isinstance(r, dict):
            continue
        rule_id = str(
            r.get("test_id")
            or r.get("testId")
            or r.get("test-id")
            or r.get("test_name")
            or "BANDIT"
        )
        file_path = str(r.get("filename") or r.get("file_name") or "")
        start_line = None
        ln = r.get("line_number") or r.get("line")
        if isinstance(ln, int):
            start_line = ln
        msg = str(
            r.get("issue_text")
            or r.get("message")
            or r.get("test_name")
            or "Potential security issue"
        )
        sev_src = str(r.get("issue_severity") or "MEDIUM").upper()
        severity = normalize_severity(sev_src)
        fid = fingerprint("bandit", rule_id, file_path, start_line, msg)
        finding = {
            "schemaVersion": "1.0.0",
            "id": fid,
            "ruleId": rule_id,
            "title": r.get("test_name") or rule_id,
            "message": msg,
            "description": msg,
            "severity": severity,
            "tool": {"name": "bandit", "version": version_hint},
            "location": {"path": file_path, "startLine": start_line or 0},
            "remediation": "Refactor code to avoid insecure patterns flagged by Bandit.",
            "tags": ["sast", "python"],
            "raw": r,
        }
        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        results.append(finding)
    return results
