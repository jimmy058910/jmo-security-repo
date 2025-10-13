#!/usr/bin/env python3
"""
Semgrep adapter: normalize Semgrep JSON to CommonFinding
Expected input shape often contains {"results": [ ... ]}
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint, normalize_severity


SEMGREP_TO_SEV = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


def load_semgrep(path: str | Path) -> List[Dict[str, Any]]:
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

    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return []

    out: List[Dict[str, Any]] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        check_id = str(r.get("check_id") or r.get("ruleId") or r.get("id") or "SEMGR")
        msg = (r.get("extra") or {}).get("message") or r.get("message") or "Semgrep finding"
        sev_raw = (r.get("extra") or {}).get("severity") or r.get("severity")
        sev_norm = SEMGREP_TO_SEV.get(str(sev_raw).upper(), None)
        severity = normalize_severity(sev_norm or str(sev_raw))
        path_str = r.get("path") or (r.get("location") or {}).get("path") or ""
        start_line = 0
        if isinstance(r.get("start"), dict) and isinstance(r["start"].get("line"), int):
            start_line = r["start"]["line"]
        elif isinstance((r.get("start") or {}).get("line"), int):
            start_line = (r.get("start") or {}).get("line")
        loc = r.get("location")
        if isinstance(loc, dict) and isinstance(loc.get("start"), dict) and isinstance(loc["start"].get("line"), int):
            start_line = loc["start"]["line"]
        fid = fingerprint("semgrep", check_id, path_str, start_line, msg)
        out.append(
            {
                "schemaVersion": "1.0.0",
                "id": fid,
                "ruleId": check_id,
                "title": check_id,
                "message": msg,
                "description": msg,
                "severity": severity,
                "tool": {"name": "semgrep", "version": str((data.get("version") if isinstance(data, dict) else None) or "unknown")},
                "location": {"path": path_str, "startLine": start_line},
                "remediation": "Review and remediate per rule guidance.",
                "tags": ["sast"],
                "raw": r,
            }
        )
    return out
