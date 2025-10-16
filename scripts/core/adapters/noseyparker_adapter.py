#!/usr/bin/env python3
"""
Nosey Parker adapter: normalize Nosey Parker JSON to CommonFinding
Expected input: {"matches": [ {"signature": ..., "path": ..., "line_number": ...}, ... ]}
This is tolerant to minor format variation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def load_noseyparker(path: str | Path) -> List[Dict[str, Any]]:
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

    matches = data.get("matches") if isinstance(data, dict) else None
    if not isinstance(matches, list):
        return []

    out: List[Dict[str, Any]] = []
    for m in matches:
        if not isinstance(m, dict):
            continue
        signature = str(m.get("signature") or m.get("DetectorName") or "NoseyParker")
        path_str = m.get("path") or (m.get("location") or {}).get("path") or ""
        line_no = 0
        if isinstance(m.get("line_number"), int):
            line_no = m["line_number"]
        else:
            start_line_val = (m.get("location") or {}).get("startLine")
            if isinstance(start_line_val, int):
                line_no = start_line_val
        msg = m.get("match") or m.get("context") or signature
        sev = normalize_severity("MEDIUM")
        fid = fingerprint("noseyparker", signature, path_str, line_no, msg)
        finding = {
            "schemaVersion": "1.0.0",
            "id": fid,
            "ruleId": signature,
            "title": signature,
            "message": msg if isinstance(msg, str) else str(msg),
            "description": "Potential secret detected by Nosey Parker",
            "severity": sev,
            "tool": {
                "name": "noseyparker",
                "version": str(data.get("version") or "unknown"),
            },
            "location": {"path": path_str, "startLine": line_no},
            "remediation": "Rotate credentials and purge from history.",
            "tags": ["secrets"],
            "risk": {"cwe": ["CWE-798"]},
            "raw": m,
        }
        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)
    return out
