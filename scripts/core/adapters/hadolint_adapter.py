#!/usr/bin/env python3
"""
Hadolint adapter: normalize hadolint JSON output to CommonFinding
Expected input: array of issues with fields like: {"code":"DL3008","file":"Dockerfile","line":12,"level":"error","message":"..."}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def load_hadolint(path: str | Path) -> List[Dict[str, Any]]:
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
    if not isinstance(data, list):
        return []
    out: List[Dict[str, Any]] = []
    for it in data:
        if not isinstance(it, dict):
            continue
        code = str(it.get("code") or "HADOLINT")
        file_path = str(it.get("file") or "Dockerfile")
        line = int(it.get("line") or 0)
        msg = str(it.get("message") or code)
        sev = normalize_severity(it.get("level") or "MEDIUM")
        fid = fingerprint("hadolint", code, file_path, line, msg)
        finding = {
            "schemaVersion": "1.0.0",
            "id": fid,
            "ruleId": code,
            "title": code,
            "message": msg,
            "description": msg,
            "severity": sev,
            "tool": {"name": "hadolint", "version": "unknown"},
            "location": {"path": file_path, "startLine": line},
            "remediation": str(it.get("reference") or "See rule documentation"),
            "tags": ["dockerfile", "lint"],
            "raw": it,
        }
        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)
    return out
