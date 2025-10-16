#!/usr/bin/env python3
"""
Checkov adapter: normalize Checkov JSON output (SAST for IaC) to CommonFinding.
Expected input may include a top-level results dictionary with "failed_checks" entries.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def load_checkov(path: str | Path) -> List[Dict[str, Any]]:
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

    out: List[Dict[str, Any]] = []
    # Handle structure: {"results":{"failed_checks":[...]}}
    results = data.get("results") if isinstance(data, dict) else None
    failed = results.get("failed_checks") if isinstance(results, dict) else None
    if isinstance(failed, list):
        for it in failed:
            if not isinstance(it, dict):
                continue
            rid = str(it.get("check_id") or it.get("check_name") or "CHECKOV")
            file_path = str(it.get("file_path") or it.get("repo_file_path") or "")
            # Line number may be provided as a list range, a scalar, or invalid; default to 0 on errors
            line_val = it.get("file_line_range")
            line = 0
            try:
                if isinstance(line_val, list) and line_val:
                    line = int(line_val[0])
                elif isinstance(line_val, (int, str)):
                    line = int(line_val)
                else:
                    line = 0
            except Exception:
                line = 0
            msg = str(it.get("check_name") or it.get("check_id") or "Policy failure")
            sev = normalize_severity(it.get("severity") or "MEDIUM")
            fid = fingerprint("checkov", rid, file_path, line, msg)
            finding = {
                "schemaVersion": "1.0.0",
                "id": fid,
                "ruleId": rid,
                "title": rid,
                "message": msg,
                "description": str(it.get("guideline") or msg),
                "severity": sev,
                "tool": {
                    "name": "checkov",
                    "version": str(data.get("checkov_version") or "unknown"),
                },
                "location": {"path": file_path, "startLine": line},
                "remediation": str(it.get("guideline") or "Review policy guidance"),
                "tags": ["iac", "policy"],
                "raw": it,
            }
            # Enrich with compliance framework mappings
            finding = enrich_finding_with_compliance(finding)
            out.append(finding)
    return out
