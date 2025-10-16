#!/usr/bin/env python3
"""
TruffleHog adapter: normalize various TruffleHog outputs to CommonFinding
Inputs supported:
- JSON array of findings
- NDJSON (one JSON object per line)
- Single JSON object
- Nested arrays [[{...}]]
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def _flatten(obj: Any) -> Iterable[Dict[str, Any]]:
    if obj is None:
        return
    if isinstance(obj, dict):
        yield obj
    elif isinstance(obj, list):
        for item in obj:
            yield from _flatten(item)


def _iter_trufflehog(path: Path) -> Iterable[Dict[str, Any]]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    if not raw.strip():
        return
    # Try JSON parse of entire file first
    try:
        data = json.loads(raw)
        for item in _flatten(data):
            if isinstance(item, dict):
                yield item
        return
    except json.JSONDecodeError:
        pass
    # Fall back to NDJSON
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj
        elif isinstance(obj, list):
            for item in _flatten(obj):
                if isinstance(item, dict):
                    yield item


def load_trufflehog(path: str | Path) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    out: List[Dict[str, Any]] = []
    for f in _iter_trufflehog(p):
        detector = str(f.get("DetectorName") or f.get("Detector") or "Unknown")
        verified = bool(f.get("Verified") or f.get("verified") or False)
        # Try to extract file path from SourceMetadata.Data.Filesystem.file or similar
        file_path = ""
        sm = f.get("SourceMetadata") or {}
        data = sm.get("Data") if isinstance(sm, dict) else {}
        if isinstance(data, dict):
            fs = data.get("Filesystem") or {}
            if isinstance(fs, dict):
                file_path = fs.get("file") or fs.get("path") or ""
        # Some variants include Filename / Raw etc.
        file_path = file_path or f.get("Filename") or f.get("Path") or ""
        start_line = None
        if isinstance(f.get("StartLine"), int):
            start_line = f["StartLine"]
        elif isinstance(f.get("Line"), int):
            start_line = f["Line"]
        msg = f.get("Raw") or f.get("Redacted") or detector
        sev = "HIGH" if verified else "MEDIUM"
        severity = normalize_severity(sev)
        rule_id = detector
        fid = fingerprint("trufflehog", rule_id, file_path, start_line, msg)
        finding = {
            "schemaVersion": "1.0.0",
            "id": fid,
            "ruleId": rule_id,
            "title": f"{detector} secret",
            "message": msg if isinstance(msg, str) else str(msg),
            "description": "Potential secret detected by TruffleHog",
            "severity": severity,
            "tool": {
                "name": "trufflehog",
                "version": str(f.get("Version") or "unknown"),
            },
            "location": {"path": file_path, "startLine": start_line or 0},
            "remediation": "Rotate credentials and purge from history.",
            "tags": ["secrets", "verified" if verified else "unverified"],
            "risk": {
                "cwe": ["CWE-798"],  # Use of Hard-coded Credentials
                "confidence": "HIGH" if verified else "MEDIUM",
                "likelihood": "HIGH",
                "impact": "HIGH",
            },
            "raw": f,
        }
        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)
    return out
