#!/usr/bin/env python3
"""
Syft adapter: normalize a minimal subset of Syft SBOM JSON into CommonFinding-like entries.
Focus: represent packages as INFO-level entries and vulnerabilities (if present in document) as proper severities.

Supported inputs:
- Syft JSON with top-level "artifacts" (packages) and optional "vulnerabilities" arrays.

Note: This provides cross-linkable context for other adapters (e.g., Trivy) by exposing package->location mapping in tags/raw.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def load_syft(path: str | Path) -> List[Dict[str, Any]]:
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
    artifacts = data.get("artifacts") if isinstance(data, dict) else None
    if isinstance(artifacts, list):
        for a in artifacts:
            name = str(a.get("name") or a.get("id") or "package")
            version = str(a.get("version") or "")
            location = ""
            locs = a.get("locations") or []
            if isinstance(locs, list) and locs:
                loc0 = locs[0]
                if isinstance(loc0, dict):
                    location = str(loc0.get("path") or "")
            title = f"{name} {version}".strip()
            msg = f"Package discovered: {title}"
            fid = fingerprint("syft", name, location, 0, msg)
            finding = {
                "schemaVersion": "1.0.0",
                "id": fid,
                "ruleId": "SBOM.PACKAGE",
                "title": title,
                "message": msg,
                "description": msg,
                "severity": "INFO",
                "tool": {
                    "name": "syft",
                    "version": str(data.get("artifactRelationships") and "unknown"),
                },
                "location": {"path": location, "startLine": 0},
                "remediation": "Track and scan dependencies.",
                "tags": ["sbom", "package"],
                "raw": a,
            }
            # Enrich with compliance framework mappings
            finding = enrich_finding_with_compliance(finding)
            out.append(finding)

    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if isinstance(vulns, list):
        for v in vulns:
            vid = str(v.get("id") or v.get("vulnerability") or "VULN")
            sev = normalize_severity(v.get("severity") or v.get("rating") or "MEDIUM")
            related = v.get("artifactIds") or []
            pkg = None
            if related and isinstance(artifacts, list):
                # attempt to find package by id
                for a in artifacts:
                    if a.get("id") in related:
                        pkg = a
                        break
            name = (pkg or {}).get("name") or "package"
            location = ""
            if pkg and isinstance(pkg.get("locations"), list) and pkg["locations"]:
                loc0 = pkg["locations"][0]
                if isinstance(loc0, dict):
                    location = str(loc0.get("path") or "")
            msg = str(v.get("description") or v.get("summary") or vid)
            fid = fingerprint("syft", vid, location, 0, msg)
            finding = {
                "schemaVersion": "1.0.0",
                "id": fid,
                "ruleId": vid,
                "title": vid,
                "message": msg,
                "description": msg,
                "severity": sev,
                "tool": {
                    "name": "syft",
                    "version": str(data.get("artifactRelationships") and "unknown"),
                },
                "location": {"path": location, "startLine": 0},
                "remediation": str(v.get("url") or "See advisory"),
                "tags": ["sbom", "vulnerability"],
                "risk": {"cwe": ["CWE-1104"]},
                "raw": v,
            }
            # Enrich with compliance framework mappings
            finding = enrich_finding_with_compliance(finding)
            out.append(finding)

    return out
