#!/usr/bin/env python3
"""

REFACTORED: v0.9.0 - Now uses plugin architecture
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
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)


@adapter_plugin(
    PluginMetadata(
        name="noseyparker",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Nosey Parker secret scanner",
        tool_name="noseyparker",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings"},
    )
)
class NoseyParkerAdapter(AdapterPlugin):
    """Adapter for Nosey Parker secret scanner (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to noseyparker.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_noseyparker_internal(output_path)

        # Convert dicts to Finding objects
        findings = []
        for f_dict in findings_dicts:
            finding = Finding(
                schemaVersion=f_dict.get("schemaVersion", "1.2.0"),
                id=f_dict.get("id", ""),
                ruleId=f_dict.get("ruleId", ""),
                severity=f_dict.get("severity", "INFO"),
                tool=f_dict.get("tool", {}),
                location=f_dict.get("location", {}),
                message=f_dict.get("message", ""),
                title=f_dict.get("title"),
                description=f_dict.get("description"),
                remediation=f_dict.get("remediation"),
                references=f_dict.get("references", []),
                tags=f_dict.get("tags", []),
                cvss=f_dict.get("cvss"),
                risk=f_dict.get("risk"),
                compliance=f_dict.get("compliance"),
                context=f_dict.get("context"),
                raw=f_dict.get("raw"),
            )
            findings.append(finding)

        return findings


def _load_noseyparker_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function that returns dicts (refactored from original load_noseyparker)."""


def _load_noseyparker_internal(path: str | Path) -> List[Dict[str, Any]]:
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
