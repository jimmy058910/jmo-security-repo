#!/usr/bin/env python3
"""
Nosey Parker adapter - Maps Nosey Parker secrets scan JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- High-performance secret scanning (Rust-based)
- Git history and file system scanning
- 200+ detector patterns for secrets
- Entropy-based detection support

Tool Version: 0.16.0+
Output Format: JSON with matches array
Exit Codes: 0 (clean), 1 (findings)

Supported Secret Types:
- API keys: AWS, GCP, Azure, GitHub, GitLab, Slack, etc.
- Credentials: Database passwords, OAuth tokens
- Private keys: SSH, PGP, TLS/SSL certificates
- Cloud provider: AWS access keys, GCP service accounts
- Service tokens: Stripe, Twilio, SendGrid, etc.

Severity Classification:
- All secrets default to MEDIUM severity
- CWE-798: Use of Hard-coded Credentials

Complementary to TruffleHog:
- Nosey Parker: Pattern-based, very fast, no verification
- TruffleHog: Verification of secrets against APIs

Example:
    >>> adapter = NoseyParkerAdapter()
    >>> findings = adapter.parse(Path('noseyparker.json'))
    >>> # Returns secret detection findings

See Also:
    - https://github.com/praetorian-inc/noseyparker
    - OWASP Secrets Management Cheat Sheet
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.core.adapters.common import safe_load_json_file
from scripts.core.common_finding import fingerprint, normalize_severity
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
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
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


def _load_noseyparker_internal(path: str | Path) -> list[dict[str, Any]]:
    data = safe_load_json_file(path, default=None)
    if data is None:
        return []

    matches = data.get("matches") if isinstance(data, dict) else None
    if not isinstance(matches, list):
        return []

    out: list[dict[str, Any]] = []
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
            "schemaVersion": "1.2.0",
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
        out.append(finding)
    return out
