#!/usr/bin/env python3
"""
Semgrep Secrets adapter - Maps Semgrep secrets-focused scan JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Specialized secrets detection using Semgrep rules
- Hardcoded credentials, API keys, tokens detection
- Complementary to Trufflehog (no verification, broader patterns)
- OWASP CWE-798, CWE-259, CWE-321 coverage

Tool Version: 1.90.0+
Output Format: JSON with results array
Exit Codes: 0 (clean), 1 (findings), 2 (error)

Supported Detection Types:
- API keys (AWS, GCP, Azure, GitHub, etc.)
- Hardcoded passwords and credentials
- Private keys and certificates
- Database connection strings
- OAuth tokens and secrets
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from scripts.core.common_finding import normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)

# Configure logging
logger = logging.getLogger(__name__)

# Semgrep severity mapping
SEMGREP_TO_SEV = {
    "ERROR": "CRITICAL",  # Secrets are critical
    "WARNING": "HIGH",
    "INFO": "MEDIUM",
}


@adapter_plugin(
    PluginMetadata(
        name="semgrep-secrets",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Semgrep secrets detection (hardcoded credentials, API keys, tokens)",
        tool_name="semgrep-secrets",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings", 2: "error"},
    )
)
class SemgrepSecretsAdapter(AdapterPlugin):
    """Adapter for Semgrep secrets detection (plugin architecture).

    v1.0.0 Features:
    - Hardcoded credentials and API keys detection
    - Complementary to Trufflehog (broader patterns, no verification)
    - OWASP CWE-798 (Hardcoded Credentials) coverage
    - Supports generic-api-key, jwt-token, generic-secret patterns

    Findings are automatically tagged as 'secret' and 'credentials'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to semgrep-secrets.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_semgrep_secrets_internal(output_path)

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


def _load_semgrep_secrets_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function to parse Semgrep Secrets JSON output.

    Args:
        path: Path to semgrep-secrets.json output file

    Returns:
        List of dicts (converted to Finding objects by parse() method)
    """
    p = Path(path)
    if not p.exists():
        return []
    raw = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse Semgrep Secrets JSON: {path}")
        return []

    out: List[Dict[str, Any]] = []

    # Semgrep JSON structure: {"results": [...], "version": "..."}
    if not isinstance(data, dict):
        return []

    # Extract version for tool metadata
    tool_version = str(data.get("version", "1.90.0"))

    # Process results array
    results = data.get("results", [])
    if not isinstance(results, list):
        return []

    for r in results:
        if not isinstance(r, dict):
            continue

        # Extract rule ID
        check_id = str(
            r.get("check_id") or r.get("ruleId") or r.get("id") or "semgrep-secret"
        )

        # Extract message
        extra = r.get("extra", {})
        msg = (
            extra.get("message")
            or r.get("message")
            or "Hardcoded secret or credential detected"
        )

        # Extract and normalize severity (secrets are critical)
        sev_raw = extra.get("severity") or r.get("severity", "ERROR")
        sev_norm = SEMGREP_TO_SEV.get(str(sev_raw).upper(), "CRITICAL")
        severity = normalize_severity(sev_norm)

        # Extract path
        path_str = r.get("path") or (r.get("location") or {}).get("path") or ""

        # Extract line number
        start_line = 0
        if isinstance(r.get("start"), dict) and isinstance(r["start"].get("line"), int):
            start_line = r["start"]["line"]

        # Alternative location structure
        loc = r.get("location")
        if (
            isinstance(loc, dict)
            and isinstance(loc.get("start"), dict)
            and isinstance(loc["start"].get("line"), int)
        ):
            start_line = loc["start"]["line"]

        # Extract metadata
        metadata = extra.get("metadata", {})

        # Extract CWE
        cwe = None
        if isinstance(metadata.get("cwe"), list) and metadata["cwe"]:
            cwe_item = metadata["cwe"][0]
            if isinstance(cwe_item, str) and cwe_item.startswith("CWE-"):
                cwe = cwe_item.replace("CWE-", "")

        # Extract OWASP
        owasp = None
        if isinstance(metadata.get("owasp"), list) and metadata["owasp"]:
            owasp = metadata["owasp"][0]

        # Build title
        title = check_id

        # Build fingerprint ID
        from scripts.core.common_finding import fingerprint

        fid = fingerprint("semgrep-secrets", check_id, path_str, start_line, msg)

        # Build references
        references = []
        if cwe:
            references.append(f"https://cwe.mitre.org/data/definitions/{cwe}.html")
        references.append(f"https://semgrep.dev/r/{check_id}")

        # Build tags
        tags = ["secret", "credentials", "hardcoded", "semgrep"]
        if "api-key" in check_id.lower() or "api_key" in check_id.lower():
            tags.append("api-key")
        if "password" in check_id.lower():
            tags.append("password")
        if "token" in check_id.lower():
            tags.append("token")
        if "jwt" in check_id.lower():
            tags.append("jwt")
        if "private-key" in check_id.lower() or "private_key" in check_id.lower():
            tags.append("private-key")
        if cwe:
            tags.append(f"cwe-{cwe}")
        if owasp:
            tags.append("owasp")

        # Build remediation
        remediation: Union[str, Dict[str, Any]] = (
            "Remove hardcoded credentials. Use environment variables, secrets management systems (AWS Secrets Manager, HashiCorp Vault), or configuration files excluded from version control."
        )
        autofix = extra.get("fix")
        if autofix:
            remediation = {
                "fix": autofix,
                "steps": [
                    "Remove the hardcoded secret",
                    "Use environment variables or secrets manager",
                    "Rotate the exposed credential",
                    "Update all systems using the credential",
                ],
            }

        # Build risk field
        risk = {}
        if cwe:
            risk["cwe"] = f"CWE-{cwe}"
        risk["confidence"] = metadata.get("confidence", "HIGH")
        risk["likelihood"] = metadata.get("likelihood", "HIGH")
        risk["impact"] = metadata.get("impact", "CRITICAL")

        # Build finding dict
        finding = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": check_id,
            "title": title,
            "message": msg,
            "description": msg,
            "severity": severity,
            "tool": {
                "name": "semgrep-secrets",
                "version": tool_version,
            },
            "location": {
                "path": path_str,
                "startLine": start_line,
            },
            "remediation": remediation,
            "references": references,
            "tags": tags,
            "risk": risk if risk else None,
            "context": {
                "check_id": check_id,
                "cwe": f"CWE-{cwe}" if cwe else None,
                "owasp": owasp if owasp else None,
                "metadata": metadata if metadata else None,
            },
            "raw": r,
        }

        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)

    return out
