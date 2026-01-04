#!/usr/bin/env python3
"""
OWASP ZAP adapter - Maps ZAP DAST scanner JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Dynamic Application Security Testing (DAST)
- Web application vulnerability scanning
- API security testing (OpenAPI, GraphQL, SOAP)
- Active and passive scanning modes

Tool Version: 2.15.0+ (weekly Docker releases)
Output Format: JSON with site[].alerts[] structure
Exit Codes: 0 (clean), varies by scan mode

Scan Types:
- Baseline: Passive scanning, fast, safe for production
- Full Scan: Active + passive, comprehensive, may modify data
- API Scan: OpenAPI/GraphQL/SOAP API security testing
- Ajax Spider: JavaScript-heavy application crawling

Risk Levels (ZAP -> CommonFinding):
- High: HIGH (confirmed exploitable vulnerabilities)
- Medium: MEDIUM (likely exploitable)
- Low: LOW (low impact issues)
- Informational: INFO (security observations)

Common Vulnerability Categories:
- Injection: SQL, XSS, Command, LDAP injection
- Authentication: Session fixation, weak auth
- CSRF: Cross-Site Request Forgery
- Security Headers: Missing security headers
- Information Disclosure: Debug info, stack traces
- SSL/TLS: Certificate issues, weak ciphers

CWE/WASC Classification:
- Each finding includes CWE ID (Common Weakness Enumeration)
- WASC ID (Web Application Security Consortium)

Example:
    >>> adapter = ZapAdapter()
    >>> findings = adapter.parse(Path('zap.json'))
    >>> # Returns web security findings with CWE/WASC enrichment

See Also:
    - https://www.zaproxy.org/
    - OWASP Testing Guide
    - OWASP Top 10
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.core.adapters.common import safe_load_json_file
from scripts.core.common_finding import fingerprint, map_tool_severity
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)


def _process_zap_instance(
    alert: dict[str, Any],
    instance: dict[str, Any],
    idx: int,
    zap_version: str,
) -> dict[str, Any] | None:
    """Process single ZAP alert instance into finding dict.

    Args:
        alert: ZAP alert dictionary containing alert details
        instance: Instance dictionary with URI, method, param, evidence
        idx: Instance index for unique fingerprinting
        zap_version: ZAP tool version string

    Returns:
        Finding dict or None if instance is invalid
    """
    if not isinstance(instance, dict):
        return None

    # Extract alert fields
    alert_name = str(alert.get("alert") or alert.get("name") or "Unknown")
    risk = str(alert.get("risk") or "Medium")
    confidence = str(alert.get("confidence") or "Medium")
    description = str(alert.get("desc") or "")
    solution = str(alert.get("solution") or "")
    reference = str(alert.get("reference") or "")
    cweid = str(alert.get("cweid") or "")
    wascid = str(alert.get("wascid") or "")

    severity_normalized = map_tool_severity("zap", risk)

    # Extract instance fields
    uri = str(instance.get("uri") or instance.get("url") or "")
    method = str(instance.get("method") or "")
    param = str(instance.get("param") or instance.get("parameter") or "")
    evidence = str(instance.get("evidence") or "")

    # Extract path from URI for location
    file_path = uri.split("?")[0] if uri else ""

    # Build message
    msg_parts = [alert_name]
    if param:
        msg_parts.append(f"(param: {param})")
    if method:
        msg_parts.append(f"[{method}]")
    message = " ".join(msg_parts)

    # Create unique fingerprint per instance
    rule_id = f"ZAP-{cweid}" if cweid else f"ZAP-{alert_name}"
    location_key = f"{uri}:{method}:{param}:{idx}"
    fid = fingerprint("zap", rule_id, location_key, 0, message)

    # Build tags
    tags = _build_zap_tags(cweid, wascid, confidence)

    # Build references list
    refs = _parse_zap_references(reference)

    return {
        "schemaVersion": "1.2.0",
        "id": fid,
        "ruleId": rule_id,
        "title": alert_name,
        "message": message,
        "description": description.strip() if description else alert_name,
        "severity": severity_normalized,
        "tool": {
            "name": "zap",
            "version": zap_version,
        },
        "location": {
            "path": file_path,
            "startLine": 0,
        },
        "remediation": solution.strip() if solution else "",
        "references": refs if refs else None,
        "tags": tags,
        "context": {
            "uri": uri,
            "method": method,
            "param": param,
            "evidence": evidence[:200] if evidence else "",  # Truncate long evidence
            "confidence": confidence,
            "risk": risk,
        },
        "raw": {
            "alert": alert_name,
            "risk": risk,
            "confidence": confidence,
            "cweid": cweid,
            "wascid": wascid,
            "uri": uri,
            "method": method,
            "param": param,
            "evidence": evidence,
        },
    }


def _build_zap_tags(cweid: str, wascid: str, confidence: str) -> list[str]:
    """Build tags list for ZAP finding.

    Args:
        cweid: CWE ID string
        wascid: WASC ID string
        confidence: Confidence level string

    Returns:
        List of tags including base tags and security-specific tags
    """
    tags = ["dast", "web-security"]
    if cweid:
        tags.append(f"CWE-{cweid}")
    if wascid:
        tags.append(f"WASC-{wascid}")
    tags.append(f"confidence:{confidence.lower()}")
    return tags


def _parse_zap_references(reference: str) -> list[str]:
    """Parse ZAP reference string into list of URLs.

    Args:
        reference: Newline-separated reference URLs

    Returns:
        List of reference URL strings
    """
    refs = []
    if reference:
        for ref_url in reference.split("\n"):
            ref_url = ref_url.strip()
            if ref_url:
                refs.append(ref_url)
    return refs


@adapter_plugin(
    PluginMetadata(
        name="zap",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for OWASP ZAP web security scanner",
        tool_name="zap",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean"},
    )
)
class ZapAdapter(AdapterPlugin):
    """Adapter for OWASP ZAP web security scanner (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to zap.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_zap_internal(output_path)

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


def _load_zap_internal(path: str | Path) -> list[dict[str, Any]]:
    """Load and normalize ZAP JSON output.

    Expected JSON structure:
    {
      "site": [
        {
          "alerts": [
            {
              "alert": "SQL Injection",
              "risk": "High",
              "confidence": "Medium",
              "desc": "...",
              "solution": "...",
              "reference": "...",
              "cweid": "89",
              "wascid": "19",
              "instances": [
                {
                  "uri": "http://example.com/page",
                  "method": "GET",
                  "param": "id",
                  "evidence": "..."
                }
              ]
            }
          ]
        }
      ]
    }
    """
    data = safe_load_json_file(path, default=None)
    if not isinstance(data, dict):
        return []

    findings: list[dict[str, Any]] = []

    # ZAP output structure: {"site": [{"alerts": [...]}]}
    sites = data.get("site", [])
    if not isinstance(sites, list):
        return []

    for site in sites:
        if not isinstance(site, dict):
            continue

        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            continue

        # Get ZAP version once for all findings
        zap_version = str(data.get("@version") or "unknown")

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            # Process instances (individual occurrences of the alert)
            instances = alert.get("instances", [])
            if not isinstance(instances, list) or len(instances) == 0:
                # If no instances, create a single finding for the alert
                instances = [{}]

            for idx, instance in enumerate(instances):
                # Use helper function to process each instance
                finding = _process_zap_instance(alert, instance, idx, zap_version)
                if finding is None:
                    continue

                findings.append(finding)

    return findings
