#!/usr/bin/env python3
"""
Akto adapter - Maps Akto API Security JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- API security testing platform (REST, GraphQL, gRPC, JSON-RPC)
- OWASP Top 10 API vulnerabilities (BOLA, BFLA, IDOR, etc.)
- 1000+ pre-built security tests
- Runtime vulnerability detection

Tool Version: 2.0.0+
Output Format: JSON with testingRunResults array
Exit Codes: 0 (pass), 1 (findings)

Supported Detections:
- OWASP Top 10 API vulnerabilities
- HackerOne Top 10
- Broken authentication/authorization
- Sensitive data exposure
"""

from __future__ import annotations

import json
import logging
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

# Configure logging
logger = logging.getLogger(__name__)


@adapter_plugin(
    PluginMetadata(
        name="akto",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Akto API Security testing platform",
        tool_name="akto",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "pass", 1: "findings"},
    )
)
class AktoAdapter(AdapterPlugin):
    """Adapter for Akto API Security platform (plugin architecture).

    v1.0.0 Features:
    - API security testing (REST, GraphQL, gRPC, JSON-RPC, Event-stream)
    - 1000+ tests for OWASP Top 10, HackerOne Top 10
    - BOLA, BFLA, IDOR, authentication/authorization vulnerabilities
    - Runtime vulnerability detection

    Findings are automatically tagged as 'api-security'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to akto.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_akto_internal(output_path)

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


def _load_akto_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function to parse Akto JSON output.

    Args:
        path: Path to akto.json output file

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
        logger.warning(f"Failed to parse Akto JSON: {path}")
        return []

    out: List[Dict[str, Any]] = []

    # Akto JSON structure: {"testingRunResults": [...]}
    if not isinstance(data, dict):
        return []

    # Extract testingRunResults array
    testing_run_results = data.get("testingRunResults", [])
    if not isinstance(testing_run_results, list):
        return []

    for test_run_result in testing_run_results:
        if not isinstance(test_run_result, dict):
            continue

        # Skip non-vulnerable findings
        vulnerable = test_run_result.get("vulnerable", False)
        if not vulnerable:
            continue

        # Extract test metadata
        test_sub_type = str(test_run_result.get("testSubType", ""))
        test_super_type = str(test_run_result.get("testSuperType", ""))

        # Extract API endpoint information
        api_info_key = test_run_result.get("apiInfoKey", {})
        if isinstance(api_info_key, dict):
            method = str(api_info_key.get("method", ""))
            url = str(api_info_key.get("url", ""))
        else:
            method = ""
            url = ""

        # Extract severity (from superCategory or confidence)
        severity_raw = None
        super_category = test_run_result.get("superCategory", {})
        if isinstance(super_category, dict):
            severity_obj = super_category.get("severity", {})
            if isinstance(severity_obj, dict):
                severity_raw = str(severity_obj.get("_name", ""))

        # Fallback to confidence if no severity
        if not severity_raw:
            confidence = test_run_result.get("confidence", {})
            if isinstance(confidence, dict):
                severity_raw = str(confidence.get("_name", "MEDIUM"))

        # Normalize severity (Akto uses: CRITICAL, HIGH, MEDIUM, LOW)
        severity = normalize_severity(severity_raw) if severity_raw else "MEDIUM"

        # Extract confidence percentage
        confidence_pct = test_run_result.get("confidencePercentage", 0)

        # Extract test results details
        test_results = test_run_result.get("testResults", "")
        if isinstance(test_results, str):
            message = test_results if test_results else f"API vulnerability: {test_super_type}"
        else:
            message = f"API vulnerability: {test_super_type}"

        # Build title
        title = f"{test_super_type}: {test_sub_type}" if test_sub_type else test_super_type

        # Build location path (use URL or fallback)
        location_path = url if url else f"{method}:/api/endpoint"

        # Generate stable fingerprint
        fid = fingerprint("akto", test_sub_type or test_super_type, location_path, 0, message)

        # Build references (Akto docs for vulnerability type)
        references = []
        if test_super_type:
            # Map test types to documentation links
            ref_url = f"https://docs.akto.io/api-security-testing/test-library/{test_super_type.lower()}"
            references.append(ref_url)

        # Build tags
        tags = ["api-security", "owasp-api"]
        if test_super_type:
            tags.append(test_super_type.lower().replace("_", "-"))
        if method:
            tags.append(method.lower())

        # Build finding dict
        finding = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": test_sub_type if test_sub_type else test_super_type,
            "title": title,
            "message": message,
            "description": f"API security test {title} detected a vulnerability in {method} {url}",
            "severity": severity,
            "tool": {
                "name": "akto",
                "version": "2.0.0",  # Akto v2.0.0+
            },
            "location": {
                "path": location_path,
                "startLine": 0,  # API endpoints don't have line numbers
            },
            "remediation": f"Review {test_super_type} vulnerability and apply API security best practices",
            "references": references,
            "tags": tags,
            "context": {
                "test_sub_type": test_sub_type if test_sub_type else None,
                "test_super_type": test_super_type,
                "api_method": method if method else None,
                "api_url": url if url else None,
                "confidence_percentage": confidence_pct,
            },
            "raw": test_run_result,
        }

        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)

    return out
