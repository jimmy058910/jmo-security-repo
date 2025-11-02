#!/usr/bin/env python3
"""
Trivy RBAC adapter - Maps Trivy Kubernetes RBAC assessment JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Kubernetes RBAC security assessment
- Role and ClusterRole privilege analysis
- Overly permissive RBAC detection
- CIS Kubernetes Benchmark compliance

Tool Version: 0.50.0+
Output Format: JSON with checks array
Exit Codes: 0 (clean), 1 (findings)

Supported Checks:
- KSV041: Managing secrets access
- KSV042: Managing ConfigMaps access
- KSV043: Managing host network namespaces
- KSV044: Managing host IPC namespaces
- KSV045: Managing host PID namespaces
- KSV046: Managing wildcard verbs
- KSV047: Managing cluster-admin role
- KSV048: Managing exec/attach privileges
- KSV049: Managing wildcard resources
- KSV050: Managing privilege escalation
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

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
        name="trivy-rbac",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Trivy Kubernetes RBAC security assessment",
        tool_name="trivy-rbac",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings"},
    )
)
class TrivyRbacAdapter(AdapterPlugin):
    """Adapter for Trivy Kubernetes RBAC assessment (plugin architecture).

    v1.0.0 Features:
    - Kubernetes RBAC privilege analysis
    - Overly permissive role detection
    - CIS Kubernetes Benchmark checks
    - Cluster-admin and wildcard permission detection

    Findings are automatically tagged as 'rbac' and 'kubernetes'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to trivy-rbac.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_trivy_rbac_internal(output_path)

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


def _load_trivy_rbac_internal(path: str | Path) -> list[dict[str, Any]]:
    """Internal function to parse Trivy RBAC JSON output.

    Args:
        path: Path to trivy-rbac.json output file

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
        logger.warning(f"Failed to parse Trivy RBAC JSON: {path}")
        return []

    out: list[dict[str, Any]] = []

    # Trivy RBAC JSON structure: {"checks": [...], "summary": {...}}
    if not isinstance(data, dict):
        return []

    # Extract Trivy version for tool metadata
    trivy_version = str(data.get("version", "0.50.0"))

    # Process checks array
    checks = data.get("checks", [])
    if not isinstance(checks, list):
        return []

    for check in checks:
        if not isinstance(check, dict):
            continue

        # Extract check metadata
        check_id = str(check.get("checkID", check.get("id", "")))
        success = check.get("success", True)

        # Only process failed checks (success=False)
        if success:
            continue

        title = str(check.get("title", check_id))
        description = str(check.get("description", ""))
        severity_raw = str(check.get("severity", "MEDIUM"))
        category = str(check.get("category", "Kubernetes Security Check"))

        # Extract resource information
        resource_namespace = str(check.get("namespace", ""))
        resource_kind = str(check.get("kind", ""))
        resource_name = str(check.get("name", ""))

        # Normalize severity
        severity = normalize_severity(severity_raw)

        # Build message
        message = description if description else title

        # Build location path
        if resource_namespace and resource_kind and resource_name:
            location_path = f"{resource_namespace}/{resource_kind}/{resource_name}"
        elif resource_kind and resource_name:
            location_path = f"{resource_kind}/{resource_name}"
        elif resource_name:
            location_path = resource_name
        else:
            location_path = f"rbac-check:{check_id}"

        # Generate stable fingerprint
        fid = fingerprint("trivy-rbac", check_id, location_path, 0, message)

        # Build references
        references = []
        if check_id:
            # Link to Trivy RBAC check documentation
            references.append(
                f"https://avd.aquasec.com/misconfig/kubernetes/{check_id.lower()}/"
            )

        # Build tags
        tags = ["rbac", "kubernetes", "k8s-security", "access-control"]
        if "cluster-admin" in title.lower() or "cluster-admin" in description.lower():
            tags.append("cluster-admin")
        if "wildcard" in title.lower() or "wildcard" in description.lower():
            tags.append("wildcard-permissions")
        if "secret" in title.lower() or "secret" in description.lower():
            tags.append("secret-access")
        if resource_kind:
            tags.append(resource_kind.lower())

        # Build finding dict
        finding = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": check_id if check_id else "trivy-rbac-check",
            "title": title,
            "message": message,
            "description": description,
            "severity": severity,
            "tool": {
                "name": "trivy-rbac",
                "version": trivy_version,
            },
            "location": {
                "path": location_path,
                "startLine": 0,  # RBAC checks don't have line numbers
            },
            "remediation": f"Review and restrict RBAC permissions for {location_path}. Follow principle of least privilege.",
            "references": references,
            "tags": tags,
            "context": {
                "check_id": check_id if check_id else None,
                "category": category,
                "resource_namespace": (
                    resource_namespace if resource_namespace else None
                ),
                "resource_kind": resource_kind if resource_kind else None,
                "resource_name": resource_name if resource_name else None,
                "success": success,
            },
            "raw": check,
        }

        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)

    return out
