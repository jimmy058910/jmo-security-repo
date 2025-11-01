#!/usr/bin/env python3
"""
Kubescape adapter - Maps Kubescape JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- CNCF Kubernetes security scanner
- Detects: K8s misconfigurations, hardening violations, RBAC issues
- Frameworks: NSA-CISA, CIS Benchmarks, MITRE ATT&CK, SOC 2
- OPA-based policy engine

Tool Version: 3.0.0+
Output Format: JSON with summaryDetails.controls and resources
Exit Codes: 0 (pass), 1 (fail/findings), 2+ (errors)

Supported Frameworks:
- NSA-CISA Kubernetes Hardening Guide
- CIS Kubernetes Benchmark
- MITRE ATT&CK for Kubernetes
- SOC 2, PCI DSS, NIST, ISO 27001
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
        name="kubescape",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Kubescape CNCF Kubernetes security scanner",
        tool_name="kubescape",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "pass", 1: "fail", 2: "error"},
    )
)
class KubescapeAdapter(AdapterPlugin):
    """Adapter for Kubescape CNCF Kubernetes security scanner (plugin architecture).

    v1.0.0 Features:
    - K8s configuration scanning (NSA-CISA, CIS, MITRE ATT&CK, SOC 2)
    - Hardening recommendations
    - RBAC misconfiguration detection
    - OPA-based policy engine

    Findings are automatically tagged as 'k8s-security'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to kubescape.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_kubescape_internal(output_path)

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


def _load_kubescape_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function to parse Kubescape JSON output.

    Args:
        path: Path to kubescape.json output file

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
        logger.warning(f"Failed to parse Kubescape JSON: {path}")
        return []

    out: List[Dict[str, Any]] = []

    # Kubescape JSON structure varies by scan type:
    # - Framework scan: {"summaryDetails": {"controls": {...}}, "resources": [...]}
    # - General scan: {"summaryDetails": {"controls": {...}}, "prioritizedResource": [...]}
    if not isinstance(data, dict):
        return []

    # Extract summary details
    summary_details = data.get("summaryDetails", {})
    if not isinstance(summary_details, dict):
        return []

    # Extract controls
    controls = summary_details.get("controls", {})
    if not isinstance(controls, dict):
        return []

    # Extract framework name if present
    framework_name = str(summary_details.get("frameworkName", ""))

    # Extract resources (maps resource ID to K8s resource details)
    resources = data.get("resources", [])
    resource_map = {}
    if isinstance(resources, list):
        for res in resources:
            if isinstance(res, dict):
                res_id = res.get("resourceID")
                if res_id:
                    resource_map[res_id] = res

    # Process each control
    for control_id, control_data in controls.items():
        if not isinstance(control_data, dict):
            continue

        # Extract control metadata
        control_name = str(control_data.get("name", control_id))
        control_desc = str(control_data.get("description", ""))

        # Extract score factor (represents severity in Kubescape's unintuitive naming)
        score_factor = control_data.get("scoreFactor", 0)

        # Determine severity based on score factor
        # scoreFactor: 0-3 = LOW, 4-6 = MEDIUM, 7-9 = HIGH, 10 = CRITICAL
        if score_factor >= 10:
            severity = "CRITICAL"
        elif score_factor >= 7:
            severity = "HIGH"
        elif score_factor >= 4:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Extract failed resources for this control
        failed_resources = control_data.get("failedResources", [])
        if not isinstance(failed_resources, list):
            failed_resources = []

        # Extract remediation
        remediation = str(control_data.get("remediation", ""))

        # If control passed (no failed resources), skip
        if not failed_resources:
            continue

        # Create findings for each failed resource
        for failed_res_id in failed_resources:
            # Extract resource details
            resource = resource_map.get(failed_res_id, {})
            resource_kind = str(resource.get("kind", "Unknown"))
            resource_name = str(resource.get("name", failed_res_id))
            resource_namespace = str(resource.get("namespace", ""))

            # Build message
            message = f"Control failed: {control_name}"
            if resource_namespace:
                message += f" (namespace: {resource_namespace}, {resource_kind}: {resource_name})"
            else:
                message += f" ({resource_kind}: {resource_name})"

            # Build location path
            location_path = f"{resource_kind}/{resource_name}"
            if resource_namespace:
                location_path = f"{resource_namespace}/{location_path}"

            # Generate stable fingerprint
            fid = fingerprint("kubescape", control_id, location_path, 0, message)

            # Build finding dict
            finding = {
                "schemaVersion": "1.2.0",
                "id": fid,
                "ruleId": control_id,
                "title": control_name,
                "message": message,
                "description": control_desc if control_desc else control_name,
                "severity": severity,
                "tool": {
                    "name": "kubescape",
                    "version": "3.0.0",  # Kubescape v3.0.0+
                },
                "location": {
                    "path": location_path,
                    "startLine": 0,  # K8s resources don't have line numbers
                },
                "remediation": remediation if remediation else "Review Kubernetes resource configuration",
                "references": [],
                "tags": ["k8s-security", "misconfiguration"],
                "context": {
                    "control_id": control_id,
                    "control_name": control_name,
                    "score_factor": score_factor,
                    "framework": framework_name if framework_name else None,
                    "resource_kind": resource_kind,
                    "resource_name": resource_name,
                    "resource_namespace": resource_namespace if resource_namespace else None,
                },
                "raw": {
                    "control": control_data,
                    "resource": resource,
                },
            }

            # Enrich with compliance framework mappings
            finding = enrich_finding_with_compliance(finding)
            out.append(finding)

    return out
