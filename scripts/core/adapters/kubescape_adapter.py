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

import logging
from pathlib import Path
from typing import Any

from scripts.core.adapters.common import safe_load_json_file
from scripts.core.common_finding import fingerprint
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
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]  # Dynamically attached by @adapter_plugin decorator

    def parse(self, output_path: Path) -> list[Finding]:
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


def _load_kubescape_internal(path: str | Path) -> list[dict[str, Any]]:
    """Internal function to parse Kubescape JSON output.

    Args:
        path: Path to kubescape.json output file

    Returns:
        List of dicts (converted to Finding objects by parse() method)
    """
    data = safe_load_json_file(path, default=None)

    out: list[dict[str, Any]] = []

    # Kubescape puts per-resource verdicts in `results[]`, NOT in
    # `summaryDetails.controls`. Each results[] entry is one scanned resource:
    #
    #   {"resourceID": "...", "controls": [
    #       {"controlID": "C-0004", "name": "...",
    #        "status": {"status": "failed"}, "severity": "High", "rules": [...]}]}
    #
    # `summaryDetails.controls` is a per-control ROLL-UP whose failure signal is
    # an integer at `ResourceCounters.failedResources` -- it never carries the
    # resource IDs needed to locate a finding.
    #
    # This function previously read a TOP-LEVEL `failedResources` LIST off each
    # summary control and skipped the control when it was empty. Kubescape has
    # never emitted that key: measured against the same insecure Pod manifest,
    # v3.0.47 and v4.0.12 produce byte-compatible shapes (identical top-level
    # keys, identical control-record keys, 130 controls each) and NEITHER has
    # it. So every control was skipped and the adapter returned [] for every
    # real scan, in every profile that ships kubescape (slim/balanced/deep),
    # while the tool exited 0 and wrote a populated file. #1094.
    if not isinstance(data, dict):
        return []

    # Summary roll-up: used only to enrich a finding with scoreFactor and
    # description, which the per-resource control record does not carry.
    summary_details = data.get("summaryDetails", {})
    if not isinstance(summary_details, dict):
        summary_details = {}
    controls_summary = summary_details.get("controls", {})
    if not isinstance(controls_summary, dict):
        controls_summary = {}

    # Extract framework name if present
    framework_name = str(summary_details.get("frameworkName", ""))

    # Resource lookup. The K8s object is nested under `object`; reading
    # `res["kind"]` (as this did) yields "Unknown" for every resource even when
    # the map is populated.
    resource_map: dict[str, dict[str, Any]] = {}
    resources = data.get("resources", [])
    if isinstance(resources, list):
        for res in resources:
            if not isinstance(res, dict):
                continue
            res_id = res.get("resourceID")
            if not res_id:
                continue
            obj = res.get("object")
            obj = obj if isinstance(obj, dict) else {}
            meta = obj.get("metadata")
            meta = meta if isinstance(meta, dict) else {}
            resource_map[str(res_id)] = {
                "kind": str(obj.get("kind") or "Unknown"),
                "name": str(meta.get("name") or res_id),
                "namespace": str(meta.get("namespace") or ""),
                "raw": res,
            }

    # One finding per (resource, failed control) pair.
    results = data.get("results", [])
    if not isinstance(results, list):
        return []

    for result in results:
        if not isinstance(result, dict):
            continue
        res_id = str(result.get("resourceID") or "")
        resource_info = resource_map.get(
            res_id,
            {
                "kind": "Unknown",
                "name": res_id or "unknown",
                "namespace": "",
                "raw": {},
            },
        )
        resource = resource_info["raw"]
        resource_kind = resource_info["kind"]
        resource_name = resource_info["name"]
        resource_namespace = resource_info["namespace"]

        result_controls = result.get("controls")
        if not isinstance(result_controls, list):
            continue

        for control_entry in result_controls:
            if not isinstance(control_entry, dict):
                continue

            # `status` is an object in v3/v4 ({"status": "failed", ...}); tolerate
            # a bare string in case an older or newer shape flattens it.
            status = control_entry.get("status")
            status_value = status.get("status") if isinstance(status, dict) else status
            if status_value != "failed":
                continue

            control_id = str(control_entry.get("controlID") or "")
            if not control_id:
                continue

            control_data = controls_summary.get(control_id)
            if not isinstance(control_data, dict):
                control_data = {}

            control_name = str(
                control_entry.get("name") or control_data.get("name") or control_id
            )
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

            # Extract remediation
            remediation = str(control_data.get("remediation", ""))

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
                "description": control_desc or control_name,
                "severity": severity,
                "tool": {
                    "name": "kubescape",
                    "version": "3.0.0",  # Kubescape v3.0.0+
                },
                "location": {
                    "path": location_path,
                    "startLine": 0,  # K8s resources don't have line numbers
                },
                "remediation": (
                    remediation or "Review Kubernetes resource configuration"
                ),
                "references": [],
                "tags": ["k8s-security", "misconfiguration"],
                "context": {
                    "control_id": control_id,
                    "control_name": control_name,
                    "score_factor": score_factor,
                    "framework": framework_name or None,
                    "resource_kind": resource_kind,
                    "resource_name": resource_name,
                    "resource_namespace": (resource_namespace or None),
                },
                "raw": {
                    "control": control_data,
                    "resource": resource,
                },
            }

            out.append(finding)

    return out
