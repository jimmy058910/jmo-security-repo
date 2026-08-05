#!/usr/bin/env python3
"""
Prowler adapter - Maps Prowler Cloud CSPM JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Multi-cloud CSPM (AWS, Azure, GCP, Kubernetes)
- Security posture management across cloud providers
- Compliance frameworks: CIS, PCI-DSS, ISO27001, GDPR, HIPAA, SOC2, etc.
- 400+ security checks

Tool Version: 4.0.0+
Output Format: JSON with findings array
Exit Codes: 0 (pass), 1+ (findings)

Supported Clouds:
- AWS (300+ checks)
- Azure (100+ checks)
- GCP (80+ checks)
- Kubernetes (50+ checks)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from scripts.core.adapters.common import safe_load_json_file, safe_load_ndjson_file
from scripts.core.common_finding import fingerprint, normalize_severity
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
        name="prowler",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Prowler Cloud CSPM (AWS, Azure, GCP, K8s)",
        tool_name="prowler",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "pass", 1: "findings"},
    )
)
class ProwlerAdapter(AdapterPlugin):
    """Adapter for Prowler Cloud CSPM (plugin architecture).

    v1.0.0 Features:
    - Multi-cloud security posture management (AWS, Azure, GCP, K8s)
    - 400+ security checks across compliance frameworks
    - CIS, PCI-DSS, ISO27001, GDPR, HIPAA, SOC2 compliance
    - Resource-level misconfiguration detection

    Findings are automatically tagged as 'cloud-security' and 'cspm'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]  # Dynamically attached by @adapter_plugin decorator

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to prowler.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_prowler_internal(output_path)

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


def _ocsf_to_native(record: dict[str, Any]) -> dict[str, Any]:
    """Map one OCSF record onto the field names the parser below already reads.

    Translating at the edge keeps the mapping in one place instead of threading
    two shapes through every field extraction.
    """
    finding_info = record.get("finding_info") or {}
    resources = record.get("resources") or []
    resource = resources[0] if isinstance(resources, list) and resources else {}
    group = resource.get("group") or {}
    metadata = record.get("metadata") or {}

    return {
        "CheckID": str(metadata.get("event_code") or finding_info.get("uid") or ""),
        "Status": str(record.get("status_code") or ""),
        "Severity": str(record.get("severity") or "medium"),
        "CheckTitle": str(finding_info.get("title") or ""),
        "CheckType": ", ".join(str(t) for t in (finding_info.get("types") or [])),
        "ServiceName": str(group.get("name") or ""),
        "Description": str(finding_info.get("desc") or ""),
        "Risk": str(record.get("risk_details") or ""),
        "StatusExtended": str(record.get("message") or ""),
        "ResourceId": str(resource.get("uid") or ""),
        "ResourceType": str(resource.get("type") or ""),
        "ResourceDetails": str((resource.get("data") or {}).get("details") or ""),
        "Provider": "iac",
        "Remediation": record.get("remediation") or {},
    }


def _iter_prowler_records(path: str | Path) -> list[dict[str, Any]]:
    """Yield prowler findings from whichever format is on disk.

    Prowler 5.x writes a **JSON array of OCSF records** for `json-ocsf`, whose
    field names share nothing with the flat `CheckID`/`Status`/`Severity` shape
    this adapter was written against - that was prowler v3's native JSON, which
    5.x no longer emits. Measured on prowler 5.35.0: `prowler iac` produced 88
    OCSF records (13 FAIL) that this adapter read as zero findings.

    Both are accepted, because the file on disk may predate the change: NDJSON
    is detected by the flat key, OCSF by `class_uid`/`finding_info`.
    """
    records = list(safe_load_ndjson_file(path))
    if records and any("CheckID" in r for r in records if isinstance(r, dict)):
        return [r for r in records if isinstance(r, dict)]

    data = safe_load_json_file(path, default=None)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return [r for r in records if isinstance(r, dict)]

    ocsf = [
        r
        for r in data
        if isinstance(r, dict) and ("finding_info" in r or "class_uid" in r)
    ]
    if ocsf:
        return [_ocsf_to_native(r) for r in ocsf]
    return [r for r in records if isinstance(r, dict)]


def _load_prowler_internal(path: str | Path) -> list[dict[str, Any]]:
    """Internal function to parse Prowler JSON output.

    Args:
        path: Path to prowler.json output file

    Returns:
        List of dicts (converted to Finding objects by parse() method)
    """
    # Prowler v4+ uses NDJSON (newline-delimited JSON)
    # Each line is a separate JSON finding object
    out: list[dict[str, Any]] = []

    for finding_data in _iter_prowler_records(path):

        # Extract core finding fields
        check_id = str(finding_data.get("CheckID", ""))
        if not check_id:
            continue

        # Extract status
        status = str(finding_data.get("Status", "FAIL"))

        # Only process FAIL findings (skip PASS)
        if status.upper() != "FAIL":
            continue

        # Extract check metadata
        check_title = str(finding_data.get("CheckTitle", check_id))
        check_type = str(finding_data.get("CheckType", ""))
        service_name = str(finding_data.get("ServiceName", ""))

        # Extract severity
        severity_raw = str(finding_data.get("Severity", "medium"))
        severity = normalize_severity(severity_raw)

        # Extract resource details
        resource_id = str(finding_data.get("ResourceId", ""))
        resource_arn = str(finding_data.get("ResourceArn", ""))
        resource_type = str(finding_data.get("ResourceType", ""))
        resource_details = str(finding_data.get("ResourceDetails", ""))

        # Extract provider and account info
        provider = str(finding_data.get("Provider", "aws"))
        account_uid = str(finding_data.get("AccountUID", ""))
        region = str(finding_data.get("Region", ""))

        # Extract status extended (detailed explanation)
        status_extended = str(finding_data.get("StatusExtended", ""))

        # Extract description and risk
        description = str(finding_data.get("Description", ""))
        risk = str(finding_data.get("Risk", ""))

        # Extract remediation
        remediation_code = str(finding_data.get("RemediationCode", ""))
        remediation_url = str(finding_data.get("RemediationUrl", ""))

        # Build message
        message = status_extended or check_title

        # Build location path (use resource ARN or ID)
        location_path = resource_arn or resource_id
        if not location_path:
            location_path = f"{provider}/{service_name}/{check_id}"

        # Generate stable fingerprint
        fid = fingerprint("prowler", check_id, location_path, 0, message)

        # Build references
        references = []
        if remediation_url:
            references.append(remediation_url)

        # Build tags
        tags = ["cloud-security", "cspm", provider.lower()]
        if service_name:
            tags.append(service_name.lower())
        if check_type:
            tags.append(check_type.lower().replace(" ", "-"))

        # Build finding dict
        finding = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": check_id,
            "title": check_title,
            "message": message,
            "description": description or check_title,
            "severity": severity,
            "tool": {
                "name": "prowler",
                "version": "4.0.0",  # Prowler v4.0.0+
            },
            "location": {
                "path": location_path,
                "startLine": 0,  # Cloud resources don't have line numbers
            },
            "remediation": remediation_code or risk,
            "references": references,
            "tags": tags,
            "context": {
                "check_id": check_id,
                "check_type": check_type,
                "service_name": service_name,
                "provider": provider,
                "account_uid": account_uid or None,
                "region": region or None,
                "resource_id": resource_id or None,
                "resource_arn": resource_arn or None,
                "resource_type": resource_type or None,
                "resource_details": resource_details or None,
                "risk": risk or None,
            },
            "raw": finding_data,
        }

        out.append(finding)

    return out
