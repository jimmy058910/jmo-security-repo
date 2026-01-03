#!/usr/bin/env python3
"""
Grype adapter - Maps Grype vulnerability scanner JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Vulnerability scanner for container images and filesystems
- CVE detection with CVSS scoring
- Fix version recommendations
- Multi-source vulnerability data (NVD, GitHub Security, etc.)

Tool Version: 0.74.0+
Output Format: JSON with matches array
Exit Codes: 0 (no vulnerabilities), 1 (vulnerabilities found), 2+ (errors)

Supported Sources:
- Container images (Docker, OCI)
- Filesystems and directories
- SBOMs (Syft, CycloneDX, SPDX)
- Multiple package ecosystems
"""

from __future__ import annotations

import logging
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

# Configure logging
logger = logging.getLogger(__name__)


def _select_best_cvss(cvss_scores: dict[str, Any]) -> dict[str, Any] | None:
    """Select best CVSS score (v3 preferred over v2).

    Args:
        cvss_scores: Dictionary of CVSS scores keyed by version (e.g., "cvss_v3.1", "cvss_v2")

    Returns:
        CVSS field dict with version, score, vector or None if no scores
    """
    if not cvss_scores:
        return None

    # Prefer CVSS v3 over v2
    for prefix, version_label in [("cvss_v3", "3.x"), ("cvss_v2", "2.0")]:
        key = next((k for k in cvss_scores if k.startswith(prefix)), None)
        if key:
            return {
                "version": version_label,
                "score": cvss_scores[key]["score"],
                "vector": cvss_scores[key]["vector"],
            }
    return None


def _build_grype_context(
    vuln_id: str,
    artifact_name: str,
    artifact_version: str,
    artifact_type: str,
    artifact_purl: str,
    fixed_versions: list[str],
    data_source: str,
    match_info: list[str],
    cvss_scores: dict[str, Any],
) -> dict[str, Any]:
    """Build context dictionary for Grype finding.

    Args:
        vuln_id: Vulnerability ID (e.g., CVE-2021-44228)
        artifact_name: Package/artifact name
        artifact_version: Package version
        artifact_type: Type of artifact (e.g., npm, pip)
        artifact_purl: Package URL
        fixed_versions: List of versions that fix the vulnerability
        data_source: Data source for the vulnerability
        match_info: List of matchers used
        cvss_scores: CVSS score dictionary

    Returns:
        Context dictionary with non-None values
    """
    return {
        "vulnerability_id": vuln_id,
        "artifact_name": artifact_name,
        "artifact_version": artifact_version,
        "artifact_type": artifact_type if artifact_type else None,
        "artifact_purl": artifact_purl if artifact_purl else None,
        "fixed_versions": fixed_versions if fixed_versions else None,
        "data_source": data_source if data_source else None,
        "matchers": match_info if match_info else None,
        "cvss_scores": cvss_scores if cvss_scores else None,
    }


def _build_grype_tags(artifact_type: str, data_source: str) -> list[str]:
    """Build tags list for Grype finding.

    Args:
        artifact_type: Type of artifact (e.g., npm, pip)
        data_source: Data source for the vulnerability

    Returns:
        List of tags including base tags and artifact-specific tags
    """
    tags = ["vulnerability", "sca", "cve"]
    if artifact_type:
        tags.append(artifact_type.lower().replace(" ", "-"))
    if data_source:
        tags.append(f"source:{data_source.lower().replace(' ', '-')}")
    return tags


@adapter_plugin(
    PluginMetadata(
        name="grype",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Grype vulnerability scanner (SCA)",
        tool_name="grype",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "vulnerabilities", 2: "error"},
    )
)
class GrypeAdapter(AdapterPlugin):
    """Adapter for Grype vulnerability scanner (plugin architecture).

    v1.0.0 Features:
    - Container image and filesystem vulnerability scanning
    - CVE detection with CVSS scoring
    - Fix version recommendations
    - Multi-source vulnerability data (NVD, GitHub, OSV)

    Findings are automatically tagged as 'vulnerability'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to grype.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_grype_internal(output_path)

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


def _load_grype_internal(path: str | Path) -> list[dict[str, Any]]:
    """Internal function to parse Grype JSON output.

    Args:
        path: Path to grype.json output file

    Returns:
        List of dicts (converted to Finding objects by parse() method)
    """
    data = safe_load_json_file(path, default=None)

    out: list[dict[str, Any]] = []

    # Grype JSON structure: {"matches": [...], "source": {...}, "descriptor": {...}}
    if not isinstance(data, dict):
        return []

    # Extract matches array
    matches = data.get("matches", [])
    if not isinstance(matches, list):
        return []

    for match in matches:
        if not isinstance(match, dict):
            continue

        # Extract vulnerability information
        vulnerability = match.get("vulnerability", {})
        if not isinstance(vulnerability, dict):
            continue

        # Extract CVE ID
        vuln_id = str(vulnerability.get("id", ""))
        if not vuln_id:
            continue

        # Extract severity
        severity_raw = str(vulnerability.get("severity", ""))
        severity = normalize_severity(severity_raw) if severity_raw else "MEDIUM"

        # Extract description
        description = str(vulnerability.get("description", ""))

        # Extract CVSS scores
        cvss_list = vulnerability.get("cvss", [])
        cvss_scores = {}
        if isinstance(cvss_list, list):
            for cvss_entry in cvss_list:
                if isinstance(cvss_entry, dict):
                    version = str(cvss_entry.get("version", ""))
                    vector = str(cvss_entry.get("vector", ""))
                    metrics = cvss_entry.get("metrics", {})
                    if isinstance(metrics, dict):
                        base_score = metrics.get("baseScore")
                        if version and base_score is not None:
                            cvss_scores[f"cvss_v{version}"] = {
                                "score": float(base_score),
                                "vector": vector,
                            }

        # Extract fix information
        fix_info = vulnerability.get("fix", {})
        fixed_versions = []
        if isinstance(fix_info, dict):
            fix_versions = fix_info.get("versions", [])
            if isinstance(fix_versions, list):
                fixed_versions = [str(v) for v in fix_versions]

        # Extract data source
        data_source = str(vulnerability.get("dataSource", ""))

        # Extract references/URLs
        references = []
        urls = vulnerability.get("urls", [])
        if isinstance(urls, list):
            references.extend([str(url) for url in urls])

        # Extract artifact information
        artifact = match.get("artifact", {})
        if not isinstance(artifact, dict):
            artifact = {}

        artifact_name = str(artifact.get("name", "unknown"))
        artifact_version = str(artifact.get("version", "unknown"))
        artifact_type = str(artifact.get("type", ""))
        artifact_purl = str(artifact.get("purl", ""))

        # Extract artifact locations
        locations = artifact.get("locations", [])
        if isinstance(locations, list) and locations:
            # Use first location
            location_obj = locations[0] if isinstance(locations[0], dict) else {}
            location_path = str(
                location_obj.get("path", f"{artifact_name}@{artifact_version}")
            )
        else:
            location_path = f"{artifact_name}@{artifact_version}"

        # Extract match details
        match_details = match.get("matchDetails", [])
        match_info = []
        if isinstance(match_details, list):
            for detail in match_details:
                if isinstance(detail, dict):
                    matcher = str(detail.get("matcher", ""))
                    match_info.append(matcher)

        # Build message
        message = f"Vulnerability {vuln_id} in {artifact_name}@{artifact_version}"
        if fixed_versions:
            message += f" (fix available: {', '.join(fixed_versions[:3])})"

        # Build title
        title = f"{vuln_id}: {artifact_name}"

        # Generate stable fingerprint
        fid = fingerprint("grype", vuln_id, location_path, 0, message)

        # Build remediation
        if fixed_versions:
            remediation = (
                f"Upgrade {artifact_name} to version {', '.join(fixed_versions[:3])}"
            )
        else:
            remediation = f"No fix available for {vuln_id} in {artifact_name}"

        # Build tags using helper
        tags = _build_grype_tags(artifact_type, data_source)

        # Build CVSS field using helper
        cvss_field = _select_best_cvss(cvss_scores)

        # Build context using helper
        context = _build_grype_context(
            vuln_id=vuln_id,
            artifact_name=artifact_name,
            artifact_version=artifact_version,
            artifact_type=artifact_type,
            artifact_purl=artifact_purl,
            fixed_versions=fixed_versions,
            data_source=data_source,
            match_info=match_info,
            cvss_scores=cvss_scores,
        )

        # Build finding dict
        finding = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": vuln_id,
            "title": title,
            "message": message,
            "description": (
                description if description else f"Vulnerability {vuln_id} detected"
            ),
            "severity": severity,
            "tool": {
                "name": "grype",
                "version": "0.74.0",  # Grype v0.74.0+
            },
            "location": {
                "path": location_path,
                "startLine": 0,  # Package vulnerabilities don't have line numbers
            },
            "remediation": remediation,
            "references": references,
            "tags": tags,
            "cvss": cvss_field,
            "context": context,
            "raw": match,
        }

        out.append(finding)

    return out
