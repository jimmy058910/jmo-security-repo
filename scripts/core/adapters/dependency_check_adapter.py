#!/usr/bin/env python3
"""
OWASP Dependency-Check adapter - Maps Dependency-Check SCA JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Software Composition Analysis (SCA)
- Known vulnerability detection in dependencies
- CPE (Common Platform Enumeration) identification
- CVE/NVD integration with CVSS scoring

Tool Version: 12.1.0+
Output Format: JSON with dependencies array
Exit Codes: 0 (success), 1+ (vulnerabilities found)

Supported Package Managers:
- Maven, Gradle (Java)
- npm, yarn (JavaScript/Node.js)
- pip, poetry (Python)
- NuGet (.NET)
- Ruby gems, Composer (PHP)
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
        name="dependency-check",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for OWASP Dependency-Check SCA tool",
        tool_name="dependency-check",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "success", 1: "vulnerabilities"},
    )
)
class DependencyCheckAdapter(AdapterPlugin):
    """Adapter for OWASP Dependency-Check SCA (plugin architecture).

    v1.0.0 Features:
    - Software Composition Analysis (SCA)
    - CVE detection in dependencies
    - CVSS v2/v3 scoring
    - CPE identification

    Findings are automatically tagged as 'dependency' and 'sca'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to dependency-check.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_dependency_check_internal(output_path)

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


def _load_dependency_check_internal(path: str | Path) -> list[dict[str, Any]]:
    """Internal function to parse Dependency-Check JSON output.

    Args:
        path: Path to dependency-check.json output file

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
        logger.warning(f"Failed to parse Dependency-Check JSON: {path}")
        return []

    out: list[dict[str, Any]] = []

    # Dependency-Check JSON structure: {"reportSchema": "1.1", "scanInfo": {...}, "dependencies": [...]}
    if not isinstance(data, dict):
        return []

    # Extract version for tool metadata
    scan_info = data.get("scanInfo", {})
    engine_version = str(scan_info.get("engineVersion", "12.1.0"))

    # Process dependencies array
    dependencies = data.get("dependencies", [])
    if not isinstance(dependencies, list):
        return []

    for dep in dependencies:
        if not isinstance(dep, dict):
            continue

        # Extract dependency metadata
        file_name = str(dep.get("fileName", ""))
        file_path = str(dep.get("filePath", file_name))

        # Extract package information (GAV for Maven, etc.)
        packages = dep.get("packages", [])
        package_id = None
        if isinstance(packages, list) and packages:
            pkg = packages[0]
            if isinstance(pkg, dict):
                package_id = str(pkg.get("id", ""))

        # Process vulnerabilities for this dependency
        vulnerabilities = dep.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            # Extract vulnerability metadata
            cve_name = str(vuln.get("name", ""))
            description = str(vuln.get("description", ""))
            severity_raw = str(vuln.get("severity", "MEDIUM"))

            # Extract CVSS scores (prefer v3 over v2)
            cvss_field = None
            cvss_v3 = vuln.get("cvssv3", {})
            cvss_v2 = vuln.get("cvssv2", {})

            if isinstance(cvss_v3, dict) and cvss_v3.get("baseScore") is not None:
                cvss_field = {
                    "version": "3.x",
                    "score": float(cvss_v3.get("baseScore", 0)),
                    "vector": str(cvss_v3.get("vectorString", "")),
                }
                # Use CVSS v3 severity if available
                severity_raw = str(cvss_v3.get("baseSeverity", severity_raw))
            elif isinstance(cvss_v2, dict) and cvss_v2.get("score") is not None:
                cvss_field = {
                    "version": "2.0",
                    "score": float(cvss_v2.get("score", 0)),
                    "vector": str(cvss_v2.get("accessVector", "")),
                }

            # Normalize severity
            severity = normalize_severity(severity_raw)

            # Build message
            message = (
                description
                if description
                else f"Known vulnerability {cve_name} detected in dependency"
            )

            # Build title
            title = f"{cve_name}: {file_name}"

            # Generate stable fingerprint
            fid = fingerprint("dependency-check", cve_name, file_path, 0, message)

            # Build references
            references = []
            if cve_name and cve_name.startswith("CVE-"):
                references.append(f"https://nvd.nist.gov/vuln/detail/{cve_name}")

            # Extract additional references from vulnerability
            vuln_refs = vuln.get("references", [])
            if isinstance(vuln_refs, list):
                for ref in vuln_refs[:3]:  # Limit to first 3 references
                    if isinstance(ref, dict):
                        url = ref.get("url") or ref.get("source")
                        if url:
                            references.append(str(url))

            # Build tags
            tags = ["dependency", "sca", "cve", "supply-chain"]
            if package_id:
                if "pkg:maven" in package_id:
                    tags.append("maven")
                if "pkg:npm" in package_id:
                    tags.append("npm")
                if "pkg:pypi" in package_id or "pkg:python" in package_id:
                    tags.append("python")
                if "pkg:nuget" in package_id:
                    tags.append("nuget")
                if "pkg:gem" in package_id:
                    tags.append("ruby")

            # Build remediation
            remediation = f"Update {file_name} to a version that resolves {cve_name}. Review release notes and security advisories."

            # Build finding dict
            finding = {
                "schemaVersion": "1.2.0",
                "id": fid,
                "ruleId": cve_name,
                "title": title,
                "message": message,
                "description": description,
                "severity": severity,
                "tool": {
                    "name": "dependency-check",
                    "version": engine_version,
                },
                "location": {
                    "path": file_path,
                    "startLine": 0,  # Dependencies don't have line numbers
                },
                "remediation": remediation,
                "references": references,
                "tags": tags,
                "cvss": cvss_field,
                "context": {
                    "cve": cve_name,
                    "dependency_file": file_name,
                    "package_id": package_id if package_id else None,
                },
                "raw": vuln,
            }

            # Enrich with compliance framework mappings
            finding = enrich_finding_with_compliance(finding)
            out.append(finding)

    return out
