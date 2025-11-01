#!/usr/bin/env python3
"""
OSV-Scanner adapter - Maps OSV-Scanner JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Google's official OSV (Open Source Vulnerabilities) scanner
- SCA (Software Composition Analysis) using osv.dev database
- Detects: Known CVEs, security advisories, vulnerabilities in dependencies
- Supports: lockfiles, SBOMs, Git repos, Docker images

Tool Version: 2.0.0+
Output Format: JSON with results[].packages[].vulnerabilities[]
Exit Codes: 0 (clean), 1 (findings), 2+ (errors)

Supported Ecosystems:
- npm, PyPI, Maven, Go, RubyGems, crates.io, NuGet, Packagist, etc.
- 40+ package ecosystems via osv.dev database
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
        name="osv-scanner",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for OSV-Scanner (Google Open Source Vulnerabilities scanner)",
        tool_name="osv-scanner",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings", 2: "error"},
    )
)
class OSVScannerAdapter(AdapterPlugin):
    """Adapter for OSV-Scanner (plugin architecture).

    v1.0.0 Features:
    - SCA using osv.dev database (40+ ecosystems)
    - CVE detection and security advisories
    - Supports lockfiles, SBOMs, Git repos, Docker images
    - Alias-based vulnerability grouping

    Findings are automatically tagged as 'sca' and 'vulnerability'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to osv-scanner.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_osv_scanner_internal(output_path)

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


def _load_osv_scanner_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function to parse OSV-Scanner JSON output.

    Args:
        path: Path to osv-scanner.json output file

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
        logger.warning(f"Failed to parse OSV-Scanner JSON: {path}")
        return []

    out: List[Dict[str, Any]] = []

    # OSV-Scanner JSON structure: {"results": [...]}
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return []

    for result in results:
        if not isinstance(result, dict):
            continue

        # Extract source information
        source = result.get("source", {})
        source_path = str(source.get("path", "")) if isinstance(source, dict) else ""
        source_type = (
            str(source.get("type", "lockfile"))
            if isinstance(source, dict)
            else "lockfile"
        )

        # Extract packages
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            continue

        for pkg_entry in packages:
            if not isinstance(pkg_entry, dict):
                continue

            # Extract package metadata
            pkg = pkg_entry.get("package", {})
            if not isinstance(pkg, dict):
                continue

            pkg_name = str(pkg.get("name", "unknown"))
            pkg_version = str(pkg.get("version", "unknown"))
            pkg_ecosystem = str(pkg.get("ecosystem", "unknown"))

            # Extract vulnerabilities
            vulnerabilities = pkg_entry.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                continue

            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue

                # Extract core vulnerability fields
                vuln_id = str(vuln.get("id", "OSV-UNKNOWN"))
                aliases = vuln.get("aliases", [])
                if not isinstance(aliases, list):
                    aliases = []

                # Build CVE list from aliases
                cve_list = [
                    alias
                    for alias in aliases
                    if isinstance(alias, str) and alias.startswith("CVE-")
                ]

                # Extract summary and details
                summary = str(vuln.get("summary", ""))
                details = str(vuln.get("details", ""))
                message = (
                    summary
                    if summary
                    else (
                        details if details else f"Vulnerability {vuln_id} in {pkg_name}"
                    )
                )

                # Extract CVSS scores first (from severity array)
                cvss_v2 = None
                cvss_v3 = None
                severity_raw = None

                if isinstance(vuln.get("severity"), list):
                    for sev_entry in vuln["severity"]:
                        if isinstance(sev_entry, dict):
                            if sev_entry.get("type") == "CVSS_V2":
                                cvss_v2 = sev_entry.get("score")
                            elif sev_entry.get("type") == "CVSS_V3":
                                cvss_v3 = sev_entry.get("score")

                # Extract severity (OSV uses database_specific.severity or derive from CVSS)
                if isinstance(vuln.get("database_specific"), dict):
                    severity_raw = vuln["database_specific"].get("severity")

                # If no explicit severity, derive from CVSS v3 score
                if not severity_raw and cvss_v3:
                    try:
                        cvss_score = float(cvss_v3)
                        if cvss_score >= 9.0:
                            severity_raw = "CRITICAL"
                        elif cvss_score >= 7.0:
                            severity_raw = "HIGH"
                        elif cvss_score >= 4.0:
                            severity_raw = "MEDIUM"
                        else:
                            severity_raw = "LOW"
                    except (ValueError, TypeError):
                        pass

                # Normalize severity
                if severity_raw:
                    severity = normalize_severity(str(severity_raw))
                else:
                    # Default to MEDIUM if no severity provided
                    severity = "MEDIUM"

                # Extract references
                references = []
                refs = vuln.get("references", [])
                if isinstance(refs, list):
                    for ref in refs:
                        if isinstance(ref, dict) and "url" in ref:
                            references.append(str(ref["url"]))

                # Generate stable fingerprint
                # Use package name + version + vuln ID for uniqueness
                fid = fingerprint(
                    "osv-scanner", vuln_id, f"{pkg_name}@{pkg_version}", 0, message
                )

                # Build finding dict
                finding = {
                    "schemaVersion": "1.2.0",
                    "id": fid,
                    "ruleId": vuln_id,
                    "title": vuln_id,
                    "message": message,
                    "description": details if details else summary,
                    "severity": severity,
                    "tool": {
                        "name": "osv-scanner",
                        "version": "2.0.0",  # OSV-Scanner v2.0.0+
                    },
                    "location": {
                        "path": source_path,
                        "startLine": 0,  # Lockfiles don't have line numbers
                    },
                    "remediation": f"Update {pkg_name} from {pkg_version} to a patched version",
                    "references": references,
                    "tags": ["sca", "vulnerability", pkg_ecosystem.lower()],
                    "cvss": (
                        {
                            "v2": cvss_v2,
                            "v3": cvss_v3,
                        }
                        if cvss_v2 or cvss_v3
                        else None
                    ),
                    "context": {
                        "package_name": pkg_name,
                        "package_version": pkg_version,
                        "package_ecosystem": pkg_ecosystem,
                        "source_type": source_type,
                        "aliases": aliases,
                        "cves": cve_list,
                    },
                    "raw": vuln,
                }

                # Enrich with compliance framework mappings
                finding = enrich_finding_with_compliance(finding)
                out.append(finding)

    return out
