#!/usr/bin/env python3
"""
Syft adapter - Maps Syft SBOM JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Software Bill of Materials (SBOM) generation
- Container image and filesystem analysis
- Package dependency enumeration
- Cross-linkable context for vulnerability scanners (Grype, Trivy)

Tool Version: 1.5.0+
Output Format: JSON (native Syft format, CycloneDX, SPDX supported)
Exit Codes: 0 (success), 1+ (errors)

Supported Package Ecosystems:
- Alpine (apk), Debian/Ubuntu (dpkg)
- Red Hat/CentOS (rpm), ArchLinux (pacman)
- Node.js (npm, yarn), Python (pip, poetry, pipenv)
- Java (Maven, Gradle), Go (modules), Rust (cargo)
- Ruby (gem), .NET (NuGet), PHP (Composer)
- Container images (Docker, OCI)

Finding Types Generated:
- SBOM.PACKAGE: Package inventory entries (INFO severity)
- Vulnerability IDs: If vulnerabilities section present (varies severity)

Cross-Tool Integration:
- Syft SBOM feeds into Grype for vulnerability scanning
- Package locations cross-linked with Trivy findings
- CWE-1104: Use of Unmaintained Third Party Components

Example:
    >>> adapter = SyftAdapter()
    >>> findings = adapter.parse(Path('syft.json'))
    >>> # Returns package inventory and optional vulnerability findings

See Also:
    - https://github.com/anchore/syft
    - Grype (vulnerability scanner companion)
    - CycloneDX and SPDX SBOM standards
"""

from __future__ import annotations

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


@adapter_plugin(
    PluginMetadata(
        name="syft",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Syft SBOM generator",
        tool_name="syft",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean"},
    )
)
class SyftAdapter(AdapterPlugin):
    """Adapter for Syft SBOM generator (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to syft.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_syft_internal(output_path)

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


def _load_syft_internal(path: str | Path) -> list[dict[str, Any]]:
    data = safe_load_json_file(path, default=None)
    if data is None:
        return []

    out: list[dict[str, Any]] = []
    artifacts = data.get("artifacts") if isinstance(data, dict) else None
    if isinstance(artifacts, list):
        for a in artifacts:
            name = str(a.get("name") or a.get("id") or "package")
            version = str(a.get("version") or "")
            location = ""
            locs = a.get("locations") or []
            if isinstance(locs, list) and locs:
                loc0 = locs[0]
                if isinstance(loc0, dict):
                    location = str(loc0.get("path") or "")
            title = f"{name} {version}".strip()
            msg = f"Package discovered: {title}"
            fid = fingerprint("syft", name, location, 0, msg)
            finding = {
                "schemaVersion": "1.2.0",
                "id": fid,
                "ruleId": "SBOM.PACKAGE",
                "title": title,
                "message": msg,
                "description": msg,
                "severity": "INFO",
                "tool": {
                    "name": "syft",
                    "version": str(data.get("artifactRelationships") and "unknown"),
                },
                "location": {"path": location, "startLine": 0},
                "remediation": "Track and scan dependencies.",
                "tags": ["sbom", "package"],
                "raw": a,
            }
            out.append(finding)

    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if isinstance(vulns, list):
        for v in vulns:
            vid = str(v.get("id") or v.get("vulnerability") or "VULN")
            sev = normalize_severity(v.get("severity") or v.get("rating") or "MEDIUM")
            related = v.get("artifactIds") or []
            pkg = None
            if related and isinstance(artifacts, list):
                # attempt to find package by id
                for a in artifacts:
                    if a.get("id") in related:
                        pkg = a
                        break
            name = (pkg or {}).get("name") or "package"
            location = ""
            if pkg and isinstance(pkg.get("locations"), list) and pkg["locations"]:
                loc0 = pkg["locations"][0]
                if isinstance(loc0, dict):
                    location = str(loc0.get("path") or "")
            msg = str(v.get("description") or v.get("summary") or vid)
            fid = fingerprint("syft", vid, location, 0, msg)
            finding = {
                "schemaVersion": "1.2.0",
                "id": fid,
                "ruleId": vid,
                "title": vid,
                "message": msg,
                "description": msg,
                "severity": sev,
                "tool": {
                    "name": "syft",
                    "version": str(data.get("artifactRelationships") and "unknown"),
                },
                "location": {"path": location, "startLine": 0},
                "remediation": str(v.get("url") or "See advisory"),
                "tags": ["sbom", "vulnerability"],
                "risk": {"cwe": ["CWE-1104"]},
                "raw": v,
            }
            out.append(finding)

    return out
