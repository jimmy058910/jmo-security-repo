#!/usr/bin/env python3
"""
cdxgen adapter - Maps cdxgen CycloneDX SBOM JSON output to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- CycloneDX SBOM generator (spec v1.4-1.6)
- Tracks components, licenses, dependencies
- Supports: npm, Python, Java, Go, Rust, C/C++, containers, and 20+ ecosystems
- SBOM types: Software (SBOM), Cryptography (CBOM), Operations (OBOM), SaaS (SaaSBOM)

Tool Version: 11.10.0+
Output Format: JSON (CycloneDX spec v1.4-1.6)
Exit Codes: 0 (success), 1+ (errors)

Supported Ecosystems:
- Node.js, Python, Java, Maven, Gradle, Go, Rust, Ruby, PHP, .NET, C/C++, containers
- 20+ package managers and ecosystems
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint
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
        name="cdxgen",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for cdxgen CycloneDX SBOM generator",
        tool_name="cdxgen",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "success", 1: "error"},
    )
)
class CdxgenAdapter(AdapterPlugin):
    """Adapter for cdxgen CycloneDX SBOM generator (plugin architecture).

    v1.0.0 Features:
    - Generates CycloneDX SBOM (spec v1.4-1.6)
    - Tracks components, licenses, dependencies
    - Supports 20+ ecosystems and package managers
    - SBOM inventory for compliance and supply chain security

    Findings represent SBOM components (not vulnerabilities).
    Tagged as 'sbom' and 'inventory'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to cdxgen.json output file (CycloneDX SBOM)

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_cdxgen_internal(output_path)

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


def _load_cdxgen_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Internal function to parse cdxgen CycloneDX SBOM JSON output.

    Args:
        path: Path to cdxgen.json output file

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
        logger.warning(f"Failed to parse cdxgen JSON: {path}")
        return []

    out: List[Dict[str, Any]] = []

    # CycloneDX SBOM structure: {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [...]}
    if not isinstance(data, dict):
        return []

    # Validate BOM format
    bom_format = data.get("bomFormat")
    if bom_format != "CycloneDX":
        logger.warning(f"Invalid BOM format: {bom_format}")
        return []

    # Extract spec version
    spec_version = data.get("specVersion", "unknown")

    # Extract components array
    components = data.get("components", [])
    if not isinstance(components, list):
        return []

    for comp in components:
        if not isinstance(comp, dict):
            continue

        # Extract component metadata
        comp_name = str(comp.get("name", "unknown"))
        comp_version = str(comp.get("version", "unknown"))
        comp_type = str(comp.get("type", "library"))  # library, application, framework, etc.
        purl = str(comp.get("purl", ""))  # Package URL
        bom_ref = str(comp.get("bom-ref", ""))

        # Extract licenses
        licenses = []
        licenses_data = comp.get("licenses", [])
        if isinstance(licenses_data, list):
            for lic in licenses_data:
                if isinstance(lic, dict):
                    if "license" in lic:
                        lic_obj = lic["license"]
                        if isinstance(lic_obj, dict):
                            lic_id = lic_obj.get("id") or lic_obj.get("name")
                            if lic_id:
                                licenses.append(str(lic_id))

        # Extract hashes
        hashes = {}
        hashes_data = comp.get("hashes", [])
        if isinstance(hashes_data, list):
            for h in hashes_data:
                if isinstance(h, dict):
                    alg = str(h.get("alg", ""))
                    content = str(h.get("content", ""))
                    if alg and content:
                        hashes[alg] = content

        # Extract supplier/manufacturer
        supplier = ""
        if isinstance(comp.get("supplier"), dict):
            supplier = str(comp["supplier"].get("name", ""))
        elif isinstance(comp.get("manufacturer"), dict):
            supplier = str(comp["manufacturer"].get("name", ""))

        # Build message
        message = f"Component: {comp_name}@{comp_version}"
        if licenses:
            message += f" (Licenses: {', '.join(licenses)})"

        # Generate stable fingerprint
        # Use purl if available, otherwise name@version
        component_id = purl if purl else f"{comp_name}@{comp_version}"
        fid = fingerprint("cdxgen", "SBOM.COMPONENT", component_id, 0, message)

        # Build finding dict
        finding = {
            "schemaVersion": "1.2.0",
            "id": fid,
            "ruleId": "SBOM.COMPONENT",
            "title": comp_name,
            "message": message,
            "description": f"SBOM component {comp_name}@{comp_version} of type {comp_type}",
            "severity": "INFO",  # SBOM components are informational
            "tool": {
                "name": "cdxgen",
                "version": "11.10.0",  # cdxgen v11.10.0+
            },
            "location": {
                "path": str(path),
                "startLine": 0,  # SBOM JSON doesn't have line numbers
            },
            "remediation": None,  # SBOM is inventory, not issues
            "references": [purl] if purl else [],
            "tags": ["sbom", "inventory", comp_type.lower()],
            "context": {
                "component_name": comp_name,
                "component_version": comp_version,
                "component_type": comp_type,
                "purl": purl if purl else None,
                "bom_ref": bom_ref if bom_ref else None,
                "licenses": licenses,
                "hashes": hashes if hashes else None,
                "supplier": supplier if supplier else None,
                "spec_version": spec_version,
            },
            "raw": comp,
        }

        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)

    return out
