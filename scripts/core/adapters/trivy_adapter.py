#!/usr/bin/env python3
"""
Trivy adapter: normalize Trivy JSON to CommonFinding
Supports filesystem scan output (trivy fs -f json .) and generic Results array.

REFACTORED: v0.9.0 - Now uses plugin architecture
"""

from __future__ import annotations
import json
from pathlib import Path

from scripts.core.common_finding import (
    extract_code_snippet,
    normalize_severity,
)
from scripts.core.compliance_mapper import enrich_finding_with_compliance
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)


@adapter_plugin(
    PluginMetadata(
        name="trivy",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Aqua Security Trivy vulnerability scanner",
        tool_name="trivy",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings", 2: "error"},
    )
)
class TrivyAdapter(AdapterPlugin):
    """Trivy vulnerability scanner adapter (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse Trivy JSON output and return normalized findings.

        Args:
            output_path: Path to trivy.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        if not output_path.exists():
            return []

        raw = output_path.read_text(encoding="utf-8", errors="ignore").strip()
        if not raw:
            return []

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        results = data.get("Results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            return []

        findings: list[Finding] = []
        tool_version = str(data.get("Version") or "unknown")

        for r in results:
            target = r.get("Target") or ""
            vulns = r.get("Vulnerabilities")
            secrets = r.get("Secrets")
            misconfigs = r.get("Misconfigurations")

            for arr, tag in (
                (vulns, "vulnerability"),
                (secrets, "secret"),
                (misconfigs, "misconfig"),
            ):
                if not isinstance(arr, list):
                    continue

                for item in arr:
                    rule_id = (
                        item.get("VulnerabilityID")
                        or item.get("Title")
                        or item.get("RuleID")
                        or tag
                    )
                    msg = item.get("Title") or item.get("Description") or tag
                    severity = normalize_severity(item.get("Severity"))
                    path_str = item.get("Target") or target or ""
                    line = item.get("StartLine") or 0

                    # Code context (for misconfigurations)
                    context = None
                    if tag == "misconfig" and path_str and line:
                        context = extract_code_snippet(
                            str(path_str), int(line), context_lines=2
                        )

                    # Risk metadata for vulnerabilities
                    risk = None
                    if tag == "vulnerability":
                        cwe_ids = item.get("CweIDs", [])
                        if cwe_ids and isinstance(cwe_ids, list):
                            risk = {"cwe": cwe_ids}

                    # Create Finding object
                    finding = Finding(
                        schemaVersion="1.2.0",
                        id="",  # Will be set by fingerprint
                        ruleId=str(rule_id),
                        title=str(rule_id),
                        message=str(msg),
                        description=str(item.get("Description") or msg),
                        severity=severity,
                        tool={"name": "trivy", "version": tool_version},
                        location={
                            "path": str(path_str),
                            "startLine": int(line) if isinstance(line, int) else 0,
                        },
                        remediation=str(item.get("PrimaryURL") or "See advisory"),
                        tags=[tag],
                        context=context,
                        risk=risk,
                        raw=item,
                    )

                    # Generate fingerprint
                    finding.id = self.get_fingerprint(finding)

                    # Enrich with compliance (converts to dict, enriches, then back)
                    finding_dict = vars(finding)
                    finding_dict = enrich_finding_with_compliance(finding_dict)
                    finding.compliance = finding_dict.get("compliance")

                    findings.append(finding)

        return findings
