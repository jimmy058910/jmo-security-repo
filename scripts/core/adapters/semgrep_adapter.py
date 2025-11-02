#!/usr/bin/env python3
"""
Semgrep adapter: normalize Semgrep JSON to CommonFinding
Expected input shape often contains {"results": [ ... ]}

REFACTORED: v0.9.0 - Now uses plugin architecture
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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


SEMGREP_TO_SEV = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


@adapter_plugin(
    PluginMetadata(
        name="semgrep",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Semgrep multi-language SAST scanner",
        tool_name="semgrep",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings", 2: "error"},
    )
)
class SemgrepAdapter(AdapterPlugin):
    """Semgrep SAST scanner adapter (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse Semgrep JSON output and return normalized findings.

        Args:
            output_path: Path to semgrep.json output file

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

        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            return []

        findings: list[Finding] = []
        tool_version = str(
            (data.get("version") if isinstance(data, dict) else None) or "unknown"
        )

        for r in results:
            if not isinstance(r, dict):
                continue

            # Extract rule ID
            check_id = str(
                r.get("check_id") or r.get("ruleId") or r.get("id") or "SEMGR"
            )

            # Extract message
            msg = (
                (r.get("extra") or {}).get("message")
                or r.get("message")
                or "Semgrep finding"
            )

            # Extract and normalize severity
            sev_raw = (r.get("extra") or {}).get("severity") or r.get("severity")
            sev_norm = SEMGREP_TO_SEV.get(str(sev_raw).upper(), None)
            severity = normalize_severity(sev_norm or str(sev_raw))

            # Extract path
            path_str = r.get("path") or (r.get("location") or {}).get("path") or ""

            # Extract line number (multiple fallbacks)
            start_line = 0
            if isinstance(r.get("start"), dict) and isinstance(
                r["start"].get("line"), int
            ):
                start_line = r["start"]["line"]
            else:
                line_val = (r.get("start") or {}).get("line")
                if isinstance(line_val, int):
                    start_line = line_val

            # Alternative location structure
            loc = r.get("location")
            if (
                isinstance(loc, dict)
                and isinstance(loc.get("start"), dict)
                and isinstance(loc["start"].get("line"), int)
            ):
                start_line = loc["start"]["line"]

            # Extract v1.1.0 fields
            extra = r.get("extra", {})

            # Remediation with autofix
            # v1.1.0: Return dict for autofix, string otherwise
            remediation: str | dict[str, Any] = (
                "Review and remediate per rule guidance."
            )
            autofix = extra.get("fix")
            if autofix:
                remediation_steps = [
                    "Apply the suggested fix above",
                    "Test the changes",
                    "Commit the fix",
                ]
                remediation = {
                    "fix": autofix,
                    "steps": remediation_steps,
                }

            # Risk metadata (CWE, OWASP, confidence)
            risk = {}
            metadata = extra.get("metadata", {})
            if metadata:
                # CWE
                cwe_list = metadata.get("cwe", [])
                if isinstance(cwe_list, list) and cwe_list:
                    risk["cwe"] = cwe_list
                elif isinstance(cwe_list, str):
                    risk["cwe"] = [cwe_list]

                # OWASP
                owasp = metadata.get("owasp", [])
                if isinstance(owasp, list) and owasp:
                    risk["owasp"] = owasp
                elif isinstance(owasp, str):
                    risk["owasp"] = [owasp]

                # Confidence
                confidence = metadata.get("confidence", "").upper()
                if confidence in ["HIGH", "MEDIUM", "LOW"]:
                    risk["confidence"] = confidence

                # Likelihood/Impact
                likelihood = metadata.get("likelihood", "").upper()
                if likelihood in ["HIGH", "MEDIUM", "LOW"]:
                    risk["likelihood"] = likelihood
                impact = metadata.get("impact", "").upper()
                if impact in ["HIGH", "MEDIUM", "LOW"]:
                    risk["impact"] = impact

            # Code context
            context = None
            if path_str and start_line:
                context = extract_code_snippet(path_str, start_line, context_lines=2)

            # Create Finding object
            finding = Finding(
                schemaVersion="1.2.0",
                id="",  # Will be set by fingerprint
                ruleId=check_id,
                title=check_id,
                message=msg,
                description=msg,
                severity=severity,
                tool={"name": "semgrep", "version": tool_version},
                location={"path": path_str, "startLine": start_line},
                remediation=remediation,
                tags=["sast"],
                context=context,
                risk=risk if risk else None,
                raw=r,
            )

            # Generate fingerprint
            finding.id = self.get_fingerprint(finding)

            # Enrich with compliance
            finding_dict = vars(finding)
            finding_dict = enrich_finding_with_compliance(finding_dict)
            finding.compliance = finding_dict.get("compliance")

            findings.append(finding)

        return findings
