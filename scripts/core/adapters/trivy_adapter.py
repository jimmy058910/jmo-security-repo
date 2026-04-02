#!/usr/bin/env python3
"""
Trivy adapter - Maps Aqua Trivy vulnerability scanner JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Comprehensive vulnerability scanner
- Container images, filesystems, git repos, IaC
- Multi-source vulnerability data (NVD, GHSA, etc.)
- OS and language package detection

Tool Version: 0.50.0+
Output Format: JSON with Results array
Exit Codes: 0 (clean), 1 (findings), 2 (error)

Scan Modes:
- trivy image: Container image scanning
- trivy fs: Filesystem scanning
- trivy repo: Git repository scanning
- trivy config: IaC misconfiguration scanning
- trivy sbom: SBOM scanning

Finding Types:
- Vulnerabilities: CVEs in packages (OS + language)
- Secrets: Hardcoded credentials and API keys
- Misconfigurations: IaC and config issues (Dockerfile, K8s, Terraform)
- Licenses: License compliance (optional)

Supported Package Ecosystems:
- OS: Alpine, Debian, Ubuntu, RHEL, CentOS, Amazon Linux
- Languages: npm, pip, Go, Ruby, Rust, NuGet, Java (JAR/WAR)

Severity Mapping (Trivy -> CommonFinding):
- CRITICAL: CRITICAL
- HIGH: HIGH
- MEDIUM: MEDIUM
- LOW: LOW
- UNKNOWN: INFO

Integration Notes:
- Syft SBOM can feed into Trivy for vulnerability scanning
- Grype is an alternative with similar capabilities
- trivy_rbac_adapter.py handles RBAC-specific findings

Example:
    >>> adapter = TrivyAdapter()
    >>> findings = adapter.parse(Path('trivy.json'))
    >>> # Returns vulnerabilities, secrets, and misconfigs

See Also:
    - https://trivy.dev/
    - https://github.com/aquasecurity/trivy
    - trivy_rbac_adapter.py for Kubernetes RBAC
"""

from __future__ import annotations

from pathlib import Path

from scripts.core.adapters.common import safe_load_json_file
from scripts.core.common_finding import (
    extract_code_snippet,
    normalize_severity,
)
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
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]  # Dynamically attached by @adapter_plugin decorator

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse Trivy JSON output and return normalized findings.

        Args:
            output_path: Path to trivy.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        data = safe_load_json_file(output_path, default=None)
        if not isinstance(data, dict):
            return []

        results = data.get("Results")
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

                    findings.append(finding)

        return findings
