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

Field mapping (measured on trivy 0.74.0's own JSON, #1221):
- ruleId: VulnerabilityID -> ID -> RuleID -> Title -> the finding class.
  0.74.0 names a misconfiguration's rule in ``ID`` (``DS-0001``,
  ``KSV-0017``, ``AWS-0086``) and a secret's in ``RuleID`` (``github-pat``);
  ranking ``Title`` above them made every misconfiguration and secret carry
  its title as its id.
- title: ``Title`` when trivy writes one, else the ruleId.
- startLine/endLine: ``CauseMetadata.StartLine``/``EndLine``, else the
  top-level ``StartLine``/``EndLine`` (secrets; older trivy). 0.74.0 writes a
  misconfiguration's lines only in ``CauseMetadata``, so reading the top level
  alone put every one at line 0, and two findings of one check in one file
  shared an id: juice-shop's 87 became 47.
- tool.version: ``Trivy.Version``, else the top-level ``Version`` (older
  trivy), else ``unknown``.
- A ``Target`` is relative to the directory trivy scanned, so code context is
  read under it rather than under the working directory. That directory is
  ``ArtifactName`` for ``trivy fs <dir>``; for ``trivy config <file>`` (``jmo
  scan --iac <file>``) ``ArtifactName`` is the file and ``Target`` its name,
  so it is the file's directory.
- cvss (vulnerabilities only, #1243): a vulnerability's ``CVSS`` is keyed by
  source (``nvd``, ``ghsa``, ``redhat``, ...), each holding up to
  ``V3Score``/``V3Vector`` and ``V2Score``/``V2Vector``. NVD's V3 score wins;
  else any other source's V3; else NVD's V2; else any other source's V2 -- v3
  always outranks v2 (schema: "Adapters select v3 over v2"), NVD is preferred
  within a version. Omitted (not even an empty ``cvss``) when the block is
  absent or empty, or holds no numeric score under either key.
- risk: a vulnerability's ``CweIDs``; a secret's CWE-798, in the dict
  gitleaks and trufflehog write (trivy's secret records carry no CWE); none
  for a misconfiguration.

Severity Mapping (Trivy -> CommonFinding):
- CRITICAL: CRITICAL
- HIGH: HIGH
- MEDIUM: MEDIUM
- LOW: LOW
- UNKNOWN: INFO

Integration Notes:
- Syft SBOM can feed into Trivy for vulnerability scanning
- Grype is an alternative with similar capabilities

Example:
    >>> adapter = TrivyAdapter()
    >>> findings = adapter.parse(Path('trivy.json'))
    >>> # Returns vulnerabilities, secrets, and misconfigs

See Also:
    - https://trivy.dev/
    - https://github.com/aquasecurity/trivy
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

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


def _line(value: Any) -> int | None:
    """A 1-based line number, or None (``bool`` is an ``int`` in Python)."""
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _lines(item: dict[str, Any]) -> tuple[int, int | None]:
    """(startLine, endLine) from ``CauseMetadata`` first, then the top level.

    Both come from the same place, so an end line is never paired with
    another source's start.
    """
    cause = item.get("CauseMetadata")
    for source in (cause if isinstance(cause, dict) else {}, item):
        start = _line(source.get("StartLine"))
        if start is not None:
            return start, _line(source.get("EndLine"))
    return 0, None


def _scanned_root(artifact_name: Any) -> Path | None:
    """The directory a ``Target`` is relative to, from ``ArtifactName``.

    ``trivy fs <dir>`` writes the directory; ``trivy config <file>`` (``jmo
    scan --iac <file>``) writes the file itself, with ``Target`` its name, so
    the root is the file's directory. Measured on 0.74.0.
    """
    if not isinstance(artifact_name, str) or not artifact_name:
        return None
    root = Path(artifact_name)
    try:
        return root.parent if root.is_file() else root
    except OSError:
        return root


def _best_vulnerability_cvss(cvss_block: Any) -> dict[str, Any] | None:
    """Best CVSS for a trivy vulnerability, or ``None``.

    ``cvss_block`` is trivy's per-vulnerability ``CVSS`` object, keyed by
    source (``nvd``, ``ghsa``, ``redhat``, ...). NVD's V3 score wins; then
    any other source's V3; then NVD's V2; then any other source's V2 -- v3
    always outranks v2 regardless of source, and NVD is the tiebreak within
    one version. Among the other sources the first in trivy's JSON wins, which
    is alphabetical: trivy's ``CVSS`` block is a Go map, and ``encoding/json``
    sorts map keys. Matches ``grype_adapter._select_best_cvss``'s v3-over-v2
    shape, adapted for trivy's by-source keying.
    """
    if not isinstance(cvss_block, dict) or not cvss_block:
        return None

    nvd = cvss_block.get("nvd")
    nvd = nvd if isinstance(nvd, dict) else None
    others = [v for k, v in cvss_block.items() if k != "nvd" and isinstance(v, dict)]
    sources = ([nvd] if nvd is not None else []) + others

    for version, score_key, vector_key in (
        ("3.x", "V3Score", "V3Vector"),
        ("2.0", "V2Score", "V2Vector"),
    ):
        for source in sources:
            score = source.get(score_key)
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                return {
                    "version": version,
                    "score": float(score),
                    "vector": str(source.get(vector_key) or ""),
                }
    return None


def _tool_version(data: dict[str, Any]) -> str:
    """``Trivy.Version`` (0.74.0), else the top-level ``Version`` (older)."""
    meta = data.get("Trivy")
    version = meta.get("Version") if isinstance(meta, dict) else None
    return str(version or data.get("Version") or "unknown")


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
        tool_version = _tool_version(data)
        scanned_root = _scanned_root(data.get("ArtifactName"))

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
                        or item.get("ID")
                        or item.get("RuleID")
                        or item.get("Title")
                        or tag
                    )
                    msg = item.get("Title") or item.get("Description") or tag
                    severity = normalize_severity(item.get("Severity"))
                    path_str = item.get("Target") or target or ""
                    line, end_line = _lines(item)

                    # Code context (for misconfigurations), read under the
                    # scanned root: jmo runs trivy from another directory.
                    context = None
                    if tag == "misconfig" and path_str and line:
                        source = (
                            scanned_root / str(path_str)
                            if scanned_root is not None
                            else Path(str(path_str))
                        )
                        context = extract_code_snippet(
                            str(source), line, context_lines=2
                        )

                    location: dict[str, Any] = {
                        "path": str(path_str),
                        "startLine": line,
                    }
                    if end_line is not None:
                        location["endLine"] = end_line

                    # Risk metadata and CVSS for vulnerabilities
                    risk: dict[str, Any] | None = None
                    cvss_field = None
                    if tag == "vulnerability":
                        cwe_ids = item.get("CweIDs", [])
                        if cwe_ids and isinstance(cwe_ids, list):
                            risk = {"cwe": cwe_ids}
                        cvss_field = _best_vulnerability_cvss(item.get("CVSS"))
                    elif tag == "secret":
                        # trivy writes no CWE on a secret, and compliance
                        # enrichment reads `risk.cwe` only. A trivy secret shares
                        # gitleaks' ruleId (`github-pat`), so the two cluster,
                        # and trivy's CRITICAL leads: the consensus copied an
                        # empty risk and the secret left `owasp-top-10`. The
                        # gitleaks and (unverified) trufflehog dict: CWE-798.
                        risk = {
                            "cwe": ["CWE-798"],
                            "confidence": "MEDIUM",
                            "likelihood": "HIGH",
                            "impact": "HIGH",
                        }

                    # Create Finding object
                    finding = Finding(
                        schemaVersion="1.2.0",
                        id="",  # Will be set by fingerprint
                        ruleId=str(rule_id),
                        title=str(item.get("Title") or rule_id),
                        message=str(msg),
                        description=str(item.get("Description") or msg),
                        severity=severity,
                        tool={"name": "trivy", "version": tool_version},
                        location=location,
                        remediation=str(item.get("PrimaryURL") or "See advisory"),
                        tags=[tag],
                        context=context,
                        risk=risk,
                        cvss=cvss_field,
                        raw=item,
                    )

                    # Generate fingerprint
                    finding.id = self.get_fingerprint(finding)

                    findings.append(finding)

        return findings
