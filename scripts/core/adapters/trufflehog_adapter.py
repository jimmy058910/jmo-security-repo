#!/usr/bin/env python3
"""
TruffleHog adapter - Maps TruffleHog secrets scan JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Secret scanning with live API verification
- Git history, filesystem, and cloud scanning
- 700+ detector patterns
- Verification against live APIs (reduces false positives)

Tool Version: 3.63.0+
Output Format: NDJSON (newline-delimited JSON), also supports JSON array
Exit Codes: 0 (clean), 1 (findings), 2 (error)

Supported Scan Sources:
- git: Git repository history scanning
- github: GitHub organization/repo scanning
- gitlab: GitLab organization/repo scanning
- filesystem: Local directory scanning
- s3: AWS S3 bucket scanning
- gcs: Google Cloud Storage scanning
- circleci: CircleCI builds scanning
- docker: Docker image layer scanning

Detector Categories (700+ patterns):
- Cloud providers: AWS, GCP, Azure, DigitalOcean
- Code hosting: GitHub, GitLab, Bitbucket tokens
- Communication: Slack, Discord, Telegram tokens
- Payment: Stripe, Square, Plaid API keys
- SaaS: Sendgrid, Twilio, Datadog, etc.
- Databases: MongoDB, Redis, PostgreSQL URIs

Severity Classification:
- HIGH: Verified secrets (confirmed active via API)
- MEDIUM: Unverified secrets (pattern match only)
- CWE-798: Use of Hard-coded Credentials

Complementary to Nosey Parker:
- TruffleHog: API verification, reduces false positives
- Nosey Parker: Faster, broader patterns, no verification

Example:
    >>> adapter = TruffleHogAdapter()
    >>> findings = adapter.parse(Path('trufflehog.json'))
    >>> # Returns verified and unverified secrets as findings

See Also:
    - https://github.com/trufflesecurity/trufflehog
    - OWASP Secrets Management Cheat Sheet
"""

from __future__ import annotations

from pathlib import Path

from scripts.core.adapters.common import safe_load_ndjson_file
from scripts.core.common_finding import normalize_severity
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)


@adapter_plugin(
    PluginMetadata(
        name="trufflehog",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for TruffleHog secret scanner with verification",
        tool_name="trufflehog",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings", 2: "error"},
    )
)
class TruffleHogAdapter(AdapterPlugin):
    """TruffleHog secret scanner adapter (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse TruffleHog JSON/NDJSON output and return normalized findings.

        Args:
            output_path: Path to trufflehog.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        findings: list[Finding] = []

        for f in safe_load_ndjson_file(output_path):
            detector = str(f.get("DetectorName") or f.get("Detector") or "Unknown")
            verified = bool(f.get("Verified") or f.get("verified") or False)

            # Try to extract file path from SourceMetadata.Data.Filesystem.file or similar
            file_path = ""
            sm = f.get("SourceMetadata") or {}
            data = sm.get("Data") if isinstance(sm, dict) else {}
            if isinstance(data, dict):
                fs = data.get("Filesystem") or {}
                if isinstance(fs, dict):
                    file_path = fs.get("file") or fs.get("path") or ""
            # Some variants include Filename / Raw etc.
            file_path = file_path or f.get("Filename") or f.get("Path") or ""

            start_line = None
            if isinstance(f.get("StartLine"), int):
                start_line = f["StartLine"]
            elif isinstance(f.get("Line"), int):
                start_line = f["Line"]

            msg = f.get("Raw") or f.get("Redacted") or detector
            sev = "HIGH" if verified else "MEDIUM"
            severity = normalize_severity(sev)
            rule_id = detector

            # Create Finding object
            finding = Finding(
                schemaVersion="1.2.0",
                id="",  # Will be set by fingerprint
                ruleId=rule_id,
                title=f"{detector} secret",
                message=msg if isinstance(msg, str) else str(msg),
                description="Potential secret detected by TruffleHog",
                severity=severity,
                tool={
                    "name": "trufflehog",
                    "version": str(f.get("Version") or "unknown"),
                },
                location={"path": file_path, "startLine": start_line or 0},
                remediation="Rotate credentials and purge from history.",
                tags=["secrets", "verified" if verified else "unverified"],
                risk={
                    "cwe": ["CWE-798"],  # Use of Hard-coded Credentials
                    "confidence": "HIGH" if verified else "MEDIUM",
                    "likelihood": "HIGH",
                    "impact": "HIGH",
                },
                raw=f,
            )

            # Generate fingerprint
            finding.id = self.get_fingerprint(finding)

            findings.append(finding)

        return findings
