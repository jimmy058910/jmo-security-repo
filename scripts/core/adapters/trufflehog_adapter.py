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

# Lob test-mode API keys are `test_` followed by 35 hex-ish characters.
# TruffleHog's detector for them accepts underscores in that run, and pytest
# names every test function `test_<words_with_underscores>` - so the two
# collide by construction, and any Python project whose test names happen to be
# 35 characters long produces Lob "secrets".
#
# They come back **Verified: true**, because Lob's API accepts test-mode keys,
# so nothing downstream can tell them apart: the adapter graded them HIGH and
# `zero-secrets.rego` ("blocks all verified secrets") failed the build. That was
# #724, and it reached users as well as CI - `jmo scan` runs the same detector.
#
# The separator is the underscore. A real key has none; a Python identifier
# always does. Measured over this repository's `tests/` tree: 2318 Lob findings,
# 412 distinct, **412/412 containing an underscore and 0/412 matching
# `[0-9a-f]{35}`**. Filtering on it costs no real detection.
LOB_KEY_PREFIX = "test_"


def _is_pytest_name_matched_as_lob_key(detector: str, secret: object) -> bool:
    """True when a Lob "secret" is really a pytest function name.

    Deliberately narrow: only the Lob detector, only a `test_` prefix, and only
    when the remainder contains an underscore. Anything else - including a
    genuine Lob key, and every other detector - is left alone.
    """
    if detector != "Lob" or not isinstance(secret, str):
        return False
    if not secret.startswith(LOB_KEY_PREFIX):
        return False
    return "_" in secret[len(LOB_KEY_PREFIX) :]


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
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]  # Dynamically attached by @adapter_plugin decorator

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

            secret = f.get("Raw")
            if _is_pytest_name_matched_as_lob_key(detector, secret):
                continue

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
