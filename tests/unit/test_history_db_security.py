#!/usr/bin/env python3
"""
Unit tests for history_db.py security features (Phase 6 Step 6.1).

Tests cover:
- Secret redaction for trufflehog findings
- Non-secret tools unchanged
- --no-store-raw-findings flag behavior
"""

from __future__ import annotations

import json

from scripts.core.history_db import redact_secrets


class TestSecretRedaction:
    """Test secret redaction in findings before database storage."""

    def test_redact_secrets_trufflehog(self):
        """Test that trufflehog secrets are redacted in raw_finding."""
        # Arrange: Create a trufflehog finding with secret data
        finding = {
            "schemaVersion": "1.2.0",
            "id": "trufflehog|github|file.py|1|abc123",
            "tool": {"name": "trufflehog", "version": "3.63.0"},
            "ruleId": "github",
            "severity": "CRITICAL",
            "message": "GitHub Personal Access Token detected",
            "location": {"path": "file.py", "startLine": 1},
            "raw": {
                "SourceMetadata": {"Data": {"Github": {"link": "https://github.com"}}},
                "SourceID": 1,
                "SourceName": "trufflehog",
                "DetectorName": "github",
                "Verified": True,
                "Raw": "ghp_1234567890abcdef",  # ← SECRET VALUE
                "RawV2": "secret_value_here",  # ← SECRET VALUE
                "Redacted": "ghp_1234567890ab***",
            },
        }

        # Act: Redact secrets
        redacted = redact_secrets(finding, store_raw=True)

        # Assert: Secret values are replaced with [REDACTED]
        raw_data = json.loads(redacted["raw_finding"])
        assert raw_data["Raw"] == "[REDACTED]"
        assert raw_data["RawV2"] == "[REDACTED]"
        assert (
            raw_data["Redacted"] == "ghp_1234567890ab***"
        )  # Already redacted, unchanged
        assert raw_data["DetectorName"] == "github"  # Non-secret field unchanged
        assert raw_data["Verified"] is True  # Non-secret field unchanged

    def test_redact_secrets_non_secret_tool_unchanged(self):
        """Test that non-secret tools (trivy, semgrep) are unchanged."""
        # Arrange: Create a trivy vulnerability finding (not a secret)
        finding = {
            "schemaVersion": "1.2.0",
            "id": "trivy|CVE-2024-1234|package.json|0|xyz123",
            "tool": {"name": "trivy", "version": "0.68.0"},
            "ruleId": "CVE-2024-1234",
            "severity": "HIGH",
            "message": "Vulnerability in lodash package",
            "location": {"path": "package.json", "startLine": 0},
            "raw": {
                "VulnerabilityID": "CVE-2024-1234",
                "PkgName": "lodash",
                "InstalledVersion": "4.17.19",
                "FixedVersion": "4.17.21",
                "Severity": "HIGH",
                "Title": "Prototype pollution vulnerability",
                "Description": "Lodash versions before 4.17.21 are vulnerable...",
                "References": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
            },
        }

        # Act: Redact secrets (should do nothing for non-secret tools)
        redacted = redact_secrets(finding, store_raw=True)

        # Assert: Finding is unchanged (no redaction for non-secret tools)
        raw_data = json.loads(redacted["raw_finding"])
        assert raw_data == finding["raw"]  # Exact match, no changes
        assert raw_data["VulnerabilityID"] == "CVE-2024-1234"
        assert (
            raw_data["Description"]
            == "Lodash versions before 4.17.21 are vulnerable..."
        )

    def test_no_store_raw_findings_flag(self):
        """Test that --no-store-raw-findings returns None for raw_finding."""
        # Arrange: Create any finding (trufflehog with secrets)
        finding = {
            "schemaVersion": "1.2.0",
            "id": "trufflehog|aws|file.py|1|abc123",
            "tool": {"name": "trufflehog", "version": "3.63.0"},
            "ruleId": "aws",
            "severity": "CRITICAL",
            "message": "AWS credentials detected",
            "location": {"path": "file.py", "startLine": 1},
            "raw": {
                "DetectorName": "aws",
                "Raw": "AKIAIOSFODNN7EXAMPLE",  # Secret value
                "Verified": True,
            },
        }

        # Act: Call with store_raw=False
        redacted = redact_secrets(finding, store_raw=False)

        # Assert: raw_finding is None (not stored at all)
        assert redacted["raw_finding"] is None

    def test_redact_secrets_handles_missing_raw_field(self):
        """Test that redaction handles findings with no 'raw' field gracefully."""
        # Arrange: Create finding without 'raw' field
        finding = {
            "schemaVersion": "1.2.0",
            "id": "trufflehog|github|file.py|1|abc123",
            "tool": {"name": "trufflehog", "version": "3.63.0"},
            "ruleId": "github",
            "severity": "CRITICAL",
            "message": "GitHub token detected",
            "location": {"path": "file.py", "startLine": 1},
            # No 'raw' field
        }

        # Act: Redact secrets
        redacted = redact_secrets(finding, store_raw=True)

        # Assert: Returns empty dict or minimal structure
        assert redacted["raw_finding"] == "{}"  # Empty JSON object

    def test_redact_secrets_handles_nested_structures(self):
        """Test that redaction handles deeply nested secret structures."""
        # Arrange: Create finding with nested secret data
        finding = {
            "schemaVersion": "1.2.0",
            "id": "trufflehog|nested|file.py|1|abc123",
            "tool": {"name": "trufflehog", "version": "3.63.0"},
            "ruleId": "nested",
            "severity": "HIGH",
            "message": "Nested secret detected",
            "location": {"path": "file.py", "startLine": 1},
            "raw": {
                "level1": {
                    "level2": {
                        "level3": {
                            "Raw": "secret_value_deep",  # ← DEEPLY NESTED SECRET
                            "RawV2": "another_secret",  # ← DEEPLY NESTED SECRET
                        }
                    }
                },
                "DetectorName": "nested",
            },
        }

        # Act: Redact secrets
        redacted = redact_secrets(finding, store_raw=True)

        # Assert: Deeply nested secrets are redacted
        raw_data = json.loads(redacted["raw_finding"])
        assert raw_data["level1"]["level2"]["level3"]["Raw"] == "[REDACTED]"
        assert raw_data["level1"]["level2"]["level3"]["RawV2"] == "[REDACTED]"
        assert raw_data["DetectorName"] == "nested"  # Non-secret unchanged

    def test_redact_secrets_preserves_finding_structure(self):
        """Test that redaction preserves all non-raw fields in finding."""
        # Arrange: Create complete finding with all fields
        finding = {
            "schemaVersion": "1.2.0",
            "id": "trufflehog|github|file.py|1|abc123",
            "tool": {"name": "trufflehog", "version": "3.63.0"},
            "ruleId": "github",
            "severity": "CRITICAL",
            "title": "GitHub Token",
            "message": "GitHub Personal Access Token detected",
            "location": {"path": "file.py", "startLine": 1, "endLine": 1},
            "remediation": "Rotate the token immediately",
            "references": ["https://docs.github.com/en/authentication"],
            "tags": ["secret", "github"],
            "cvss": {
                "score": 9.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            "risk": {"confidence": "HIGH", "likelihood": "HIGH", "impact": "HIGH"},
            "raw": {"Raw": "ghp_secret", "DetectorName": "github"},
        }

        # Act: Redact secrets
        redacted = redact_secrets(finding, store_raw=True)

        # Assert: All non-raw fields preserved exactly
        assert redacted["id"] == finding["id"]
        assert redacted["tool"] == finding["tool"]
        assert redacted["severity"] == finding["severity"]
        assert redacted["title"] == finding["title"]
        assert redacted["message"] == finding["message"]
        assert redacted["location"] == finding["location"]
        assert redacted["remediation"] == finding["remediation"]
        assert redacted["cvss"] == finding["cvss"]
        assert redacted["risk"] == finding["risk"]
        # Only raw_finding should be modified
        raw_data = json.loads(redacted["raw_finding"])
        assert raw_data["Raw"] == "[REDACTED]"
