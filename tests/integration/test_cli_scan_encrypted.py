#!/usr/bin/env python3
"""
Integration tests for --encrypt-findings CLI flag (Phase 6 Step 6.2).

Tests that the flag enables encryption of raw finding data in history database.
"""

from __future__ import annotations

import json
import os

import pytest

from scripts.core.history_db import get_connection, store_scan, decrypt_raw_finding


class TestEncryptFindingsFlag:
    """Test --encrypt-findings flag behavior in full workflow."""

    def test_scan_encrypt_findings_flag(self, tmp_path):
        """
        Test that --encrypt-findings flag encrypts raw_finding data.

        Workflow:
        1. Set JMO_ENCRYPTION_KEY environment variable
        2. Create findings.json with sensitive data
        3. Store scan with encrypt_findings=True
        4. Query database and verify raw_finding is encrypted (not plaintext)
        5. Decrypt and verify original data
        """
        # Arrange: Set encryption key
        encryption_key = "test-encryption-key-32-chars!!"
        os.environ["JMO_ENCRYPTION_KEY"] = encryption_key

        # Create test results directory with findings.json
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {
            "meta": {
                "output_version": "1.0.0",
                "jmo_version": "0.9.0",
                "schema_version": "1.2.0",
                "timestamp": "2025-11-04T12:00:00Z",
                "scan_id": "test-enc-1",
                "profile": "fast",
                "tools": ["trufflehog"],
                "target_count": 1,
                "finding_count": 1,
                "platform": "Linux",
            },
            "findings": [
                {
                    "schemaVersion": "1.2.0",
                    "id": "trufflehog|github|file.py|1|abc123",
                    "tool": {"name": "trufflehog", "version": "3.63.0"},
                    "ruleId": "github",
                    "severity": "CRITICAL",
                    "message": "GitHub Personal Access Token detected",
                    "location": {"path": "file.py", "startLine": 1},
                    "raw": {
                        "DetectorName": "github",
                        "Raw": "ghp_1234567890abcdef",  # SECRET VALUE
                        "Verified": True,
                    },
                },
            ]
        }

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        # Create individual-repos directory
        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        # Database path
        db_path = tmp_path / "test_history.db"

        # Act: Store scan with encrypt_findings=True
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trufflehog"],
            db_path=db_path,
            encrypt_findings=True,  # ← FLAG UNDER TEST
        )

        # Assert: Verify scan was stored
        assert scan_id is not None
        assert db_path.exists()

        # Assert: Query database and verify raw_finding is encrypted
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT raw_finding FROM findings WHERE scan_id = ? AND tool = ?",
            (scan_id, "trufflehog"),
        )
        row = cursor.fetchone()

        assert row is not None
        encrypted_raw = row[0]
        assert encrypted_raw is not None

        # Verify raw_finding is NOT plaintext JSON
        assert "ghp_1234567890abcdef" not in encrypted_raw  # Secret not in plaintext
        assert "DetectorName" not in encrypted_raw  # Field names not visible
        assert encrypted_raw.startswith("gAAAAA")  # Fernet encrypted data signature

        # Verify we can decrypt it back to original
        decrypted_json = decrypt_raw_finding(encrypted_raw)
        decrypted_data = json.loads(decrypted_json)
        assert decrypted_data["DetectorName"] == "github"
        assert decrypted_data["Raw"] == "[REDACTED]"  # Redaction still applied

        conn.close()

        # Cleanup
        del os.environ["JMO_ENCRYPTION_KEY"]

    def test_scan_without_encryption_key_fails(self, tmp_path):
        """
        Test that encryption fails if JMO_ENCRYPTION_KEY not set.

        Security requirement: Must not silently fall back to unencrypted storage.
        """
        # Arrange: Ensure key is NOT set
        if "JMO_ENCRYPTION_KEY" in os.environ:
            del os.environ["JMO_ENCRYPTION_KEY"]

        # Create test results
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {
            "meta": {
                "output_version": "1.0.0",
                "jmo_version": "0.9.0",
                "schema_version": "1.2.0",
                "timestamp": "2025-11-04T12:00:00Z",
                "scan_id": "test-enc-2",
                "profile": "fast",
                "tools": [],
                "target_count": 1,
                "finding_count": 0,
                "platform": "Linux",
            },
            "findings": []
        }
        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        db_path = tmp_path / "test_history.db"

        # Act & Assert: Should raise ValueError about missing key
        with pytest.raises(
            ValueError, match="JMO_ENCRYPTION_KEY environment variable not set"
        ):
            store_scan(
                results_dir=results_dir,
                profile="fast",
                tools=["trivy"],
                db_path=db_path,
                encrypt_findings=True,  # Requires key
            )

    def test_scan_default_no_encryption(self, tmp_path):
        """
        Test that by default (encrypt_findings=False), raw findings are NOT encrypted.

        Ensures backward compatibility - default behavior unchanged.
        """
        # Arrange: Create test results directory with findings.json
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {
            "meta": {
                "output_version": "1.0.0",
                "jmo_version": "0.9.0",
                "schema_version": "1.2.0",
                "timestamp": "2025-11-04T12:00:00Z",
                "scan_id": "test-enc-3",
                "profile": "balanced",
                "tools": ["trivy"],
                "target_count": 1,
                "finding_count": 1,
                "platform": "Linux",
            },
            "findings": [
                {
                    "schemaVersion": "1.2.0",
                    "id": "trivy|CVE-2024-1234|package.json|0|xyz123",
                    "tool": {"name": "trivy", "version": "0.68.0"},
                    "ruleId": "CVE-2024-1234",
                    "severity": "HIGH",
                    "message": "Vulnerability in lodash",
                    "location": {"path": "package.json", "startLine": 0},
                    "raw": {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.19",
                    },
                }
            ]
        }

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        db_path = tmp_path / "test_history.db"

        # Act: Store scan with default (encrypt_findings=False)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
            encrypt_findings=False,  # ← DEFAULT BEHAVIOR
        )

        # Assert: Verify scan was stored
        assert scan_id is not None

        # Assert: Query database and verify raw_finding is plaintext JSON
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT raw_finding FROM findings WHERE scan_id = ? AND tool = ?",
            (scan_id, "trivy"),
        )
        row = cursor.fetchone()

        assert row is not None
        raw_finding = row[0]
        assert raw_finding is not None

        # Verify it's plaintext JSON (not encrypted)
        raw_data = json.loads(raw_finding)  # Should parse without decryption
        assert raw_data["VulnerabilityID"] == "CVE-2024-1234"
        assert raw_data["PkgName"] == "lodash"

        conn.close()

    def test_scan_encrypt_with_redaction(self, tmp_path):
        """
        Test interaction between encryption and secret redaction.

        When both features are used:
        1. Redaction applied first (secrets replaced with [REDACTED])
        2. Redacted data is then encrypted
        3. Decrypted data should show [REDACTED], not original secrets
        """
        # Arrange: Set encryption key
        os.environ["JMO_ENCRYPTION_KEY"] = "test-key-32-chars-padding!!!!!"

        # Create findings with secrets
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {
            "meta": {
                "output_version": "1.0.0",
                "jmo_version": "0.9.0",
                "schema_version": "1.2.0",
                "timestamp": "2025-11-04T12:00:00Z",
                "scan_id": "test-enc-4",
                "profile": "fast",
                "tools": ["trufflehog"],
                "target_count": 1,
                "finding_count": 1,
                "platform": "Linux",
            },
            "findings": [
                {
                    "schemaVersion": "1.2.0",
                    "id": "trufflehog|aws|config.py|5|secret123",
                    "tool": {"name": "trufflehog", "version": "3.63.0"},
                    "ruleId": "aws",
                    "severity": "CRITICAL",
                    "message": "AWS Access Key detected",
                    "location": {"path": "config.py", "startLine": 5},
                    "raw": {
                        "DetectorName": "aws",
                        "Raw": "AKIAIOSFODNN7EXAMPLE",  # SECRET
                        "Verified": True,
                    },
                }
            ]
        }

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        db_path = tmp_path / "test_history.db"

        # Act: Store with encryption (redaction automatic for secret scanners)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trufflehog"],
            db_path=db_path,
            encrypt_findings=True,
        )

        # Assert: Encrypted data decrypts to redacted (not original secret)
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT raw_finding FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()

        encrypted_raw = row[0]
        assert encrypted_raw is not None

        # Decrypt and verify redaction applied
        decrypted_json = decrypt_raw_finding(encrypted_raw)
        decrypted_data = json.loads(decrypted_json)

        assert decrypted_data["Raw"] == "[REDACTED]"  # Redacted BEFORE encryption
        assert decrypted_data["DetectorName"] == "aws"  # Non-secret field intact

        conn.close()

        # Cleanup
        del os.environ["JMO_ENCRYPTION_KEY"]
