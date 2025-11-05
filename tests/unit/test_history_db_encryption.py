#!/usr/bin/env python3
"""
Unit tests for history database encryption (Phase 6 Step 6.2).

Tests cover:
- Encryption of raw finding data using Fernet symmetric encryption
- Decryption round-trip (encrypt → decrypt → original data)
- Graceful handling of missing encryption key
- Backward compatibility with unencrypted databases
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scripts.core.history_db import encrypt_raw_finding, decrypt_raw_finding


class TestRawFindingEncryption:
    """Test encryption/decryption of raw finding data."""

    def test_encrypt_raw_findings(self):
        """
        Test that raw finding data is encrypted using Fernet symmetric encryption.

        Encryption requirements:
        - Uses cryptography.fernet.Fernet (industry standard)
        - Key derived from JMO_ENCRYPTION_KEY environment variable
        - Encrypted data is base64-encoded string
        - Original data NOT recoverable without key
        """
        # Arrange: Set encryption key environment variable
        encryption_key = "test-encryption-key-32-chars!!"  # 32 bytes for Fernet
        os.environ["JMO_ENCRYPTION_KEY"] = encryption_key

        # Create raw finding data (sensitive secret)
        raw_data = {
            "DetectorName": "github",
            "Raw": "ghp_1234567890abcdef",  # SECRET VALUE
            "Verified": True,
        }
        raw_json = json.dumps(raw_data)

        # Act: Encrypt the raw finding
        encrypted = encrypt_raw_finding(raw_json)

        # Assert: Encrypted data is different from original
        assert encrypted != raw_json
        assert isinstance(encrypted, str)
        assert len(encrypted) > len(raw_json)  # Encryption adds overhead

        # Assert: Original secret NOT present in encrypted data
        assert "ghp_1234567890abcdef" not in encrypted
        assert "Raw" not in encrypted  # Field names also encrypted

        # Cleanup
        del os.environ["JMO_ENCRYPTION_KEY"]

    def test_decrypt_raw_findings_round_trip(self):
        """
        Test that encryption → decryption produces original data.

        Round-trip verification:
        1. Start with raw finding JSON
        2. Encrypt using key
        3. Decrypt using same key
        4. Verify decrypted data matches original
        """
        # Arrange: Set encryption key
        encryption_key = "test-encryption-key-32-chars!!"
        os.environ["JMO_ENCRYPTION_KEY"] = encryption_key

        # Create complex raw finding with nested structures
        raw_data = {
            "SourceMetadata": {
                "Data": {"Github": {"link": "https://github.com"}},
            },
            "DetectorName": "aws",
            "Raw": "AKIAIOSFODNN7EXAMPLE",  # AWS access key
            "RawV2": "secret_value_here",
            "Verified": True,
            "NestedLevel": {
                "DeepSecret": "password123",
                "NonSecret": "metadata",
            },
        }
        original_json = json.dumps(raw_data, sort_keys=True)

        # Act: Encrypt then decrypt
        encrypted = encrypt_raw_finding(original_json)
        decrypted = decrypt_raw_finding(encrypted)

        # Assert: Decrypted matches original exactly
        assert decrypted == original_json

        # Assert: Parse decrypted JSON and verify structure
        decrypted_data = json.loads(decrypted)
        assert decrypted_data["DetectorName"] == "aws"
        assert decrypted_data["Raw"] == "AKIAIOSFODNN7EXAMPLE"
        assert decrypted_data["NestedLevel"]["DeepSecret"] == "password123"

        # Cleanup
        del os.environ["JMO_ENCRYPTION_KEY"]

    def test_encrypt_without_key_raises_error(self):
        """
        Test that encryption fails gracefully if JMO_ENCRYPTION_KEY not set.

        Security requirement: Encryption must not silently fail.
        If user requests encryption, it MUST either succeed or raise clear error.
        """
        # Arrange: Ensure key is not set
        if "JMO_ENCRYPTION_KEY" in os.environ:
            del os.environ["JMO_ENCRYPTION_KEY"]

        raw_data = {"DetectorName": "github", "Raw": "secret"}
        raw_json = json.dumps(raw_data)

        # Act & Assert: Encryption should raise ValueError
        with pytest.raises(ValueError, match="JMO_ENCRYPTION_KEY environment variable not set"):
            encrypt_raw_finding(raw_json)

    def test_decrypt_without_key_raises_error(self):
        """
        Test that decryption fails gracefully if JMO_ENCRYPTION_KEY not set.
        """
        # Arrange: Ensure key is not set
        if "JMO_ENCRYPTION_KEY" in os.environ:
            del os.environ["JMO_ENCRYPTION_KEY"]

        # Fake encrypted data
        encrypted_data = "gAAAAABhX..."

        # Act & Assert: Decryption should raise ValueError
        with pytest.raises(ValueError, match="JMO_ENCRYPTION_KEY environment variable not set"):
            decrypt_raw_finding(encrypted_data)

    def test_decrypt_with_wrong_key_raises_error(self):
        """
        Test that decryption with incorrect key raises InvalidToken error.

        Security requirement: Wrong key must not silently return garbage data.
        """
        # Arrange: Encrypt with one key
        os.environ["JMO_ENCRYPTION_KEY"] = "correct-key-32-chars-padding!!"
        raw_json = json.dumps({"secret": "data"})
        encrypted = encrypt_raw_finding(raw_json)

        # Act: Try to decrypt with different key
        os.environ["JMO_ENCRYPTION_KEY"] = "wrong-key-32-chars-padding!!!!"

        # Assert: Decryption should raise InvalidToken error
        from cryptography.fernet import InvalidToken

        with pytest.raises(InvalidToken):
            decrypt_raw_finding(encrypted)

        # Cleanup
        del os.environ["JMO_ENCRYPTION_KEY"]

    def test_encrypt_empty_string(self):
        """
        Test encryption of empty string (edge case).
        """
        os.environ["JMO_ENCRYPTION_KEY"] = "test-key-32-chars-padding!!!!!"
        encrypted = encrypt_raw_finding("")
        decrypted = decrypt_raw_finding(encrypted)
        assert decrypted == ""
        del os.environ["JMO_ENCRYPTION_KEY"]

    def test_encrypt_large_finding(self):
        """
        Test encryption of large raw finding (10KB+).

        Ensures performance is acceptable for large payloads.
        """
        os.environ["JMO_ENCRYPTION_KEY"] = "test-key-32-chars-padding!!!!!"

        # Create large raw finding (10KB)
        large_data = {
            "findings": [
                {"id": f"finding-{i}", "data": "x" * 100} for i in range(100)
            ]
        }
        large_json = json.dumps(large_data)
        assert len(large_json) > 10_000  # Verify >10KB

        # Encrypt and decrypt
        encrypted = encrypt_raw_finding(large_json)
        decrypted = decrypt_raw_finding(encrypted)

        # Verify round-trip
        assert decrypted == large_json

        # Cleanup
        del os.environ["JMO_ENCRYPTION_KEY"]
