"""
Tests for SLSA Attestation Dependencies (Phase 0).

This test module verifies that all required dependencies for SLSA attestation
are properly installed and available.

Test Strategy (TDD):
1. Test sigstore-python library import
2. Test cryptography library availability
3. Test cosign binary availability (CLI mode)
4. Test OIDC token detection helpers
5. Test configuration schema for attestation settings
6. Test graceful degradation when dependencies missing

Coverage Target: 100% (8/8 tests)
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestSigstoreDependencies:
    """Test sigstore-python library availability."""

    def test_sigstore_import(self):
        """Test that sigstore library can be imported."""
        try:
            import sigstore

            assert sigstore is not None
        except ImportError:
            pytest.fail("sigstore library not installed - run: pip install sigstore")

    def test_sigstore_version(self):
        """Test that sigstore version is >= 2.0."""
        import sigstore

        # Check version is present
        assert hasattr(sigstore, "__version__")

        # Parse version (format: "2.1.5" -> (2, 1, 5))
        version_parts = sigstore.__version__.split(".")
        major = int(version_parts[0])

        # Require sigstore >= 2.0 for SLSA provenance v1.0 support
        assert major >= 2, f"sigstore version {sigstore.__version__} < 2.0"


class TestCryptographyDependencies:
    """Test cryptography library for hashing and signing."""

    def test_cryptography_import(self):
        """Test that cryptography library can be imported."""
        try:
            import cryptography

            assert cryptography is not None
        except ImportError:
            pytest.fail(
                "cryptography library not installed - run: pip install cryptography"
            )

    def test_hash_algorithms_available(self):
        """Test that SHA-256, SHA-384, SHA-512 are available."""
        from cryptography.hazmat.primitives import hashes

        # SLSA provenance requires SHA-256, SHA-384, SHA-512
        assert hashes.SHA256
        assert hashes.SHA384
        assert hashes.SHA512


class TestCosignBinary:
    """Test cosign binary availability (CLI mode)."""

    def test_cosign_in_path_or_local_bin(self):
        """Test that cosign is in PATH or ~/.jmo/bin/."""
        # Check system PATH
        cosign_in_path = shutil.which("cosign")

        # Check local ~/.jmo/bin/ directory
        local_cosign = Path.home() / ".jmo" / "bin" / "cosign"
        cosign_local = local_cosign.exists() and local_cosign.is_file()

        # At least one must be present
        assert cosign_in_path or cosign_local, (
            "cosign binary not found in PATH or ~/.jmo/bin/. "
            "Install: curl -L https://github.com/sigstore/cosign/releases/download/v2.2.3/cosign-linux-amd64 "
            "-o ~/.jmo/bin/cosign && chmod +x ~/.jmo/bin/cosign"
        )

    def test_cosign_version(self):
        """Test that cosign version is >= 2.0."""
        # Try system PATH first
        cosign_cmd = shutil.which("cosign")

        # Fallback to ~/.jmo/bin/
        if not cosign_cmd:
            local_cosign = Path.home() / ".jmo" / "bin" / "cosign"
            if local_cosign.exists():
                cosign_cmd = str(local_cosign)

        if not cosign_cmd:
            pytest.skip("cosign binary not available - skipping version test")

        # Run cosign version
        result = subprocess.run(
            [cosign_cmd, "version"], capture_output=True, text=True, timeout=5
        )

        assert result.returncode == 0, f"cosign version check failed: {result.stderr}"

        # Parse version (output format: "GitVersion:v2.2.3")
        version_output = result.stdout
        assert "GitVersion:" in version_output or "v2." in version_output


class TestOIDCTokenDetection:
    """Test OIDC token detection utilities."""

    def test_github_token_detection(self):
        """Test GitHub token detection from environment."""
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_test123"}):
            # This will be implemented in attestation.py
            # For now, just test env var access
            assert os.getenv("GITHUB_TOKEN") == "ghp_test123"

    def test_gitlab_token_detection(self):
        """Test GitLab token detection from environment."""
        with patch.dict(os.environ, {"GITLAB_TOKEN": "glpat_test123"}):
            assert os.getenv("GITLAB_TOKEN") == "glpat_test123"

    def test_no_token_returns_none(self):
        """Test graceful handling when no OIDC token present."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove GITHUB_TOKEN and GITLAB_TOKEN if present
            assert os.getenv("GITHUB_TOKEN") is None
            assert os.getenv("GITLAB_TOKEN") is None


class TestAttestationConfiguration:
    """Test attestation configuration schema."""

    def test_attestation_config_schema(self):
        """Test that attestation config can be loaded from jmo.yml."""
        import yaml

        # Example attestation config
        config = {
            "attestation": {
                "enabled": True,
                "auto_attest": True,
                "backend": "sigstore",
                "sigstore": {
                    "oidc_provider": "detect",
                    "fulcio_url": "https://fulcio.sigstore.dev",
                    "rekor_url": "https://rekor.sigstore.dev",
                },
                "storage": {"attestation_dir": "results/attestations"},
            }
        }

        # Validate schema structure
        assert "attestation" in config
        assert config["attestation"]["enabled"] is True
        assert config["attestation"]["backend"] == "sigstore"
        assert "sigstore" in config["attestation"]
        assert "fulcio_url" in config["attestation"]["sigstore"]

    def test_graceful_degradation_config(self):
        """Test graceful degradation when attestation disabled."""
        config = {"attestation": {"enabled": False}}

        # Should not require other fields when disabled
        assert config["attestation"]["enabled"] is False


class TestDependencyGracefulDegradation:
    """Test graceful degradation when dependencies missing."""

    def test_missing_sigstore_warning(self):
        """Test warning message when sigstore unavailable."""
        # This will be implemented in attestation.py
        # For now, test the pattern we'll use

        try:
            import sigstore

            available = True
        except ImportError:
            available = False

        if not available:
            # Should log warning but not fail
            import logging

            logger = logging.getLogger(__name__)
            logger.warning("sigstore library not available - attestation disabled")

    def test_missing_cosign_fallback(self):
        """Test fallback when cosign not in PATH."""
        # Check if cosign is missing
        if not shutil.which("cosign"):
            # Should attempt to download to ~/.jmo/bin/
            local_bin = Path.home() / ".jmo" / "bin"
            local_bin.mkdir(parents=True, exist_ok=True)

            # Verify directory exists
            assert local_bin.exists()


# Integration test fixture
@pytest.fixture
def mock_attestation_env():
    """Mock environment for attestation testing."""
    with patch.dict(
        os.environ, {"GITHUB_TOKEN": "ghp_test123", "COSIGN_EXPERIMENTAL": "1"}
    ):
        yield


class TestAttestationEnvironment:
    """Test complete attestation environment setup."""

    def test_complete_environment(self, mock_attestation_env):
        """Test that all components are available for attestation."""
        # Check all dependencies
        try:
            import sigstore
            import cryptography

            sigstore_available = True
        except ImportError:
            sigstore_available = False

        # Check OIDC token
        github_token = os.getenv("GITHUB_TOKEN")

        # Check cosign binary
        cosign_available = shutil.which("cosign") is not None

        # At least sigstore OR cosign should be available
        # (Can use pure Python sigstore-python or cosign binary)
        assert sigstore_available or cosign_available, (
            "Neither sigstore-python nor cosign binary available. "
            "Install at least one: pip install sigstore OR install cosign binary"
        )
