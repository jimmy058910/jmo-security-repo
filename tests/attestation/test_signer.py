"""
Tests for Sigstore signing functionality.

Tests the SigstoreSigner class which handles:
- OIDC token acquisition (GitHub Actions, GitLab CI, local OAuth)
- Keyless signing via Sigstore
- Rekor transparency log verification
"""

import json
import sys
from unittest.mock import MagicMock, patch

import pytest
import requests

from scripts.core.attestation.constants import (
    FULCIO_URL_PRODUCTION,
    FULCIO_URL_STAGING,
    REKOR_URL_PRODUCTION,
    REKOR_URL_STAGING,
    SIGNING_TIMEOUT,
)
from scripts.core.attestation.signer import SigstoreSigner

# Check if sigstore is available (optional dependency)
try:
    import sigstore.oidc  # noqa: F401

    HAS_SIGSTORE = True
except ImportError:
    HAS_SIGSTORE = False

requires_sigstore = pytest.mark.skipif(
    not HAS_SIGSTORE, reason="sigstore package not installed"
)


class TestSignerInitialization:
    """Tests for SigstoreSigner initialization."""

    def test_init_default_production(self):
        """Test initialization defaults to production endpoints."""
        signer = SigstoreSigner()

        assert signer.fulcio_url == FULCIO_URL_PRODUCTION
        assert signer.rekor_url == REKOR_URL_PRODUCTION
        assert signer.use_staging is False

    def test_init_staging(self):
        """Test initialization with staging endpoints."""
        config = {"use_staging": True}
        signer = SigstoreSigner(config=config)

        assert signer.fulcio_url == FULCIO_URL_STAGING
        assert signer.rekor_url == REKOR_URL_STAGING
        assert signer.use_staging is True

    def test_init_custom_endpoints(self):
        """Test initialization with custom endpoints."""
        config = {
            "fulcio_url": "https://custom-fulcio.example.com",
            "rekor_url": "https://custom-rekor.example.com",
        }
        signer = SigstoreSigner(config=config)

        assert signer.fulcio_url == "https://custom-fulcio.example.com"
        assert signer.rekor_url == "https://custom-rekor.example.com"

    def test_init_custom_overrides_staging(self):
        """Test custom endpoints override staging flag."""
        config = {
            "use_staging": True,
            "fulcio_url": "https://custom-fulcio.example.com",
        }
        signer = SigstoreSigner(config=config)

        assert signer.fulcio_url == "https://custom-fulcio.example.com"
        assert signer.use_staging is True  # Flag still set but URL overridden


class TestSignMethod:
    """Tests for sign method."""

    @patch("subprocess.run")
    def test_sign_success_production(self, mock_run, tmp_path):
        """Test successful signing in production mode."""
        signer = SigstoreSigner()

        # Create test attestation file
        attestation_file = tmp_path / "findings.json.att.json"
        attestation_file.write_text('{"test": "attestation"}')

        # Mock successful sigstore sign command
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        # Mock bundle file creation
        bundle_data = {
            "messageSignature": {"signature": "base64_signature_here"},
            "verificationMaterial": {
                "certificate": "base64_certificate_here",
                "tlogEntries": [{"logIndex": 12345}],
            },
        }

        with patch("pathlib.Path.read_text", return_value=json.dumps(bundle_data)):
            with patch("pathlib.Path.write_text"):
                result = signer.sign(str(attestation_file))

        assert result["signature_path"] is not None
        assert result["certificate_path"] is not None
        assert result["bundle_path"] is not None
        assert (
            result["rekor_entry"] == f"{REKOR_URL_PRODUCTION}/api/v1/log/entries/12345"
        )

        # Verify sigstore command was called
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        # sys.executable, not "python3". A bare "python3" binds to whatever is
        # first on PATH; measured on this machine it resolved to an unrelated
        # venv and answered "No module named sigstore" while the project venv
        # had sigstore 4.5.0 installed.
        assert cmd[0] == sys.executable
        assert cmd[1:4] == ["-m", "sigstore", "sign"]
        assert "--bundle" in cmd
        # Signing outside CI walks a human through a browser OAuth redirect,
        # which the 30s ATTESTATION_TIMEOUT could not cover.
        assert mock_run.call_args[1]["timeout"] == SIGNING_TIMEOUT

    @patch("subprocess.run")
    def test_sign_success_staging(self, mock_run, tmp_path):
        """Test successful signing in staging mode."""
        signer = SigstoreSigner(config={"use_staging": True})

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text('{"test": "data"}')

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        bundle_data = {
            "messageSignature": {"signature": "sig"},
            "verificationMaterial": {
                "certificate": "cert",
                "tlogEntries": [{"logIndex": 99}],
            },
        }

        with patch("pathlib.Path.read_text", return_value=json.dumps(bundle_data)):
            with patch("pathlib.Path.write_text"):
                result = signer.sign(str(attestation_file))

        # Verify staging flag was used
        cmd = mock_run.call_args[0][0]
        assert "--staging" in cmd
        assert result["rekor_entry"] == f"{REKOR_URL_STAGING}/api/v1/log/entries/99"

    @patch("subprocess.run")
    def test_sign_file_not_found(self, mock_run, tmp_path):
        """Test signing fails when attestation file not found."""
        signer = SigstoreSigner()

        nonexistent_file = tmp_path / "nonexistent.json"

        with pytest.raises(FileNotFoundError):
            signer.sign(str(nonexistent_file))

        # Sigstore should not be called
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_sign_subprocess_failure(self, mock_run, tmp_path):
        """Test signing fails when sigstore command fails."""
        signer = SigstoreSigner()

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text('{"test": "data"}')

        # Mock failed sigstore command
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Signing failed: invalid token",
        )

        with pytest.raises(Exception, match="Sigstore signing failed"):
            signer.sign(str(attestation_file))

    @patch("subprocess.run")
    def test_sign_no_rekor_entry(self, mock_run, tmp_path):
        """Test signing when Rekor entry is missing."""
        signer = SigstoreSigner()

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text('{"test": "data"}')

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        # Bundle with missing tlogEntries
        bundle_data = {
            "messageSignature": {"signature": "sig"},
            "verificationMaterial": {
                "certificate": "cert",
                "tlogEntries": [],  # Empty
            },
        }

        with patch("pathlib.Path.read_text", return_value=json.dumps(bundle_data)):
            with patch("pathlib.Path.write_text"):
                result = signer.sign(str(attestation_file))

        # Should still succeed but with no Rekor entry
        assert result["rekor_entry"] is None


class TestVerifyRekorEntry:
    """Tests for verify_rekor_entry method."""

    @patch("requests.get")
    def test_verify_rekor_entry_exists(self, mock_get):
        """Test verifying existing Rekor entry."""
        signer = SigstoreSigner()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = signer.verify_rekor_entry(
            "https://rekor.sigstore.dev/api/v1/log/entries/12345"
        )

        assert result is True
        mock_get.assert_called_once()

    @patch("requests.get")
    def test_verify_rekor_entry_not_found(self, mock_get):
        """Test verifying non-existent Rekor entry."""
        signer = SigstoreSigner()

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = signer.verify_rekor_entry(
            "https://rekor.sigstore.dev/api/v1/log/entries/99999"
        )

        assert result is False

    @patch("requests.get")
    def test_verify_rekor_entry_unexpected_status(self, mock_get):
        """Test handling unexpected HTTP status."""
        signer = SigstoreSigner()

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = signer.verify_rekor_entry(
            "https://rekor.sigstore.dev/api/v1/log/entries/12345"
        )

        assert result is False

    @patch("requests.get")
    def test_verify_rekor_entry_timeout(self, mock_get):
        """Test handling Rekor service timeout."""
        signer = SigstoreSigner()

        mock_get.side_effect = requests.exceptions.Timeout("Timeout")

        with pytest.raises(requests.exceptions.Timeout):
            signer.verify_rekor_entry(
                "https://rekor.sigstore.dev/api/v1/log/entries/12345"
            )

    @patch("requests.get")
    def test_verify_rekor_entry_connection_error(self, mock_get):
        """Test handling Rekor service connection error."""
        signer = SigstoreSigner()

        mock_get.side_effect = requests.exceptions.ConnectionError("Connection failed")

        with pytest.raises(requests.exceptions.ConnectionError):
            signer.verify_rekor_entry(
                "https://rekor.sigstore.dev/api/v1/log/entries/12345"
            )


class TestSigstoreAvailability:
    """ "sigstore is missing" and "this signature is bad" must not be the same
    answer.

    Both used to arrive as a non-zero subprocess exit routed through the same
    error path — and the missing-module case was reached constantly, because
    the command named `python3` rather than this interpreter.
    """

    def test_require_sigstore_names_the_interpreter_when_absent(self):
        from scripts.core.attestation.signer import require_sigstore

        with patch("importlib.util.find_spec", return_value=None):
            with pytest.raises(RuntimeError) as excinfo:
                require_sigstore()

        assert "sigstore is not installed" in str(excinfo.value)
        assert sys.executable in str(excinfo.value)

    def test_require_sigstore_is_quiet_when_present(self):
        """Negative control: the guard must be capable of not firing."""
        from scripts.core.attestation.signer import require_sigstore

        require_sigstore()

    @patch("subprocess.run")
    def test_sign_refuses_before_spawning_when_sigstore_is_absent(
        self, mock_run, tmp_path
    ):
        attestation = tmp_path / "attestation.json"
        attestation.write_text('{"test": "data"}', encoding="utf-8")

        with patch("importlib.util.find_spec", return_value=None):
            with pytest.raises(RuntimeError, match="sigstore is not installed"):
                SigstoreSigner().sign(str(attestation))

        mock_run.assert_not_called()
