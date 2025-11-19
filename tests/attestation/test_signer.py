"""
Tests for Sigstore signing functionality.

Tests the SigstoreSigner class which handles:
- OIDC token acquisition (GitHub Actions, GitLab CI, local OAuth)
- Keyless signing via Sigstore
- Rekor transparency log verification
"""

import pytest
import json
from unittest.mock import patch, MagicMock
import requests
from scripts.core.attestation.signer import SigstoreSigner
from scripts.core.attestation.constants import (
    FULCIO_URL_PRODUCTION,
    REKOR_URL_PRODUCTION,
    FULCIO_URL_STAGING,
    REKOR_URL_STAGING,
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


class TestCIEnvironmentDetection:
    """Tests for CI environment detection."""

    @patch.dict(
        "os.environ",
        {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.url"},
        clear=True,
    )
    def test_detect_github_actions(self):
        """Test GitHub Actions detection."""
        signer = SigstoreSigner()

        result = signer._detect_ci_environment()

        assert result == "github"

    @patch.dict("os.environ", {"CI_JOB_JWT": "jwt_token_here"}, clear=True)
    def test_detect_gitlab_ci(self):
        """Test GitLab CI detection."""
        signer = SigstoreSigner()

        result = signer._detect_ci_environment()

        assert result == "gitlab"

    @patch.dict("os.environ", {}, clear=True)
    def test_detect_local(self):
        """Test local environment detection."""
        signer = SigstoreSigner()

        result = signer._detect_ci_environment()

        assert result == "local"


class TestOIDCTokenAcquisition:
    """Tests for OIDC token acquisition methods."""

    @patch("requests.get")
    @patch.dict(
        "os.environ",
        {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request_token_here",
        },
        clear=True,
    )
    def test_get_github_oidc_token_success(self, mock_get):
        """Test successful GitHub OIDC token acquisition."""
        signer = SigstoreSigner()

        # Mock successful token response
        mock_response = MagicMock()
        mock_response.json.return_value = {"value": "github_oidc_token_123"}
        mock_get.return_value = mock_response

        token = signer._get_github_oidc_token()

        assert token == "github_oidc_token_123"
        mock_get.assert_called_once()

        # Verify request parameters
        call_args = mock_get.call_args
        assert call_args[0][0] == "https://token.actions.githubusercontent.com"
        assert call_args[1]["params"]["audience"] == "sigstore"

    @patch("requests.get")
    @patch.dict(
        "os.environ",
        {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.url",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request_token",
        },
        clear=True,
    )
    def test_get_github_oidc_token_failure(self, mock_get):
        """Test GitHub OIDC token acquisition failure."""
        signer = SigstoreSigner()

        # Mock failed token response
        mock_get.side_effect = requests.exceptions.HTTPError("Token request failed")

        with pytest.raises(requests.exceptions.HTTPError):
            signer._get_github_oidc_token()

    @patch.dict("os.environ", {"CI_JOB_JWT": "gitlab_jwt_token_abc"}, clear=True)
    def test_get_gitlab_oidc_token(self):
        """Test GitLab OIDC token acquisition."""
        signer = SigstoreSigner()

        token = signer._get_gitlab_oidc_token()

        assert token == "gitlab_jwt_token_abc"

    @patch("sigstore.oidc.Issuer")
    def test_get_local_oidc_token_success(self, mock_issuer_class):
        """Test local OIDC token acquisition via OAuth flow."""
        signer = SigstoreSigner()

        # Mock sigstore-python OAuth flow
        mock_issuer = MagicMock()
        mock_token = MagicMock()
        mock_token.value = "local_oauth_token_xyz"
        mock_issuer.identity_token.return_value = mock_token
        mock_issuer_class.production.return_value = mock_issuer

        token = signer._get_local_oidc_token()

        assert token == "local_oauth_token_xyz"

    @patch("sigstore.oidc.Issuer")
    def test_get_local_oidc_token_failure(self, mock_issuer_class):
        """Test local OIDC token acquisition failure."""
        signer = SigstoreSigner()

        # Mock OAuth flow failure
        mock_issuer_class.production.side_effect = Exception("OAuth failed")

        with pytest.raises(Exception, match="OAuth failed"):
            signer._get_local_oidc_token()

    @patch.object(SigstoreSigner, "_get_github_oidc_token")
    @patch.dict(
        "os.environ", {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.url"}, clear=True
    )
    def test_get_oidc_token_github(self, mock_github_token):
        """Test _get_oidc_token routes to GitHub method."""
        signer = SigstoreSigner()
        mock_github_token.return_value = "github_token"

        token = signer._get_oidc_token()

        assert token == "github_token"
        mock_github_token.assert_called_once()

    @patch.object(SigstoreSigner, "_get_gitlab_oidc_token")
    @patch.dict("os.environ", {"CI_JOB_JWT": "jwt_token"}, clear=True)
    def test_get_oidc_token_gitlab(self, mock_gitlab_token):
        """Test _get_oidc_token routes to GitLab method."""
        signer = SigstoreSigner()
        mock_gitlab_token.return_value = "gitlab_token"

        token = signer._get_oidc_token()

        assert token == "gitlab_token"
        mock_gitlab_token.assert_called_once()

    @patch.object(SigstoreSigner, "_get_local_oidc_token")
    @patch.dict("os.environ", {}, clear=True)
    def test_get_oidc_token_local(self, mock_local_token):
        """Test _get_oidc_token routes to local OAuth method."""
        signer = SigstoreSigner()
        mock_local_token.return_value = "local_token"

        token = signer._get_oidc_token()

        assert token == "local_token"
        mock_local_token.assert_called_once()


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
        assert "sigstore" in cmd
        assert "sign" in cmd
        assert "--bundle" in cmd

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
