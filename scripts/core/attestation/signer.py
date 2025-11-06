"""
Sigstore signing for SLSA attestations.

This module implements keyless signing using Sigstore infrastructure:
- OIDC token acquisition (GitHub Actions, GitLab CI, local OAuth)
- Fulcio certificate signing
- Rekor transparency log upload
- Signature bundle creation

Implementation uses the sigstore CLI tool for simplicity and reliability.
"""

import os
import json
import subprocess
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import requests

from .constants import (
    FULCIO_URL_PRODUCTION,
    FULCIO_URL_STAGING,
    REKOR_URL_PRODUCTION,
    REKOR_URL_STAGING,
    ATTESTATION_TIMEOUT,
    REKOR_TIMEOUT,
)

logger = logging.getLogger(__name__)


class SigstoreSigner:
    """
    Sigstore-based signer for attestations.

    Uses keyless signing with Fulcio CA and Rekor transparency log.
    Supports multiple OIDC providers (GitHub Actions, GitLab CI, local OAuth).
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Sigstore signer.

        Args:
            config: Optional configuration dict with keys:
                - use_staging: Use staging endpoints (default: False)
                - fulcio_url: Custom Fulcio URL
                - rekor_url: Custom Rekor URL
        """
        self.config = config or {}

        # Determine endpoints
        if self.config.get("use_staging"):
            self.fulcio_url = FULCIO_URL_STAGING
            self.rekor_url = REKOR_URL_STAGING
            self.use_staging = True
        else:
            self.fulcio_url = FULCIO_URL_PRODUCTION
            self.rekor_url = REKOR_URL_PRODUCTION
            self.use_staging = False

        # Allow custom endpoints
        self.fulcio_url = self.config.get("fulcio_url", self.fulcio_url)
        self.rekor_url = self.config.get("rekor_url", self.rekor_url)

        logger.debug(f"Sigstore signer initialized: Fulcio={self.fulcio_url}, Rekor={self.rekor_url}")

    def _detect_ci_environment(self) -> str:
        """
        Detect CI environment for OIDC token acquisition.

        Returns:
            "github", "gitlab", or "local"
        """
        if "ACTIONS_ID_TOKEN_REQUEST_URL" in os.environ:
            return "github"
        elif "CI_JOB_JWT" in os.environ:
            return "gitlab"
        else:
            return "local"

    def _get_oidc_token(self) -> str:
        """
        Acquire OIDC token from CI environment or local OAuth flow.

        Returns:
            OIDC token string

        Raises:
            Exception: If token acquisition fails
        """
        ci_env = self._detect_ci_environment()

        if ci_env == "github":
            return self._get_github_oidc_token()
        elif ci_env == "gitlab":
            return self._get_gitlab_oidc_token()
        else:
            return self._get_local_oidc_token()

    def _get_github_oidc_token(self) -> str:
        """
        Acquire OIDC token from GitHub Actions.

        Uses ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN
        environment variables.

        Returns:
            OIDC token string

        Raises:
            Exception: If token request fails
        """
        token_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
        request_token = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]

        headers = {
            "Authorization": f"Bearer {request_token}",
            "Accept": "application/json"
        }

        # Request token with audience for Sigstore
        params = {"audience": "sigstore"}

        response = requests.get(
            token_url,
            headers=headers,
            params=params,
            timeout=ATTESTATION_TIMEOUT
        )
        response.raise_for_status()

        token_data = response.json()
        return token_data["value"]

    def _get_gitlab_oidc_token(self) -> str:
        """
        Acquire OIDC token from GitLab CI.

        Uses CI_JOB_JWT environment variable.

        Returns:
            OIDC token string
        """
        return os.environ["CI_JOB_JWT"]

    def _get_local_oidc_token(self) -> str:
        """
        Acquire OIDC token via local OAuth flow.

        Uses sigstore-python's OAuth flow to get token interactively.

        Returns:
            OIDC token string

        Raises:
            Exception: If OAuth flow fails
        """
        try:
            # Use sigstore-python's built-in OAuth flow
            from sigstore.oidc import Issuer

            issuer = Issuer.production()
            token = issuer.identity_token()
            return token.value
        except Exception as e:
            logger.error(f"Local OIDC token acquisition failed: {e}")
            raise

    def sign(self, attestation_path: str) -> Dict[str, Any]:
        """
        Sign attestation using Sigstore keyless signing.

        Creates:
        - Signature file (.sig)
        - Certificate file (.crt)
        - Sigstore bundle (.sigstore.json) with Rekor entry

        Args:
            attestation_path: Path to attestation JSON file

        Returns:
            Dict with:
                - signature_path: Path to signature file
                - certificate_path: Path to certificate file
                - bundle_path: Path to Sigstore bundle
                - rekor_entry: Rekor transparency log URL

        Raises:
            Exception: If signing or Rekor upload fails
        """
        attestation_path_obj = Path(attestation_path)
        if not attestation_path_obj.exists():
            raise FileNotFoundError(f"Attestation file not found: {attestation_path}")

        try:
            logger.info(f"Signing attestation: {attestation_path}")

            # Build sigstore CLI command
            cmd = ["python3", "-m", "sigstore", "sign"]

            # Add staging flag if configured
            if self.use_staging:
                cmd.append("--staging")

            # Output bundle path
            bundle_path = attestation_path_obj.with_suffix(attestation_path_obj.suffix + ".sigstore.json")
            cmd.extend(["--bundle", str(bundle_path)])

            # Input file
            cmd.append(str(attestation_path))

            # Run sigstore sign command
            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=ATTESTATION_TIMEOUT,
                check=False
            )

            if result.returncode != 0:
                logger.error(f"Sigstore signing failed: {result.stderr}")
                raise Exception(f"Sigstore signing failed: {result.stderr}")

            logger.info(f"Signature bundle saved: {bundle_path}")

            # Parse bundle for individual components
            bundle_data = json.loads(bundle_path.read_text())

            # Extract signature
            message_sig = bundle_data.get("messageSignature", {})
            signature_b64 = message_sig.get("signature", "")

            # Extract certificate
            verification_material = bundle_data.get("verificationMaterial", {})
            certificate_b64 = verification_material.get("certificate", "")

            # Extract Rekor entry
            tlog_entries = verification_material.get("tlogEntries", [])
            rekor_entry_url = None
            if tlog_entries:
                log_index = tlog_entries[0].get("logIndex")
                if log_index is not None:
                    rekor_entry_url = f"{self.rekor_url}/api/v1/log/entries/{log_index}"

            # Save individual files
            signature_path = attestation_path_obj.with_suffix(attestation_path_obj.suffix + ".sig")
            signature_path.write_text(signature_b64)

            certificate_path = attestation_path_obj.with_suffix(attestation_path_obj.suffix + ".crt")
            certificate_path.write_text(certificate_b64)

            logger.info("✅ Signing complete")
            logger.info(f"  Signature: {signature_path}")
            logger.info(f"  Certificate: {certificate_path}")
            logger.info(f"  Bundle: {bundle_path}")
            if rekor_entry_url:
                logger.info(f"  Rekor entry: {rekor_entry_url}")

            return {
                "signature_path": str(signature_path),
                "certificate_path": str(certificate_path),
                "bundle_path": str(bundle_path),
                "rekor_entry": rekor_entry_url
            }

        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise

    def verify_rekor_entry(self, rekor_entry_url: str) -> bool:
        """
        Verify that Rekor transparency log entry exists.

        Args:
            rekor_entry_url: Rekor entry URL

        Returns:
            True if entry exists, False otherwise

        Raises:
            Exception: If Rekor service is unavailable
        """
        try:
            response = requests.get(rekor_entry_url, timeout=REKOR_TIMEOUT)
            if response.status_code == 200:
                logger.info(f"✅ Rekor entry verified: {rekor_entry_url}")
                return True
            elif response.status_code == 404:
                logger.warning(f"❌ Rekor entry not found: {rekor_entry_url}")
                return False
            else:
                logger.warning(f"⚠️ Unexpected Rekor response: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Rekor verification failed: {e}")
            raise
