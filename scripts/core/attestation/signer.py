"""
Sigstore signing for SLSA attestations.

This module implements keyless signing using Sigstore infrastructure:
- Fulcio certificate signing
- Rekor transparency log upload
- Signature bundle creation

Implementation shells out to the sigstore CLI, which performs its own OIDC
token acquisition (GitHub Actions, GitLab CI, or a local browser flow). This
module does not acquire or handle OIDC tokens itself.
"""

import importlib.util
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

import requests

from .constants import (
    FULCIO_URL_PRODUCTION,
    FULCIO_URL_STAGING,
    REKOR_TIMEOUT,
    REKOR_URL_PRODUCTION,
    REKOR_URL_STAGING,
    SIGNING_TIMEOUT,
)

logger = logging.getLogger(__name__)


def require_sigstore() -> None:
    """Fail early, and by name, when sigstore is not available.

    Signing and signature verification shell out to ``sys.executable -m
    sigstore``. If the module is absent the subprocess exits 1 with
    "No module named sigstore" — which, routed through a verifier, reads
    exactly like "this signature is bad". Those must never be the same
    answer, so the absent-tool case is raised distinctly before any
    subprocess runs.

    Raises:
        RuntimeError: If sigstore cannot be imported by this interpreter.
    """
    if importlib.util.find_spec("sigstore") is None:
        raise RuntimeError(
            "sigstore is not installed for this interpreter "
            f"({sys.executable}). Install it with `uv sync --group dev`, or "
            "`pip install sigstore`, then retry."
        )


class SigstoreSigner:
    """
    Sigstore-based signer for attestations.

    Uses keyless signing with Fulcio CA and Rekor transparency log.
    OIDC is performed by the sigstore CLI this class invokes, not here.
    """

    def __init__(self, config: dict[str, Any] | None = None):
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

        logger.debug(
            f"Sigstore signer initialized: Fulcio={self.fulcio_url}, Rekor={self.rekor_url}"
        )

    def sign(self, attestation_path: str) -> dict[str, Any]:
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

        require_sigstore()

        try:
            logger.info(f"Signing attestation: {attestation_path}")

            # Build sigstore CLI command. sys.executable, never "python3":
            # a bare "python3" binds to whatever is first on PATH, which need
            # not be — and on Windows usually is not — the interpreter running
            # JMo. Measured: it resolved to an unrelated venv that answered
            # "No module named sigstore" while this venv had sigstore 4.5.0.
            cmd = [sys.executable, "-m", "sigstore", "sign"]

            # Add staging flag if configured
            if self.use_staging:
                cmd.append("--staging")

            # Output bundle path
            bundle_path = attestation_path_obj.with_suffix(
                attestation_path_obj.suffix + ".sigstore.json"
            )
            cmd.extend(["--bundle", str(bundle_path)])

            # Input file
            cmd.append(str(attestation_path))

            # Run sigstore sign command
            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                # Not ATTESTATION_TIMEOUT: keyless signing outside CI walks a
                # human through a browser OAuth redirect, which 30 seconds
                # cannot cover.
                timeout=SIGNING_TIMEOUT,
                check=False,
            )

            if result.returncode != 0:
                raise RuntimeError(f"Sigstore signing failed: {result.stderr}")

            logger.info(f"Signature bundle saved: {bundle_path}")

            # Parse bundle for individual components
            bundle_data = json.loads(bundle_path.read_text(encoding="utf-8"))

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
            signature_path = attestation_path_obj.with_suffix(
                attestation_path_obj.suffix + ".sig"
            )
            signature_path.write_text(signature_b64, encoding="utf-8")

            certificate_path = attestation_path_obj.with_suffix(
                attestation_path_obj.suffix + ".crt"
            )
            certificate_path.write_text(certificate_b64, encoding="utf-8")

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
                "rekor_entry": rekor_entry_url,
            }

        except (
            Exception
        ) as e:  # Acceptable: re-raises after logging — signing failure is fatal
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
        except (
            Exception
        ) as e:  # Acceptable: re-raises after logging — Rekor failure is fatal for verification
            logger.error(f"Rekor verification failed: {e}")
            raise
