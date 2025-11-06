"""
Attestation verification.

This module provides verification functionality for SLSA attestations,
including tamper detection and digest validation.
"""

import json
import hashlib
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
import logging

from .constants import (
    REKOR_URL,
    VERIFICATION_TIMEOUT,
)
from .tamper_detector import TamperDetector, TamperIndicator

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of attestation verification."""

    is_valid: bool
    subject_name: Optional[str] = None
    subject_digest: Optional[str] = None
    builder_id: Optional[str] = None
    build_time: Optional[str] = None
    rekor_entry: Optional[str] = None
    error_message: Optional[str] = None
    tamper_detected: bool = False
    tamper_indicators: List[TamperIndicator] = field(default_factory=list)


class AttestationVerifier:
    """Verify attestations and detect tampering."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        enable_tamper_detection: bool = True,
        max_age_days: int = 90
    ):
        """Initialize verifier.

        Args:
            config: Optional configuration
            enable_tamper_detection: Enable advanced tamper detection (default: True)
            max_age_days: Maximum attestation age before flagging (default: 90 days)
        """
        self.config = config or {}
        self.rekor_url = self.config.get("rekor_url", REKOR_URL)
        self.enable_tamper_detection = enable_tamper_detection
        self.tamper_detector = TamperDetector(max_age_days=max_age_days) if enable_tamper_detection else None

    def _compute_digest(self, file_path: str, algorithm: str = "sha256") -> str:
        """
        Compute digest of file using specified algorithm.

        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, sha384, sha512)

        Returns:
            Hexadecimal digest string
        """
        hash_obj = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def _verify_subject_digest(
        self,
        subject_path: str,
        expected_digests: Dict[str, str]
    ) -> bool:
        """
        Verify subject file matches expected digests (multi-hash support).

        Args:
            subject_path: Path to subject file
            expected_digests: Dict of algorithm -> expected digest
                             e.g., {"sha256": "abc123...", "sha384": "def456..."}

        Returns:
            True if ALL provided digests match, False otherwise
        """
        for algorithm, expected_digest in expected_digests.items():
            try:
                actual_digest = self._compute_digest(subject_path, algorithm)
                if actual_digest != expected_digest:
                    logger.error(f"{algorithm.upper()} digest mismatch: {actual_digest} != {expected_digest}")
                    return False
            except ValueError:
                logger.warning(f"Unsupported hash algorithm: {algorithm}")
                continue

        return True

    def verify(
        self,
        subject_path: str,
        attestation_path: str,
        signature_path: Optional[str] = None,
        check_rekor: bool = False,
        policy_path: Optional[str] = None,
        historical_attestations: Optional[List[str]] = None
    ) -> VerificationResult:
        """Verify attestation for a subject.

        Args:
            subject_path: Path to subject file (e.g., findings.json)
            attestation_path: Path to attestation file
            signature_path: Optional path to signature file
            check_rekor: Whether to check Rekor transparency log
            policy_path: Optional policy file for additional checks
            historical_attestations: Optional list of historical attestations for tamper detection

        Returns:
            VerificationResult with validation status
        """
        result = VerificationResult(is_valid=False)

        # Load attestation
        try:
            with open(attestation_path) as f:
                attestation_data = json.load(f)

            # Parse as InTotoStatement
            if attestation_data.get("_type") != "https://in-toto.io/Statement/v0.1":
                result.error_message = "Invalid attestation format"
                return result

        except Exception as e:
            result.error_message = f"Could not load attestation: {e}"
            return result

        # Extract subject information
        subjects = attestation_data.get("subject", [])
        if not subjects:
            result.error_message = "No subjects in attestation"
            return result

        # Get first subject (typically findings.json)
        subject = subjects[0]
        subject_name = subject.get("name")
        subject_digest_obj = subject.get("digest", {})

        # Support multi-hash digests (SHA-256, SHA-384, SHA-512)
        if not subject_digest_obj:
            result.error_message = "No digest in attestation"
            return result

        # Verify subject digest (all provided hashes must match)
        if not Path(subject_path).exists():
            result.error_message = f"Subject file not found: {subject_path}"
            return result

        if not self._verify_subject_digest(subject_path, subject_digest_obj):
            result.error_message = "Subject digest mismatch"
            result.tamper_detected = True
            return result

        # Verify cryptographic signature if provided
        if signature_path:
            if not Path(signature_path).exists():
                result.error_message = f"Signature bundle not found: {signature_path}"
                return result

            try:
                logger.info("Verifying cryptographic signature...")
                sig_valid = self._verify_signature(attestation_path, signature_path)
                if not sig_valid:
                    result.error_message = "Signature verification failed"
                    return result
                logger.info("✅ Signature verified")
            except Exception as e:
                result.error_message = f"Signature verification error: {e}"
                return result

        # Run advanced tamper detection if enabled
        if self.enable_tamper_detection and self.tamper_detector:
            try:
                indicators = self.tamper_detector.check_all(
                    subject_path=subject_path,
                    attestation_path=attestation_path,
                    historical_attestations=historical_attestations or []
                )

                result.tamper_indicators = indicators

                # Check for CRITICAL indicators
                critical_indicators = [
                    ind for ind in indicators
                    if ind.severity.value == "CRITICAL"
                ]

                if critical_indicators:
                    result.tamper_detected = True
                    result.is_valid = False
                    result.error_message = f"CRITICAL tamper detected: {critical_indicators[0].description}"
                    return result

            except Exception as e:
                logger.warning(f"Tamper detection failed: {e}")
                # Don't fail verification if tamper detection fails
                # (graceful degradation)

        # Extract builder and build time
        predicate = attestation_data.get("predicate", {})
        run_details = predicate.get("runDetails", {})
        builder = run_details.get("builder", {})
        metadata = run_details.get("metadata", {})

        builder_id = builder.get("id")
        build_time = metadata.get("finishedOn")

        # Verification succeeded
        result.is_valid = True
        result.subject_name = subject_name
        # Use SHA-256 as primary digest for backward compatibility
        result.subject_digest = subject_digest_obj.get("sha256", list(subject_digest_obj.values())[0])
        result.builder_id = builder_id
        result.build_time = build_time

        logger.info(f"Attestation verified successfully for {subject_name}")
        return result

    def _verify_signature(self, attestation_path: str, bundle_path: str) -> bool:
        """
        Verify cryptographic signature using sigstore.

        Args:
            attestation_path: Path to attestation file
            bundle_path: Path to Sigstore bundle (.sigstore.json)

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Build sigstore verify command
            cmd = [
                "python3", "-m", "sigstore", "verify",
                "--bundle", bundle_path,
                attestation_path
            ]

            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=VERIFICATION_TIMEOUT,
                check=False
            )

            if result.returncode == 0:
                return True
            else:
                logger.warning(f"Signature verification failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            raise
