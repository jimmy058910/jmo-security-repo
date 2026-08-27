"""
Attestation verification.

This module provides verification functionality for SLSA attestations,
including tamper detection and digest validation.
"""

import hashlib
import json
import logging
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .constants import (
    REKOR_URL,
    VERIFICATION_TIMEOUT,
)
from .signer import SigstoreSigner, require_sigstore
from .tamper_detector import TamperDetector, TamperIndicator

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of attestation verification."""

    is_valid: bool
    subject_name: str | None = None
    subject_digest: str | None = None
    subject_digest_algorithm: str | None = None
    builder_id: str | None = None
    build_time: str | None = None
    rekor_entry: str | None = None
    error_message: str | None = None
    tamper_detected: bool = False
    tamper_indicators: list[TamperIndicator] = field(default_factory=list)


class AttestationVerifier:
    """Verify attestations and detect tampering."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        enable_tamper_detection: bool = True,
        max_age_days: int = 90,
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
        self.tamper_detector = (
            TamperDetector(max_age_days=max_age_days)
            if enable_tamper_detection
            else None
        )

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
        self, subject_path: str, expected_digests: dict[str, str]
    ) -> tuple[bool, str | None]:
        """
        Verify subject file matches expected digests (multi-hash support).

        Args:
            subject_path: Path to subject file
            expected_digests: Dict of algorithm -> expected digest
                             e.g., {"sha256": "abc123...", "sha384": "def456..."}

        Returns:
            (True, None) if at least one digest was actually compared and every
            comparison matched. (False, reason) otherwise.

        A digest map naming only algorithms this Python cannot compute leaves
        nothing to compare, and a comparison that never ran is not a pass — it
        is a verification that could not be performed. Returning True there
        made `{"sha3_999": "deadbeef"}` verify successfully.
        """
        compared = 0

        for algorithm, expected_digest in expected_digests.items():
            try:
                actual_digest = self._compute_digest(subject_path, algorithm)
            except ValueError:
                logger.warning(f"Unsupported hash algorithm: {algorithm}")
                continue

            compared += 1
            # hexdigest() is always lowercase; in-toto does not mandate a case
            # for hex digest values. Comparing raw made an attestation whose
            # sha256 was written in uppercase fail as TAMPER DETECTED against a
            # subject nothing had touched -- an accusation, aimed at the wrong
            # artifact, over a formatting difference (#950). Only JMo's own
            # generator emits lowercase, so the whole suite missed it.
            #
            # Case and surrounding whitespace are the only things normalised.
            # Neither can make two different digests compare equal, so this
            # narrows what is reported as tampering without widening what
            # verifies.
            if actual_digest.strip().lower() != str(expected_digest).strip().lower():
                logger.error(
                    f"{algorithm.upper()} digest mismatch: {actual_digest} != {expected_digest}"
                )
                return False, "Subject digest mismatch"

        if compared == 0:
            supported = ", ".join(sorted(hashlib.algorithms_available))
            logger.error(
                "No digest could be verified: the attestation names only "
                f"unsupported algorithms ({', '.join(expected_digests)}). "
                f"This Python supports: {supported}"
            )
            return False, (
                "No verifiable digest in attestation (unsupported algorithms: "
                f"{', '.join(expected_digests)})"
            )

        return True, None

    def verify(
        self,
        subject_path: str,
        attestation_path: str,
        signature_path: str | None = None,
        check_rekor: bool = False,
        historical_attestations: list[str] | None = None,
        cert_identity: str | None = None,
        cert_oidc_issuer: str | None = None,
    ) -> VerificationResult:
        """Verify attestation for a subject.

        Args:
            subject_path: Path to subject file (e.g., findings.json)
            attestation_path: Path to attestation file
            signature_path: Optional path to the Sigstore bundle
            check_rekor: Whether to confirm the bundle's Rekor log entry exists.
                Requires signature_path — there is no log index without a bundle.
            historical_attestations: Optional list of historical attestations for tamper detection
            cert_identity: Expected certificate SAN. Required with signature_path:
                keyless signing proves *who* signed, and a bundle checked
                without naming an expected signer proves only that somebody did.
            cert_oidc_issuer: Expected OIDC issuer URL. Required with signature_path.

        Returns:
            VerificationResult with validation status
        """
        result = VerificationResult(is_valid=False)

        # Load attestation
        try:
            with open(attestation_path, encoding="utf-8") as f:
                attestation_data = json.load(f)

            # Parse as InTotoStatement
            if attestation_data.get("_type") != "https://in-toto.io/Statement/v0.1":
                result.error_message = "Invalid attestation format"
                return result

        except (
            Exception
        ) as e:  # Acceptable: attestation file may be corrupted or unreadable
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

        digest_ok, digest_error = self._verify_subject_digest(
            subject_path, subject_digest_obj
        )
        if not digest_ok:
            result.error_message = digest_error
            # Only a genuine mismatch is evidence of tampering. "Nothing could
            # be compared" is a verification that did not run, and saying
            # TAMPER DETECTED there would be as misleading as saying PASS.
            result.tamper_detected = digest_error == "Subject digest mismatch"
            return result

        # Verify cryptographic signature if provided
        if signature_path:
            if not Path(signature_path).exists():
                result.error_message = f"Signature bundle not found: {signature_path}"
                return result

            if not cert_identity or not cert_oidc_issuer:
                result.error_message = (
                    "Signature verification needs cert_identity and "
                    "cert_oidc_issuer — a bundle verified against no expected "
                    "signer proves only that someone signed it"
                )
                return result

            try:
                logger.info("Verifying cryptographic signature...")
                sig_valid, sig_detail = self._verify_signature(
                    attestation_path, signature_path, cert_identity, cert_oidc_issuer
                )
                if not sig_valid:
                    result.error_message = "Signature verification failed"
                    if sig_detail:
                        result.error_message += f": {sig_detail}"
                    return result
                logger.info("✅ Signature verified")
            except (
                Exception
            ) as e:  # Acceptable: sigstore may fail for many reasons — report as verification error
                result.error_message = f"Signature verification error: {e}"
                return result

            if check_rekor:
                rekor_url = self._rekor_entry_url(signature_path)
                if rekor_url is None:
                    result.error_message = (
                        "Rekor check requested but the bundle carries no "
                        "transparency log entry"
                    )
                    return result
                try:
                    if not SigstoreSigner(
                        {"rekor_url": self.rekor_url}
                    ).verify_rekor_entry(rekor_url):
                        result.error_message = (
                            f"Rekor transparency log entry not found: {rekor_url}"
                        )
                        return result
                except (
                    Exception
                ) as e:  # Unreachable log ≠ absent log — say which one happened.
                    result.error_message = f"Rekor check could not complete: {e}"
                    return result
                result.rekor_entry = rekor_url
        elif check_rekor:
            # Asking for a Rekor check with nothing to look up must not be
            # answered with a pass. There is no log index without a bundle.
            result.error_message = (
                "Rekor check requires a signature bundle (pass --signature)"
            )
            return result

        # Run advanced tamper detection if enabled
        if self.enable_tamper_detection and self.tamper_detector:
            try:
                indicators = self.tamper_detector.check_all(
                    subject_path=subject_path,
                    attestation_path=attestation_path,
                    historical_attestations=historical_attestations or [],
                )

                result.tamper_indicators = indicators

                # Check for CRITICAL indicators
                critical_indicators = [
                    ind for ind in indicators if ind.severity.value == "CRITICAL"
                ]

                if critical_indicators:
                    result.tamper_detected = True
                    result.is_valid = False
                    result.error_message = f"CRITICAL tamper detected: {critical_indicators[0].description}"
                    return result

            except (
                Exception
            ) as e:  # A checker that crashed has not passed — fail closed.
                # Graceful degradation is the wrong default in a verifier: it
                # turns "this check could not run" into "this check found
                # nothing". Measured — setting `startedOn` to an integer made
                # `.replace()` raise, and the same attestation flipped from
                # CRITICAL tamper detected to verified successfully.
                logger.error(f"Tamper detection could not complete: {e}")
                result.error_message = f"Tamper detection could not complete: {e}"
                return result

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
        # Use SHA-256 as primary digest for backward compatibility. Only label
        # it SHA-256 when it is one — reporting a sha512 (or an unrecognised
        # algorithm) under a "SHA-256:" heading tells the reader the wrong
        # thing about what was checked.
        result.subject_digest = subject_digest_obj.get("sha256")
        result.subject_digest_algorithm = "sha256"
        if result.subject_digest is None:
            algorithm, value = next(iter(subject_digest_obj.items()))
            result.subject_digest = value
            result.subject_digest_algorithm = algorithm
        result.builder_id = builder_id
        result.build_time = build_time

        logger.info(f"Attestation verified successfully for {subject_name}")
        return result

    @staticmethod
    def _rekor_entry_url(bundle_path: str, rekor_url: str = REKOR_URL) -> str | None:
        """Read the Rekor log index out of a Sigstore bundle.

        Args:
            bundle_path: Path to a Sigstore bundle (.sigstore.json)
            rekor_url: Base URL of the transparency log

        Returns:
            The entry URL, or None if the bundle carries no tlog entry.
        """
        bundle = json.loads(Path(bundle_path).read_bytes().decode("utf-8"))
        entries = bundle.get("verificationMaterial", {}).get("tlogEntries", [])
        if not entries:
            return None
        log_index = entries[0].get("logIndex")
        if log_index is None:
            return None
        return f"{rekor_url}/api/v1/log/entries/{log_index}"

    def _verify_signature(
        self,
        attestation_path: str,
        bundle_path: str,
        cert_identity: str,
        cert_oidc_issuer: str,
    ) -> tuple[bool, str]:
        """
        Verify cryptographic signature using sigstore.

        Args:
            attestation_path: Path to attestation file
            bundle_path: Path to Sigstore bundle (.sigstore.json)
            cert_identity: Expected identity in the certificate's SAN
            cert_oidc_issuer: Expected OIDC issuer URL

        Returns:
            (True, "") if the signature is valid, else (False, sigstore's own
            stderr). The tool's diagnosis is carried out rather than collapsed
            into one message, because "the bundle is malformed" and "the trust
            root could not be fetched" are different answers and only one of
            them is a verdict about the artifact.

        Raises:
            RuntimeError: If sigstore is not importable from this interpreter —
                "the verifier could not run" must not look like "the signature
                is bad".
        """
        require_sigstore()

        try:
            # `sigstore verify` is not a leaf command: it dispatches to
            # `identity` or `github`, and `identity` requires both
            # --cert-identity and --cert-oidc-issuer. Without the subcommand
            # the process exited on an argparse error every single time, which
            # this code reported as "Signature verification failed" — a
            # verifier that can only ever say no is no more usable than one
            # that can only ever say yes.
            #
            # sys.executable, never "python3": a bare "python3" binds to
            # whatever happens to be first on PATH, which on this machine is an
            # unrelated venv that answers "No module named sigstore".
            cmd = [
                sys.executable,
                "-m",
                "sigstore",
                "verify",
                "identity",
                # A bundle carries its own certificate chain and log entry, so
                # verification does not need to reach the network. Without this
                # every check first tried to refresh the TUF trust root and
                # failed there — which is not an answer about the signature.
                "--offline",
                "--bundle",
                bundle_path,
                "--cert-identity",
                cert_identity,
                "--cert-oidc-issuer",
                cert_oidc_issuer,
                attestation_path,
            ]

            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=VERIFICATION_TIMEOUT,
                check=False,
            )

            if result.returncode == 0:
                return True, ""

            # sigstore renders a boxed, line-wrapped report; flatten it and
            # keep the head, which is where its verdict is.
            detail = " ".join((result.stderr or result.stdout or "").split())
            if len(detail) > 300:
                detail = detail[:297] + "..."
            logger.warning(f"Signature verification failed: {detail}")
            return False, detail

        except (
            Exception
        ) as e:  # Acceptable: re-raises after logging — caller handles verification failure
            logger.error(f"Signature verification error: {e}")
            raise
