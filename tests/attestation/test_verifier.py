"""
Tests for attestation verification.

Tests the AttestationVerifier class which handles:
- Multi-hash digest verification
- Cryptographic signature verification
- Tamper detection integration
- Policy checking
"""

import hashlib
import json
import sys
from unittest.mock import MagicMock, patch

from scripts.core.attestation.tamper_detector import (
    TamperIndicator,
    TamperIndicatorType,
    TamperSeverity,
)
from scripts.core.attestation.verifier import AttestationVerifier, VerificationResult


class TestVerifierInitialization:
    """Tests for AttestationVerifier initialization."""

    def test_init_default(self):
        """Test default initialization."""
        verifier = AttestationVerifier()

        assert verifier.enable_tamper_detection is True
        assert verifier.tamper_detector is not None

    def test_init_without_tamper_detection(self):
        """Test initialization with tamper detection disabled."""
        verifier = AttestationVerifier(enable_tamper_detection=False)

        assert verifier.enable_tamper_detection is False
        assert verifier.tamper_detector is None

    def test_init_custom_max_age(self):
        """Test initialization with custom max age."""
        verifier = AttestationVerifier(max_age_days=30)

        assert verifier.tamper_detector.max_age_days == 30

    def test_init_custom_config(self):
        """Test initialization with custom config."""
        config = {"rekor_url": "https://custom-rekor.example.com"}
        verifier = AttestationVerifier(config=config)

        assert verifier.rekor_url == "https://custom-rekor.example.com"


class TestComputeDigest:
    """Tests for digest computation."""

    def test_compute_sha256(self, tmp_path):
        """Test SHA-256 digest computation."""
        verifier = AttestationVerifier()

        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"test content")

        result = verifier._compute_digest(str(test_file), "sha256")

        expected = hashlib.sha256(b"test content").hexdigest()
        assert result == expected

    def test_compute_sha384(self, tmp_path):
        """Test SHA-384 digest computation."""
        verifier = AttestationVerifier()

        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"test content")

        result = verifier._compute_digest(str(test_file), "sha384")

        expected = hashlib.sha384(b"test content").hexdigest()
        assert result == expected

    def test_compute_sha512(self, tmp_path):
        """Test SHA-512 digest computation."""
        verifier = AttestationVerifier()

        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"test content")

        result = verifier._compute_digest(str(test_file), "sha512")

        expected = hashlib.sha512(b"test content").hexdigest()
        assert result == expected

    def test_compute_digest_empty_file(self, tmp_path):
        """Test digest computation for empty file."""
        verifier = AttestationVerifier()

        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")

        result = verifier._compute_digest(str(test_file), "sha256")

        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected


class TestVerifySubjectDigest:
    """Tests for subject digest verification."""

    def test_verify_single_digest_match(self, tmp_path):
        """Test verification with single matching digest."""
        verifier = AttestationVerifier()

        test_file = tmp_path / "subject.json"
        test_file.write_bytes(b'{"test": "data"}')

        expected_sha256 = hashlib.sha256(b'{"test": "data"}').hexdigest()

        ok, error = verifier._verify_subject_digest(
            str(test_file), {"sha256": expected_sha256}
        )

        assert ok is True
        assert error is None

    def test_verify_multiple_digests_match(self, tmp_path):
        """Test verification with multiple matching digests."""
        verifier = AttestationVerifier()

        test_file = tmp_path / "subject.json"
        content = b'{"test": "data"}'
        test_file.write_bytes(content)

        expected_sha256 = hashlib.sha256(content).hexdigest()
        expected_sha384 = hashlib.sha384(content).hexdigest()
        expected_sha512 = hashlib.sha512(content).hexdigest()

        ok, error = verifier._verify_subject_digest(
            str(test_file),
            {
                "sha256": expected_sha256,
                "sha384": expected_sha384,
                "sha512": expected_sha512,
            },
        )

        assert ok is True
        assert error is None

    def test_verify_digest_mismatch(self, tmp_path):
        """Test verification fails with digest mismatch."""
        verifier = AttestationVerifier()

        test_file = tmp_path / "subject.json"
        test_file.write_bytes(b'{"test": "data"}')

        ok, error = verifier._verify_subject_digest(
            str(test_file), {"sha256": "incorrect_hash_value"}
        )

        assert ok is False
        assert error == "Subject digest mismatch"

    def test_verify_digest_with_no_supported_algorithm_is_not_a_pass(self, tmp_path):
        """An attestation naming only unknown algorithms leaves nothing to
        compare, and nothing-compared must not report as verified.

        This is the shape the chunk exists for: `{"sha3_999": "deadbeef"}`
        returned True and `jmo verify` printed "verified successfully" with
        zero digests checked.
        """
        verifier = AttestationVerifier()

        test_file = tmp_path / "subject.json"
        test_file.write_bytes(b'{"test": "data"}')

        ok, error = verifier._verify_subject_digest(
            str(test_file), {"sha3_999": "deadbeef"}
        )

        assert ok is False
        assert error is not None
        assert "sha3_999" in error

    def test_verify_digest_skips_unknown_but_honours_a_known_one(self, tmp_path):
        """A mix still verifies on the algorithm it can compute."""
        verifier = AttestationVerifier()

        test_file = tmp_path / "subject.json"
        content = b'{"test": "data"}'
        test_file.write_bytes(content)

        ok, error = verifier._verify_subject_digest(
            str(test_file),
            {
                "sha3_999": "deadbeef",
                "sha256": hashlib.sha256(content).hexdigest(),
            },
        )

        assert ok is True
        assert error is None

    def test_verify_partial_digest_mismatch(self, tmp_path):
        """Test verification fails if any digest mismatches."""
        verifier = AttestationVerifier()

        test_file = tmp_path / "subject.json"
        content = b'{"test": "data"}'
        test_file.write_bytes(content)

        correct_sha256 = hashlib.sha256(content).hexdigest()

        ok, error = verifier._verify_subject_digest(
            str(test_file),
            {
                "sha256": correct_sha256,  # Correct
                "sha384": "incorrect_hash",  # Incorrect
            },
        )

        assert ok is False
        assert error == "Subject digest mismatch"


class TestVerifySignature:
    """Tests for cryptographic signature verification."""

    @patch("subprocess.run")
    def test_verify_signature_success(self, mock_run, tmp_path):
        """Test successful signature verification."""
        verifier = AttestationVerifier()

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text('{"test": "attestation"}')

        bundle_file = tmp_path / "attestation.json.sigstore.json"
        bundle_file.write_text('{"bundle": "data"}')

        # Mock successful verification
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        ok, detail = verifier._verify_signature(
            str(attestation_file),
            str(bundle_file),
            "you@example.com",
            "https://oauth2.sigstore.dev/auth",
        )

        assert ok is True
        assert detail == ""

        # The command must be one sigstore will actually run. Asserting only
        # that "verify" and "--bundle" appear passed happily over
        # `sigstore verify --bundle ... <file>`, which exits on an argparse
        # error every time because `verify` dispatches to a subcommand.
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == sys.executable, "must use this interpreter, not `python3`"
        assert cmd[1:5] == ["-m", "sigstore", "verify", "identity"]
        assert "--bundle" in cmd
        assert "--cert-identity" in cmd
        assert "--cert-oidc-issuer" in cmd

    @patch("subprocess.run")
    def test_verify_signature_failure(self, mock_run, tmp_path):
        """Test signature verification failure."""
        verifier = AttestationVerifier()

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text('{"test": "attestation"}')

        bundle_file = tmp_path / "bundle.json"
        bundle_file.write_text('{"bundle": "data"}')

        # Mock failed verification
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="Verification failed: invalid signature"
        )

        ok, detail = verifier._verify_signature(
            str(attestation_file),
            str(bundle_file),
            "you@example.com",
            "https://oauth2.sigstore.dev/auth",
        )

        assert ok is False
        # sigstore's own diagnosis is carried out, not collapsed into one
        # generic message: "the bundle is malformed" and "the trust root could
        # not be fetched" are different answers.
        assert "invalid signature" in detail


class TestVerifyMethod:
    """Tests for main verify method."""

    def test_verify_valid_attestation(self, tmp_path):
        """Test verifying valid attestation without signature."""
        verifier = AttestationVerifier(enable_tamper_detection=False)

        # Create subject file
        subject_file = tmp_path / "findings.json"
        content = b'{"findings": []}'
        subject_file.write_bytes(content)

        # Create attestation file
        attestation = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "findings.json",
                    "digest": {"sha256": hashlib.sha256(content).hexdigest()},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {},
                "runDetails": {
                    "builder": {"id": "https://github.com/test/repo"},
                    "metadata": {"finishedOn": "2025-01-01T00:00:00Z"},
                },
            },
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation))

        result = verifier.verify(
            subject_path=str(subject_file), attestation_path=str(attestation_file)
        )

        assert result.is_valid is True
        assert result.subject_name == "findings.json"
        assert result.subject_digest is not None
        assert result.builder_id == "https://github.com/test/repo"
        assert result.build_time == "2025-01-01T00:00:00Z"

    def test_verify_invalid_attestation_type(self, tmp_path):
        """Test verification fails with invalid attestation type."""
        verifier = AttestationVerifier()

        subject_file = tmp_path / "findings.json"
        subject_file.write_bytes(b'{"findings": []}')

        attestation = {
            "_type": "https://invalid.type/v1",  # Invalid type
            "subject": [],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {},
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation))

        result = verifier.verify(
            subject_path=str(subject_file), attestation_path=str(attestation_file)
        )

        assert result.is_valid is False
        assert result.error_message == "Invalid attestation format"

    def test_verify_no_subjects(self, tmp_path):
        """Test verification fails when no subjects in attestation."""
        verifier = AttestationVerifier()

        subject_file = tmp_path / "findings.json"
        subject_file.write_bytes(b'{"findings": []}')

        attestation = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [],  # Empty subjects
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {},
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation))

        result = verifier.verify(
            subject_path=str(subject_file), attestation_path=str(attestation_file)
        )

        assert result.is_valid is False
        assert result.error_message == "No subjects in attestation"

    def test_verify_subject_digest_mismatch(self, tmp_path):
        """Test verification fails when subject digest mismatches."""
        verifier = AttestationVerifier()

        # Create subject file
        subject_file = tmp_path / "findings.json"
        subject_file.write_bytes(b'{"findings": []}')

        # Attestation with incorrect digest
        attestation = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {"name": "findings.json", "digest": {"sha256": "incorrect_digest_here"}}
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {},
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation))

        result = verifier.verify(
            subject_path=str(subject_file), attestation_path=str(attestation_file)
        )

        assert result.is_valid is False
        assert result.error_message == "Subject digest mismatch"
        assert result.tamper_detected is True

    def test_verify_subject_file_not_found(self, tmp_path):
        """Test verification fails when subject file not found."""
        verifier = AttestationVerifier()

        nonexistent_file = tmp_path / "nonexistent.json"

        attestation = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "findings.json", "digest": {"sha256": "abc"}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {},
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation))

        result = verifier.verify(
            subject_path=str(nonexistent_file), attestation_path=str(attestation_file)
        )

        assert result.is_valid is False
        assert "Subject file not found" in result.error_message

    @patch.object(AttestationVerifier, "_verify_signature")
    def test_verify_with_signature_success(self, mock_verify_sig, tmp_path):
        """Test verification with valid signature."""
        verifier = AttestationVerifier(enable_tamper_detection=False)

        # Create files
        subject_file = tmp_path / "findings.json"
        content = b'{"findings": []}'
        subject_file.write_bytes(content)

        attestation = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "findings.json",
                    "digest": {"sha256": hashlib.sha256(content).hexdigest()},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {},
                "runDetails": {"builder": {}, "metadata": {}},
            },
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation))

        signature_file = tmp_path / "signature.sigstore.json"
        signature_file.write_text('{"bundle": "data"}')

        # Mock successful signature verification
        mock_verify_sig.return_value = (True, "")

        result = verifier.verify(
            subject_path=str(subject_file),
            attestation_path=str(attestation_file),
            signature_path=str(signature_file),
            cert_identity="you@example.com",
            cert_oidc_issuer="https://oauth2.sigstore.dev/auth",
        )

        assert result.is_valid is True
        mock_verify_sig.assert_called_once()

    def test_verify_with_bundle_but_no_expected_signer_is_refused(self, tmp_path):
        """A bundle checked against no expected signer proves only that
        somebody signed it, so it must not be accepted as a verification."""
        verifier = AttestationVerifier(enable_tamper_detection=False)

        subject_file = tmp_path / "findings.json"
        content = b'{"findings": []}'
        subject_file.write_bytes(content)

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(
            json.dumps(
                {
                    "_type": "https://in-toto.io/Statement/v0.1",
                    "subject": [
                        {
                            "name": "findings.json",
                            "digest": {"sha256": hashlib.sha256(content).hexdigest()},
                        }
                    ],
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "predicate": {
                        "buildDefinition": {},
                        "runDetails": {"builder": {}, "metadata": {}},
                    },
                }
            )
        )

        signature_file = tmp_path / "signature.sigstore.json"
        signature_file.write_text('{"bundle": "data"}')

        result = verifier.verify(
            subject_path=str(subject_file),
            attestation_path=str(attestation_file),
            signature_path=str(signature_file),
        )

        assert result.is_valid is False
        assert "cert_identity" in (result.error_message or "")

    @patch.object(AttestationVerifier, "_verify_signature")
    def test_verify_with_signature_failure(self, mock_verify_sig, tmp_path):
        """Test verification with invalid signature."""
        verifier = AttestationVerifier(enable_tamper_detection=False)

        subject_file = tmp_path / "findings.json"
        content = b'{"findings": []}'
        subject_file.write_bytes(content)

        attestation = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "findings.json",
                    "digest": {"sha256": hashlib.sha256(content).hexdigest()},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {},
                "runDetails": {"builder": {}, "metadata": {}},
            },
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation))

        signature_file = tmp_path / "signature.sigstore.json"
        signature_file.write_text('{"bundle": "data"}')

        # Mock failed signature verification
        mock_verify_sig.return_value = (False, "the bundle is malformed")

        result = verifier.verify(
            subject_path=str(subject_file),
            attestation_path=str(attestation_file),
            signature_path=str(signature_file),
            cert_identity="you@example.com",
            cert_oidc_issuer="https://oauth2.sigstore.dev/auth",
        )

        assert result.is_valid is False
        assert result.error_message == (
            "Signature verification failed: the bundle is malformed"
        )

    @patch("scripts.core.attestation.verifier.TamperDetector")
    def test_tamper_detection_crash_fails_closed(
        self, mock_tamper_detector_class, tmp_path
    ):
        """A tamper check that raised was logged as a warning and then
        verification continued to `is_valid = True`.

        That turned "this check could not run" into "this check found
        nothing". Measured on the real CLI: rewriting `startedOn` from a
        string to an integer made `.replace()` raise inside the detector, and
        the same attestation flipped from CRITICAL tamper detected to verified
        successfully.
        """
        detector = MagicMock()
        detector.check_all.side_effect = AttributeError(
            "'int' object has no attribute 'replace'"
        )
        mock_tamper_detector_class.return_value = detector

        verifier = AttestationVerifier(enable_tamper_detection=True)

        subject_file = tmp_path / "findings.json"
        content = b'{"findings": []}'
        subject_file.write_bytes(content)

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(
            json.dumps(
                {
                    "_type": "https://in-toto.io/Statement/v0.1",
                    "subject": [
                        {
                            "name": "findings.json",
                            "digest": {"sha256": hashlib.sha256(content).hexdigest()},
                        }
                    ],
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "predicate": {
                        "buildDefinition": {},
                        "runDetails": {"builder": {}, "metadata": {}},
                    },
                }
            )
        )

        result = verifier.verify(
            subject_path=str(subject_file), attestation_path=str(attestation_file)
        )

        assert result.is_valid is False
        assert "could not complete" in (result.error_message or "")

    @patch("scripts.core.attestation.verifier.TamperDetector")
    def test_verify_with_tamper_detection_critical(
        self, mock_tamper_detector_class, tmp_path
    ):
        """Test verification fails with critical tamper indicators."""
        # Create mock tamper detector
        mock_detector = MagicMock()
        critical_indicator = TamperIndicator(
            severity=TamperSeverity.CRITICAL,
            indicator_type=TamperIndicatorType.DIGEST_MISMATCH,
            description="Critical digest mismatch",
            evidence={},
        )
        mock_detector.check_all.return_value = [critical_indicator]
        mock_tamper_detector_class.return_value = mock_detector

        verifier = AttestationVerifier(enable_tamper_detection=True)

        subject_file = tmp_path / "findings.json"
        content = b'{"findings": []}'
        subject_file.write_bytes(content)

        attestation = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "findings.json",
                    "digest": {"sha256": hashlib.sha256(content).hexdigest()},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {},
                "runDetails": {"builder": {}, "metadata": {}},
            },
        }

        attestation_file = tmp_path / "attestation.json"
        attestation_file.write_text(json.dumps(attestation))

        result = verifier.verify(
            subject_path=str(subject_file), attestation_path=str(attestation_file)
        )

        assert result.is_valid is False
        assert result.tamper_detected is True
        assert "CRITICAL tamper detected" in result.error_message
        assert len(result.tamper_indicators) == 1


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_verification_result_defaults(self):
        """Test VerificationResult with defaults."""
        result = VerificationResult(is_valid=False)

        assert result.is_valid is False
        assert result.subject_name is None
        assert result.error_message is None
        assert result.tamper_detected is False
        assert result.tamper_indicators == []

    def test_verification_result_full(self):
        """Test VerificationResult with all fields."""
        indicator = TamperIndicator(
            severity=TamperSeverity.HIGH,
            indicator_type=TamperIndicatorType.SUSPICIOUS_PATTERN,
            description="Test",
            evidence={},
        )

        result = VerificationResult(
            is_valid=True,
            subject_name="findings.json",
            subject_digest="abc123",
            builder_id="https://github.com/test/repo",
            build_time="2025-01-01T00:00:00Z",
            rekor_entry="https://rekor.sigstore.dev/12345",
            tamper_detected=True,
            tamper_indicators=[indicator],
        )

        assert result.is_valid is True
        assert result.subject_name == "findings.json"
        assert result.tamper_detected is True
        assert len(result.tamper_indicators) == 1
