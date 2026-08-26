"""
Tests for attestation CLI commands (Phase 2).

This test module verifies the CLI commands for attestation generation
and verification without signing (signing is tested in Phase 3).

Test Strategy (TDD):
1. Test jmo attest command parsing and execution
2. Test jmo verify command parsing and execution
3. Test attestation output file generation
4. Test verification success/failure scenarios
5. Test tamper detection
6. Test integration with scan arguments
7. Test wizard flow integration
8. Test error handling (missing files, invalid formats)

Coverage Target: 100% (45/45 tests)
"""

import json
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestAttestCommandParsing:
    """Test jmo attest command argument parsing."""

    def test_attest_command_exists(self, monkeypatch):
        """Test that 'attest' subcommand is registered."""
        import sys

        from scripts.cli.jmo import parse_args

        monkeypatch.setattr(sys, "argv", ["jmo", "attest", "findings.json"])
        args = parse_args()
        assert args.cmd == "attest"
        assert args.subject == "findings.json"

    def test_attest_with_output_flag(self, monkeypatch):
        """Test --output flag for custom attestation path."""
        import sys

        from scripts.cli.jmo import parse_args

        monkeypatch.setattr(
            sys,
            "argv",
            ["jmo", "attest", "findings.json", "--output", "custom.att.json"],
        )
        args = parse_args()
        assert args.output == "custom.att.json"

    def test_attest_with_tools_flag(self, monkeypatch):
        """Test --tools flag for specifying tools used."""
        import sys

        from scripts.cli.jmo import parse_args

        monkeypatch.setattr(
            sys,
            "argv",
            ["jmo", "attest", "findings.json", "--tools", "trivy", "semgrep"],
        )
        args = parse_args()
        assert args.tools == ["trivy", "semgrep"]

    def test_attest_with_scan_args_flag(self, monkeypatch):
        """Test --scan-args flag for providing scan context."""
        import sys

        from scripts.cli.jmo import parse_args

        monkeypatch.setattr(
            sys,
            "argv",
            ["jmo", "attest", "findings.json", "--scan-args", "scan_config.json"],
        )
        args = parse_args()
        assert args.scan_args == "scan_config.json"

    def test_attest_with_sign_flag(self, monkeypatch):
        """Test --sign flag for Sigstore signing."""
        import sys

        from scripts.cli.jmo import parse_args

        monkeypatch.setattr(sys, "argv", ["jmo", "attest", "findings.json", "--sign"])
        args = parse_args()
        assert args.sign is True

    def test_attest_with_rekor_flag(self, monkeypatch):
        """Test --rekor flag for transparency log upload."""
        import sys

        from scripts.cli.jmo import parse_args

        monkeypatch.setattr(sys, "argv", ["jmo", "attest", "findings.json", "--rekor"])
        args = parse_args()
        assert args.rekor is True


class TestVerifyCommandParsing:
    """Test jmo verify command argument parsing."""

    def test_verify_command_exists(self, monkeypatch):
        """Test that 'verify' subcommand is registered."""
        import sys

        from scripts.cli.jmo import parse_args

        monkeypatch.setattr(sys, "argv", ["jmo", "verify", "findings.json"])
        args = parse_args()
        assert args.cmd == "verify"
        assert args.subject == "findings.json"

    def test_verify_with_attestation_flag(self, monkeypatch):
        """Test --attestation flag for custom attestation path."""
        import sys

        from scripts.cli.jmo import parse_args

        monkeypatch.setattr(
            sys,
            "argv",
            ["jmo", "verify", "findings.json", "--attestation", "custom.att.json"],
        )
        args = parse_args()
        assert args.attestation == "custom.att.json"

    def test_verify_with_rekor_check_flag(self, monkeypatch):
        """Test --rekor-check flag for transparency log verification."""
        import sys

        from scripts.cli.jmo import parse_args

        monkeypatch.setattr(
            sys, "argv", ["jmo", "verify", "findings.json", "--rekor-check"]
        )
        args = parse_args()
        assert args.rekor_check is True

    def test_verify_rejects_removed_policy_flag(self, monkeypatch):
        """`--policy` was accepted, advertised, and never read.

        `verify()` took a policy_path parameter it referenced nowhere in its
        body, so the flag was a documented verification check that did not
        exist. It is gone rather than silently inert; argparse must now reject
        it (exit 2) instead of accepting it and doing nothing.
        """
        import sys

        from scripts.cli.jmo import parse_args

        monkeypatch.setattr(
            sys, "argv", ["jmo", "verify", "findings.json", "--policy", "policy.yaml"]
        )
        with pytest.raises(SystemExit) as excinfo:
            parse_args()
        assert excinfo.value.code == 2

    def test_verify_signature_flags_parse(self, monkeypatch):
        """The flags that make a signature check possible must exist."""
        import sys

        from scripts.cli.jmo import parse_args

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "jmo",
                "verify",
                "findings.json",
                "--signature",
                "bundle.sigstore.json",
                "--cert-identity",
                "you@example.com",
                "--cert-oidc-issuer",
                "https://oauth2.sigstore.dev/auth",
            ],
        )
        args = parse_args()
        assert args.signature == "bundle.sigstore.json"
        assert args.cert_identity == "you@example.com"
        assert args.cert_oidc_issuer == "https://oauth2.sigstore.dev/auth"


class TestAttestCommandExecution:
    """Test jmo attest command execution."""

    @pytest.fixture
    def sample_findings(self, tmp_path):
        """Create sample findings.json file."""
        findings = {
            "meta": {
                "jmo_version": "1.0.0",
                "profile": "balanced",
                "tools": ["trivy", "semgrep"],
                "target_count": 1,
            },
            "findings": [
                {"id": "fingerprint-abc123", "severity": "HIGH", "tool": "trivy"}
            ],
        }

        findings_path = tmp_path / "findings.json"
        findings_path.write_text(json.dumps(findings))
        return findings_path

    def test_attest_generates_provenance(self, sample_findings):
        """Test that attest command generates provenance."""
        from scripts.cli.jmo import cmd_attest

        args = Namespace(
            subject=str(sample_findings),
            output=None,
            sign=False,
            rekor=False,
            scan_args=None,
            tools=["trivy", "semgrep"],
            human_logs=False,
            log_level="INFO",
        )

        exit_code = cmd_attest(args)

        assert exit_code == 0
        # Check attestation file was created
        attestation_path = Path(str(sample_findings) + ".att.json")
        assert attestation_path.exists()

    def test_attest_creates_custom_output_path(self, sample_findings, tmp_path):
        """Test that attest respects --output flag."""
        from scripts.cli.jmo import cmd_attest

        custom_output = tmp_path / "custom.att.json"

        args = Namespace(
            subject=str(sample_findings),
            output=str(custom_output),
            sign=False,
            rekor=False,
            scan_args=None,
            tools=["trivy"],
            human_logs=False,
            log_level="INFO",
        )

        exit_code = cmd_attest(args)

        assert exit_code == 0
        assert custom_output.exists()

    def test_attest_fails_on_missing_subject(self):
        """A path that does not exist is a usage error (2), not a verdict (1).

        See docs/CLI_REFERENCE.md "Exit Codes": 1 means the command ran and
        answered no; 2 means nothing ran. Attesting a filename that isn't there
        attested nothing.
        """
        from scripts.cli.jmo import cmd_attest

        args = Namespace(
            subject="/nonexistent/findings.json",
            output=None,
            sign=False,
            rekor=False,
            scan_args=None,
            tools=["trivy"],
            human_logs=False,
            log_level="INFO",
        )

        exit_code = cmd_attest(args)

        assert exit_code == 2

    def test_attest_rekor_without_sign_is_a_usage_error(self, sample_findings):
        """`--rekor` alone warned and exited 0, so a CI step asking for a
        transparency-log entry "succeeded" without producing one."""
        from scripts.cli.jmo import cmd_attest

        args = Namespace(
            subject=str(sample_findings),
            output=None,
            sign=False,
            rekor=True,
            scan_args=None,
            tools=["trivy"],
            human_logs=False,
            log_level="INFO",
        )

        assert cmd_attest(args) == 2

    def test_attest_directory_is_a_usage_error_not_a_traceback(self, tmp_path):
        """A directory reached open() and surfaced a raw PermissionError."""
        from scripts.cli.jmo import cmd_attest

        args = Namespace(
            subject=str(tmp_path),
            output=None,
            sign=False,
            rekor=False,
            scan_args=None,
            tools=["trivy"],
            human_logs=False,
            log_level="INFO",
        )

        assert cmd_attest(args) == 2

    def test_attest_loads_scan_args_from_file(self, sample_findings, tmp_path):
        """Test that attest loads scan arguments from JSON file."""
        from scripts.cli.jmo import cmd_attest

        # Create scan args file
        scan_args = {
            "profile_name": "balanced",
            "tools": ["trivy", "semgrep", "trufflehog"],
            "threads": 4,
            "repos": ["repo1", "repo2"],
        }
        scan_args_path = tmp_path / "scan_args.json"
        scan_args_path.write_text(json.dumps(scan_args))

        args = Namespace(
            subject=str(sample_findings),
            output=None,
            sign=False,
            rekor=False,
            scan_args=str(scan_args_path),
            tools=None,  # Should use tools from scan_args
            human_logs=False,
            log_level="INFO",
        )

        exit_code = cmd_attest(args)

        assert exit_code == 0
        # Verify attestation contains scan args
        attestation_path = Path(str(sample_findings) + ".att.json")
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))

        assert (
            attestation["predicate"]["buildDefinition"]["externalParameters"]["profile"]
            == "balanced"
        )
        assert (
            "trivy"
            in attestation["predicate"]["buildDefinition"]["externalParameters"][
                "tools"
            ]
        )

    def test_attest_includes_provenance_structure(self, sample_findings):
        """Test that attestation has correct SLSA provenance structure."""
        from scripts.cli.jmo import cmd_attest

        args = Namespace(
            subject=str(sample_findings),
            output=None,
            sign=False,
            rekor=False,
            scan_args=None,
            tools=["trivy"],
            human_logs=False,
            log_level="INFO",
        )

        exit_code = cmd_attest(args)

        assert exit_code == 0
        attestation_path = Path(str(sample_findings) + ".att.json")
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))

        # Verify in-toto statement structure
        assert attestation["_type"] == "https://in-toto.io/Statement/v0.1"
        assert attestation["predicateType"] == "https://slsa.dev/provenance/v1"
        assert "subject" in attestation
        assert "predicate" in attestation

        # Verify SLSA provenance structure
        predicate = attestation["predicate"]
        assert "buildDefinition" in predicate
        assert "runDetails" in predicate


class TestVerifyCommandExecution:
    """Test jmo verify command execution."""

    @pytest.fixture
    def sample_attestation(self, tmp_path):
        """Create sample attestation and subject."""
        # Create subject file
        findings = {"findings": [{"id": "test", "severity": "HIGH"}]}
        subject_path = tmp_path / "findings.json"
        subject_path.write_text(json.dumps(findings))

        # Generate attestation
        from scripts.core.attestation.provenance import ProvenanceGenerator

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=subject_path,
            profile="balanced",
            tools=["trivy"],
            targets=["repo1"],
        )

        attestation_path = tmp_path / "findings.json.att.json"
        attestation_path.write_text(json.dumps(statement))

        return subject_path, attestation_path

    def test_verify_succeeds_for_valid_attestation(self, sample_attestation):
        """Test that verify succeeds for valid attestation."""
        from scripts.cli.jmo import cmd_verify

        subject_path, attestation_path = sample_attestation

        args = Namespace(
            subject=str(subject_path),
            attestation=str(attestation_path),
            rekor_check=False,
            signature=None,
            cert_identity=None,
            cert_oidc_issuer=None,
            human_logs=False,
            log_level="INFO",
        )

        exit_code = cmd_verify(args)

        assert exit_code == 0  # Verification success

    def test_verify_detects_tampered_subject(self, sample_attestation, tmp_path):
        """Test that verify detects tampered subject file."""
        from scripts.cli.jmo import cmd_verify

        subject_path, attestation_path = sample_attestation

        # Tamper with subject file
        subject_path.write_text('{"findings": [{"modified": true}]}')

        args = Namespace(
            subject=str(subject_path),
            attestation=str(attestation_path),
            rekor_check=False,
            signature=None,
            cert_identity=None,
            cert_oidc_issuer=None,
            human_logs=False,
            log_level="INFO",
        )

        exit_code = cmd_verify(args)

        assert exit_code == 1  # Verification failure (tamper detected)

    def test_verify_fails_on_missing_subject(self):
        """A missing subject is a usage error (2), not a failed verification.

        Returning 1 made "you typo'd the filename" and "this artifact is
        forged" the same signal to a CI gate. See docs/CLI_REFERENCE.md
        "Exit Codes".
        """
        from scripts.cli.jmo import cmd_verify

        args = Namespace(
            subject="/nonexistent/findings.json",
            attestation="/nonexistent/findings.json.att.json",
            rekor_check=False,
            signature=None,
            cert_identity=None,
            cert_oidc_issuer=None,
            human_logs=False,
            log_level="INFO",
        )

        exit_code = cmd_verify(args)

        assert exit_code == 2

    def test_verify_fails_on_missing_attestation(self, tmp_path):
        """No attestation means nothing was verified — a usage error (2)."""
        from scripts.cli.jmo import cmd_verify

        # Create subject but no attestation
        subject_path = tmp_path / "findings.json"
        subject_path.write_text('{"findings": []}')

        args = Namespace(
            subject=str(subject_path),
            attestation=str(tmp_path / "nonexistent.att.json"),
            rekor_check=False,
            signature=None,
            cert_identity=None,
            cert_oidc_issuer=None,
            human_logs=False,
            log_level="INFO",
        )

        exit_code = cmd_verify(args)

        assert exit_code == 2

    def test_verify_uses_default_attestation_path(self, sample_attestation):
        """Test that verify uses <subject>.att.json as default."""
        from scripts.cli.jmo import cmd_verify

        subject_path, attestation_path = sample_attestation

        # Rename attestation to default location
        default_att_path = Path(str(subject_path) + ".att.json")
        attestation_path.rename(default_att_path)

        args = Namespace(
            subject=str(subject_path),
            attestation=None,  # Should use default path
            rekor_check=False,
            signature=None,
            cert_identity=None,
            cert_oidc_issuer=None,
            human_logs=False,
            log_level="INFO",
        )

        exit_code = cmd_verify(args)

        assert exit_code == 0  # Verification success


class TestVerifierClass:
    """Test AttestationVerifier class."""

    def test_verifier_computes_digest(self, tmp_path):
        """Test digest computation for verification."""
        import hashlib

        from scripts.core.attestation.verifier import AttestationVerifier

        # Create test file
        test_file = tmp_path / "test.json"
        test_content = b'{"test": "data"}'
        test_file.write_bytes(test_content)

        verifier = AttestationVerifier()
        digest = verifier._compute_digest(str(test_file))

        # Compare with expected digest
        expected = hashlib.sha256(test_content).hexdigest()
        assert digest == expected

    def test_verifier_detects_digest_mismatch(self, tmp_path):
        """Test that verifier detects digest mismatches."""
        from scripts.core.attestation.verifier import AttestationVerifier

        test_file = tmp_path / "test.json"
        test_file.write_text('{"test": "data"}')

        verifier = AttestationVerifier()

        # Wrong digest should fail verification (multi-hash format)
        ok, error = verifier._verify_subject_digest(
            str(test_file), expected_digests={"sha256": "0" * 64}  # Wrong digest
        )
        assert ok is False
        assert error == "Subject digest mismatch"

    def test_verifier_matches_correct_digest(self, tmp_path):
        """Test that verifier accepts correct digest."""
        import hashlib

        from scripts.core.attestation.verifier import AttestationVerifier

        test_file = tmp_path / "test.json"
        test_content = b'{"test": "data"}'
        test_file.write_bytes(test_content)

        verifier = AttestationVerifier()
        expected_digest = hashlib.sha256(test_content).hexdigest()

        # Unpack: a bare `assert verifier._verify_subject_digest(...)` on the
        # (ok, error) tuple is true for (False, "mismatch") too, so it could
        # not fail.
        ok, error = verifier._verify_subject_digest(
            str(test_file), expected_digests={"sha256": expected_digest}
        )
        assert ok is True
        assert error is None

    def test_verification_result_structure(self):
        """Test VerificationResult dataclass structure."""
        from scripts.core.attestation.verifier import VerificationResult

        result = VerificationResult(
            is_valid=True,
            subject_name="findings.json",
            subject_digest="abc123...",
            builder_id="https://github.com/user/repo",
            build_time="2025-01-03T10:00:00Z",
            rekor_entry="uuid-abc123",
        )

        assert result.is_valid is True
        assert result.subject_name == "findings.json"
        assert result.rekor_entry == "uuid-abc123"
        assert result.tamper_detected is False

    def test_verification_result_with_tamper(self):
        """Test VerificationResult with tamper detection."""
        from scripts.core.attestation.verifier import VerificationResult

        result = VerificationResult(
            is_valid=False, error_message="Digest mismatch", tamper_detected=True
        )

        assert result.is_valid is False
        assert result.tamper_detected is True
        assert result.error_message == "Digest mismatch"


class TestWizardIntegration:
    """Test wizard flow integration for attestation."""

    def test_wizard_prompts_for_attestation_after_scan(self):
        """Test that wizard prompts for attestation after successful scan."""
        # Placeholder for wizard integration (future enhancement)
        # This will be implemented when wizard supports post-scan attestation prompts
        assert True  # Placeholder - wizard integration pending

    def test_wizard_generates_attestation_metadata(self):
        """Test that wizard captures scan metadata for attestation."""
        # This test will verify wizard stores:
        # - Profile used
        # - Tools executed
        # - Targets scanned
        # - Execution context

        # Placeholder for Phase 2 wizard integration
        assert True


class TestAttestationStorage:
    """Test SQLite storage integration for attestations."""

    def test_store_attestation_in_history_db(self):
        """Test storing attestation in SQLite database."""
        from scripts.core.history_db import store_attestation

        attestation = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {},
        }

        scan_id = "scan-abc123"

        with patch("scripts.core.history_db.get_connection") as mock_conn:
            mock_cursor = MagicMock()
            # Mock table exists
            mock_cursor.fetchone.return_value = ("attestations",)
            mock_conn.return_value.cursor.return_value = mock_cursor

            store_attestation(
                scan_id=scan_id, attestation=attestation, rekor_published=False
            )

            # Verify INSERT was called
            assert mock_cursor.execute.call_count >= 2

    def test_load_attestation_from_history_db(self):
        """Test loading attestation from SQLite database."""
        import time

        from scripts.core.history_db import load_attestation

        scan_id = "scan-abc123"

        with patch("scripts.core.history_db.get_connection") as mock_conn:
            mock_cursor = MagicMock()
            mock_cursor.fetchone.return_value = (
                '{"_type": "https://in-toto.io/Statement/v0.1"}',
                None,
                None,
                None,
                0,
                int(time.time()),
                2,
            )
            mock_conn.return_value.cursor.return_value = mock_cursor

            result = load_attestation(scan_id)

            assert result is not None
            assert result["scan_id"] == scan_id


class TestErrorHandling:
    """Test error handling in attestation commands."""

    def test_attest_handles_invalid_json(self, tmp_path):
        """Test attest handles invalid JSON gracefully."""
        from scripts.cli.jmo import cmd_attest

        # Create invalid JSON file
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ invalid json }")

        args = Namespace(
            subject=str(invalid_file),
            output=None,
            sign=False,
            rekor=False,
            scan_args=None,
            tools=["trivy"],
            human_logs=False,
            log_level="INFO",
        )

        # Should not crash, but might succeed with digest of invalid JSON
        # (Attestation is about provenance, not validation)
        exit_code = cmd_attest(args)
        assert exit_code == 0

    def test_verify_handles_invalid_attestation_format(self, tmp_path):
        """Test verify handles invalid attestation format."""
        from scripts.cli.jmo import cmd_verify

        # Create subject
        subject_path = tmp_path / "findings.json"
        subject_path.write_text('{"findings": []}')

        # Create invalid attestation
        attestation_path = tmp_path / "invalid.att.json"
        attestation_path.write_text('{"invalid": "attestation"}')

        args = Namespace(
            subject=str(subject_path),
            attestation=str(attestation_path),
            rekor_check=False,
            signature=None,
            cert_identity=None,
            cert_oidc_issuer=None,
            human_logs=False,
            log_level="INFO",
        )

        exit_code = cmd_verify(args)

        assert exit_code == 1  # Verification failure

    def test_attest_handles_permission_denied(self, tmp_path):
        """Test attest handles permission errors gracefully."""
        from scripts.cli.jmo import cmd_attest

        # Create read-only file
        subject_path = tmp_path / "readonly.json"
        subject_path.write_text('{"findings": []}')
        subject_path.chmod(0o444)  # Read-only

        args = Namespace(
            subject=str(subject_path),
            output=str(tmp_path / "no_permission" / "output.att.json"),
            sign=False,
            rekor=False,
            scan_args=None,
            tools=["trivy"],
            human_logs=False,
            log_level="INFO",
        )

        # Should fail gracefully (no crash)
        exit_code = cmd_attest(args)
        # May succeed depending on OS permissions
        assert isinstance(exit_code, int)


class TestVerifyReportsWhatItDidNotCheck:
    """A verification that never ran must never be reported as a pass.

    `cmd_verify` never passed `signature_path`, so `verify()`'s signature block
    was unreachable from the CLI while `--help` listed "Signature verification
    (if signed)" as one of its checks. A forged `.sigstore.json` sitting beside
    the attestation produced "verified successfully", exit 0, and no mention of
    the bundle at all.
    """

    @pytest.fixture
    def attested(self, tmp_path):
        """A real subject + its real attestation, via the real generator."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        subject = tmp_path / "findings.json"
        subject.write_text(json.dumps({"findings": []}), encoding="utf-8")

        attestation = tmp_path / "findings.json.att.json"
        attestation.write_text(
            json.dumps(
                ProvenanceGenerator().generate(
                    findings_path=subject, profile="fast", tools=[], targets=[]
                )
            ),
            encoding="utf-8",
        )
        return subject, attestation

    @staticmethod
    def _args(subject, attestation, **overrides):
        base = {
            "subject": str(subject),
            "attestation": str(attestation),
            "signature": None,
            "cert_identity": None,
            "cert_oidc_issuer": None,
            "rekor_check": False,
            "human_logs": True,
            "log_level": "INFO",
        }
        base.update(overrides)
        return Namespace(**base)

    def test_unchecked_signature_is_said_out_loud(self, attested, capsys):
        from scripts.cli.jmo import cmd_verify

        subject, attestation = attested
        assert cmd_verify(self._args(subject, attestation)) == 0

        captured = capsys.readouterr()
        assert "NOT CHECKED" in captured.err + captured.out

    def test_forged_bundle_beside_the_attestation_is_not_silently_ignored(
        self, attested, capsys
    ):
        """Before the fix this exited 0 having never opened the bundle. Now the
        bundle is only consulted when a signer is named — and naming one is
        what makes the check happen at all."""
        from scripts.cli.jmo import cmd_verify

        subject, attestation = attested
        bundle = attestation.with_name(attestation.name + ".sigstore.json")
        bundle.write_text("THIS IS NOT A SIGNATURE", encoding="utf-8")

        # No signer named: reported as unchecked, never as verified.
        assert cmd_verify(self._args(subject, attestation)) == 0
        assert "NOT CHECKED" in capsys.readouterr().err

        # Signer named: the bundle is actually read, and it fails.
        code = cmd_verify(
            self._args(
                subject,
                attestation,
                cert_identity="you@example.com",
                cert_oidc_issuer="https://oauth2.sigstore.dev/auth",
            )
        )
        assert code == 1

    def test_high_severity_indicators_reach_the_operator(self, attested, capsys):
        """`result.tamper_indicators` was populated and then displayed nowhere.

        A subject named ../../../etc/passwd and a localhost builder are both
        HIGH, neither fails verification, and neither was printed — so the
        command said "verified successfully" and nothing else.
        """
        from scripts.cli.jmo import cmd_verify

        subject, attestation = attested
        doc = json.loads(attestation.read_bytes().decode("utf-8"))
        doc["predicate"]["runDetails"]["builder"]["id"] = "http://localhost:1337"
        attestation.write_bytes(json.dumps(doc).encode("utf-8"))

        assert cmd_verify(self._args(subject, attestation)) == 0

        output = capsys.readouterr().err
        assert "[HIGH]" in output
        assert "localhost" in output

    def test_clean_attestation_reports_no_indicators(self, attested, capsys):
        """Negative control: the reporter must be capable of staying silent."""
        from scripts.cli.jmo import cmd_verify

        subject, attestation = attested
        assert cmd_verify(self._args(subject, attestation)) == 0
        assert "[HIGH]" not in capsys.readouterr().err

    def test_tampered_subject_still_fails(self, attested):
        """The one check that always worked must keep working."""
        from scripts.cli.jmo import cmd_verify

        subject, attestation = attested
        subject.write_text(json.dumps({"findings": ["injected"]}), encoding="utf-8")

        assert cmd_verify(self._args(subject, attestation)) == 1

    def test_attestation_with_no_verifiable_digest_fails(self, attested):
        """The headline defect: `{"sha3_999": ...}` verified successfully with
        zero digests compared."""
        from scripts.cli.jmo import cmd_verify

        subject, attestation = attested
        doc = json.loads(attestation.read_bytes().decode("utf-8"))
        doc["subject"][0]["digest"] = {"sha3_999": "deadbeef"}
        attestation.write_bytes(json.dumps(doc).encode("utf-8"))

        assert cmd_verify(self._args(subject, attestation)) == 1

    def test_non_string_timestamp_does_not_disable_verification(self, attested):
        """One type change used to flip this attestation from CRITICAL tamper
        detected to verified successfully."""
        from scripts.cli.jmo import cmd_verify

        subject, attestation = attested
        doc = json.loads(attestation.read_bytes().decode("utf-8"))
        doc["predicate"]["runDetails"]["metadata"]["startedOn"] = 99999999999
        attestation.write_bytes(json.dumps(doc).encode("utf-8"))

        assert cmd_verify(self._args(subject, attestation)) == 1
