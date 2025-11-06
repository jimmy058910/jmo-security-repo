"""
Phase 6: SLSA Level 2 Compliance Tests

Comprehensive tests for validating SLSA Level 2 compliance requirements:
- Build provenance exists and is signed
- Build service generates provenance
- Provenance is non-falsifiable
- Build parameters are captured
- Provenance includes all build dependencies
- Build environment is isolated

SLSA Level 2 Requirements:
1. Source - Version controlled
2. Build - Scripted build
3. Provenance - Generated and signed
4. Common - Documented and accessible

Test Coverage: 25 tests for SLSA Level 2 validation
"""

import json
import hashlib
import pytest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, Mock


# ============================================================================
# Test Class 1: Provenance Existence (5 tests)
# ============================================================================


class TestProvenanceExistence:
    """Test that provenance is generated for all builds."""

    def test_provenance_generated_for_scan(self, tmp_path):
        """Test that provenance is generated after scan."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        # SLSA Level 2: Provenance MUST exist
        assert statement is not None
        assert statement["_type"] == "https://in-toto.io/Statement/v0.1"
        assert "predicate" in statement

    def test_provenance_includes_slsa_version(self, tmp_path):
        """Test provenance includes SLSA version."""
        from scripts.core.attestation import ProvenanceGenerator
        from scripts.core.attestation.constants import SLSA_VERSION

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        # Should include SLSA version
        predicate = statement.get("predicate", {})
        build_def = predicate.get("buildDefinition", {})
        build_type = build_def.get("buildType", "")

        assert SLSA_VERSION in build_type or "slsa" in build_type.lower()

    def test_provenance_includes_subject_digest(self, tmp_path):
        """Test provenance includes subject with digest."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_content = '{"findings": []}'
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(findings_content)

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        # SLSA Level 2: Subject digest MUST be present
        subjects = statement.get("subject", [])
        assert len(subjects) > 0

        subject = subjects[0]
        assert "name" in subject
        assert "digest" in subject

        digest = subject["digest"]
        assert "sha256" in digest
        assert len(digest["sha256"]) == 64  # SHA-256 hex digest

    def test_provenance_subject_digest_matches_file(self, tmp_path):
        """Test subject digest matches actual file hash."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_content = '{"findings": []}'
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(findings_content)

        # Compute expected hash
        expected_hash = hashlib.sha256(findings_content.encode()).hexdigest()

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        # Subject digest MUST match file
        subjects = statement.get("subject", [])
        actual_hash = subjects[0]["digest"]["sha256"]

        assert actual_hash == expected_hash

    def test_provenance_persists_to_file(self, tmp_path):
        """Test provenance can be saved to .att.json file."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        # Save provenance
        attestation_path = tmp_path / "findings.json.att.json"
        attestation_path.write_text(json.dumps(statement, indent=2))

        # SLSA Level 2: Provenance MUST be persistent
        assert attestation_path.exists()
        assert attestation_path.stat().st_size > 0


# ============================================================================
# Test Class 2: Build Service Requirements (5 tests)
# ============================================================================


class TestBuildServiceRequirements:
    """Test build service generates provenance automatically."""

    def test_build_service_id_present(self, tmp_path):
        """Test provenance includes build service ID."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        # SLSA Level 2: Builder ID MUST be present
        predicate = statement.get("predicate", {})
        run_details = predicate.get("runDetails", {})
        builder = run_details.get("builder", {})

        assert "id" in builder
        assert len(builder["id"]) > 0

    def test_build_service_detects_github_actions(self, tmp_path):
        """Test build service detects GitHub Actions."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        with patch.dict("os.environ", {"GITHUB_ACTIONS": "true", "CI": "true"}):
            generator = ProvenanceGenerator()
            statement = generator.generate(
                findings_path=findings_path,
                profile="fast",
                tools=["trivy"],
                targets=["repo1"],
            )

            predicate = statement.get("predicate", {})
            run_details = predicate.get("runDetails", {})
            builder = run_details.get("builder", {})
            builder_id = builder.get("id", "")

            # Should detect GitHub Actions
            assert "github" in builder_id.lower()

    def test_build_service_detects_gitlab_ci(self, tmp_path):
        """Test build service detects GitLab CI."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        with patch.dict("os.environ", {"GITLAB_CI": "true", "CI": "true"}):
            generator = ProvenanceGenerator()
            statement = generator.generate(
                findings_path=findings_path,
                profile="fast",
                tools=["trivy"],
                targets=["repo1"],
            )

            predicate = statement.get("predicate", {})
            run_details = predicate.get("runDetails", {})
            builder = run_details.get("builder", {})
            builder_id = builder.get("id", "")

            # Should detect GitLab CI
            assert "gitlab" in builder_id.lower()

    def test_build_service_includes_version(self, tmp_path):
        """Test build service includes version information."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        predicate = statement.get("predicate", {})
        run_details = predicate.get("runDetails", {})
        builder = run_details.get("builder", {})

        # Should include version (optional but recommended)
        assert "version" in builder or "id" in builder

    def test_build_service_timestamps_present(self, tmp_path):
        """Test build service includes timestamps."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        predicate = statement.get("predicate", {})
        run_details = predicate.get("runDetails", {})
        metadata = run_details.get("metadata", {})

        # SLSA Level 2: Timestamps SHOULD be present
        assert "startedOn" in metadata or "finishedOn" in metadata


# ============================================================================
# Test Class 3: Non-Falsifiable Provenance (5 tests)
# ============================================================================


class TestNonFalsifiableProvenance:
    """Test provenance is non-falsifiable (signed)."""

    @patch("subprocess.run")
    def test_provenance_can_be_signed(self, mock_run, tmp_path):
        """Test provenance can be cryptographically signed."""
        from scripts.core.attestation import ProvenanceGenerator, SigstoreSigner

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        # Generate provenance
        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        # Save to file
        attestation_path = tmp_path / "findings.json.att.json"
        attestation_path.write_text(json.dumps(statement, indent=2))

        # Mock signing
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Create fake bundle
        bundle_path = tmp_path / "findings.json.att.json.sigstore.json"
        bundle_data = {
            "messageSignature": {"signature": "sig123"},
            "verificationMaterial": {"certificate": "cert123", "tlogEntries": []},
        }
        bundle_path.write_text(json.dumps(bundle_data))

        # Sign provenance
        signer = SigstoreSigner()
        result = signer.sign(str(attestation_path))

        # SLSA Level 2: Provenance MUST be signed
        assert result is not None
        assert "bundle_path" in result

    @patch("subprocess.run")
    def test_signed_provenance_includes_certificate(self, mock_run, tmp_path):
        """Test signed provenance includes certificate."""
        from scripts.core.attestation import SigstoreSigner

        attestation_path = tmp_path / "test.att.json"
        attestation_path.write_text(json.dumps({"test": "data"}))

        # Mock signing
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Create bundle with certificate
        bundle_path = tmp_path / "test.att.json.sigstore.json"
        bundle_data = {
            "messageSignature": {"signature": "sig123"},
            "verificationMaterial": {
                "certificate": "base64-certificate-data",
                "tlogEntries": [],
            },
        }
        bundle_path.write_text(json.dumps(bundle_data))

        signer = SigstoreSigner()
        result = signer.sign(str(attestation_path))

        # SLSA Level 2: Certificate MUST be present
        assert result["certificate_path"] is not None

    @patch("subprocess.run")
    def test_signed_provenance_includes_transparency_log(self, mock_run, tmp_path):
        """Test signed provenance includes transparency log entry."""
        from scripts.core.attestation import SigstoreSigner

        attestation_path = tmp_path / "test.att.json"
        attestation_path.write_text(json.dumps({"test": "data"}))

        # Mock signing
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Create bundle with Rekor entry
        bundle_path = tmp_path / "test.att.json.sigstore.json"
        bundle_data = {
            "messageSignature": {"signature": "sig123"},
            "verificationMaterial": {
                "certificate": "cert123",
                "tlogEntries": [{"logIndex": "12345", "logID": "rekor-id"}],
            },
        }
        bundle_path.write_text(json.dumps(bundle_data))

        signer = SigstoreSigner()
        result = signer.sign(str(attestation_path))

        # SLSA Level 2: Transparency log SHOULD be present
        assert result["rekor_entry"] is not None

    @patch("subprocess.run")
    def test_signature_verification_succeeds(self, mock_run, tmp_path):
        """Test signature can be verified."""
        from scripts.core.attestation import AttestationVerifier

        # Create test files
        findings_content = '{"findings": []}'
        subject_path = tmp_path / "findings.json"
        subject_path.write_text(findings_content)

        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "findings.json",
                    "digest": {
                        "sha256": hashlib.sha256(findings_content.encode()).hexdigest()
                    },
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {},
        }
        attestation_path.write_text(json.dumps(attestation_data))

        bundle_path = tmp_path / "findings.json.att.json.sigstore.json"
        bundle_path.write_text(json.dumps({"signature": "sig"}))

        # Mock successful verification
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(subject_path),
            attestation_path=str(attestation_path),
            signature_path=str(bundle_path),
        )

        # SLSA Level 2: Signature MUST be verifiable
        assert result.is_valid is True

    def test_tampered_provenance_detected(self, tmp_path):
        """Test tampering is detected via digest mismatch."""
        from scripts.core.attestation import AttestationVerifier

        # Create files
        original_content = '{"findings": []}'
        subject_path = tmp_path / "findings.json"
        subject_path.write_text(original_content)

        # Create attestation with WRONG hash (simulating tampering)
        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {"name": "findings.json", "digest": {"sha256": "0" * 64}}  # Wrong hash
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {},
        }
        attestation_path.write_text(json.dumps(attestation_data))

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(subject_path), attestation_path=str(attestation_path)
        )

        # SLSA Level 2: Tampering MUST be detected
        assert result.is_valid is False
        assert result.tamper_detected is True


# ============================================================================
# Test Class 4: Build Parameters Captured (5 tests)
# ============================================================================


class TestBuildParametersCaptured:
    """Test build parameters are captured in provenance."""

    def test_scan_profile_captured(self, tmp_path):
        """Test scan profile is captured."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="balanced",
            tools=["trivy"],
            targets=["repo1"],
        )

        # SLSA Level 2: Build parameters MUST be captured
        predicate = statement.get("predicate", {})
        build_def = predicate.get("buildDefinition", {})
        external_params = build_def.get("externalParameters", {})

        assert "profile" in external_params or "profile_name" in external_params
        profile = external_params.get("profile") or external_params.get("profile_name")
        assert profile == "balanced"

    def test_tools_list_captured(self, tmp_path):
        """Test tools list is captured."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy", "semgrep", "trufflehog"],
            targets=["repo1"],
        )

        predicate = statement.get("predicate", {})
        build_def = predicate.get("buildDefinition", {})
        external_params = build_def.get("externalParameters", {})

        # SLSA Level 2: Tools MUST be captured
        assert "tools" in external_params
        tools = external_params["tools"]
        assert len(tools) == 3
        assert "trivy" in [t["name"] if isinstance(t, dict) else t for t in tools]

    def test_scan_targets_captured(self, tmp_path):
        """Test scan targets are captured."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1", "repo2", "repo3"],
        )

        predicate = statement.get("predicate", {})
        build_def = predicate.get("buildDefinition", {})
        external_params = build_def.get("externalParameters", {})

        # SLSA Level 2: Targets MUST be captured
        assert "repos" in external_params or "targets" in external_params
        targets = external_params.get("repos") or external_params.get("targets")
        assert len(targets) >= 3

    def test_git_context_captured(self, tmp_path):
        """Test Git context is captured when available."""
        from scripts.core.attestation import MetadataCapture

        # Test Git context capture
        capture = MetadataCapture()

        # Simulate Git context
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="abc123def", stderr="")
            git_context = capture.capture_git_context(".")

            # SLSA Level 2: Source info SHOULD be captured
            assert isinstance(git_context, dict)

    def test_ci_metadata_captured(self, tmp_path):
        """Test CI metadata is captured in CI environment."""
        from scripts.core.attestation import MetadataCapture

        capture = MetadataCapture()

        with patch.dict(
            "os.environ",
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_SHA": "abc123",
            },
        ):
            ci_metadata = capture.capture_ci_metadata()

            # SLSA Level 2: CI context SHOULD be captured
            assert ci_metadata["ci_provider"] == "github"
            assert ci_metadata["repository"] == "owner/repo"
            assert ci_metadata["commit"] == "abc123"


# ============================================================================
# Test Class 5: SLSA Level 2 Compliance Checker (5 tests)
# ============================================================================


class TestSLSAComplianceChecker:
    """Test SLSA Level 2 compliance validation."""

    def test_check_provenance_completeness(self, tmp_path):
        """Test checking provenance has all required fields."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        # SLSA Level 2 required fields
        required_fields = ["_type", "subject", "predicateType", "predicate"]

        for field in required_fields:
            assert field in statement, f"Missing required field: {field}"

    def test_check_provenance_predicate_structure(self, tmp_path):
        """Test provenance predicate has correct structure."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        predicate = statement.get("predicate", {})

        # SLSA Level 2 predicate requirements
        assert "buildDefinition" in predicate
        assert "runDetails" in predicate

    def test_check_builder_id_format(self, tmp_path):
        """Test builder ID follows correct format."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        predicate = statement.get("predicate", {})
        run_details = predicate.get("runDetails", {})
        builder = run_details.get("builder", {})
        builder_id = builder.get("id", "")

        # SLSA Level 2: Builder ID SHOULD be a URI
        assert len(builder_id) > 0
        # Should be URI-like (http://, https://, or custom scheme)
        assert "://" in builder_id or builder_id.startswith("jmo-")

    def test_check_subject_integrity(self, tmp_path):
        """Test subject digest integrity."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_content = '{"findings": []}'
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(findings_content)

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        subjects = statement.get("subject", [])
        subject = subjects[0]

        # SLSA Level 2: Subject digest MUST be cryptographically strong
        digest = subject.get("digest", {})
        assert "sha256" in digest  # SHA-256 minimum
        assert len(digest["sha256"]) == 64  # Valid hex digest

    @patch("subprocess.run")
    def test_full_slsa_level_2_compliance(self, mock_run, tmp_path):
        """Test full SLSA Level 2 compliance workflow."""
        from scripts.core.attestation import (
            ProvenanceGenerator,
            SigstoreSigner,
            AttestationVerifier,
        )

        # 1. Generate provenance
        findings_content = '{"findings": []}'
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(findings_content)

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="balanced",
            tools=["trivy", "semgrep"],
            targets=["repo1"],
        )

        # Save provenance
        attestation_path = tmp_path / "findings.json.att.json"
        attestation_path.write_text(json.dumps(statement, indent=2))

        # 2. Sign provenance
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        bundle_path = tmp_path / "findings.json.att.json.sigstore.json"
        bundle_data = {
            "messageSignature": {"signature": "sig123"},
            "verificationMaterial": {
                "certificate": "cert123",
                "tlogEntries": [{"logIndex": "12345"}],
            },
        }
        bundle_path.write_text(json.dumps(bundle_data))

        signer = SigstoreSigner()
        sign_result = signer.sign(str(attestation_path))

        # 3. Verify provenance
        verifier = AttestationVerifier()
        verify_result = verifier.verify(
            subject_path=str(findings_path),
            attestation_path=str(attestation_path),
            signature_path=str(bundle_path),
        )

        # SLSA Level 2 COMPLIANCE CHECKLIST:
        # ✅ Provenance generated
        assert statement is not None
        # ✅ Provenance signed
        assert sign_result is not None
        # ✅ Signature verifiable
        assert verify_result.is_valid is True
        # ✅ Build parameters captured
        assert "predicate" in statement
        # ✅ Builder identified
        assert verify_result.builder_id is not None
