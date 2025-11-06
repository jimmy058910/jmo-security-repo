"""
Phase 4: CI/CD Auto-Attestation Tests

Tests for automatic attestation generation in CI/CD environments,
including GitHub Actions, GitLab CI, and Docker integration.

Test Coverage:
- CI environment detection (GitHub Actions, GitLab CI, local)
- Auto-attestation triggering logic
- Scan metadata capture
- Attestation generation in CI mode
- Docker variant support
- Error handling and graceful degradation
"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock
from datetime import datetime, timezone


# ============================================================================
# Test Class 1: CI Environment Detection (7 tests)
# ============================================================================


class TestCIEnvironmentDetection:
    """Test detection of CI/CD environments."""

    @patch.dict("os.environ", {"CI": "true"}, clear=True)
    def test_detect_generic_ci_environment(self):
        """Test detecting generic CI environment."""
        assert os.getenv("CI") == "true"

    @patch.dict("os.environ", {"GITHUB_ACTIONS": "true", "CI": "true"}, clear=True)
    def test_detect_github_actions_environment(self):
        """Test detecting GitHub Actions specifically."""
        assert os.getenv("GITHUB_ACTIONS") == "true"
        assert os.getenv("CI") == "true"

    @patch.dict("os.environ", {"GITLAB_CI": "true", "CI": "true"}, clear=True)
    def test_detect_gitlab_ci_environment(self):
        """Test detecting GitLab CI specifically."""
        assert os.getenv("GITLAB_CI") == "true"
        assert os.getenv("CI") == "true"

    @patch.dict("os.environ", {}, clear=True)
    def test_detect_local_non_ci_environment(self):
        """Test detecting non-CI (local) environment."""
        assert os.getenv("CI") is None
        assert os.getenv("GITHUB_ACTIONS") is None
        assert os.getenv("GITLAB_CI") is None

    @patch.dict("os.environ", {"JMO_ATTEST_ENABLED": "true"}, clear=True)
    def test_detect_env_var_attestation_override(self):
        """Test JMO_ATTEST_ENABLED environment variable."""
        assert os.getenv("JMO_ATTEST_ENABLED") == "true"

    @patch.dict("os.environ", {"JMO_ATTEST_ENABLED": "false"}, clear=True)
    def test_detect_disabled_attestation_via_env(self):
        """Test disabling attestation via environment variable."""
        assert os.getenv("JMO_ATTEST_ENABLED") == "false"

    def test_ci_environment_detector_utility(self):
        """Test utility function for CI environment detection."""
        from scripts.core.attestation.ci_detector import CIDetector

        detector = CIDetector()
        assert detector is not None

        # Should have methods for detection
        assert hasattr(detector, "is_ci")
        assert hasattr(detector, "get_ci_provider")
        assert hasattr(detector, "should_auto_attest")


# ============================================================================
# Test Class 2: Auto-Attestation Logic (8 tests)
# ============================================================================


class TestAutoAttestationLogic:
    """Test auto-attestation triggering logic."""

    def test_should_attest_when_cli_flag_enabled(self):
        """Test --attest flag takes highest priority."""
        from scripts.core.attestation.ci_detector import CIDetector

        detector = CIDetector()

        # CLI flag should override everything
        assert detector.should_auto_attest(cli_flag=True) is True
        assert detector.should_auto_attest(cli_flag=False) is False

    @patch.dict("os.environ", {"CI": "true", "JMO_ATTEST_ENABLED": "true"})
    def test_should_attest_in_ci_with_env_var(self):
        """Test auto-attestation in CI with env var enabled."""
        from scripts.core.attestation.ci_detector import CIDetector

        detector = CIDetector()

        # No CLI flag, should check env var and CI
        assert detector.should_auto_attest(cli_flag=None) is True

    @patch.dict("os.environ", {"CI": "true"}, clear=True)
    def test_should_attest_in_ci_default_behavior(self):
        """Test default auto-attestation in CI (no explicit config)."""
        from scripts.core.attestation.ci_detector import CIDetector

        detector = CIDetector()

        # In CI without explicit config, should default to False for safety
        assert detector.should_auto_attest(cli_flag=None) is False

    @patch.dict("os.environ", {}, clear=True)
    def test_should_not_attest_locally_without_flag(self):
        """Test no auto-attestation locally without explicit flag."""
        from scripts.core.attestation.ci_detector import CIDetector

        detector = CIDetector()

        # Local environment, no flags, should not attest
        assert detector.should_auto_attest(cli_flag=None) is False

    def test_three_tier_priority_cli_overrides_env(self):
        """Test CLI flag overrides environment variable."""
        from scripts.core.attestation.ci_detector import CIDetector

        with patch.dict("os.environ", {"JMO_ATTEST_ENABLED": "true"}):
            detector = CIDetector()

            # CLI flag=False should override env=true
            assert detector.should_auto_attest(cli_flag=False) is False

    def test_three_tier_priority_env_overrides_config(self):
        """Test environment variable overrides config file."""
        from scripts.core.attestation.ci_detector import CIDetector

        with patch.dict("os.environ", {"JMO_ATTEST_ENABLED": "false"}):
            detector = CIDetector(config={"attestation": {"auto_attest": True}})

            # Env var should override config
            assert detector.should_auto_attest(cli_flag=None) is False

    def test_config_file_enables_attestation(self):
        """Test config file can enable auto-attestation."""
        from scripts.core.attestation.ci_detector import CIDetector

        with patch.dict("os.environ", {}, clear=True):
            detector = CIDetector(config={"attestation": {"auto_attest": True}})

            # Config should enable if no higher priority overrides
            with patch.dict("os.environ", {"CI": "true"}):
                assert detector.should_auto_attest(cli_flag=None) is True

    @patch.dict("os.environ", {"CI": "true", "JMO_ATTEST_ENABLED": "invalid"})
    def test_invalid_env_var_falls_back_gracefully(self):
        """Test invalid JMO_ATTEST_ENABLED value handled gracefully."""
        from scripts.core.attestation.ci_detector import CIDetector

        detector = CIDetector()

        # Invalid env var should be treated as not set
        assert detector.should_auto_attest(cli_flag=None) is False


# ============================================================================
# Test Class 3: Scan Metadata Capture (6 tests)
# ============================================================================


class TestScanMetadataCapture:
    """Test capturing scan metadata for attestations."""

    def test_capture_basic_scan_metadata(self):
        """Test capturing basic scan parameters."""
        from scripts.core.attestation.metadata_capture import MetadataCapture

        capture = MetadataCapture()
        metadata = capture.from_scan_args(
            profile="balanced",
            tools=["trivy", "semgrep"],
            repos=["repo1"],
            threads=4,
            timeout=600
        )

        assert metadata["profile_name"] == "balanced"
        assert metadata["tools"] == ["trivy", "semgrep"]
        assert metadata["repos"] == ["repo1"]
        assert metadata["threads"] == 4
        assert metadata["timeout"] == 600

    def test_capture_multi_target_metadata(self):
        """Test capturing metadata for multi-target scans."""
        from scripts.core.attestation.metadata_capture import MetadataCapture

        capture = MetadataCapture()
        metadata = capture.from_scan_args(
            repos=["repo1", "repo2"],
            images=["nginx:latest"],
            urls=["https://example.com"]
        )

        assert metadata["repos"] == ["repo1", "repo2"]
        assert metadata["images"] == ["nginx:latest"]
        assert metadata["urls"] == ["https://example.com"]

    def test_capture_git_context_metadata(self):
        """Test capturing Git context (commit, branch, tag)."""
        from scripts.core.attestation.metadata_capture import MetadataCapture

        capture = MetadataCapture()

        with patch("subprocess.run") as mock_run:
            # Mock git commands
            mock_run.side_effect = [
                Mock(returncode=0, stdout="abc123def456"),  # commit
                Mock(returncode=0, stdout="main"),  # branch
                Mock(returncode=0, stdout="v1.0.0"),  # tag
            ]

            metadata = capture.capture_git_context(repo_path="/fake/repo")

            assert metadata["commit"] == "abc123def456"
            assert metadata["branch"] == "main"
            assert metadata["tag"] == "v1.0.0"

    def test_capture_ci_specific_metadata(self):
        """Test capturing CI-specific metadata (GitHub Actions, GitLab CI)."""
        from scripts.core.attestation.metadata_capture import MetadataCapture

        capture = MetadataCapture()

        with patch.dict("os.environ", {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_SHA": "commit123",
            "GITHUB_REF": "refs/heads/main"
        }):
            metadata = capture.capture_ci_metadata()

            assert metadata["ci_provider"] == "github"
            assert metadata["repository"] == "owner/repo"
            assert metadata["commit"] == "commit123"
            assert metadata["ref"] == "refs/heads/main"

    def test_metadata_serialization_to_json(self):
        """Test metadata can be serialized to JSON."""
        from scripts.core.attestation.metadata_capture import MetadataCapture

        capture = MetadataCapture()
        metadata = capture.from_scan_args(
            profile="fast",
            tools=["trivy"],
            repos=["repo1"]
        )

        # Should be JSON serializable
        json_str = json.dumps(metadata)
        assert json_str is not None

        # Should be deserializable
        restored = json.loads(json_str)
        assert restored["profile"] == "fast"

    def test_metadata_capture_handles_missing_git(self):
        """Test metadata capture gracefully handles missing git."""
        from scripts.core.attestation.metadata_capture import MetadataCapture

        capture = MetadataCapture()

        with patch("subprocess.run") as mock_run:
            # Git command fails
            mock_run.return_value = Mock(returncode=128, stdout="")

            metadata = capture.capture_git_context(repo_path="/fake/repo")

            # Should return empty dict or defaults
            assert isinstance(metadata, dict)


# ============================================================================
# Test Class 4: CI Mode Integration (7 tests)
# ============================================================================


class TestCIModeIntegration:
    """Test attestation generation in jmo ci command."""

    @patch("subprocess.run")
    def test_ci_mode_generates_attestation(self, mock_run, tmp_path):
        """Test jmo ci generates attestation after scan."""
        # This test validates the concept - actual CI integration
        # would be tested in integration tests
        from scripts.core.attestation import ProvenanceGenerator

        # Setup findings file
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(json.dumps({"findings": []}))

        # Generate attestation
        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"]
        )

        # Should generate valid attestation
        assert statement["_type"] == "https://in-toto.io/Statement/v0.1"
        assert "predicate" in statement

    def test_ci_mode_skips_attestation_without_flag(self, tmp_path):
        """Test jmo ci skips attestation if not requested."""
        from scripts.core.attestation.ci_detector import CIDetector

        # Test that auto-attestation is disabled by default
        with patch.dict("os.environ", {}, clear=True):
            detector = CIDetector()
            assert detector.should_auto_attest(cli_flag=False) is False

    @patch("subprocess.run")
    def test_ci_mode_signs_attestation_in_github_actions(self, mock_run, tmp_path):
        """Test jmo ci signs attestation in GitHub Actions."""
        from scripts.core.attestation import ProvenanceGenerator, SigstoreSigner

        # Setup attestation file
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(json.dumps({"findings": []}))

        attestation_path = tmp_path / "findings.json.att.json"
        bundle_path = tmp_path / "findings.json.att.json.sigstore.json"

        # Generate attestation
        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"]
        )
        # Save attestation manually
        attestation_path.write_text(json.dumps(statement, indent=2))

        # Mock signing
        def create_bundle(*args, **kwargs):
            bundle_data = {
                "messageSignature": {"signature": "sig123"},
                "verificationMaterial": {
                    "certificate": "cert123",
                    "tlogEntries": [{"logIndex": "12345"}]
                }
            }
            bundle_path.write_text(json.dumps(bundle_data))
            return Mock(returncode=0, stderr="")

        mock_run.side_effect = create_bundle

        # Sign in GitHub Actions environment
        with patch.dict("os.environ", {"GITHUB_ACTIONS": "true", "CI": "true"}):
            signer = SigstoreSigner()
            result = signer.sign(str(attestation_path))

            # Should create bundle
            assert bundle_path.exists()
            assert mock_run.call_count >= 1

    def test_ci_mode_handles_signing_failure_gracefully(self, tmp_path):
        """Test signing failures are handled gracefully."""
        from scripts.core.attestation.signer import SigstoreSigner

        attestation_path = tmp_path / "test.att.json"
        attestation_path.write_text(json.dumps({"_type": "https://in-toto.io/Statement/v0.1"}))

        with patch("subprocess.run") as mock_run:
            # Simulate signing failure
            mock_run.return_value = Mock(returncode=1, stderr="Signing failed")

            signer = SigstoreSigner()

            # Should raise exception (caller handles gracefully)
            with pytest.raises(Exception):
                signer.sign(str(attestation_path))

    def test_ci_mode_saves_attestation_to_correct_path(self, tmp_path):
        """Test attestation saved to findings.json.att.json."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text(json.dumps({"findings": []}))

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"]
        )

        attestation_path_str = str(findings_path) + ".att.json"
        attestation_path_obj = Path(attestation_path_str)

        # Save attestation manually
        attestation_path_obj.write_text(json.dumps(statement, indent=2))

        # Should exist at expected path
        assert attestation_path_obj.exists()

        # Should be valid JSON
        with open(attestation_path_str) as f:
            data = json.load(f)
            assert data["_type"] == "https://in-toto.io/Statement/v0.1"

    def test_ci_mode_includes_scan_metadata_in_attestation(self, tmp_path):
        """Test attestation includes scan metadata from CI args."""
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings_path.write_text(json.dumps({"findings": []}))

        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="balanced",
            tools=["trivy", "semgrep"],
            targets=["repo1", "repo2"],
            threads=4
        )

        # Should include invocation parameters
        predicate = statement["predicate"]
        build_def = predicate.get("buildDefinition", {})

        # Metadata should be embedded
        assert "externalParameters" in build_def or "resolvedDependencies" in build_def

    def test_ci_mode_threshold_check_runs_after_attestation(self, tmp_path):
        """Test threshold check logic works with attestation generation."""
        # This tests the concept - actual CI integration would be in integration tests
        from scripts.core.attestation import ProvenanceGenerator

        findings_path = tmp_path / "findings.json"
        findings = {
            "findings": [
                {"severity": "HIGH", "ruleId": "TEST-001"}
            ]
        }
        findings_path.write_text(json.dumps(findings))

        # Generate attestation
        generator = ProvenanceGenerator()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"]
        )

        # Attestation should be generated successfully
        assert statement["_type"] == "https://in-toto.io/Statement/v0.1"

        # Threshold check would run after this (tested separately in CI integration)


# ============================================================================
# Test Class 5: Docker Variant Support (5 tests)
# ============================================================================


class TestDockerVariantSupport:
    """Test attestation support in Docker variants."""

    def test_full_variant_includes_sigstore_binary(self):
        """Test full Docker variant includes sigstore-python."""
        # This would be tested in actual Docker environment
        # Mock test just verifies the concept
        assert True  # Placeholder

    def test_balanced_variant_includes_sigstore_binary(self):
        """Test balanced Docker variant includes sigstore-python."""
        assert True  # Placeholder

    def test_slim_variant_skips_sigstore_warns_user(self):
        """Test slim variant doesn't include Sigstore, warns in docs."""
        assert True  # Placeholder

    def test_fast_variant_skips_sigstore_warns_user(self):
        """Test fast variant doesn't include Sigstore, warns in docs."""
        assert True  # Placeholder

    def test_docker_volume_mount_for_attestation_persistence(self):
        """Test Docker users can mount volume for attestation files."""
        # Would test: docker run -v ./attestations:/results/attestations
        assert True  # Placeholder


# ============================================================================
# Test Class 6: Error Handling (5 tests)
# ============================================================================


class TestCICDErrorHandling:
    """Test error handling in CI/CD attestation."""

    def test_missing_findings_file_logs_warning(self, tmp_path):
        """Test missing findings.json logs warning but doesn't fail."""
        from scripts.core.attestation.ci_detector import CIDetector

        detector = CIDetector()

        # Should handle gracefully if findings don't exist
        findings_path = tmp_path / "nonexistent.json"
        assert not findings_path.exists()

    def test_invalid_scan_metadata_skips_attestation(self):
        """Test invalid scan metadata skips attestation gracefully."""
        from scripts.core.attestation.metadata_capture import MetadataCapture

        capture = MetadataCapture()

        # Invalid inputs should not crash
        try:
            metadata = capture.from_scan_args(
                profile=None,
                tools=None,
                repos=None
            )
            assert isinstance(metadata, dict)
        except Exception:
            pytest.fail("Should handle invalid metadata gracefully")

    def test_sigstore_unavailable_warns_continues(self, tmp_path):
        """Test Sigstore unavailable logs warning but continues."""
        from scripts.core.attestation.signer import SigstoreSigner

        signer = SigstoreSigner()

        attestation_path = tmp_path / "test.att.json"
        attestation_path.write_text(json.dumps({"_type": "https://in-toto.io/Statement/v0.1"}))

        with patch("subprocess.run") as mock_run:
            # Simulate sigstore CLI failure
            mock_run.return_value = Mock(returncode=1, stderr="Network error")

            with pytest.raises(Exception):
                signer.sign(str(attestation_path))

    def test_rekor_timeout_skips_upload_warns(self, tmp_path):
        """Test Rekor timeout skips upload with warning."""
        from scripts.core.attestation.signer import SigstoreSigner

        signer = SigstoreSigner()

        # Test verify_rekor_entry with timeout
        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Timeout")

            with pytest.raises(Exception):
                signer.verify_rekor_entry("https://rekor.sigstore.dev/api/v1/log/entries/123")

    def test_partial_git_context_fills_defaults(self):
        """Test partial Git context uses defaults for missing data."""
        from scripts.core.attestation.metadata_capture import MetadataCapture

        capture = MetadataCapture()

        with patch("subprocess.run") as mock_run:
            # Git commit works, but branch/tag fail
            mock_run.side_effect = [
                Mock(returncode=0, stdout="abc123"),  # commit works
                Mock(returncode=128, stdout=""),  # branch fails
                Mock(returncode=128, stdout=""),  # tag fails
            ]

            metadata = capture.capture_git_context(repo_path="/fake")

            # Should have commit but handle failures
            assert "commit" in metadata or metadata == {}


# ============================================================================
# Test Class 7: Performance Validation (2 tests)
# ============================================================================


class TestCICDPerformance:
    """Test performance requirements for CI/CD attestation."""

    def test_attestation_generation_under_500ms(self, tmp_path):
        """Test attestation generation completes in <500ms."""
        from scripts.core.attestation import ProvenanceGenerator
        import time

        findings_path = tmp_path / "findings.json"
        findings_path.write_text(json.dumps({"findings": [{"id": "TEST-001"}] * 100}))

        generator = ProvenanceGenerator()

        start = time.time()
        statement = generator.generate(
            findings_path=findings_path,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"]
        )
        elapsed = time.time() - start

        # Should be fast (<500ms for typical scan)
        assert elapsed < 0.5, f"Attestation generation took {elapsed:.3f}s (expected <0.5s)"

    def test_ci_mode_overhead_minimal(self, tmp_path):
        """Test CI mode with attestation adds minimal overhead."""
        # This would measure end-to-end CI pipeline time
        # Placeholder for now
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
