"""
Phase 5: Verification & Tamper Detection Tests

Comprehensive tests for advanced attestation verification including:
- Multi-hash digest verification (SHA-256, SHA-384, SHA-512)
- Timestamp anomaly detection
- Builder consistency checks
- Tool version rollback detection
- Suspicious pattern detection
- Attack scenario simulation

Test Coverage: 40 tests for robust verification and tamper detection
"""

import json
import hashlib
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, Mock

from scripts.core.attestation.tamper_detector import TamperSeverity, TamperIndicatorType


# ============================================================================
# Test Class 1: Multi-Hash Digest Verification (6 tests)
# ============================================================================


class TestMultiHashDigestVerification:
    """Test verification with multiple hash algorithms (SHA-256, SHA-384, SHA-512)."""

    def test_verify_with_sha256_digest(self, tmp_path):
        """Test verification with SHA-256 digest."""
        from scripts.core.attestation.verifier import AttestationVerifier

        # Create subject file
        findings_content = '{"findings": []}'
        subject_path = tmp_path / "findings.json"
        subject_path.write_text(findings_content)

        # Compute SHA-256
        sha256_hash = hashlib.sha256(findings_content.encode()).hexdigest()

        # Create attestation
        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {"sha256": sha256_hash}
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(subject_path),
            attestation_path=str(attestation_path)
        )

        assert result.is_valid is True
        assert result.subject_digest == sha256_hash

    def test_verify_with_multiple_digests(self, tmp_path):
        """Test verification with SHA-256, SHA-384, SHA-512 (SLSA best practice)."""
        from scripts.core.attestation.verifier import AttestationVerifier

        findings_content = '{"findings": []}'
        subject_path = tmp_path / "findings.json"
        subject_path.write_text(findings_content)

        # Compute all three hashes
        sha256_hash = hashlib.sha256(findings_content.encode()).hexdigest()
        sha384_hash = hashlib.sha384(findings_content.encode()).hexdigest()
        sha512_hash = hashlib.sha512(findings_content.encode()).hexdigest()

        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {
                    "sha256": sha256_hash,
                    "sha384": sha384_hash,
                    "sha512": sha512_hash
                }
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(subject_path),
            attestation_path=str(attestation_path)
        )

        assert result.is_valid is True

    def test_verify_digest_mismatch_sha256(self, tmp_path):
        """Test detecting SHA-256 digest mismatch (tamper detection)."""
        from scripts.core.attestation.verifier import AttestationVerifier

        subject_path = tmp_path / "findings.json"
        subject_path.write_text('{"findings": []}')

        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {"sha256": "0" * 64}  # Wrong hash
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(subject_path),
            attestation_path=str(attestation_path)
        )

        assert result.is_valid is False
        assert result.tamper_detected is True
        assert "digest mismatch" in result.error_message.lower()

    def test_verify_partial_digest_match(self, tmp_path):
        """Test that all provided digests must match."""
        from scripts.core.attestation.verifier import AttestationVerifier

        findings_content = '{"findings": []}'
        subject_path = tmp_path / "findings.json"
        subject_path.write_text(findings_content)

        sha256_hash = hashlib.sha256(findings_content.encode()).hexdigest()

        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {
                    "sha256": sha256_hash,  # Correct
                    "sha512": "0" * 128  # Wrong
                }
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(subject_path),
            attestation_path=str(attestation_path)
        )

        # Should fail if any digest mismatches
        assert result.is_valid is False

    def test_verify_missing_subject_file(self, tmp_path):
        """Test handling missing subject file."""
        from scripts.core.attestation.verifier import AttestationVerifier

        subject_path = tmp_path / "nonexistent.json"

        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {"sha256": "abc123"}
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(subject_path),
            attestation_path=str(attestation_path)
        )

        assert result.is_valid is False

    def test_verify_corrupted_attestation_file(self, tmp_path):
        """Test handling corrupted attestation JSON."""
        from scripts.core.attestation.verifier import AttestationVerifier

        subject_path = tmp_path / "findings.json"
        subject_path.write_text('{"findings": []}')

        attestation_path = tmp_path / "findings.json.att.json"
        attestation_path.write_text("INVALID JSON{{{")

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(subject_path),
            attestation_path=str(attestation_path)
        )

        assert result.is_valid is False
        assert "could not load" in result.error_message.lower()


# ============================================================================
# Test Class 2: Timestamp Anomaly Detection (7 tests)
# ============================================================================


class TestTimestampAnomalyDetection:
    """Test detection of suspicious timestamp anomalies."""

    def test_detect_future_timestamp(self, tmp_path):
        """Test detecting attestation with future timestamp."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        # Create attestation with future timestamp
        future_time = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": future_time,
                        "finishedOn": future_time
                    }
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_timestamp_anomalies(str(attestation_path))

        # Should detect future timestamp
        assert len(indicators) > 0
        assert any("future" in ind.description.lower() for ind in indicators)

    def test_detect_impossible_duration(self, tmp_path):
        """Test detecting impossibly long build duration."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        base_time = datetime.now(timezone.utc) - timedelta(hours=50)
        start_time = base_time.isoformat()
        # 48 hour build (default max: 24h)
        finish_time = (base_time + timedelta(hours=48)).isoformat()

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": start_time,
                        "finishedOn": finish_time
                    }
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_timestamp_anomalies(str(attestation_path))

        # Should detect suspiciously long duration
        assert len(indicators) > 0
        assert any("duration" in ind.description.lower() for ind in indicators)

    def test_detect_finish_before_start(self, tmp_path):
        """Test detecting finish time before start time."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        base_time = datetime.now(timezone.utc)
        start_time = base_time.isoformat()
        finish_time = (base_time - timedelta(hours=1)).isoformat()

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": start_time,
                        "finishedOn": finish_time
                    }
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_timestamp_anomalies(str(attestation_path))

        assert len(indicators) > 0
        # Finish before start is CRITICAL severity
        assert any(ind.severity == TamperSeverity.CRITICAL for ind in indicators)

    def test_detect_very_old_attestation(self, tmp_path):
        """Test detecting attestation created years ago (stale)."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        old_time = (datetime.now(timezone.utc) - timedelta(days=365 * 2)).isoformat()

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": old_time,
                        "finishedOn": old_time
                    }
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_timestamp_anomalies(str(attestation_path))

        # Should warn about stale attestation
        assert len(indicators) > 0
        assert any("stale" in ind.description.lower() or "old" in ind.description.lower() for ind in indicators)

    def test_accept_valid_timestamps(self, tmp_path):
        """Test accepting valid recent timestamps."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        start_time = base_time.isoformat()
        finish_time = (base_time + timedelta(minutes=2)).isoformat()

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": start_time,
                        "finishedOn": finish_time
                    }
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_timestamp_anomalies(str(attestation_path))

        # Should NOT detect anomalies
        assert len(indicators) == 0

    def test_handle_missing_timestamps(self, tmp_path):
        """Test handling attestation with missing timestamps."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {"runDetails": {}}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_timestamp_anomalies(str(attestation_path))

        # Should handle gracefully (may warn but not crash)
        assert isinstance(indicators, list)

    def test_detect_timezone_manipulation(self, tmp_path):
        """Test detecting timezone manipulation attempts."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        # Create timestamp with suspicious timezone offset
        base_time = datetime.now(timezone.utc)
        # Manipulated timestamp (claims to be from far future timezone)
        manipulated_time = base_time.replace(tzinfo=timezone(timedelta(hours=20))).isoformat()

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": manipulated_time,
                        "finishedOn": manipulated_time
                    }
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_timestamp_anomalies(str(attestation_path))

        # May detect suspicious timezone (optional advanced check)
        assert isinstance(indicators, list)


# ============================================================================
# Test Class 3: Builder Consistency Checks (6 tests)
# ============================================================================


class TestBuilderConsistencyChecks:
    """Test builder consistency across attestations."""

    def test_detect_builder_id_change(self, tmp_path):
        """Test detecting builder ID change across attestations."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        # Historical attestation
        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "builder": {"id": "https://github.com/actions/runner"}
                }
            }
        }
        historical_path.write_text(json.dumps(historical_data))

        # Current attestation with different builder
        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {
                "runDetails": {
                    "builder": {"id": "https://malicious-ci.example.com/builder"}
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_builder_consistency(
            str(current_path),
            [str(historical_path)]
        )

        assert len(indicators) > 0
        assert any("builder" in ind.description.lower() for ind in indicators)

    def test_accept_consistent_builder(self, tmp_path):
        """Test accepting consistent builder across attestations."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        builder_id = "https://github.com/actions/runner"

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "builder": {"id": builder_id}
                }
            }
        }
        historical_path.write_text(json.dumps(historical_data))

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {
                "runDetails": {
                    "builder": {"id": builder_id}
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_builder_consistency(
            str(current_path),
            [str(historical_path)]
        )

        # Should NOT flag consistent builder
        builder_changes = [ind for ind in indicators if "builder" in ind.description.lower()]
        assert len(builder_changes) == 0

    def test_detect_ci_platform_change(self, tmp_path):
        """Test detecting CI platform change (GitHub → GitLab)."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "builder": {"id": "https://github.com/actions/runner"}
                }
            }
        }
        historical_path.write_text(json.dumps(historical_data))

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {
                "runDetails": {
                    "builder": {"id": "https://gitlab.com/gitlab-org/gitlab-runner"}
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_builder_consistency(
            str(current_path),
            [str(historical_path)]
        )

        assert len(indicators) > 0
        # Builder ID change is CRITICAL severity
        assert any(ind.severity == TamperSeverity.CRITICAL for ind in indicators)

    def test_handle_missing_builder_info(self, tmp_path):
        """Test handling attestations with missing builder info."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {"runDetails": {}}
        }
        historical_path.write_text(json.dumps(historical_data))

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {"runDetails": {}}
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_builder_consistency(
            str(current_path),
            [str(historical_path)]
        )

        # Should handle gracefully
        assert isinstance(indicators, list)

    def test_multiple_historical_attestations(self, tmp_path):
        """Test checking consistency across multiple historical attestations."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        builder_id = "https://github.com/actions/runner"

        # Create 3 historical attestations with same builder
        historical_paths = []
        for i in range(3):
            path = tmp_path / f"historical_{i}.att.json"
            data = {
                "_type": "https://in-toto.io/Statement/v0.1",
                "subject": [{"name": "test", "digest": {"sha256": f"hash{i}"}}],
                "predicate": {
                    "runDetails": {
                        "builder": {"id": builder_id}
                    }
                }
            }
            path.write_text(json.dumps(data))
            historical_paths.append(str(path))

        # Current with different builder
        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "new"}}],
            "predicate": {
                "runDetails": {
                    "builder": {"id": "https://suspicious.example.com/builder"}
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_builder_consistency(
            str(current_path),
            historical_paths
        )

        # Should detect deviation from established pattern
        assert len(indicators) > 0

    def test_builder_version_change_warning(self, tmp_path):
        """Test warning on builder version change (not necessarily malicious)."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/actions/runner",
                        "version": {"github-runner": "2.300.0"}
                    }
                }
            }
        }
        historical_path.write_text(json.dumps(historical_data))

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/actions/runner",
                        "version": {"github-runner": "2.301.0"}
                    }
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_builder_consistency(
            str(current_path),
            [str(historical_path)]
        )

        # May warn about version change (LOW severity)
        version_warnings = [ind for ind in indicators if ind.severity == "LOW"]
        # Version changes are expected, should be LOW or no warning
        assert all(ind.severity in ["LOW", "INFO"] for ind in indicators if "version" in ind.description.lower())


# ============================================================================
# Test Class 4: Tool Version Rollback Detection (5 tests)
# ============================================================================


class TestToolVersionRollbackDetection:
    """Test detection of suspicious tool version rollbacks."""

    def test_detect_tool_version_downgrade(self, tmp_path):
        """Test detecting tool version downgrade (potential rollback attack)."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.45.0"}
                    ]
                }
            }
        }
        historical_path.write_text(json.dumps(historical_data))

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.40.0"}  # Downgrade
                    ]
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_tool_rollback(
            str(current_path),
            [str(historical_path)]
        )

        assert len(indicators) > 0
        assert any("rollback" in ind.description.lower() or "downgrade" in ind.description.lower() for ind in indicators)

    def test_accept_tool_version_upgrade(self, tmp_path):
        """Test accepting legitimate tool version upgrades."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.40.0"}
                    ]
                }
            }
        }
        historical_path.write_text(json.dumps(historical_data))

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.45.0"}  # Upgrade (OK)
                    ]
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_tool_rollback(
            str(current_path),
            [str(historical_path)]
        )

        # Should NOT flag upgrades
        rollback_indicators = [ind for ind in indicators if "rollback" in ind.description.lower()]
        assert len(rollback_indicators) == 0

    def test_detect_critical_tool_rollback(self, tmp_path):
        """Test high-severity alert for critical tool rollbacks (trivy, semgrep)."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.45.0"}
                    ]
                }
            }
        }
        historical_path.write_text(json.dumps(historical_data))

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.30.0"}  # Major downgrade
                    ]
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_tool_rollback(
            str(current_path),
            [str(historical_path)]
        )

        # Critical tool rollback should be CRITICAL severity (trivy is a critical tool)
        assert any(ind.severity == TamperSeverity.CRITICAL for ind in indicators)

    def test_handle_missing_tool_versions(self, tmp_path):
        """Test handling attestations missing tool version info."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {"buildDefinition": {}}
        }
        historical_path.write_text(json.dumps(historical_data))

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {"buildDefinition": {}}
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_tool_rollback(
            str(current_path),
            [str(historical_path)]
        )

        # Should handle gracefully
        assert isinstance(indicators, list)

    def test_detect_multiple_tool_rollbacks(self, tmp_path):
        """Test detecting multiple simultaneous tool rollbacks (coordinated attack)."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.45.0"},
                        {"name": "semgrep", "version": "1.50.0"}
                    ]
                }
            }
        }
        historical_path.write_text(json.dumps(historical_data))

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.30.0"},  # Rollback
                        {"name": "semgrep", "version": "1.30.0"}  # Rollback
                    ]
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_tool_rollback(
            str(current_path),
            [str(historical_path)]
        )

        # Should detect both rollbacks
        assert len(indicators) >= 2


# ============================================================================
# Test Class 5: Suspicious Pattern Detection (6 tests)
# ============================================================================


class TestSuspiciousPatternDetection:
    """Test detection of various suspicious patterns in attestations."""

    def test_detect_empty_findings_with_many_tools(self, tmp_path):
        """Test detecting empty findings despite running many tools."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')  # Empty

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {"sha256": hashlib.sha256(b'{"findings": []}').hexdigest()}
            }],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy"},
                        {"name": "semgrep"},
                        {"name": "trufflehog"},
                        {"name": "checkov"},
                        {"name": "bandit"}
                    ]
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_suspicious_patterns(
            str(findings_path),
            str(attestation_path)
        )

        # May warn about suspicious empty results
        assert isinstance(indicators, list)

    def test_detect_findings_count_mismatch(self, tmp_path):
        """Test detecting mismatch between reported and actual findings count."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": [{"id": "1"}, {"id": "2"}]}')  # 2 findings

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {"sha256": hashlib.sha256(b'{"findings": [{"id": "1"}, {"id": "2"}]}').hexdigest()}
            }],
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "findings_count": 100  # Claims 100 but file has 2
                    }
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_suspicious_patterns(
            str(findings_path),
            str(attestation_path)
        )

        # Should detect mismatch
        assert len(indicators) > 0

    def test_detect_unusual_subject_name(self, tmp_path):
        """Test detecting unusual subject file names."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        findings_path = tmp_path / "totally_legit_findings.json"
        findings_path.write_text('{"findings": []}')

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "../../../etc/passwd",  # Path traversal attempt
                "digest": {"sha256": "abc123"}
            }],
            "predicate": {}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_suspicious_patterns(
            str(findings_path),
            str(attestation_path)
        )

        # Should detect path traversal
        assert len(indicators) > 0
        assert any(ind.severity == TamperSeverity.HIGH for ind in indicators)

    def test_detect_missing_required_fields(self, tmp_path):
        """Test detecting missing required SLSA fields."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "findings.json", "digest": {"sha256": "abc123"}}],
            # Missing predicate entirely
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_suspicious_patterns(
            str(findings_path),
            str(attestation_path)
        )

        # Should detect missing required fields
        assert len(indicators) > 0

    def test_detect_suspicious_builder_patterns(self, tmp_path):
        """Test detecting suspicious builder patterns (localhost, private IPs)."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "findings.json", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "builder": {"id": "http://localhost:8080/builder"}  # Suspicious
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_suspicious_patterns(
            str(findings_path),
            str(attestation_path)
        )

        # Should warn about localhost builder
        assert len(indicators) > 0

    def test_accept_normal_attestation(self, tmp_path):
        """Test accepting normal, well-formed attestation."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        findings_content = '{"findings": [{"id": "1", "severity": "HIGH"}]}'
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(findings_content)

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {"sha256": hashlib.sha256(findings_content.encode()).hexdigest()}
            }],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [{"name": "trivy", "version": "0.45.0"}]
                },
                "runDetails": {
                    "builder": {"id": "https://github.com/actions/runner"}
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_suspicious_patterns(
            str(findings_path),
            str(attestation_path)
        )

        # Should NOT detect issues
        high_severity = [ind for ind in indicators if ind.severity == TamperSeverity.HIGH]
        assert len(high_severity) == 0


# ============================================================================
# Test Class 6: Attack Scenario Simulation (6 tests)
# ============================================================================


class TestAttackScenarioSimulation:
    """Test defense against real-world attack scenarios."""

    def test_defend_against_file_substitution_attack(self, tmp_path):
        """Test detecting file substitution after attestation."""
        from scripts.core.attestation.verifier import AttestationVerifier

        # Original file
        original_content = '{"findings": []}'
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(original_content)

        # Create valid attestation
        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {"sha256": hashlib.sha256(original_content.encode()).hexdigest()}
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        # Attacker substitutes file
        findings_path.write_text('{"findings": []}')  # Same content but potentially different

        # Actually different content to simulate attack
        malicious_content = '{"findings": [], "backdoor": true}'
        findings_path.write_text(malicious_content)

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(findings_path),
            attestation_path=str(attestation_path)
        )

        # Should detect tampering
        assert result.is_valid is False
        assert result.tamper_detected is True

    def test_defend_against_replay_attack(self, tmp_path):
        """Test detecting replay attack with old attestation."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        # Old attestation from 2 years ago
        old_time = (datetime.now(timezone.utc) - timedelta(days=730)).isoformat()

        attestation_path = tmp_path / "old.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "findings.json", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": old_time,
                        "finishedOn": old_time
                    }
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_timestamp_anomalies(str(attestation_path))

        # Should warn about stale attestation
        assert len(indicators) > 0

    def test_defend_against_tool_bypass_attack(self, tmp_path):
        """Test detecting tool bypass (running older vulnerable tool version)."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.45.0"}  # Current
                    ]
                }
            }
        }
        historical_path.write_text(json.dumps(historical_data))

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"name": "trivy", "version": "0.20.0"}  # Vulnerable old version
                    ]
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_tool_rollback(
            str(current_path),
            [str(historical_path)]
        )

        # Should detect suspicious rollback
        assert len(indicators) > 0

    def test_defend_against_builder_impersonation(self, tmp_path):
        """Test detecting builder impersonation attack."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "builder": {"id": "https://github.com/actions/runner"}
                }
            }
        }
        historical_path.write_text(json.dumps(historical_data))

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {
                "runDetails": {
                    # Typosquatting attack
                    "builder": {"id": "https://github.com/actlons/runner"}
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()
        indicators = detector.check_builder_consistency(
            str(current_path),
            [str(historical_path)]
        )

        # Should detect builder change
        assert len(indicators) > 0

    def test_defend_against_timestamp_manipulation(self, tmp_path):
        """Test detecting timestamp manipulation attack."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        base_time = datetime.now(timezone.utc)
        # Attacker claims scan finished before it started
        start_time = base_time.isoformat()
        finish_time = (base_time - timedelta(hours=1)).isoformat()

        attestation_path = tmp_path / "test.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "startedOn": start_time,
                        "finishedOn": finish_time
                    }
                }
            }
        }
        attestation_path.write_text(json.dumps(attestation_data))

        detector = TamperDetector()
        indicators = detector.check_timestamp_anomalies(str(attestation_path))

        # Should detect impossible timestamps (finish before start is CRITICAL)
        assert len(indicators) > 0
        assert any(ind.severity == TamperSeverity.CRITICAL for ind in indicators)

    def test_defend_against_coordinated_attack(self, tmp_path):
        """Test detecting coordinated attack (multiple indicators)."""
        from scripts.core.attestation.tamper_detector import TamperDetector

        historical_path = tmp_path / "historical.att.json"
        historical_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [{"name": "trivy", "version": "0.45.0"}]
                },
                "runDetails": {
                    "builder": {"id": "https://github.com/actions/runner"}
                }
            }
        }
        historical_path.write_text(json.dumps(historical_data))

        # Coordinated attack: rollback + builder change + timestamp manipulation
        base_time = datetime.now(timezone.utc)
        future_time = (base_time + timedelta(days=1)).isoformat()

        current_path = tmp_path / "current.att.json"
        current_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "def456"}}],
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [{"name": "trivy", "version": "0.20.0"}]  # Rollback
                },
                "runDetails": {
                    "builder": {"id": "http://localhost:8080/builder"},  # Suspicious builder
                    "metadata": {
                        "startedOn": future_time,  # Future timestamp
                        "finishedOn": future_time
                    }
                }
            }
        }
        current_path.write_text(json.dumps(current_data))

        detector = TamperDetector()

        # Check all indicators
        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": []}')

        all_indicators = []
        all_indicators.extend(detector.check_timestamp_anomalies(str(current_path)))
        all_indicators.extend(detector.check_builder_consistency(str(current_path), [str(historical_path)]))
        all_indicators.extend(detector.check_tool_rollback(str(current_path), [str(historical_path)]))
        all_indicators.extend(detector.check_suspicious_patterns(str(findings_path), str(current_path)))

        # Should detect multiple indicators (HIGH severity)
        assert len(all_indicators) >= 3
        assert any(ind.severity == TamperSeverity.HIGH for ind in all_indicators)


# ============================================================================
# Test Class 7: Integration with Phase 3 Verification (4 tests)
# ============================================================================


class TestVerificationIntegration:
    """Test integration between tamper detection and attestation verification."""

    def test_full_verification_pipeline(self, tmp_path):
        """Test complete verification pipeline with all checks."""
        from scripts.core.attestation.verifier import AttestationVerifier

        findings_content = '{"findings": []}'
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(findings_content)

        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {"sha256": hashlib.sha256(findings_content.encode()).hexdigest()}
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(findings_path),
            attestation_path=str(attestation_path)
        )

        assert result.is_valid is True

    def test_verification_with_tamper_detection(self, tmp_path):
        """Test verification catches tampering."""
        from scripts.core.attestation.verifier import AttestationVerifier

        findings_path = tmp_path / "findings.json"
        findings_path.write_text('{"findings": [], "tampered": true}')

        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {"sha256": "0" * 64}  # Wrong
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(findings_path),
            attestation_path=str(attestation_path)
        )

        assert result.is_valid is False
        assert result.tamper_detected is True

    @patch("subprocess.run")
    def test_verification_with_signature_and_tamper_check(self, mock_run, tmp_path):
        """Test combined signature verification and tamper detection."""
        from scripts.core.attestation.verifier import AttestationVerifier

        findings_content = '{"findings": []}'
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(findings_content)

        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {"sha256": hashlib.sha256(findings_content.encode()).hexdigest()}
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        bundle_path = tmp_path / "findings.json.att.json.sigstore.json"
        bundle_path.write_text(json.dumps({"signature": "sig"}))

        # Mock successful signature verification
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        verifier = AttestationVerifier()
        result = verifier.verify(
            subject_path=str(findings_path),
            attestation_path=str(attestation_path),
            signature_path=str(bundle_path)
        )

        assert result.is_valid is True

    def test_verification_fails_on_invalid_signature(self, tmp_path):
        """Test verification fails if signature invalid even with valid digest."""
        from scripts.core.attestation.verifier import AttestationVerifier

        findings_content = '{"findings": []}'
        findings_path = tmp_path / "findings.json"
        findings_path.write_text(findings_content)

        attestation_path = tmp_path / "findings.json.att.json"
        attestation_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": "findings.json",
                "digest": {"sha256": hashlib.sha256(findings_content.encode()).hexdigest()}
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }
        attestation_path.write_text(json.dumps(attestation_data))

        bundle_path = tmp_path / "findings.json.att.json.sigstore.json"
        bundle_path.write_text(json.dumps({"signature": "invalid"}))

        with patch("subprocess.run") as mock_run:
            mock_result = Mock()
            mock_result.returncode = 1  # Failed
            mock_result.stderr = "Invalid signature"
            mock_run.return_value = mock_result

            verifier = AttestationVerifier()
            result = verifier.verify(
                subject_path=str(findings_path),
                attestation_path=str(attestation_path),
                signature_path=str(bundle_path)
            )

            assert result.is_valid is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
