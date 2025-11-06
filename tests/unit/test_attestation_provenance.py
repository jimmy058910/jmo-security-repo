"""
Tests for SLSA Provenance Core (Phase 1).

This test module verifies the core provenance generation functionality
without signing (signing is tested in Phase 3).

Test Strategy (TDD):
1. Test provenance document structure (SLSA v1.0 compliance)
2. Test subject generation with multi-hash digests
3. Test build definition metadata
4. Test run details with builder info
5. Test SQLite storage integration
6. Test coverage metrics calculation
7. Test migration for existing databases

Coverage Target: 100% (25/25 tests)
"""

import json
import hashlib
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from typing import Dict, Any

import pytest


class TestProvenanceModels:
    """Test SLSA provenance data models."""

    def test_subject_model(self):
        """Test Subject model with multiple digest algorithms."""
        from scripts.core.attestation.models import Subject, Digest

        # Create digest with SHA-256, SHA-384, SHA-512
        digest = Digest(sha256="abc123...", sha384="def456...", sha512="ghi789...")

        # Create subject
        subject = Subject(name="findings.json", digest=digest)

        assert subject.name == "findings.json"
        assert subject.digest.sha256 == "abc123..."
        assert subject.digest.sha384 == "def456..."
        assert subject.digest.sha512 == "ghi789..."

    def test_build_definition_model(self):
        """Test BuildDefinition model."""
        from scripts.core.attestation.models import BuildDefinition

        build_def = BuildDefinition(
            buildType="https://jmotools.com/jmo-scan/v1",
            externalParameters={
                "profile": "balanced",
                "targets": ["repo1"],
                "tools": ["trivy", "semgrep"],
            },
            internalParameters={"version": "1.0.0", "threads": 4},
            resolvedDependencies=[],
        )

        assert build_def.buildType == "https://jmotools.com/jmo-scan/v1"
        assert build_def.externalParameters["profile"] == "balanced"
        assert "trivy" in build_def.externalParameters["tools"]

    def test_run_details_model(self):
        """Test RunDetails model."""
        from scripts.core.attestation.models import RunDetails, Builder, Metadata

        builder = Builder(
            id="https://github.com/jimmy058910/jmo-security-repo",
            version={"jmo": "1.0.0", "python": "3.11.5"},
        )

        metadata = Metadata(
            invocationId="uuid-abc123",
            startedOn="2025-01-03T10:00:00Z",
            finishedOn="2025-01-03T10:15:00Z",
        )

        run_details = RunDetails(builder=builder, metadata=metadata)

        assert run_details.builder.id.endswith("jmo-security-repo")
        assert run_details.metadata.invocationId == "uuid-abc123"

    def test_intoto_statement_model(self):
        """Test complete in-toto statement structure."""
        from scripts.core.attestation.models import (
            InTotoStatement,
            Subject,
            Digest,
            SLSAProvenance,
        )

        # Create minimal statement
        statement = InTotoStatement(
            _type="https://in-toto.io/Statement/v0.1",
            subject=[Subject(name="findings.json", digest=Digest(sha256="abc123"))],
            predicateType="https://slsa.dev/provenance/v1",
            predicate={},
        )

        assert statement._type == "https://in-toto.io/Statement/v0.1"
        assert statement.predicateType == "https://slsa.dev/provenance/v1"
        assert len(statement.subject) == 1


class TestHashGeneration:
    """Test multi-algorithm hash generation."""

    def test_sha256_generation(self):
        """Test SHA-256 hash generation."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        test_data = b"test content"
        expected = hashlib.sha256(test_data).hexdigest()

        generator = ProvenanceGenerator()
        actual = generator._calculate_sha256(test_data)

        assert actual == expected

    def test_sha384_generation(self):
        """Test SHA-384 hash generation."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        test_data = b"test content"
        expected = hashlib.sha384(test_data).hexdigest()

        generator = ProvenanceGenerator()
        actual = generator._calculate_sha384(test_data)

        assert actual == expected

    def test_sha512_generation(self):
        """Test SHA-512 hash generation."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        test_data = b"test content"
        expected = hashlib.sha512(test_data).hexdigest()

        generator = ProvenanceGenerator()
        actual = generator._calculate_sha512(test_data)

        assert actual == expected

    def test_multi_hash_generation(self):
        """Test generating all three hash algorithms."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write('{"findings": []}')
            findings_path = Path(f.name)

        try:
            generator = ProvenanceGenerator()
            digests = generator.generate_digests(findings_path)

            assert "sha256" in digests
            assert "sha384" in digests
            assert "sha512" in digests
            assert len(digests["sha256"]) == 64  # SHA-256 hex length
            assert len(digests["sha384"]) == 96  # SHA-384 hex length
            assert len(digests["sha512"]) == 128  # SHA-512 hex length
        finally:
            findings_path.unlink()


class TestVersionDetection:
    """Test JMo version detection from pyproject.toml."""

    def test_version_from_pyproject_toml(self):
        """Test reading version from pyproject.toml."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        generator = ProvenanceGenerator()
        version = generator._get_jmo_version()

        # Should match pyproject.toml version
        assert version is not None
        assert isinstance(version, str)
        # Format: X.Y.Z (e.g., "1.0.0" or "0.9.0")
        parts = version.split(".")
        assert len(parts) == 3

    def test_python_version_detection(self):
        """Test Python version detection."""
        from scripts.core.attestation.provenance import ProvenanceGenerator
        import sys

        generator = ProvenanceGenerator()
        python_version = generator._get_python_version()

        # Should match current Python version
        expected = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        assert python_version == expected


class TestProvenanceGeneration:
    """Test complete provenance document generation."""

    @pytest.fixture
    def sample_findings_file(self, tmp_path):
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

    def test_generate_provenance(self, sample_findings_file):
        """Test generating complete provenance document."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        generator = ProvenanceGenerator()
        provenance = generator.generate(
            findings_path=sample_findings_file,
            profile="balanced",
            tools=["trivy", "semgrep"],
            targets=["repo1"],
        )

        # Validate structure
        assert provenance["_type"] == "https://in-toto.io/Statement/v0.1"
        assert provenance["predicateType"] == "https://slsa.dev/provenance/v1"
        assert "subject" in provenance
        assert "predicate" in provenance

    def test_subject_includes_findings_file(self, sample_findings_file):
        """Test that subject includes findings.json."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        generator = ProvenanceGenerator()
        provenance = generator.generate(
            findings_path=sample_findings_file,
            profile="balanced",
            tools=["trivy"],
            targets=["repo1"],
        )

        subjects = provenance["subject"]
        assert len(subjects) == 1
        assert subjects[0]["name"] == "findings.json"
        assert "sha256" in subjects[0]["digest"]

    def test_build_definition_includes_parameters(self, sample_findings_file):
        """Test that buildDefinition includes scan parameters."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        generator = ProvenanceGenerator()
        provenance = generator.generate(
            findings_path=sample_findings_file,
            profile="balanced",
            tools=["trivy", "semgrep"],
            targets=["repo1", "image1"],
        )

        build_def = provenance["predicate"]["buildDefinition"]

        # External parameters (user-provided)
        assert build_def["externalParameters"]["profile"] == "balanced"
        assert "trivy" in build_def["externalParameters"]["tools"]
        assert "semgrep" in build_def["externalParameters"]["tools"]
        assert "repo1" in build_def["externalParameters"]["targets"]

        # Internal parameters (JMo internal)
        assert "version" in build_def["internalParameters"]
        assert "threads" in build_def["internalParameters"]

    def test_run_details_includes_builder_info(self, sample_findings_file):
        """Test that runDetails includes builder metadata."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        generator = ProvenanceGenerator()
        provenance = generator.generate(
            findings_path=sample_findings_file,
            profile="balanced",
            tools=["trivy"],
            targets=["repo1"],
        )

        run_details = provenance["predicate"]["runDetails"]

        # Builder info
        assert "builder" in run_details
        assert "id" in run_details["builder"]
        assert "version" in run_details["builder"]
        assert "jmo" in run_details["builder"]["version"]
        assert "python" in run_details["builder"]["version"]

        # Metadata (timing)
        assert "metadata" in run_details
        assert "invocationId" in run_details["metadata"]
        assert "startedOn" in run_details["metadata"]

    def test_provenance_json_serializable(self, sample_findings_file):
        """Test that provenance can be serialized to JSON."""
        from scripts.core.attestation.provenance import ProvenanceGenerator

        generator = ProvenanceGenerator()
        provenance = generator.generate(
            findings_path=sample_findings_file,
            profile="balanced",
            tools=["trivy"],
            targets=["repo1"],
        )

        # Should serialize without errors
        json_str = json.dumps(provenance, indent=2)
        assert isinstance(json_str, str)

        # Should deserialize back
        deserialized = json.loads(json_str)
        assert deserialized["_type"] == provenance["_type"]


class TestSQLiteIntegration:
    """Test SQLite database integration for attestations."""

    @pytest.fixture
    def test_db(self, tmp_path):
        """Create test database."""
        db_path = tmp_path / "test_history.db"
        # Initialize database schema (will be implemented in history_db.py)
        return db_path

    def test_store_attestation(self, test_db):
        """Test storing attestation in database."""
        from scripts.core.history_db import store_attestation, get_connection

        # Create test attestation
        attestation = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {},
        }

        scan_id = "scan-abc123"

        # Store attestation
        with patch("scripts.core.history_db.get_connection") as mock_conn:
            mock_cursor = MagicMock()
            # Mock table exists (skip migration)
            mock_cursor.fetchone.return_value = ("attestations",)
            mock_conn.return_value.cursor.return_value = mock_cursor

            store_attestation(
                scan_id=scan_id, attestation=attestation, rekor_published=False
            )

            # Verify INSERT was called (will be called twice: once for SELECT, once for INSERT)
            assert mock_cursor.execute.call_count >= 2
            # Check last call was INSERT
            last_call_args = mock_cursor.execute.call_args[0]
            assert "INSERT OR REPLACE INTO attestations" in last_call_args[0]

    def test_load_attestation(self, test_db):
        """Test loading attestation from database."""
        from scripts.core.history_db import load_attestation

        scan_id = "scan-abc123"

        with patch("scripts.core.history_db.get_connection") as mock_conn:
            # Mock database response
            mock_cursor = MagicMock()
            mock_cursor.fetchone.return_value = (
                '{"_type": "https://in-toto.io/Statement/v0.1"}',  # attestation_json
                None,  # signature_path
                None,  # certificate_path
                None,  # rekor_entry
                0,  # rekor_published
                int(time.time()),  # created_at
                2,  # slsa_level
            )
            mock_conn.return_value.cursor.return_value = mock_cursor

            result = load_attestation(scan_id)

            # Verify query was called
            mock_cursor.execute.assert_called_once()
            call_args = mock_cursor.execute.call_args[0]
            assert "SELECT" in call_args[0]
            assert "FROM attestations" in call_args[0]

            # Verify result
            assert result is not None
            assert result["scan_id"] == scan_id
            assert result["attestation"]["_type"] == "https://in-toto.io/Statement/v0.1"

    def test_load_missing_attestation(self):
        """Test loading non-existent attestation returns None."""
        from scripts.core.history_db import load_attestation

        with patch("scripts.core.history_db.get_connection") as mock_conn:
            mock_cursor = MagicMock()
            mock_cursor.fetchone.return_value = None
            mock_conn.return_value.cursor.return_value = mock_cursor

            result = load_attestation("nonexistent-scan")

            assert result is None

    def test_attestation_coverage_metrics(self):
        """Test attestation coverage calculation."""
        from scripts.core.history_db import get_attestation_coverage

        with patch("scripts.core.history_db.get_connection") as mock_conn:
            mock_cursor = MagicMock()

            # Mock queries (total scans, attested scans, rekor published, missing)
            mock_cursor.fetchone.side_effect = [
                (10,),  # total_scans
                (7,),  # attested_scans
                (5,),  # rekor_published
            ]
            mock_cursor.fetchall.return_value = [
                ("scan-1",),
                ("scan-2",),
                ("scan-3",),  # missing_scan_ids
            ]

            mock_conn.return_value.cursor.return_value = mock_cursor

            coverage = get_attestation_coverage(days=30)

            # Verify calculations
            assert coverage["total_scans"] == 10
            assert coverage["attested_scans"] == 7
            assert coverage["missing_scans"] == 3
            assert coverage["coverage_percentage"] == 70.0
            assert coverage["rekor_published"] == 5
            assert coverage["rekor_rate"] == pytest.approx(71.43, rel=0.01)
            assert len(coverage["missing_scan_ids"]) == 3


class TestDatabaseMigration:
    """Test database migration for adding attestations table."""

    def test_migration_creates_table(self):
        """Test migration creates attestations table."""
        from scripts.core.history_db import migrate_add_attestations_table

        with patch("scripts.core.history_db.get_connection") as mock_conn:
            mock_cursor = MagicMock()

            # Mock: table doesn't exist
            mock_cursor.fetchone.return_value = None
            mock_conn.return_value.cursor.return_value = mock_cursor

            migrate_add_attestations_table()

            # Verify CREATE TABLE was called
            assert mock_cursor.execute.call_count >= 3  # CREATE TABLE + 2 indexes

    def test_migration_skips_if_exists(self):
        """Test migration skips if table already exists."""
        from scripts.core.history_db import migrate_add_attestations_table

        with patch("scripts.core.history_db.get_connection") as mock_conn:
            mock_cursor = MagicMock()

            # Mock: table exists
            mock_cursor.fetchone.return_value = ("attestations",)
            mock_conn.return_value.cursor.return_value = mock_cursor

            migrate_add_attestations_table()

            # Verify only SELECT was called (no CREATE)
            assert mock_cursor.execute.call_count == 1


class TestConstants:
    """Test attestation constants."""

    def test_slsa_version_constant(self):
        """Test SLSA version constant."""
        from scripts.core.attestation.constants import SLSA_VERSION

        assert SLSA_VERSION == "https://slsa.dev/provenance/v1"

    def test_intoto_version_constant(self):
        """Test in-toto version constant."""
        from scripts.core.attestation.constants import INTOTO_VERSION

        assert INTOTO_VERSION == "https://in-toto.io/Statement/v0.1"

    def test_jmo_build_type_constant(self):
        """Test JMo build type constant."""
        from scripts.core.attestation.constants import JMO_BUILD_TYPE

        assert JMO_BUILD_TYPE == "https://jmotools.com/jmo-scan/v1"
