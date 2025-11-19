"""
Tests for SLSA attestation data models.

Tests the dataclass models used in SLSA provenance and in-toto statements:
- Digest (multi-hash support)
- Subject (artifact representation)
- Builder (builder information)
- Metadata (timing information)
- RunDetails (builder + metadata)
- BuildDefinition (scan parameters)
- SLSAProvenance (SLSA v1.0 provenance)
- InTotoStatement (complete attestation)
"""

import pytest
from scripts.core.attestation.models import (
    Digest,
    Subject,
    Builder,
    Metadata,
    RunDetails,
    BuildDefinition,
    SLSAProvenance,
    InTotoStatement,
)


class TestDigest:
    """Tests for Digest model."""

    def test_digest_with_all_hashes(self):
        """Test Digest with all three hash algorithms."""
        digest = Digest(
            sha256="a" * 64,
            sha384="b" * 96,
            sha512="c" * 128,
        )

        assert digest.sha256 == "a" * 64
        assert digest.sha384 == "b" * 96
        assert digest.sha512 == "c" * 128

    def test_digest_with_only_sha256(self):
        """Test Digest with only SHA-256 (minimum requirement)."""
        digest = Digest(sha256="a" * 64)

        assert digest.sha256 == "a" * 64
        assert digest.sha384 is None
        assert digest.sha512 is None

    def test_digest_to_dict_all_hashes(self):
        """Test to_dict() with all hashes included."""
        digest = Digest(
            sha256="a" * 64,
            sha384="b" * 96,
            sha512="c" * 128,
        )

        result = digest.to_dict()

        assert result == {
            "sha256": "a" * 64,
            "sha384": "b" * 96,
            "sha512": "c" * 128,
        }

    def test_digest_to_dict_only_sha256(self):
        """Test to_dict() excludes None values."""
        digest = Digest(sha256="a" * 64)

        result = digest.to_dict()

        assert result == {"sha256": "a" * 64}
        assert "sha384" not in result
        assert "sha512" not in result


class TestSubject:
    """Tests for Subject model."""

    def test_subject_creation(self):
        """Test Subject creation with name and digest."""
        digest = Digest(sha256="a" * 64)
        subject = Subject(name="findings.json", digest=digest)

        assert subject.name == "findings.json"
        assert subject.digest == digest

    def test_subject_to_dict(self):
        """Test Subject to_dict() serialization."""
        digest = Digest(sha256="a" * 64, sha384="b" * 96)
        subject = Subject(name="findings.json", digest=digest)

        result = subject.to_dict()

        assert result == {
            "name": "findings.json",
            "digest": {
                "sha256": "a" * 64,
                "sha384": "b" * 96,
            },
        }


class TestBuilder:
    """Tests for Builder model."""

    def test_builder_creation(self):
        """Test Builder creation with ID and version."""
        builder = Builder(
            id="https://github.com/jimmy058910/jmo-security-repo",
            version={"jmo": "1.0.0", "python": "3.11.5"},
        )

        assert builder.id == "https://github.com/jimmy058910/jmo-security-repo"
        assert builder.version == {"jmo": "1.0.0", "python": "3.11.5"}

    def test_builder_to_dict(self):
        """Test Builder to_dict() serialization."""
        builder = Builder(
            id="https://github.com/test/repo",
            version={"jmo": "1.0.0"},
        )

        result = builder.to_dict()

        assert result == {
            "id": "https://github.com/test/repo",
            "version": {"jmo": "1.0.0"},
        }


class TestMetadata:
    """Tests for Metadata model."""

    def test_metadata_creation_with_all_fields(self):
        """Test Metadata with invocationId, startedOn, finishedOn."""
        metadata = Metadata(
            invocationId="abc-123",
            startedOn="2025-01-01T00:00:00Z",
            finishedOn="2025-01-01T01:00:00Z",
        )

        assert metadata.invocationId == "abc-123"
        assert metadata.startedOn == "2025-01-01T00:00:00Z"
        assert metadata.finishedOn == "2025-01-01T01:00:00Z"

    def test_metadata_creation_minimal(self):
        """Test Metadata with only invocationId (required field)."""
        metadata = Metadata(invocationId="abc-123")

        assert metadata.invocationId == "abc-123"
        assert metadata.startedOn is None
        assert metadata.finishedOn is None

    def test_metadata_to_dict_all_fields(self):
        """Test to_dict() with all fields present."""
        metadata = Metadata(
            invocationId="abc-123",
            startedOn="2025-01-01T00:00:00Z",
            finishedOn="2025-01-01T01:00:00Z",
        )

        result = metadata.to_dict()

        assert result == {
            "invocationId": "abc-123",
            "startedOn": "2025-01-01T00:00:00Z",
            "finishedOn": "2025-01-01T01:00:00Z",
        }

    def test_metadata_to_dict_minimal(self):
        """Test to_dict() excludes None values."""
        metadata = Metadata(invocationId="abc-123")

        result = metadata.to_dict()

        assert result == {"invocationId": "abc-123"}
        assert "startedOn" not in result
        assert "finishedOn" not in result


class TestRunDetails:
    """Tests for RunDetails model."""

    def test_run_details_creation(self):
        """Test RunDetails with Builder and Metadata."""
        builder = Builder(
            id="https://github.com/test/repo",
            version={"jmo": "1.0.0"},
        )
        metadata = Metadata(
            invocationId="abc-123",
            startedOn="2025-01-01T00:00:00Z",
        )

        run_details = RunDetails(builder=builder, metadata=metadata)

        assert run_details.builder == builder
        assert run_details.metadata == metadata

    def test_run_details_to_dict(self):
        """Test RunDetails to_dict() serialization."""
        builder = Builder(
            id="https://github.com/test/repo",
            version={"jmo": "1.0.0"},
        )
        metadata = Metadata(invocationId="abc-123")

        run_details = RunDetails(builder=builder, metadata=metadata)
        result = run_details.to_dict()

        assert result == {
            "builder": {
                "id": "https://github.com/test/repo",
                "version": {"jmo": "1.0.0"},
            },
            "metadata": {"invocationId": "abc-123"},
        }


class TestBuildDefinition:
    """Tests for BuildDefinition model."""

    def test_build_definition_creation(self):
        """Test BuildDefinition with all fields."""
        build_def = BuildDefinition(
            buildType="https://jmotools.com/jmo-scan/v1",
            externalParameters={"profile": "balanced", "tools": ["trivy"]},
            internalParameters={"version": "1.0.0", "threads": 4},
            resolvedDependencies=[{"name": "trivy", "version": "0.50.0"}],
        )

        assert build_def.buildType == "https://jmotools.com/jmo-scan/v1"
        assert build_def.externalParameters == {
            "profile": "balanced",
            "tools": ["trivy"],
        }
        assert build_def.internalParameters == {"version": "1.0.0", "threads": 4}
        assert build_def.resolvedDependencies == [
            {"name": "trivy", "version": "0.50.0"}
        ]

    def test_build_definition_empty_dependencies(self):
        """Test BuildDefinition with default empty resolvedDependencies."""
        build_def = BuildDefinition(
            buildType="https://jmotools.com/jmo-scan/v1",
            externalParameters={},
            internalParameters={},
        )

        assert build_def.resolvedDependencies == []

    def test_build_definition_to_dict(self):
        """Test BuildDefinition to_dict() serialization."""
        build_def = BuildDefinition(
            buildType="https://jmotools.com/jmo-scan/v1",
            externalParameters={"profile": "fast"},
            internalParameters={"threads": 8},
            resolvedDependencies=[],
        )

        result = build_def.to_dict()

        assert result == {
            "buildType": "https://jmotools.com/jmo-scan/v1",
            "externalParameters": {"profile": "fast"},
            "internalParameters": {"threads": 8},
            "resolvedDependencies": [],
        }


class TestSLSAProvenance:
    """Tests for SLSAProvenance model."""

    def test_slsa_provenance_creation(self):
        """Test SLSAProvenance with BuildDefinition and RunDetails."""
        build_def = BuildDefinition(
            buildType="https://jmotools.com/jmo-scan/v1",
            externalParameters={},
            internalParameters={},
        )
        builder = Builder(id="https://github.com/test/repo", version={})
        metadata = Metadata(invocationId="abc-123")
        run_details = RunDetails(builder=builder, metadata=metadata)

        provenance = SLSAProvenance(
            buildDefinition=build_def,
            runDetails=run_details,
        )

        assert provenance.buildDefinition == build_def
        assert provenance.runDetails == run_details

    def test_slsa_provenance_to_dict(self):
        """Test SLSAProvenance to_dict() serialization."""
        build_def = BuildDefinition(
            buildType="https://jmotools.com/jmo-scan/v1",
            externalParameters={"profile": "balanced"},
            internalParameters={"version": "1.0.0"},
        )
        builder = Builder(
            id="https://github.com/test/repo",
            version={"jmo": "1.0.0"},
        )
        metadata = Metadata(invocationId="abc-123")
        run_details = RunDetails(builder=builder, metadata=metadata)

        provenance = SLSAProvenance(
            buildDefinition=build_def,
            runDetails=run_details,
        )

        result = provenance.to_dict()

        assert result == {
            "buildDefinition": {
                "buildType": "https://jmotools.com/jmo-scan/v1",
                "externalParameters": {"profile": "balanced"},
                "internalParameters": {"version": "1.0.0"},
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/test/repo",
                    "version": {"jmo": "1.0.0"},
                },
                "metadata": {"invocationId": "abc-123"},
            },
        }


class TestInTotoStatement:
    """Tests for InTotoStatement model."""

    def test_intoto_statement_creation(self):
        """Test InTotoStatement with all required fields."""
        digest = Digest(sha256="a" * 64)
        subject = Subject(name="findings.json", digest=digest)

        statement = InTotoStatement(
            _type="https://in-toto.io/Statement/v0.1",
            subject=[subject],
            predicateType="https://slsa.dev/provenance/v1",
            predicate={"buildDefinition": {}, "runDetails": {}},
        )

        assert statement._type == "https://in-toto.io/Statement/v0.1"
        assert len(statement.subject) == 1
        assert statement.subject[0] == subject
        assert statement.predicateType == "https://slsa.dev/provenance/v1"
        assert statement.predicate == {"buildDefinition": {}, "runDetails": {}}

    def test_intoto_statement_to_dict(self):
        """Test InTotoStatement to_dict() serialization."""
        digest = Digest(sha256="a" * 64)
        subject = Subject(name="findings.json", digest=digest)

        statement = InTotoStatement(
            _type="https://in-toto.io/Statement/v0.1",
            subject=[subject],
            predicateType="https://slsa.dev/provenance/v1",
            predicate={"test": "value"},
        )

        result = statement.to_dict()

        assert result == {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "findings.json",
                    "digest": {"sha256": "a" * 64},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {"test": "value"},
        }

    def test_intoto_statement_multiple_subjects(self):
        """Test InTotoStatement with multiple subjects."""
        subject1 = Subject(name="findings.json", digest=Digest(sha256="a" * 64))
        subject2 = Subject(name="sbom.json", digest=Digest(sha256="b" * 64))

        statement = InTotoStatement(
            _type="https://in-toto.io/Statement/v0.1",
            subject=[subject1, subject2],
            predicateType="https://slsa.dev/provenance/v1",
            predicate={},
        )

        assert len(statement.subject) == 2
        assert statement.subject[0].name == "findings.json"
        assert statement.subject[1].name == "sbom.json"

        result = statement.to_dict()
        assert len(result["subject"]) == 2
