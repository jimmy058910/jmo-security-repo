"""
Tests for SLSA provenance generation.

Tests the ProvenanceGenerator class which creates complete SLSA provenance
documents (in-toto statements) without signing.
"""

import json
import hashlib
from unittest.mock import patch
from scripts.core.attestation.provenance import ProvenanceGenerator
from scripts.core.attestation.constants import (
    SLSA_VERSION,
    INTOTO_VERSION,
    JMO_BUILD_TYPE,
)


class TestProvenanceGeneratorInit:
    """Tests for ProvenanceGenerator initialization."""

    def test_initialization(self):
        """Test ProvenanceGenerator initializes correctly."""
        generator = ProvenanceGenerator()

        assert generator.jmo_version is not None
        assert generator.python_version is not None
        assert isinstance(generator.jmo_version, str)
        assert isinstance(generator.python_version, str)

    def test_jmo_version_format(self):
        """Test JMo version has expected format."""
        generator = ProvenanceGenerator()

        # Version should be semantic (X.Y.Z)
        parts = generator.jmo_version.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()

    def test_python_version_format(self):
        """Test Python version has expected format."""
        generator = ProvenanceGenerator()

        # Version should be X.Y.Z
        parts = generator.python_version.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()


class TestDigestCalculation:
    """Tests for digest calculation methods."""

    def test_calculate_sha256(self):
        """Test SHA-256 hash calculation."""
        generator = ProvenanceGenerator()
        data = b"test data"

        result = generator._calculate_sha256(data)

        expected = hashlib.sha256(data).hexdigest()
        assert result == expected

    def test_calculate_sha384(self):
        """Test SHA-384 hash calculation."""
        generator = ProvenanceGenerator()
        data = b"test data"

        result = generator._calculate_sha384(data)

        expected = hashlib.sha384(data).hexdigest()
        assert result == expected

    def test_calculate_sha512(self):
        """Test SHA-512 hash calculation."""
        generator = ProvenanceGenerator()
        data = b"test data"

        result = generator._calculate_sha512(data)

        expected = hashlib.sha512(data).hexdigest()
        assert result == expected

    def test_generate_digests(self, tmp_path):
        """Test generate_digests for a file."""
        generator = ProvenanceGenerator()

        # Create test file
        test_file = tmp_path / "test.json"
        test_file.write_bytes(b"test content")

        result = generator.generate_digests(test_file)

        assert "sha256" in result
        assert "sha384" in result
        assert "sha512" in result
        assert len(result["sha256"]) == 64  # SHA-256 hex length
        assert len(result["sha384"]) == 96  # SHA-384 hex length
        assert len(result["sha512"]) == 128  # SHA-512 hex length

    def test_generate_digests_empty_file(self, tmp_path):
        """Test generate_digests for empty file."""
        generator = ProvenanceGenerator()

        # Create empty file
        test_file = tmp_path / "empty.json"
        test_file.write_bytes(b"")

        result = generator.generate_digests(test_file)

        # Empty file should still have digests
        assert result["sha256"] == hashlib.sha256(b"").hexdigest()


class TestSubjectCreation:
    """Tests for _create_subject method."""

    def test_create_subject(self, tmp_path):
        """Test creating subject with multi-hash digests."""
        generator = ProvenanceGenerator()

        # Create test file
        findings_file = tmp_path / "findings.json"
        findings_file.write_bytes(b'{"findings": []}')

        subjects = generator._create_subject(findings_file)

        assert len(subjects) == 1
        subject = subjects[0]
        assert subject.name == "findings.json"
        assert subject.digest.sha256 is not None
        assert subject.digest.sha384 is not None
        assert subject.digest.sha512 is not None


class TestBuildDefinitionCreation:
    """Tests for _create_build_definition method."""

    def test_create_build_definition_minimal(self):
        """Test creating build definition with minimal parameters."""
        generator = ProvenanceGenerator()

        build_def = generator._create_build_definition(
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
        )

        assert build_def.buildType == f"{JMO_BUILD_TYPE}@slsa/v1"
        assert build_def.externalParameters["profile"] == "fast"
        assert build_def.externalParameters["tools"] == ["trivy"]
        assert build_def.externalParameters["targets"] == ["repo1"]

    def test_create_build_definition_with_internal_params(self):
        """Test build definition includes internal parameters."""
        generator = ProvenanceGenerator()

        build_def = generator._create_build_definition(
            profile="balanced",
            tools=["trivy", "semgrep"],
            targets=["repo1"],
            threads=8,
            timeout=1200,
        )

        assert build_def.internalParameters["version"] == generator.jmo_version
        assert build_def.internalParameters["threads"] == 8
        assert build_def.internalParameters["timeout"] == 1200

    def test_create_build_definition_empty_dependencies(self):
        """Test build definition has empty resolvedDependencies."""
        generator = ProvenanceGenerator()

        build_def = generator._create_build_definition(
            profile="balanced",
            tools=[],
            targets=[],
        )

        # Phase 1 leaves dependencies empty (TODO for future phase)
        assert build_def.resolvedDependencies == []


class TestRunDetailsCreation:
    """Tests for _create_run_details method."""

    def test_create_run_details_minimal(self):
        """Test creating run details with defaults."""
        generator = ProvenanceGenerator()

        run_details = generator._create_run_details()

        assert run_details.builder.id is not None
        assert run_details.builder.version["jmo"] == generator.jmo_version
        assert run_details.builder.version["python"] == generator.python_version
        assert run_details.metadata.invocationId is not None
        assert run_details.metadata.startedOn is not None

    def test_create_run_details_with_custom_invocation_id(self):
        """Test run details with custom invocation ID."""
        generator = ProvenanceGenerator()

        run_details = generator._create_run_details(invocation_id="custom-id-123")

        assert run_details.metadata.invocationId == "custom-id-123"

    def test_create_run_details_with_timestamps(self):
        """Test run details with custom timestamps."""
        generator = ProvenanceGenerator()

        run_details = generator._create_run_details(
            started_on="2025-01-01T00:00:00Z",
            finished_on="2025-01-01T01:00:00Z",
        )

        assert run_details.metadata.startedOn == "2025-01-01T00:00:00Z"
        assert run_details.metadata.finishedOn == "2025-01-01T01:00:00Z"

    @patch.dict(
        "os.environ",
        {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "test/repo"},
        clear=True,
    )
    def test_detect_builder_id_github(self):
        """Test builder ID detection for GitHub Actions."""
        generator = ProvenanceGenerator()

        builder_id = generator._detect_builder_id()

        assert builder_id == "https://github.com/test/repo"

    @patch.dict(
        "os.environ",
        {"GITLAB_CI": "true", "CI_PROJECT_URL": "https://gitlab.com/test/project"},
        clear=True,
    )
    def test_detect_builder_id_gitlab(self):
        """Test builder ID detection for GitLab CI."""
        generator = ProvenanceGenerator()

        builder_id = generator._detect_builder_id()

        assert builder_id == "https://gitlab.com/test/project"

    @patch.dict("os.environ", {}, clear=True)
    def test_detect_builder_id_local(self):
        """Test builder ID defaults to JMo repo for local builds."""
        generator = ProvenanceGenerator()

        builder_id = generator._detect_builder_id()

        assert builder_id == "https://github.com/jimmy058910/jmo-security-repo"


class TestProvenanceGeneration:
    """Tests for complete provenance generation."""

    def test_generate_complete_provenance(self, tmp_path):
        """Test generating complete SLSA provenance document."""
        generator = ProvenanceGenerator()

        # Create test findings file
        findings_file = tmp_path / "findings.json"
        findings_file.write_text('{"findings": []}')

        provenance = generator.generate(
            findings_path=findings_file,
            profile="balanced",
            tools=["trivy", "semgrep"],
            targets=["repo1"],
            threads=4,
            timeout=600,
        )

        # Verify in-toto statement structure
        assert provenance["_type"] == INTOTO_VERSION
        assert len(provenance["subject"]) == 1
        assert provenance["predicateType"] == SLSA_VERSION

        # Verify subject
        subject = provenance["subject"][0]
        assert subject["name"] == "findings.json"
        assert "sha256" in subject["digest"]

        # Verify predicate (SLSA provenance)
        predicate = provenance["predicate"]
        assert "buildDefinition" in predicate
        assert "runDetails" in predicate

        # Verify build definition
        build_def = predicate["buildDefinition"]
        assert build_def["buildType"] == f"{JMO_BUILD_TYPE}@slsa/v1"
        assert build_def["externalParameters"]["profile"] == "balanced"
        assert build_def["externalParameters"]["tools"] == ["trivy", "semgrep"]

        # Verify run details
        run_details = predicate["runDetails"]
        assert "builder" in run_details
        assert "metadata" in run_details

    def test_generate_with_custom_invocation_id(self, tmp_path):
        """Test generating provenance with custom invocation ID."""
        generator = ProvenanceGenerator()

        findings_file = tmp_path / "findings.json"
        findings_file.write_text('{"findings": []}')

        provenance = generator.generate(
            findings_path=findings_file,
            profile="fast",
            tools=["trivy"],
            targets=["repo1"],
            invocation_id="custom-id-abc",
        )

        metadata = provenance["predicate"]["runDetails"]["metadata"]
        assert metadata["invocationId"] == "custom-id-abc"

    def test_generate_with_timestamps(self, tmp_path):
        """Test generating provenance with custom timestamps."""
        generator = ProvenanceGenerator()

        findings_file = tmp_path / "findings.json"
        findings_file.write_text('{"findings": []}')

        provenance = generator.generate(
            findings_path=findings_file,
            profile="balanced",
            tools=["trivy"],
            targets=["repo1"],
            started_on="2025-01-01T00:00:00Z",
            finished_on="2025-01-01T01:00:00Z",
        )

        metadata = provenance["predicate"]["runDetails"]["metadata"]
        assert metadata["startedOn"] == "2025-01-01T00:00:00Z"
        assert metadata["finishedOn"] == "2025-01-01T01:00:00Z"

    def test_generate_provenance_serializable(self, tmp_path):
        """Test generated provenance is JSON serializable."""
        generator = ProvenanceGenerator()

        findings_file = tmp_path / "findings.json"
        findings_file.write_text('{"findings": []}')

        provenance = generator.generate(
            findings_path=findings_file,
            profile="balanced",
            tools=["trivy"],
            targets=["repo1"],
        )

        # Should be serializable to JSON
        json_str = json.dumps(provenance)
        assert json_str is not None

        # Should be deserializable
        parsed = json.loads(json_str)
        assert parsed["_type"] == INTOTO_VERSION

    def test_generate_with_multiple_tools(self, tmp_path):
        """Test generating provenance with multiple tools."""
        generator = ProvenanceGenerator()

        findings_file = tmp_path / "findings.json"
        findings_file.write_text('{"findings": []}')

        provenance = generator.generate(
            findings_path=findings_file,
            profile="deep",
            tools=["trivy", "semgrep", "trufflehog", "syft"],
            targets=["repo1", "repo2"],
        )

        external_params = provenance["predicate"]["buildDefinition"][
            "externalParameters"
        ]
        assert len(external_params["tools"]) == 4
        assert len(external_params["targets"]) == 2

    @patch.dict(
        "os.environ", {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "test/ci-repo"}
    )
    def test_generate_in_github_actions(self, tmp_path):
        """Test generating provenance in GitHub Actions environment."""
        generator = ProvenanceGenerator()

        findings_file = tmp_path / "findings.json"
        findings_file.write_text('{"findings": []}')

        provenance = generator.generate(
            findings_path=findings_file,
            profile="balanced",
            tools=["trivy"],
            targets=["repo1"],
        )

        builder_id = provenance["predicate"]["runDetails"]["builder"]["id"]
        assert builder_id == "https://github.com/test/ci-repo"


class TestProvenanceValidation:
    """Tests for provenance document validation."""

    def test_provenance_has_required_fields(self, tmp_path):
        """Test provenance document has all required fields."""
        generator = ProvenanceGenerator()

        findings_file = tmp_path / "findings.json"
        findings_file.write_text('{"findings": []}')

        provenance = generator.generate(
            findings_path=findings_file,
            profile="balanced",
            tools=["trivy"],
            targets=["repo1"],
        )

        # Required top-level fields
        assert "_type" in provenance
        assert "subject" in provenance
        assert "predicateType" in provenance
        assert "predicate" in provenance

        # Required predicate fields
        predicate = provenance["predicate"]
        assert "buildDefinition" in predicate
        assert "runDetails" in predicate

    def test_provenance_types_correct(self, tmp_path):
        """Test provenance uses correct type URIs."""
        generator = ProvenanceGenerator()

        findings_file = tmp_path / "findings.json"
        findings_file.write_text('{"findings": []}')

        provenance = generator.generate(
            findings_path=findings_file,
            profile="balanced",
            tools=["trivy"],
            targets=["repo1"],
        )

        assert provenance["_type"] == "https://in-toto.io/Statement/v0.1"
        assert provenance["predicateType"] == "https://slsa.dev/provenance/v1"

        build_type = provenance["predicate"]["buildDefinition"]["buildType"]
        assert build_type.startswith("https://jmotools.com/jmo-scan/v1")
        assert "@slsa/v1" in build_type
