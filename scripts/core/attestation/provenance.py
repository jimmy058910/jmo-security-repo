"""
SLSA Provenance generation for JMo Security scans.

This module implements the core provenance generation logic without signing.
Signing is handled separately in Phase 3 (Sigstore integration).

Usage:
    generator = ProvenanceGenerator()
    provenance = generator.generate(
        findings_path=Path("results/findings.json"),
        profile="balanced",
        tools=["trivy", "semgrep"],
        targets=["repo1"]
    )
"""

import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from .constants import SLSA_VERSION, INTOTO_VERSION, JMO_BUILD_TYPE
from .models import (
    Digest,
    Subject,
    Builder,
    Metadata,
    RunDetails,
    BuildDefinition,
    SLSAProvenance,
    InTotoStatement,
)


class ProvenanceGenerator:
    """Generate SLSA provenance documents for JMo Security scans."""

    def __init__(self):
        """Initialize provenance generator."""
        self.jmo_version = self._get_jmo_version()
        self.python_version = self._get_python_version()

    def _get_jmo_version(self) -> str:
        """Read JMo version from pyproject.toml.

        Returns:
            Version string (e.g., "1.0.0")
        """
        try:
            # Python 3.11+ has built-in tomllib
            import tomllib
        except ImportError:
            # Python 3.10 needs tomli
            import tomli as tomllib

        pyproject_path = Path(__file__).parent.parent.parent.parent / "pyproject.toml"

        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
            return str(data["project"]["version"])

    def _get_python_version(self) -> str:
        """Get current Python version.

        Returns:
            Version string (e.g., "3.11.5")
        """
        return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    def _calculate_sha256(self, data: bytes) -> str:
        """Calculate SHA-256 hash of data.

        Args:
            data: Bytes to hash

        Returns:
            Hexadecimal hash string
        """
        return hashlib.sha256(data).hexdigest()

    def _calculate_sha384(self, data: bytes) -> str:
        """Calculate SHA-384 hash of data.

        Args:
            data: Bytes to hash

        Returns:
            Hexadecimal hash string
        """
        return hashlib.sha384(data).hexdigest()

    def _calculate_sha512(self, data: bytes) -> str:
        """Calculate SHA-512 hash of data.

        Args:
            data: Bytes to hash

        Returns:
            Hexadecimal hash string
        """
        return hashlib.sha512(data).hexdigest()

    def generate_digests(self, file_path: Path) -> Dict[str, str]:
        """Generate multiple hash digests for a file.

        SLSA recommends multiple hash algorithms for defense-in-depth.

        Args:
            file_path: Path to file to hash

        Returns:
            Dictionary with sha256, sha384, sha512 hashes
        """
        with open(file_path, "rb") as f:
            data = f.read()

        return {
            "sha256": self._calculate_sha256(data),
            "sha384": self._calculate_sha384(data),
            "sha512": self._calculate_sha512(data),
        }

    def _create_subject(self, findings_path: Path) -> List[Subject]:
        """Create subject list for in-toto statement.

        Args:
            findings_path: Path to findings.json file

        Returns:
            List of Subject objects
        """
        digests = self.generate_digests(findings_path)

        digest = Digest(
            sha256=digests["sha256"],
            sha384=digests["sha384"],
            sha512=digests["sha512"]
        )

        subject = Subject(name="findings.json", digest=digest)

        return [subject]

    def _create_build_definition(
        self,
        profile: str,
        tools: List[str],
        targets: List[str],
        threads: int = 4,
        timeout: int = 600
    ) -> BuildDefinition:
        """Create build definition with scan parameters.

        Args:
            profile: Scan profile (fast, balanced, deep)
            tools: List of tools used
            targets: List of scan targets
            threads: Number of parallel threads
            timeout: Timeout in seconds

        Returns:
            BuildDefinition object
        """
        # Include SLSA version reference in buildType
        # Format: https://jmotools.com/jmo-scan/v1@slsa/v1
        build_type_with_slsa = f"{JMO_BUILD_TYPE}@slsa/v1"

        return BuildDefinition(
            buildType=build_type_with_slsa,
            externalParameters={
                "profile": profile,
                "tools": tools,
                "targets": targets,
            },
            internalParameters={
                "version": self.jmo_version,
                "threads": threads,
                "timeout": timeout,
            },
            resolvedDependencies=[]  # TODO: Add tool versions in future phase
        )

    def _create_run_details(
        self,
        invocation_id: Optional[str] = None,
        started_on: Optional[str] = None,
        finished_on: Optional[str] = None
    ) -> RunDetails:
        """Create run details with builder and timing metadata.

        Args:
            invocation_id: Unique invocation ID (generated if None)
            started_on: ISO 8601 start timestamp (current time if None)
            finished_on: ISO 8601 finish timestamp (optional)

        Returns:
            RunDetails object
        """
        if invocation_id is None:
            invocation_id = str(uuid.uuid4())

        if started_on is None:
            started_on = datetime.now(timezone.utc).isoformat()

        # Detect CI environment and set builder ID accordingly
        builder_id = self._detect_builder_id()

        builder = Builder(
            id=builder_id,
            version={
                "jmo": self.jmo_version,
                "python": self.python_version,
            }
        )

        metadata = Metadata(
            invocationId=invocation_id,
            startedOn=started_on,
            finishedOn=finished_on
        )

        return RunDetails(builder=builder, metadata=metadata)

    def _detect_builder_id(self) -> str:
        """Detect builder ID based on CI environment.

        Returns:
            Builder ID string (GitHub Actions URL, GitLab CI URL, or JMo repo URL)
        """
        from .ci_detector import CIDetector

        detector = CIDetector()
        ci_provider = detector.get_ci_provider()

        if ci_provider == "github":
            # GitHub Actions: Use repository URL from GITHUB_REPOSITORY
            repo = os.getenv("GITHUB_REPOSITORY", "unknown/unknown")
            return f"https://github.com/{repo}"
        elif ci_provider == "gitlab":
            # GitLab CI: Use project URL from CI_PROJECT_URL
            project_url = os.getenv("CI_PROJECT_URL", "https://gitlab.com/unknown/unknown")
            return project_url
        else:
            # Local or generic CI: Use JMo repository URL
            return "https://github.com/jimmy058910/jmo-security-repo"

    def generate(
        self,
        findings_path: Path,
        profile: str,
        tools: List[str],
        targets: List[str],
        threads: int = 4,
        timeout: int = 600,
        invocation_id: Optional[str] = None,
        started_on: Optional[str] = None,
        finished_on: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate complete SLSA provenance document.

        Args:
            findings_path: Path to findings.json file
            profile: Scan profile name
            tools: List of tools used in scan
            targets: List of scan targets
            threads: Number of parallel threads (default: 4)
            timeout: Timeout in seconds (default: 600)
            invocation_id: Unique scan ID (auto-generated if None)
            started_on: ISO 8601 start timestamp (current time if None)
            finished_on: ISO 8601 finish timestamp (optional)

        Returns:
            Complete in-toto statement with SLSA provenance (as dict)
        """
        # Create subject (findings.json)
        subjects = self._create_subject(findings_path)

        # Create build definition
        build_definition = self._create_build_definition(
            profile=profile,
            tools=tools,
            targets=targets,
            threads=threads,
            timeout=timeout
        )

        # Create run details
        run_details = self._create_run_details(
            invocation_id=invocation_id,
            started_on=started_on,
            finished_on=finished_on
        )

        # Create SLSA provenance
        slsa_provenance = SLSAProvenance(
            buildDefinition=build_definition,
            runDetails=run_details
        )

        # Create in-toto statement
        statement = InTotoStatement(
            _type=INTOTO_VERSION,
            subject=subjects,
            predicateType=SLSA_VERSION,
            predicate=slsa_provenance.to_dict()
        )

        return statement.to_dict()
