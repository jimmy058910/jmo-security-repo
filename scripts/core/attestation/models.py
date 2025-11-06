"""
Data models for SLSA provenance and in-toto statements.

This module defines dataclasses representing the SLSA provenance v1.0
and in-toto statement v0.1 schemas.

References:
- SLSA Provenance v1.0: https://slsa.dev/spec/v1.0/provenance
- in-toto Statement v0.1: https://github.com/in-toto/attestation/blob/main/spec/v1.0/statement.md
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class Digest:
    """Multi-algorithm digest for artifacts.

    SLSA requires multiple hash algorithms for defense-in-depth.
    """

    sha256: str
    sha384: Optional[str] = None
    sha512: Optional[str] = None

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary, excluding None values."""
        result = {"sha256": self.sha256}
        if self.sha384:
            result["sha384"] = self.sha384
        if self.sha512:
            result["sha512"] = self.sha512
        return result


@dataclass
class Subject:
    """Subject of the attestation (artifact being attested).

    Represents the artifact (e.g., findings.json) with its name and digest.
    """

    name: str
    digest: Digest

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {"name": self.name, "digest": self.digest.to_dict()}


@dataclass
class Builder:
    """Builder information (who/what performed the build).

    In JMo's case, this represents the scanning infrastructure.
    """

    id: str  # URI identifying the builder (e.g., GitHub repo URL)
    version: Dict[str, str]  # Version info (jmo, python, etc.)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class Metadata:
    """Build/scan metadata (timing, invocation details)."""

    invocationId: str  # Unique ID for this scan invocation
    startedOn: Optional[str] = None  # ISO 8601 timestamp
    finishedOn: Optional[str] = None  # ISO 8601 timestamp

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        result = {"invocationId": self.invocationId}
        if self.startedOn:
            result["startedOn"] = self.startedOn
        if self.finishedOn:
            result["finishedOn"] = self.finishedOn
        return result


@dataclass
class RunDetails:
    """Details about the scan execution."""

    builder: Builder
    metadata: Metadata

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {"builder": self.builder.to_dict(), "metadata": self.metadata.to_dict()}


@dataclass
class BuildDefinition:
    """Build/scan definition (parameters, dependencies).

    Describes what was scanned and how.
    """

    buildType: str  # URI identifying the build type (JMo scan type)
    externalParameters: Dict[
        str, Any
    ]  # User-provided parameters (profile, tools, targets)
    internalParameters: Dict[str, Any]  # JMo internal parameters (threads, timeout)
    resolvedDependencies: List[Dict[str, Any]] = field(
        default_factory=list
    )  # Tool versions

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class SLSAProvenance:
    """SLSA Provenance v1.0 predicate.

    The predicate contains the actual provenance information:
    what was built, how it was built, and who built it.
    """

    buildDefinition: BuildDefinition
    runDetails: RunDetails

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "buildDefinition": self.buildDefinition.to_dict(),
            "runDetails": self.runDetails.to_dict(),
        }


@dataclass
class InTotoStatement:
    """Complete in-toto statement with SLSA provenance.

    This is the top-level attestation document that gets signed.

    Structure:
        {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "...", "digest": {...}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {...}
        }
    """

    _type: str  # in-toto statement type URI
    subject: List[Subject]  # Artifacts being attested
    predicateType: str  # Type of predicate (SLSA provenance URI)
    predicate: Dict[str, Any]  # SLSA provenance data

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "_type": self._type,
            "subject": [s.to_dict() for s in self.subject],
            "predicateType": self.predicateType,
            "predicate": self.predicate,
        }
