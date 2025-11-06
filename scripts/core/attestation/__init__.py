"""
Supply chain attestation module for JMo Security.

This module provides SLSA provenance generation, signing, and verification
for scan results.

Usage:
    from scripts.core.attestation import ProvenanceGenerator, AttestationVerifier

    # Generate provenance
    generator = ProvenanceGenerator()
    provenance = generator.generate(
        findings_path=Path("results/findings.json"),
        profile="balanced",
        tools=["trivy", "semgrep"],
        targets=["repo1"]
    )

    # Verify attestation
    verifier = AttestationVerifier()
    result = verifier.verify(
        subject_path="findings.json",
        attestation_path="findings.json.att.json"
    )
"""

from .provenance import ProvenanceGenerator
from .verifier import AttestationVerifier, VerificationResult
from .signer import SigstoreSigner
from .ci_detector import CIDetector
from .metadata_capture import MetadataCapture
from .tamper_detector import (
    TamperDetector,
    TamperIndicator,
    TamperSeverity,
    TamperIndicatorType,
)
from .models import (
    SLSAProvenance,
    InTotoStatement,
    Subject,
    Digest,
    BuildDefinition,
    RunDetails,
    Builder,
    Metadata,
)
from .constants import (
    SLSA_VERSION,
    INTOTO_VERSION,
    JMO_BUILD_TYPE,
    SLSA_LEVEL_1,
    SLSA_LEVEL_2,
    SLSA_LEVEL_3,
    SLSA_LEVEL_4,
    REKOR_URL,
    FULCIO_URL,
)

__all__ = [
    "ProvenanceGenerator",
    "AttestationVerifier",
    "VerificationResult",
    "SigstoreSigner",
    "CIDetector",
    "MetadataCapture",
    "TamperDetector",
    "TamperIndicator",
    "TamperSeverity",
    "TamperIndicatorType",
    "SLSAProvenance",
    "InTotoStatement",
    "Subject",
    "Digest",
    "BuildDefinition",
    "RunDetails",
    "Builder",
    "Metadata",
    "SLSA_VERSION",
    "INTOTO_VERSION",
    "JMO_BUILD_TYPE",
    "SLSA_LEVEL_1",
    "SLSA_LEVEL_2",
    "SLSA_LEVEL_3",
    "SLSA_LEVEL_4",
    "REKOR_URL",
    "FULCIO_URL",
]
