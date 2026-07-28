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

from .ci_detector import CIDetector
from .constants import (
    FULCIO_URL,
    INTOTO_VERSION,
    JMO_BUILD_TYPE,
    REKOR_URL,
    SLSA_LEVEL_1,
    SLSA_LEVEL_2,
    SLSA_LEVEL_3,
    SLSA_LEVEL_4,
    SLSA_VERSION,
)
from .metadata_capture import MetadataCapture
from .models import (
    BuildDefinition,
    Builder,
    Digest,
    InTotoStatement,
    Metadata,
    RunDetails,
    SLSAProvenance,
    Subject,
)
from .provenance import ProvenanceGenerator
from .signer import SigstoreSigner
from .tamper_detector import (
    TamperDetector,
    TamperIndicator,
    TamperIndicatorType,
    TamperSeverity,
)
from .verifier import AttestationVerifier, VerificationResult

__all__ = [
    "FULCIO_URL",
    "INTOTO_VERSION",
    "JMO_BUILD_TYPE",
    "REKOR_URL",
    "SLSA_LEVEL_1",
    "SLSA_LEVEL_2",
    "SLSA_LEVEL_3",
    "SLSA_LEVEL_4",
    "SLSA_VERSION",
    "AttestationVerifier",
    "BuildDefinition",
    "Builder",
    "CIDetector",
    "Digest",
    "InTotoStatement",
    "Metadata",
    "MetadataCapture",
    "ProvenanceGenerator",
    "RunDetails",
    "SLSAProvenance",
    "SigstoreSigner",
    "Subject",
    "TamperDetector",
    "TamperIndicator",
    "TamperIndicatorType",
    "TamperSeverity",
    "VerificationResult",
]
