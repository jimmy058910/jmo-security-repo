"""
Constants for SLSA attestation.

This module defines constants used throughout the attestation system,
including SLSA provenance versions, in-toto statement types, and JMo-specific
build types.
"""

# SLSA Provenance version
# v1 is the current stable version as of 2024
SLSA_VERSION = "https://slsa.dev/provenance/v1"

# in-toto Statement version
# v0.1 is the current version for in-toto attestations
INTOTO_VERSION = "https://in-toto.io/Statement/v0.1"

# JMo-specific build type
# Identifies JMo Security scans in SLSA provenance
JMO_BUILD_TYPE = "https://jmotools.com/jmo-scan/v1"

# SLSA Levels
SLSA_LEVEL_1 = 1  # Build provenance exists
SLSA_LEVEL_2 = 2  # Signed provenance (target for v1.0.0)
SLSA_LEVEL_3 = 3  # Non-falsifiable provenance (future)
SLSA_LEVEL_4 = 4  # Two-party review (future)

# Sigstore URLs
FULCIO_URL_PRODUCTION = "https://fulcio.sigstore.dev"
REKOR_URL_PRODUCTION = "https://rekor.sigstore.dev"

FULCIO_URL_STAGING = "https://fulcio.sigstage.dev"
REKOR_URL_STAGING = "https://rekor.sigstage.dev"

# Default URLs (production)
FULCIO_URL = FULCIO_URL_PRODUCTION
REKOR_URL = REKOR_URL_PRODUCTION

# Timeouts (seconds)
ATTESTATION_TIMEOUT = 30
VERIFICATION_TIMEOUT = 20
REKOR_TIMEOUT = 10

# Error codes
ERROR_CODES = {
    "INVALID_SUBJECT": 101,
    "SIGNING_FAILED": 102,
    "VERIFICATION_FAILED": 103,
    "REKOR_UNAVAILABLE": 104,
    "OIDC_TOKEN_ERROR": 105,
    "FULCIO_ERROR": 106,
    "INVALID_ATTESTATION": 107,
    "TAMPER_DETECTED": 108,
}

# Hash algorithms (SLSA requires multiple)
HASH_ALGORITHMS = ["sha256", "sha384", "sha512"]
