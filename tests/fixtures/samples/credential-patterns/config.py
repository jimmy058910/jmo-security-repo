#!/usr/bin/env python3
"""
Sample configuration with INTENTIONAL exposed secrets for testing.

These are FAKE credentials designed to trigger secret detection tools:
- TruffleHog (secrets scanner)
- Semgrep secrets (secrets detection)
- Trivy secrets scanning

DO NOT use these values anywhere - they are synthetic test data.
All values below are non-functional test patterns.
"""

# Fake AWS credentials (pattern matches but not valid)
# These trigger AWS credential detection rules
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Fake GitHub token (pattern matches but expired/invalid)
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Fake webhook URL (generic pattern, not a real service)
SLACK_WEBHOOK = "https://chat.example.invalid/webhook/T00000000/B00000000/abc123token"

# Fake database connection string with credentials
DATABASE_URL = "postgresql://admin:password123@localhost:5432/mydb"

# Fake API keys (synthetic patterns)
PAYMENT_API_KEY = "test_key_4eC39HqLyjWDarjtT1zdp7dc"
SENDGRID_API_KEY = "SG.xxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Private key pattern (not a real key)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyf8Pcy5b3G6UOoJjl6FJyPcULNJ6m
FAKE_DATA_NOT_A_REAL_KEY_JUST_PATTERN_MATCH_TEST
Wl8B4QO1Y+ZqEhE0n/x7xN1xN1xN1xN1xN1xN1xN1xN1xN1xN1xN1xN1xN1xN1x=
-----END RSA PRIVATE KEY-----"""

# JWT secret (example pattern)
JWT_SECRET = "your-256-bit-secret-key-here-for-signing"


def get_database_connection():
    """Returns database connection with hardcoded credentials."""
    return {
        "host": "db.example.com",
        "user": "root",
        "password": "admin123",  # Hardcoded password
        "database": "production",
    }


# Generic password patterns
CONFIG = {
    "api_password": "supersecretpassword",
    "encryption_key": "base64encodedkey==",
    "oauth_client_secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0",
}
