import json
from pathlib import Path

from scripts.core.adapters.semgrep_secrets_adapter import SemgrepSecretsAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_semgrep_secrets_adapter_api_key(tmp_path: Path):
    """Test Semgrep Secrets adapter with API key detection."""
    data = {
        "version": "1.90.0",
        "results": [
            {
                "check_id": "generic-api-key",
                "path": "src/config.py",
                "start": {"line": 42},
                "message": "Hardcoded API key detected",
                "extra": {
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-798"],
                        "owasp": ["A07:2021"],
                        "confidence": "HIGH",
                        "likelihood": "HIGH",
                        "impact": "CRITICAL"
                    }
                }
            }
        ]
    }
    f = tmp_path / "semgrep-secrets.json"
    write(f, data)
    adapter = SemgrepSecretsAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "generic-api-key"
    assert items[0].severity == "CRITICAL"  # ERROR mapped to CRITICAL for secrets
    assert "secret" in items[0].tags
    assert "credentials" in items[0].tags
    assert "api-key" in items[0].tags
    assert "cwe-798" in items[0].tags
    assert items[0].location["path"] == "src/config.py"
    assert items[0].location["startLine"] == 42
    assert "https://cwe.mitre.org/data/definitions/798.html" in items[0].references
    assert "https://semgrep.dev/r/generic-api-key" in items[0].references
    assert items[0].risk["cwe"] == "CWE-798"
    assert items[0].risk["confidence"] == "HIGH"


def test_semgrep_secrets_adapter_password(tmp_path: Path):
    """Test Semgrep Secrets adapter with hardcoded password."""
    data = {
        "version": "1.90.0",
        "results": [
            {
                "check_id": "hardcoded-password",
                "path": "app/auth.py",
                "start": {"line": 108},
                "message": "Hardcoded password detected in source code",
                "extra": {
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-259"]
                    }
                }
            }
        ]
    }
    f = tmp_path / "semgrep-secrets.json"
    write(f, data)
    adapter = SemgrepSecretsAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "hardcoded-password"
    assert items[0].severity == "CRITICAL"
    assert "password" in items[0].tags
    assert items[0].risk["cwe"] == "CWE-259"


def test_semgrep_secrets_adapter_jwt_token(tmp_path: Path):
    """Test Semgrep Secrets adapter with JWT token detection."""
    data = {
        "version": "1.90.0",
        "results": [
            {
                "check_id": "jwt-token-hardcoded",
                "path": "services/auth_service.py",
                "start": {"line": 200},
                "message": "Hardcoded JWT secret token",
                "extra": {
                    "severity": "WARNING",
                    "metadata": {
                        "cwe": ["CWE-321"]
                    }
                }
            }
        ]
    }
    f = tmp_path / "semgrep-secrets.json"
    write(f, data)
    adapter = SemgrepSecretsAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "HIGH"  # WARNING mapped to HIGH
    assert "jwt" in items[0].tags
    assert "token" in items[0].tags


def test_semgrep_secrets_adapter_private_key(tmp_path: Path):
    """Test Semgrep Secrets adapter with private key detection."""
    data = {
        "version": "1.90.0",
        "results": [
            {
                "check_id": "private-key-detected",
                "path": "certs/keys.py",
                "start": {"line": 15},
                "message": "Private key embedded in source code",
                "extra": {
                    "severity": "ERROR"
                }
            }
        ]
    }
    f = tmp_path / "semgrep-secrets.json"
    write(f, data)
    adapter = SemgrepSecretsAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert "private-key" in items[0].tags


def test_semgrep_secrets_adapter_with_autofix(tmp_path: Path):
    """Test Semgrep Secrets adapter with autofix suggestion."""
    data = {
        "version": "1.90.0",
        "results": [
            {
                "check_id": "generic-api-key",
                "path": "config.py",
                "start": {"line": 10},
                "message": "Hardcoded API key",
                "extra": {
                    "severity": "ERROR",
                    "fix": "API_KEY = os.getenv('API_KEY')",
                    "metadata": {}
                }
            }
        ]
    }
    f = tmp_path / "semgrep-secrets.json"
    write(f, data)
    adapter = SemgrepSecretsAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Remediation should be dict with fix and steps
    assert isinstance(items[0].remediation, dict)
    assert items[0].remediation["fix"] == "API_KEY = os.getenv('API_KEY')"
    assert "Rotate the exposed credential" in items[0].remediation["steps"]


def test_semgrep_secrets_adapter_multiple_secrets(tmp_path: Path):
    """Test Semgrep Secrets adapter with multiple secret detections."""
    data = {
        "version": "1.90.0",
        "results": [
            {
                "check_id": "aws-access-key",
                "path": "deploy/aws.py",
                "start": {"line": 5},
                "message": "AWS access key hardcoded",
                "extra": {
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-798"]}
                }
            },
            {
                "check_id": "github-token",
                "path": "scripts/deploy.sh",
                "start": {"line": 20},
                "message": "GitHub personal access token detected",
                "extra": {
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-798"]}
                }
            },
            {
                "check_id": "database-password",
                "path": "config/database.py",
                "start": {"line": 42},
                "message": "Database password hardcoded",
                "extra": {
                    "severity": "WARNING",
                    "metadata": {"cwe": ["CWE-259"]}
                }
            }
        ]
    }
    f = tmp_path / "semgrep-secrets.json"
    write(f, data)
    adapter = SemgrepSecretsAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].severity == "CRITICAL"  # ERROR
    assert items[1].severity == "CRITICAL"  # ERROR
    assert items[2].severity == "HIGH"  # WARNING
    assert items[0].ruleId == "aws-access-key"
    assert items[1].ruleId == "github-token"
    assert items[2].ruleId == "database-password"


def test_semgrep_secrets_adapter_alternative_location(tmp_path: Path):
    """Test Semgrep Secrets adapter with alternative location structure."""
    data = {
        "version": "1.90.0",
        "results": [
            {
                "check_id": "generic-secret",
                "location": {
                    "path": "app/settings.py",
                    "start": {"line": 156}
                },
                "message": "Generic secret detected",
                "extra": {
                    "severity": "INFO"
                }
            }
        ]
    }
    f = tmp_path / "semgrep-secrets.json"
    write(f, data)
    adapter = SemgrepSecretsAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].location["path"] == "app/settings.py"
    assert items[0].location["startLine"] == 156
    assert items[0].severity == "MEDIUM"  # INFO mapped to MEDIUM


def test_semgrep_secrets_adapter_minimal_metadata(tmp_path: Path):
    """Test Semgrep Secrets adapter handles minimal metadata gracefully."""
    data = {
        "version": "1.90.0",
        "results": [
            {
                "check_id": "test-secret",
                "path": "test.py",
                "start": {"line": 1},
                "message": "Test secret",
                "extra": {
                    "severity": "ERROR"
                }
            }
        ]
    }
    f = tmp_path / "semgrep-secrets.json"
    write(f, data)
    adapter = SemgrepSecretsAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should handle missing metadata gracefully
    assert items[0].risk is None or isinstance(items[0].risk, dict)
    assert items[0].context["cwe"] is None
    assert items[0].context["owasp"] is None


def test_semgrep_secrets_adapter_empty_results(tmp_path: Path):
    """Test Semgrep Secrets adapter with empty results array."""
    data = {
        "version": "1.90.0",
        "results": []
    }
    f = tmp_path / "semgrep-secrets.json"
    write(f, data)
    adapter = SemgrepSecretsAdapter()
    items = adapter.parse(f)

    assert items == []


def test_semgrep_secrets_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Semgrep Secrets findings are enriched with compliance mappings."""
    data = {
        "version": "1.90.0",
        "results": [
            {
                "check_id": "test-secret",
                "path": "test.py",
                "start": {"line": 10},
                "message": "Test secret detected",
                "extra": {
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-798"]
                    }
                }
            }
        ]
    }
    f = tmp_path / "semgrep-secrets.json"
    write(f, data)
    adapter = SemgrepSecretsAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
