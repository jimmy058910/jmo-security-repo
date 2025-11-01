import json
from pathlib import Path

from scripts.core.adapters.akto_adapter import AktoAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_akto_adapter_bola_vulnerability(tmp_path: Path):
    """Test Akto adapter with BOLA (Broken Object Level Authorization) finding."""
    data = {
        "testingRunResults": [
            {
                "vulnerable": True,
                "testSubType": "REPLACE_AUTH_TOKEN",
                "testSuperType": "BOLA",
                "apiInfoKey": {
                    "method": "GET",
                    "url": "/api/users/123"
                },
                "superCategory": {
                    "severity": {
                        "_name": "HIGH"
                    }
                },
                "confidencePercentage": 95,
                "testResults": "Broken Object Level Authorization detected - user can access other users' data"
            }
        ]
    }
    f = tmp_path / "akto.json"
    write(f, data)
    adapter = AktoAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "REPLACE_AUTH_TOKEN"
    assert items[0].severity == "HIGH"
    assert "api-security" in items[0].tags
    assert "owasp-api" in items[0].tags
    assert "bola" in items[0].tags
    assert "get" in items[0].tags
    assert items[0].context["test_super_type"] == "BOLA"
    assert items[0].context["api_method"] == "GET"
    assert items[0].context["api_url"] == "/api/users/123"
    assert items[0].context["confidence_percentage"] == 95
    assert items[0].location["path"] == "/api/users/123"


def test_akto_adapter_bfla_vulnerability(tmp_path: Path):
    """Test Akto adapter with BFLA (Broken Function Level Authorization) finding."""
    data = {
        "testingRunResults": [
            {
                "vulnerable": True,
                "testSubType": "CHANGE_METHOD_TO_DELETE",
                "testSuperType": "BFLA",
                "apiInfoKey": {
                    "method": "POST",
                    "url": "/api/admin/users"
                },
                "confidence": {
                    "_name": "CRITICAL"
                },
                "confidencePercentage": 100,
                "testResults": "User can access admin functionality by changing HTTP method"
            }
        ]
    }
    f = tmp_path / "akto.json"
    write(f, data)
    adapter = AktoAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "CHANGE_METHOD_TO_DELETE"
    assert items[0].severity == "CRITICAL"
    assert items[0].context["test_super_type"] == "BFLA"
    assert items[0].context["api_method"] == "POST"


def test_akto_adapter_idor_vulnerability(tmp_path: Path):
    """Test Akto adapter with IDOR (Insecure Direct Object Reference) finding."""
    data = {
        "testingRunResults": [
            {
                "vulnerable": True,
                "testSubType": "SEQUENTIAL_ID",
                "testSuperType": "IDOR",
                "apiInfoKey": {
                    "method": "GET",
                    "url": "/api/invoices/42"
                },
                "superCategory": {
                    "severity": {
                        "_name": "MEDIUM"
                    }
                },
                "confidencePercentage": 80,
                "testResults": "Sequential ID allows enumeration of resources"
            }
        ]
    }
    f = tmp_path / "akto.json"
    write(f, data)
    adapter = AktoAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "MEDIUM"
    assert "idor" in items[0].tags


def test_akto_adapter_multiple_vulnerabilities(tmp_path: Path):
    """Test Akto adapter with multiple API vulnerabilities."""
    data = {
        "testingRunResults": [
            {
                "vulnerable": True,
                "testSubType": "JWT_NONE_ALGO",
                "testSuperType": "BROKEN_AUTH",
                "apiInfoKey": {
                    "method": "POST",
                    "url": "/api/auth/login"
                },
                "superCategory": {
                    "severity": {
                        "_name": "CRITICAL"
                    }
                },
                "confidencePercentage": 100
            },
            {
                "vulnerable": True,
                "testSubType": "MASS_ASSIGNMENT",
                "testSuperType": "MASS_ASSIGNMENT",
                "apiInfoKey": {
                    "method": "PUT",
                    "url": "/api/users/profile"
                },
                "confidence": {
                    "_name": "HIGH"
                },
                "confidencePercentage": 90
            },
            {
                "vulnerable": True,
                "testSubType": "SSRF",
                "testSuperType": "SSRF",
                "apiInfoKey": {
                    "method": "POST",
                    "url": "/api/fetch"
                },
                "superCategory": {
                    "severity": {
                        "_name": "HIGH"
                    }
                },
                "confidencePercentage": 85
            }
        ]
    }
    f = tmp_path / "akto.json"
    write(f, data)
    adapter = AktoAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].severity == "CRITICAL"
    assert items[1].severity == "HIGH"
    assert items[2].severity == "HIGH"
    assert items[0].context["test_super_type"] == "BROKEN_AUTH"
    assert items[1].context["test_super_type"] == "MASS_ASSIGNMENT"
    assert items[2].context["test_super_type"] == "SSRF"


def test_akto_adapter_non_vulnerable_skipped(tmp_path: Path):
    """Test Akto adapter skips non-vulnerable findings."""
    data = {
        "testingRunResults": [
            {
                "vulnerable": False,
                "testSubType": "TEST_PASSED",
                "testSuperType": "AUTH_CHECK",
                "apiInfoKey": {
                    "method": "GET",
                    "url": "/api/secure"
                }
            },
            {
                "vulnerable": True,
                "testSubType": "WEAK_JWT",
                "testSuperType": "BROKEN_AUTH",
                "apiInfoKey": {
                    "method": "POST",
                    "url": "/api/login"
                },
                "confidence": {
                    "_name": "HIGH"
                },
                "confidencePercentage": 95
            }
        ]
    }
    f = tmp_path / "akto.json"
    write(f, data)
    adapter = AktoAdapter()
    items = adapter.parse(f)

    # Only vulnerable finding should be processed
    assert len(items) == 1
    assert items[0].ruleId == "WEAK_JWT"


def test_akto_adapter_missing_api_info(tmp_path: Path):
    """Test Akto adapter handles missing API info gracefully."""
    data = {
        "testingRunResults": [
            {
                "vulnerable": True,
                "testSubType": "GENERIC_VULN",
                "testSuperType": "API_VULN",
                "confidence": {
                    "_name": "MEDIUM"
                },
                "confidencePercentage": 70
            }
        ]
    }
    f = tmp_path / "akto.json"
    write(f, data)
    adapter = AktoAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].context["api_method"] is None
    assert items[0].context["api_url"] is None
    assert items[0].location["path"] == ":/api/endpoint"  # Fallback


def test_akto_adapter_low_severity(tmp_path: Path):
    """Test Akto adapter with LOW severity finding."""
    data = {
        "testingRunResults": [
            {
                "vulnerable": True,
                "testSubType": "INFO_DISCLOSURE",
                "testSuperType": "INFO_LEAK",
                "apiInfoKey": {
                    "method": "GET",
                    "url": "/api/version"
                },
                "confidence": {
                    "_name": "LOW"
                },
                "confidencePercentage": 40
            }
        ]
    }
    f = tmp_path / "akto.json"
    write(f, data)
    adapter = AktoAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "LOW"


def test_akto_adapter_empty_results(tmp_path: Path):
    """Test Akto adapter with empty test results array."""
    data = {
        "testingRunResults": []
    }
    f = tmp_path / "akto.json"
    write(f, data)
    adapter = AktoAdapter()
    items = adapter.parse(f)

    assert items == []


def test_akto_adapter_empty_file(tmp_path: Path):
    """Test Akto adapter handles empty JSON file."""
    f = tmp_path / "akto.json"
    f.write_text("", encoding="utf-8")
    adapter = AktoAdapter()
    items = adapter.parse(f)

    assert items == []


def test_akto_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Akto findings are enriched with compliance mappings."""
    data = {
        "testingRunResults": [
            {
                "vulnerable": True,
                "testSubType": "BOLA_TEST",
                "testSuperType": "BOLA",
                "apiInfoKey": {
                    "method": "GET",
                    "url": "/api/data"
                },
                "confidence": {
                    "_name": "HIGH"
                },
                "confidencePercentage": 90
            }
        ]
    }
    f = tmp_path / "akto.json"
    write(f, data)
    adapter = AktoAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
