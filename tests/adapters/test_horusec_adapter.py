import json
from pathlib import Path

from scripts.core.adapters.horusec_adapter import HorusecAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_horusec_adapter_sql_injection(tmp_path: Path):
    """Test Horusec adapter with SQL injection vulnerability."""
    data = {
        "version": "2.8.0",
        "totalVulnerabilities": 1,
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "HS-JAVA-1",
                "severity": "HIGH",
                "file": "src/main/java/com/app/UserDAO.java",
                "line": 42,
                "details": "SQL Injection vulnerability detected - user input directly concatenated into SQL query",
                "securityTool": "SecurityCodeScan",
                "type": "SQL Injection",
                "code": "String query = \"SELECT * FROM users WHERE id=\" + userId;"
            }
        ]
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "HS-JAVA-1"
    assert items[0].severity == "HIGH"
    assert "sast" in items[0].tags
    assert "horusec" in items[0].tags
    assert "sql-injection" in items[0].tags
    assert "securitycodescan" in items[0].tags
    assert items[0].context["security_tool"] == "SecurityCodeScan"
    assert items[0].context["vulnerability_type"] == "SQL Injection"
    assert items[0].location["path"] == "src/main/java/com/app/UserDAO.java"
    assert items[0].location["startLine"] == 42


def test_horusec_adapter_xss(tmp_path: Path):
    """Test Horusec adapter with XSS vulnerability."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "HS-JS-2",
                "severity": "MEDIUM",
                "file": "public/js/app.js",
                "line": 108,
                "details": "Cross-Site Scripting (XSS) vulnerability - unescaped user input rendered in DOM",
                "securityTool": "HorusecJavascript",
                "type": "Cross-Site Scripting (XSS)"
            }
        ]
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "MEDIUM"
    assert "xss" in items[0].tags


def test_horusec_adapter_hardcoded_secret(tmp_path: Path):
    """Test Horusec adapter with hardcoded secret."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "HS-PY-3",
                "severity": "CRITICAL",
                "file": "config/settings.py",
                "line": 15,
                "details": "Hardcoded secret detected in configuration file",
                "securityTool": "HorusecPython",
                "type": "Hardcoded Secret",
                "code": "API_KEY = 'sk_live_1234567890abcdef'"
            }
        ]
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "CRITICAL"
    assert "hardcoded-secret" in items[0].tags
    assert items[0].context["code_snippet"] == "API_KEY = 'sk_live_1234567890abcdef'"


def test_horusec_adapter_command_injection(tmp_path: Path):
    """Test Horusec adapter with command injection vulnerability."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "HS-GO-4",
                "severity": "HIGH",
                "file": "api/handlers.go",
                "line": 200,
                "details": "Command injection vulnerability - user input passed to shell command",
                "securityTool": "HorusecGolang",
                "type": "Command Injection"
            }
        ]
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "HIGH"
    assert "injection" in items[0].tags


def test_horusec_adapter_multiple_vulnerabilities(tmp_path: Path):
    """Test Horusec adapter with multiple vulnerabilities."""
    data = {
        "version": "2.8.0",
        "totalVulnerabilities": 3,
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "HS-JAVA-1",
                "severity": "CRITICAL",
                "file": "UserService.java",
                "line": 50,
                "details": "SQL Injection",
                "securityTool": "HorusecJava",
                "type": "SQL Injection"
            },
            {
                "vulnerabilityID": "HS-JAVA-2",
                "severity": "HIGH",
                "file": "AuthController.java",
                "line": 75,
                "details": "CSRF vulnerability",
                "securityTool": "HorusecJava",
                "type": "CSRF"
            },
            {
                "vulnerabilityID": "HS-JS-1",
                "severity": "MEDIUM",
                "file": "client.js",
                "line": 120,
                "details": "XSS vulnerability",
                "securityTool": "HorusecJavascript",
                "type": "XSS"
            }
        ]
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].severity == "CRITICAL"
    assert items[1].severity == "HIGH"
    assert items[2].severity == "MEDIUM"
    assert items[0].ruleId == "HS-JAVA-1"
    assert items[1].ruleId == "HS-JAVA-2"
    assert items[2].ruleId == "HS-JS-1"


def test_horusec_adapter_minimal_metadata(tmp_path: Path):
    """Test Horusec adapter handles minimal vulnerability metadata gracefully."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "HS-TEST-1",
                "severity": "LOW",
                "file": "test.py",
                "line": 10
            }
        ]
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should use fallback values
    assert items[0].ruleId == "HS-TEST-1"
    assert items[0].message.startswith("Security vulnerability detected")
    assert items[0].context["security_tool"] is None
    assert items[0].context["vulnerability_type"] is None


def test_horusec_adapter_no_vulnerability_id(tmp_path: Path):
    """Test Horusec adapter handles missing vulnerabilityID gracefully."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "severity": "MEDIUM",
                "file": "app.js",
                "line": 50,
                "type": "Generic Security Issue",
                "details": "Security issue detected"
            }
        ]
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should use type as fallback ruleId
    assert items[0].ruleId == "Generic Security Issue"
    assert items[0].title == "Generic Security Issue"


def test_horusec_adapter_severity_normalization(tmp_path: Path):
    """Test Horusec adapter normalizes different severity levels."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "HS-1",
                "severity": "INFO",
                "file": "test1.py",
                "line": 1
            },
            {
                "vulnerabilityID": "HS-2",
                "severity": "LOW",
                "file": "test2.py",
                "line": 2
            },
            {
                "vulnerabilityID": "HS-3",
                "severity": "MEDIUM",
                "file": "test3.py",
                "line": 3
            }
        ]
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].severity == "INFO"
    assert items[1].severity == "LOW"
    assert items[2].severity == "MEDIUM"


def test_horusec_adapter_empty_vulnerabilities(tmp_path: Path):
    """Test Horusec adapter with empty vulnerabilities array."""
    data = {
        "version": "2.8.0",
        "totalVulnerabilities": 0,
        "analysisVulnerabilities": []
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert items == []


def test_horusec_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Horusec findings are enriched with compliance mappings."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "HS-TEST",
                "severity": "HIGH",
                "file": "test.py",
                "line": 10,
                "type": "Test Vulnerability"
            }
        ]
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
