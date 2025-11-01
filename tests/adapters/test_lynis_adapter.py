import json
from pathlib import Path

from scripts.core.adapters.lynis_adapter import LynisAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_lynis_adapter_warning(tmp_path: Path):
    """Test Lynis adapter with HIGH severity warning."""
    data = {
        "system_info": {
            "hostname": "prod-web-01",
            "os": "Linux",
            "os_version": "Ubuntu 22.04"
        },
        "warnings": [
            {
                "test_id": "AUTH-9308",
                "message": "Default umask is not secure",
                "details": "The default umask value is 0022, which allows others to read files. Consider changing to 0027 or 0077."
            }
        ]
    }
    f = tmp_path / "lynis.json"
    write(f, data)
    adapter = LynisAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "AUTH-9308"
    assert items[0].severity == "HIGH"
    assert "system-hardening" in items[0].tags
    assert "compliance" in items[0].tags
    assert "warning" in items[0].tags
    assert items[0].context["finding_type"] == "warning"
    assert items[0].context["hostname"] == "prod-web-01"
    assert items[0].context["os"] == "Linux"
    assert items[0].context["os_version"] == "Ubuntu 22.04"
    assert items[0].location["path"] == "prod-web-01"
    assert "https://cisofy.com/lynis/controls/AUTH-9308/" in items[0].references


def test_lynis_adapter_suggestion(tmp_path: Path):
    """Test Lynis adapter with MEDIUM severity suggestion."""
    data = {
        "system_info": {
            "hostname": "app-server-02",
            "os": "CentOS",
            "os_version": "8.5"
        },
        "suggestions": [
            {
                "test_id": "BOOT-5122",
                "message": "Install additional security packages",
                "details": "Consider installing fail2ban for intrusion prevention"
            }
        ]
    }
    f = tmp_path / "lynis.json"
    write(f, data)
    adapter = LynisAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "BOOT-5122"
    assert items[0].severity == "MEDIUM"
    assert "suggestion" in items[0].tags
    assert items[0].context["finding_type"] == "suggestion"


def test_lynis_adapter_vulnerability(tmp_path: Path):
    """Test Lynis adapter with CRITICAL severity vulnerability."""
    data = {
        "system_info": {
            "hostname": "db-server-01",
            "os": "Linux"
        },
        "vulnerabilities": [
            {
                "id": "CVE-2024-1234",
                "cve": "CVE-2024-1234",
                "message": "OpenSSL vulnerability detected",
                "package": "openssl"
            }
        ]
    }
    f = tmp_path / "lynis.json"
    write(f, data)
    adapter = LynisAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "CVE-2024-1234"
    assert items[0].severity == "CRITICAL"
    assert "vulnerability" in items[0].tags
    assert "cve" in items[0].tags
    assert "package" in items[0].tags
    assert items[0].context["finding_type"] == "vulnerability"
    assert items[0].context["cve"] == "CVE-2024-1234"
    assert items[0].context["package"] == "openssl"
    assert items[0].location["path"] == "db-server-01:openssl"
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-1234" in items[0].references


def test_lynis_adapter_multiple_findings(tmp_path: Path):
    """Test Lynis adapter with multiple finding types."""
    data = {
        "system_info": {
            "hostname": "multi-test",
            "os": "macOS",
            "os_version": "14.0"
        },
        "warnings": [
            {
                "test_id": "SSH-7408",
                "message": "SSH PermitRootLogin is enabled",
                "details": "Root login via SSH is not recommended"
            }
        ],
        "suggestions": [
            {
                "test_id": "FILE-6310",
                "message": "Enable system file integrity monitoring",
                "details": "Consider using AIDE or Samhain"
            },
            {
                "test_id": "FIRE-4512",
                "message": "Enable firewall",
                "details": "macOS firewall is currently disabled"
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2024-5678",
                "cve": "CVE-2024-5678",
                "message": "Sudo privilege escalation vulnerability",
                "package": "sudo"
            }
        ]
    }
    f = tmp_path / "lynis.json"
    write(f, data)
    adapter = LynisAdapter()
    items = adapter.parse(f)

    assert len(items) == 4
    # First: warning (HIGH)
    assert items[0].severity == "HIGH"
    assert items[0].ruleId == "SSH-7408"
    # Second & Third: suggestions (MEDIUM)
    assert items[1].severity == "MEDIUM"
    assert items[1].ruleId == "FILE-6310"
    assert items[2].severity == "MEDIUM"
    assert items[2].ruleId == "FIRE-4512"
    # Fourth: vulnerability (CRITICAL)
    assert items[3].severity == "CRITICAL"
    assert items[3].ruleId == "CVE-2024-5678"


def test_lynis_adapter_missing_test_id(tmp_path: Path):
    """Test Lynis adapter handles findings without test_id gracefully."""
    data = {
        "system_info": {
            "hostname": "test-host"
        },
        "warnings": [
            {
                "message": "Security issue detected",
                "details": "Some details here"
            }
        ],
        "suggestions": [
            {
                "message": "Consider improving security",
                "details": "Some suggestion"
            }
        ]
    }
    f = tmp_path / "lynis.json"
    write(f, data)
    adapter = LynisAdapter()
    items = adapter.parse(f)

    assert len(items) == 2
    # Warning without test_id
    assert items[0].ruleId == "lynis-warning"
    assert items[0].context["test_id"] is None
    # Suggestion without test_id
    assert items[1].ruleId == "lynis-suggestion"
    assert items[1].context["test_id"] is None


def test_lynis_adapter_minimal_system_info(tmp_path: Path):
    """Test Lynis adapter with minimal system info."""
    data = {
        "warnings": [
            {
                "test_id": "TEST-1234",
                "message": "Test warning"
            }
        ]
    }
    f = tmp_path / "lynis.json"
    write(f, data)
    adapter = LynisAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should use fallback values
    assert items[0].context["hostname"] == "localhost"
    assert items[0].context["os"] == "unknown"
    assert items[0].context["os_version"] is None
    assert items[0].location["path"] == "localhost"


def test_lynis_adapter_vulnerability_without_package(tmp_path: Path):
    """Test Lynis adapter handles vulnerability without package info."""
    data = {
        "system_info": {
            "hostname": "test-host"
        },
        "vulnerabilities": [
            {
                "id": "VULN-123",
                "cve": "CVE-2024-9999",
                "message": "Generic vulnerability"
            }
        ]
    }
    f = tmp_path / "lynis.json"
    write(f, data)
    adapter = LynisAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].context["package"] is None
    assert items[0].location["path"] == "test-host"  # No package suffix


def test_lynis_adapter_empty_arrays(tmp_path: Path):
    """Test Lynis adapter with empty warnings/suggestions/vulnerabilities arrays."""
    data = {
        "system_info": {
            "hostname": "clean-host"
        },
        "warnings": [],
        "suggestions": [],
        "vulnerabilities": []
    }
    f = tmp_path / "lynis.json"
    write(f, data)
    adapter = LynisAdapter()
    items = adapter.parse(f)

    assert items == []


def test_lynis_adapter_empty_file(tmp_path: Path):
    """Test Lynis adapter handles empty JSON file."""
    f = tmp_path / "lynis.json"
    f.write_text("", encoding="utf-8")
    adapter = LynisAdapter()
    items = adapter.parse(f)

    assert items == []


def test_lynis_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Lynis findings are enriched with compliance mappings."""
    data = {
        "system_info": {
            "hostname": "compliance-test"
        },
        "warnings": [
            {
                "test_id": "COMP-1234",
                "message": "Compliance issue detected"
            }
        ]
    }
    f = tmp_path / "lynis.json"
    write(f, data)
    adapter = LynisAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
