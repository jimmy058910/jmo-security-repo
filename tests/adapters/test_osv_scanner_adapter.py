import json
from pathlib import Path

from scripts.core.adapters.osv_scanner_adapter import OSVScannerAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_osv_scanner_adapter_npm_vulnerability(tmp_path: Path):
    """Test OSV-Scanner adapter with npm package vulnerability."""
    data = {
        "results": [
            {
                "source": {
                    "path": "package-lock.json",
                    "type": "lockfile"
                },
                "packages": [
                    {
                        "package": {
                            "name": "lodash",
                            "version": "4.17.15",
                            "ecosystem": "npm"
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-p6mc-m468-83gw",
                                "aliases": ["CVE-2020-8203"],
                                "summary": "Prototype Pollution in lodash",
                                "details": "Versions of lodash prior to 4.17.19 are vulnerable to prototype pollution.",
                                "severity": [
                                    {
                                        "type": "CVSS_V3",
                                        "score": "7.4"
                                    }
                                ],
                                "references": [
                                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203"},
                                    {"url": "https://github.com/advisories/GHSA-p6mc-m468-83gw"}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "osv-scanner.json"
    write(f, data)
    adapter = OSVScannerAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "GHSA-p6mc-m468-83gw"
    assert items[0].severity == "HIGH"  # 7.4 CVSS is HIGH
    assert "sca" in items[0].tags
    assert "vulnerability" in items[0].tags
    assert "npm" in items[0].tags
    assert items[0].context["package_name"] == "lodash"
    assert items[0].context["package_version"] == "4.17.15"
    assert "CVE-2020-8203" in items[0].context["cves"]
    assert items[0].cvss["v3"] == "7.4"


def test_osv_scanner_adapter_pypi_vulnerability(tmp_path: Path):
    """Test OSV-Scanner adapter with PyPI package vulnerability."""
    data = {
        "results": [
            {
                "source": {
                    "path": "requirements.txt",
                    "type": "lockfile"
                },
                "packages": [
                    {
                        "package": {
                            "name": "django",
                            "version": "2.2.0",
                            "ecosystem": "PyPI"
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-2hrw-hx67-34x6",
                                "aliases": ["CVE-2021-28658"],
                                "summary": "Directory traversal in Django",
                                "database_specific": {
                                    "severity": "CRITICAL"
                                },
                                "references": [
                                    {"url": "https://www.djangoproject.com/weblog/2021/apr/06/security-releases/"}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "osv-scanner.json"
    write(f, data)
    adapter = OSVScannerAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "GHSA-2hrw-hx67-34x6"
    assert items[0].severity == "CRITICAL"
    assert "pypi" in items[0].tags
    assert items[0].context["package_ecosystem"] == "PyPI"


def test_osv_scanner_adapter_multiple_vulnerabilities(tmp_path: Path):
    """Test OSV-Scanner adapter with multiple vulnerabilities in different packages."""
    data = {
        "results": [
            {
                "source": {
                    "path": "go.sum",
                    "type": "lockfile"
                },
                "packages": [
                    {
                        "package": {
                            "name": "github.com/gin-gonic/gin",
                            "version": "1.6.0",
                            "ecosystem": "Go"
                        },
                        "vulnerabilities": [
                            {
                                "id": "GO-2020-0001",
                                "aliases": ["CVE-2020-28483"],
                                "summary": "Gin before 1.6.0 allows a denial of service",
                                "details": "The framework allows attackers to craft malicious requests",
                                "references": [
                                    {"url": "https://pkg.go.dev/vuln/GO-2020-0001"}
                                ]
                            }
                        ]
                    },
                    {
                        "package": {
                            "name": "golang.org/x/crypto",
                            "version": "0.0.0-20200622213623-75b288015ac9",
                            "ecosystem": "Go"
                        },
                        "vulnerabilities": [
                            {
                                "id": "GO-2021-0113",
                                "aliases": ["CVE-2020-29652"],
                                "summary": "Panic in ssh server",
                                "severity": [
                                    {
                                        "type": "CVSS_V3",
                                        "score": "7.5"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "osv-scanner.json"
    write(f, data)
    adapter = OSVScannerAdapter()
    items = adapter.parse(f)

    assert len(items) == 2
    assert items[0].ruleId == "GO-2020-0001"
    assert items[1].ruleId == "GO-2021-0113"
    assert "go" in items[0].tags
    assert "go" in items[1].tags


def test_osv_scanner_adapter_docker_source(tmp_path: Path):
    """Test OSV-Scanner adapter with Docker image scan source."""
    data = {
        "results": [
            {
                "source": {
                    "path": "nginx:latest",
                    "type": "docker"
                },
                "packages": [
                    {
                        "package": {
                            "name": "openssl",
                            "version": "1.1.1g",
                            "ecosystem": "Debian"
                        },
                        "vulnerabilities": [
                            {
                                "id": "DSA-4963-1",
                                "aliases": ["CVE-2021-3711"],
                                "summary": "OpenSSL buffer overflow",
                                "database_specific": {
                                    "severity": "HIGH"
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "osv-scanner.json"
    write(f, data)
    adapter = OSVScannerAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].context["source_type"] == "docker"
    assert items[0].location["path"] == "nginx:latest"
    assert "debian" in items[0].tags


def test_osv_scanner_adapter_no_severity(tmp_path: Path):
    """Test OSV-Scanner adapter handles missing severity gracefully."""
    data = {
        "results": [
            {
                "source": {"path": "pom.xml", "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "log4j-core",
                            "version": "2.14.1",
                            "ecosystem": "Maven"
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-jfh8-c2jp-5v3q",
                                "aliases": ["CVE-2021-44228"],
                                "summary": "Log4Shell RCE vulnerability"
                                # No severity field
                            }
                        ]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "osv-scanner.json"
    write(f, data)
    adapter = OSVScannerAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "MEDIUM"  # Default when no severity


def test_osv_scanner_adapter_empty_file(tmp_path: Path):
    """Test OSV-Scanner adapter handles empty JSON file."""
    f = tmp_path / "osv-scanner.json"
    f.write_text("", encoding="utf-8")
    adapter = OSVScannerAdapter()
    items = adapter.parse(f)

    assert items == []


def test_osv_scanner_adapter_no_vulnerabilities(tmp_path: Path):
    """Test OSV-Scanner adapter with clean scan (no vulnerabilities)."""
    data = {
        "results": [
            {
                "source": {"path": "package.json", "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "react",
                            "version": "18.2.0",
                            "ecosystem": "npm"
                        },
                        "vulnerabilities": []
                    }
                ]
            }
        ]
    }
    f = tmp_path / "osv-scanner.json"
    write(f, data)
    adapter = OSVScannerAdapter()
    items = adapter.parse(f)

    assert items == []


def test_osv_scanner_adapter_aliases_extraction(tmp_path: Path):
    """Test OSV-Scanner adapter extracts CVE aliases correctly."""
    data = {
        "results": [
            {
                "source": {"path": "Cargo.lock", "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "tokio",
                            "version": "1.0.0",
                            "ecosystem": "crates.io"
                        },
                        "vulnerabilities": [
                            {
                                "id": "RUSTSEC-2021-0072",
                                "aliases": [
                                    "CVE-2021-38191",
                                    "CVE-2021-38192",
                                    "GHSA-4q83-7cq4-p6wg"
                                ],
                                "summary": "Data race in tokio"
                            }
                        ]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "osv-scanner.json"
    write(f, data)
    adapter = OSVScannerAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert "CVE-2021-38191" in items[0].context["cves"]
    assert "CVE-2021-38192" in items[0].context["cves"]
    assert len(items[0].context["aliases"]) == 3


def test_osv_scanner_adapter_compliance_enrichment(tmp_path: Path):
    """Test that OSV-Scanner findings are enriched with compliance mappings."""
    data = {
        "results": [
            {
                "source": {"path": "yarn.lock", "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "express",
                            "version": "4.16.0",
                            "ecosystem": "npm"
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-rv95-896h-c2vc",
                                "aliases": ["CVE-2022-24999"],
                                "summary": "qs vulnerable to Prototype Pollution",
                                "database_specific": {
                                    "severity": "HIGH"
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }
    f = tmp_path / "osv-scanner.json"
    write(f, data)
    adapter = OSVScannerAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
