import json
from pathlib import Path

from scripts.core.adapters.grype_adapter import GrypeAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_grype_adapter_cve_with_fix(tmp_path: Path):
    """Test Grype adapter with CVE vulnerability that has a fix."""
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-1234",
                    "severity": "HIGH",
                    "description": "Buffer overflow in libxml2 allows remote code execution",
                    "cvss": [
                        {
                            "version": "3.1",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "metrics": {
                                "baseScore": 9.8
                            }
                        }
                    ],
                    "fix": {
                        "versions": ["2.9.14", "2.10.0"]
                    },
                    "dataSource": "nvd",
                    "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2023-1234"]
                },
                "artifact": {
                    "name": "libxml2",
                    "version": "2.9.10",
                    "type": "deb",
                    "purl": "pkg:deb/ubuntu/libxml2@2.9.10",
                    "locations": [
                        {
                            "path": "/usr/lib/x86_64-linux-gnu/libxml2.so.2"
                        }
                    ]
                },
                "matchDetails": [
                    {
                        "matcher": "dpkg-matcher"
                    }
                ]
            }
        ]
    }
    f = tmp_path / "grype.json"
    write(f, data)
    adapter = GrypeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "CVE-2023-1234"
    assert items[0].severity == "HIGH"
    assert "vulnerability" in items[0].tags
    assert "sca" in items[0].tags
    assert "cve" in items[0].tags
    assert "deb" in items[0].tags
    assert items[0].context["artifact_name"] == "libxml2"
    assert items[0].context["artifact_version"] == "2.9.10"
    assert items[0].context["fixed_versions"] == ["2.9.14", "2.10.0"]
    assert items[0].cvss["version"] == "3.x"
    assert items[0].cvss["score"] == 9.8
    assert "Upgrade libxml2 to version 2.9.14, 2.10.0" in items[0].remediation


def test_grype_adapter_cve_no_fix(tmp_path: Path):
    """Test Grype adapter with CVE vulnerability without a fix."""
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-5678",
                    "severity": "MEDIUM",
                    "description": "Denial of service in nginx",
                    "fix": {
                        "versions": []
                    },
                    "dataSource": "github"
                },
                "artifact": {
                    "name": "nginx",
                    "version": "1.20.0",
                    "type": "apk",
                    "locations": [
                        {
                            "path": "/usr/sbin/nginx"
                        }
                    ]
                }
            }
        ]
    }
    f = tmp_path / "grype.json"
    write(f, data)
    adapter = GrypeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "MEDIUM"
    assert "No fix available" in items[0].remediation


def test_grype_adapter_multiple_vulnerabilities(tmp_path: Path):
    """Test Grype adapter with multiple vulnerabilities."""
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-1111",
                    "severity": "CRITICAL",
                    "description": "Critical vuln in openssl",
                    "fix": {
                        "versions": ["3.0.8"]
                    }
                },
                "artifact": {
                    "name": "openssl",
                    "version": "3.0.7",
                    "locations": [
                        {
                            "path": "/usr/lib/libssl.so.3"
                        }
                    ]
                }
            },
            {
                "vulnerability": {
                    "id": "CVE-2023-2222",
                    "severity": "HIGH",
                    "description": "High vuln in curl",
                    "fix": {
                        "versions": ["8.0.0"]
                    }
                },
                "artifact": {
                    "name": "curl",
                    "version": "7.88.0",
                    "locations": [
                        {
                            "path": "/usr/bin/curl"
                        }
                    ]
                }
            },
            {
                "vulnerability": {
                    "id": "CVE-2023-3333",
                    "severity": "LOW",
                    "description": "Low vuln in zlib",
                    "fix": {
                        "versions": ["1.2.13"]
                    }
                },
                "artifact": {
                    "name": "zlib",
                    "version": "1.2.11",
                    "locations": [
                        {
                            "path": "/usr/lib/libz.so.1"
                        }
                    ]
                }
            }
        ]
    }
    f = tmp_path / "grype.json"
    write(f, data)
    adapter = GrypeAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].severity == "CRITICAL"
    assert items[1].severity == "HIGH"
    assert items[2].severity == "LOW"
    assert items[0].ruleId == "CVE-2023-1111"
    assert items[1].ruleId == "CVE-2023-2222"
    assert items[2].ruleId == "CVE-2023-3333"


def test_grype_adapter_cvss_v2_fallback(tmp_path: Path):
    """Test Grype adapter with CVSS v2 when v3 not available."""
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2020-1234",
                    "severity": "HIGH",
                    "description": "Old vulnerability with CVSS v2",
                    "cvss": [
                        {
                            "version": "2.0",
                            "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                            "metrics": {
                                "baseScore": 7.5
                            }
                        }
                    ],
                    "fix": {
                        "versions": ["1.0.0"]
                    }
                },
                "artifact": {
                    "name": "oldpackage",
                    "version": "0.9.0",
                    "locations": [
                        {
                            "path": "/usr/lib/oldpackage.so"
                        }
                    ]
                }
            }
        ]
    }
    f = tmp_path / "grype.json"
    write(f, data)
    adapter = GrypeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].cvss["version"] == "2.0"
    assert items[0].cvss["score"] == 7.5


def test_grype_adapter_multiple_cvss_versions(tmp_path: Path):
    """Test Grype adapter prefers CVSS v3 over v2."""
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-5555",
                    "severity": "HIGH",
                    "description": "Vulnerability with both CVSS v2 and v3",
                    "cvss": [
                        {
                            "version": "2.0",
                            "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                            "metrics": {
                                "baseScore": 7.5
                            }
                        },
                        {
                            "version": "3.1",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "metrics": {
                                "baseScore": 9.8
                            }
                        }
                    ],
                    "fix": {
                        "versions": ["2.0.0"]
                    }
                },
                "artifact": {
                    "name": "testpkg",
                    "version": "1.0.0",
                    "locations": [
                        {
                            "path": "/usr/lib/testpkg.so"
                        }
                    ]
                }
            }
        ]
    }
    f = tmp_path / "grype.json"
    write(f, data)
    adapter = GrypeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should prefer CVSS v3
    assert items[0].cvss["version"] == "3.x"
    assert items[0].cvss["score"] == 9.8


def test_grype_adapter_missing_locations(tmp_path: Path):
    """Test Grype adapter handles missing location information."""
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-6666",
                    "severity": "MEDIUM",
                    "description": "Test vulnerability",
                    "fix": {
                        "versions": []
                    }
                },
                "artifact": {
                    "name": "testartifact",
                    "version": "1.0.0",
                    "locations": []
                }
            }
        ]
    }
    f = tmp_path / "grype.json"
    write(f, data)
    adapter = GrypeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should use fallback format
    assert items[0].location["path"] == "testartifact@1.0.0"


def test_grype_adapter_purl_tagging(tmp_path: Path):
    """Test Grype adapter includes purl in context."""
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-7777",
                    "severity": "HIGH",
                    "description": "Test",
                    "fix": {
                        "versions": []
                    }
                },
                "artifact": {
                    "name": "requests",
                    "version": "2.28.0",
                    "type": "python",
                    "purl": "pkg:pypi/requests@2.28.0",
                    "locations": [
                        {
                            "path": "/usr/lib/python3/dist-packages/requests"
                        }
                    ]
                }
            }
        ]
    }
    f = tmp_path / "grype.json"
    write(f, data)
    adapter = GrypeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].context["artifact_purl"] == "pkg:pypi/requests@2.28.0"
    assert "python" in items[0].tags


def test_grype_adapter_empty_matches(tmp_path: Path):
    """Test Grype adapter with empty matches array."""
    data = {
        "matches": []
    }
    f = tmp_path / "grype.json"
    write(f, data)
    adapter = GrypeAdapter()
    items = adapter.parse(f)

    assert items == []


def test_grype_adapter_empty_file(tmp_path: Path):
    """Test Grype adapter handles empty JSON file."""
    f = tmp_path / "grype.json"
    f.write_text("", encoding="utf-8")
    adapter = GrypeAdapter()
    items = adapter.parse(f)

    assert items == []


def test_grype_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Grype findings are enriched with compliance mappings."""
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-8888",
                    "severity": "HIGH",
                    "description": "Test vulnerability",
                    "fix": {
                        "versions": []
                    }
                },
                "artifact": {
                    "name": "testpkg",
                    "version": "1.0.0",
                    "locations": [
                        {
                            "path": "/usr/lib/testpkg.so"
                        }
                    ]
                }
            }
        ]
    }
    f = tmp_path / "grype.json"
    write(f, data)
    adapter = GrypeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
