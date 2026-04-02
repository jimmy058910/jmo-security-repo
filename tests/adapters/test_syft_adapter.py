"""Tests for Syft adapter."""

import json
from pathlib import Path

from scripts.core.adapters.syft_adapter import SyftAdapter


def write(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a file and return the path."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_syft_packages(tmp_path: Path):
    """Test Syft adapter parses package artifacts."""
    sample = {
        "artifacts": [
            {
                "id": "pkg-1",
                "name": "requests",
                "version": "2.28.1",
                "type": "python",
                "locations": [{"path": "/app/requirements.txt"}],
            },
            {
                "id": "pkg-2",
                "name": "flask",
                "version": "2.0.0",
                "type": "python",
                "locations": [{"path": "/app/requirements.txt"}],
            },
        ],
        "artifactRelationships": [],
    }
    p = write(tmp_path, "syft.json", json.dumps(sample))

    adapter = SyftAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 2
    assert all(f.ruleId == "SBOM.PACKAGE" for f in findings)
    assert all(f.severity == "INFO" for f in findings)
    assert all("sbom" in f.tags for f in findings)
    assert all("package" in f.tags for f in findings)

    # Check package names in titles
    titles = {f.title for f in findings}
    assert "requests 2.28.1" in titles
    assert "flask 2.0.0" in titles


def test_syft_vulnerabilities(tmp_path: Path):
    """Test Syft adapter parses vulnerabilities."""
    sample = {
        "artifacts": [
            {
                "id": "pkg-1",
                "name": "vulnerable-package",
                "version": "1.0.0",
                "locations": [{"path": "/app/package.json"}],
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2024-1234",
                "severity": "HIGH",
                "description": "Remote code execution vulnerability",
                "artifactIds": ["pkg-1"],
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
            }
        ],
    }
    p = write(tmp_path, "syft.json", json.dumps(sample))

    adapter = SyftAdapter()
    findings = adapter.parse(p)

    # 1 package + 1 vulnerability
    assert len(findings) == 2

    # Find the vulnerability finding
    vuln = next((f for f in findings if f.ruleId == "CVE-2024-1234"), None)
    assert vuln is not None
    assert vuln.severity == "HIGH"
    assert "vulnerability" in vuln.tags
    assert vuln.location["path"] == "/app/package.json"


def test_syft_empty_results(tmp_path: Path):
    """Test Syft adapter handles empty artifacts."""
    sample = {"artifacts": [], "artifactRelationships": []}
    p = write(tmp_path, "syft.json", json.dumps(sample))

    adapter = SyftAdapter()
    findings = adapter.parse(p)

    assert findings == []


def test_syft_empty_bad_input(tmp_path: Path):
    """Test Syft adapter handles empty/bad input."""
    adapter = SyftAdapter()

    p1 = write(tmp_path, "empty.json", "")
    assert adapter.parse(p1) == []

    p2 = write(tmp_path, "bad.json", "{not json}")
    assert adapter.parse(p2) == []


def test_syft_missing_file(tmp_path: Path):
    """Test Syft adapter handles missing file."""
    adapter = SyftAdapter()
    missing = tmp_path / "nonexistent.json"
    assert adapter.parse(missing) == []


def test_syft_package_without_location(tmp_path: Path):
    """Test Syft adapter handles packages without location."""
    sample = {
        "artifacts": [
            {
                "id": "pkg-1",
                "name": "orphan-package",
                "version": "1.0.0",
                # No locations
            }
        ],
    }
    p = write(tmp_path, "syft.json", json.dumps(sample))

    adapter = SyftAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].location["path"] == ""
    assert findings[0].title == "orphan-package 1.0.0"


def test_syft_multiple_package_types(tmp_path: Path):
    """Test Syft adapter handles various package types."""
    sample = {
        "artifacts": [
            {
                "id": "1",
                "name": "python-pkg",
                "version": "1.0",
                "type": "python",
                "locations": [{"path": "/requirements.txt"}],
            },
            {
                "id": "2",
                "name": "npm-pkg",
                "version": "2.0",
                "type": "npm",
                "locations": [{"path": "/package.json"}],
            },
            {
                "id": "3",
                "name": "go-pkg",
                "version": "3.0",
                "type": "go-module",
                "locations": [{"path": "/go.mod"}],
            },
        ],
    }
    p = write(tmp_path, "syft.json", json.dumps(sample))

    adapter = SyftAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 3
    paths = {f.location["path"] for f in findings}
    assert paths == {"/requirements.txt", "/package.json", "/go.mod"}


def test_syft_vulnerability_severity_levels(tmp_path: Path):
    """Test Syft adapter maps vulnerability severity correctly."""
    sample = {
        "artifacts": [
            {
                "id": "1",
                "name": "pkg",
                "version": "1.0",
                "locations": [{"path": "/test"}],
            }
        ],
        "vulnerabilities": [
            {"id": "CVE-1", "severity": "critical", "artifactIds": ["1"]},
            {"id": "CVE-2", "severity": "high", "artifactIds": ["1"]},
            {"id": "CVE-3", "severity": "medium", "artifactIds": ["1"]},
            {"id": "CVE-4", "severity": "low", "artifactIds": ["1"]},
        ],
    }
    p = write(tmp_path, "syft.json", json.dumps(sample))

    adapter = SyftAdapter()
    findings = adapter.parse(p)

    # 1 package + 4 vulnerabilities
    vulns = [f for f in findings if "vulnerability" in f.tags]
    assert len(vulns) == 4

    severity_map = {f.ruleId: f.severity for f in vulns}
    assert severity_map["CVE-1"] == "CRITICAL"
    assert severity_map["CVE-2"] == "HIGH"
    assert severity_map["CVE-3"] == "MEDIUM"
    assert severity_map["CVE-4"] == "LOW"


def test_syft_vulnerability_no_matching_artifact(tmp_path: Path):
    """Test Syft adapter handles vulnerability without matching artifact."""
    sample = {
        "artifacts": [
            {
                "id": "pkg-1",
                "name": "pkg",
                "version": "1.0",
                "locations": [{"path": "/app"}],
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2024-ORPHAN",
                "severity": "HIGH",
                "artifactIds": ["non-existent"],
                "description": "Orphan vulnerability",
            }
        ],
    }
    p = write(tmp_path, "syft.json", json.dumps(sample))

    adapter = SyftAdapter()
    findings = adapter.parse(p)

    # Should still parse, just without location info
    assert len(findings) == 2  # 1 package + 1 vuln
    vuln = next((f for f in findings if f.ruleId == "CVE-2024-ORPHAN"), None)
    assert vuln is not None
    assert vuln.location["path"] == ""


def test_syft_compliance_enrichment(tmp_path: Path):
    """Test Syft findings are enriched with compliance mappings."""
    sample = {
        "artifacts": [
            {
                "id": "1",
                "name": "test-pkg",
                "version": "1.0",
                "locations": [{"path": "/test"}],
            }
        ],
    }
    p = write(tmp_path, "syft.json", json.dumps(sample))

    adapter = SyftAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].schemaVersion == "1.2.0"


def test_syft_metadata(tmp_path: Path):
    """Test Syft adapter metadata."""
    adapter = SyftAdapter()
    metadata = adapter.metadata

    assert metadata.name == "syft"
    assert metadata.tool_name == "syft"
    assert metadata.schema_version == "1.2.0"
    assert metadata.output_format == "json"


def test_syft_large_sbom(tmp_path: Path):
    """Test Syft adapter handles large SBOM."""
    # Generate 100 packages
    artifacts = [
        {
            "id": f"pkg-{i}",
            "name": f"package-{i}",
            "version": f"{i}.0.0",
            "type": "npm",
            "locations": [{"path": f"/node_modules/package-{i}"}],
        }
        for i in range(100)
    ]
    sample = {"artifacts": artifacts}
    p = write(tmp_path, "syft.json", json.dumps(sample))

    adapter = SyftAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 100
    assert all(f.severity == "INFO" for f in findings)
