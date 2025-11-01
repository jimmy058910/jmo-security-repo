import json
from pathlib import Path

from scripts.core.adapters.cdxgen_adapter import CdxgenAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_cdxgen_adapter_basic_sbom(tmp_path: Path):
    """Test cdxgen adapter with basic CycloneDX SBOM."""
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:npm/[email protected]",
                "purl": "pkg:npm/[email protected]",
                "name": "lodash",
                "version": "4.17.21",
                "licenses": [
                    {
                        "license": {
                            "id": "MIT"
                        }
                    }
                ]
            }
        ]
    }
    f = tmp_path / "cdxgen.json"
    write(f, data)
    adapter = CdxgenAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "SBOM.COMPONENT"
    assert items[0].severity == "INFO"
    assert "sbom" in items[0].tags
    assert "inventory" in items[0].tags
    assert items[0].context["component_name"] == "lodash"
    assert items[0].context["component_version"] == "4.17.21"
    assert items[0].context["purl"] == "pkg:npm/[email protected]"
    assert "MIT" in items[0].context["licenses"]


def test_cdxgen_adapter_multiple_components(tmp_path: Path):
    """Test cdxgen adapter with multiple components."""
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "express",
                "version": "4.18.2",
                "purl": "pkg:npm/[email protected]",
                "licenses": [
                    {
                        "license": {
                            "id": "MIT"
                        }
                    }
                ]
            },
            {
                "type": "library",
                "name": "react",
                "version": "18.2.0",
                "purl": "pkg:npm/[email protected]",
                "licenses": [
                    {
                        "license": {
                            "id": "MIT"
                        }
                    }
                ]
            }
        ]
    }
    f = tmp_path / "cdxgen.json"
    write(f, data)
    adapter = CdxgenAdapter()
    items = adapter.parse(f)

    assert len(items) == 2
    assert items[0].context["component_name"] == "express"
    assert items[1].context["component_name"] == "react"


def test_cdxgen_adapter_python_packages(tmp_path: Path):
    """Test cdxgen adapter with Python packages."""
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "name": "django",
                "version": "4.2.0",
                "purl": "pkg:pypi/[email protected]",
                "licenses": [
                    {
                        "license": {
                            "id": "BSD-3-Clause"
                        }
                    }
                ],
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": "7e4225ec065e0f354ccf7349a22d209de09cc1c074832be9eb84c51c1799109a"
                    }
                ]
            }
        ]
    }
    f = tmp_path / "cdxgen.json"
    write(f, data)
    adapter = CdxgenAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].context["purl"] == "pkg:pypi/[email protected]"
    assert items[0].context["licenses"] == ["BSD-3-Clause"]
    assert "SHA-256" in items[0].context["hashes"]


def test_cdxgen_adapter_with_supplier(tmp_path: Path):
    """Test cdxgen adapter with supplier information."""
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "spring-boot",
                "version": "3.1.0",
                "purl": "pkg:maven/org.springframework.boot/[email protected]",
                "supplier": {
                    "name": "Spring Community",
                    "url": ["https://spring.io"]
                },
                "licenses": [
                    {
                        "license": {
                            "id": "Apache-2.0"
                        }
                    }
                ]
            }
        ]
    }
    f = tmp_path / "cdxgen.json"
    write(f, data)
    adapter = CdxgenAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].context["supplier"] == "Spring Community"


def test_cdxgen_adapter_application_type(tmp_path: Path):
    """Test cdxgen adapter with application component type."""
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "application",
                "name": "my-app",
                "version": "1.0.0",
                "purl": "pkg:npm/[email protected]",
                "licenses": [
                    {
                        "license": {
                            "name": "Proprietary"
                        }
                    }
                ]
            }
        ]
    }
    f = tmp_path / "cdxgen.json"
    write(f, data)
    adapter = CdxgenAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].context["component_type"] == "application"
    assert "application" in items[0].tags
    assert items[0].context["licenses"] == ["Proprietary"]


def test_cdxgen_adapter_no_purl(tmp_path: Path):
    """Test cdxgen adapter handles components without PURL."""
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "type": "library",
                "name": "custom-lib",
                "version": "2.0.0",
                # No purl field
                "licenses": [
                    {
                        "license": {
                            "id": "MIT"
                        }
                    }
                ]
            }
        ]
    }
    f = tmp_path / "cdxgen.json"
    write(f, data)
    adapter = CdxgenAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].context["purl"] is None
    # Should still create finding with name@version
    assert "custom-lib" in items[0].message


def test_cdxgen_adapter_empty_components(tmp_path: Path):
    """Test cdxgen adapter with empty components array."""
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": []
    }
    f = tmp_path / "cdxgen.json"
    write(f, data)
    adapter = CdxgenAdapter()
    items = adapter.parse(f)

    assert items == []


def test_cdxgen_adapter_invalid_bom_format(tmp_path: Path):
    """Test cdxgen adapter handles invalid BOM format."""
    data = {
        "bomFormat": "SPDX",  # Not CycloneDX
        "components": [
            {
                "name": "test",
                "version": "1.0.0"
            }
        ]
    }
    f = tmp_path / "cdxgen.json"
    write(f, data)
    adapter = CdxgenAdapter()
    items = adapter.parse(f)

    assert items == []


def test_cdxgen_adapter_empty_file(tmp_path: Path):
    """Test cdxgen adapter handles empty JSON file."""
    f = tmp_path / "cdxgen.json"
    f.write_text("", encoding="utf-8")
    adapter = CdxgenAdapter()
    items = adapter.parse(f)

    assert items == []


def test_cdxgen_adapter_compliance_enrichment(tmp_path: Path):
    """Test that cdxgen findings are enriched with compliance mappings."""
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "openssl",
                "version": "1.1.1",
                "purl": "pkg:generic/[email protected]",
                "licenses": [
                    {
                        "license": {
                            "id": "OpenSSL"
                        }
                    }
                ]
            }
        ]
    }
    f = tmp_path / "cdxgen.json"
    write(f, data)
    adapter = CdxgenAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
