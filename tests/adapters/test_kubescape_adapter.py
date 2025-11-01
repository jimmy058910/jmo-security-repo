import json
from pathlib import Path

from scripts.core.adapters.kubescape_adapter import KubescapeAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_kubescape_adapter_basic_finding(tmp_path: Path):
    """Test Kubescape adapter with basic control failure."""
    data = {
        "summaryDetails": {
            "frameworkName": "NSA-CISA",
            "controls": {
                "C-0001": {
                    "name": "Privileged container",
                    "description": "Containers running in privileged mode",
                    "scoreFactor": 9,
                    "failedResources": ["pod-123"],
                    "remediation": "Remove privileged: true from container spec"
                }
            }
        },
        "resources": [
            {
                "resourceID": "pod-123",
                "kind": "Pod",
                "name": "nginx-pod",
                "namespace": "default"
            }
        ]
    }
    f = tmp_path / "kubescape.json"
    write(f, data)
    adapter = KubescapeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "C-0001"
    assert items[0].severity == "HIGH"  # scoreFactor 9 = HIGH
    assert "k8s-security" in items[0].tags
    assert "misconfiguration" in items[0].tags
    assert items[0].context["resource_kind"] == "Pod"
    assert items[0].context["resource_name"] == "nginx-pod"
    assert items[0].context["resource_namespace"] == "default"
    assert items[0].context["framework"] == "NSA-CISA"


def test_kubescape_adapter_critical_severity(tmp_path: Path):
    """Test Kubescape adapter with CRITICAL severity (scoreFactor >= 10)."""
    data = {
        "summaryDetails": {
            "controls": {
                "C-0002": {
                    "name": "Anonymous access enabled",
                    "description": "Cluster allows anonymous access",
                    "scoreFactor": 10,
                    "failedResources": ["cluster-1"],
                    "remediation": "Disable anonymous access"
                }
            }
        },
        "resources": [
            {
                "resourceID": "cluster-1",
                "kind": "Cluster",
                "name": "prod-cluster"
            }
        ]
    }
    f = tmp_path / "kubescape.json"
    write(f, data)
    adapter = KubescapeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "CRITICAL"
    assert items[0].context["score_factor"] == 10


def test_kubescape_adapter_multiple_failed_resources(tmp_path: Path):
    """Test Kubescape adapter with multiple failed resources for same control."""
    data = {
        "summaryDetails": {
            "controls": {
                "C-0003": {
                    "name": "HostPath mount",
                    "description": "Containers mounting hostPath volumes",
                    "scoreFactor": 7,
                    "failedResources": ["pod-1", "pod-2", "pod-3"],
                    "remediation": "Avoid hostPath mounts"
                }
            }
        },
        "resources": [
            {
                "resourceID": "pod-1",
                "kind": "Pod",
                "name": "app-1",
                "namespace": "production"
            },
            {
                "resourceID": "pod-2",
                "kind": "Pod",
                "name": "app-2",
                "namespace": "production"
            },
            {
                "resourceID": "pod-3",
                "kind": "Pod",
                "name": "app-3",
                "namespace": "staging"
            }
        ]
    }
    f = tmp_path / "kubescape.json"
    write(f, data)
    adapter = KubescapeAdapter()
    items = adapter.parse(f)

    assert len(items) == 3  # One finding per failed resource
    assert all(f.ruleId == "C-0003" for f in items)
    assert items[0].context["resource_namespace"] == "production"
    assert items[2].context["resource_namespace"] == "staging"


def test_kubescape_adapter_no_namespace(tmp_path: Path):
    """Test Kubescape adapter with cluster-scoped resource (no namespace)."""
    data = {
        "summaryDetails": {
            "controls": {
                "C-0004": {
                    "name": "ClusterRole permissions",
                    "description": "Excessive ClusterRole permissions",
                    "scoreFactor": 6,
                    "failedResources": ["role-123"]
                }
            }
        },
        "resources": [
            {
                "resourceID": "role-123",
                "kind": "ClusterRole",
                "name": "admin-role"
                # No namespace field
            }
        ]
    }
    f = tmp_path / "kubescape.json"
    write(f, data)
    adapter = KubescapeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "MEDIUM"  # scoreFactor 6 = MEDIUM
    assert items[0].context["resource_namespace"] is None
    assert "namespace:" not in items[0].message


def test_kubescape_adapter_low_severity(tmp_path: Path):
    """Test Kubescape adapter with LOW severity (scoreFactor < 4)."""
    data = {
        "summaryDetails": {
            "controls": {
                "C-0005": {
                    "name": "Label best practices",
                    "description": "Missing recommended labels",
                    "scoreFactor": 2,
                    "failedResources": ["pod-456"]
                }
            }
        },
        "resources": [
            {
                "resourceID": "pod-456",
                "kind": "Deployment",
                "name": "web-app",
                "namespace": "default"
            }
        ]
    }
    f = tmp_path / "kubescape.json"
    write(f, data)
    adapter = KubescapeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "LOW"


def test_kubescape_adapter_no_failed_resources(tmp_path: Path):
    """Test Kubescape adapter skips controls with no failures."""
    data = {
        "summaryDetails": {
            "controls": {
                "C-0006": {
                    "name": "Passing control",
                    "description": "This control passed",
                    "scoreFactor": 8,
                    "failedResources": []  # No failures
                }
            }
        },
        "resources": []
    }
    f = tmp_path / "kubescape.json"
    write(f, data)
    adapter = KubescapeAdapter()
    items = adapter.parse(f)

    assert items == []  # Should skip controls with no failures


def test_kubescape_adapter_missing_resource_details(tmp_path: Path):
    """Test Kubescape adapter handles missing resource details gracefully."""
    data = {
        "summaryDetails": {
            "controls": {
                "C-0007": {
                    "name": "Test control",
                    "scoreFactor": 5,
                    "failedResources": ["unknown-resource"]
                }
            }
        },
        "resources": []  # Resource not in map
    }
    f = tmp_path / "kubescape.json"
    write(f, data)
    adapter = KubescapeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].context["resource_kind"] == "Unknown"
    assert items[0].context["resource_name"] == "unknown-resource"


def test_kubescape_adapter_empty_controls(tmp_path: Path):
    """Test Kubescape adapter with empty controls."""
    data = {
        "summaryDetails": {
            "controls": {}
        },
        "resources": []
    }
    f = tmp_path / "kubescape.json"
    write(f, data)
    adapter = KubescapeAdapter()
    items = adapter.parse(f)

    assert items == []


def test_kubescape_adapter_empty_file(tmp_path: Path):
    """Test Kubescape adapter handles empty JSON file."""
    f = tmp_path / "kubescape.json"
    f.write_text("", encoding="utf-8")
    adapter = KubescapeAdapter()
    items = adapter.parse(f)

    assert items == []


def test_kubescape_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Kubescape findings are enriched with compliance mappings."""
    data = {
        "summaryDetails": {
            "frameworkName": "CIS-Kubernetes",
            "controls": {
                "C-0008": {
                    "name": "RBAC enabled",
                    "description": "Ensure RBAC is enabled",
                    "scoreFactor": 9,
                    "failedResources": ["cluster-1"]
                }
            }
        },
        "resources": [
            {
                "resourceID": "cluster-1",
                "kind": "Cluster",
                "name": "test-cluster"
            }
        ]
    }
    f = tmp_path / "kubescape.json"
    write(f, data)
    adapter = KubescapeAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
