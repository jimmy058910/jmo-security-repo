import json
from pathlib import Path

from scripts.core.adapters.trivy_rbac_adapter import TrivyRbacAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_trivy_rbac_adapter_cluster_admin(tmp_path: Path):
    """Test Trivy RBAC adapter with cluster-admin role finding."""
    data = {
        "version": "0.50.1",
        "checks": [
            {
                "checkID": "KSV047",
                "success": False,
                "severity": "CRITICAL",
                "title": "Managing cluster-admin role",
                "description": "ServiceAccount has cluster-admin role binding which grants excessive privileges",
                "category": "Kubernetes Security Check",
                "namespace": "kube-system",
                "kind": "ServiceAccount",
                "name": "admin-sa"
            }
        ]
    }
    f = tmp_path / "trivy-rbac.json"
    write(f, data)
    adapter = TrivyRbacAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "KSV047"
    assert items[0].severity == "CRITICAL"
    assert "rbac" in items[0].tags
    assert "kubernetes" in items[0].tags
    assert "cluster-admin" in items[0].tags
    assert items[0].context["check_id"] == "KSV047"
    assert items[0].context["resource_namespace"] == "kube-system"
    assert items[0].context["resource_kind"] == "ServiceAccount"
    assert items[0].context["resource_name"] == "admin-sa"
    assert items[0].location["path"] == "kube-system/ServiceAccount/admin-sa"
    assert "https://avd.aquasec.com/misconfig/kubernetes/ksv047/" in items[0].references


def test_trivy_rbac_adapter_wildcard_permissions(tmp_path: Path):
    """Test Trivy RBAC adapter with wildcard permissions finding."""
    data = {
        "version": "0.50.0",
        "checks": [
            {
                "checkID": "KSV046",
                "success": False,
                "severity": "HIGH",
                "title": "Managing wildcard verbs",
                "description": "Role grants wildcard (*) verbs which is overly permissive",
                "category": "Kubernetes Security Check",
                "namespace": "default",
                "kind": "Role",
                "name": "wildcard-role"
            }
        ]
    }
    f = tmp_path / "trivy-rbac.json"
    write(f, data)
    adapter = TrivyRbacAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "HIGH"
    assert "wildcard-permissions" in items[0].tags


def test_trivy_rbac_adapter_secret_access(tmp_path: Path):
    """Test Trivy RBAC adapter with secrets access finding."""
    data = {
        "version": "0.50.0",
        "checks": [
            {
                "checkID": "KSV041",
                "success": False,
                "severity": "MEDIUM",
                "title": "Managing secrets access",
                "description": "Role has access to list/get/watch secrets",
                "category": "Kubernetes Security Check",
                "namespace": "app-namespace",
                "kind": "Role",
                "name": "app-role"
            }
        ]
    }
    f = tmp_path / "trivy-rbac.json"
    write(f, data)
    adapter = TrivyRbacAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "MEDIUM"
    assert "secret-access" in items[0].tags
    assert items[0].context["check_id"] == "KSV041"


def test_trivy_rbac_adapter_multiple_findings(tmp_path: Path):
    """Test Trivy RBAC adapter with multiple RBAC findings."""
    data = {
        "version": "0.50.1",
        "checks": [
            {
                "checkID": "KSV047",
                "success": False,
                "severity": "CRITICAL",
                "title": "Managing cluster-admin role",
                "description": "Excessive cluster-admin privileges",
                "namespace": "kube-system",
                "kind": "ClusterRoleBinding",
                "name": "admin-binding"
            },
            {
                "checkID": "KSV046",
                "success": False,
                "severity": "HIGH",
                "title": "Managing wildcard verbs",
                "description": "Role grants wildcard verbs",
                "namespace": "default",
                "kind": "Role",
                "name": "wildcard-role"
            },
            {
                "checkID": "KSV041",
                "success": False,
                "severity": "MEDIUM",
                "title": "Managing secrets access",
                "description": "Role can access secrets",
                "namespace": "app",
                "kind": "Role",
                "name": "app-role"
            }
        ]
    }
    f = tmp_path / "trivy-rbac.json"
    write(f, data)
    adapter = TrivyRbacAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].severity == "CRITICAL"
    assert items[1].severity == "HIGH"
    assert items[2].severity == "MEDIUM"
    assert items[0].ruleId == "KSV047"
    assert items[1].ruleId == "KSV046"
    assert items[2].ruleId == "KSV041"


def test_trivy_rbac_adapter_success_checks_skipped(tmp_path: Path):
    """Test Trivy RBAC adapter skips successful checks."""
    data = {
        "version": "0.50.0",
        "checks": [
            {
                "checkID": "KSV050",
                "success": True,
                "severity": "HIGH",
                "title": "Managing privilege escalation",
                "description": "Role does not allow privilege escalation (PASS)",
                "kind": "Role",
                "name": "safe-role"
            },
            {
                "checkID": "KSV047",
                "success": False,
                "severity": "CRITICAL",
                "title": "Managing cluster-admin role",
                "description": "ServiceAccount has cluster-admin privileges",
                "kind": "ServiceAccount",
                "name": "admin-sa"
            }
        ]
    }
    f = tmp_path / "trivy-rbac.json"
    write(f, data)
    adapter = TrivyRbacAdapter()
    items = adapter.parse(f)

    # Only failed check should be processed
    assert len(items) == 1
    assert items[0].ruleId == "KSV047"


def test_trivy_rbac_adapter_no_namespace(tmp_path: Path):
    """Test Trivy RBAC adapter handles cluster-scoped resources without namespace."""
    data = {
        "version": "0.50.0",
        "checks": [
            {
                "checkID": "KSV048",
                "success": False,
                "severity": "HIGH",
                "title": "Managing exec/attach privileges",
                "description": "ClusterRole grants exec/attach to pods",
                "kind": "ClusterRole",
                "name": "pod-exec-role"
            }
        ]
    }
    f = tmp_path / "trivy-rbac.json"
    write(f, data)
    adapter = TrivyRbacAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Location should be kind/name without namespace
    assert items[0].location["path"] == "ClusterRole/pod-exec-role"
    assert items[0].context["resource_namespace"] is None


def test_trivy_rbac_adapter_minimal_check_info(tmp_path: Path):
    """Test Trivy RBAC adapter handles minimal check information gracefully."""
    data = {
        "version": "0.50.0",
        "checks": [
            {
                "checkID": "KSV999",
                "success": False,
                "severity": "MEDIUM"
            }
        ]
    }
    f = tmp_path / "trivy-rbac.json"
    write(f, data)
    adapter = TrivyRbacAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should use fallback values
    assert items[0].ruleId == "KSV999"
    assert items[0].title == "KSV999"  # Fallback to check_id
    assert items[0].location["path"] == "rbac-check:KSV999"
    assert items[0].context["resource_namespace"] is None
    assert items[0].context["resource_kind"] is None


def test_trivy_rbac_adapter_kind_tagging(tmp_path: Path):
    """Test Trivy RBAC adapter includes resource kind in tags."""
    data = {
        "version": "0.50.0",
        "checks": [
            {
                "checkID": "KSV041",
                "success": False,
                "severity": "MEDIUM",
                "title": "Secret access",
                "kind": "ClusterRoleBinding",
                "name": "test-binding"
            }
        ]
    }
    f = tmp_path / "trivy-rbac.json"
    write(f, data)
    adapter = TrivyRbacAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert "clusterrolebinding" in items[0].tags


def test_trivy_rbac_adapter_empty_checks(tmp_path: Path):
    """Test Trivy RBAC adapter with empty checks array."""
    data = {
        "version": "0.50.0",
        "checks": []
    }
    f = tmp_path / "trivy-rbac.json"
    write(f, data)
    adapter = TrivyRbacAdapter()
    items = adapter.parse(f)

    assert items == []


def test_trivy_rbac_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Trivy RBAC findings are enriched with compliance mappings."""
    data = {
        "version": "0.50.0",
        "checks": [
            {
                "checkID": "KSV047",
                "success": False,
                "severity": "CRITICAL",
                "title": "Test RBAC check",
                "kind": "Role",
                "name": "test-role"
            }
        ]
    }
    f = tmp_path / "trivy-rbac.json"
    write(f, data)
    adapter = TrivyRbacAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
