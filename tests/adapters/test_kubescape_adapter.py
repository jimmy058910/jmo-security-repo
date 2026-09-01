"""Tests for the Kubescape adapter.

These fixtures build the shape kubescape ACTUALLY emits, via `kubescape_output()`.
They previously hand-wrote a different one -- a top-level `failedResources` LIST
on each summary control -- which no released kubescape has ever produced.
Measured against the same insecure Pod manifest, v3.0.47 and v4.0.12 both emit
`resourceIDs` plus a nested integer `ResourceCounters.failedResources`, and put
the per-resource verdicts in a top-level `results[]`.

The consequence was total: the adapter skipped every control and returned `[]`
for every real scan, in the three profiles that ship kubescape, while the tool
exited 0 and wrote a populated file. The tests stayed green throughout, because
fixture and adapter were written from the same wrong belief -- the
mirror-of-a-mirror shape in `.claude/rules/testing.rules.md`.

So: build fixtures HERE with `kubescape_output()`, and keep the real captured
output in `tests/fixtures/golden/kubescape/`. A hand-written dict cannot catch
this class of drift; only real output can. See #1094.
"""

import json
from pathlib import Path

from scripts.core.adapters.kubescape_adapter import KubescapeAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def kubescape_output(controls, resources, failures, framework=""):
    """Build kubescape JSON in the shape the real tool emits.

    Args:
        controls: {control_id: {"name", "description", "scoreFactor", "remediation"}}
        resources: [{"id", "kind", "name", "namespace"}]
        failures: [(resource_id, control_id), ...] -- the failed pairs
        framework: optional frameworkName

    The summary block carries only counters; `results[]` carries the verdicts.
    """
    failed_by_resource: dict[str, list[str]] = {}
    for res_id, ctrl_id in failures:
        failed_by_resource.setdefault(res_id, []).append(ctrl_id)

    summary_controls = {}
    for ctrl_id, meta in controls.items():
        failed_count = sum(1 for _, c in failures if c == ctrl_id)
        summary_controls[ctrl_id] = {
            "controlID": ctrl_id,
            "name": meta.get("name", ctrl_id),
            "description": meta.get("description", ""),
            "scoreFactor": meta.get("scoreFactor", 0),
            "remediation": meta.get("remediation", ""),
            "status": "failed" if failed_count else "passed",
            "statusInfo": {"status": "failed" if failed_count else "passed"},
            # The real signal: an integer count, not a list of IDs.
            "ResourceCounters": {
                "passedResources": 0 if failed_count else 1,
                "failedResources": failed_count,
                "skippedResources": 0,
                "excludedResources": 0,
            },
            "resourceIDs": {},
        }

    out_resources = []
    for res in resources:
        metadata = {"name": res.get("name", res["id"])}
        if res.get("namespace"):
            metadata["namespace"] = res["namespace"]
        out_resources.append(
            {
                "resourceID": res["id"],
                # kind/name/namespace live under `object`, not at the top level.
                "object": {
                    "apiVersion": "v1",
                    "kind": res.get("kind", "Unknown"),
                    "metadata": metadata,
                },
                "source": {"path": "manifest.yaml"},
            }
        )

    results = []
    for res_id, ctrl_ids in failed_by_resource.items():
        results.append(
            {
                "resourceID": res_id,
                "controls": [
                    {
                        "controlID": c,
                        "name": controls.get(c, {}).get("name", c),
                        "status": {"status": "failed"},
                        "severity": "High",
                        "rules": [{"name": f"rule-{c}", "status": "failed"}],
                    }
                    for c in ctrl_ids
                ],
            }
        )

    summary = {"controls": summary_controls}
    if framework:
        summary["frameworkName"] = framework
    return {
        "summaryDetails": summary,
        "resources": out_resources,
        "results": results,
    }


def test_kubescape_adapter_basic_finding(tmp_path: Path):
    """Test Kubescape adapter with basic control failure."""
    data = kubescape_output(
        controls={
            "C-0001": {
                "name": "Privileged container",
                "description": "Containers running in privileged mode",
                "scoreFactor": 9,
                "remediation": "Remove privileged: true from container spec",
            }
        },
        resources=[
            {
                "id": "pod-123",
                "kind": "Pod",
                "name": "nginx-pod",
                "namespace": "default",
            }
        ],
        failures=[("pod-123", "C-0001")],
        framework="NSA-CISA",
    )
    f = tmp_path / "kubescape.json"
    write(f, data)
    items = KubescapeAdapter().parse(f)

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
    """scoreFactor 10 maps to CRITICAL."""
    data = kubescape_output(
        controls={
            "C-0002": {
                "name": "Cluster-admin binding",
                "description": "Cluster-admin role bound to a subject",
                "scoreFactor": 10,
            }
        },
        resources=[{"id": "cluster-1", "kind": "ClusterRoleBinding", "name": "admin"}],
        failures=[("cluster-1", "C-0002")],
    )
    f = tmp_path / "kubescape.json"
    write(f, data)
    items = KubescapeAdapter().parse(f)

    assert len(items) == 1
    assert items[0].severity == "CRITICAL"


def test_kubescape_adapter_multiple_failed_resources(tmp_path: Path):
    """One finding per failed (resource, control) pair."""
    data = kubescape_output(
        controls={
            "C-0003": {"name": "Host PID", "scoreFactor": 7},
        },
        resources=[
            {"id": "pod-1", "kind": "Pod", "name": "a", "namespace": "ns1"},
            {"id": "pod-2", "kind": "Pod", "name": "b", "namespace": "ns1"},
            {"id": "pod-3", "kind": "Pod", "name": "c", "namespace": "ns2"},
        ],
        failures=[("pod-1", "C-0003"), ("pod-2", "C-0003"), ("pod-3", "C-0003")],
    )
    f = tmp_path / "kubescape.json"
    write(f, data)
    items = KubescapeAdapter().parse(f)

    assert len(items) == 3
    assert {i.context["resource_name"] for i in items} == {"a", "b", "c"}
    assert all(i.severity == "HIGH" for i in items)


def test_kubescape_adapter_no_namespace(tmp_path: Path):
    """Cluster-scoped resources carry no namespace."""
    data = kubescape_output(
        controls={"C-0005": {"name": "Cluster control", "scoreFactor": 6}},
        resources=[{"id": "role-123", "kind": "ClusterRole", "name": "view"}],
        failures=[("role-123", "C-0005")],
    )
    f = tmp_path / "kubescape.json"
    write(f, data)
    items = KubescapeAdapter().parse(f)

    assert len(items) == 1
    assert items[0].context["resource_namespace"] is None
    assert items[0].location["path"] == "ClusterRole/view"


def test_kubescape_adapter_low_severity(tmp_path: Path):
    """A low scoreFactor maps to LOW."""
    data = kubescape_output(
        controls={"C-0009": {"name": "Minor control", "scoreFactor": 2}},
        resources=[{"id": "pod-456", "kind": "Pod", "name": "minor"}],
        failures=[("pod-456", "C-0009")],
    )
    f = tmp_path / "kubescape.json"
    write(f, data)
    items = KubescapeAdapter().parse(f)

    assert len(items) == 1
    assert items[0].severity == "LOW"


def test_kubescape_adapter_no_failed_resources(tmp_path: Path):
    """A control nothing failed produces no finding.

    With no entry in `failures`, the control is `passed` in the summary and
    absent from `results[]` -- which is how kubescape reports a clean control.
    """
    data = kubescape_output(
        controls={
            "C-0006": {
                "name": "Passing control",
                "description": "This control passed",
                "scoreFactor": 8,
            }
        },
        resources=[{"id": "pod-ok", "kind": "Pod", "name": "fine"}],
        failures=[],
    )
    f = tmp_path / "kubescape.json"
    write(f, data)
    items = KubescapeAdapter().parse(f)

    assert items == []


def test_kubescape_adapter_missing_resource_details(tmp_path: Path):
    """A results[] entry whose resource is absent from resources[] degrades."""
    data = kubescape_output(
        controls={"C-0007": {"name": "Test control", "scoreFactor": 5}},
        resources=[],  # deliberately not describing the resource
        failures=[("unknown-resource", "C-0007")],
    )
    f = tmp_path / "kubescape.json"
    write(f, data)
    items = KubescapeAdapter().parse(f)

    assert len(items) == 1
    assert items[0].context["resource_kind"] == "Unknown"
    assert items[0].context["resource_name"] == "unknown-resource"


def test_kubescape_adapter_empty_controls(tmp_path: Path):
    """No controls and no results yields nothing."""
    data = kubescape_output(controls={}, resources=[], failures=[])
    f = tmp_path / "kubescape.json"
    write(f, data)
    items = KubescapeAdapter().parse(f)

    assert items == []


def test_kubescape_adapter_empty_file(tmp_path: Path):
    """Test Kubescape adapter handles empty JSON file."""
    f = tmp_path / "kubescape.json"
    f.write_text("", encoding="utf-8")
    items = KubescapeAdapter().parse(f)

    assert items == []


def test_kubescape_adapter_results_without_summary(tmp_path: Path):
    """Verdicts in results[] are honoured even with an empty summary block.

    The summary is used only to enrich (scoreFactor, description). A finding
    must not depend on it, or a shape change there silently empties the report
    again -- which is exactly how #1094 behaved.
    """
    data = {
        "summaryDetails": {"controls": {}},
        "resources": [
            {
                "resourceID": "pod-x",
                "object": {"kind": "Pod", "metadata": {"name": "orphan"}},
            }
        ],
        "results": [
            {
                "resourceID": "pod-x",
                "controls": [
                    {
                        "controlID": "C-0100",
                        "name": "Some control",
                        "status": {"status": "failed"},
                    }
                ],
            }
        ],
    }
    f = tmp_path / "kubescape.json"
    write(f, data)
    items = KubescapeAdapter().parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "C-0100"
    assert items[0].context["resource_name"] == "orphan"
    # scoreFactor is absent, so severity falls back to the lowest bucket.
    assert items[0].severity == "LOW"


def test_kubescape_adapter_skips_passed_and_skipped_controls(tmp_path: Path):
    """Only `status.status == "failed"` becomes a finding.

    kubescape emits `passed` and `skipped` entries in the same controls[] array;
    treating any non-empty entry as a failure would report the whole framework.
    """
    data = {
        "summaryDetails": {"controls": {}},
        "resources": [
            {
                "resourceID": "pod-y",
                "object": {"kind": "Pod", "metadata": {"name": "p"}},
            }
        ],
        "results": [
            {
                "resourceID": "pod-y",
                "controls": [
                    {"controlID": "C-1", "status": {"status": "passed"}},
                    {
                        "controlID": "C-2",
                        "status": {"status": "skipped", "subStatus": "configuration"},
                    },
                    {"controlID": "C-3", "status": {"status": "failed"}},
                ],
            }
        ],
    }
    f = tmp_path / "kubescape.json"
    write(f, data)
    items = KubescapeAdapter().parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "C-3"


def test_kubescape_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Kubescape findings are enriched with compliance mappings."""
    data = kubescape_output(
        controls={
            "C-0008": {
                "name": "RBAC enabled",
                "description": "Ensure RBAC is enabled",
                "scoreFactor": 9,
            }
        },
        resources=[{"id": "cluster-1", "kind": "Cluster", "name": "test-cluster"}],
        failures=[("cluster-1", "C-0008")],
        framework="CIS-Kubernetes",
    )
    f = tmp_path / "kubescape.json"
    write(f, data)
    items = KubescapeAdapter().parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
