"""Unit tests for the trivy-rbac adapter.

EVERY FIXTURE HERE IS THE SHAPE `trivy config` ACTUALLY WRITES.

The previous version of this file built ten fixtures of the form
``{"version": "0.50.0", "checks": [{"checkID": ..., "success": False}]}`` and all
ten passed against an adapter that scored **zero findings on every real scan**
(#1215). No version of trivy has emitted that document. The tests were not weak
-- they were mutation-sensitive and precise -- they simply asserted the parse of
a file that does not exist.

So the shape below is not invented. It is taken from
``tests/fixtures/golden/trivy_rbac/v0.74.0/trivy-rbac.json``, real captured
output from the pinned 0.74.0, and ``test_the_fixture_shape_matches_real_output``
fails if these fixtures and that capture ever drift apart. A unit fixture cannot
police itself; only a real one can.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scripts.core.adapters.trivy_rbac_adapter import TrivyRbacAdapter

GOLDEN_RAW = (
    Path(__file__).parent.parent
    / "fixtures"
    / "golden"
    / "trivy_rbac"
    / "v0.74.0"
    / "trivy-rbac.json"
)


def write(p: Path, obj: Any) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def misconf(**overrides: Any) -> dict[str, Any]:
    """One `Misconfigurations[]` entry, with real defaults."""
    base: dict[str, Any] = {
        "Type": "Kubernetes Security Check",
        "ID": "KSV-0001",
        "Title": "Can elevate its own privileges",
        "Description": "A program inside the container can elevate its own privileges.",
        "Message": "Container 'app' of Pod 'x' should set 'allowPrivilegeEscalation' to false",
        "Namespace": "builtin.kubernetes.KSV0001",
        "Query": "data.builtin.kubernetes.KSV0001.deny",
        "Resolution": "Set 'allowPrivilegeEscalation' to 'false'.",
        "Severity": "MEDIUM",
        "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv-0001",
        "References": ["https://avd.aquasec.com/misconfig/ksv-0001"],
        "Status": "FAIL",
        "CauseMetadata": {
            "Provider": "Kubernetes",
            "Service": "general",
            "StartLine": 14,
            "EndLine": 18,
        },
    }
    base.update(overrides)
    return base


def report(*results: dict[str, Any], version: str = "0.74.0") -> dict[str, Any]:
    """A whole `trivy config` report."""
    return {
        "SchemaVersion": 2,
        "Trivy": {"Version": version},
        "ArtifactName": "manifests",
        "ArtifactType": "filesystem",
        "Results": list(results),
    }


def result(target: str, *misconfs: dict[str, Any]) -> dict[str, Any]:
    return {
        "Target": target,
        "Class": "config",
        "Type": "kubernetes",
        "Misconfigurations": list(misconfs),
    }


def parse(tmp_path: Path, doc: Any) -> list[Any]:
    f = tmp_path / "trivy-rbac.json"
    write(f, doc)
    return TrivyRbacAdapter().parse(f)


# --------------------------------------------------------------------------
# the shape itself -- the guard the old file did not have
# --------------------------------------------------------------------------


def test_the_fixture_shape_matches_real_output():
    """The keys these tests build must be the keys trivy really writes.

    This is the assertion whose absence let #1215 live: ten precise tests of a
    document trivy has never produced. It reads the golden capture rather than
    anything written by hand, so it fails if the fixtures above drift into
    fiction again.
    """
    raw = json.loads(GOLDEN_RAW.read_text(encoding="utf-8"))

    assert "checks" not in raw, (
        "the pre-#1215 adapter read a top-level `checks` array; real output has none"
    )
    assert raw["SchemaVersion"] == 2
    assert set(raw) >= {"SchemaVersion", "Trivy", "Results"}

    real_result = raw["Results"][0]
    assert set(real_result) >= set(result("t", misconf()))

    real_misconf = next(
        m for r in raw["Results"] for m in r.get("Misconfigurations", [])
    )
    assert set(real_misconf) >= set(misconf()), (
        f"fixture keys not in real output: {set(misconf()) - set(real_misconf)}"
    )


def test_the_pre_fix_schema_yields_nothing():
    """A document in the old imagined shape must produce no findings.

    Pins the regression directly: if someone restores the `checks` lookup, the
    golden test goes red and so does this.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        items = parse(
            Path(td),
            {
                "version": "0.50.0",
                "checks": [{"checkID": "KSV041", "success": False, "severity": "HIGH"}],
            },
        )
    assert items == []


# --------------------------------------------------------------------------
# core parse
# --------------------------------------------------------------------------


def test_a_failing_misconfiguration_becomes_a_finding(tmp_path: Path):
    items = parse(tmp_path, report(result("manifests/pod.yaml", misconf())))

    assert len(items) == 1
    f = items[0]
    assert f.ruleId == "KSV-0001"
    assert f.severity == "MEDIUM"
    assert f.title == "Can elevate its own privileges"
    assert f.tool["name"] == "trivy-rbac"
    assert f.tool["version"] == "0.74.0"


def test_the_location_is_the_file_trivy_scanned(tmp_path: Path):
    """`Target` is a path on disk.

    The pre-#1215 adapter synthesised `"<Kind>/<name>"` and line 0, a string
    matching no file -- so findings could not group by file and dedup had no
    real key to cluster on.
    """
    items = parse(tmp_path, report(result("manifests/pod.yaml", misconf())))

    assert items[0].location["path"] == "manifests/pod.yaml"
    assert items[0].location["startLine"] == 14


def test_a_check_without_a_start_line_falls_back_to_zero(tmp_path: Path):
    """Measured: 1 of 56 real misconfigurations carries no StartLine.

    KSV-0109 ("ConfigMap with secrets") is a file-level check, so its
    CauseMetadata has only Provider and Service.
    """
    items = parse(
        tmp_path,
        report(
            result(
                "manifests/configmap.yaml",
                misconf(
                    ID="KSV-0109",
                    Title="ConfigMap with secrets",
                    CauseMetadata={"Provider": "Kubernetes", "Service": "general"},
                ),
            )
        ),
    )

    assert items[0].location["startLine"] == 0
    assert items[0].location["path"] == "manifests/configmap.yaml"


def test_passing_checks_are_not_findings(tmp_path: Path):
    """`--include-non-failures` adds PASS entries, and `per_tool` flags reach it."""
    items = parse(
        tmp_path,
        report(
            result(
                "manifests/pod.yaml",
                misconf(ID="KSV-0001", Status="PASS"),
                misconf(ID="KSV-0003", Status="FAIL"),
            )
        ),
    )

    assert [f.ruleId for f in items] == ["KSV-0003"]


def test_findings_are_collected_across_every_target(tmp_path: Path):
    items = parse(
        tmp_path,
        report(
            result(
                "manifests/pod.yaml", misconf(ID="KSV-0001"), misconf(ID="KSV-0003")
            ),
            result("manifests/deployment.yml", misconf(ID="KSV-0011")),
            result("manifests/ingress.yaml"),
        ),
    )

    assert len(items) == 3
    assert {f.location["path"] for f in items} == {
        "manifests/pod.yaml",
        "manifests/deployment.yml",
    }
    assert len({f.id for f in items}) == 3, "fingerprints must not collide"


# --------------------------------------------------------------------------
# field mapping
# --------------------------------------------------------------------------


def test_the_instance_message_is_preferred_over_the_generic_description(
    tmp_path: Path,
):
    """`Message` names the offending object; `Description` is the rule text."""
    items = parse(
        tmp_path,
        report(
            result(
                "manifests/configmap.yaml",
                misconf(
                    Message="ConfigMap 'app-config' stores secrets in key(s) '{\"PASSWORD\"}'",
                    Description="Generic rule text.",
                ),
            )
        ),
    )

    assert "app-config" in items[0].message
    assert items[0].description == "Generic rule text."


def test_an_absent_message_falls_back_to_the_description(tmp_path: Path):
    items = parse(
        tmp_path,
        report(
            result(
                "manifests/pod.yaml",
                misconf(Message="", Description="Generic rule text."),
            )
        ),
    )

    assert items[0].message == "Generic rule text."


def test_remediation_uses_the_tool_resolution(tmp_path: Path):
    items = parse(
        tmp_path,
        report(
            result(
                "manifests/pod.yaml",
                misconf(Resolution="Set 'privileged' to 'false'."),
            )
        ),
    )

    assert items[0].remediation == "Set 'privileged' to 'false'."


def test_a_missing_resolution_gets_a_generic_remediation(tmp_path: Path):
    items = parse(
        tmp_path, report(result("manifests/pod.yaml", misconf(Resolution="")))
    )

    assert "least privilege" in items[0].remediation
    assert "manifests/pod.yaml" in items[0].remediation


def test_references_merge_the_primary_url_without_duplicating_it(tmp_path: Path):
    """Real output repeats PrimaryURL inside References -- measured on all 56."""
    items = parse(
        tmp_path,
        report(
            result(
                "manifests/pod.yaml",
                misconf(
                    PrimaryURL="https://avd.aquasec.com/misconfig/ksv-0001",
                    References=[
                        "https://avd.aquasec.com/misconfig/ksv-0001",
                        "https://kubernetes.io/docs/concepts/policy/",
                    ],
                ),
            )
        ),
    )

    assert items[0].references == [
        "https://avd.aquasec.com/misconfig/ksv-0001",
        "https://kubernetes.io/docs/concepts/policy/",
    ]


def test_cause_metadata_reaches_context(tmp_path: Path):
    items = parse(tmp_path, report(result("manifests/pod.yaml", misconf())))

    ctx = items[0].context
    assert ctx["check_id"] == "KSV-0001"
    assert ctx["target"] == "manifests/pod.yaml"
    assert ctx["provider"] == "Kubernetes"
    assert ctx["service"] == "general"


# --------------------------------------------------------------------------
# tags
# --------------------------------------------------------------------------


def test_every_finding_carries_the_base_tags(tmp_path: Path):
    items = parse(tmp_path, report(result("manifests/pod.yaml", misconf())))

    assert {"rbac", "kubernetes", "k8s-security", "access-control"} <= set(
        items[0].tags
    )


def test_cluster_admin_wildcard_and_secret_tags_come_from_the_rule_text(
    tmp_path: Path,
):
    admin = parse(
        tmp_path,
        report(result("r.yaml", misconf(Title="Do not bind to cluster-admin role"))),
    )
    wildcard = parse(
        tmp_path,
        report(result("r.yaml", misconf(Title="No wildcard verb roles"))),
    )
    secret = parse(
        tmp_path,
        report(result("r.yaml", misconf(Title="ConfigMap with secrets"))),
    )

    assert "cluster-admin" in admin[0].tags
    assert "wildcard-permissions" in wildcard[0].tags
    assert "secret-access" in secret[0].tags
    assert "wildcard-permissions" not in admin[0].tags


# --------------------------------------------------------------------------
# degenerate input
# --------------------------------------------------------------------------


def test_a_report_with_no_results_yields_nothing(tmp_path: Path):
    assert parse(tmp_path, report()) == []


def test_a_target_with_no_misconfigurations_yields_nothing(tmp_path: Path):
    assert parse(tmp_path, report(result("manifests/ingress.yaml"))) == []


def test_a_json_list_at_the_top_level_yields_nothing(tmp_path: Path):
    assert parse(tmp_path, [{"ID": "KSV-0001"}]) == []


def test_malformed_entries_are_skipped_without_losing_the_good_ones(
    tmp_path: Path,
):
    doc = report()
    doc["Results"] = [
        "not-a-dict",
        {"Target": "a.yaml", "Misconfigurations": "not-a-list"},
        result("manifests/pod.yaml", misconf(ID="KSV-0003")),
    ]
    doc["Results"][2]["Misconfigurations"].insert(0, "not-a-dict")

    items = parse(tmp_path, doc)

    assert [f.ruleId for f in items] == ["KSV-0003"]


def test_a_missing_trivy_block_does_not_crash_the_version(tmp_path: Path):
    doc = report(result("manifests/pod.yaml", misconf()))
    del doc["Trivy"]

    items = parse(tmp_path, doc)

    assert items[0].tool["version"] == "unknown"
