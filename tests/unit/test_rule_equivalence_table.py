"""Regression tests for #846 - the equivalence table's *content*.

`RULE_EQUIVALENCE` groups rules that are supposed to be the same issue reported
by different tools. A match returns `1.0` from `metadata_similarity` - the
strongest possible signal - so a wrong entry actively drives clustering, and
the loser of the merge survives only inside `context.duplicates`.

Three groups listed genuinely different controls. Each was verified against the
tool's own `check_name` on a real `deep` scan, not against the inline comment
(which was itself wrong for `CKV_AWS_17`):

===============  =====================================================
`CKV_AWS_23`     "Ensure every security group and rule has a
                 description" - a documentation control, grouped with
                 SSH/RDP open-ingress rules
`CKV_AWS_21`     "Ensure all data stored in the S3 bucket have
                 versioning enabled" - grouped under public-S3
`CKV_AWS_17`     "Ensure all data stored in RDS is not publicly
                 accessible" - grouped under unencrypted-storage, with
                 an inline comment claiming it was RDS *encryption*
===============  =====================================================

Six `gitleaks` tuples were also removed. gitleaks has no adapter, is absent
from `tool_registry.PROFILE_TOOLS` and from `versions.yaml` - it appeared
nowhere in the product except this table.

The guards below are **derived**, not enumerated. A list of "tools that should
appear" would be a mirror of the table and could not notice what the table
gained; `_adapter_names()` reads the authority instead.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from scripts.core.adapters.checkov_adapter import CheckovAdapter
from scripts.core.adapters.hadolint_adapter import HadolintAdapter
from scripts.core.adapters.trivy_adapter import TrivyAdapter
from scripts.core.normalize_and_report import _cluster_cross_tool_duplicates
from scripts.core.rule_equivalence import (
    RULE_EQUIVALENCE,
    are_rules_equivalent,
    get_canonical_rule_id,
)

ADAPTER_DIR = Path("scripts/core/adapters")


def _adapter_names() -> set[str]:
    """Tools that actually have an adapter, read from the filesystem.

    The authority for "does this tool exist" is whether something can parse its
    output. Derived rather than listed so it cannot drift.
    """
    from scripts.core.validators.scan_validator import EXPECTED_ADAPTERS

    names = {
        p.name[: -len("_adapter.py")].replace("_", "-")
        for p in ADAPTER_DIR.glob("*_adapter.py")
    }
    # Meta-guard: an extractor that silently finds nothing satisfies every
    # assertion built on it (testing.rules.md). Checked against the validator's
    # list, which tests/core/test_scan_validator.py pins to the same directory,
    # rather than a floor that a cut to the matrix drops below.
    assert names == {a.replace("_", "-") for a in EXPECTED_ADAPTERS}, sorted(names)
    assert {"trivy", "checkov", "opengrep"} <= names, sorted(names)
    return names


def test_every_tool_in_the_table_has_an_adapter():
    """The property that makes the gitleaks class impossible to reintroduce.

    Six `("gitleaks", ...)` tuples sat in this table with no adapter, no
    registry entry and no `versions.yaml` pin. They could never match anything,
    because no finding can carry a tool name that nothing produces.
    """
    adapters = _adapter_names()
    named = {tool for members in RULE_EQUIVALENCE.values() for tool, _ in members}
    orphans = sorted(named - adapters)
    assert not orphans, (
        f"these tools appear in RULE_EQUIVALENCE but have no adapter, so their "
        f"entries can never match: {orphans}"
    )


@pytest.mark.parametrize(
    ("tool", "rule_id", "reason"),
    [
        (
            "checkov",
            "CKV_AWS_23",
            'is "Ensure every security group and rule has a description" - a '
            "documentation control, not an open-ingress finding",
        ),
        (
            "checkov",
            "CKV_AWS_21",
            'is "Ensure all data stored in the S3 bucket have versioning '
            'enabled" - not a public-bucket finding',
        ),
        (
            "checkov",
            "CKV_AWS_19",
            "is S3 encryption at rest - not a public-bucket finding",
        ),
        (
            "checkov",
            "CKV_AWS_17",
            'is "Ensure all data stored in RDS is not publicly accessible" - '
            "not an encryption finding, despite the comment that said so",
        ),
    ],
)
def test_rules_that_are_a_different_control_are_not_grouped(tool, rule_id, reason):
    assert get_canonical_rule_id(tool, rule_id) is None, f"{tool} {rule_id} {reason}"


@pytest.mark.parametrize(
    ("tool", "rule_id", "canonical"),
    [
        ("checkov", "CKV_AWS_24", "iac-security-group-open-ingress"),
        ("checkov", "CKV_AWS_25", "iac-security-group-open-ingress"),
        ("checkov", "CKV_AWS_20", "iac-public-s3-bucket"),
        ("checkov", "CKV_AWS_3", "iac-unencrypted-storage"),
        # trivy 0.74.0's ids (#1221). `DS031` stood here until then: it is the
        # Dockerfile secrets check, not open ingress.
        ("trivy", "AWS-0107", "iac-security-group-open-ingress"),
        ("trivy", "AWS-0092", "iac-public-s3-bucket"),
        ("trivy", "AWS-0026", "iac-unencrypted-storage"),
    ],
)
def test_the_genuinely_equivalent_rules_are_still_grouped(tool, rule_id, canonical):
    """The negative control.

    Deleting entries until the wrong ones are gone is easy; the table has to
    still do its job. These are the members of the same three groups that ARE
    the control the group names.
    """
    assert get_canonical_rule_id(tool, rule_id) == canonical


def test_the_repaired_groups_no_longer_merge_different_controls():
    """Asserted through the public predicate, not by reading the table.

    This is what the defect actually caused: checkov's versioning check scoring
    a perfect metadata match against trivy's public-bucket finding.
    """
    # `are_rules_equivalent` returns a TUPLE `(bool, canonical | None)`. A bare
    # `assert are_rules_equivalent(...)` passes on every non-empty tuple, so it
    # would hold with the table emptied - the positive half of this test would
    # have been vacuous. Unpack, and assert the canonical id too.
    # The trivy side is the id trivy 0.74.0 prints (#1221): AWS-0092 "S3
    # Buckets not publicly accessible through ACL.", AWS-0107 "Security groups
    # should not allow unrestricted ingress to SSH or RDP from any IP
    # address.", AWS-0026 "EBS volumes must be encrypted".
    merged, canonical = are_rules_equivalent(
        "checkov", "CKV_AWS_21", "trivy", "AWS-0092"
    )
    assert (merged, canonical) == (False, None), "versioning is not public access"

    assert are_rules_equivalent("checkov", "CKV_AWS_23", "trivy", "AWS-0107") == (
        False,
        None,
    ), "a description check is not an open-ingress finding"

    assert are_rules_equivalent("checkov", "CKV_AWS_17", "trivy", "AWS-0026") == (
        False,
        None,
    ), "RDS public access is not an encryption finding"

    # ...while the real cross-tool pairs still are.
    assert are_rules_equivalent("checkov", "CKV_AWS_20", "trivy", "AWS-0092") == (
        True,
        "iac-public-s3-bucket",
    )
    assert are_rules_equivalent("checkov", "CKV_AWS_24", "trivy", "AWS-0107") == (
        True,
        "iac-security-group-open-ingress",
    )


# Each trivy key's partners, measured 2026-09-28 on the three files behind
# tests/fixtures/samples/trivy/misconfig-0.74.json (their text is in
# tests/adapters/test_trivy_adapter.py): trivy 0.74.0, hadolint 2.14.0 and
# checkov 3.3.16 were each run on them, and `checkov --list` gave the rest.
# Every pair is one check in both tools' own words. Making trivy's ids live
# (#1221) made these groups live, and the partners they held before were
# measured against the same output: eleven named another check. Re-run with
# hadolint 2.15.1, the version versions.yaml pins: every hadolint id above
# fires on the same lines with the same words, and 2.15.1 adds DL3064, the
# partner DS-0031 lacked under 2.14.0 (and DL3066, which pairs with nothing).
TRIVY_PARTNERS = [
    # "Secrets passed via `build-args` or envs or copied secret files" /
    # "Potentially sensitive data should not be used in the `ARG` or `ENV`
    # commands" (hadolint 2.15.1; 2.14.0 has no such check)
    ("DS-0031", "hadolint", "DL3064", "dockerfile-secret-in-arg-or-env"),
    # "Can elevate its own privileges" / "Containers should not run with
    # allowPrivilegeEscalation"
    ("KSV-0001", "checkov", "CKV_K8S_20", "k8s-privilege-escalation"),
    # "Memory requests not specified" / "Memory requests should be set"
    ("KSV-0016", "checkov", "CKV_K8S_12", "k8s-no-memory-requests"),
    # "Memory not limited" / "Memory limits should be set"
    ("KSV-0018", "checkov", "CKV_K8S_13", "k8s-no-memory-limits"),
    # "CPU not limited" / "CPU limits should be set"
    ("KSV-0011", "checkov", "CKV_K8S_11", "k8s-no-cpu-limits"),
    # "Privileged" / "Container should not be privileged"
    ("KSV-0017", "checkov", "CKV_K8S_16", "k8s-privileged-container"),
    # "Access to host PID" / "Containers should not share the host process ID
    # namespace"
    ("KSV-0010", "checkov", "CKV_K8S_17", "k8s-host-pid"),
    # "Runs as root user" / "Minimize the admission of root containers"
    ("KSV-0012", "checkov", "CKV_K8S_23", "k8s-root-container"),
    # "Port 22 exposed" / "Ensure port 22 is not exposed"
    ("DS-0004", "checkov", "CKV_DOCKER_1", "dockerfile-port-22-exposed"),
    # "Deprecated MAINTAINER used" / "Ensure that LABEL maintainer is used
    # instead of MAINTAINER (deprecated)" / "MAINTAINER is deprecated"
    ("DS-0022", "checkov", "CKV_DOCKER_6", "dockerfile-deprecated-maintainer"),
    ("DS-0022", "hadolint", "DL4000", "dockerfile-deprecated-maintainer"),
    # "Duplicate aliases defined in different FROMs" / "Ensure From Alias are
    # unique for multistage builds." / "FROM aliases (stage names) must be
    # unique"
    ("DS-0012", "checkov", "CKV_DOCKER_11", "dockerfile-duplicate-stage-alias"),
    ("DS-0012", "hadolint", "DL3024", "dockerfile-duplicate-stage-alias"),
    # "'RUN <package-manager> update' instruction alone" / "Ensure update
    # instructions are not use alone in the Dockerfile"
    ("DS-0017", "checkov", "CKV_DOCKER_5", "dockerfile-update-alone"),
    # "ADD instead of COPY" / "Use COPY instead of ADD for files and folders"
    ("DS-0005", "hadolint", "DL3020", "dockerfile-add-instead-of-copy"),
    # "No HEALTHCHECK defined" / "`HEALTHCHECK` instruction missing."
    ("DS-0026", "hadolint", "DL3057", "dockerfile-no-healthcheck"),
    # "':latest' tag used" / "Ensure the base image uses a non latest version
    # tag"
    ("DS-0001", "checkov", "CKV_DOCKER_7", "dockerfile-latest-tag"),
]


@pytest.mark.parametrize(("trivy_id", "tool", "rule_id", "canonical"), TRIVY_PARTNERS)
def test_trivys_checks_pair_with_the_same_check_in_other_tools(
    trivy_id, tool, rule_id, canonical
):
    assert are_rules_equivalent("trivy", trivy_id, tool, rule_id) == (
        True,
        canonical,
    )


@pytest.mark.parametrize(
    ("trivy_id", "tool", "rule_id", "theirs"),
    [
        ("KSV-0012", "checkov", "CKV_K8S_20", "allowPrivilegeEscalation, not root"),
        ("KSV-0011", "checkov", "CKV_K8S_12", "memory requests, not CPU limits"),
        ("KSV-0011", "checkov", "CKV_K8S_13", "memory limits, not CPU limits"),
        ("KSV-0017", "checkov", "CKV_K8S_1", "a PodSecurityPolicy's host PID"),
        ("DS-0001", "checkov", "CKV_DOCKER_1", '"Ensure port 22 is not exposed"'),
        ("DS-0026", "hadolint", "DL3055", '"Label `commit` is not a valid git hash."'),
        ("DS-0005", "hadolint", "DL3010", '"Use `ADD` for extracting archives"'),
        ("DS-0025", "hadolint", "DL3018", '"Pin versions in apk add"'),
        ("DS-0031", "hadolint", "DL3059", '"Multiple consecutive `RUN` instructions"'),
        ("DS-0031", "checkov", "CKV_DOCKER_5", "an update instruction left alone"),
        ("DS-0031", "checkov", "CKV_DOCKER_11", "a duplicated stage alias"),
    ],
)
def test_trivys_checks_do_not_pair_with_another_check(trivy_id, tool, rule_id, theirs):
    """The pairings the table held until the trivy keys went live, all wrong."""
    assert are_rules_equivalent("trivy", trivy_id, tool, rule_id) == (
        False,
        None,
    ), f"{tool} {rule_id} is {theirs}"


def test_no_group_is_left_with_a_single_tool():
    """A group spanning one tool cannot do cross-tool deduplication.

    Removing members is how a group becomes pointless without anyone noticing,
    so this fires if a future edit empties one out.
    """
    single = {
        canonical: sorted({tool for tool, _ in members})
        for canonical, members in RULE_EQUIVALENCE.items()
        if len({tool for tool, _ in members}) < 2
    }
    assert not single, f"these groups span only one tool: {single}"


def test_every_group_still_has_members_and_no_duplicate_pairs():
    empty = [c for c, m in RULE_EQUIVALENCE.items() if not m]
    assert not empty, f"empty groups: {empty}"

    seen: dict[tuple[str, str], str] = {}
    clashes = []
    for canonical, members in RULE_EQUIVALENCE.items():
        for pair in members:
            if pair in seen:
                clashes.append((pair, seen[pair], canonical))
            seen[pair] = canonical
    assert not clashes, f"one (tool, rule) mapped to two canonical ids: {clashes}"


# Real output, clustered as a report clusters it (#1354). A pair the table
# lists merges only if the two tools' locations also score: checkov reports a
# Kubernetes resource's whole range, trivy one container's lines inside it.
REAL_OUTPUT = Path(__file__).resolve().parents[1] / "fixtures" / "rule_equivalence"


def _parsed(adapter: type, name: str) -> list[dict]:
    return [finding.to_dict() for finding in adapter().parse(REAL_OUTPUT / name)]


def _merged_pairs(findings: list[dict]) -> set[frozenset[tuple[str, str]]]:
    """Each consensus finding that merged several, as its (tool, rule) members."""
    member = {f["id"]: (f["tool"]["name"], f["ruleId"]) for f in findings}
    merged = set()
    for consensus in _cluster_cross_tool_duplicates(copy.deepcopy(findings)):
        duplicates = (consensus.get("context") or {}).get("duplicates") or []
        if duplicates:
            lead = member[consensus["id"].removeprefix("cluster-")]
            merged.add(frozenset({lead, *(member[d["id"]] for d in duplicates)}))
    return merged


def _pair(trivy_id: str, tool: str, rule_id: str) -> frozenset[tuple[str, str]]:
    return frozenset({("trivy", trivy_id), (tool, rule_id)})


def test_trivy_and_hadolint_merge_the_same_check_on_one_dockerfile():
    """`RUN cd /x && make`: trivy's DS-0013 and hadolint's DL3003 are one
    finding, as `USER root`'s DS-0002 and DL3002 already were."""
    findings = _parsed(TrivyAdapter, "Dockerfile.trivy.json") + _parsed(
        HadolintAdapter, "Dockerfile.hadolint.json"
    )

    assert _merged_pairs(findings) == {
        _pair("DS-0013", "hadolint", "DL3003"),
        _pair("DS-0002", "hadolint", "DL3002"),
    }


def test_every_kubernetes_pair_merges_and_nothing_else_does():
    """All eleven trivy/checkov pairs on one Pod merge, and no other trivy
    finding joins a checkov one: 20 and 22 findings share one resource, so a
    location rule that ignored the table would merge unrelated checks."""
    findings = _parsed(TrivyAdapter, "pod.trivy.json") + _parsed(
        CheckovAdapter, "pod.checkov.json"
    )

    assert _merged_pairs(findings) == {
        _pair("KSV-0017", "checkov", "CKV_K8S_16"),  # privileged
        _pair("KSV-0001", "checkov", "CKV_K8S_20"),  # privilege escalation
        _pair("KSV-0010", "checkov", "CKV_K8S_17"),  # host PID
        _pair("KSV-0012", "checkov", "CKV_K8S_23"),  # runs as root
        _pair("KSV-0009", "checkov", "CKV_K8S_19"),  # host network
        _pair("KSV-0011", "checkov", "CKV_K8S_11"),  # CPU limits
        _pair("KSV-0018", "checkov", "CKV_K8S_13"),  # memory limits
        _pair("KSV-0016", "checkov", "CKV_K8S_12"),  # memory requests
        _pair("KSV-0015", "checkov", "CKV_K8S_10"),  # CPU requests
        _pair("KSV-0013", "checkov", "CKV_K8S_14"),  # image tag
        _pair("KSV-0014", "checkov", "CKV_K8S_22"),  # read-only root filesystem
    }


def test_a_range_inside_another_counts_only_for_a_listed_pair():
    """Every trivy finding on the Pod sits inside every checkov range, so
    containment is no evidence by itself: an unlisted pair keeps its Jaccard
    (4 shared lines of 12). The clustering test above cannot see this, since
    on this Pod no unlisted pair would cross 0.65 either way (max 0.591)."""
    from scripts.core.dedup_enhanced import SimilarityCalculator

    trivy = {f["ruleId"]: f for f in _parsed(TrivyAdapter, "pod.trivy.json")}
    checkov = {f["ruleId"]: f for f in _parsed(CheckovAdapter, "pod.checkov.json")}
    image_tag, unlisted = trivy["KSV-0013"], checkov["CKV_K8S_37"]
    calculator = SimilarityCalculator()

    assert calculator.location_similarity(
        image_tag["location"], unlisted["location"]
    ) == pytest.approx(4 / 12)
    # Through the score a report uses: containment is decided per pair, so
    # an unlisted pair keeps 0.2024 (it would be 0.70 with location 1.0).
    assert calculator.calculate_similarity(image_tag, unlisted) == pytest.approx(
        0.2024, abs=1e-3
    )
    assert calculator.calculate_similarity(
        image_tag, checkov["CKV_K8S_14"]
    ) > calculator.calculate_similarity(image_tag, unlisted)
