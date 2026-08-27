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

from pathlib import Path

import pytest

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
    names = {
        p.name[: -len("_adapter.py")].replace("_", "-")
        for p in ADAPTER_DIR.glob("*_adapter.py")
    }
    # Meta-guard: an extractor that silently finds nothing satisfies every
    # assertion built on it (testing.rules.md).
    assert len(names) >= 25, f"adapter discovery found only {len(names)}: {names}"
    assert {"trivy", "checkov", "semgrep", "bandit"} <= names, sorted(names)
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
        ("trivy", "DS031", "iac-security-group-open-ingress"),
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
    merged, canonical = are_rules_equivalent(
        "checkov", "CKV_AWS_21", "trivy", "Public S3 bucket"
    )
    assert (merged, canonical) == (False, None), "versioning is not public access"

    assert are_rules_equivalent(
        "checkov", "CKV_AWS_23", "trivy", "Security group allows open ingress"
    ) == (False, None), "a description check is not an open-ingress finding"

    assert are_rules_equivalent(
        "checkov", "CKV_AWS_17", "trivy", "Unencrypted storage"
    ) == (False, None), "RDS public access is not an encryption finding"

    # ...while the real cross-tool pairs still are.
    assert are_rules_equivalent(
        "checkov", "CKV_AWS_20", "trivy", "Public S3 bucket"
    ) == (
        True,
        "iac-public-s3-bucket",
    )
    assert are_rules_equivalent(
        "checkov", "CKV_AWS_24", "trivy", "Security group allows open ingress"
    ) == (True, "iac-security-group-open-ingress")


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
