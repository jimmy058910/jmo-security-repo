"""A consensus finding is the merge of its cluster's members, in any load order (#1355).

The report phase enriches every finding (CWE, compliance, EPSS/KEV priority)
BEFORE cross-tool clustering, so a consensus built as a copy of one member
threw every other member's enrichment away -- and which member survived
depended on file-load order, because the report loads each tool's output on a
thread and keeps whichever finished first. Measured on juice-shop in PR A:
five same-line gitleaks + trufflehog pairs took the `owasp-top-10` violations
from 7 to 2, since gitleaks led and carried no CWE.

These tests state the property rather than a list of fields, so the next field
a finding grows is covered without anyone remembering to add it:

(a) every leaf value any member carries is reachable in the consensus, except
    the documented exceptions below;
(b) the consensus is byte-identical for every order its members arrive in;
(c) a policy's violation set over the consensus is identical for every order.

Documented exceptions to (a) -- what a consensus holds instead:

- ``id``: ``cluster-<lead id>``; every other member's id is in
  ``context.duplicates``.
- ``tool``: every member's is in ``detected_by``.
- ``severity``: the highest; each other member's own is in its duplicates entry.
- ``location``: the lead's, whole (one place, not a blend of several).
- ``raw``: per member -- the lead's at ``raw``, each other member's in its
  duplicates entry (a tool's native payload, never blended across tools).
- ``cvss``: one member's, whole, by the preference rule (v3 over v2 over
  unversioned, then the higher score), checked on its own below.
- ``priority``: the most urgent value field by field (a KEV flag, the higher
  EPSS and score, the earlier due date), checked on its own below.
- a scalar the lead holds its own value for: the lead's (e.g. ``message``,
  ``ruleId``, ``risk.confidence``).
- a compliance entry of a framework ``COMPLIANCE_ENTRY_KEYS`` names is one per
  key, as ``compliance_mapper`` keeps it within one finding: its key is
  reachable, its description may be the lead's wording.

The corpus is the golden adapter outputs (gitleaks, osv-scanner, zizmor) with a
synthetic fourth member carrying a key no real finding has, so (a) can fail.
Their members come from different repositories and would never score as
similar, so the similarity measurement is stubbed: that is the clusterer's
question, and this file is about what a cluster becomes once formed.
"""

from __future__ import annotations

import copy
import functools
import itertools
import json
from pathlib import Path
from typing import Any

import pytest

from scripts.core import dedup_enhanced
from scripts.core.common_finding import Severity
from scripts.core.compliance_mapper import (
    COMPLIANCE_ENTRY_KEYS,
    enrich_findings_with_compliance,
)
from scripts.core.cwe_extraction import backfill_risk_cwe
from scripts.core.dedup_enhanced import (
    FindingCluster,
    FindingClusterer,
    LSHSignatureGenerator,
    SimilarityCalculator,
)
from scripts.core.normalize_and_report import _cluster_cross_tool_duplicates

_GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "golden"
_LIST = "[]"  # a path segment meaning "some element of this list"

# ----------------------------------------------------------------------------
# The corpus
# ----------------------------------------------------------------------------


def _golden(tool_version: str) -> list[dict[str, Any]]:
    """A golden file's findings, shaped as the report phase sees them.

    The golden files keep ``None`` fields; ``Finding.to_dict`` drops them.
    """
    findings = json.loads(
        (_GOLDEN / tool_version / "expected-findings.json").read_bytes()
    )
    return [{k: v for k, v in f.items() if v is not None} for f in findings]


def _priority(
    score: float, epss: float | None, kev: bool, due: str | None
) -> dict[str, Any]:
    """The dict `_enrich_with_priority` writes (normalize_and_report)."""
    return {
        "priority": score,
        "epss": epss,
        "epss_percentile": None if epss is None else round(min(1.0, epss + 0.05), 3),
        "is_kev": kev,
        "kev_due_date": due,
        "components": {
            "severity_score": 7,
            "epss_multiplier": 1.0 + (epss or 0.0) * 4.0,
            "kev_multiplier": 3.0 if kev else 1.0,
            "reachability_multiplier": 1.0,
        },
    }


def _synthetic(index: int) -> dict[str, Any]:
    """A member carrying what no golden finding does, and never the lead."""
    return {
        "schemaVersion": "1.2.0",
        "id": f"synthetic-{index:03d}",
        "ruleId": "SYNTHETIC-1",
        "severity": "LOW",
        "tool": {"name": "zz-synthetic", "version": "0.0.1"},
        "location": {"path": "synthetic/member.txt", "startLine": index + 1},
        "message": "A cluster member carrying fields no other member has",
        "references": [f"https://example.invalid/synthetic/{index}"],
        "tags": ["synthetic"],
        "risk": {"cwe": ["CWE-79"]},
        # Outranks osv-scanner's unversioned score, loses to any v3.
        "cvss": {
            "version": "2.0",
            "score": 9.3,
            "vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
        },
        # The highest EPSS in the group, but not KEV-listed.
        "priority": _priority(61.3, 0.97, kev=False, due=None),
        "x-synthetic-extra": {"only-here": [f"leaf-{index}"], "deeper": {"flag": True}},
        "raw": {"synthetic": index},
    }


def _enriched(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The report phase's enrichment, in its order: CWE backfill, compliance."""
    members = copy.deepcopy(members)
    backfill_risk_cwe(members)
    return enrich_findings_with_compliance(members)


@functools.cache
def _corpus() -> list[list[dict[str, Any]]]:
    """Groups of one finding per tool, every golden finding in at least one.

    The KEV-listed member rotates, so it is the lead in some groups and not in
    others; every fifth group also takes the synthetic member.
    """
    gitleaks = _golden("gitleaks/v8.30.1")
    osv = _golden("osv_scanner/v2.5.1")
    zizmor = _golden("zizmor/v1.30.1")
    groups = []
    for i, finding in enumerate(osv):
        members = [gitleaks[i % len(gitleaks)], finding, zizmor[i % len(zizmor)]]
        members = copy.deepcopy(members)
        kev = i % len(members)
        for j, member in enumerate(members):
            if j == kev:
                member["priority"] = _priority(100.0, 0.21, kev=True, due="2026-10-15")
            elif j == (kev + 1) % len(members):
                member["priority"] = _priority(46.7, None, kev=False, due=None)
        if i % 5 == 0:
            members.append(_synthetic(i))
        groups.append(_enriched(members))
    return groups


# ----------------------------------------------------------------------------
# Building a consensus three ways
# ----------------------------------------------------------------------------


@pytest.fixture
def every_pair_similar(monkeypatch):
    """Any two findings score 1.0 and share an LSH bucket.

    Clustering still refuses a second finding from one tool, so a group of one
    finding per tool becomes exactly one cluster. The osv-scanner member is a
    dependency finding, which the clusterer matches on identity rather than
    similarity (#1346); it takes the similarity path here too, so its
    `dependency` object is merged like every other field.
    """
    monkeypatch.setattr(
        SimilarityCalculator, "calculate_similarity", lambda self, a, b: 1.0
    )
    monkeypatch.setattr(
        LSHSignatureGenerator, "generate_signatures", lambda self, f: ["one-bucket"]
    )
    monkeypatch.setattr(dedup_enhanced, "dependency_key", lambda finding: None)


def _by_cluster_add(order: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    """A cluster assembled by hand, in this order, every pair equally similar."""
    cluster = FindingCluster(representative=copy.deepcopy(order[0]))
    for member in order[1:]:
        cluster.add(copy.deepcopy(member), 0.9)
    return cluster.to_consensus_finding()


def _by_report_phase(order: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    """Through `_cluster_cross_tool_duplicates`, the report phase's own call."""
    out = _cluster_cross_tool_duplicates(
        copy.deepcopy(list(order)), similarity_threshold=0.65
    )
    assert len(out) == 1, f"the group must form one cluster, got {len(out)} findings"
    return out[0]


@pytest.fixture(params=["cluster.add", "greedy", "lsh"])
def build(request, monkeypatch, every_pair_similar):
    if request.param == "cluster.add":
        return _by_cluster_add
    if request.param == "lsh":
        monkeypatch.setattr(FindingClusterer, "LSH_THRESHOLD", 0)
    return _by_report_phase


# ----------------------------------------------------------------------------
# The invariant
# ----------------------------------------------------------------------------


def _leaves(value: Any, path: tuple[str, ...] = ()):
    """(path, value) for every scalar; a list item's segment is `_LIST`."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _leaves(item, (*path, key))
    elif isinstance(value, list):
        for item in value:
            yield from _leaves(item, (*path, _LIST))
    elif value is not None:
        yield path, value


def _holds(node: Any, path: tuple[str, ...], value: Any) -> bool:
    """Whether `value` is reachable from `node` along `path`."""
    if not path:
        return node == value and isinstance(node, bool) == isinstance(value, bool)
    head, rest = path[0], path[1:]
    if head == _LIST:
        return isinstance(node, list) and any(_holds(i, rest, value) for i in node)
    return isinstance(node, dict) and head in node and _holds(node[head], rest, value)


def _lead_holds_its_own(lead: dict[str, Any], path: tuple[str, ...]) -> bool:
    """Whether the lead holds a value on `path` that the merge keeps instead.

    A scalar at `path`, or a different shape at or above it, is the lead's
    and stands. A list the member's item would join does not count: lists
    are unioned, so that item must be in the consensus.
    """
    node: Any = lead
    for key in path:
        if key == _LIST:
            return node is not None and not isinstance(node, list)
        if not isinstance(node, dict):
            return node is not None
        if node.get(key) is None:
            return False
        node = node[key]
    return node is not None


def _keyed_compliance_detail(path: tuple[str, ...]) -> bool:
    """A compliance entry's non-key field, where entries are one per key."""
    return (
        len(path) == 4
        and path[0] == "compliance"
        and path[1] in COMPLIANCE_ENTRY_KEYS
        and path[2] == _LIST
        and path[3] != COMPLIANCE_ENTRY_KEYS[path[1]]
    )


def _severity_rank(value: Any) -> int:
    order = [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    return order.index(Severity.from_string(value))


def _lost_leaves(
    consensus: dict[str, Any], members: list[dict[str, Any]]
) -> list[tuple[str, tuple[str, ...], Any]]:
    """(member id, path, value) for every leaf the consensus does not hold."""
    lead_id = consensus["id"].removeprefix("cluster-")
    (lead,) = [m for m in members if m["id"] == lead_id]
    duplicates = {d["id"]: d for d in consensus["context"]["duplicates"]}
    lost = []
    for member in members:
        is_lead = member is lead
        for path, value in _leaves(member):
            head = path[0]
            if head in ("cvss", "priority"):
                continue  # their own rules: see _cvss_problems / _priority_problems
            if head == "id":
                ok = (
                    consensus["id"] == f"cluster-{value}"
                    if is_lead
                    else value in duplicates
                )
            elif head == "tool":
                ok = any(_holds(t, path[1:], value) for t in consensus["detected_by"])
            elif head == "severity":
                ok = _severity_rank(value) <= _severity_rank(
                    consensus["severity"]
                ) and (is_lead or duplicates[member["id"]]["severity"] == value)
            elif is_lead:
                ok = _holds(consensus, path, value)
            elif head == "raw":
                ok = _holds(duplicates[member["id"]], path, value)
            elif head == "message":
                ok = duplicates[member["id"]]["message"] == value
            elif head == "location" or _keyed_compliance_detail(path):
                continue
            else:
                ok = _holds(consensus, path, value) or _lead_holds_its_own(lead, path)
            if not ok:
                lost.append((member["id"], path, value))
    return lost


def _cvss_rank(cvss: dict[str, Any]) -> tuple[int, float]:
    """Ruling 34 (#1356): v3.x over v4.0 over v2.0 over no version, then the
    higher score. An independent oracle -- it does not call `preferred_cvss`,
    so it cannot pass merely because the implementation and the test share a
    bug."""
    version = str(cvss.get("version") or "")
    if version.startswith("3"):
        tier = 3
    elif version.startswith("4"):
        tier = 2
    elif version.startswith("2"):
        tier = 1
    else:
        tier = 0
    score = cvss.get("score")
    return tier, float(score) if isinstance(score, (int, float)) else -1.0


def _cvss_problems(
    consensus: dict[str, Any], members: list[dict[str, Any]]
) -> list[str]:
    offered = [m["cvss"] for m in members if isinstance(m.get("cvss"), dict)]
    if not offered:
        return []
    chosen = consensus.get("cvss")
    if chosen not in offered:
        return [f"cvss {chosen!r} is none of the members' {offered!r}"]
    best = max(_cvss_rank(c) for c in offered)
    if _cvss_rank(chosen) != best:
        return [f"cvss {chosen!r} ranks {_cvss_rank(chosen)}, a member's ranks {best}"]
    return []


def _priority_problems(
    consensus: dict[str, Any], members: list[dict[str, Any]]
) -> list[str]:
    """No member's priority is more urgent than the consensus's, anywhere."""
    merged = consensus.get("priority") or {}
    problems = []
    for member in members:
        for path, value in _leaves(member.get("priority") or {}):
            node: Any = merged
            for key in path:
                node = node.get(key) if isinstance(node, dict) else None
            if isinstance(value, bool):
                ok = node is True or not value
            elif isinstance(value, (int, float)):
                ok = isinstance(node, (int, float)) and node >= value
            else:  # kev_due_date: the earlier deadline
                ok = isinstance(node, str) and node <= value
            if not ok:
                problems.append(
                    f"{member['id']} priority.{'.'.join(path)}={value!r}, consensus {node!r}"
                )
    return problems


def _owasp_violations(findings: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    """`policies/builtin/owasp-top-10.rego`'s violation set, in Python.

    One violation per finding carrying an OWASP category; the category is the
    list's FIRST element (``categories[0]``), so list order is policy-visible.
    """
    return sorted(
        (
            f["id"],
            f.get("severity"),
            f["compliance"]["owaspTop10_2021"][0],
            f.get("ruleId"),
            (f.get("location") or {}).get("path"),
        )
        for f in findings
        if (f.get("compliance") or {}).get("owaspTop10_2021")
    )


def _canonical(finding: dict[str, Any]) -> str:
    return json.dumps(finding, sort_keys=True)


def _tools(order: tuple[dict[str, Any], ...]) -> str:
    return ",".join(m["tool"]["name"] for m in order)


# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------


def test_the_corpus_can_fail_the_invariant():
    """Meta-guard: the corpus holds what a copy of one member would lose."""
    assert len(_corpus()) == 303
    synthetic = [
        g for g in _corpus() if any(m["tool"]["name"] == "zz-synthetic" for m in g)
    ]
    assert len(synthetic) == 61
    # Members disagreeing on CWE and on OWASP, a KEV listing on every tool in
    # turn (so on leads and non-leads), and ties on severity (the case load
    # order decided).
    assert any(
        len({tuple((m.get("risk") or {}).get("cwe") or ()) for m in g}) > 1
        for g in _corpus()
    )
    assert any(
        len(
            {tuple((m.get("compliance") or {}).get("owaspTop10_2021") or ()) for m in g}
        )
        > 1
        for g in _corpus()
    )
    kev_tools = {
        m["tool"]["name"]
        for g in _corpus()
        for m in g
        if (m.get("priority") or {}).get("is_kev")
    }
    assert kev_tools == {"gitleaks", "osv-scanner", "zizmor"}
    tied = [g for g in _corpus() if len({m["severity"] for m in g}) < len(g)]
    assert len(tied) > 100, len(tied)


def test_nothing_any_member_carried_is_lost(build):
    """(a): every leaf of every member is in the consensus, bar the exceptions."""
    failures = []
    for group in _corpus():
        for order in itertools.permutations(group):
            consensus = build(order)
            problems = [
                *(
                    f"lost {mid} {'.'.join(p)}={v!r}"
                    for mid, p, v in _lost_leaves(consensus, group)
                ),
                *_cvss_problems(consensus, group),
                *_priority_problems(consensus, group),
            ]
            if problems:
                failures.append(f"[{_tools(order)}] {problems[:4]}")
    assert not failures, f"{len(failures)} load order(s) lost data, e.g. {failures[:3]}"


def test_the_consensus_is_identical_for_every_load_order(build):
    """(b) and (c): byte-identical consensus, identical policy violations."""
    failures = []
    for group in _corpus():
        orders = list(itertools.permutations(group))
        first = build(orders[0])
        for order in orders[1:]:
            consensus = build(order)
            if _canonical(consensus) != _canonical(first):
                failures.append(
                    f"[{_tools(order)}] id {consensus['id']} vs {first['id']} "
                    f"(first order [{_tools(orders[0])}])"
                )
            elif _owasp_violations([consensus]) != _owasp_violations([first]):
                failures.append(f"[{_tools(order)}] owasp violations differ")
    assert not failures, f"{len(failures)} load order(s) differ, e.g. {failures[:3]}"


def test_a_member_only_field_survives():
    """The synthetic member's own key, which no merge rule names, survives."""
    group = next(
        g for g in _corpus() if any(m["tool"]["name"] == "zz-synthetic" for m in g)
    )
    consensus = _by_cluster_add(tuple(group))
    assert consensus["x-synthetic-extra"] == {
        "only-here": ["leaf-0"],
        "deeper": {"flag": True},
    }
    assert "https://example.invalid/synthetic/0" in consensus["references"]
    assert "CWE-79" in consensus["risk"]["cwe"]


def test_a_kev_listed_member_leaves_the_consensus_kev_listed():
    """KEV on a member that does not lead, and a higher EPSS on another."""
    lead = {
        "id": "a",
        "severity": "CRITICAL",
        "tool": {"name": "trivy", "version": "1"},
        "priority": _priority(40.0, 0.10, kev=False, due=None),
    }
    kev = {
        "id": "b",
        "severity": "HIGH",
        "tool": {"name": "osv-scanner", "version": "1"},
        "priority": _priority(90.0, 0.30, kev=True, due="2026-11-01"),
    }
    likely = {
        "id": "c",
        "severity": "LOW",
        "tool": {"name": "grype", "version": "1"},
        "priority": _priority(20.0, 0.95, kev=False, due=None),
    }
    for order in itertools.permutations([lead, kev, likely]):
        priority = _by_cluster_add(order)["priority"]
        assert priority["is_kev"] is True
        assert priority["kev_due_date"] == "2026-11-01"
        assert priority["epss"] == 0.95
        assert priority["priority"] == 90.0
        assert priority["components"]["kev_multiplier"] == 3.0


def test_the_lead_is_chosen_by_severity_then_tool_then_id():
    """A tie on severity is broken by tool name, then id -- never by order."""
    members = [
        {"id": "z1", "severity": "HIGH", "tool": {"name": "trufflehog"}},
        {"id": "a1", "severity": "HIGH", "tool": {"name": "gitleaks"}},
        {"id": "m1", "severity": "MEDIUM", "tool": {"name": "bandit"}},
    ]
    for order in itertools.permutations(members):
        consensus = _by_cluster_add(order)
        assert consensus["id"] == "cluster-a1", _tools(order)
        assert [d["id"] for d in consensus["context"]["duplicates"]] == ["z1", "m1"]
        assert [t["name"] for t in consensus["detected_by"]] == [
            "gitleaks",
            "trufflehog",
            "bandit",
        ]


@pytest.mark.parametrize("algorithm", ["greedy", "lsh"])
def test_which_findings_cluster_does_not_depend_on_load_order(algorithm, monkeypatch):
    """Two checkov rules on one line, and a trivy rule similar to both.

    One cluster holds one finding per tool, so trivy joins one checkov finding
    and the other stays alone. Which one used to be whichever loaded first:
    the greedy pass took the first as a cluster's representative, and the LSH
    pass handed a group's members out in the same order. Real similarity, no
    stub: trivy-cpu scores 1.0 with ckv-cpu (an equivalent rule) and 0.75
    with ckv-mem (same line, same message).
    """
    if algorithm == "lsh":
        monkeypatch.setattr(FindingClusterer, "LSH_THRESHOLD", 0)

    def finding(fid: str, tool: str, rule: str) -> dict[str, Any]:
        return {
            "id": fid,
            "ruleId": rule,
            "severity": "MEDIUM",
            "message": "Container resources are not limited",
            "tool": {"name": tool, "version": "1"},
            "location": {"path": "k8s/deploy.yaml", "startLine": 20},
            "raw": {},
            "tags": ["iac"],
        }

    members = [
        finding("ckv-cpu", "checkov", "CKV_K8S_11"),
        finding("ckv-mem", "checkov", "CKV_K8S_13"),
        finding("trivy-cpu", "trivy", "KSV-0011"),
    ]
    results = {
        _tools(order): _canonical_list(
            _cluster_cross_tool_duplicates(copy.deepcopy(list(order)), 0.65)
        )
        for order in itertools.permutations(members)
    }
    assert len(set(results.values())) == 1, sorted(results.items())
    # Meta-guard: the case under test -- trivy clustered, one checkov alone.
    (out,) = set(results.values())
    assert sorted(f["id"] for f in json.loads(out)) == ["ckv-mem", "cluster-ckv-cpu"]


def _canonical_list(findings: list[dict[str, Any]]) -> str:
    return json.dumps(sorted(findings, key=lambda f: f["id"]), sort_keys=True)


def test_the_lead_scores_one_whichever_member_was_added_first():
    """A lead that joins late scores 1.0; the one it displaces, the pair's score."""
    first = {"id": "b", "severity": "LOW", "tool": {"name": "semgrep"}}
    lead = {"id": "a", "severity": "HIGH", "tool": {"name": "bandit"}}
    cluster = FindingCluster(representative=first)
    cluster.add(lead, 0.8)
    assert cluster.representative is lead
    assert cluster.similarity_scores == {"a": 1.0, "b": 0.8}
    consensus = cluster.to_consensus_finding()
    assert consensus["context"]["duplicates"][0]["similarity_score"] == 0.8
    assert consensus["confidence"]["avg_similarity"] == 0.9


def test_location_tool_and_raw_are_the_leads_whole():
    """Not blended: one place, one tool, one tool's own payload.

    The other member's `raw` is kept with it, in its duplicates entry.
    """
    lead = {
        "id": "a",
        "severity": "HIGH",
        "tool": {"name": "gitleaks", "version": "8.30.1"},
        "location": {"path": "app.ts", "startLine": 7},
        "raw": {"ruleId": "jwt"},
    }
    other = {
        "id": "b",
        "severity": "HIGH",
        "tool": {"name": "trufflehog", "version": "3.97.1", "extra": "x"},
        "location": {"path": "app.ts", "startLine": 8, "startColumn": 3},
        "raw": {"DetectorName": "JWT"},
    }
    for order in itertools.permutations([lead, other]):
        consensus = _by_cluster_add(order)
        assert consensus["location"] == lead["location"]
        assert consensus["tool"] == lead["tool"]
        assert consensus["raw"] == lead["raw"]
        assert consensus["context"]["duplicates"][0]["raw"] == other["raw"]


def test_compliance_entries_stay_one_per_key():
    """Two members mapping one PCI requirement in two wordings list it once.

    `compliance_mapper` has two descriptions for PCI DSS 8.3.2 (its CWE table
    and its secrets-category table); the PCI report groups by requirement, so
    a second entry would count the finding twice under 8.3.2.
    """
    lead = {
        "id": "a",
        "severity": "HIGH",
        "tool": {"name": "gitleaks"},
        "compliance": {"pciDss4_0": [{"requirement": "8.3.2", "description": "one"}]},
    }
    other = {
        "id": "b",
        "severity": "HIGH",
        "tool": {"name": "trufflehog"},
        "compliance": {
            "pciDss4_0": [
                {"requirement": "8.3.2", "description": "two"},
                {"requirement": "8.2.1", "description": "three"},
            ]
        },
    }
    consensus = _by_cluster_add((other, lead))
    assert consensus["compliance"]["pciDss4_0"] == [
        {"requirement": "8.3.2", "description": "one"},
        {"requirement": "8.2.1", "description": "three"},
    ]


def test_merging_leaves_the_members_untouched():
    """The consensus is a new object; the lead's own dicts are not written to."""
    lead = {
        "id": "a",
        "severity": "HIGH",
        "tool": {"name": "bandit"},
        "context": {"snippet": "x"},
        "tags": ["one"],
    }
    other = {"id": "b", "severity": "LOW", "tool": {"name": "semgrep"}, "tags": ["two"]}
    before = copy.deepcopy([lead, other])
    cluster = FindingCluster(representative=lead)
    cluster.add(other, 0.9)
    cluster.to_consensus_finding()
    assert [lead, other] == before


@pytest.mark.parametrize(
    ("candidates", "expected"),
    [
        # v3.x outranks v2.0 whatever the numbers.
        (
            [{"version": "2.0", "score": 10.0}, {"version": "3.x", "score": 5.3}],
            {"version": "3.x", "score": 5.3},
        ),
        # Within one version, the higher score.
        (
            [{"version": "3.x", "score": 5.3}, {"version": "3.1", "score": 7.5}],
            {"version": "3.1", "score": 7.5},
        ),
        # A missing version sorts last (SARIF's bare `security-severity`).
        (
            [{"score": 9.8}, {"version": "2.0", "score": 4.0}],
            {"version": "2.0", "score": 4.0},
        ),
        # A tie keeps the earlier candidate; non-dicts and empties are skipped.
        (
            [
                None,
                {},
                "7.5",
                {"version": "3.x", "score": 7.5, "vector": "first"},
                {"version": "3.x", "score": 7.5, "vector": "second"},
            ],
            {"version": "3.x", "score": 7.5, "vector": "first"},
        ),
        ([None, {}], None),
        ([], None),
        # Ruling 34 (#1356): v3.x outranks v4.0 whatever the numbers.
        (
            [{"version": "4.0", "score": 9.0}, {"version": "3.x", "score": 5.3}],
            {"version": "3.x", "score": 5.3},
        ),
        # v4.0 is the only offer.
        (
            [{"version": "4.0", "score": 8.7}],
            {"version": "4.0", "score": 8.7},
        ),
        # v4.0 outranks v2.0 whatever the numbers.
        (
            [{"version": "2.0", "score": 10.0}, {"version": "4.0", "score": 1.0}],
            {"version": "4.0", "score": 1.0},
        ),
        # v2.0 is the only offer.
        (
            [{"version": "2.0", "score": 6.5}],
            {"version": "2.0", "score": 6.5},
        ),
    ],
)
def test_preferred_cvss(candidates, expected):
    """Ruling 29's order, extended by Ruling 34 (#1356) with v4.0."""
    from scripts.core.common_finding import preferred_cvss

    assert preferred_cvss(candidates) == expected


def test_consensus_merge_prefers_v3_then_v4_then_v2_across_members():
    """Ruling 34 (#1356) through the actual consensus-merge code path, not
    just the bare helper: two cluster members carrying different CVSS
    versions, merged by `FindingCluster.to_consensus_finding`."""
    v2 = {
        "id": "a",
        "severity": "LOW",
        "tool": {"name": "grype"},
        "cvss": {"version": "2.0", "score": 10.0},
    }
    v4 = {
        "id": "b",
        "severity": "LOW",
        "tool": {"name": "trivy"},
        "cvss": {"version": "4.0", "score": 1.0},
    }
    v3 = {
        "id": "c",
        "severity": "LOW",
        "tool": {"name": "osv-scanner"},
        "cvss": {"version": "3.x", "score": 5.0},
    }

    v2_v4 = FindingCluster(representative=copy.deepcopy(v2))
    v2_v4.add(copy.deepcopy(v4), 0.9)
    assert v2_v4.to_consensus_finding()["cvss"] == {"version": "4.0", "score": 1.0}

    v3_v4 = FindingCluster(representative=copy.deepcopy(v3))
    v3_v4.add(copy.deepcopy(v4), 0.9)
    assert v3_v4.to_consensus_finding()["cvss"] == {"version": "3.x", "score": 5.0}
