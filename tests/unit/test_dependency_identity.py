"""One vulnerability in one installed package version is one finding (#1346).

Whichever dependency scanners report it, and however many. A dependency finding
has no line, so the similarity clusterer's location term was 0.0 for every
pair and no two dependency scanners had ever clustered: measured on a real
lockfile, trivy and osv-scanner reported the same 47 and the report held 85.
And trivy's id hashed the advisory title, not the version, so two installed
versions of one package with one advisory were one finding: its 47 were 38.

The identity is (lockfile, package, installed version, advisory), the advisory
matched on an id or an alias. These tests drive the real adapters over tool
documents shaped as trivy 0.74.0, osv-scanner 2.6.0 and grype 0.115.0 wrote
them on NodeGoat (public; ids and packages are NodeGoat's), through the report
phase's own `gather_results`.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

import pytest

from scripts.core import normalize_and_report
from scripts.core.dedup_enhanced import (
    FindingClusterer,
    SimilarityCalculator,
    cluster_dependency_findings,
)
from scripts.core.normalize_and_report import gather_results

TOOLS = ("grype", "osv-scanner", "trivy")


# --- tool documents, in each tool's own shape -----------------------------------


def trivy_vuln(
    vid: str, name: str, version: str, vendor_ids=(), severity: str = "HIGH"
) -> dict[str, Any]:
    record = {
        "VulnerabilityID": vid,
        "PkgID": f"{name}@{version}",
        "PkgName": name,
        "PkgIdentifier": {"PURL": f"pkg:npm/{name}@{version}"},
        "InstalledVersion": version,
        "Severity": severity,
        # trivy's message is the advisory's title, which names no version
        "Title": f"{name}: advisory {vid}",
    }
    if vendor_ids:
        record["VendorIDs"] = list(vendor_ids)
    return record


def trivy_doc(repo: Path, by_lockfile: dict[str, list[dict]]) -> dict[str, Any]:
    return {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.74.0"},
        "ArtifactName": str(repo),
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": lockfile,
                "Class": "lang-pkgs",
                "Type": "npm",
                "Vulnerabilities": vulns,
            }
            for lockfile, vulns in by_lockfile.items()
        ],
    }


def osv_doc(
    repo: Path, entries: list[tuple[str, str, str, list[str]]]
) -> dict[str, Any]:
    """entries: (lockfile, name@version, rule id, every id of the rule)."""
    rules: list[dict] = []
    results = []
    for lockfile, package, rule_id, ids in entries:
        if rule_id not in [r["id"] for r in rules]:
            rules.append(
                {
                    "id": rule_id,
                    "name": rule_id,
                    "deprecatedIds": ids,
                    "shortDescription": {"text": f"{rule_id}: advisory"},
                    "properties": {"security-severity": "7.5"},
                }
            )
        aka = ", ".join(f"'{i}'" for i in ids if i != rule_id)
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": [r["id"] for r in rules].index(rule_id),
                "level": "warning",
                "message": {
                    "text": f"Package '{package}' is vulnerable to '{rule_id}'"
                    + (f" (also known as {aka})." if aka else ".")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": (repo / lockfile).as_uri()}
                        }
                    }
                ],
            }
        )
    driver = {"name": "osv-scanner", "version": "2.6.0", "rules": rules}
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def grype_match(
    vid: str, name: str, version: str, related=(), lockfile="package-lock.json"
):
    return {
        "vulnerability": {"id": vid, "severity": "High", "description": "advisory"},
        "relatedVulnerabilities": [{"id": r, "namespace": "nvd:cpe"} for r in related],
        "artifact": {
            "name": name,
            "version": version,
            "type": "npm",
            "purl": f"pkg:npm/{name}@{version}",
            "locations": [{"path": f"/{lockfile}"}],
        },
    }


def report(tmp_path: Path, monkeypatch, docs: dict[str, Any]) -> list[dict[str, Any]]:
    """The report phase over these raw tool outputs, as `jmo scan` leaves them."""
    # EPSS/KEV lookups would reach the network; priority is not under test.
    monkeypatch.setattr(normalize_and_report, "_enrich_with_priority", lambda f: None)
    results = tmp_path / "results"
    target = results / "individual-repos" / "app"
    target.mkdir(parents=True)
    (results / ".scan_metadata.json").write_bytes(
        json.dumps({"repo_paths": [str(repo_dir(tmp_path))]}).encode()
    )
    for tool, doc in docs.items():
        (target / f"{tool}.json").write_bytes(json.dumps(doc).encode())
    return gather_results(results)


def repo_dir(tmp_path: Path) -> Path:
    return tmp_path / "app"


def detected_by(finding: dict[str, Any]) -> tuple[str, ...]:
    reporters = finding.get("detected_by") or [finding["tool"]]
    return tuple(sorted(r["name"] for r in reporters))


# --- the three advisories, as NodeGoat has them ---------------------------------

# lodash at two installed versions with one advisory, and minimist at one.
GHSA_LODASH = "GHSA-jf85-cpcp-j695"
GHSA_MINIMIST = "GHSA-xvch-5gv4-984h"
PACKAGES = [
    ("lodash", "4.13.1", "CVE-2019-10744", GHSA_LODASH),
    ("lodash", "4.17.4", "CVE-2019-10744", GHSA_LODASH),
    ("minimist", "0.0.8", "CVE-2021-44906", GHSA_MINIMIST),
]


def docs_for(repo: Path, tools: tuple[str, ...]) -> dict[str, Any]:
    docs: dict[str, Any] = {}
    if "trivy" in tools:
        docs["trivy"] = trivy_doc(
            repo,
            {
                "package-lock.json": [
                    trivy_vuln(c, n, v, [g]) for n, v, c, g in PACKAGES
                ]
            },
        )
    if "osv-scanner" in tools:
        docs["osv-scanner"] = osv_doc(
            repo,
            [("package-lock.json", f"{n}@{v}", c, [c, g]) for n, v, c, g in PACKAGES],
        )
    if "grype" in tools:
        # grype names the GHSA and relates the CVE (measured, 0.115.0)
        docs["grype"] = {
            "matches": [grype_match(g, n, v, [c]) for n, v, c, g in PACKAGES]
        }
    return docs


@pytest.mark.parametrize(
    "tools",
    [
        combo
        for size in range(1, len(TOOLS) + 1)
        for combo in itertools.combinations(TOOLS, size)
    ],
    ids=lambda combo: "+".join(combo),
)
def test_one_vulnerability_in_one_installed_version_is_one_finding(
    tmp_path, monkeypatch, tools
):
    """The gate's shape in miniature: three (package, version, advisory), so
    three findings from any one tool, from any two and from all three, each
    detected by every tool that ran -- never 2 (trivy's versions collapsed)
    and never 3 per tool (dependency scanners never clustering)."""
    findings = report(tmp_path, monkeypatch, docs_for(repo_dir(tmp_path), tools))

    assert len(findings) == len(PACKAGES), [
        (f["ruleId"], f.get("dependency"), detected_by(f)) for f in findings
    ]
    assert {detected_by(f) for f in findings} == {tuple(sorted(tools))}
    # each is exactly one of the three packages, whatever tool leads it
    assert sorted(
        (f["dependency"]["name"], f["dependency"]["version"]) for f in findings
    ) == sorted((n, v) for n, v, _, _ in PACKAGES)


def test_each_installed_version_pairs_with_its_own_version(tmp_path, monkeypatch):
    """Two versions of one package with one advisory are two findings, and a
    tool's 4.13.1 finding is never the other tool's 4.17.4 finding."""
    findings = report(
        tmp_path, monkeypatch, docs_for(repo_dir(tmp_path), ("osv-scanner", "trivy"))
    )
    assert len(findings) == len(PACKAGES)
    for finding in findings:
        versions = {finding["dependency"]["version"]}
        for member in (finding.get("context") or {}).get("duplicates", []):
            raw = member["raw"]
            # trivy's record names its version; osv-scanner's message does
            versions.add(
                raw["InstalledVersion"]
                if "InstalledVersion" in raw
                else raw["message"]["text"].split("'")[1].rpartition("@")[2]
            )
        assert len(versions) == 1, (finding["ruleId"], versions)


def test_a_version_pairs_only_with_its_own_version():
    """Load order puts the other version's cluster first, so only the key
    can keep the pairs straight."""
    findings = [
        dep("o-a", "osv-scanner", "CVE-2019-10744", "lodash", "4.17.4", [GHSA_LODASH]),
        dep("o-b", "osv-scanner", "CVE-2019-10744", "lodash", "4.13.1", [GHSA_LODASH]),
        dep("t-a", "trivy", "CVE-2019-10744", "lodash", "4.13.1", [GHSA_LODASH]),
        dep("t-b", "trivy", "CVE-2019-10744", "lodash", "4.17.4", [GHSA_LODASH]),
    ]
    assert membership(cluster_dependency_findings(findings)) == {
        frozenset({"o-a", "t-b"}),
        frozenset({"o-b", "t-a"}),
    }


def test_the_consensus_carries_the_dependency_merged(tmp_path, monkeypatch):
    """The #1355 merge, on a real pair: the lead's name and version, the
    ecosystem trivy knows and osv-scanner's SARIF does not, the aliases of
    both tools unioned."""
    repo = repo_dir(tmp_path)
    docs = {
        "trivy": trivy_doc(
            repo,
            {
                "package-lock.json": [
                    trivy_vuln("CVE-2019-10744", "lodash", "4.17.4", [GHSA_LODASH])
                ]
            },
        ),
        "osv-scanner": osv_doc(
            repo,
            [
                (
                    "package-lock.json",
                    "lodash@4.17.4",
                    "CVE-2019-10744",
                    ["CVE-2019-10744", GHSA_LODASH, "GHSA-extra-only-osv"],
                )
            ],
        ),
    }
    [finding] = report(tmp_path, monkeypatch, docs)

    assert detected_by(finding) == ("osv-scanner", "trivy")
    dependency = finding["dependency"]
    assert (dependency["name"], dependency["version"]) == ("lodash", "4.17.4")
    assert dependency["ecosystem"] == "npm"  # trivy's, whichever tool leads
    assert set(dependency["aliases"]) == {GHSA_LODASH, "GHSA-extra-only-osv"}


def test_an_alias_is_enough(tmp_path, monkeypatch):
    """Two tools naming one advisory by different primary ids are one finding.

    NodeGoat's lodash 4.13.1: trivy reports CVE-2026-4800, and osv-scanner
    files it under its rule CVE-2021-23337, whose `deprecatedIds` list it."""
    repo = repo_dir(tmp_path)
    docs = {
        "trivy": trivy_doc(
            repo,
            {
                "package-lock.json": [
                    trivy_vuln(
                        "CVE-2026-4800", "lodash", "4.13.1", ["GHSA-r5fr-rjxr-66jc"]
                    )
                ]
            },
        ),
        "osv-scanner": osv_doc(
            repo,
            [
                (
                    "package-lock.json",
                    "lodash@4.13.1",
                    "CVE-2021-23337",
                    [
                        "CVE-2021-23337",
                        "CVE-2026-4800",
                        "GHSA-35jh-r3h4-6jhm",
                        "GHSA-r5fr-rjxr-66jc",
                    ],
                )
            ],
        ),
        # grype names only the GHSA, and relates the CVE: an alias both ways
        "grype": {
            "matches": [
                grype_match(
                    "GHSA-r5fr-rjxr-66jc", "lodash", "4.13.1", ["CVE-2026-4800"]
                )
            ]
        },
    }
    findings = report(tmp_path, monkeypatch, docs)

    assert [detected_by(f) for f in findings] == [TOOLS]


def test_different_lockfiles_are_different_findings(tmp_path, monkeypatch):
    """Equal package, version and advisory in two lockfiles: two findings,
    each detected by both tools, never one."""
    repo = repo_dir(tmp_path)
    vuln = ("CVE-2021-44906", "minimist", "0.0.8", GHSA_MINIMIST)
    lockfiles = ("package-lock.json", "web/package-lock.json")
    docs = {
        "trivy": trivy_doc(
            repo,
            {
                lf: [trivy_vuln(vuln[0], vuln[1], vuln[2], [vuln[3]])]
                for lf in lockfiles
            },
        ),
        "osv-scanner": osv_doc(
            repo,
            [
                (lf, f"{vuln[1]}@{vuln[2]}", vuln[0], [vuln[0], vuln[3]])
                for lf in lockfiles
            ],
        ),
    }
    findings = report(tmp_path, monkeypatch, docs)

    assert sorted(f["location"]["path"] for f in findings) == sorted(lockfiles)
    assert {detected_by(f) for f in findings} == {("osv-scanner", "trivy")}


def test_one_package_in_two_lockfiles_from_two_tools_is_two_findings(
    tmp_path, monkeypatch
):
    """trivy reports it in one lockfile and osv-scanner in the other: equal
    package, version and advisory, and still not one finding."""
    repo = repo_dir(tmp_path)
    docs = {
        "trivy": trivy_doc(
            repo,
            {
                "package-lock.json": [
                    trivy_vuln("CVE-2021-44906", "minimist", "0.0.8", [GHSA_MINIMIST])
                ]
            },
        ),
        "osv-scanner": osv_doc(
            repo,
            [
                (
                    "web/package-lock.json",
                    "minimist@0.0.8",
                    "CVE-2021-44906",
                    ["CVE-2021-44906", GHSA_MINIMIST],
                )
            ],
        ),
    }
    findings = report(tmp_path, monkeypatch, docs)

    assert sorted((f["location"]["path"], detected_by(f)) for f in findings) == [
        ("package-lock.json", ("trivy",)),
        ("web/package-lock.json", ("osv-scanner",)),
    ]


def test_two_tools_spell_one_package_differently(tmp_path, monkeypatch):
    """Measured spellings of one package: trivy writes a PyPI name as the
    requirements file does and a Go version with its `v`; osv-scanner writes
    `flask-cors` and `0.3.0`."""
    repo = repo_dir(tmp_path)
    trivy = trivy_doc(repo, {})
    trivy["Results"] = [
        {
            "Target": "requirements.txt",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    **trivy_vuln(
                        "CVE-2020-25032", "Flask_Cors", "3.0.8", ["GHSA-xc3p-ff3m-f46v"]
                    ),
                    "PkgIdentifier": {"PURL": "pkg:pypi/flask-cors@3.0.8"},
                }
            ],
        },
        {
            "Target": "go.mod",
            "Type": "gomod",
            "Vulnerabilities": [
                {
                    **trivy_vuln(
                        "CVE-2020-14040",
                        "golang.org/x/text",
                        "v0.3.0",
                        ["GHSA-5rcv-m4m3-hfh7", "GO-2020-0015"],
                    ),
                    "PkgIdentifier": {"PURL": "pkg:golang/golang.org/x/text@v0.3.0"},
                }
            ],
        },
    ]
    docs = {
        "trivy": trivy,
        "osv-scanner": osv_doc(
            repo,
            [
                (
                    "requirements.txt",
                    "flask-cors@3.0.8",
                    "CVE-2020-25032",
                    ["CVE-2020-25032", "GHSA-xc3p-ff3m-f46v"],
                ),
                (
                    "go.mod",
                    "golang.org/x/text@0.3.0",
                    "CVE-2020-14040",
                    ["CVE-2020-14040", "GO-2020-0015", "GHSA-5rcv-m4m3-hfh7"],
                ),
            ],
        ),
    }
    findings = report(tmp_path, monkeypatch, docs)

    assert len(findings) == 2
    assert {detected_by(f) for f in findings} == {("osv-scanner", "trivy")}


# --- the clusterer's rules, on findings as the report phase holds them ----------


def dep(
    fid,
    tool,
    rule,
    name,
    version,
    aliases=(),
    path="package-lock.json",
    severity="HIGH",
):
    return {
        "id": fid,
        "ruleId": rule,
        "severity": severity,
        "tool": {"name": tool, "version": "1"},
        "location": {"path": path, "startLine": 0},
        "message": f"{rule} in {name}",
        "tags": ["vulnerability"],
        "dependency": {"name": name, "version": version, "aliases": list(aliases)},
        "raw": {},
    }


def membership(clusters) -> set[frozenset[str]]:
    return {frozenset(f["id"] for f in c.findings) for c in clusters}


def test_one_finding_per_tool_when_one_rule_covers_two_advisories():
    """osv-scanner's lodash rule lists both advisories trivy reports apart
    (measured on NodeGoat). It joins one of them; trivy's other finding stays
    a finding of its own rather than a second trivy member."""
    findings = [
        dep(
            "t1", "trivy", "CVE-2021-23337", "lodash", "4.13.1", ["GHSA-35jh-r3h4-6jhm"]
        ),
        dep(
            "t2", "trivy", "CVE-2026-4800", "lodash", "4.13.1", ["GHSA-r5fr-rjxr-66jc"]
        ),
        dep(
            "o1",
            "osv-scanner",
            "CVE-2021-23337",
            "lodash",
            "4.13.1",
            ["CVE-2026-4800", "GHSA-35jh-r3h4-6jhm", "GHSA-r5fr-rjxr-66jc"],
        ),
    ]
    clusters = cluster_dependency_findings(findings)

    assert sorted(len(c.findings) for c in clusters) == [1, 2]
    for cluster in clusters:
        tools = [f["tool"]["name"] for f in cluster.findings]
        assert len(tools) == len(set(tools))


def test_a_split_linked_set_still_pairs_by_shared_id():
    """osv-scanner's rule links trivy's two lodash advisories into one set.
    Split one tool per cluster, grype's CVE-2026-4800 finding joins trivy's
    CVE-2026-4800 one, not whichever cluster without a grype finding came
    first."""
    findings = [
        dep(
            "t1",
            "trivy",
            "CVE-2021-23337",
            "lodash",
            "4.13.1",
            ["GHSA-35jh-r3h4-6jhm"],
            severity="CRITICAL",
        ),
        dep(
            "t2",
            "trivy",
            "CVE-2026-4800",
            "lodash",
            "4.13.1",
            ["GHSA-r5fr-rjxr-66jc"],
            severity="CRITICAL",
        ),
        dep(
            "o1",
            "osv-scanner",
            "CVE-2021-23337",
            "lodash",
            "4.13.1",
            ["CVE-2026-4800", "GHSA-35jh-r3h4-6jhm", "GHSA-r5fr-rjxr-66jc"],
        ),
        dep(
            "g1", "grype", "GHSA-r5fr-rjxr-66jc", "lodash", "4.13.1", ["CVE-2026-4800"]
        ),
    ]
    assert membership(cluster_dependency_findings(findings)) == {
        frozenset({"t1", "o1"}),
        frozenset({"t2", "g1"}),
    }


def test_a_third_tool_joins_through_an_alias_only_a_member_carries():
    """trivy leads (the highest severity) knowing only the CVE; grype knows
    only the GHSA; osv-scanner, not the lead, knows both. One finding."""
    findings = [
        dep("t1", "trivy", "CVE-2019-10744", "lodash", "4.17.4", severity="CRITICAL"),
        dep("o1", "osv-scanner", "CVE-2019-10744", "lodash", "4.17.4", [GHSA_LODASH]),
        dep("g1", "grype", GHSA_LODASH, "lodash", "4.17.4"),
    ]
    assert membership(cluster_dependency_findings(findings)) == {
        frozenset({"t1", "o1", "g1"})
    }


def test_a_dependency_finding_never_joins_a_finding_without_one():
    """Even where the similarity measure would join them: same file and line,
    same message, same CVE in `raw` -- the premise is pinned below."""
    dependency = dep("t1", "trivy", "CVE-2019-10744", "lodash", "4.17.4")
    dependency["location"]["startLine"] = 12
    dependency["raw"] = {"VulnerabilityID": "CVE-2019-10744"}
    other = {
        "id": "s1",
        "ruleId": "CVE-2019-10744",
        "severity": "HIGH",
        "tool": {"name": "semgrep", "version": "1"},
        "location": {"path": "package-lock.json", "startLine": 12},
        "message": dependency["message"],
        "tags": ["vulnerability"],
        "raw": {"VulnerabilityID": "CVE-2019-10744"},
    }
    assert SimilarityCalculator().calculate_similarity(dependency, other) >= 0.65

    for algorithm in ("greedy", "lsh"):
        clusters = FindingClusterer(algorithm=algorithm).cluster([dependency, other])
        assert membership(clusters) == {frozenset({"t1"}), frozenset({"s1"})}, algorithm


def test_membership_does_not_depend_on_load_order():
    findings = [
        dep(
            "t1", "trivy", "CVE-2021-23337", "lodash", "4.13.1", ["GHSA-35jh-r3h4-6jhm"]
        ),
        dep(
            "t2", "trivy", "CVE-2026-4800", "lodash", "4.13.1", ["GHSA-r5fr-rjxr-66jc"]
        ),
        dep(
            "o1",
            "osv-scanner",
            "CVE-2021-23337",
            "lodash",
            "4.13.1",
            ["CVE-2026-4800", "GHSA-35jh-r3h4-6jhm", "GHSA-r5fr-rjxr-66jc"],
        ),
        dep(
            "g1", "grype", "GHSA-r5fr-rjxr-66jc", "lodash", "4.13.1", ["CVE-2026-4800"]
        ),
        dep(
            "g2", "grype", "GHSA-35jh-r3h4-6jhm", "lodash", "4.13.1", ["CVE-2021-23337"]
        ),
    ]
    seen = {
        frozenset(membership(cluster_dependency_findings(list(order))))
        for order in itertools.permutations(findings)
    }
    assert len(seen) == 1, seen


def _large_corpus() -> list[dict[str, Any]]:
    """Over LSH_THRESHOLD: 120 packages x (trivy, osv-scanner, grype), a third
    of them matched only through an alias, the same advisory in a second
    lockfile, and 150 findings of other tools, so both algorithms have work
    outside the dependency findings."""
    findings = []
    for i in range(120):
        name, version, cve, ghsa = (
            f"pkg{i}",
            f"1.{i}.0",
            f"CVE-2020-{1000 + i}",
            f"GHSA-{i:04d}-aaaa-bbbb",
        )
        lockfile = "package-lock.json" if i % 2 else "web/package-lock.json"
        # A third: trivy's CVE is neither other tool's id, only its GHSA
        # alias is (NodeGoat's lodash CVE-2026-4800 shape).
        trivy_id = cve if i % 3 else f"CVE-2026-{5000 + i}"
        findings += [
            dep(f"t{i}", "trivy", trivy_id, name, version, [ghsa], path=lockfile),
            dep(f"o{i}", "osv-scanner", cve, name, version, [ghsa], path=lockfile),
            dep(f"g{i}", "grype", ghsa, name, version, [cve], path=lockfile),
        ]
        # the same package, version and advisory in the OTHER lockfile, trivy only
        findings.append(
            dep(
                f"x{i}",
                "trivy",
                cve,
                name,
                version,
                [ghsa],
                path="web/package-lock.json" if i % 2 else "package-lock.json",
            )
        )
    for i in range(150):
        findings.append(
            {
                "id": f"c{i}",
                "ruleId": f"CKV_K8S_{i % 7}",
                "severity": "MEDIUM",
                "tool": {"name": "checkov" if i % 2 else "kubescape", "version": "1"},
                "location": {"path": f"k8s/app{i // 2}.yaml", "startLine": 10},
                "message": f"Privileged container in workload {i // 2}",
                "raw": {"CWE": "CWE-250"},
            }
        )
    return findings


def test_the_lsh_path_matches_dependency_findings_as_greedy_does():
    findings = _large_corpus()
    auto = FindingClusterer()
    assert auto._should_use_lsh(len(findings)), "the corpus must reach the LSH path"

    lsh = auto.cluster(findings)
    greedy = FindingClusterer(algorithm="greedy").cluster(findings)

    assert membership(lsh) == membership(greedy)
    dependency_clusters = [c for c in lsh if "dependency" in c.representative]
    # 120 found by all three tools, and 120 trivy findings in the other lockfile
    assert sorted(len(c.findings) for c in dependency_clusters) == [1] * 120 + [3] * 120
    for cluster in dependency_clusters:
        assert len({f["location"]["path"] for f in cluster.findings}) == 1
        assert len({f["dependency"]["version"] for f in cluster.findings}) == 1
