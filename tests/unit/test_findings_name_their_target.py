#!/usr/bin/env python3
"""Every finding names its target, and a finding in two targets is two (#1309).

A finding's id hashed the tool, the rule, the scan-root-relative path, the line
and the message, so the same file in two repositories of one scan had one id.
The report keyed deduplication on that id: the second repository's finding was
deleted, and the survivor did not say which repository it was from. The
dependency clusterer keyed on (lockfile, package, version) and made the same
mistake: two repositories with a root `package-lock.json` holding one
vulnerable package were one cluster.

The report now reads the target from where `jmo scan` put the output (the
`individual-*` folder gives the type, the subfolder the name), carries it on the
finding as `target`, and derives every id from the adapter's id and the target.

The SBOM enrichment (#1408) takes the same view: a trivy finding takes a package
from its own target's syft document only, and from a lockfile of many packages
the one it is a finding of.

Each test builds a results directory in the shape `jmo scan` writes: one
folder per target, the tool outputs in the shapes the adapters parse, the rows
in `scan-timings.json` and the run record. No scanner is needed, so these run
on every CI shard.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from scripts.cli import jmo
from scripts.core import normalize_and_report as nr
from scripts.core.common_finding import FINGERPRINT_LENGTH, target_id
from scripts.core.dedup_enhanced import (
    FindingClusterer,
    LSHClusterer,
    LSHSignatureGenerator,
    SimilarityCalculator,
    cluster_dependency_findings,
    dependency_key,
)
from scripts.core.plugin_loader import get_plugin_registry
from scripts.core.scan_timings import State, ToolRun, write_scan_timings

# --- tool outputs, in the shapes their adapters parse ----------------------------


def shellcheck_doc() -> bytes:
    """One finding in `deploy.sh`: the same bytes in every repository."""
    return json.dumps(
        [
            {
                "file": "deploy.sh",
                "line": 7,
                "endLine": 7,
                "column": 12,
                "endColumn": 16,
                "level": "warning",
                "code": 2086,
                "message": "Double quote to prevent globbing and word splitting.",
            }
        ]
    ).encode()


LODASH = ("lodash", "4.17.15")
ADVISORY = "CVE-2021-23337"
ALIAS = "GHSA-35jh-r3h4-6jhm"


def trivy_doc() -> bytes:
    """trivy's report of lodash 4.17.15 in the root `package-lock.json`."""
    name, version = LODASH
    return json.dumps(
        {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.74.0"},
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": ADVISORY,
                            "PkgID": f"{name}@{version}",
                            "PkgName": name,
                            "PkgIdentifier": {"PURL": f"pkg:npm/{name}@{version}"},
                            "InstalledVersion": version,
                            "Severity": "HIGH",
                            "Title": f"{name}: command injection",
                            "VendorIDs": [ALIAS],
                        }
                    ],
                }
            ],
        }
    ).encode()


def osv_doc(checkout: Path) -> bytes:
    """osv-scanner's SARIF of the same advisory. Its location is the lockfile's
    absolute `file://` URI on the scanning machine, as osv-scanner writes it."""
    name, version = LODASH
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "osv-scanner",
                            "version": "2.6.0",
                            "rules": [
                                {
                                    "id": ADVISORY,
                                    "name": ADVISORY,
                                    "deprecatedIds": [ADVISORY, ALIAS],
                                    "shortDescription": {"text": f"{ADVISORY}: lodash"},
                                    "properties": {"security-severity": "7.5"},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": ADVISORY,
                            "ruleIndex": 0,
                            "level": "warning",
                            "message": {
                                "text": f"Package '{name}@{version}' is vulnerable "
                                f"to '{ADVISORY}' (also known as '{ALIAS}')."
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": (
                                                checkout / "package-lock.json"
                                            ).as_uri()
                                        }
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ).encode()


def nuclei_doc(url: str) -> bytes:
    """One nuclei record, matched at `url` (the adapter's id hashes the URL)."""
    return json.dumps(
        {
            "template-id": "exposed-panel",
            "info": {"name": "Exposed panel", "severity": "medium"},
            "matched-at": url,
            "type": "http",
        }
    ).encode()


# --- a results directory in the shape `jmo scan` writes --------------------------


class Results:
    """A results directory, grown one target at a time."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.checkouts = root.parent / "checkouts"
        self.repo_paths: list[str] = []

    def checkout(self, name: str) -> Path:
        path = self.checkouts / name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def add(
        self,
        folder: str,
        name: str,
        outputs: dict[str, bytes],
        *,
        target_type: str = "repo",
        root: Path | None = None,
    ) -> Path:
        """One target: its tool outputs and the rows `jmo scan` records."""
        out = self.root / folder / name
        out.mkdir(parents=True, exist_ok=True)
        rows = {}
        for filename, data in outputs.items():
            (out / filename).write_bytes(data)
            tool = filename.split(".", 1)[0]
            rows[tool] = ToolRun(tool, State.RAN)
        write_scan_timings(
            out,
            rows,
            target=name,
            target_type=target_type,
            wall_seconds=1.0,
            root=str(root) if root else None,
        )
        if root:
            self.repo_paths.append(str(root))
        (self.root / ".scan_metadata.json").write_bytes(
            json.dumps({"tools": sorted(rows), "repo_paths": self.repo_paths}).encode()
        )
        return out

    def run(self) -> SimpleNamespace:
        """`jmo report` over this directory, as `jmo scan` drives it, and what
        a user reads afterwards."""
        argv = ["jmo", "report", "--results-dir", str(self.root)]
        with patch.object(sys, "argv", argv):
            args = jmo.parse_args()
        code = jmo.cmd_report(args)
        summaries = self.root / "summaries"
        document = json.loads((summaries / "findings.json").read_bytes())
        sarif = json.loads((summaries / "findings.sarif").read_bytes())
        with open(summaries / "findings.csv", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        return SimpleNamespace(
            code=code, findings=document["findings"], sarif=sarif, csv=rows
        )


@pytest.fixture
def scan(tmp_path: Path, monkeypatch):
    """An empty results directory, with `jmo report` set up to read it."""
    (tmp_path / "jmo.yml").write_bytes(b"outputs: [json, sarif, csv]\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    # EPSS/KEV lookups would reach the network; priority is not under test.
    monkeypatch.setattr(nr, "_enrich_with_priority", lambda findings: None)
    return Results(tmp_path / "results")


def adapter_findings(folder: Path, adapter: str, filename: str) -> list[dict[str, Any]]:
    """What the tool's adapter itself makes of an output: the finding before the
    report phase has touched its path or its id."""
    plugin = get_plugin_registry().get(adapter)
    assert plugin is not None, adapter
    return [f.to_dict() for f in plugin().parse(folder / filename)]


def named(finding: dict[str, Any]) -> tuple[str, str]:
    return finding["target"]["type"], finding["target"]["name"]


def detected_by(finding: dict[str, Any]) -> tuple[str, ...]:
    reporters = finding.get("detected_by") or [finding["tool"]]
    return tuple(sorted(r["name"] for r in reporters))


# --- the report -----------------------------------------------------------------


def test_the_same_finding_in_two_repositories_is_two_findings(scan):
    """The shape of #1309: an identical `deploy.sh` finding in two repositories.
    Dedup keyed on an id built from the relative path, kept the first and
    deleted the second, and the survivor named neither."""
    for repo in ("app-one", "app-two"):
        scan.add(
            "individual-repos",
            repo,
            {"shellcheck.json": shellcheck_doc()},
            root=scan.checkout(repo),
        )

    done = scan.run()

    assert done.code == 0
    assert len(done.findings) == 2, "the second repository's finding was deleted"
    assert sorted(named(f) for f in done.findings) == [
        ("repo", "app-one"),
        ("repo", "app-two"),
    ]
    assert len({f["id"] for f in done.findings}) == 2
    # The paths keep their shape: the repository is a field, not a prefix.
    assert [f["location"]["path"] for f in done.findings] == ["deploy.sh"] * 2


def test_a_lockfile_in_two_repositories_is_one_cluster_each(scan):
    """trivy and osv-scanner report lodash 4.17.15 in each repository's root
    lockfile. Two repositories are two clusters, each of the two tools."""
    for repo in ("app-one", "app-two"):
        checkout = scan.checkout(repo)
        scan.add(
            "individual-repos",
            repo,
            {"trivy.json": trivy_doc(), "osv-scanner.json": osv_doc(checkout)},
            root=checkout,
        )

    done = scan.run()

    assert len(done.findings) == 2, "the two repositories' lockfiles became one cluster"
    assert sorted((named(f), detected_by(f)) for f in done.findings) == [
        (("repo", "app-one"), ("osv-scanner", "trivy")),
        (("repo", "app-two"), ("osv-scanner", "trivy")),
    ]
    assert {f["location"]["path"] for f in done.findings} == {"package-lock.json"}


def test_a_single_target_keeps_its_paths_and_gains_only_a_target(scan):
    """With one target nothing is merged or split. Every `location` is the
    adapter's own, byte for byte, and every id is the adapter's id with the
    target joined to it: no other input to the id changed."""
    checkout = scan.checkout("app-one")
    out = scan.add(
        "individual-repos",
        "app-one",
        {"shellcheck.json": shellcheck_doc(), "osv-scanner.json": osv_doc(checkout)},
        root=checkout,
    )
    adapted = adapter_findings(out, "shellcheck", "shellcheck.json") + adapter_findings(
        out, "osv_scanner", "osv-scanner.json"
    )

    done = scan.run()

    assert len(done.findings) == len(adapted) == 2
    by_tool = {f["tool"]["name"]: f for f in done.findings}
    shellcheck = next(f for f in adapted if f["tool"]["name"] == "shellcheck")
    assert by_tool["shellcheck"]["location"] == shellcheck["location"]
    assert by_tool["shellcheck"]["id"] == target_id(shellcheck["id"], "repo", "app-one")
    assert by_tool["shellcheck"]["id"] != shellcheck["id"]
    # osv-scanner wrote an absolute path; the report phase makes it relative
    # to the scan root, as it did before the target existed.
    assert by_tool["osv-scanner"]["location"]["path"] == "package-lock.json"


def test_an_id_does_not_depend_on_where_the_checkout_is(scan, tmp_path):
    """osv-scanner writes the lockfile's absolute path, and its adapter hashes
    it. The report makes the path relative and re-keys the id from it before
    the id is scoped to the target, so the same repository scanned from two
    directories has the same ids: a directory's name is part of an id, and its
    parents are not."""
    elsewhere = Results(tmp_path / "elsewhere" / "results")
    ids = []
    for results in (scan, elsewhere):
        checkout = results.checkout("app-one")
        results.add(
            "individual-repos",
            "app-one",
            {"osv-scanner.json": osv_doc(checkout)},
            root=checkout,
        )
        ids.append({f["id"] for f in results.run().findings})

    assert checkout.parent != scan.checkout("app-one").parent
    assert ids[0] == ids[1] != set()


@pytest.mark.parametrize(
    ("folder", "target_type"),
    [
        ("individual-repos", "repo"),
        ("individual-images", "image"),
        ("individual-iac", "iac"),
        ("individual-web", "url"),
        ("individual-gitlab", "gitlab"),
        ("individual-k8s", "k8s"),
    ],
)
def test_the_target_type_is_the_scan_codes_for_its_folder(scan, folder, target_type):
    """`jmo scan` names the six kinds of target `repo`, `image`, `iac`, `url`,
    `gitlab` and `k8s` (`scan_orchestrator.py`); the report reads the same
    word from the folder the output is in."""
    scan.add(folder, "thing", {"shellcheck.json": shellcheck_doc()})

    (finding,) = scan.run().findings

    assert finding["target"] == {"type": target_type, "name": "thing"}


def test_a_finding_whose_id_is_not_its_path_is_still_scoped_to_its_target(scan):
    """nuclei hashes the matched URL, not `location.path`, and the report
    cannot recompute its id from the finding's fields. The id is derived from
    the adapter's own, so it works for any adapter."""
    for site in ("one.example", "two.example"):
        scan.add(
            "individual-web",
            site,
            {"nuclei.json": nuclei_doc("https://shop.example/admin")},
            target_type="url",
        )

    done = scan.run()

    assert len(done.findings) == 2
    assert sorted(named(f) for f in done.findings) == [
        ("url", "one.example"),
        ("url", "two.example"),
    ]
    assert len({f["id"] for f in done.findings}) == 2


def test_the_sarif_result_names_its_target_and_keeps_its_uri(scan):
    """`artifactLocation.uri` is a path in the repository, not a path in the
    scan: the target goes in the result's `properties`."""
    for repo in ("app-one", "app-two"):
        scan.add("individual-repos", repo, {"shellcheck.json": shellcheck_doc()})

    results = scan.run().sarif["runs"][0]["results"]

    assert sorted(r["properties"]["target"]["name"] for r in results) == [
        "app-one",
        "app-two",
    ]
    assert {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in results
    } == {"deploy.sh"}


def test_the_csv_has_a_target_column(scan):
    for repo in ("app-one", "app-two"):
        scan.add("individual-repos", repo, {"shellcheck.json": shellcheck_doc()})

    rows = scan.run().csv

    assert sorted(r["target"] for r in rows) == ["app-one", "app-two"]
    assert {r["path"] for r in rows} == {"deploy.sh"}


def test_the_schema_describes_the_target(scan):
    """`docs/schemas/common_finding.v1.json` is the contract `jmo validate`
    checks findings against."""
    from scripts.core.schema_validator import load_schema, validate_finding

    scan.add("individual-repos", "app-one", {"shellcheck.json": shellcheck_doc()})

    (finding,) = scan.run().findings

    schema = load_schema()
    assert "target" in schema["properties"]
    assert validate_finding(finding, schema) == []
    broken = {**finding, "target": {"type": "repo"}}
    assert validate_finding(broken, schema) != []


# --- the id ---------------------------------------------------------------------


def test_the_id_is_the_adapters_id_joined_to_the_target():
    adapter_id = "0123456789abcdef"
    derived = target_id(adapter_id, "repo", "app-one")

    assert re.fullmatch(f"[0-9a-f]{{{FINGERPRINT_LENGTH}}}", derived)
    assert derived == target_id(adapter_id, "repo", "app-one")
    # Each input matters. A renamed checkout is a new target, so every id in it
    # changes (UPGRADE.md says so).
    assert target_id(adapter_id, "repo", "app-two") != derived
    assert target_id(adapter_id, "image", "app-one") != derived
    assert target_id("fedcba9876543210", "repo", "app-one") != derived
    assert derived != adapter_id


# --- the dependency clusterer ---------------------------------------------------


def dep(
    fid: str, tool: str, target: str | None, version: str = "4.17.15"
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": fid,
        "ruleId": ADVISORY,
        "severity": "HIGH",
        "tool": {"name": tool, "version": "1"},
        "location": {"path": "package-lock.json"},
        "message": f"lodash {ADVISORY}",
        "dependency": {"name": "lodash", "version": version, "aliases": [ALIAS]},
    }
    if target is not None:
        finding["target"] = {"type": "repo", "name": target}
    return finding


def membership(clusters) -> set[frozenset[str]]:
    return {frozenset(f["id"] for f in c.findings) for c in clusters}


def test_two_targets_lockfiles_are_two_dependency_keys():
    """Same lockfile path, package and version; the key still tells them apart."""
    assert dependency_key(dep("a", "trivy", "app-one")) != dependency_key(
        dep("b", "trivy", "app-two")
    )
    assert dependency_key(dep("a", "trivy", "app-one")) == dependency_key(
        dep("b", "osv-scanner", "app-one")
    )


def test_a_dependency_finding_without_a_target_is_still_a_dependency():
    """The clusterer is a public API, and findings built without the report
    phase carry no target."""
    assert dependency_key(dep("a", "trivy", None)) is not None


def test_dependency_findings_cluster_within_their_target_only():
    """Sorted by tool then id, app-two's osv-scanner finding (`o-1`) and app-one's
    trivy finding (`t-1`) come first of their tools. Without the target in the
    key, one-per-tool pairing joins them across the two repositories."""
    findings = [
        dep("t-1", "trivy", "app-one"),
        dep("o-2", "osv-scanner", "app-one"),
        dep("t-2", "trivy", "app-two"),
        dep("o-1", "osv-scanner", "app-two"),
    ]

    assert membership(cluster_dependency_findings(findings)) == {
        frozenset({"t-1", "o-2"}),
        frozenset({"t-2", "o-1"}),
    }


# --- the similarity clusterer ---------------------------------------------------


def misconfig(
    fid: str, tool: str, target: str | None, path: str = "Dockerfile"
) -> dict[str, Any]:
    """One tool's finding of the rule at line 1. Two tools' findings of it in
    one place are one consensus finding, as they have always been."""
    finding: dict[str, Any] = {
        "id": fid,
        "ruleId": "DS002",
        "severity": "HIGH",
        "tool": {"name": tool, "version": "1"},
        "location": {"path": path, "startLine": 1},
        "message": "Image user should not be root",
    }
    if target is not None:
        finding["target"] = {"type": "repo", "name": target}
    return finding


ALGORITHMS = pytest.mark.parametrize("algorithm", ["greedy", "lsh"])


@ALGORITHMS
def test_two_tools_findings_in_two_targets_are_two_clusters(algorithm):
    """The #1309 flaw in the similarity clusterer: trivy's finding in app-one
    and checkov's at the same rule, path and line in app-two were ONE cluster,
    naming one repository. The location term is the path as relative to its
    target, so it cannot tell the targets apart."""
    findings = [
        misconfig("a1", "trivy", "app-one"),
        misconfig("b1", "checkov", "app-two"),
    ]

    clusters = FindingClusterer(algorithm=algorithm).cluster(findings)

    assert sorted(
        (c.representative["target"]["name"], [f["id"] for f in c.findings])
        for c in clusters
    ) == [("app-one", ["a1"]), ("app-two", ["b1"])]


@ALGORITHMS
def test_each_target_clusters_its_own_tools_findings(algorithm):
    """Both tools in both targets: each target's pair is its own cluster, and
    never a cross-target pairing (app-two's checkov sorts ahead of app-one's)."""
    findings = [
        misconfig("t-1", "trivy", "app-one"),
        misconfig("c-2", "checkov", "app-one"),
        misconfig("t-2", "trivy", "app-two"),
        misconfig("c-1", "checkov", "app-two"),
    ]

    clusters = FindingClusterer(algorithm=algorithm).cluster(findings)

    assert membership(clusters) == {
        frozenset({"t-1", "c-2"}),
        frozenset({"t-2", "c-1"}),
    }


@ALGORITHMS
@pytest.mark.parametrize("target", ["app-one", None], ids=["one-target", "no-target"])
def test_two_tools_findings_in_one_place_still_cluster(algorithm, target):
    """The control: the same pair in one target is one cluster, as before the
    guard. So is a pair built without the report phase, which carries no target
    (the clusterer is a public API)."""
    findings = [
        misconfig("a1", "trivy", target),
        misconfig("b1", "checkov", target),
    ]

    clusters = FindingClusterer(algorithm=algorithm).cluster(findings)

    assert membership(clusters) == {frozenset({"a1", "b1"})}


def test_findings_of_two_targets_have_no_similarity():
    calculator = SimilarityCalculator()
    same = calculator.calculate_similarity(
        misconfig("a1", "trivy", "app-one"), misconfig("b1", "checkov", "app-one")
    )
    apart = calculator.calculate_similarity(
        misconfig("a1", "trivy", "app-one"), misconfig("b1", "checkov", "app-two")
    )

    assert same >= calculator.threshold
    assert apart == 0.0


def one_pair_per_target(count: int) -> list[dict[str, Any]]:
    """trivy's and checkov's finding of one rule at one place, in each of
    `count` targets: what a large `--repos-dir` scan holds for a Dockerfile
    every repository copied."""
    return [
        misconfig(f"{tool}-{n}", tool, f"app-{n:03}")
        for n in range(count)
        for tool in ("trivy", "checkov")
    ]


@pytest.mark.parametrize(
    ("algorithm", "targets"),
    [("lsh", 60), ("auto", 250)],
    ids=["lsh-60-targets", "auto-250-targets"],
)
def test_a_large_scan_still_clusters_within_each_target(
    algorithm, targets, monkeypatch
):
    """LSH skips a bucket of more than `MAX_BUCKET_SIZE` entries, and every
    target's pair lands in the same buckets (the path and line are relative to
    the target). Before the target was in the bucket, each target added its own
    entries: at 51 targets the bucket passed 100 and the pairs of ALL targets
    went unmerged (measured: 51 targets, 102 clusters; greedy, 51). `auto`
    selects LSH from 500 findings."""
    findings = one_pair_per_target(targets)

    # The test must be able to see the cap: unscoped, one band holds every
    # finding, and that is more than LSH will compare.
    generator = LSHSignatureGenerator()
    buckets: dict[str, int] = {}
    for finding in findings:
        for signature in generator.generate_signatures(finding):
            buckets[signature] = buckets.get(signature, 0) + 1
    assert max(buckets.values()) > LSHClusterer.MAX_BUCKET_SIZE

    # ... and must really go through LSH.
    used = []
    original = LSHClusterer.cluster

    def spy(self, *args, **kwargs):
        used.append(len(args[0]))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(LSHClusterer, "cluster", spy)

    clusters = FindingClusterer(algorithm=algorithm).cluster(findings)

    assert used == [len(findings)]
    assert membership(clusters) == {
        frozenset({f"trivy-{n}", f"checkov-{n}"}) for n in range(targets)
    }
    assert {c.representative["target"]["name"] for c in clusters} == {
        f"app-{n:03}" for n in range(targets)
    }


# --- the SBOM enrichment (#1408) --------------------------------------------------


def syft_doc(packages: list[tuple[str, str, str]], image: str | None = None) -> bytes:
    """syft's document of `packages` ((name, version, path) each, npm packages
    unless `image` is given, then apk). `image` is `name:version`, as syft's
    `source` names the image it catalogued."""
    document: dict[str, Any] = {
        "artifacts": [
            {
                "id": f"pkg-{n}",
                "name": name,
                "version": version,
                "type": "apk" if image else "npm",
                "locations": [{"path": path}],
            }
            for n, (name, version, path) in enumerate(packages)
        ],
        "artifactRelationships": [],
    }
    if image:
        source, version = image.split(":")
        document["source"] = {"type": "image", "name": source, "version": version}
    return json.dumps(document).encode()


APK_DB = "/lib/apk/db/installed"


def trivy_openssl_doc() -> bytes:
    """trivy's report of openssl 3.0.0 in an image's operating-system packages."""
    return json.dumps(
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "nginx:1.27 (alpine 3.20)",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-0001",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.0",
                            "Severity": "HIGH",
                            "Title": "openssl: flaw",
                        }
                    ],
                }
            ],
        }
    ).encode()


def of_tool(done: SimpleNamespace, tool: str) -> list[dict[str, Any]]:
    return [f for f in done.findings if f["tool"]["name"] == tool]


def sbom_package(finding: dict[str, Any]) -> tuple[str, str] | None:
    """The (name, version) of the SBOM package the report attached, if any."""
    sbom = (finding.get("context") or {}).get("sbom")
    return (sbom["name"], sbom["version"]) if sbom else None


def package_tags(finding: dict[str, Any]) -> list[str]:
    return [t for t in finding.get("tags", []) if t.startswith("pkg:")]


def test_one_package_in_two_images_is_two_findings(scan):
    """#1408 as filed: two syft documents identical but for `source.name`. The
    package's path is inside the image, so it is the same in both. A3's id is
    scoped to the target, so each image has its own finding; this guards that
    for images (it passed when written)."""
    for folder, image in (("alpine_3.19", "alpine:3.19"), ("nginx_1.27", "nginx:1.27")):
        scan.add(
            "individual-images",
            folder,
            {"syft.json": syft_doc([("openssl", "3.1.0", APK_DB)], image=image)},
            target_type="image",
        )

    done = scan.run()

    assert sorted(named(f) for f in done.findings) == [
        ("image", "alpine_3.19"),
        ("image", "nginx_1.27"),
    ]
    assert len({f["id"] for f in done.findings}) == 2


OPENSSL = ("openssl", "3.1.0", APK_DB)
ZLIB = ("zlib", "1.3", APK_DB)


@pytest.mark.parametrize(
    ("outputs", "titles"),
    [
        (
            {"syft.json": syft_doc([OPENSSL] * 2, image="nginx:1.27")},
            ["openssl 3.1.0"],
        ),
        # The second file also lists zlib, so a second file that was never read
        # would show: there would be no zlib finding.
        (
            {
                "syft.json": syft_doc([OPENSSL], image="nginx:1.27"),
                "syft.again.json": syft_doc([OPENSSL, ZLIB], image="nginx:1.27"),
            },
            ["openssl 3.1.0", "zlib 1.3"],
        ),
    ],
    ids=["listed-twice", "read-twice"],
)
def test_one_package_in_one_image_is_one_finding_however_often_syft_says_it(
    scan, outputs, titles
):
    """The other half of the id guard: the same package in the same image,
    listed twice in one document or read from two, is one finding, not two."""
    scan.add("individual-images", "nginx_1.27", outputs, target_type="image")

    done = scan.run()

    assert sorted(f["title"] for f in done.findings) == titles
    assert {named(f) for f in done.findings} == {("image", "nginx_1.27")}


@pytest.mark.parametrize("trivy_in", ["alpine_3.19", "nginx_1.27"])
def test_trivy_takes_the_package_of_its_own_image(scan, trivy_in):
    """Both images hold an openssl at the same path in the apk database, at
    different versions. trivy's finding is in one of them and takes that image's
    package; the SBOM index had no target, so it took the first image's (a
    finding in nginx_1.27 was tagged with alpine_3.19's openssl 3.1.0)."""
    versions = {"alpine_3.19": "3.1.0", "nginx_1.27": "3.0.0"}
    for folder, version in versions.items():
        image = folder.replace("_", ":")
        outputs = {"syft.json": syft_doc([("openssl", version, APK_DB)], image=image)}
        if folder == trivy_in:
            outputs["trivy.json"] = trivy_openssl_doc()
        scan.add("individual-images", folder, outputs, target_type="image")

    (trivy,) = of_tool(scan.run(), "trivy")

    assert named(trivy) == ("image", trivy_in)
    assert sbom_package(trivy) == ("openssl", versions[trivy_in])
    assert package_tags(trivy) == [f"pkg:openssl@{versions[trivy_in]}"]


def test_trivy_takes_no_package_from_an_image_that_is_not_its_own(scan):
    """trivy scanned nginx_1.27; syft catalogued only alpine_3.19, which holds an
    openssl. The finding has no SBOM package of its own, so it gets none."""
    scan.add(
        "individual-images",
        "alpine_3.19",
        {"syft.json": syft_doc([("openssl", "3.1.0", APK_DB)], image="alpine:3.19")},
        target_type="image",
    )
    scan.add(
        "individual-images",
        "nginx_1.27",
        {"trivy.json": trivy_openssl_doc()},
        target_type="image",
    )

    (trivy,) = of_tool(scan.run(), "trivy")

    assert named(trivy) == ("image", "nginx_1.27")
    assert sbom_package(trivy) is None
    assert package_tags(trivy) == []


LOCKFILE_PACKAGES = [("axios", "0.21.0"), ("lodash", "4.17.15")]


@pytest.mark.parametrize("order", [1, -1], ids=["axios-first", "lodash-first"])
def test_trivy_takes_its_own_package_from_a_lockfile_of_many(scan, order):
    """syft lists every package of a lockfile at the lockfile's path. trivy's
    finding is of lodash; matching by path alone gave it the first package
    listed there, so with axios first the finding was tagged `pkg:axios@0.21.0`."""
    packages = [(n, v, "/package-lock.json") for n, v in LOCKFILE_PACKAGES][::order]
    scan.add(
        "individual-repos",
        "app-one",
        {"syft.json": syft_doc(packages), "trivy.json": trivy_doc()},
    )

    (trivy,) = of_tool(scan.run(), "trivy")

    assert trivy["location"]["path"] == "package-lock.json"
    assert sbom_package(trivy) == LODASH
    assert package_tags(trivy) == ["pkg:lodash@4.17.15"]


def test_a_package_the_lockfile_does_not_list_is_not_given_another(scan):
    """trivy found lodash; syft's lockfile lists only axios. The path matches
    and the name does not, so there is no SBOM package to attach."""
    scan.add(
        "individual-repos",
        "app-one",
        {
            "syft.json": syft_doc([("axios", "0.21.0", "/package-lock.json")]),
            "trivy.json": trivy_doc(),
        },
    )

    (trivy,) = of_tool(scan.run(), "trivy")

    assert sbom_package(trivy) is None
    assert package_tags(trivy) == []


def sbom_pair(
    syft_target: dict[str, str] | None, trivy_target: dict[str, str] | None
) -> dict[str, Any]:
    """A syft package and a trivy finding of it, each with the target given
    (None: the finding carries no `target` key, as one built outside `jmo scan`)."""
    syft = {
        "id": "s1",
        "tool": {"name": "syft"},
        "tags": ["sbom", "package"],
        "raw": {"name": "lodash", "version": "4.17.15"},
        "location": {"path": "package-lock.json"},
    }
    trivy = {
        "id": "t1",
        "tool": {"name": "trivy"},
        "tags": [],
        "raw": {"PkgName": "lodash"},
        "location": {"path": "package-lock.json"},
    }
    if syft_target:
        syft["target"] = syft_target
    if trivy_target:
        trivy["target"] = trivy_target
    return {"syft": syft, "trivy": trivy}


def test_findings_with_no_target_still_match_each_other():
    """A results directory `jmo scan` did not write, or a caller of the report's
    public functions, has findings with no `target`. They are one group."""
    pair = sbom_pair(None, None)

    nr._enrich_trivy_with_syft([pair["syft"], pair["trivy"]])

    assert sbom_package(pair["trivy"]) == LODASH
    assert package_tags(pair["trivy"]) == ["pkg:lodash@4.17.15"]


@pytest.mark.parametrize(
    ("syft_target", "trivy_target"),
    [
        ({"type": "repo", "name": "app-one"}, None),
        (None, {"type": "repo", "name": "app-one"}),
    ],
    ids=["syft-names-one", "trivy-names-one"],
)
def test_a_finding_with_no_target_does_not_match_a_named_target(
    syft_target, trivy_target
):
    """No target is not every target: a finding without one takes nothing from
    a package that names its target, and the reverse."""
    pair = sbom_pair(syft_target, trivy_target)

    nr._enrich_trivy_with_syft([pair["syft"], pair["trivy"]])

    assert sbom_package(pair["trivy"]) is None


def test_a_package_in_two_lockfiles_takes_the_one_at_the_findings_path():
    """lodash is in two lockfiles of one repository, the one the finding is in
    listed second, and spelled `Lodash` there. The path picks the package, and
    comparing names at it is case-insensitive: a name that fails the comparison
    falls back to the first package of that name, in the other lockfile."""
    pair = sbom_pair(None, None)
    pair["syft"]["raw"] = {"name": "Lodash", "version": "4.17.15"}
    elsewhere = {
        **pair["syft"],
        "id": "s0",
        "raw": {"name": "lodash", "version": "4.17.11"},
        "location": {"path": "docs/package-lock.json"},
    }

    nr._enrich_trivy_with_syft([elsewhere, pair["syft"], pair["trivy"]])

    assert sbom_package(pair["trivy"]) == ("Lodash", "4.17.15")


def test_a_repositorys_ids_are_the_same_as_before_the_enrichment_was_scoped(scan):
    """A5 changed which SBOM package a finding takes, and nothing about its id.
    The ids of one repository's packages, measured before the change (the
    adapter's fingerprint scoped to the target by A3), pinned so that scoping
    the enrichment cannot move them."""
    scan.add(
        "individual-repos",
        "app-one",
        {
            "syft.json": syft_doc(
                [(n, v, "/package-lock.json") for n, v in LOCKFILE_PACKAGES]
            )
        },
    )

    done = scan.run()

    assert {f["title"]: f["id"] for f in done.findings} == {
        "axios 0.21.0": "93817962fb756f90",
        "lodash 4.17.15": "5f8a409eda8a6ea2",
    }
