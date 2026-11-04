"""A finding's compliance category comes from what it is, not only its tool (#1370).

trivy reports vulnerabilities, misconfigurations and secrets, and every one of
them used to be filed under supply chain (`sca`), because the tool name decided
first. The categories choose the CIS, NIST, PCI and MITRE entries a finding
carries, so a leaked token and a writable root filesystem were reported as
dependency risks.

The trivy document is trivy 0.74.0's own output: one result each from
`tests/fixtures/samples/trivy/vuln-0.74.json` and `misconfig-0.74.json`, and
`github-pat-0.74.json`, captured 2026-11-04 with
`trivy fs -q -f json --scanners secret .` on a file holding one generated
GitHub token (trivy masks the match, so the file holds no token; `.gitignore`
skips any file named `*secret*`).
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.core.compliance_mapper import (
    CIS_CONTROLS_V8_1,
    COMPLIANCE_ENTRY_KEYS,
    CWE_TO_MITRE_ATTACK,
    CWE_TO_NIST_CSF_2_0,
    CWE_TO_PCI_DSS_4_0,
    MITRE_ATTACK,
    NIST_CSF_2_0,
    PCI_DSS_4_0,
)
from scripts.core.normalize_and_report import gather_results

TRIVY = Path(__file__).resolve().parents[1] / "fixtures" / "samples" / "trivy"
GOLDEN_ZIZMOR = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "golden"
    / "zizmor"
    / "v1.30.1"
    / "raw-output.json"
)


def _first_result_holding(name: str, key: str) -> dict:
    document = json.loads((TRIVY / name).read_text(encoding="utf-8"))
    result = next(r for r in document["Results"] if r.get(key))
    return {**result, key: result[key][:1]}


def _gathered(tmp_path: Path, outputs: dict[str, object]) -> list[dict]:
    target = tmp_path / "results" / "individual-repos" / "repo"
    target.mkdir(parents=True)
    for name, document in outputs.items():
        (target / name).write_bytes(json.dumps(document).encode("utf-8"))
    return gather_results(tmp_path / "results")


def _category(finding: dict) -> str | None:
    """The category whose CIS entries the finding carries, or None for none."""
    carried = (finding.get("compliance") or {}).get("cisControlsV8_1")
    names = [name for name, entries in CIS_CONTROLS_V8_1.items() if entries == carried]
    assert len(names) <= 1, names
    return names[0] if names else None


def test_trivy_files_each_finding_by_what_it_is(tmp_path: Path):
    document = json.loads((TRIVY / "vuln-0.74.json").read_text(encoding="utf-8"))
    document["Results"] = [
        _first_result_holding("vuln-0.74.json", "Vulnerabilities"),
        _first_result_holding("misconfig-0.74.json", "Misconfigurations"),
        _first_result_holding("github-pat-0.74.json", "Secrets"),
    ]

    findings = _gathered(tmp_path, {"trivy.json": document})

    assert {f["tags"][0]: _category(f) for f in findings} == {
        "vulnerability": "sca",
        "misconfig": "iac",
        "secret": "secrets",
    }


def test_shellcheck_and_zizmor_findings_have_a_category(tmp_path: Path):
    """Both used to get none, so they carried no CIS, NIST or PCI entry."""
    shellcheck = [  # one comment, as shellcheck 0.11 prints it with --format=json
        {
            "file": "vulnerable_script.sh",
            "line": 9,
            "endLine": 9,
            "column": 5,
            "endColumn": 14,
            "level": "info",
            "code": 2086,
            "message": "Double quote to prevent globbing and word splitting.",
        }
    ]
    zizmor = json.loads(GOLDEN_ZIZMOR.read_text(encoding="utf-8"))

    findings = _gathered(
        tmp_path, {"shellcheck.json": shellcheck, "zizmor.json": zizmor}
    )

    categories = {(f["tool"]["name"], _category(f)) for f in findings}
    assert categories == {("shellcheck", "sast"), ("zizmor", "iac")}


def test_every_compliance_key_has_one_wording():
    """A finding keeps the first entry per key (`first_entry_per_key`), so two
    wordings of one key meant two findings of one control read differently,
    depending on which table matched first."""
    tables = {
        "nistCsf2_0": (NIST_CSF_2_0, CWE_TO_NIST_CSF_2_0),
        "pciDss4_0": (PCI_DSS_4_0, CWE_TO_PCI_DSS_4_0),
        "mitreAttack": (MITRE_ATTACK, CWE_TO_MITRE_ATTACK),
    }
    two_wordings = {}
    for framework, (by_category, by_cwe) in tables.items():
        key = COMPLIANCE_ENTRY_KEYS[framework]
        wordings: dict[str, set[str]] = {}
        for entries in [*by_category.values(), *by_cwe.values()]:
            for entry in entries:
                wordings.setdefault(entry[key], set()).add(
                    json.dumps(entry, sort_keys=True)
                )
        two_wordings.update(
            {f"{framework} {k}": len(v) for k, v in wordings.items() if len(v) > 1}
        )

    assert two_wordings == {}
