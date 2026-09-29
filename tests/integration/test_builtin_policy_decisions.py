#!/usr/bin/env python3
"""Every builtin policy, against a known violation and a known clean input.

This is chunk 16's acceptance criterion, executable:

    Every policy decision is exercised against BOTH a findings file known to
    contain a violation and one known not to, so a PASS proves the rule fired
    rather than that the input was empty -- and the exit code, the human output
    and the machine-readable artifact are each checked, not just whichever one
    is convenient.

The violating input is built by running **real tool records through the real
adapters** and then the **real compliance enricher**. It is deliberately never
hand-written: a hand-authored finding is written to match whatever the policy
reads, so it confirms any field name at all. That is not hypothetical --
``test_policy_evaluation_with_violations_performance`` supplied
``raw: {"verified": True}``, a shape no adapter produces, and would have passed
against a ``zero-secrets`` policy that could not fire.

Two shipped policies were structurally inert when this file was written:

* ``zero-secrets`` PASSED on a findings file whose only entry was a verified
  AWS key -- it read ``raw.verified`` where TruffleHog writes ``Verified``.
* ``hipaa-compliance`` PASSED on every possible input -- its
  ``sprintf("CWE-%d", ...)`` against an array of strings matched nothing.

These tests need a real OPA binary and are skipped without one. **No CI job
installs OPA** (measured 2026-08-20: no workflow references it), so this file is
a maintainer-machine gate, not a CI gate. The structural half that does run
everywhere is ``tests/unit/test_policy_field_contract.py``.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from scripts.cli import jmo
from scripts.cli.policy_commands import cmd_policy_test
from scripts.core.adapters.nuclei_adapter import NucleiAdapter
from scripts.core.adapters.semgrep_adapter import SemgrepAdapter
from scripts.core.adapters.trufflehog_adapter import TruffleHogAdapter
from scripts.core.compliance_mapper import enrich_findings_with_compliance
from scripts.core.reporters.policy_reporter import (
    evaluate_policies,
    write_policy_report,
)
from scripts.core.tool_utils import find_tool

BUILTIN_DIR = Path(__file__).parent.parent.parent / "policies" / "builtin"
USER_DIR = Path.home() / ".jmo" / "policies"

POLICIES = [
    "hipaa-compliance",
    "owasp-top-10",
    "pci-dss",
    "production-hardening",
    "zero-secrets",
]

# `requires_tools` alongside the skipif, not instead of it. These tests shell
# out to a real `opa eval` against real .rego policies -- running the real
# binary is the point -- and the marker is what declares that. The skipif alone
# left the dependency undeclared: the tests ran here and skipped on CI, which is
# machine-dependent behaviour with nothing saying so. Invisible until the spawn
# recorder stopped watching only semgrep (#994). The marker also means the
# tool-contract job, which installs the tools, now runs them instead of
# skipping them.
pytestmark = [
    pytest.mark.requires_tools,
    pytest.mark.skipif(
        find_tool("opa") is None,
        reason="OPA binary not found (PATH or ~/.jmo/bin)",
    ),
]


def _adapter_findings(records: dict[str, Any]) -> list[dict[str, Any]]:
    """Run real tool records through their real adapters, then enrich."""
    out: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        if "trufflehog" in records:
            p = tmp / "trufflehog.json"
            p.write_bytes(
                ("\n".join(json.dumps(r) for r in records["trufflehog"]) + "\n").encode(
                    "utf-8"
                )
            )
            out += [f.to_dict() for f in TruffleHogAdapter().parse(p)]
        if "semgrep" in records:
            p = tmp / "semgrep.json"
            p.write_bytes(
                json.dumps({"results": records["semgrep"], "errors": []}).encode(
                    "utf-8"
                )
            )
            out += [f.to_dict() for f in SemgrepAdapter().parse(p)]
        if "nuclei" in records:
            p = tmp / "nuclei.json"
            p.write_bytes(
                ("\n".join(json.dumps(r) for r in records["nuclei"]) + "\n").encode(
                    "utf-8"
                )
            )
            out += [f.to_dict() for f in NucleiAdapter().parse(p)]
    return enrich_findings_with_compliance(out)


@pytest.fixture(scope="module")
def violating_findings() -> list[dict[str, Any]]:
    """Findings that every one of the five policies must reject.

    One verified AWS secret (HIGH) and one XSS (HIGH, CWE-79). Between them
    they carry every signal the five policies gate on: the ``verified`` tag and
    ``raw.Verified`` for zero-secrets, HIGH severity for production-hardening,
    an OWASP mapping for owasp-top-10, PCI requirement 6.2.4 -- which is in
    ``critical_requirements`` -- for pci-dss, and CWE-79 for hipaa-compliance.
    """
    findings = _adapter_findings(
        {
            "trufflehog": [
                {
                    "SourceMetadata": {
                        "Data": {"Filesystem": {"file": "config/prod.env"}}
                    },
                    "DetectorName": "AWS",
                    "Verified": True,
                    "Raw": "AKIAIOSFODNN7EXAMPLE",
                    "StartLine": 3,
                }
            ],
            "semgrep": [
                {
                    "check_id": "javascript.browser.security.insecure-document-method",
                    "path": "web/app.js",
                    "start": {"line": 12},
                    "end": {"line": 12},
                    "extra": {
                        "message": "User controlled data in innerHTML",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": [
                                "CWE-79: Improper Neutralization of Input During "
                                "Web Page Generation"
                            ],
                            "owasp": ["A03:2021 - Injection"],
                        },
                    },
                }
            ],
        }
    )
    # Guard the fixture, not just the assertions built on it. An asymmetric,
    # verified fixture is load-bearing here: if the adapter stops setting the
    # verified tag, every "policy correctly FAILED" below would still pass for
    # the wrong reason.
    assert len(findings) == 2, f"fixture built {len(findings)} findings, expected 2"
    th = next(f for f in findings if f["tool"]["name"] == "trufflehog")
    assert "verified" in th["tags"], th["tags"]
    assert th["raw"]["Verified"] is True
    assert th["severity"] == "HIGH"
    sg = next(f for f in findings if f["tool"]["name"] == "semgrep")
    assert "CWE-79" in str(sg["risk"]["cwe"])
    assert "A03:2021" in sg["compliance"]["owaspTop10_2021"]
    assert any(r["requirement"] == "6.2.4" for r in sg["compliance"]["pciDss4_0"]), sg[
        "compliance"
    ]["pciDss4_0"]
    return findings


@pytest.fixture(scope="module")
def clean_findings() -> list[dict[str, Any]]:
    """Findings that every one of the five policies must accept.

    Low-severity, no CWE, no secret tool -- so each policy's rule is given a
    real population to run against and finds nothing, which is a different
    thing from being handed an empty list.
    """
    findings = _adapter_findings(
        {
            "semgrep": [
                {
                    "check_id": "python.lang.best-practice.unused-import",
                    "path": "app.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "message": "Unused import",
                        "severity": "INFO",
                        "metadata": {},
                    },
                }
            ]
        }
    )
    assert findings, "clean fixture is empty -- a policy cannot 'find nothing' in it"
    assert all(f["severity"] in ("INFO", "LOW") for f in findings), [
        f["severity"] for f in findings
    ]
    return findings


def _write(tmp_path: Path, name: str, findings: list[dict[str, Any]]) -> Path:
    p = tmp_path / name
    p.write_bytes(
        json.dumps({"meta": {}, "findings": findings}, indent=1).encode("utf-8")
    )
    return p


# ---------------------------------------------------------------- exit code +
# ------------------------------------------------------------- human output --


@pytest.mark.parametrize("policy", POLICIES)
def test_policy_fails_on_a_known_violation(
    policy, violating_findings, tmp_path, capsys
):
    """Output 1 and 2: the exit code and what the user reads."""
    findings_file = _write(tmp_path, "violating.json", violating_findings)
    rc = cmd_policy_test(
        argparse.Namespace(policy=policy, findings_file=str(findings_file))
    )
    out = capsys.readouterr().out

    assert rc == 1, f"{policy} returned {rc} on a findings file with a known violation"
    assert "FAILED" in out, out
    assert "PASSED" not in out, out

    # A FAIL with zero violations is the under-reporting shape: `allow` keys on
    # one population and the violation objects on another, so a missing
    # optional field can empty the list while the gate still fails.
    count = int(
        next(line for line in out.splitlines() if line.startswith("Violations:"))
        .split(":")[1]
        .strip()
    )
    assert count > 0, f"{policy} FAILED but listed 0 violations"


@pytest.mark.parametrize("policy", POLICIES)
def test_policy_passes_on_a_known_clean_input(policy, clean_findings, tmp_path, capsys):
    """The negative control. Without it, 'always FAIL' would pass the test above."""
    findings_file = _write(tmp_path, "clean.json", clean_findings)
    rc = cmd_policy_test(
        argparse.Namespace(policy=policy, findings_file=str(findings_file))
    )
    out = capsys.readouterr().out

    assert rc == 0, f"{policy} returned {rc} on a findings file with no violation"
    assert "PASSED" in out, out
    assert "Violations: 0" in out, out


# ------------------------------------------------------- machine-readable ----


def test_policy_report_artifact_agrees_with_the_verdict(
    violating_findings, clean_findings, tmp_path
):
    """Output 3: POLICY_REPORT.md, written by the engine's *other* consumer.

    ``jmo report --policy`` goes through ``policy_reporter.evaluate_policies``,
    which builds its own ``PolicyEngine``. Before this chunk that path wrote
    "zero-secrets | PASSED | 0 | 0 | No verified secrets detected" into the
    shipped artifact for a scan whose only finding was a verified AWS key.
    """
    for label, findings, want_pass in (
        ("violating", violating_findings, False),
        ("clean", clean_findings, True),
    ):
        results = evaluate_policies(findings, POLICIES, BUILTIN_DIR, USER_DIR)
        assert set(results) == set(POLICIES), f"{label}: evaluated {sorted(results)}"

        for name, result in results.items():
            assert result.passed is want_pass, (
                f"{label}: {name} passed={result.passed}, expected {want_pass}"
            )
            if not want_pass:
                assert result.violations, f"{label}: {name} failed with no violations"

        out = tmp_path / f"POLICY_REPORT-{label}.md"
        write_policy_report(results, out)
        text = out.read_text(encoding="utf-8")
        for name in POLICIES:
            assert name in text, f"{label}: {name} missing from the report"
        assert ("FAILED" in text) is not want_pass, text[:400]


# ------------------------------------------------------------------ shape ----


def test_one_finding_yields_one_violation_per_policy(violating_findings, tmp_path):
    """A finding matching several of a policy's sub-rules is still one issue.

    ``production-hardening`` builds violations from three overlapping
    populations. A verified TruffleHog secret is in two of them, and Rego keeps
    set members differing in any field -- so before the ``not`` guards the gate
    reported "2 blocking issues" for one finding.
    """
    results = evaluate_policies(
        violating_findings, ["production-hardening"], BUILTIN_DIR, USER_DIR
    )
    violations = results["production-hardening"].violations
    fingerprints = [v["fingerprint"] for v in violations]
    assert len(fingerprints) == len(set(fingerprints)), (
        f"the same finding appears more than once: {sorted(fingerprints)}"
    )
    assert len(violations) == len(violating_findings), (
        f"{len(violations)} violations for {len(violating_findings)} findings"
    )


def test_metadata_matches_opa_reading_of_the_policys_own_package():
    """Output 4: what ``policy list`` / ``policy show`` print.

    ``get_metadata`` queried the literal ``data.jmo.policy.metadata`` while
    every builtin declares its own sub-package, so OPA returned ``{}`` every
    time and a textual fallback ran instead -- one that split on "," and cut
    through list values. ``jmo policy show hipaa-compliance`` printed
    ``tags: ["hipaa``. All 5 builtins were affected.
    """
    import re
    import subprocess

    from scripts.core.policy_engine import PolicyEngine

    opa = find_tool("opa")
    engine = PolicyEngine()
    checked = 0
    for policy_path in sorted(BUILTIN_DIR.glob("*.rego")):
        text = policy_path.read_text(encoding="utf-8")
        package = re.search(r"^\s*package\s+([\w.]+)", text, re.MULTILINE).group(1)
        proc = subprocess.run(
            [
                opa,
                "eval",
                "-d",
                str(policy_path),
                "--format",
                "json",
                f"data.{package}.metadata",
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        truth = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
        assert engine.get_metadata(policy_path) == truth, policy_path.name
        # Lists must survive whole; this is the exact shape that was truncated.
        assert isinstance(truth["tags"], list) and len(truth["tags"]) >= 2
        checked += 1
    assert checked == 5, f"checked {checked} policies, expected 5"


def test_each_verification_signal_blocks_on_its_own(violating_findings):
    """Both of zero-secrets' signals must be load-bearing, separately.

    Every real verified secret carries both -- the normalised ``verified``
    tag AND TruffleHog's ``raw.Verified`` -- so a fixture built from adapter
    output cannot tell which arm is doing the work. Mutation testing proved
    it: flipping the tag arm to ``unverified`` changed no test result,
    because the raw arm still matched.

    Both inputs below are schema-valid: ``tags`` and ``raw`` are optional in
    common_finding.v1.json, so a finding carrying one and not the other is a
    degenerate input the policy must still handle, not an invented one.
    """
    secret = next(f for f in violating_findings if f["tool"]["name"] == "trufflehog")

    tag_only = {k: v for k, v in secret.items() if k != "raw"}
    assert "verified" in tag_only["tags"]

    raw_only = dict(secret)
    raw_only["tags"] = ["secrets"]
    assert raw_only["raw"]["Verified"] is True

    for label, finding in (("tag only", tag_only), ("raw only", raw_only)):
        results = evaluate_policies([finding], ["zero-secrets"], BUILTIN_DIR, USER_DIR)
        result = results["zero-secrets"]
        assert not result.passed, (
            f"zero-secrets PASSED on a verified secret carrying the {label} signal"
        )
        assert len(result.violations) == 1, result.violations


def test_hipaa_detects_a_cwe_carrying_its_description(violating_findings):
    """The descriptive `risk.cwe` spelling must be decisive on its own.

    Adapters write two shapes: the bare id (``CWE-798``, semgrep-secrets and
    trufflehog) and the id with its description appended (``CWE-79:
    Improper Neutralization ...``, most others). Only the second needs
    canonicalising, and only the second was broken.

    In a mixed fixture the bare-id finding rescues the policy, so removing
    the canonicalisation changed no test result. Measured by mutation:
    ``id := canonical_cwe(raw)`` -> ``id := raw`` survived the whole suite.
    """
    descriptive = [f for f in violating_findings if f["tool"]["name"] == "semgrep"]
    assert len(descriptive) == 1
    cwe = descriptive[0]["risk"]["cwe"]
    assert cwe == [
        "CWE-79: Improper Neutralization of Input During Web Page Generation"
    ], cwe

    results = evaluate_policies(
        descriptive, ["hipaa-compliance"], BUILTIN_DIR, USER_DIR
    )
    result = results["hipaa-compliance"]
    assert not result.passed, (
        "hipaa-compliance PASSED on a HIGH finding whose risk.cwe is CWE-79, "
        "a CWE it lists as blocking -- the description suffix defeated it"
    )
    assert result.violations[0]["cwe"] == "CWE-79", result.violations
    assert "164.312" in result.violations[0]["safeguard"], result.violations


def test_zero_secrets_counts_no_verified_secret_as_unverified(violating_findings):
    """The negative control for the hint: a verified secret is blocked, not
    counted among the ones passed, on either verification signal."""
    results = evaluate_policies(
        violating_findings, ["zero-secrets"], BUILTIN_DIR, USER_DIR
    )
    result = results["zero-secrets"]

    assert not result.passed
    assert result.warnings == [], result.warnings
    assert "not verified" not in result.message, result.message


def test_zero_secrets_says_what_it_does_not_block(tmp_path, monkeypatch, capsys):
    """#1327 item 4: zero-secrets blocks verified secrets only. TruffleHog
    verifies only with `per_tool.trufflehog.verify: true` (off by default since
    v2.0.0) and gitleaks never does, so it passed every secret and said "No
    verified secrets detected", with no hint why at run time or in the report.

    Through `jmo report`, with a real TruffleHog record through the real
    adapter and the real OPA. The verdict stays PASS: an unverified secret is
    not what this policy blocks, and `--fail-on HIGH` is what stops on it."""
    target = tmp_path / "results" / "individual-repos" / "proj"
    target.mkdir(parents=True)
    record = {
        "SourceMetadata": {"Data": {"Filesystem": {"file": "config/prod.env"}}},
        "DetectorName": "AWS",
        "Verified": False,
        "Raw": "AKIAIOSFODNN7EXAMPLE",
        "StartLine": 3,
    }
    (target / "trufflehog.json").write_bytes((json.dumps(record) + "\n").encode())
    monkeypatch.chdir(tmp_path)
    argv = ["jmo", "report", str(tmp_path / "results"), "--policy", "zero-secrets"]
    with patch.object(sys, "argv", argv):
        args = jmo.parse_args()

    assert jmo.cmd_report(args) == 0

    report = (tmp_path / "results" / "summaries" / "POLICY_REPORT.md").read_text(
        encoding="utf-8"
    )
    assert "zero-secrets | ✅ PASSED" in report, report
    # In the summary's message, and as the policy's one warning.
    assert "; 1 secret(s) are not verified, so not blocked" in report, report
    assert "### Warnings (1)" in report, report
    assert "per_tool.trufflehog.verify" in report, report
    said = [
        line
        for line in capsys.readouterr().err.splitlines()
        if "zero-secrets" in line and "not verified" in line
    ]
    assert len(said) == 1, said


# ------------------------------------------------ consensus findings (#1355) --
#
# Cross-tool clustering merges one secret's reports into one consensus finding
# whose `tool` is its lead's. On a severity tie the lead is the first tool by
# name, so gitleaks leads a gitleaks + TruffleHog pair and semgrep a semgrep +
# TruffleHog one -- and neither is a tool these policies select secrets by. A
# policy reading `tool.name` alone passed a verified TruffleHog secret whenever
# another scanner also reported it. juice-shop `1618a611`'s
# `terraform/networking.tf:171` shape; no key material.

_KEY_PATH, _KEY_LINE = "terraform/networking.tf", 171

# The policies' secret rules, and how each marks a finding it flags: every
# zero-secrets violation, and production-hardening's `secrets` category.
_SECRET_RULES = {
    "zero-secrets": lambda v: True,
    "production-hardening": lambda v: v.get("category") == "secrets",
}


def _one_key_from(tools: tuple[str, ...], verified: bool) -> list[dict[str, Any]]:
    """The key's record from each of `tools`, through the real adapters."""
    from scripts.core.adapters.gitleaks_adapter import GitleaksAdapter

    records: dict[str, tuple[Any, str, str]] = {
        "gitleaks": (
            GitleaksAdapter,
            "gitleaks.json",
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "gitleaks"}},
                            "results": [
                                {
                                    "message": {
                                        "text": "private-key has detected secret "
                                        f"for file {_KEY_PATH}."
                                    },
                                    "ruleId": "private-key",
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": _KEY_PATH},
                                                "region": {
                                                    "startLine": _KEY_LINE,
                                                    "endLine": _KEY_LINE,
                                                },
                                            }
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ),
        ),
        "semgrep": (
            SemgrepAdapter,
            "semgrep.json",
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "generic.secrets.security.detected-private-key",
                            "path": _KEY_PATH,
                            "start": {"line": _KEY_LINE},
                            "end": {"line": _KEY_LINE},
                            "extra": {
                                "message": "Private Key detected.",
                                "severity": "ERROR",
                                "metadata": {"cwe": ["CWE-798"]},
                            },
                        }
                    ],
                    "errors": [],
                }
            ),
        ),
        "trufflehog": (
            TruffleHogAdapter,
            "trufflehog.json",
            json.dumps(
                {
                    "SourceMetadata": {
                        "Data": {"Filesystem": {"file": _KEY_PATH, "line": _KEY_LINE}}
                    },
                    "DetectorName": "PrivateKey",
                    "Verified": verified,
                }
            )
            + "\n",
        ),
    }
    out: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as td:
        for tool in tools:
            adapter, name, text = records[tool]
            p = Path(td) / name
            p.write_bytes(text.encode("utf-8"))
            parsed = [f.to_dict() for f in adapter().parse(p)]
            assert len(parsed) == 1, (tool, parsed)
            out += parsed
    return out


def _report_phase(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The report phase's order: CWE backfill, compliance, then clustering."""
    import copy

    from scripts.core.cwe_extraction import backfill_risk_cwe
    from scripts.core.normalize_and_report import _cluster_cross_tool_duplicates

    findings = copy.deepcopy(findings)
    backfill_risk_cwe(findings)
    findings = enrich_findings_with_compliance(findings)
    return _cluster_cross_tool_duplicates(findings, similarity_threshold=0.65)


def _flagged(policy: str, findings: list[dict[str, Any]]) -> set[str]:
    """The ids of `findings` that `policy`'s secret rule flags, via real OPA."""
    result = evaluate_policies(findings, [policy], BUILTIN_DIR, USER_DIR)[policy]
    return {v["fingerprint"] for v in result.violations if _SECRET_RULES[policy](v)}


@pytest.mark.parametrize(
    "order", [("gitleaks", "trufflehog"), ("trufflehog", "gitleaks")], ids="-".join
)
def test_a_verified_trufflehog_secret_gitleaks_also_reports_is_blocked(order):
    """Both load orders: zero-secrets FAILS with one violation.

    Measured at 705f5317 (copy-of-the-lead consensus, load order picks the
    lead): gitleaks-first passed, trufflehog-first failed. With #1355's
    tie-break alone, gitleaks leads in both orders and both passed.
    """
    members = {f["tool"]["name"]: f for f in _one_key_from(order, verified=True)}
    (consensus,) = _report_phase([members[tool] for tool in order])

    # Meta-guards: one cluster, led by the tool the policies do not list.
    assert {r["name"] for r in consensus["detected_by"]} == {"gitleaks", "trufflehog"}
    assert consensus["tool"]["name"] == "gitleaks"

    zero = evaluate_policies([consensus], ["zero-secrets"], BUILTIN_DIR, USER_DIR)
    result = zero["zero-secrets"]
    assert result.passed is False, result.message
    assert len(result.violations) == 1, result.violations
    assert result.violations[0]["fingerprint"] == consensus["id"]

    assert _flagged("production-hardening", [consensus]) == {consensus["id"]}


@pytest.mark.parametrize(
    "hadolint_first", [True, False], ids=["hadolint-first", "trivy-first"]
)
def test_a_hadolint_dockerfile_issue_trivy_leads_keeps_its_category(hadolint_first):
    """production-hardening's `dockerfile` category reads every reporter too.

    hadolint's DL3024 ("FROM aliases must be unique", level error: HIGH) and
    trivy's DS-0012 (CRITICAL) are one rule-equivalence class, so they
    cluster, and trivy leads on severity -- in any order, before #1355 and
    after. Reading `tool.name` alone moved the finding from `dockerfile` to
    the generic `security` category. The verdict fails either way.
    """
    from scripts.core.adapters.hadolint_adapter import HadolintAdapter
    from scripts.core.adapters.trivy_adapter import TrivyAdapter

    records = {
        "hadolint": (
            HadolintAdapter,
            [
                {
                    "code": "DL3024",
                    "level": "error",
                    "line": 9,
                    "file": "Dockerfile",
                    "message": "FROM aliases (stage names) must be unique",
                }
            ],
        ),
        "trivy": (
            TrivyAdapter,
            {
                "Trivy": {"Version": "0.74.0"},
                "Results": [
                    {
                        "Target": "Dockerfile",
                        "Misconfigurations": [
                            {
                                "ID": "DS-0012",
                                "Title": "Duplicate aliases defined in different FROMs",
                                "Severity": "CRITICAL",
                                "CauseMetadata": {"StartLine": 9, "EndLine": 9},
                            }
                        ],
                    }
                ],
            },
        ),
    }
    members = []
    with tempfile.TemporaryDirectory() as td:
        for tool in ("hadolint", "trivy") if hadolint_first else ("trivy", "hadolint"):
            adapter, record = records[tool]
            if tool == "trivy":
                # The scanned root: trivy's adapter reads a code snippet under
                # it, and there is no Dockerfile here to read.
                record = {**record, "ArtifactName": td}
            p = Path(td) / f"{tool}.json"
            p.write_bytes(json.dumps(record).encode("utf-8"))
            members += [f.to_dict() for f in adapter().parse(p)]
    assert len(members) == 2, members

    (consensus,) = _report_phase(members)
    assert consensus["tool"]["name"] == "trivy", "the case under test: not led"
    assert {r["name"] for r in consensus["detected_by"]} == {"hadolint", "trivy"}

    result = evaluate_policies(
        [consensus], ["production-hardening"], BUILTIN_DIR, USER_DIR
    )["production-hardening"]
    assert result.passed is False
    assert [v["category"] for v in result.violations] == ["dockerfile"], (
        result.violations
    )


def test_a_consensus_is_flagged_whenever_a_member_alone_would_be():
    """The general guard for the secret rules, over every load order.

    Members: gitleaks, semgrep and TruffleHog reporting one key, in four
    TruffleHog shapes -- verified (both signals), the tag alone, `raw.Verified`
    alone (the degenerate inputs `test_each_verification_signal_blocks_on_its_own`
    requires the policy to handle) and unverified. Every subset holding the
    TruffleHog record, in every order, through the real report phase; each
    output finding must be flagged if any member it stands for is flagged when
    evaluated alone.
    """
    base = {f["tool"]["name"]: f for f in _one_key_from(("gitleaks", "semgrep"), True)}
    verified = _one_key_from(("trufflehog",), verified=True)[0]
    shapes = {
        "verified": verified,
        "tag-only": {k: v for k, v in verified.items() if k != "raw"},
        "raw-only": {**verified, "tags": ["secrets"]},
        "unverified": _one_key_from(("trufflehog",), verified=False)[0],
    }
    assert shapes["raw-only"]["raw"]["Verified"] is True
    for shape, finding in shapes.items():
        # One id per shape, so a batch evaluation can tell them apart.
        shapes[shape] = {**finding, "id": f"{finding['id']}-{shape}"}
    members = [*base.values(), *shapes.values()]

    alone = {policy: _flagged(policy, members) for policy in _SECRET_RULES}
    # Meta-guard: what each rule flags alone, so the property is not vacuous:
    # zero-secrets every verified shape, production-hardening every TruffleHog
    # secret; neither gitleaks nor semgrep, which is the point.
    ids = {shape: f["id"] for shape, f in shapes.items()}
    assert alone["zero-secrets"] == {
        ids["verified"],
        ids["tag-only"],
        ids["raw-only"],
    }
    assert alone["production-hardening"] == set(ids.values())

    outputs: list[dict[str, Any]] = []
    covers: dict[str, list[str]] = {}
    for shape, trufflehog in shapes.items():
        for others in ((), ("gitleaks",), ("semgrep",), ("gitleaks", "semgrep")):
            group = [trufflehog, *(base[t] for t in others)]
            for n, order in enumerate(itertools.permutations(group)):
                for f in _report_phase(list(order)):
                    run_id = f"{f['id']}#{shape}/{'+'.join(others)}/{n}"
                    duplicates = (f.get("context") or {}).get("duplicates") or []
                    covers[run_id] = [
                        f["id"].removeprefix("cluster-"),
                        *(d["id"] for d in duplicates),
                    ]
                    outputs.append({**f, "id": run_id})

    for policy in _SECRET_RULES:
        flagged = _flagged(policy, outputs)
        missed = [
            (run_id, member)
            for run_id, member_ids in covers.items()
            for member in member_ids
            if member in alone[policy] and run_id not in flagged
        ]
        assert not missed, f"{policy}: {len(missed)} finding(s) missed, {missed[:3]}"
        # Meta-guard: the case that regressed -- another tool leads a
        # consensus holding a flagged TruffleHog member -- is exercised: every
        # order of every group with a second tool (10 per shape).
        led_by_another = [
            f["id"]
            for f in outputs
            if f["tool"]["name"] != "trufflehog"
            and any(m in alone[policy] for m in covers[f["id"]])
        ]
        assert len(led_by_another) == 10 * len(alone[policy]), (
            policy,
            len(led_by_another),
        )
