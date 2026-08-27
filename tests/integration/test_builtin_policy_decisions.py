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
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

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
            assert (
                result.passed is want_pass
            ), f"{label}: {name} passed={result.passed}, expected {want_pass}"
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
    assert len(fingerprints) == len(
        set(fingerprints)
    ), f"the same finding appears more than once: {sorted(fingerprints)}"
    assert len(violations) == len(
        violating_findings
    ), f"{len(violations)} violations for {len(violating_findings)} findings"


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
            f"zero-secrets PASSED on a verified secret carrying the " f"{label} signal"
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
