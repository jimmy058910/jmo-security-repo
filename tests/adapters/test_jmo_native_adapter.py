"""Tests for the jmo-native binding: registration, severity and the CWE lift.

The importer itself is tested in test_sarif_common.py. What this binding adds
is `risk`: the runner writes each rule's CWE as a rule property (`cwe`), and
compliance enrichment reads `risk.cwe` and nowhere else, so without the lift
every jmo-native finding would map to no framework at all (the gitleaks case,
#1328).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.core import native_checks
from scripts.core.adapters.jmo_native_adapter import JmoNativeAdapter
from scripts.core.compliance_mapper import enrich_finding_with_compliance
from scripts.core.plugin_loader import PluginLoader, PluginRegistry


def _document(tmp_path: Path) -> Path:
    """One result per rule, from the runner's own SARIF writer."""
    findings = [
        native_checks.NativeFinding(rule, f"src/{n}.ts", n + 1, 1, "m")
        for n, rule in enumerate(native_checks.RULES)
    ]
    out = tmp_path / "jmo-native.json"
    out.write_bytes(json.dumps(native_checks.build_sarif(findings)).encode("utf-8"))
    return out


def test_registers_under_its_file_stem():
    loader = PluginLoader(PluginRegistry())
    name = loader._load_plugin(
        Path("scripts/core/adapters/jmo_native_adapter.py").resolve()
    )
    assert name == "jmo_native"
    assert loader.registry.get("jmo_native") is JmoNativeAdapter
    meta = JmoNativeAdapter().metadata
    assert (meta.tool_name, meta.output_format) == ("jmo-native", "sarif")


def test_the_hyphenated_tool_name_reaches_the_binding():
    """The report maps `jmo-native.json` to an adapter by its tool name, and a
    module name cannot hold a hyphen: the loader's own conversion must land on
    this file, as it does for osv-scanner."""
    loader = PluginLoader(PluginRegistry())
    assert loader._tool_to_adapter_name("jmo-native") == "jmo_native"
    assert loader.get_adapter("jmo_native") is JmoNativeAdapter


def test_every_finding_carries_the_tool_its_version_and_tags(tmp_path):
    findings = JmoNativeAdapter().parse(_document(tmp_path))

    assert len(findings) == len(native_checks.RULES)
    # No versions.yaml pin: the version is the one the runner writes, JMo's.
    assert {f.tool["name"] for f in findings} == {"jmo-native"}
    assert {f.tool["version"] for f in findings} == {native_checks.JMO_VERSION}
    assert all({"sast", "sarif"} <= set(f.tags) for f in findings)


def test_severity_is_each_rules_own(tmp_path):
    findings = JmoNativeAdapter().parse(_document(tmp_path))

    assert {f.ruleId: f.severity for f in findings} == {
        rule: meta.severity for rule, meta in native_checks.RULES.items()
    }


def test_the_rules_cwe_is_lifted_into_risk(tmp_path):
    findings = JmoNativeAdapter().parse(_document(tmp_path))

    for f in findings:
        cwe = native_checks.RULES[f.ruleId].cwe
        assert f.risk is not None, f.ruleId
        assert f.risk["confidence"] == "MEDIUM", f.ruleId
        if cwe is None:
            assert "cwe" not in f.risk, f.ruleId
        else:
            assert f.risk["cwe"] == [cwe], f.ruleId


def _compliance(finding: dict) -> dict:
    return enrich_finding_with_compliance(finding).get("compliance", {})


@pytest.mark.parametrize(
    "rule",
    [rule for rule, meta in sorted(native_checks.RULES.items()) if meta.cwe],
)
def test_enrichment_maps_the_lifted_cwe(tmp_path, rule):
    """The point of the lift: the same finding without `risk.cwe` maps to
    less. OWASP and the CWE Top 25 key on the CWE alone."""
    finding = next(
        f for f in JmoNativeAdapter().parse(_document(tmp_path)) if f.ruleId == rule
    ).to_dict()
    without = {
        **finding,
        "risk": {k: v for k, v in finding["risk"].items() if k != "cwe"},
    }

    assert _compliance(finding) != _compliance(without), rule
    assert "owaspTop10_2021" in _compliance(finding), rule


def test_a_public_env_secret_is_broken_access_control(tmp_path):
    """Ruling 75: OWASP Top 10 2021 maps CWE-540 (Inclusion of Sensitive
    Information in Source Code) to A01, and the public-env rule is how a
    server secret ends up in the browser bundle."""
    finding = next(
        f
        for f in JmoNativeAdapter().parse(_document(tmp_path))
        if f.ruleId == native_checks.RULE_PUBLIC_ENV
    ).to_dict()

    assert finding["risk"]["cwe"] == ["CWE-540"]
    assert _compliance(finding)["owaspTop10_2021"] == ["A01:2021"]


def _with_a_bad_run_first(tmp_path: Path, bad: object) -> Path:
    path = _document(tmp_path)
    document = json.loads(path.read_bytes())
    document["runs"].insert(0, bad)
    path.write_bytes(json.dumps(document).encode("utf-8"))
    return path


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("junk", id="a-run-that-is-not-an-object"),
        pytest.param({"tool": "jmo-native", "results": []}, id="tool-is-a-string"),
    ],
)
def test_a_shape_parse_sarif_tolerates_still_gets_its_cwes(tmp_path, bad):
    """Review Minor 1: both shapes raised AttributeError in the lift, while
    `parse_sarif` reads past them. The lift walks the document the way
    `parse_sarif` does, so it reads past them too."""
    findings = JmoNativeAdapter().parse(_with_a_bad_run_first(tmp_path, bad))

    assert len(findings) == len(native_checks.RULES)
    for f in findings:
        cwe = native_checks.RULES[f.ruleId].cwe
        assert f.risk is not None
        assert f.risk.get("cwe") == ([cwe] if cwe else None), f.ruleId


def test_the_rule_without_a_cwe_goes_through_enrichment(tmp_path):
    finding = next(
        f
        for f in JmoNativeAdapter().parse(_document(tmp_path))
        if f.ruleId == native_checks.RULE_RLS_NO_POLICY
    ).to_dict()

    assert "cwe" not in finding["risk"]
    assert "owaspTop10_2021" not in _compliance(finding)
