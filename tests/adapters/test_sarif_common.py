"""Tests for the generic SARIF 2.1.0 importer (`sarif_common.parse_sarif`).

Cases the three real documents do not exercise, so the chain is tested where it
is hard, not only where it happens to be easy (spec section 4.2). The real
documents are covered by the golden fixtures and the binding tests.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from scripts.core.adapters.sarif_common import SarifToolSpec, parse_sarif
from scripts.core.common_finding import fingerprint
from scripts.core.exceptions import AdapterParseException

SPEC = SarifToolSpec(tool="sarifdemo", tags=("demo",))


def sarif(
    results: list,
    rules: list[dict] | None = None,
    *,
    version: str | None = "2.1.0",
    driver: dict | None = None,
    runs: list | None = None,
) -> dict:
    drv = {"name": "demo", "version": "9.9.9"} if driver is None else driver
    if rules is not None:
        drv["rules"] = rules
    doc: dict = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json"}
    if version is not None:
        doc["version"] = version
    doc["runs"] = (
        runs if runs is not None else [{"tool": {"driver": drv}, "results": results}]
    )
    return doc


def result(uri: str = "src/a.py", line: int = 3, **extra) -> dict:
    r = {
        "ruleId": "R1",
        "message": {"text": "boom"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "startColumn": 7, "endLine": line},
                }
            }
        ],
    }
    r.update(extra)
    return r


def write(tmp_path: Path, doc) -> Path:
    p = tmp_path / "sarifdemo.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


# --- shape and version ------------------------------------------------------


def test_valid_json_that_is_not_sarif_raises(tmp_path):
    """The #822 class: a tool invoked with a JSON flag instead of a SARIF flag
    writes valid JSON, exits 0, and must not read as zero findings."""
    p = write(tmp_path, {"findings": []})
    with pytest.raises(AdapterParseException) as exc:
        parse_sarif(p, SPEC)
    assert exc.value.tool == "sarifdemo"
    assert "runs" in exc.value.reason


def test_runs_that_is_not_a_list_raises(tmp_path):
    p = write(tmp_path, {"version": "2.1.0", "runs": {"not": "a list"}})
    with pytest.raises(AdapterParseException):
        parse_sarif(p, SPEC)


def test_json_list_raises(tmp_path):
    p = write(tmp_path, [1, 2, 3])
    with pytest.raises(AdapterParseException):
        parse_sarif(p, SPEC)


def test_missing_and_empty_files_return_empty(tmp_path):
    assert parse_sarif(tmp_path / "absent.json", SPEC) == []
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    assert parse_sarif(empty, SPEC) == []


def test_other_version_warns_and_parses(tmp_path, caplog):
    p = write(tmp_path, sarif([result()], version="2.2.0"))
    with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.sarif_common"):
        findings = parse_sarif(p, SPEC)
    assert len(findings) == 1
    assert any("2.2.0" in r.getMessage() for r in caplog.records)


def test_multiple_runs_are_concatenated(tmp_path):
    def run(n: int) -> dict:
        return {
            "tool": {"driver": {"name": "demo"}},
            "results": [result(line=i) for i in range(n)],
        }

    p = write(tmp_path, sarif([], runs=[run(2), run(3)]))
    assert len(parse_sarif(p, SPEC)) == 5


# --- severity chain, one rank at a time -------------------------------------


@pytest.mark.parametrize(
    "props,expected",
    [
        ({"security-severity": "9.0"}, "CRITICAL"),
        ({"security-severity": "7.0"}, "HIGH"),
        ({"security-severity": "4.0"}, "MEDIUM"),
        ({"security-severity": "0.1"}, "LOW"),
        ({"security-severity": "0.0"}, "INFO"),
        ({"security-severity": "10.0"}, "CRITICAL"),
        ({"security-severity": "8.9"}, "HIGH"),
        ({"security-severity": "6.9"}, "MEDIUM"),
        ({"security-severity": "3.9"}, "LOW"),
    ],
)
def test_rank1_security_severity_buckets(tmp_path, props, expected):
    p = write(tmp_path, sarif([result(level="note", properties=props)]))
    f = parse_sarif(p, SPEC)[0]
    assert f.severity == expected
    assert f.cvss == {"score": float(props["security-severity"])}


def test_rank1_on_the_rule_when_the_result_has_none(tmp_path):
    rules = [{"id": "R1", "properties": {"security-severity": "7.5"}}]
    p = write(tmp_path, sarif([result(level="warning")], rules))
    f = parse_sarif(p, SPEC)[0]
    assert (f.severity, f.cvss) == ("HIGH", {"score": 7.5})


def test_rank1_malformed_falls_through_to_rank2(tmp_path):
    props = {"security-severity": "high", "demo/severity": "Low"}
    p = write(tmp_path, sarif([result(level="error", properties=props)]))
    f = parse_sarif(p, SPEC)[0]
    assert f.severity == "LOW"
    assert f.cvss is None


def test_rank2_suffix_severity_property(tmp_path):
    props = {"zizmor/severity": "Informational"}
    p = write(tmp_path, sarif([result(level="error", properties=props)]))
    assert parse_sarif(p, SPEC)[0].severity == "INFO"


def test_rank2_exact_severity_property_on_rule(tmp_path):
    rules = [{"id": "R1", "properties": {"severity": "critical"}}]
    p = write(tmp_path, sarif([result(level="note")], rules))
    assert parse_sarif(p, SPEC)[0].severity == "CRITICAL"


def test_rank3_result_level(tmp_path):
    p = write(tmp_path, sarif([result(level="error")]))
    assert parse_sarif(p, SPEC)[0].severity == "HIGH"


def test_rank4_default_configuration_level(tmp_path):
    rules = [{"id": "R1", "defaultConfiguration": {"level": "note"}}]
    p = write(tmp_path, sarif([result()], rules))
    assert parse_sarif(p, SPEC)[0].severity == "LOW"


def test_rank5_sarif_default_is_warning(tmp_path):
    p = write(tmp_path, sarif([result()]))
    f = parse_sarif(p, SPEC)[0]
    assert f.severity == "MEDIUM"
    assert f.cvss is None


# --- rule lookup ------------------------------------------------------------


def test_rule_by_index(tmp_path):
    rules = [{"id": "X", "name": "wrong"}, {"id": "R1", "name": "Right name"}]
    p = write(tmp_path, sarif([result(ruleIndex=1)], rules))
    assert parse_sarif(p, SPEC)[0].title == "Right name"


@pytest.mark.parametrize("index", [-1, 5, "1", None])
def test_rule_index_invalid_falls_back_to_id_match(tmp_path, index):
    rules = [{"id": "R0", "name": "nope"}, {"id": "R1", "name": "By id"}]
    r = result()
    if index is not None:
        r["ruleIndex"] = index
    p = write(tmp_path, sarif([r], rules))
    assert parse_sarif(p, SPEC)[0].title == "By id"


def test_no_rule_at_all(tmp_path):
    r = result()
    del r["ruleId"]
    p = write(tmp_path, sarif([r]))
    f = parse_sarif(p, SPEC)[0]
    assert f.ruleId == "SARIF"
    assert f.title == "SARIF"


# --- location ---------------------------------------------------------------


@pytest.mark.parametrize(
    "uri,expected",
    [
        ("file:///home/u/repo/a.py", "/home/u/repo/a.py"),
        ("file:///C:/Users/u/repo/a.py", "C:/Users/u/repo/a.py"),
        ("file://server/share/a.py", "//server/share/a.py"),
        ("file:///C:/a%20b/c%23.py", "C:/a b/c#.py"),
        ("src/a.py", "src/a.py"),
        ("C:/abs/a.py", "C:/abs/a.py"),
        ("https://example.com/x", "https://example.com/x"),
    ],
)
def test_uri_decoding(tmp_path, uri, expected):
    p = write(tmp_path, sarif([result(uri=uri)]))
    assert parse_sarif(p, SPEC)[0].location["path"] == expected


def test_region_absent_leaves_start_line_absent(tmp_path):
    """osv-scanner supplies no region; a line of 0 must not be invented."""
    r = result()
    del r["locations"][0]["physicalLocation"]["region"]
    p = write(tmp_path, sarif([r]))
    loc = parse_sarif(p, SPEC)[0].location
    assert loc["path"] == "src/a.py"
    assert "startLine" not in loc


def test_region_lines_and_columns_carried(tmp_path):
    p = write(tmp_path, sarif([result(line=12)]))
    loc = parse_sarif(p, SPEC)[0].location
    assert (loc["startLine"], loc["endLine"], loc["startColumn"]) == (12, 12, 7)


def test_no_locations_gives_empty_path(tmp_path):
    r = result()
    del r["locations"]
    p = write(tmp_path, sarif([r]))
    assert parse_sarif(p, SPEC)[0].location == {"path": ""}


# --- fingerprint, fields, tool version --------------------------------------


def test_fingerprint_is_the_canonical_five_components(tmp_path):
    """The exact shape `_normalize_paths_and_ids` recomputes, over the decoded
    path, so ids survive root-stripping in the report phase."""
    p = write(tmp_path, sarif([result(uri="file:///C:/r/a.py", line=3)]))
    f = parse_sarif(p, SPEC)[0]
    assert f.id == fingerprint("sarifdemo", "R1", "C:/r/a.py", 3, "boom")


def test_field_mapping_from_rule(tmp_path):
    rules = [
        {
            "id": "R1",
            "name": "Rule name",
            "shortDescription": {"text": "short"},
            "fullDescription": {"text": "full"},
            "help": {"text": "do this"},
            "helpUri": "https://example.com/R1",
            "properties": {"tags": ["security", "demo"]},
        }
    ]
    p = write(tmp_path, sarif([result()], rules))
    f = parse_sarif(p, SPEC)[0]
    assert f.title == "Rule name"
    assert f.description == "full"
    assert f.remediation == "do this"
    assert f.references == ["https://example.com/R1"]
    assert f.tags == ["demo", "security"]
    assert f.raw["ruleId"] == "R1"
    assert f.tool == {"name": "sarifdemo", "version": "9.9.9"}
    assert f.schemaVersion == "1.2.0"


def test_field_fallbacks_without_rule_metadata(tmp_path):
    p = write(tmp_path, sarif([result()]))
    f = parse_sarif(p, SPEC)[0]
    assert (f.title, f.description, f.remediation, f.references) == (
        "R1",
        "boom",
        "See rule documentation",
        [],
    )


def test_tool_version_prefers_registry_then_driver_then_semantic(tmp_path, monkeypatch):
    """gitleaks 8.30.1 reports `semanticVersion: v8.0.0` and no `version`
    (spec section 2.4); versions.yaml wins when it has a row."""
    from scripts.core.adapters import sarif_common

    p = write(
        tmp_path,
        sarif([result()], driver={"name": "demo", "semanticVersion": "v8.0.0"}),
    )
    assert parse_sarif(p, SPEC)[0].tool["version"] == "v8.0.0"

    p = write(tmp_path, sarif([result()], driver={"name": "demo"}))
    assert parse_sarif(p, SPEC)[0].tool["version"] == "unknown"

    monkeypatch.setattr(sarif_common, "_registry_version", lambda tool: "1.2.3")
    p = write(tmp_path, sarif([result()], driver={"name": "demo", "version": "9.9.9"}))
    assert parse_sarif(p, SPEC)[0].tool["version"] == "1.2.3"


def test_non_dict_results_and_runs_are_skipped(tmp_path):
    doc = sarif([result(), "junk", 7])
    doc["runs"].append("not a run")
    p = write(tmp_path, doc)
    assert len(parse_sarif(p, SPEC)) == 1
