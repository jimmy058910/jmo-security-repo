# Phase 1 — SARIF importer: task plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the generic SARIF 2.1.0 importer with zizmor, gitleaks and osv-scanner
bindings (PR 1244), then make `fingerprint()` column-aware with one formula (a second
PR), closing #1242 #1010 #34.

**Architecture:** `scripts/core/adapters/sarif_common.py` holds one module-level
`parse_sarif(path, spec)`; each binding is a ~25-line `@adapter_plugin` class that
delegates to it. Nothing under `scripts/core/` outside `adapters/` changes in PR 1244.
The second PR touches `common_finding.fingerprint`, `plugin_api.get_fingerprint`,
`normalize_and_report._normalize_paths_and_ids` and `shellcheck_adapter`.

**Tech Stack:** Python 3.12, pytest, the existing plugin loader, `jmo report`.

**Spec:** `docs/superpowers/specs/2026-09-12-sarif-importer-design.md` (on this branch);
program plan `docs/superpowers/plans/2026-09-12-v2.0.0-program.md` § Phase 1.

## Global Constraints

Copied from the program plan; every task's requirements include these.

- **Backward compatibility is NOT a constraint.** No users; ids may change.
- **One formatter:** `ruff format`. `make` is not on PATH: run `pre-commit run --all-files`.
- **No `shell=True`.**
- **Conventional commits. No AI-attribution markers of any kind.** Commit only the work
  this plan names.
- **Never commit to `dev`.** PR into it, squash.
- **Closing keywords go in an individual COMMIT message.** A PR body into `dev` is inert.
- **Gates are numbers through `jmo scan` / `jmo report`, never a bare binary.**
- **Pre-dedup ≠ post-dedup.** Assert per-tool counts from single-tool `jmo report` runs.
- **Check line endings on every touched file:** `git diff --numstat` must equal
  `git diff --ignore-cr-at-eol --numstat`. Write files with `write_bytes`, never
  `sed -i` under MSYS.
- **Run local suites with `PYTHONUTF8` unset.** Interpreter: `.venv/Scripts/python.exe`
  (PATH `python` is pre-3.12).
- **Bounded suite:** `JMO_THREADS=2 .venv/Scripts/python.exe -m pytest tests/ -n 8 -q -m "not smoke and not requires_tools and not docker"`.
- **Read the `windows-2022` job log, never its check tick.** Baseline from #1249's run:
  **9817 passed / 98 skipped / 256 deselected**. Diff the skip count too.
- **Mutation-test every guard.** Restore from a file backup, never `git checkout --`.
- `--plan` goes **before** the `phase_audit.py` subcommand.

## Measured before this plan was written (2026-09-12)

| Claim | Measured |
|---|---|
| The three documents regenerate at 217 / 69 / 303 | yes, with the archive README's exact commands; same result multisets as the fixtures, not byte-identical (timestamps) |
| Distinct canonical keys with column | zizmor 216, gitleaks 69, osv 291 — spec §2.5 |
| gitleaks `driver.version` | **absent**; `semanticVersion` is `v8.0.0`; ToolRegistry has none of the three, so gitleaks findings will carry `v8.0.0` |
| gitleaks fixture URIs | **repository-relative**, not the absolute native paths spec §2.2 describes — Phase 0 ran the tool from inside the target. Same count. |
| `ruleIndex` | present on all 303 osv results, absent on zizmor and gitleaks — §2.3 |
| `defaultConfiguration.level` | set by **0** rules in any document — the §4.2 unit case is the only coverage |
| Adapters raising `AdapterParseException` today | **0 of 27** (only docstring examples) — §3.6 |
| `scripts/core/validators/scan_validator.py` | `EXPECTED_ADAPTER_COUNT = 27` and `_check_adapter_count` returns **FAIL** at any other count. Outside `adapters/`, so **not touched**: `jmo validate` reports one FAIL check at 30 adapters until Phase 2 rewrites every tool-count literal. Not run by `ci.yml`; `release.yml` runs it tag-only behind `\|\|`. |
| `tests/adapters/test_adapter_malformed.py::ALL_ADAPTERS` | hardcoded list; every case asserts `parse()` returns a list. The SARIF bindings raise on non-SARIF by design (§3.6), so they stay **out** of that list and are covered in `test_sarif_common.py` instead. |
| Golden test discovery | a version dir needs `expected-findings.json` plus one other `.json`; `ADAPTER_REGISTRY` must name the tool or `test_adapter_registry_completeness` fails |
| Only `shellcheck_adapter.py` writes `location.startColumn` today | yes |
| `fingerprint()` callers outside adapters | `normalize_and_report._normalize_paths_and_ids` only; `get_fingerprint` used by semgrep, trivy, trufflehog |
| semgrep golden fixture | **0 expected findings** (vacuous) — not Phase 1's; route to Phase 6 |
| `#34` re-scope comment | "closes when that path is documented for contributors" |

## File structure

**PR 1244 (Part A):**

| File | Responsibility |
|---|---|
| `scripts/core/adapters/sarif_common.py` | NEW — `SarifToolSpec`, `parse_sarif`, severity chain, `file:` decoding, rule lookup |
| `scripts/core/adapters/zizmor_adapter.py` | NEW — binding |
| `scripts/core/adapters/gitleaks_adapter.py` | NEW — binding |
| `scripts/core/adapters/osv_scanner_adapter.py` | NEW — binding |
| `tests/adapters/test_sarif_common.py` | NEW — importer unit tests + the fourth-tool proof |
| `tests/adapters/test_zizmor_adapter.py`, `test_gitleaks_adapter.py`, `test_osv_scanner_adapter.py` | NEW — binding tests |
| `tests/adapters/test_adapter_golden.py` | MODIFY — three `ADAPTER_REGISTRY` entries |
| `tests/fixtures/golden/{zizmor,gitleaks,osv_scanner}/*/expected-findings.json` | NEW — generated by the adapters |
| `docs/superpowers/specs/2026-09-12-sarif-importer-design.md` | MODIFY — status, §4.3 measured table + commands, §5 validator note, gitleaks version note |
| `CONTRIBUTING.md`, `.claude/rules/adapters.rules.md`, `CLAUDE.md`, `docs/USER_GUIDE.md`, `CHANGELOG.md` | MODIFY — SARIF binding path (#34), counts 27 → 30, Unreleased entry |
| `docs/superpowers/specs/2026-09-12-v2.0.0-program-design.md` | MODIFY — §9 `.test_durations` row (handoff nit) |

**Second PR (Part B):** `scripts/core/common_finding.py`, `scripts/core/plugin_api.py`,
`scripts/core/normalize_and_report.py`, `scripts/core/adapters/shellcheck_adapter.py`,
`scripts/core/adapters/sarif_common.py`, their tests, regenerated zizmor/gitleaks
`expected-findings.json`, spec §3.4/§4.3.

---

# Part A — PR 1244: the importer

### Task A1: `sarif_common.py` (TDD)

**Files:**
- Create: `scripts/core/adapters/sarif_common.py`
- Test: `tests/adapters/test_sarif_common.py`

**Interfaces:**
- Produces: `SarifToolSpec(tool: str, tags: tuple[str, ...] = ())`,
  `parse_sarif(output_path: Path, spec: SarifToolSpec) -> list[Finding]`,
  `SARIF_VERSION = "2.1.0"`.

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for the generic SARIF 2.1.0 importer (`sarif_common.parse_sarif`).

Cases the three real documents do not exercise, so the chain is tested where it
is hard, not only where it happens to be easy (spec section 4.2).
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
    results: list[dict],
    rules: list[dict] | None = None,
    *,
    version: str | None = "2.1.0",
    driver: dict | None = None,
    runs: list[dict] | None = None,
) -> dict:
    drv = {"name": "demo", "version": "9.9.9"} if driver is None else driver
    if rules is not None:
        drv["rules"] = rules
    doc: dict = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json"}
    if version is not None:
        doc["version"] = version
    doc["runs"] = runs if runs is not None else [{"tool": {"driver": drv}, "results": results}]
    return doc


def result(uri="src/a.py", line=3, **extra) -> dict:
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
    run = lambda n: {"tool": {"driver": {"name": "demo"}}, "results": [result(line=i) for i in range(n)]}
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
    p = write(tmp_path, sarif([result(level="error", properties={"zizmor/severity": "Informational"})]))
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
        "R1", "boom", "See rule documentation", []
    )


def test_tool_version_prefers_registry_then_driver_then_semantic(tmp_path, monkeypatch):
    from scripts.core.adapters import sarif_common

    p = write(tmp_path, sarif([result()], driver={"name": "demo", "semanticVersion": "v8.0.0"}))
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
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/Scripts/python.exe -m pytest tests/adapters/test_sarif_common.py -q -p no:cacheprovider`
Expected: ImportError on `scripts.core.adapters.sarif_common`.

- [ ] **Step 3: Implement `sarif_common.py`**

```python
#!/usr/bin/env python3
"""Generic SARIF 2.1.0 importer shared by the SARIF-emitting tool bindings.

Design: docs/superpowers/specs/2026-09-12-sarif-importer-design.md.

This module deliberately defines **no** ``AdapterPlugin`` subclass. The plugin
loader registers the first subclass it meets in ``sorted(dir(module))``, so a
registrable base class named ``SarifAdapter`` would win over ``ZizmorAdapter``
and lose to ``GitleaksAdapter`` -- one tool in three broken by the first letter
of its class name (spec section 2.6). Each binding is an ordinary adapter whose
``parse()`` calls :func:`parse_sarif` with its :class:`SarifToolSpec`.

Severity is resolved by a five-rank chain (section 3.2), because ``result.level``
alone reads every osv-scanner finding as MEDIUM and collapses zizmor's Low and
Informational into one bucket. ``file:`` URIs are decoded to plain paths
(section 3.3) so the report phase's root-stripping can see a path instead of a
URI -- the #861 failure class.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from scripts.core.adapters.common import safe_load_json_file
from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.exceptions import AdapterParseException
from scripts.core.plugin_api import Finding
from scripts.core.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"

# CVSS v3.1 qualitative ranges; `> 0.0` is LOW, `0.0` is INFO (section 3.2).
_CVSS_BUCKETS: tuple[tuple[float, str], ...] = (
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
)


@dataclass(frozen=True)
class SarifToolSpec:
    """What one binding contributes: the tool name and its static tags."""

    tool: str  # Finding.tool["name"] AND the ToolRegistry key
    tags: tuple[str, ...] = ()


def parse_sarif(output_path: Path, spec: SarifToolSpec) -> list[Finding]:
    """Parse one SARIF 2.1.0 document into CommonFinding objects.

    Raises:
        AdapterParseException: the file is valid JSON but not a SARIF
            document (no ``runs`` list). Missing, empty and malformed files
            return ``[]`` through ``safe_load_json_file``'s shared warnings.
    """
    path = Path(output_path)
    data = safe_load_json_file(path, default=None)
    if data is None:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        raise AdapterParseException(
            spec.tool, path, "not a SARIF document: expected an object with a `runs` list"
        )

    version = data.get("version")
    if version is not None and version != SARIF_VERSION:
        logger.warning(
            "%s: SARIF version %r is not %s; parsing anyway (SARIF is additive)",
            spec.tool,
            version,
            SARIF_VERSION,
        )

    runs = [run for run in data["runs"] if isinstance(run, dict)]
    tool_version = _tool_version(spec.tool, runs)
    findings: list[Finding] = []
    for run in runs:
        rules = _rules(run)
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if isinstance(result, dict):
                findings.append(_finding(result, rules, spec, tool_version))
    return findings


# --- tool version ------------------------------------------------------------


def _registry_version(tool: str) -> str | None:
    """versions.yaml first; the document's own version claim is a fallback
    (gitleaks 8.30.1 reports ``semanticVersion: v8.0.0``, section 2.4)."""
    try:
        info = ToolRegistry().get_tool(tool)
    except Exception:  # Acceptable: registry may not be initialised
        return None
    return info.version if info else None


def _tool_version(tool: str, runs: list[dict[str, Any]]) -> str:
    registry = _registry_version(tool)
    if registry:
        return str(registry)
    driver = _driver(runs[0]) if runs else {}
    for key in ("version", "semanticVersion"):
        value = driver.get(key)
        if isinstance(value, str) and value:
            return value
    return "unknown"


def _driver(run: dict[str, Any]) -> dict[str, Any]:
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    return driver if isinstance(driver, dict) else {}


def _rules(run: dict[str, Any]) -> list[Any]:
    rules = _driver(run).get("rules")
    return rules if isinstance(rules, list) else []


def _rule_for(result: dict[str, Any], rules: list[Any]) -> dict[str, Any]:
    """By ``ruleIndex`` when supplied and in range, else by ``rules[].id ==
    result.ruleId`` (section 2.3: osv-scanner sets the index, zizmor and
    gitleaks do not)."""
    index = result.get("ruleIndex")
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules):
        candidate = rules[index]
        if isinstance(candidate, dict):
            return candidate
    rule_id = result.get("ruleId")
    if rule_id is not None:
        for candidate in rules:
            if isinstance(candidate, dict) and candidate.get("id") == rule_id:
                return candidate
    return {}


# --- severity ----------------------------------------------------------------


def _props(holder: dict[str, Any]) -> dict[str, Any]:
    props = holder.get("properties")
    return props if isinstance(props, dict) else {}


def _security_severity(holders: tuple[dict[str, Any], ...]) -> float | None:
    """Rank 1: GitHub's ``security-severity`` (a CVSS base score as a string),
    on the result first, then on the rule. A non-numeric value is ignored."""
    for holder in holders:
        raw = _props(holder).get("security-severity")
        if raw is None or isinstance(raw, bool):
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            logger.debug("ignoring non-numeric security-severity %r", raw)
    return None


def _severity_property(holders: tuple[dict[str, Any], ...]) -> str | None:
    """Rank 2: a property named ``severity`` or ending in ``/severity``
    (``zizmor/severity`` and any future ``<tool>/severity``)."""
    for holder in holders:
        for key, value in _props(holder).items():
            if (key == "severity" or key.endswith("/severity")) and isinstance(value, str):
                return value
    return None


def _bucket(score: float) -> str:
    for floor, severity in _CVSS_BUCKETS:
        if score >= floor:
            return severity
    return "LOW" if score > 0.0 else "INFO"


def _resolve_severity(
    result: dict[str, Any], rule: dict[str, Any]
) -> tuple[str, dict[str, float] | None]:
    """Section 3.2, first hit wins. Returns ``(severity, cvss-or-None)``."""
    holders = (result, rule)
    score = _security_severity(holders)
    if score is not None:
        return _bucket(score), {"score": score}
    prop = _severity_property(holders)
    if prop is not None:
        return normalize_severity(prop), None
    level = result.get("level")
    if isinstance(level, str) and level:
        return normalize_severity(level), None
    default = rule.get("defaultConfiguration")
    default_level = default.get("level") if isinstance(default, dict) else None
    if isinstance(default_level, str) and default_level:
        return normalize_severity(default_level), None
    return normalize_severity("warning"), None  # SARIF's documented default


# --- location ----------------------------------------------------------------


def _decode_uri(uri: str) -> str:
    """``file:`` URIs become plain paths; anything else passes through unchanged."""
    if not uri.lower().startswith("file:"):
        return uri
    parts = urlsplit(uri)
    path = unquote(parts.path)
    if parts.netloc and parts.netloc.lower() != "localhost":
        return f"//{parts.netloc}{path}"
    if len(path) >= 3 and path[0] == "/" and path[1].isalpha() and path[2] == ":":
        path = path[1:]  # `/C:/x` -> `C:/x`
    return path


def _location(result: dict[str, Any]) -> dict[str, Any]:
    locations = result.get("locations")
    physical: dict[str, Any] = {}
    if isinstance(locations, list) and locations and isinstance(locations[0], dict):
        candidate = locations[0].get("physicalLocation")
        if isinstance(candidate, dict):
            physical = candidate
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    location: dict[str, Any] = {"path": _decode_uri(uri) if isinstance(uri, str) else ""}
    region = physical.get("region")
    if isinstance(region, dict):
        for key in ("startLine", "endLine", "startColumn", "endColumn"):
            value = region.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                location[key] = value
    return location


# --- fields ------------------------------------------------------------------


def _text(holder: dict[str, Any], key: str) -> str | None:
    value = holder.get(key)
    if isinstance(value, dict):
        text = value.get("text")
        return text if isinstance(text, str) and text else None
    return None


def _finding(
    result: dict[str, Any],
    rules: list[Any],
    spec: SarifToolSpec,
    tool_version: str,
) -> Finding:
    rule = _rule_for(result, rules)
    rule_id = str(result.get("ruleId") or rule.get("id") or "SARIF")
    message = _text(result, "message") or ""
    title = str(rule.get("name") or _text(rule, "shortDescription") or rule_id)
    description = _text(rule, "fullDescription") or _text(rule, "shortDescription") or message
    severity, cvss = _resolve_severity(result, rule)
    location = _location(result)

    tags = list(spec.tags)
    for tag in _props(rule).get("tags") or []:
        if isinstance(tag, str) and tag not in tags:
            tags.append(tag)
    help_uri = rule.get("helpUri")

    return Finding(
        schemaVersion="1.2.0",
        id=fingerprint(spec.tool, rule_id, location["path"], location.get("startLine"), message),
        ruleId=rule_id,
        severity=severity,
        tool={"name": spec.tool, "version": tool_version},
        location=location,
        message=message,
        title=title,
        description=description,
        remediation=_text(rule, "help") or "See rule documentation",
        references=[help_uri] if isinstance(help_uri, str) and help_uri else [],
        tags=tags,
        cvss=cvss,
        raw=result,
    )
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv/Scripts/python.exe -m pytest tests/adapters/test_sarif_common.py -q -p no:cacheprovider`
Expected: all pass.

- [ ] **Step 5: Mutate one guard, watch a test fail, restore from backup**

Copy the file to the scratchpad first. Change `return "LOW" if score > 0.0 else "INFO"`
to `return "LOW"`; `test_rank1_security_severity_buckets[0.0]` must fail. Restore by
copying the backup over the file, never `git checkout --`.

- [ ] **Step 6: Lint, then commit**

```bash
.venv/Scripts/pre-commit.exe run --files scripts/core/adapters/sarif_common.py tests/adapters/test_sarif_common.py
git add scripts/core/adapters/sarif_common.py tests/adapters/test_sarif_common.py
git commit -m "feat(adapters): add the generic SARIF 2.1.0 importer"
```

### Task A2: the three bindings, golden fixtures, registry entries

**Files:**
- Create: `scripts/core/adapters/zizmor_adapter.py`, `gitleaks_adapter.py`, `osv_scanner_adapter.py`
- Create: `tests/adapters/test_zizmor_adapter.py`, `test_gitleaks_adapter.py`, `test_osv_scanner_adapter.py`
- Create: `tests/fixtures/golden/{zizmor/v1.30.1,gitleaks/v8.30.1,osv_scanner/v2.5.1}/expected-findings.json`
- Modify: `tests/adapters/test_adapter_golden.py` `ADAPTER_REGISTRY` (after the `trivy_rbac` entry)

**Interfaces:**
- Consumes: `parse_sarif`, `SarifToolSpec` from Task A1.
- Produces: registry names `zizmor`, `gitleaks`, `osv_scanner`; `tool_name` `zizmor`,
  `gitleaks`, `osv-scanner`. `loader._tool_to_adapter_name("osv-scanner")` already
  yields `osv_scanner`, so `osv-scanner.json` routes without a loader change.

- [ ] **Step 1: Write the failing binding tests** (one file per tool; zizmor shown, the
  other two differ only in the names, tags and fixture directory)

```python
"""Tests for the zizmor binding: registration and delegation to the SARIF importer."""

from __future__ import annotations

from pathlib import Path

from scripts.core.adapters.zizmor_adapter import ZizmorAdapter
from scripts.core.plugin_loader import PluginLoader, PluginRegistry

GOLDEN = Path("tests/fixtures/golden/zizmor/v1.30.1/raw-output.json")


def test_registers_under_its_file_stem():
    loader = PluginLoader(PluginRegistry())
    name = loader._load_plugin(Path("scripts/core/adapters/zizmor_adapter.py").resolve())
    assert name == "zizmor"
    assert loader.registry.get("zizmor") is ZizmorAdapter
    meta = ZizmorAdapter().metadata
    assert (meta.tool_name, meta.output_format) == ("zizmor", "sarif")


def test_parses_the_golden_document_with_the_binding_tags():
    findings = ZizmorAdapter().parse(GOLDEN)
    assert len(findings) == 217
    assert all(f.tool["name"] == "zizmor" for f in findings)
    assert all({"github-actions", "workflow", "sarif"} <= set(f.tags) for f in findings)
    assert all("://" not in f.location["path"] for f in findings)
```

gitleaks: `GitleaksAdapter`, stem `gitleaks`, tool_name `gitleaks`, 69 findings,
tags `{"secrets", "sarif"}`, plus `assert all(f.tool["version"] == "v8.0.0" ...)`
(measured: no `driver.version`, `semanticVersion` is `v8.0.0`, no registry row).
osv_scanner: `OsvScannerAdapter`, stem `osv_scanner`, tool_name `osv-scanner`, 303
findings, tags `{"sca", "vulnerability", "sarif"}`, plus
`assert all("startLine" not in f.location for f in findings)` and
`assert sum(1 for f in findings if f.cvss) == 285`.

- [ ] **Step 2: Run to verify failure** — ImportError for each binding module.

- [ ] **Step 3: Write the bindings** (zizmor shown; the other two substitute the
  values from Step 1. Every line counts toward the "one ~25-line file" gate.)

```python
"""zizmor (GitHub Actions auditor) -- SARIF binding.

One SarifToolSpec against sarif_common.parse_sarif; nothing else. Adding a
fourth SARIF tool is another file of this shape.
"""

from __future__ import annotations

from pathlib import Path

from scripts.core.adapters.sarif_common import SarifToolSpec, parse_sarif
from scripts.core.plugin_api import AdapterPlugin, Finding, PluginMetadata, adapter_plugin

_SPEC = SarifToolSpec(tool="zizmor", tags=("github-actions", "workflow", "sarif"))


@adapter_plugin(
    PluginMetadata(
        name="zizmor",
        version="1.0.0",
        description="Adapter for zizmor GitHub Actions auditor (SARIF)",
        tool_name="zizmor",
        schema_version="1.2.0",
        output_format="sarif",
        exit_codes={0: "clean", 14: "findings"},
    )
)
class ZizmorAdapter(AdapterPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        return parse_sarif(output_path, _SPEC)
```

gitleaks: `exit_codes={0: "clean", 1: "findings"}`; osv_scanner:
`exit_codes={0: "clean", 1: "findings"}`, `name="osv_scanner"`, `tool_name="osv-scanner"`.

- [ ] **Step 4: Run the binding tests** — pass.

- [ ] **Step 5: Generate `expected-findings.json` the way `generate_golden.py` does**
  (`asdict(f)`, `json.dump(indent=2, default=str)`, written as bytes, LF):

```python
# scratchpad/gen_expected.py -- run from the repo root
import json
from dataclasses import asdict
from pathlib import Path
from scripts.core.adapters.zizmor_adapter import ZizmorAdapter
from scripts.core.adapters.gitleaks_adapter import GitleaksAdapter
from scripts.core.adapters.osv_scanner_adapter import OsvScannerAdapter
for cls, d in [(ZizmorAdapter, "zizmor/v1.30.1"), (GitleaksAdapter, "gitleaks/v8.30.1"), (OsvScannerAdapter, "osv_scanner/v2.5.1")]:
    root = Path("tests/fixtures/golden") / d
    findings = cls().parse(root / "raw-output.json")
    out = json.dumps([asdict(f) for f in findings], indent=2, default=str) + "\n"
    (root / "expected-findings.json").write_bytes(out.encode("utf-8"))
    print(d, len(findings))
```

Expected: 217 / 69 / 303 (the adapter emits one finding per result; dedup is the
report phase's).

- [ ] **Step 6: Register in the golden harness**

```python
    # Phase 1 of the v2.0.0 program: the three SARIF bindings. Each is ~25 lines
    # over `sarif_common.parse_sarif`, so a regression here is the importer's.
    "zizmor": {"module": "scripts.core.adapters.zizmor_adapter", "class": "ZizmorAdapter"},
    "gitleaks": {"module": "scripts.core.adapters.gitleaks_adapter", "class": "GitleaksAdapter"},
    "osv_scanner": {"module": "scripts.core.adapters.osv_scanner_adapter", "class": "OsvScannerAdapter"},
```

- [ ] **Step 7: Run the golden suite**

Run: `.venv/Scripts/python.exe -m pytest tests/adapters/test_adapter_golden.py -q -p no:cacheprovider`
Expected: 3 new `-v1.30.1` / `-v8.30.1` / `-v2.5.1` cases pass in all three parametrized
tests; `test_adapter_registry_completeness` passes.

- [ ] **Step 8: Lint, EOL check, commit**

```bash
.venv/Scripts/pre-commit.exe run --files scripts/core/adapters/*_adapter.py tests/adapters/test_*_adapter.py tests/adapters/test_adapter_golden.py
git add scripts/core/adapters/zizmor_adapter.py scripts/core/adapters/gitleaks_adapter.py scripts/core/adapters/osv_scanner_adapter.py tests/adapters/test_zizmor_adapter.py tests/adapters/test_gitleaks_adapter.py tests/adapters/test_osv_scanner_adapter.py tests/adapters/test_adapter_golden.py tests/fixtures/golden
git diff --cached --numstat > /tmp/a; git diff --cached --ignore-cr-at-eol --numstat > /tmp/b; diff /tmp/a /tmp/b
git commit -m "feat(adapters): bind zizmor, gitleaks and osv-scanner through the SARIF importer"
```

### Task A3: the fourth-tool proof

**Files:**
- Modify: `tests/adapters/test_sarif_common.py` (append)

- [ ] **Step 1: Write the test** — a binding written into a temporary plugin directory,
  loaded by the real loader, parsing a document, with no change to `sarif_common.py`:

```python
FOURTH_TOOL = '''
from pathlib import Path
from scripts.core.adapters.sarif_common import SarifToolSpec, parse_sarif
from scripts.core.plugin_api import AdapterPlugin, Finding, PluginMetadata, adapter_plugin

_SPEC = SarifToolSpec(tool="fourth", tags=("fourth",))

@adapter_plugin(PluginMetadata(name="fourth", version="1.0.0", tool_name="fourth", output_format="sarif"))
class FourthAdapter(AdapterPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> list[Finding]:
        return parse_sarif(output_path, _SPEC)
'''


def test_a_fourth_sarif_tool_is_one_small_file(tmp_path):
    """Spec section 6.4: one new file, no change to sarif_common."""
    from scripts.core.plugin_loader import PluginLoader, PluginRegistry

    plugin = tmp_path / "fourth_adapter.py"
    plugin.write_text(FOURTH_TOOL, encoding="utf-8")
    assert len(FOURTH_TOOL.strip().splitlines()) <= 25

    loader = PluginLoader(PluginRegistry())
    assert loader._load_plugin(plugin) == "fourth"
    adapter = loader.registry.get("fourth")()
    doc = write(tmp_path, sarif([result(level="error")]))
    findings = adapter.parse(doc)
    assert [(f.tool["name"], f.severity, f.tags) for f in findings] == [("fourth", "HIGH", ["fourth"])]
```

- [ ] **Step 2: Run** — pass. **Step 3: Commit**
  `git commit -m "test(adapters): prove a fourth SARIF tool is one small binding file"`.

### Task A4: the §4.3 merge gate through `jmo report`

**Files:**
- Scratchpad only: `scratchpad/sarif_gate.py` (the commands also go into the spec, Task A5)

- [ ] **Step 1: Build four results directories and run `jmo report` on each**

For each tool: `results/<tool>/individual-repos/target/<file>.json` is a copy of the
fixture (`zizmor.json`, `gitleaks.json`, `osv-scanner.json`), and
`results/<tool>/.scan_metadata.json` is `{"repo_paths": ["<absolute target dir>"]}` with
the archived NodeGoat directory for osv so the `file://` path is root-stripped. A fourth
directory holds all three. Then:

```bash
.venv/Scripts/python.exe -m scripts.cli.jmo report results/<tool> --out results/<tool>/summaries
```

- [ ] **Step 2: Count from `summaries/findings.json`, never from the adapter**

```python
import json, collections
f = json.load(open("results/<tool>/summaries/findings.json", encoding="utf-8"))
print(len(f), collections.Counter(x["severity"] for x in f))
```

Record the table. Expected from the spec: zizmor 216 (HIGH 143 / MEDIUM 12 / LOW 49 /
INFO 12); gitleaks 68 (MEDIUM 68); osv 291 (CRITICAL 30 / HIGH 147 / MEDIUM 102 /
LOW 12). Combined run: all three tool names present, no `location.path` containing
`://`, and osv's path is `package-lock.json`.

- [ ] **Step 3: If any number differs, the measurement wins** — correct §4.3 in the
  spec and say so in the PR body; do not tune the code to the table.

### Task A5: documentation (#34)

**Files:**
- Modify: `docs/superpowers/specs/2026-09-12-sarif-importer-design.md` (status line;
  §2.4 gitleaks `driver.version` absent; §4.3 table as measured + the exact commands;
  §5 row for `scan_validator.EXPECTED_ADAPTER_COUNT`)
- Modify: `CONTRIBUTING.md` after the "Creating a New Adapter" section — new
  `### Adding a tool that emits SARIF` with the binding from Task A2 Step 3
- Modify: `.claude/rules/adapters.rules.md` — a "SARIF tools" section: no
  `AdapterPlugin` subclass in `sarif_common.py` and why; bindings import no other
  subclass; they are absent from `test_adapter_malformed.ALL_ADAPTERS` because they raise
  on non-SARIF by design
- Modify: `CLAUDE.md:229`, `CONTRIBUTING.md:1062,1072`, `docs/USER_GUIDE.md:1290` — 27 → 30
- Modify: `CHANGELOG.md` `## [Unreleased]` — `### Added` entry
- Modify: `docs/superpowers/specs/2026-09-12-v2.0.0-program-design.md:268` —
  `.test_durations` row: "reader: pytest-split via `--splits`, `ci.yml:415` — keep"

- [ ] **Step 1: Make the edits with byte-level writes; run
  `.venv/Scripts/python.exe scripts/dev/check_doc_links.py` and pre-commit on the files.**
- [ ] **Step 2: Commit with the closing keyword in the commit message**

```bash
git commit -m "docs: document the SARIF binding path for contributors

Closes #34"
```

### Task A6: verify, push, PR

- [ ] **Step 1:** `.venv/Scripts/pre-commit.exe run --all-files` — green.
- [ ] **Step 2:** bounded suite with `PYTHONUTF8` unset — 0 failed; note the skip count.
- [ ] **Step 3:** `git diff origin/dev --stat -- scripts/core | grep -v adapters/` — empty.
- [ ] **Step 4:** `wc -l scripts/core/adapters/{zizmor,gitleaks,osv_scanner}_adapter.py`.
- [ ] **Step 5:** `.venv/Scripts/python.exe -m scripts.cli.jmo validate --tier quick` —
  record the `adapter-count` line (expected FAIL "Expected 27 adapters, found 30").
- [ ] **Step 6:** `python scripts/dev/phase_audit.py verify` — unclaimed 0.
- [ ] **Step 7:** push; mark PR 1244 ready; rewrite its body with the §4.3 table, the
  validator note and the gates. Read the `windows-2022` job **log** and compare to
  9817 / 98 / 256.

---

# Part B — second PR: column-aware fingerprint, one formula (#1242 #1010)

Branch `feature/fingerprint-column` from `feature/sarif-importer` (PR base
`feature/sarif-importer` until #1244 merges; GitHub retargets it to `dev` then).

### Task B1: measure first

- [ ] `grep -rn "_legacy_plugin_fingerprint\|get_fingerprint" tests/` — list every test
  that pins the legacy formula.
- [ ] `grep -rn '"[0-9a-f]\{16\}"' tests/adapters/test_trivy_adapter.py tests/adapters/test_trufflehog_adapter.py tests/adapters/test_semgrep_adapter.py` — hardcoded ids that change if the formula converges (expected: none; assert, do not assume).
- [ ] Baseline: run `_normalize_paths_and_ids` over shellcheck output with two findings
  of one rule on one line at columns 5 and 20 under an absolute path; record
  `(paths_changed, ids_rekeyed)` and the distinct-id count (expected today: 2, 2, **1**).

### Task B2: `fingerprint(..., start_column=None)`

**Files:** `scripts/core/common_finding.py:193`; `tests/unit/test_common_finding.py` (or
the nearest existing fingerprint test module).

- [ ] Test: `fingerprint("t", "r", "p", 3, "m") == "<hex pinned from today's output>"`
  and `fingerprint("t", "r", "p", 3, "m", start_column=7) != fingerprint("t", "r", "p", 3, "m")`.
- [ ] Implement: append `|{start_column}` to `base` **only when `start_column is not None`**.
- [ ] Commit: `feat(core): make fingerprint() column-aware, opt-in`.

### Task B3: one formula (#1010)

**Files:** `scripts/core/plugin_api.py:144`, `scripts/core/normalize_and_report.py:214,284-300`,
`tests/unit/test_finding_path_normalization.py`.

- [ ] Invert `test_the_two_fingerprint_formulas_agree_except_on_line_and_whitespace` into
  `test_get_fingerprint_is_the_canonical_fingerprint` asserting equality on a **missing
  line** and a **padded message** (the two cases that differ today).
- [ ] `get_fingerprint` delegates to `fingerprint(tool name, ruleId, path, location.get("startLine"), message)`.
- [ ] Delete `_legacy_plugin_fingerprint` and its `elif` branch; delete
  `test_legacy_plugin_fingerprint_formula_is_also_recognised`.
- [ ] Commit: `refactor(core): one fingerprint formula\n\nCloses #1010`.

### Task B4: column-aware re-keying and shellcheck (#1242)

**Files:** `scripts/core/normalize_and_report.py` (`_normalize_paths_and_ids`),
`scripts/core/adapters/shellcheck_adapter.py:210`, tests beside each.

- [ ] Test (normalize): a finding whose id is the 6-component hash under an absolute
  path is re-keyed to the 6-component hash under the relative path; a 5-component id is
  still re-keyed as before.
- [ ] Implement the key chain: for `column = location.get("startColumn")`, try the
  5-component shape first, then, if `column is not None`, the 6-component shape;
  recompute under the same shape.
- [ ] Test (shellcheck): two findings of `SC2086` on one line at columns 5 and 20 yield
  two distinct ids; re-run Task B1's baseline — `(2, 2, 2)`.
- [ ] Implement: `fingerprint("shellcheck", code_str, file_path, start_line, message, start_column=start_column)`.
- [ ] Commit: `fix(core): key findings on their column so two secrets on one line survive dedup\n\nCloses #1242`.

### Task B5: the importer passes the column; the gate moves to 69

**Files:** `scripts/core/adapters/sarif_common.py` (`_finding`), spec §3.4 and §4.3,
regenerated `expected-findings.json` for zizmor and gitleaks (osv has no region).

- [ ] Test in `test_sarif_common.py`: two results on one line at different columns give
  two ids.
- [ ] Implement: `fingerprint(..., message, start_column=location.get("startColumn"))`.
- [ ] Regenerate the two expected files (Task A2 Step 5); counts unchanged.
- [ ] Re-run Task A4: gitleaks **69**, zizmor still 216 (its duplicate is byte-identical,
  same column), osv 291. Update spec §3.4 (the known cost is paid) and §4.3.
- [ ] Commit: `feat(adapters): fingerprint SARIF findings by column`.

### Task B6: verify, PR

Same as Task A6 Steps 1–2 and 6–7, plus `git diff --stat` shows only the files this
part names.

---

## Self-review

- Spec §3.1 module layout → A1, A2. §3.2 chain → A1 tests per rank. §3.3 decoding →
  A1 `test_uri_decoding`. §3.4 canonical fingerprint → A1; column deferred → B5.
  §3.5 mapping → A1 field tests. §3.6 raise + version warning → A1. §4.1 fixtures →
  A2. §4.2 cases → A1 (all seven bullets). §4.3 gate → A4. §6.2 → A6 Step 3.
  §6.4 → A3. Phase 1 acceptance "second PR" → B1–B6. #34 → A5.
- Program plan's "shellcheck golden count is unchanged": **there is no shellcheck golden
  fixture** (measured: `tests/fixtures/golden/` has none). B1/B4 substitute the
  measured re-key triple.
- Types: `SarifToolSpec.tags` is a tuple everywhere; `parse_sarif` takes `Path`;
  `fingerprint`'s new parameter is keyword `start_column`.
