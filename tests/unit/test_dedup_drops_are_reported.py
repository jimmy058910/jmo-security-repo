"""Regression tests for #848 - a discarded finding must not be silent.

Both dedup functions tested `if fingerprint and fingerprint not in seen`, so a
finding with a missing or empty `id` failed the first half and was **dropped
entirely** - not deduplicated, discarded - with no log record at any level and
no count in the report to compare against.

Two things measured while fixing it, both of which change the issue's framing:

- `docs/schemas/common_finding.v1.json` already carries `minLength: 1` on `id`
  and names #848 in its description, so #843's gap is closed.
- But **nothing between the adapters and dedup validates against that schema**.
  `schema_validator` is reached only by `jmo validate` and the YAML reporter.
  The contract is documented, not enforced, so this path is reachable today by
  any adapter that ships a falsy id.

The drop is deliberately kept. A finding with no id cannot be deduplicated,
suppressed, diffed or referenced, and `calculate_priorities_bulk` reads
`finding["id"]` unguarded. What #848 changes is that it is counted and named.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from scripts.core import normalize_and_report as nr

DEDUPERS = [
    nr.deduplicate_findings_memory_efficient,
    nr.deduplicate_findings_streaming,
]
IDS = ["memory_efficient", "streaming"]


def _finding(fid, tool="bandit"):
    return {"id": fid, "tool": {"name": tool}, "message": "m"}


@pytest.mark.parametrize("dedupe", DEDUPERS, ids=IDS)
@pytest.mark.parametrize("bad_id", ["", None], ids=["empty", "missing"])
def test_a_dropped_finding_is_reported_at_warning(dedupe, bad_id, caplog):
    findings = [_finding("keep"), _finding(bad_id)]

    with caplog.at_level(logging.WARNING, logger=nr.logger.name):
        kept = dedupe(findings)

    assert [f["id"] for f in kept] == ["keep"]
    records = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert records, "a discarded finding produced no record at WARNING or above"
    text = records[0].getMessage()
    assert "1 finding" in text, text
    assert "bandit" in text, "the record must name the tool that lost a finding"
    assert "MISSING" in text, text


@pytest.mark.parametrize("dedupe", DEDUPERS, ids=IDS)
def test_the_count_and_the_tools_are_both_right(dedupe, caplog):
    findings = [
        _finding("keep"),
        _finding("", tool="bandit"),
        _finding("", tool="semgrep"),
        _finding(None, tool="semgrep"),
    ]

    with caplog.at_level(logging.WARNING, logger=nr.logger.name):
        kept = dedupe(findings)

    assert len(kept) == 1
    text = caplog.records[0].getMessage()
    assert "3 finding" in text, text
    assert "bandit=1" in text and "semgrep=2" in text, text


@pytest.mark.parametrize("dedupe", DEDUPERS, ids=IDS)
def test_a_healthy_scan_says_nothing(dedupe, caplog):
    """The negative control.

    #843 measured 0 of 264 real findings with an empty id, so this fires on
    approximately no real scan. A warning that appears on every run is the
    always-fires shape #784 removed.
    """
    with caplog.at_level(logging.DEBUG, logger=nr.logger.name):
        kept = dedupe([_finding("a"), _finding("b"), _finding("a")])

    assert [f["id"] for f in kept] == ["a", "b"], "dedup itself must still work"
    assert not [r for r in caplog.records if "no id" in r.getMessage()]


@pytest.mark.parametrize("dedupe", DEDUPERS, ids=IDS)
def test_a_finding_with_no_tool_is_still_counted(dedupe, caplog):
    with caplog.at_level(logging.WARNING, logger=nr.logger.name):
        dedupe([{"id": ""}])
    assert "unknown=1" in caplog.records[0].getMessage()


def test_both_dedupers_behave_identically_on_the_same_input():
    """Two copies of a data-loss path is how one gets fixed and the other does not."""
    findings = [_finding("a"), _finding(""), _finding("a"), _finding(None)]
    assert nr.deduplicate_findings_memory_efficient(list(findings)) == (
        nr.deduplicate_findings_streaming(list(findings))
    )


def test_the_schema_documents_the_contract_this_guard_enforces():
    """Pins the relationship, so neither half can drift alone.

    If `minLength` is ever removed from `id`, the schema stops describing what
    the pipeline does - and since nothing validates on this path, the schema is
    the only place a reader would learn the rule.
    """
    schema = json.loads(
        Path("docs/schemas/common_finding.v1.json").read_text(encoding="utf-8")
    )
    assert schema["properties"]["id"].get("minLength") == 1
    assert "id" in schema["required"]
