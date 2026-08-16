"""Diff identity, risk direction, and malformed-input reporting.

Every test here corresponds to a defect measured against real scans during the
chunk-12 audit. Each names what was observed, so a future reader can tell the
guard from the wallpaper.
"""

from __future__ import annotations

import json
import logging

import pytest

from scripts.core.diff_engine import (
    CLUSTER_ID_PREFIX,
    PRIORITY_CHANGE_THRESHOLD,
    DiffEngine,
)


def finding(fid, severity="HIGH", message="msg", **extra):
    f = {
        "id": fid,
        "severity": severity,
        "message": message,
        "ruleId": "R1",
        "tool": {"name": "bandit"},
        "location": {"path": "a.py", "startLine": 1},
    }
    f.update(extra)
    return f


def consensus(rep_id, duplicate_ids, **extra):
    """A finding shaped like one `dedup_enhanced` produces for a cluster."""
    f = finding(f"{CLUSTER_ID_PREFIX}{rep_id}", **extra)
    f["context"] = {
        "duplicates": [{"id": d, "tool": {"name": "semgrep"}} for d in duplicate_ids],
        "cluster_size": 1 + len(duplicate_ids),
    }
    f["detected_by"] = [{"name": "bandit"}, {"name": "semgrep"}]
    return f


class TestClusterIdentity:
    """#847 -- clustering must not change a finding's diff identity.

    Measured end to end before the fix, running the real report pipeline over
    two results directories differing only in whether a second tool also
    reported one issue: `jmo diff` returned 1 new and 1 resolved for the same
    B602 shell-injection finding -- same rule, message, file and line, the ids
    differing only by the `cluster-` prefix. Read as a report, it said a real
    vulnerability had been fixed.
    """

    def test_finding_that_joins_a_cluster_is_unchanged(self):
        engine = DiffEngine()
        result = engine._compare_findings(
            [finding("abc123")],
            [consensus("abc123", ["def456"])],
            None,
            None,
        )
        assert result.statistics["total_resolved"] == 0
        assert result.statistics["total_new"] == 0
        assert result.statistics["total_unchanged"] == 1

    def test_finding_that_leaves_a_cluster_is_unchanged(self):
        """The reverse direction: a tool stops reporting, the cluster dissolves."""
        engine = DiffEngine()
        result = engine._compare_findings(
            [consensus("abc123", ["def456"])],
            [finding("abc123")],
            None,
            None,
        )
        assert result.statistics["total_resolved"] == 0
        assert result.statistics["total_new"] == 0
        assert result.statistics["total_unchanged"] == 1

    def test_matches_on_a_duplicate_when_the_representative_changes(self):
        """The cluster's representative is not stable between scans.

        `_get_highest_severity` picks it, so a severity change in either member
        can swap which finding represents the cluster. Matching on the
        `context.duplicates` ids as well as the prefix survives that; matching
        on the prefix alone would not.
        """
        engine = DiffEngine()
        result = engine._compare_findings(
            [consensus("aaa", ["bbb"])],
            [consensus("bbb", ["aaa"])],
            None,
            None,
        )
        assert result.statistics["total_resolved"] == 0
        assert result.statistics["total_new"] == 0
        assert result.statistics["total_unchanged"] == 1

    def test_a_genuinely_new_cluster_is_still_new(self):
        """Negative control: the fix must not swallow real changes."""
        engine = DiffEngine()
        result = engine._compare_findings(
            [finding("abc123")],
            [finding("abc123"), consensus("zzz999", ["yyy888"])],
            None,
            None,
        )
        assert result.statistics["total_new"] == 1
        assert result.statistics["total_resolved"] == 0
        assert result.statistics["total_unchanged"] == 1

    def test_a_genuinely_resolved_finding_is_still_resolved(self):
        """Second negative control, in the other direction."""
        engine = DiffEngine()
        result = engine._compare_findings(
            [finding("abc123"), finding("gone111")],
            [finding("abc123")],
            None,
            None,
        )
        assert result.statistics["total_resolved"] == 1
        assert result.resolved[0]["id"] == "gone111"

    def test_a_cluster_counts_once_not_once_per_member(self):
        """Classification is per finding, not per covered fingerprint."""
        engine = DiffEngine()
        result = engine._compare_findings(
            [finding("aaa"), finding("bbb")],
            [consensus("aaa", ["bbb"])],
            None,
            None,
        )
        stats = result.statistics
        assert stats["total_unchanged"] == 1
        assert stats["total_new"] == 0
        # Both baseline findings are accounted for by the one cluster, so
        # neither is reported as fixed.
        assert stats["total_resolved"] == 0


class TestRiskDelta:
    """The direction reported beside a change must agree with the change."""

    @pytest.mark.parametrize(
        ("baseline_sev", "current_sev", "expected"),
        [
            ("MEDIUM", "HIGH", "worsened"),
            ("HIGH", "MEDIUM", "improved"),
            ("CRITICAL", "HIGH", "improved"),
            ("LOW", "CRITICAL", "worsened"),
            ("INFO", "LOW", "worsened"),
        ],
    )
    def test_one_step_severity_change_is_decisive_with_a_stable_priority(
        self, baseline_sev, current_sev, expected
    ):
        """A severity move settles the direction even when priority does not move.

        The old weighted score gave one step exactly +/-0.5 and compared with a
        strict `> 0.5`, so any finding carrying an EPSS or CVSS score -- which
        pins priority independently of severity -- came out "unchanged". The
        generated Markdown printed the contradiction on one line:
        "Severity: MEDIUM -> **HIGH** (unchanged)".
        """
        engine = DiffEngine()
        baseline = {"severity": baseline_sev, "risk": {"epss_score": 0.5}}
        current = {"severity": current_sev, "risk": {"epss_score": 0.5}}
        assert engine._calculate_risk_delta(baseline, current) == expected

    def test_compliance_mappings_alone_do_not_report_worsened(self):
        """Gaining a framework mapping is better labelling, not more risk.

        At the old weight of 0.2 per mapping, three additions crossed the
        threshold on their own. That matters for this release specifically:
        v1.1.0's compliance fix took several mapping tables from 0 matches to
        dozens, so upgrading would have reported large numbers of untouched
        findings as having worsened.
        """
        engine = DiffEngine()
        baseline = {"severity": "HIGH", "compliance": {}}
        current = {
            "severity": "HIGH",
            "compliance": {"owaspTop10_2021": ["A01", "A02", "A03", "A04", "A05"]},
        }
        assert engine._calculate_risk_delta(baseline, current) == "unchanged"

    def test_priority_still_decides_when_severity_is_unchanged(self):
        """Negative control: the fallback must not be dead."""
        engine = DiffEngine()
        base = {"severity": "HIGH", "risk": {"epss_score": 0.10}}
        worse = {"severity": "HIGH", "risk": {"epss_score": 0.90}}
        assert engine._calculate_risk_delta(base, worse) == "worsened"
        assert engine._calculate_risk_delta(worse, base) == "improved"

    def test_priority_below_the_threshold_is_unchanged(self):
        """Second control: the threshold is real, not decorative."""
        engine = DiffEngine()
        step = (PRIORITY_CHANGE_THRESHOLD - 1) / 100
        base = {"severity": "HIGH", "risk": {"epss_score": 0.50}}
        nudged = {"severity": "HIGH", "risk": {"epss_score": 0.50 + step}}
        assert engine._calculate_risk_delta(base, nudged) == "unchanged"


class TestMalformedInputIsReported:
    """A corrupt baseline must not read as a clean one."""

    def _dir(self, tmp_path, name, payload):
        d = tmp_path / name
        (d / "summaries").mkdir(parents=True)
        path = d / "summaries" / "findings.json"
        path.write_text(
            payload if isinstance(payload, str) else json.dumps(payload),
            encoding="utf-8",
        )
        return d

    def test_findings_as_a_string_raises_instead_of_reading_as_empty(self, tmp_path):
        """`{"findings": "oops"}` used to become one finding per character.

        Each was then dropped further down, so the diff reported every finding
        in the other scan as new -- a corrupt baseline that looked like a clean
        sweep.
        """
        engine = DiffEngine()
        bad = self._dir(tmp_path, "bad", {"meta": {}, "findings": "oops"})
        good = self._dir(tmp_path, "good", {"meta": {}, "findings": [finding("a")]})
        with pytest.raises(ValueError, match="to be a list"):
            engine.compare_directories(bad, good)

    def test_non_object_entries_are_reported(self, tmp_path, caplog):
        caplog.set_level(logging.DEBUG)
        engine = DiffEngine()
        bad = self._dir(
            tmp_path, "bad", {"meta": {}, "findings": ["notadict", finding("a")]}
        )
        good = self._dir(tmp_path, "good", {"meta": {}, "findings": [finding("a")]})
        engine.compare_directories(bad, good)
        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings, "a non-object finding was discarded with no record"
        assert "not objects" in caplog.text

    def test_a_healthy_pair_logs_no_warning(self, tmp_path, caplog):
        """Negative control -- the report must not fire on every clean run."""
        caplog.set_level(logging.DEBUG)
        engine = DiffEngine()
        a = self._dir(tmp_path, "a", {"meta": {}, "findings": [finding("x")]})
        b = self._dir(tmp_path, "b", {"meta": {}, "findings": [finding("x")]})
        engine.compare_directories(a, b)
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []

    def test_findings_with_no_usable_id_are_counted_and_reported(self, caplog):
        """They are unclassifiable, and were previously invisible.

        A finding with no `id` key was dropped from both indexes with zero log
        records at any level; one with `id: ""` or `id: null` was indexed under
        a falsy key and reported as *resolved*, i.e. as fixed.
        """
        caplog.set_level(logging.DEBUG)
        engine = DiffEngine()
        baseline = [
            finding("keep"),
            {"severity": "HIGH", "message": "no id at all"},
            {"id": "", "severity": "HIGH", "message": "empty id"},
            {"id": None, "severity": "HIGH", "message": "null id"},
        ]
        result = engine._compare_findings(baseline, [finding("keep")], None, None)
        stats = result.statistics
        assert stats["total_resolved"] == 0, "an unclassifiable finding read as fixed"
        assert stats["total_unchanged"] == 1

        # The record must be at WARNING, not DEBUG. `_build_identity_lookup`
        # also leaves a DEBUG breadcrumb whose text contains both "no usable
        # id" and the count, so asserting on `caplog.text` alone passes with
        # the user-visible warning removed -- which is the whole point of the
        # fix. A mutation removing the WARNING survived until this asserted
        # the level.
        warnings = [
            r
            for r in caplog.records
            if r.levelno >= logging.WARNING and "no usable id" in r.getMessage()
        ]
        assert warnings, "the drop was reported only at DEBUG, i.e. invisibly"
        assert "3 baseline" in warnings[0].getMessage()
        assert "0 current" in warnings[0].getMessage()
