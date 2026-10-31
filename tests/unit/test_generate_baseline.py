"""Unit tests for scripts/dev/generate_baseline.py, the tool that derives the
juice-shop and WebGoat baselines.

The scan and the clone are replaced with fakes: what is under test is how
findings become baseline rows and metadata, and that what the generator records
is exactly what tests/integration/test_baseline_validation.py then asserts.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.dev import generate_baseline as gb
from tests.integration.targets import JUICE_SHOP_COMMIT, PINNED_TARGETS
from tests.integration.test_baseline_validation import compare_to_baseline

SQLI_TITLED = (
    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
)


def finding(tool="opengrep", severity="HIGH", cwe=None, detected_by=None):
    item = {"tool": {"name": tool}, "severity": severity, "ruleId": f"{tool}.rule"}
    if cwe is not None:
        item["risk"] = {"cwe": cwe}
    if detected_by:
        item["detected_by"] = [{"name": name} for name in detected_by]
    return item


class TestCategorizeFindings:
    def test_one_row_per_bare_cwe_across_both_spellings(self):
        rows = gb.categorize_findings(
            [
                finding(cwe=["CWE-89"]),
                finding(cwe=[SQLI_TITLED]),
                finding(cwe=["89"]),
            ]
        )
        assert [(r["rule_id"], r["min_count"]) for r in rows] == [("CWE-89", 3)]

    def test_a_finding_counts_once_per_distinct_cwe(self):
        rows = gb.categorize_findings([finding(cwe=["CWE-89", SQLI_TITLED, "CWE-79"])])
        assert {r["rule_id"]: r["min_count"] for r in rows} == {
            "CWE-89": 1,
            "CWE-79": 1,
        }

    def test_severities_pool_to_the_highest_seen(self):
        rows = gb.categorize_findings(
            [
                finding(severity="LOW", cwe=["CWE-79"]),
                finding(severity="CRITICAL", cwe=["CWE-79"]),
                finding(severity="MEDIUM", cwe=["CWE-79"]),
            ]
        )
        assert rows == [
            {
                "rule_id": "CWE-79",
                "severity": "CRITICAL",
                "category": "xss",
                "min_count": 3,
            }
        ]

    def test_category_falls_back_to_the_cwe_number(self):
        rows = gb.categorize_findings([finding(cwe=["CWE-1004"])])
        assert rows[0]["category"] == "cwe-1004"

    def test_findings_without_a_cwe_produce_no_row(self):
        assert gb.categorize_findings([finding(), finding(cwe=None)]) == []

    def test_rows_run_most_common_first_then_by_cwe_number(self):
        rows = gb.categorize_findings(
            [
                finding(cwe=["CWE-79"]),
                finding(cwe=["CWE-22"]),
                finding(cwe=["CWE-798"]),
                finding(cwe=["CWE-798"]),
                finding(cwe=["CWE-100"]),
            ]
        )
        assert [r["rule_id"] for r in rows] == [
            "CWE-798",
            "CWE-22",
            "CWE-79",
            "CWE-100",
        ]

    def test_every_derived_row_is_met_by_the_findings_it_came_from(self):
        """The generator and the test count CWEs the same way, or a fresh baseline fails."""
        findings = [
            finding(severity="HIGH", cwe=["CWE-89", SQLI_TITLED]),
            finding(severity="CRITICAL", cwe=[SQLI_TITLED]),
            finding(severity="MEDIUM", cwe=["CWE-79"]),
            finding(tool="gitleaks", cwe=["CWE-798"]),
            finding(),
        ]
        baseline = {
            "metadata": {"target": "t/t"},
            "expected_findings": gb.categorize_findings(findings),
            "tolerance": gb.calculate_tolerance(),
        }
        assert compare_to_baseline(findings, baseline).missing_rules == []

    def test_a_row_is_missed_when_the_findings_shrink(self):
        """Negative control: the comparison above is not vacuous."""
        findings = [finding(cwe=["CWE-79"]), finding(cwe=["CWE-79"])]
        baseline = {
            "metadata": {"target": "t/t"},
            "expected_findings": gb.categorize_findings(findings),
            "tolerance": gb.calculate_tolerance(),
        }
        assert compare_to_baseline(findings[:1], baseline).missing_rules == [
            "CWE-79 (expected 2, found 1)"
        ]


def test_tolerance_allows_no_missing_row():
    tolerance = gb.calculate_tolerance()
    assert tolerance["missing_critical"] == 0
    assert tolerance["missing_high"] == 0
    assert tolerance["missing_medium"] == 0


class TestGenerateBaseline:
    def _fake_scan(self, monkeypatch, findings, returncode=0, stderr=""):
        calls = {}

        def fake_clone(url, commit, dest):
            calls["clone"] = (url, commit, dest.name)
            dest.mkdir(parents=True)

        def fake_run_scan(target_path, results_dir):
            calls["scan"] = (target_path, results_dir)
            summaries = results_dir / "summaries"
            summaries.mkdir(parents=True)
            payload = {"meta": {}, "findings": findings}
            (summaries / "findings.json").write_bytes(json.dumps(payload).encode())
            return subprocess.CompletedProcess([], returncode, "", stderr)

        monkeypatch.setattr(gb, "clone_at_commit", fake_clone)
        monkeypatch.setattr(gb, "run_scan", fake_run_scan)
        return calls

    FINDINGS = [
        finding(tool="opengrep", cwe=["CWE-79"]),
        finding(
            tool="gitleaks", cwe=["CWE-798"], detected_by=["gitleaks", "trufflehog"]
        ),
        finding(tool="trivy"),
    ]

    def test_a_known_target_is_cloned_at_its_pin(self, monkeypatch):
        calls = self._fake_scan(monkeypatch, self.FINDINGS)
        baseline = gb.generate_baseline("juice-shop")
        assert calls["clone"] == (
            PINNED_TARGETS["juice-shop"].url,
            JUICE_SHOP_COMMIT,
            "juice-shop",
        )
        assert baseline["metadata"]["target"] == "juice-shop/juice-shop"
        assert baseline["metadata"]["version"] == JUICE_SHOP_COMMIT

    def test_metadata_counts_tools_by_every_reporting_tool(self, monkeypatch):
        self._fake_scan(monkeypatch, self.FINDINGS)
        metadata = gb.generate_baseline("webgoat")["metadata"]
        assert metadata["findings_per_tool"] == {
            "gitleaks": 1,
            "opengrep": 1,
            "trivy": 1,
            "trufflehog": 1,
        }
        assert metadata["tools_used"] == sorted(metadata["findings_per_tool"])
        assert metadata["finding_count"] == 3

    def test_a_local_directory_is_scanned_where_it_is(self, monkeypatch, tmp_path):
        calls = self._fake_scan(monkeypatch, self.FINDINGS)
        baseline = gb.generate_baseline(str(tmp_path))
        assert "clone" not in calls
        assert calls["scan"][0] == tmp_path.resolve()
        assert baseline["metadata"]["version"] == "local"

    def test_an_unknown_target_names_the_pinned_ones(self):
        with pytest.raises(ValueError, match="juice-shop"):
            gb.generate_baseline("dvwa")

    def test_a_failed_scan_raises_with_stderr(self, monkeypatch):
        self._fake_scan(monkeypatch, self.FINDINGS, returncode=2, stderr="tool x died")
        with pytest.raises(RuntimeError, match=r"(?s)exited 2.*tool x died"):
            gb.generate_baseline("juice-shop")

    def test_a_scan_that_finds_nothing_raises(self, monkeypatch):
        self._fake_scan(monkeypatch, [])
        with pytest.raises(RuntimeError, match="found nothing"):
            gb.generate_baseline("juice-shop")


class TestMain:
    def _run(self, monkeypatch, output: Path):
        baseline = {
            "metadata": {
                "target": "t/t",
                "version": "local",
                "generated": "2026-10-30T00:00:00Z",
            },
            "expected_findings": [],
            "tolerance": gb.calculate_tolerance(),
        }
        monkeypatch.setattr(gb, "generate_baseline", lambda target: baseline)
        monkeypatch.setattr(
            sys, "argv", ["generate_baseline", "--target", "x", "--output", str(output)]
        )
        assert gb.main() == 0

    def test_writes_lf_with_a_trailing_newline_to_a_new_file(
        self, monkeypatch, tmp_path
    ):
        out = tmp_path / "new.baseline.json"
        self._run(monkeypatch, out)
        data = out.read_bytes()
        assert data.endswith(b"}\n") and b"\r" not in data

    def test_keeps_the_crlf_an_existing_file_has(self, monkeypatch, tmp_path):
        # The committed baselines are CRLF; a rewrite as LF would read as a
        # whole-file line-ending flip (scripts/dev/check_eol_flips.py).
        out = tmp_path / "old.baseline.json"
        out.write_bytes(b'{\r\n  "old": true\r\n}\r\n')
        self._run(monkeypatch, out)
        data = out.read_bytes()
        assert data.endswith(b"}\r\n")
        assert data.count(b"\n") == data.count(b"\r\n")

    def test_output_validates_against_the_schema(self, monkeypatch, tmp_path):
        out = tmp_path / "x.baseline.json"
        self._run(monkeypatch, out)
        assert gb.validate_baseline(out)
