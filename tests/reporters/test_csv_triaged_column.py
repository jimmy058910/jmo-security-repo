#!/usr/bin/env python3
"""The CSV `triaged` column must be able to say YES (#857).

It could not. Measured on a real 242-finding scan: **242 rows, `NO` for all
242**, for two independent reasons --

1. `cmd_report` reassigns `findings` to the post-suppression list before
   `write_csv` is called, so any row reaching the reporter is one that no
   *active* rule matched; and
2. the lookup was `suppressions.get(finding_id)`, keyed by finding id, so
   chunk 8's `path`/`ruleId`/`severity`/`line` selectors could never be found
   either.

The one reachable and useful meaning is **expired**: a rule matches the
finding but its acceptance has lapsed, so the finding is back in the report.
The tests below assert reachability first -- a column that cannot vary is the
defect, so a test that only checks `NO` would have passed throughout.
"""

from __future__ import annotations

import csv
import datetime as dt
from pathlib import Path

from scripts.core.reporters.csv_reporter import write_csv
from scripts.core.suppress import load_suppressions

YESTERDAY = (dt.date.today() - dt.timedelta(days=1)).isoformat()
NEXT_CENTURY = "2199-01-01"

FINDINGS = [
    {
        "id": "aaaaaaaaaaaaaaaa",
        "ruleId": "B105",
        "severity": "HIGH",
        "message": "Hardcoded password",
        "location": {"path": "app/config.py", "startLine": 10},
        "tool": {"name": "bandit"},
    },
    {
        "id": "bbbbbbbbbbbbbbbb",
        "ruleId": "CKV_AWS_23",
        "severity": "MEDIUM",
        "message": "Security group has no description",
        "location": {"path": "iac/main.tf", "startLine": 3},
        "tool": {"name": "checkov"},
    },
]


def _rows(tmp_path: Path, suppressions) -> dict[str, str]:
    out = tmp_path / "findings.csv"
    write_csv(FINDINGS, out, suppressions=suppressions)
    with out.open(newline="", encoding="utf-8") as fh:
        return {r["ruleId"]: r["triaged"] for r in csv.DictReader(fh)}


def _suppressions(tmp_path: Path, body: str):
    p = tmp_path / "jmo.suppress.yml"
    p.write_text(body, encoding="utf-8")
    return load_suppressions(str(p))


class TestTriagedIsReachable:
    def test_expired_id_rule_marks_the_finding_triaged(self, tmp_path):
        sup = _suppressions(
            tmp_path,
            f"suppressions:\n"
            f"  - id: aaaaaaaaaaaaaaaa\n"
            f"    reason: accepted risk\n"
            f"    expires: '{YESTERDAY}'\n",
        )
        assert _rows(tmp_path, sup) == {"B105": "YES", "CKV_AWS_23": "NO"}

    def test_expired_path_rule_marks_the_finding_triaged(self, tmp_path):
        """Chunk 8's selectors must reach the column, not just `id`."""
        sup = _suppressions(
            tmp_path,
            f"suppressions:\n"
            f"  - path: 'iac/*'\n"
            f"    reason: legacy stack\n"
            f"    expires: '{YESTERDAY}'\n",
        )
        assert _rows(tmp_path, sup) == {"B105": "NO", "CKV_AWS_23": "YES"}

    def test_expired_rule_id_rule_marks_the_finding_triaged(self, tmp_path):
        sup = _suppressions(
            tmp_path,
            f"suppressions:\n"
            f"  - ruleId: 'CKV_AWS_*'\n"
            f"    reason: reviewed\n"
            f"    expires: '{YESTERDAY}'\n",
        )
        assert _rows(tmp_path, sup)["CKV_AWS_23"] == "YES"


class TestTriagedStaysNoWhenItShould:
    def test_unexpired_rule_does_not_mark_the_finding(self, tmp_path):
        """An active rule removes the finding upstream; it is not 'triaged' here."""
        sup = _suppressions(
            tmp_path,
            f"suppressions:\n"
            f"  - id: aaaaaaaaaaaaaaaa\n"
            f"    reason: accepted risk\n"
            f"    expires: '{NEXT_CENTURY}'\n",
        )
        assert _rows(tmp_path, sup) == {"B105": "NO", "CKV_AWS_23": "NO"}

    def test_rule_with_no_expiry_does_not_mark_the_finding(self, tmp_path):
        sup = _suppressions(
            tmp_path,
            "suppressions:\n  - id: aaaaaaaaaaaaaaaa\n    reason: permanent\n",
        )
        assert _rows(tmp_path, sup) == {"B105": "NO", "CKV_AWS_23": "NO"}

    def test_expired_rule_matching_nothing_marks_nothing(self, tmp_path):
        sup = _suppressions(
            tmp_path,
            f"suppressions:\n"
            f"  - path: 'somewhere/else/*'\n"
            f"    reason: unrelated\n"
            f"    expires: '{YESTERDAY}'\n",
        )
        assert _rows(tmp_path, sup) == {"B105": "NO", "CKV_AWS_23": "NO"}

    def test_no_suppressions_at_all(self, tmp_path):
        assert _rows(tmp_path, None) == {"B105": "NO", "CKV_AWS_23": "NO"}
        assert _rows(tmp_path, {}) == {"B105": "NO", "CKV_AWS_23": "NO"}
