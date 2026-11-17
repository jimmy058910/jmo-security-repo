"""`jmo report` reports what is in front of it, and history records that run.

Three defects an outside review reproduced on `origin/dev` at a4445b52
(2026-11-17), each pinned here against a results directory built by hand in
the shape a real scan leaves, so no scanner is needed:

- a path holding no scan output produced a clean, successful report;
- the history row stored the previous run's `findings.json` when this run
  wrote no JSON;
- the report's `meta.scan_id` and the history row's id were two different
  UUIDs, so `jmo history show <report id>` found nothing.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

import pytest

from scripts.cli.report_orchestrator import cmd_report

# One ShellCheck finding, as ShellCheck's own JSON writes it.
SC2086 = {
    "file": "demo.sh",
    "line": 2,
    "endLine": 2,
    "column": 6,
    "endColumn": 8,
    "level": "info",
    "code": 2086,
    "message": "Double quote to prevent globbing and word splitting.",
}


def _scan_results(results_dir: Path, shellcheck_findings: list[dict]) -> Path:
    """The tree `jmo scan --repo example --tools shellcheck` leaves.

    Measured 2026-11-17 with ShellCheck on a one-file repository: a zero-
    finding scan leaves `.scan_metadata.json`, and `individual-repos/example/`
    holding `shellcheck.json` (`[]`) and `scan-timings.json`.
    """
    target = results_dir / "individual-repos" / "example"
    target.mkdir(parents=True, exist_ok=True)
    (target / "shellcheck.json").write_text(
        json.dumps(shellcheck_findings), encoding="utf-8"
    )
    (results_dir / ".scan_metadata.json").write_text(
        json.dumps(
            {
                "tools": ["shellcheck"],
                "target_count": 1,
                "tool_runs": [
                    {
                        "target": "example",
                        "target_type": "repo",
                        "tool": "shellcheck",
                        "state": "ran",
                        "reason": None,
                        "seconds": 0.004,
                        "exit_code": 0,
                        "attempts": 1,
                        "kept_findings": None,
                        "own_config": None,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return results_dir


def _config(tmp_path: Path, outputs: list[str]) -> Path:
    cfg = tmp_path / f"jmo-{'-'.join(outputs) or 'none'}.yml"
    cfg.write_text(f"outputs: [{', '.join(outputs)}]\n", encoding="utf-8")
    return cfg


def _args(results_dir: Path, config: Path, **overrides) -> argparse.Namespace:
    values = {
        "results_dir": None,
        "results_dir_pos": str(results_dir),
        "results_dir_opt": None,
        "out": None,
        "config": str(config),
        "fail_on": None,
        "profile": False,
        "threads": None,
        "policies": None,
        "fail_on_policy_violation": False,
        "store_history": False,
        "history_db": None,
        "fail_on_store_error": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class _Log:
    """Collects `_log_fn` records as (level, message)."""

    def __init__(self) -> None:
        self.records: list[tuple[str, str]] = []

    def __call__(self, _args, level: str, message: str) -> None:
        self.records.append((level, message))

    def at(self, level: str) -> list[str]:
        return [m for lvl, m in self.records if lvl == level]


def _tree(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


# ---------------------------------------------------------------------------
# A path with nothing to report is an error, not a clean report
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "make_input",
    [
        pytest.param(lambda root: root / "never-scanned", id="missing"),
        pytest.param(
            lambda root: (
                (root / "a-file").write_text("x", encoding="utf-8") and root / "a-file"
            ),
            id="a-file",
        ),
        pytest.param(
            lambda root: (root / "empty").mkdir() or root / "empty", id="empty-dir"
        ),
        pytest.param(
            # What a report-only run leaves: the reports of an earlier `jmo
            # report` on a missing path, and no scan output at all.
            lambda root: (
                (root / "reports-only" / "summaries").mkdir(parents=True)
                or root / "reports-only"
            ),
            id="only-summaries",
        ),
    ],
)
def test_nothing_to_report_exits_2_and_writes_nothing(tmp_path, make_input):
    """`jmo report <path> --fail-on LOW` on a path holding no scan output.

    Before: it created the path, wrote seven reports of zero findings and
    exited 0, the exact signal a CI gate reads as "scanned, nothing found".
    """
    work = tmp_path / "work"
    work.mkdir()
    target = make_input(work)
    before = _tree(work)
    log = _Log()

    rc = cmd_report(
        _args(target, _config(tmp_path, ["json", "md"]), fail_on="LOW"), log
    )

    assert rc == 2
    assert _tree(work) == before, "the report created files for a path it refused"
    errors = log.at("ERROR")
    assert len(errors) == 1 and str(target) in errors[0], log.records


def test_a_refused_report_does_not_create_its_out_dir(tmp_path):
    """`--out` elsewhere is not created either: nothing was reported."""
    out = tmp_path / "reports"
    log = _Log()

    rc = cmd_report(
        _args(tmp_path / "missing", _config(tmp_path, ["json"]), out=str(out)), log
    )

    assert rc == 2
    assert not out.exists()


def test_a_scan_with_zero_findings_still_reports_clean(tmp_path):
    """The case the check must not catch: a scan that ran and found nothing."""
    results = _scan_results(tmp_path / "results", [])
    log = _Log()

    rc = cmd_report(
        _args(results, _config(tmp_path, ["json", "md"]), fail_on="LOW"), log
    )

    assert rc == 0, log.records
    doc = json.loads((results / "summaries" / "findings.json").read_text("utf-8"))
    assert doc["findings"] == []


def test_a_scan_whose_every_tool_failed_still_reports(tmp_path):
    """A scan whose tool failed leaves metadata and a target folder: it ran.

    Measured: `jmo scan` of an empty repository wrote `.scan_metadata.json`
    with a `failed` row and a target folder holding only `scan-timings.json`.
    """
    results = tmp_path / "results"
    (results / "individual-repos" / "emptyrepo").mkdir(parents=True)
    (results / ".scan_metadata.json").write_text(
        json.dumps({"tools": ["shellcheck"], "tool_runs": []}), encoding="utf-8"
    )

    rc = cmd_report(_args(results, _config(tmp_path, ["json"])), _Log())

    assert rc == 0
    assert (results / "summaries" / "findings.json").is_file()


def test_tool_output_without_scan_metadata_still_reports(tmp_path):
    """Tool output alone is enough: the shape v1.x results directories have."""
    results = tmp_path / "results"
    target = results / "individual-repos" / "example"
    target.mkdir(parents=True)
    (target / "shellcheck.json").write_text(json.dumps([SC2086]), encoding="utf-8")

    rc = cmd_report(_args(results, _config(tmp_path, ["json"]), fail_on="LOW"), _Log())

    assert rc == 1, "the one LOW finding must reach the threshold"


# ---------------------------------------------------------------------------
# The history row holds this run's findings, whatever outputs were asked for
# ---------------------------------------------------------------------------


def _rows(db: Path) -> list[tuple[str, int]]:
    """(scan id, total_findings) per stored scan, oldest first."""
    conn = sqlite3.connect(db)
    try:
        return list(conn.execute("SELECT id, total_findings FROM scans ORDER BY rowid"))
    finally:
        conn.close()


def _store(results: Path, db: Path, config: Path, **overrides) -> tuple[int, _Log]:
    log = _Log()
    rc = cmd_report(
        _args(
            results,
            config,
            store_history=True,
            history_db=str(db),
            fail_on_store_error=True,
            **overrides,
        ),
        log,
    )
    return rc, log


def test_a_markdown_only_rerun_stores_its_own_findings_not_the_last_json(tmp_path):
    """The review's two-scan case, in one results directory.

    Run 1 finds one issue and writes JSON and Markdown. The issue is fixed and
    run 2 asks for Markdown alone. Before: SUMMARY.md said 0 while the new
    row said 1, read from run 1's findings.json, and `--fail-on-store-error`
    exited 0 because nothing failed.
    """
    results = _scan_results(tmp_path / "results", [SC2086])
    db = tmp_path / "history.db"
    rc1, _ = _store(results, db, _config(tmp_path, ["json", "md"]))

    _scan_results(results, [])
    rc2, log2 = _store(results, db, _config(tmp_path, ["md"]))

    assert (rc1, rc2) == (0, 0), log2.records
    summary = (results / "summaries" / "SUMMARY.md").read_text(encoding="utf-8")
    assert "Total findings: 0" in summary
    assert [total for _, total in _rows(db)] == [1, 0]


def test_a_markdown_only_scan_is_stored_with_no_json_on_disk(tmp_path):
    """Before: no findings.json, so the store raised and the row was missing."""
    results = _scan_results(tmp_path / "results", [SC2086])
    db = tmp_path / "history.db"

    rc, log = _store(results, db, _config(tmp_path, ["md"]))

    assert rc == 0, log.records
    assert not (results / "summaries" / "findings.json").exists()
    assert [total for _, total in _rows(db)] == [1]


def test_reports_written_elsewhere_are_stored_from_this_run(tmp_path):
    """`--out` elsewhere: the store read `<results>/summaries` whatever it said.

    A stale findings.json left there by an earlier report is the trap.
    """
    results = _scan_results(tmp_path / "results", [SC2086])
    db = tmp_path / "history.db"
    _store(results, db, _config(tmp_path, ["json"]))

    _scan_results(results, [])
    rc, log = _store(results, db, _config(tmp_path, ["json"]), out=str(tmp_path / "o"))

    assert rc == 0, log.records
    assert [total for _, total in _rows(db)] == [1, 0]


def test_the_stored_findings_are_the_ones_findings_json_reports(tmp_path):
    """Every writer runs before the store, on the same finding objects.

    A writer that changed a finding in place would put something in history
    that no report shows. Compared field by field against findings.json, with
    every output on. The dashboard strips the scan root from what it embeds
    (#1007), so the raw output names the root and the metadata records it:
    stripping in place would reach the stored `raw_finding`.
    """
    root = tmp_path / "repo"
    absolute = {**SC2086, "file": str(root / "demo.sh")}
    results = _scan_results(
        tmp_path / "results", [absolute, {**absolute, "line": 5, "endLine": 5}]
    )
    meta_path = results / ".scan_metadata.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta_path.write_text(
        json.dumps({**meta, "repo_paths": [str(root)]}), encoding="utf-8"
    )
    db = tmp_path / "history.db"
    outputs = ["json", "md", "yaml", "html", "simple-html", "sarif", "csv"]
    rc, log = _store(results, db, _config(tmp_path, outputs + ["compliance"]))
    assert rc == 0, log.records

    reported = json.loads(
        (results / "summaries" / "findings.json").read_text(encoding="utf-8")
    )["findings"]
    conn = sqlite3.connect(db)
    try:
        stored = {
            fp: (sev, rule, path, line, raw)
            for fp, sev, rule, path, line, raw in conn.execute(
                "SELECT fingerprint, severity, rule_id, path, start_line, "
                "raw_finding FROM findings"
            )
        }
    finally:
        conn.close()

    assert len(reported) == 2
    # Compared as data: `json.dumps` doubles each backslash of a Windows path,
    # so the path is never a substring of its own dumped text.
    assert all(f["raw"]["file"] == str(root / "demo.sh") for f in reported)
    assert stored == {
        f["id"]: (
            f["severity"],
            f["ruleId"],
            f["location"]["path"],
            f["location"]["startLine"],
            json.dumps(f["raw"]),
        )
        for f in reported
    }


@pytest.mark.parametrize(
    ("outputs", "names_the_precondition"), [(["json"], False), (["md"], True)]
)
def test_a_failed_store_names_a_recovery_that_works(
    tmp_path, monkeypatch, outputs, names_the_precondition
):
    """`jmo history store` reads summaries/findings.json; say so when absent."""
    results = _scan_results(tmp_path / "results", [SC2086])

    def fail(**_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("scripts.core.history_db.store_scan", fail)
    rc, log = _store(results, tmp_path / "history.db", _config(tmp_path, outputs))

    assert rc == 1
    (error,) = log.at("ERROR")
    assert f"jmo history store --results-dir {results}" in error
    assert ("with `json` in outputs" in error) is names_the_precondition
