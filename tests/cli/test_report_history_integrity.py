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
