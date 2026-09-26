#!/usr/bin/env python3
"""Guard the scan-accounting reconciler: every requested tool, exactly one row.

`scripts/dev/reconcile_scan_accounting.py` is the acceptance instrument for the
silent-data-loss class this repo has repeatedly shipped: a scan that exits 0
while producing less than it found. Its verdict is derived from the scan's own
artifacts, never from the exit code.

Since v2.0.0 Phase 3 the scan writes the account itself, one row per requested
tool per target, and the reconciler checks the rows instead of scraping log
lines. These tests hand it broken artifacts - a tool with no row, a tool with
two, a row for an undeclared name, a `ran` row with no output - because a
reconciler that cannot fail is worth nothing.

The end-to-end half is `tests/integration/test_scan_accounting.py`, which
reconciles a real scan.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.core.scan_timings import (
    SCAN_TIMINGS_FILENAME,
    Reason,
    State,
    ToolRun,
    build_scan_timings,
)
from scripts.dev.reconcile_scan_accounting import main, reconcile

RAN = ToolRun("trivy", State.RAN, seconds=1.0)
SKIPPED = ToolRun("hadolint", State.SKIPPED, Reason.NO_DOCKERFILES)
FAILED = ToolRun("semgrep", State.FAILED, Reason.TIMED_OUT)
DECLARED = ["trivy", "hadolint", "semgrep"]


def _scan(
    tmp_path: Path,
    rows=(RAN, SKIPPED, FAILED),
    *,
    meta_rows=None,
    outputs=None,
    doc_target="proj",
) -> Path:
    """A results directory with one repository target."""
    results = tmp_path / "results"
    target = results / "individual-repos" / "proj"
    target.mkdir(parents=True)
    by_tool = {r.tool: r for r in rows}
    doc = build_scan_timings(
        by_tool, target=doc_target, target_type="repo", wall_seconds=1
    )
    doc["tools"] = [r.to_dict() for r in rows]  # keep duplicates if a test wants them
    (target / SCAN_TIMINGS_FILENAME).write_bytes(json.dumps(doc).encode("utf-8"))
    for tool, body in (outputs if outputs is not None else {"trivy": "{}"}).items():
        (target / f"{tool}.json").write_bytes(body.encode("utf-8"))
    meta = {
        "tools": DECLARED,
        "tool_runs": [
            {"target": "proj", "target_type": "repo", **r.to_dict()}
            for r in (rows if meta_rows is None else meta_rows)
        ],
    }
    (results / ".scan_metadata.json").write_bytes(json.dumps(meta).encode("utf-8"))
    return results


def test_a_fully_accounted_scan_passes(tmp_path) -> None:
    result = reconcile(_scan(tmp_path))

    assert result.ok, result
    assert result.rows[("repo", "proj")]["hadolint"].label == "skipped:no Dockerfiles"


def test_a_tool_with_no_row_is_missing(tmp_path) -> None:
    """The #1227 shape: hadolint with no Dockerfile had no row anywhere."""
    result = reconcile(_scan(tmp_path, rows=(RAN, FAILED)))

    assert not result.ok
    assert "proj: hadolint" in result.missing
    assert "individual-repos/proj: hadolint" in result.missing


def test_a_tool_with_two_rows_is_a_duplicate(tmp_path) -> None:
    result = reconcile(_scan(tmp_path, rows=(RAN, SKIPPED, FAILED, RAN)))

    assert not result.ok
    assert "proj: trivy" in result.duplicate


def test_a_row_for_an_undeclared_tool_is_stray(tmp_path) -> None:
    extra = ToolRun("zap", State.SKIPPED, Reason.NEEDS_URL)
    result = reconcile(_scan(tmp_path, rows=(RAN, SKIPPED, FAILED, extra)))

    assert not result.ok
    assert "proj: zap" in result.stray


def test_a_row_that_does_not_parse_is_invalid(tmp_path) -> None:
    results = _scan(tmp_path)
    meta = json.loads((results / ".scan_metadata.json").read_bytes())
    meta["tool_runs"][0]["state"] = "succeeded"
    (results / ".scan_metadata.json").write_bytes(json.dumps(meta).encode("utf-8"))

    result = reconcile(results)

    assert not result.ok
    assert result.invalid and "succeeded" in result.invalid[0]


def test_ran_with_no_output_file_fails(tmp_path) -> None:
    """The #700 class: a success with nothing written."""
    result = reconcile(_scan(tmp_path, outputs={}))

    assert not result.ok
    assert result.no_output == ["individual-repos/proj: trivy"]


def test_ran_with_unparseable_output_fails(tmp_path) -> None:
    result = reconcile(_scan(tmp_path, outputs={"trivy": "{not json"}))

    assert not result.ok
    assert result.no_output == ["individual-repos/proj: trivy"]


def test_ndjson_output_parses(tmp_path) -> None:
    """trufflehog and nuclei write NDJSON; an empty file is a clean run."""
    for i, body in enumerate(('{"a": 1}\n{"b": 2}\n', "")):
        result = reconcile(_scan(tmp_path / f"case{i}", outputs={"trivy": body}))
        assert result.ok, (body, result)


def test_a_target_whose_scanner_raised_has_rows_and_no_folder(tmp_path) -> None:
    """Its rows are in the metadata only: it wrote nothing. That is accounted."""
    results = _scan(tmp_path)
    meta = json.loads((results / ".scan_metadata.json").read_bytes())
    meta["tool_runs"] += [
        {"target": "crashed", "target_type": "repo", **r.to_dict()}
        for r in (
            ToolRun("trivy", State.FAILED, Reason.SCANNER_ERROR),
            ToolRun("hadolint", State.FAILED, Reason.SCANNER_ERROR),
            ToolRun("semgrep", State.FAILED, Reason.SCANNER_ERROR),
        )
    ]
    (results / ".scan_metadata.json").write_bytes(json.dumps(meta).encode("utf-8"))

    assert reconcile(results).ok


def test_timings_for_a_target_the_metadata_does_not_know_disagree(tmp_path) -> None:
    results = _scan(tmp_path, meta_rows=())

    result = reconcile(results)

    assert not result.ok
    assert result.timings_disagree


def test_a_row_the_timings_record_differently_disagrees(tmp_path) -> None:
    """#1316: the docstring promised each document "agrees with the metadata's
    rows" while only the number of documents was compared."""
    timed_out = ToolRun("trivy", State.FAILED, Reason.TIMED_OUT)

    result = reconcile(_scan(tmp_path, meta_rows=(timed_out, SKIPPED, FAILED)))

    assert not result.ok
    assert result.timings_disagree == [
        "individual-repos/proj: trivy is ran here, failed:timed out in "
        ".scan_metadata.json"
    ]


def test_timings_naming_the_target_differently_disagree(tmp_path) -> None:
    """#1315's shape: one target, a GitLab clone recorded as `app` in its
    timings and `group/app` in the metadata. One document and one target, so a
    count cannot see it."""
    result = reconcile(_scan(tmp_path, doc_target="app"))

    assert not result.ok
    assert result.timings_disagree == [
        "individual-repos/proj: names repo app, which .scan_metadata.json has no "
        "rows for"
    ]


def test_two_documents_naming_one_target_disagree(tmp_path) -> None:
    """Two folders for one name: #1312's duplicate target."""
    results = _scan(tmp_path)
    twin = results / "individual-repos" / "proj-2"
    twin.mkdir()
    for name in (SCAN_TIMINGS_FILENAME, "trivy.json"):
        (twin / name).write_bytes(
            (results / "individual-repos/proj" / name).read_bytes()
        )

    result = reconcile(results)

    assert not result.ok
    assert result.timings_disagree == [
        "individual-repos/proj-2: names repo proj, as individual-repos/proj does"
    ]


def test_main_exits_non_zero_on_a_broken_scan(tmp_path, capsys) -> None:
    ok = _scan(tmp_path / "ok")
    broken = _scan(tmp_path / "broken", rows=(RAN,))

    assert main([str(ok)]) == 0
    assert main([str(broken)]) == 1
    assert "MISSING" in capsys.readouterr().out
