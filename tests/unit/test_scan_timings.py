"""The scan phase writes one accounting row per requested tool (#722, #1227).

`ToolRunner` has always timed and classified every invocation, and every scan
job reduced that to a dict of booleans; a tool that never reached `ToolRunner`
had no row at all. Schema 3 of `scan-timings.json` is the rows: every requested
tool, `ran`, `skipped:<reason>` or `failed:<reason>`, with its seconds.

Two properties matter more than the schema itself:

* **Nothing captured from the tool's own streams may be written.** `stdout` on
  a secret scanner's result is the secrets it found. A row has no field that
  could hold it, and a test builds one from such a result to prove it.
* **`no_output` is not folded into a coarser outcome.** An accepted return code
  with nothing written is the #700 bug class; it keeps a reason of its own.
"""

from __future__ import annotations

import json
import logging
from dataclasses import fields
from pathlib import Path

import pytest

from scripts.cli.scan_jobs.tool_loop import _row_from_results
from scripts.core.scan_timings import (
    FAIL_REASONS,
    SCAN_TIMINGS_FILENAME,
    SCAN_TIMINGS_SCHEMA_VERSION,
    SKIP_REASONS,
    Reason,
    State,
    ToolRun,
    write_scan_timings,
)
from scripts.core.tool_descriptors import DESCRIPTORS
from scripts.core.tool_runner import ToolResult

EXPECTED_TOP_LEVEL_KEYS = {
    "schema_version",
    "target",
    "target_type",
    "wall_seconds",
    # Schema 2 (#824): a target abandoned before any tool ran is otherwise
    # indistinguishable from one whose tools all applied elsewhere.
    "outcome",
    "error",
    "tools",
}
EXPECTED_ROW_KEYS = {
    "tool",
    "state",
    "reason",
    "seconds",
    "exit_code",
    "attempts",
    "invocations",
    "detail",
}


def _write(tmp_path: Path, rows: list[ToolRun], **kwargs) -> dict:
    params = {"target": "demo", "target_type": "repo", "wall_seconds": 1.0, **kwargs}
    path = write_scan_timings(tmp_path, {r.tool: r for r in rows}, **params)
    return json.loads(path.read_bytes())


def test_writes_the_file_beside_the_tool_outputs(tmp_path: Path) -> None:
    """Consumers find it by name inside `individual-<type>s/<target>/`."""
    path = write_scan_timings(
        tmp_path,
        {"trivy": ToolRun("trivy", State.RAN, seconds=3.5)},
        target="demo",
        target_type="repo",
        wall_seconds=3.6,
    )

    assert path == tmp_path / SCAN_TIMINGS_FILENAME
    assert path.exists(), "write_scan_timings returned a path it did not create"


def test_top_level_keys_are_pinned_to_the_producer(tmp_path: Path) -> None:
    """A removed key breaks a consumer as badly as a renamed one, and an added
    key is a schema change that should be a conscious edit here."""
    doc = _write(tmp_path, [ToolRun("trivy", State.RAN)])

    assert set(doc) == EXPECTED_TOP_LEVEL_KEYS
    assert doc["schema_version"] == SCAN_TIMINGS_SCHEMA_VERSION
    assert doc["target"] == "demo"
    assert doc["target_type"] == "repo"


def test_row_keys_are_pinned(tmp_path: Path) -> None:
    doc = _write(tmp_path, [ToolRun("trivy", State.RAN)])

    assert set(doc["tools"][0]) == EXPECTED_ROW_KEYS


def test_schema_version_is_pinned_to_a_literal() -> None:
    """The version is only useful if it moves when the shape does. Version 3
    (v2.0.0 Phase 3) replaced ToolRunner's result fields with the row."""
    assert SCAN_TIMINGS_SCHEMA_VERSION == 3
    assert len(EXPECTED_TOP_LEVEL_KEYS) == 7
    assert len(EXPECTED_ROW_KEYS) == 8


def test_a_row_round_trips(tmp_path: Path) -> None:
    row = ToolRun(
        "semgrep",
        State.FAILED,
        Reason.EXIT_CODE,
        seconds=12.5,
        exit_code=7,
        attempts=2,
        invocations=1,
        detail="Return code 7 not in (0, 1, 2)",
    )

    doc = _write(tmp_path, [row])

    assert ToolRun.from_dict(doc["tools"][0]) == row
    assert doc["tools"][0]["state"] == "failed"
    assert doc["tools"][0]["reason"] == "unaccepted exit code"


def test_never_serializes_tool_stdout_or_stderr(tmp_path: Path) -> None:
    """trufflehog's stdout is a list of live credentials, and this artifact is
    pasted into issues. A row built from such a result must not carry it."""
    assert not {f.name for f in fields(ToolRun)} & {"stdout", "stderr"}

    result = ToolResult(
        tool="trufflehog",
        status="success",
        returncode=0,
        duration=4.0,
        stdout='{"Raw": "AKIA_SECRET_FROM_STDOUT"}',
        stderr="stderr-content-marker",
    )
    row = _row_from_results(
        DESCRIPTORS["trufflehog"], [result], 1, tmp_path, lambda *a: None
    )
    doc_text = json.dumps(_write(tmp_path, [row]))

    assert "AKIA_SECRET_FROM_STDOUT" not in doc_text
    assert "stderr-content-marker" not in doc_text


@pytest.mark.parametrize(
    ("result", "label"),
    [
        (ToolResult(tool="checkov", status="success"), "ran"),
        (
            ToolResult(tool="checkov", status="no_output", returncode=0),
            "failed:no output",
        ),
        (
            ToolResult(tool="checkov", status="error", returncode=3, failure="crash"),
            "failed:unaccepted exit code",
        ),
        (
            ToolResult(
                tool="checkov",
                status="retry_exhausted",
                timed_out=True,
                failure="timeout",
            ),
            "failed:timed out",
        ),
        (
            ToolResult(tool="checkov", status="error", failure="missing_tool"),
            "failed:not found at run time",
        ),
        (
            ToolResult(tool="checkov", status="error", failure="system_error"),
            "failed:could not be run",
        ),
    ],
)
def test_every_tool_runner_outcome_keeps_its_own_reason(
    tmp_path, result, label
) -> None:
    """None is folded into another: `no_output` is how checkov's broken
    Windows wrapper was graded a success across a whole benchmark."""
    row = _row_from_results(
        DESCRIPTORS["checkov"], [result], 1, tmp_path, lambda *a: None
    )

    assert row.label == label


def test_the_reason_sets_are_closed_and_cover_every_reason() -> None:
    """A reason that is recorded and never printed is the trap that removed a
    third NOT_ATTEMPTED_* reason in Phase 2; every Reason is one of the two."""
    assert set(Reason) == SKIP_REASONS | FAIL_REASONS
    assert {Reason.NOT_INSTALLED} == SKIP_REASONS & FAIL_REASONS


def test_records_wall_seconds_apart_from_the_sum_of_durations(tmp_path: Path) -> None:
    """Tools run concurrently, so per-tool seconds sum to more than the elapsed
    time; both are kept because they answer different questions."""
    doc = _write(
        tmp_path,
        [
            ToolRun("trivy", State.RAN, seconds=30.0),
            ToolRun("semgrep", State.RAN, seconds=45.0),
        ],
        wall_seconds=48.0,
    )

    assert doc["wall_seconds"] == 48.0
    assert sum(t["seconds"] for t in doc["tools"]) == 75.0


def test_empty_row_set_still_writes_a_file(tmp_path: Path) -> None:
    doc = _write(tmp_path, [], wall_seconds=0.0)

    assert doc["tools"] == []


def test_an_unwritable_directory_does_not_abort_the_scan(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """This runs after every tool has finished; raising would discard a
    completed scan to protect a timing file. Logged, not swallowed."""
    missing = tmp_path / "does" / "not" / "exist"

    with caplog.at_level(logging.WARNING, logger="scripts.core.scan_timings"):
        path = write_scan_timings(
            missing,
            {"trivy": ToolRun("trivy", State.RAN)},
            target="demo",
            target_type="repo",
            wall_seconds=1.0,
        )

    assert path is None, "an unwritable destination must report no file written"
    assert SCAN_TIMINGS_FILENAME in caplog.text


def test_the_file_is_written_with_lf_endings(tmp_path: Path) -> None:
    """write_bytes, not write_text, which emits CRLF on Windows."""
    path = write_scan_timings(
        tmp_path,
        {"trivy": ToolRun("trivy", State.RAN)},
        target="d",
        target_type="repo",
        wall_seconds=0,
    )

    assert b"\r\n" not in path.read_bytes()
