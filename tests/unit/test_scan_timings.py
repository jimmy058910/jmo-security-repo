"""The scan phase must persist the per-tool measurements it already takes.

`ToolRunner` has always produced a `ToolResult` per invocation carrying
`duration` (a real `perf_counter` span), `status`, `returncode` and `attempts`.
Every scan job then iterated those results reading only `.tool` and `.status`,
collapsed them to a dict of booleans, and dropped the rest on the floor -- so
"which tool made my scan slow?" was unanswerable from JMo's own data even though
JMo had measured the answer (#722).

These tests pin the file that keeps it. Two properties matter more than the
schema itself:

* **Nothing captured from the tool's own streams may be written.** `stdout` on a
  secret scanner's result is the secrets it found. `to_dict()` already excludes
  `stdout`/`stderr`; a future `asdict()` "simplification" would turn this
  artifact into a leak, so it is asserted rather than assumed.
* **`status` is not collapsed into a coarser outcome enum.** #722 proposed a
  four-value outcome with `skipped` in it; `ToolRunner`'s four real values are
  different, and `no_output` -- an accepted return code with nothing written --
  is the exact shape of the #700 bug class. Mapping between the two vocabularies
  would discard the signal that found a real defect.

See `TOOL_RUNNER_STATUSES` below for why that count is four and not the five
`ToolResult`'s docstring advertises (#727).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from scripts.core.scan_timings import (
    SCAN_TIMINGS_FILENAME,
    SCAN_TIMINGS_SCHEMA_VERSION,
    write_scan_timings,
)
from scripts.core.tool_runner import ToolResult

EXPECTED_TOP_LEVEL_KEYS = {
    "schema_version",
    "target",
    "target_type",
    "wall_seconds",
    "tools",
}


def _write(tmp_path: Path, results: list[ToolResult], **kwargs) -> dict:
    """Write a timings file into tmp_path and return the parsed document."""
    params = {
        "target": "demo",
        "target_type": "repo",
        "wall_seconds": 1.0,
        **kwargs,
    }
    path = write_scan_timings(tmp_path, results, **params)
    return json.loads(path.read_text(encoding="utf-8"))


def test_writes_the_file_beside_the_tool_outputs(tmp_path: Path) -> None:
    """The artifact lands in the target's own output directory.

    Consumers discover it the same way they discover `trivy.json` -- by name
    inside `individual-<type>s/<target>/` -- so it must be a sibling of the
    tool output it describes, not a separate tree to correlate.
    """
    path = write_scan_timings(
        tmp_path,
        [ToolResult(tool="trivy", status="success", returncode=0, duration=3.5)],
        target="demo",
        target_type="repo",
        wall_seconds=3.6,
    )

    assert path == tmp_path / SCAN_TIMINGS_FILENAME
    assert path.exists(), "write_scan_timings returned a path it did not create"


def test_top_level_keys_are_pinned_to_the_producer(tmp_path: Path) -> None:
    """Pinned with `==`, matching the timings.json contract test from #723.

    A removed key breaks a consumer exactly as badly as a renamed one, and a
    silently added key is a schema change that should be a conscious edit here.
    This is the guard the report-phase `timings.json` lacked for months while
    the published skill drifted completely away from it.
    """
    doc = _write(tmp_path, [ToolResult(tool="trivy", status="success")])

    assert set(doc) == EXPECTED_TOP_LEVEL_KEYS, (
        "scan-timings.json top-level keys drifted from the producer.\n"
        f"  missing: {sorted(EXPECTED_TOP_LEVEL_KEYS - set(doc))}\n"
        f"  unexpected: {sorted(set(doc) - EXPECTED_TOP_LEVEL_KEYS)}"
    )
    assert doc["schema_version"] == SCAN_TIMINGS_SCHEMA_VERSION
    assert doc["target"] == "demo"
    assert doc["target_type"] == "repo"


def test_per_tool_entries_are_exactly_tool_result_to_dict(tmp_path: Path) -> None:
    """The per-tool record is `ToolResult.to_dict()`, not a re-derived shape.

    Re-deriving would create a second vocabulary for data that already has one,
    and every rename in `ToolResult` would then need a matching edit here to
    stay honest -- which is precisely the drift this file exists to prevent.
    """
    result = ToolResult(
        tool="semgrep",
        status="success",
        returncode=0,
        attempts=2,
        duration=12.5,
        output_file=Path("semgrep.json"),
    )

    doc = _write(tmp_path, [result])

    assert doc["tools"] == [result.to_dict()]


def test_never_serializes_tool_stdout_or_stderr(tmp_path: Path) -> None:
    """A scanner's captured output is its findings. It must not land here.

    trufflehog's stdout is a list of live credentials. `scan-timings.json` is a
    performance artifact users paste into issues, so anything read off the
    tool's own streams is disqualified regardless of how convenient it is.
    """
    doc_text = json.dumps(
        _write(
            tmp_path,
            [
                ToolResult(
                    tool="trufflehog",
                    status="success",
                    returncode=0,
                    duration=4.0,
                    stdout='{"Raw": "AKIA_SECRET_FROM_STDOUT"}',
                    stderr="stderr-content-marker",
                )
            ],
        )
    )

    assert "AKIA_SECRET_FROM_STDOUT" not in doc_text, (
        "tool stdout reached scan-timings.json. On a secret scanner that is the "
        "secrets themselves. Serialize via ToolResult.to_dict(), never asdict()."
    )
    assert "stderr-content-marker" not in doc_text, (
        "tool stderr reached scan-timings.json; it can carry scanned file "
        "content and paths well beyond what a timing artifact needs."
    )


# The four values `tool_runner.py` actually assigns to `ToolResult.status`.
#
# Deliberately NOT five. `ToolResult`'s docstring claimed a `"timeout"` status
# that `run_tool` never assigned, and #722's rescoping read that claim off the
# docstring rather than the code. Listing it here would make this file assert
# against fiction -- the exact defect class the #718 remediation exists to
# remove.
#
# A timed-out tool reports `error` or `retry_exhausted` **and** `timed_out=True`
# (#727). The flag is what carries the timeout; `status` carries whether the
# retry budget was exhausted. Both are in `to_dict()`, so both reach this file.
TOOL_RUNNER_STATUSES = ["success", "no_output", "error", "retry_exhausted"]


@pytest.mark.parametrize("status", TOOL_RUNNER_STATUSES)
def test_preserves_every_tool_runner_status_verbatim(
    tmp_path: Path, status: str
) -> None:
    """Each status survives; none is folded into a coarser outcome.

    `no_output` is the one that matters most: an accepted return code with an
    empty artifact is how checkov's broken Windows wrapper was graded a success
    across all 5 repos of a public-repo benchmark while the scan exited 0. A
    four-value outcome enum of the shape #722 proposed has nowhere to put it.
    """
    doc = _write(tmp_path, [ToolResult(tool="checkov", status=status)])

    assert doc["tools"][0]["status"] == status


def test_records_wall_seconds_apart_from_the_sum_of_durations(
    tmp_path: Path,
) -> None:
    """Both numbers are kept, because they answer different questions.

    Tools run concurrently, so the per-tool durations sum to more than the
    elapsed time. Using that sum as the denominator for "what share of my scan
    was tool X" understates every tool by the parallelism factor -- the same
    invalid-denominator defect the profile-optimizer review caught (#718 chunk
    A). Recording the real elapsed span removes the temptation to reconstruct
    it wrongly.
    """
    doc = _write(
        tmp_path,
        [
            ToolResult(tool="trivy", status="success", duration=30.0),
            ToolResult(tool="semgrep", status="success", duration=45.0),
        ],
        wall_seconds=48.0,
    )

    assert doc["wall_seconds"] == 48.0
    assert sum(t["duration"] for t in doc["tools"]) == 75.0, (
        "per-tool durations must be preserved individually, not normalised "
        "against wall_seconds"
    )


def test_empty_result_set_still_writes_a_file(tmp_path: Path) -> None:
    """ "No tools ran" is a measurement, and a missing file cannot express it.

    Without the file, a scan where every tool was skipped is indistinguishable
    from a build where this feature is not working at all.
    """
    doc = _write(tmp_path, [], wall_seconds=0.0)

    assert doc["tools"] == []
    assert doc["wall_seconds"] == 0.0


def test_an_unwritable_directory_does_not_abort_the_scan(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A diagnostic artifact must never cost a completed scan its results.

    This runs after every tool has finished -- up to 70 minutes of work on a
    `deep` profile. Raising here would discard all of it to protect a timing
    file, so the failure is logged and the scan continues.

    Logged, not swallowed: a silently absent artifact is the failure mode this
    repository keeps relearning, so it has to name itself on a durable stream
    rather than only in a progress glyph.
    """
    missing = tmp_path / "does" / "not" / "exist"

    with caplog.at_level(logging.WARNING, logger="scripts.core.scan_timings"):
        path = write_scan_timings(
            missing,
            [ToolResult(tool="trivy", status="success")],
            target="demo",
            target_type="repo",
            wall_seconds=1.0,
        )

    assert path is None, "an unwritable destination must report no file written"
    assert (
        SCAN_TIMINGS_FILENAME in caplog.text
    ), f"the write failed on no stream. caplog was: {caplog.text!r}"
