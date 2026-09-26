"""One accounting row per requested tool, per target (#722, #1227).

Every tool a scan was asked for lands in exactly one of three states on every
target: **ran**, **skipped:<reason>** or **failed:<reason>**, with how long it
took. Before v2.0.0 Phase 3 the scan jobs reduced `ToolRunner`'s results to a
dict of booleans, and a tool that never reached `ToolRunner` -- not installed,
no Dockerfile to lint, a DAST tool handed a directory -- had no row at all:
hadolint and shellcheck on a repository without their files appeared in no
stream, no artifact and no log line (#1227).

The rows are written to `scan-timings.json` beside the target's tool outputs,
and `cmd_scan` carries every target's rows into `.scan_metadata.json`, from
which `store_scan` fills the `scan_tool_runs` table.

Related:
- `scripts/cli/report_orchestrator.py` writes the sibling `timings.json`, which
  covers the **report** phase (how long adapters took to parse tool output).
  This file covers the **scan** phase. Neither substitutes for the other.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SCAN_TIMINGS_FILENAME = "scan-timings.json"

# Bumped when the document's shape changes, so a consumer can refuse a shape it
# does not understand instead of misreading it. Version 3 (v2.0.0 Phase 3): a
# row for every requested tool, including the ones that never ran, keyed
# `tool/state/reason/seconds/...` rather than ToolRunner's result fields.
SCAN_TIMINGS_SCHEMA_VERSION = 3

# `outcome` values: did the target get as far as running tools at all.
OUTCOME_COMPLETED = "completed"
OUTCOME_FAILED_BEFORE_TOOLS = "failed-before-tools"


class State(StrEnum):
    """What happened to one tool on one target."""

    RAN = "ran"
    SKIPPED = "skipped"
    FAILED = "failed"


class Reason(StrEnum):
    """Why a tool did not run, or why its run does not count.

    A closed set, so a reason cannot be recorded and then never printed: the
    trap that removed a third `NOT_ATTEMPTED_*` reason in Phase 2, which was
    written by one module and queried by none.
    """

    # skipped, or failed without --allow-missing-tools
    NOT_INSTALLED = "not installed"
    # skipped: the target is not one this tool reads
    NEEDS_URL = "needs --url"
    NOT_FOR_TARGET = "not for this target type"
    # skipped: the target has nothing of the kind this tool reads
    NO_DOCKERFILES = "no Dockerfiles"
    NO_SHELL_SCRIPTS = "no shell scripts"
    NO_GO_SOURCES = "no Go sources"
    NO_IAC = "no IaC or workflow files"
    # failed
    NO_FILES_TO_SCAN = "no files to scan"
    EXAMINED_ZERO = "examined 0 files"
    TIMED_OUT = "timed out"
    EXIT_CODE = "unaccepted exit code"
    NO_OUTPUT = "no output"
    NOT_FOUND_AT_RUN = "not found at run time"
    COULD_NOT_RUN = "could not be run"
    BEFORE_TOOLS = "target not scanned"
    SCANNER_ERROR = "scanner error"


SKIP_REASONS: frozenset[Reason] = frozenset(
    {
        Reason.NOT_INSTALLED,
        Reason.NEEDS_URL,
        Reason.NOT_FOR_TARGET,
        Reason.NO_DOCKERFILES,
        Reason.NO_SHELL_SCRIPTS,
        Reason.NO_GO_SOURCES,
        Reason.NO_IAC,
    }
)
# The target is not one this tool reads: the row says so, and says nothing
# about this target.
OFF_TARGET_REASONS: frozenset[Reason] = frozenset(
    {Reason.NEEDS_URL, Reason.NOT_FOR_TARGET}
)
FAIL_REASONS: frozenset[Reason] = frozenset(
    {
        Reason.NOT_INSTALLED,
        Reason.NO_FILES_TO_SCAN,
        Reason.EXAMINED_ZERO,
        Reason.TIMED_OUT,
        Reason.EXIT_CODE,
        Reason.NO_OUTPUT,
        Reason.NOT_FOUND_AT_RUN,
        Reason.COULD_NOT_RUN,
        Reason.BEFORE_TOOLS,
        Reason.SCANNER_ERROR,
    }
)


@dataclass(frozen=True)
class ToolRun:
    """One tool on one target. The accounting record (#722).

    `detail` is the human-readable why (a tool's own error line, a return
    code) and goes to `scan-timings.json` only; `scan_tool_runs` keeps the
    closed `reason`. Nothing the tool printed is kept: on a secret scanner,
    stdout *is* the secrets.
    """

    tool: str
    state: State
    reason: Reason | None = None
    seconds: float = 0.0
    exit_code: int | None = None
    attempts: int = 0
    invocations: int = 0
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.state is State.RAN:
            if self.reason is not None:
                raise ValueError(f"{self.tool}: a tool that ran has no reason")
        elif self.state is State.SKIPPED:
            if self.reason not in SKIP_REASONS:
                raise ValueError(f"{self.tool}: {self.reason!r} is not a skip reason")
        elif self.reason not in FAIL_REASONS:
            raise ValueError(f"{self.tool}: {self.reason!r} is not a failure reason")

    @property
    def label(self) -> str:
        """`ran`, `skipped:<reason>` or `failed:<reason>`."""
        return (
            self.state.value if self.reason is None else f"{self.state}:{self.reason}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "state": self.state.value,
            "reason": None if self.reason is None else self.reason.value,
            "seconds": round(self.seconds, 3),
            "exit_code": self.exit_code,
            "attempts": self.attempts,
            "invocations": self.invocations,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ToolRun:
        """Read a row back; raises ValueError/KeyError on anything else."""
        reason = data.get("reason")
        return cls(
            tool=str(data["tool"]),
            state=State(data["state"]),
            reason=None if reason is None else Reason(reason),
            seconds=float(data.get("seconds") or 0.0),
            exit_code=data.get("exit_code"),
            attempts=int(data.get("attempts") or 0),
            invocations=int(data.get("invocations") or 0),
            detail=data.get("detail"),
        )


# A target's rows, keyed by tool: one key per tool is "exactly one row" by
# construction, which a list would have to be checked for.
TargetRows = dict[str, ToolRun]


def build_scan_timings(
    rows: Mapping[str, ToolRun],
    *,
    target: str,
    target_type: str,
    wall_seconds: float,
    outcome: str = OUTCOME_COMPLETED,
    error: str | None = None,
) -> dict[str, Any]:
    """The scan-timings document for one target.

    `wall_seconds` is recorded rather than derived because tools run
    concurrently: the per-tool seconds sum to more than the elapsed time.
    """
    return {
        "schema_version": SCAN_TIMINGS_SCHEMA_VERSION,
        "target": target,
        "target_type": target_type,
        "wall_seconds": round(wall_seconds, 3),
        "outcome": outcome,
        "error": error,
        "tools": [row.to_dict() for row in rows.values()],
    }


def write_scan_timings(
    out_dir: Path,
    rows: Mapping[str, ToolRun],
    *,
    target: str,
    target_type: str,
    wall_seconds: float,
    outcome: str = OUTCOME_COMPLETED,
    error: str | None = None,
) -> Path | None:
    """Write `scan-timings.json` into a target's output directory.

    Returns the path written, or None if it could not be written. Never raises
    on a write failure: this runs after every tool has finished, and an
    unwritable diagnostic must not discard a completed scan. `out_dir` is not
    created here: an absent destination must mean "nothing written".
    """
    path = out_dir / SCAN_TIMINGS_FILENAME
    document = build_scan_timings(
        rows,
        target=target,
        target_type=target_type,
        wall_seconds=wall_seconds,
        outcome=outcome,
        error=error,
    )
    try:
        path.write_bytes(json.dumps(document, indent=2).encode("utf-8"))
    except OSError as e:
        logger.warning(
            "Could not write %s to %s: %s", SCAN_TIMINGS_FILENAME, out_dir, e
        )
        return None
    return path
