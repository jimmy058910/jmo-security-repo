"""Three things a first run meets in JMo's output (#1082).

1. The scan's progress line was written to stderr whether or not anyone was
   watching. Redirected to a log, its `\\r` frames accumulated: a 20-minute scan
   left a 46 KB log holding about 6 real lines.
2. The history database was `--history-db` on `scan` and `ci` but `--db` on
   `wizard`, `diff`, `history` and `trends`, and nothing said so.
3. "N files could not be analysed" arrived as one JSON line carrying every
   file's reason, unreadable in a terminal and in a log consumer.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import sys
from pathlib import Path

import pytest

from scripts.cli import jmo


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


# -- 1. the progress line ---------------------------------------------------


def test_the_progress_line_stays_out_of_a_redirected_stderr(monkeypatch):
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)

    jmo.ProgressTracker._write_progress_line("\r[0/2] trufflehog (14s) [0%]")

    assert stderr.getvalue() == ""


def test_a_terminal_still_gets_the_progress_line(monkeypatch):
    """The control: "never write it" would pass the test above."""
    stderr = _Tty()
    monkeypatch.setattr(sys, "stderr", stderr)

    jmo.ProgressTracker._write_progress_line("\r[0/2] trufflehog (14s) [0%]")

    assert "[0/2] trufflehog" in stderr.getvalue()


# -- 2. one spelling for the history database -------------------------------


def _subparsers(parser, prefix=()):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                yield (*prefix, name), sub
                yield from _subparsers(sub, (*prefix, name))


def test_the_history_database_has_one_spelling():
    """No subcommand spells it `--db`, and every one that reads the database
    takes `--history-db`: scan, ci, wizard, diff, and each history and trends
    subcommand. Derived from the parser, so a new subcommand is checked too."""
    spelled_db = []
    takes_history_db = set()
    for command, sub in _subparsers(jmo.build_parser()):
        options = {o for a in sub._actions for o in a.option_strings}
        if "--db" in options:
            spelled_db.append(" ".join(command))
        if "--history-db" in options:
            takes_history_db.add(command)
    assert spelled_db == []

    readers = {("scan",), ("ci",), ("wizard",), ("diff",)} | {
        command
        for command, _sub in _subparsers(jmo.build_parser())
        if len(command) == 2
        and command[0] in ("history", "trends")
        # Explains the metrics; it opens no database.
        and command != ("trends", "explain")
    }
    assert len(readers) >= 20
    assert readers - takes_history_db == set()


# -- 3. the bulk warning ----------------------------------------------------


def _results_with_unanalysed_files(root: Path, count: int) -> Path:
    results = root / "results"
    target = results / "individual-repos" / "app"
    target.mkdir(parents=True)
    errors = [
        {"path": f"src/f{i}.js", "message": f"Syntax error at line {i}: " + "x" * 300}
        for i in range(count)
    ]
    (target / "opengrep.json").write_text(
        json.dumps({"results": [], "errors": errors}), encoding="utf-8"
    )
    return results


def _report_log(argv: list[str], capsys) -> list[dict]:
    args = jmo.build_parser().parse_args(argv)
    jmo.configure_scan_logging(args)
    try:
        jmo.cmd_report(args)
    finally:
        jmo.reset_scan_logging()
    lines = capsys.readouterr().err.splitlines()
    return [json.loads(line) for line in lines if line.startswith("{")]


def test_the_bulk_warning_is_one_short_line_with_structured_detail(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    results = _results_with_unanalysed_files(tmp_path, 30)

    log = _report_log(["report", str(results)], capsys)

    (warn,) = [r for r in log if "could not be analysed" in r["msg"]]
    assert warn["level"] == "WARN"
    assert "30 file(s)" in warn["msg"]
    assert "NOT clean results" in warn["msg"]
    assert "SUMMARY.md" in warn["msg"]
    assert "Syntax error" not in warn["msg"], "per-file detail is in the message"
    assert len(warn["msg"]) < 300
    assert warn["tools"] == ["opengrep"]
    assert warn["unanalysed_count"] == 30
    assert len(warn["sample"]) == 10
    assert all("Syntax error" in s for s in warn["sample"])
    assert warn["detail_file"].endswith("SUMMARY.md")
    assert Path(warn["detail_file"]).exists()


def test_without_a_summary_the_sample_stays_in_the_message(
    tmp_path, capsys, monkeypatch
):
    """With no SUMMARY.md to point at, the files are named in the line itself."""
    monkeypatch.chdir(tmp_path)
    results = _results_with_unanalysed_files(tmp_path, 3)
    cfg = tmp_path / "jmo.yml"
    cfg.write_text("outputs: [json]\n", encoding="utf-8")

    log = _report_log(["report", str(results), "--config", str(cfg)], capsys)

    (warn,) = [r for r in log if "could not be analysed" in r["msg"]]
    assert "src/f0.js" in warn["msg"]
    assert "detail_file" not in warn


def test_structured_fields_reach_json_but_not_human_logs():
    record = logging.LogRecord(
        "scripts.x", logging.WARNING, __file__, 1, "short message", None, None
    )
    record.jmo_fields = {"unanalysed_count": 3}

    as_json = json.loads(jmo._ScanLogFormatter(human=False).format(record))
    as_human = jmo._ScanLogFormatter(human=True).format(record)

    assert as_json["msg"] == "short message"
    assert as_json["unanalysed_count"] == 3
    assert "unanalysed_count" not in as_human


@pytest.mark.parametrize("reserved", ["ts", "level", "msg"])
def test_a_field_cannot_overwrite_the_line_itself(reserved):
    record = logging.LogRecord(
        "scripts.x", logging.WARNING, __file__, 1, "kept", None, None
    )
    record.jmo_fields = {reserved: "clobbered"}

    as_json = json.loads(jmo._ScanLogFormatter(human=False).format(record))

    assert as_json[reserved] != "clobbered"


def test_a_redirected_scan_log_gets_no_blank_line(monkeypatch):
    """The newline that ends the progress line after the last tool was printed
    to a log too, where there was no progress line to end."""
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    tracker = jmo.ProgressTracker(1, argparse.Namespace(), total_tools=1)

    tracker.update_tool("shellcheck", "start")
    tracker.update_tool("shellcheck", "success", 0)

    assert "" not in stderr.getvalue().splitlines()
    assert "\n" not in stderr.getvalue()


def test_a_redirected_retry_message_carries_no_carriage_return(monkeypatch):
    """`log()` cleared the progress line with `\\r` and spaces before each retry,
    timeout and no-output message: the lines a log most needs arrived behind
    frames there was no progress line to clear."""
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    tracker = jmo.ProgressTracker(1, argparse.Namespace(), total_tools=1)

    tracker.update_tool("trivy", "retrying", attempt=1, max_attempts=2, message="x")

    assert "trivy: Retry 1/2" in stderr.getvalue()
    assert "\r" not in stderr.getvalue()


def test_a_terminal_still_has_the_progress_line_cleared(monkeypatch):
    stderr = _Tty()
    monkeypatch.setattr(sys, "stderr", stderr)
    tracker = jmo.ProgressTracker(1, argparse.Namespace(), total_tools=1)

    tracker.update_tool("trivy", "retrying", attempt=1, max_attempts=2, message="x")

    assert stderr.getvalue().startswith("\r")
