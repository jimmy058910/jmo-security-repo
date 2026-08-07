#!/usr/bin/env python3
from __future__ import annotations

import sys
import types
from pathlib import Path

from scripts.cli.jmo import cmd_report, parse_args


def test_report_optional_results_dir_mapping(monkeypatch, tmp_path):
    # --results-dir should populate results_dir_opt
    p = tmp_path / "opt-results"
    # The value is a string path, not created, that's fine for argparse mapping
    monkeypatch.setattr(sys, "argv", ["jmo", "report", "--results-dir", str(p)])
    ns = parse_args()
    assert getattr(ns, "cmd", None) == "report"
    assert getattr(ns, "results_dir_opt", None) == str(p)
    # Positional should be None in this form
    assert getattr(ns, "results_dir_pos", None) is None


def test_report_positional_results_dir_mapping(monkeypatch, tmp_path):
    # Positional results_dir should populate results_dir_pos
    p = tmp_path / "pos-results"
    monkeypatch.setattr(sys, "argv", ["jmo", "report", str(p)])
    ns = parse_args()
    assert getattr(ns, "cmd", None) == "report"
    assert getattr(ns, "results_dir_pos", None) == str(p)
    # Optional should be None in this form
    assert getattr(ns, "results_dir_opt", None) is None


def test_cmd_report_missing_results_dir_returns_error(tmp_path: Path):
    # When neither positional nor optional is provided, cmd_report should return 2
    args = types.SimpleNamespace(
        cmd="report",
        results_dir=None,
        results_dir_pos=None,
        results_dir_opt=None,
        out=None,
        config=str(tmp_path / "no.yml"),
        fail_on=None,
        profile=False,
        threads=None,
        log_level=None,
        human_logs=False,
    )
    rc = cmd_report(args)
    assert rc == 2


def _profile_flag_help(monkeypatch, subcommand: str) -> str:
    """The `--profile` help string as argparse would print it for a subcommand."""
    monkeypatch.setattr(sys, "argv", ["jmo", subcommand, "--help"])
    import argparse

    captured = {}

    def record(self, *a, **k):
        for action in self._actions:
            if "--profile" in action.option_strings:
                captured["help"] = action.help
        raise SystemExit(0)

    monkeypatch.setattr(argparse.ArgumentParser, "print_help", record)
    try:
        parse_args()
    except SystemExit:
        pass
    return captured.get("help", "")


def test_profile_flag_help_names_the_phase_it_times(monkeypatch):
    """`--profile` must not read as if it timed the tools.

    It writes `timings.json`, which measures how long *adapters took to parse*
    tool output -- the report phase. The old wording, "Collect per-tool timing
    and write timings.json", reads as per-tool *scan* timing, and that is
    exactly how it was read: issue #722 was filed asking for instrumentation
    that this flag was believed to provide and never did.

    Scan-phase tool durations live in `scan-timings.json`, written by the scan
    jobs. Both files exist now, so the flag has to say which one it is.
    """
    for subcommand in ("report", "ci"):
        help_text = _profile_flag_help(monkeypatch, subcommand).lower()

        assert "parse" in help_text, (
            f"`jmo {subcommand} --profile` does not say it times parsing. "
            f"Got: {help_text!r}"
        )
        assert "scan-timings.json" in help_text, (
            f"`jmo {subcommand} --profile` does not point at the scan-phase "
            f"file, so a user looking for tool run times has no signpost. "
            f"Got: {help_text!r}"
        )
