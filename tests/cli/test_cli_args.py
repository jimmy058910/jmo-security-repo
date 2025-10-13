#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

import types

from scripts.cli.jmo import parse_args, cmd_report


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
