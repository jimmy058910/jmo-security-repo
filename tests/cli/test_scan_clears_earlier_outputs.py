#!/usr/bin/env python3
"""A scan clears the outputs it is about to write (#1371).

A results directory reused from an earlier scan still holds that scan's
`<tool>.json`. The report now reads a tool's output only when this scan's row
says the tool ran, but the row can only vouch for a file this scan wrote:

- A tool that exits 0 and writes nothing was graded `ran` when an earlier
  scan's file was there, because the runner's "wrote nothing" check is "does
  the output file exist". It must be `failed:no output`.
- The files a tool leaves are named `<tool>.json`, `<tool>.git.json` and
  `<tool>.part<N>.json`, and belong to the tool by their name before the first
  dot (the rule the report maps an output to its adapter by). A `<tool>*`
  prefix match would delete `yara-x.json` as `yara`'s.

The process is faked at the one place `ToolRunner` starts it, so no scanner is
needed and nothing is spawned.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.cli import jmo
from scripts.cli.scan_jobs import tool_loop
from scripts.core.scan_timings import Reason, State
from scripts.core.tool_runner import ToolRunner


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "README.md").write_bytes(b"# proj\n")
    return project


@pytest.fixture
def out(tmp_path: Path) -> Path:
    folder = tmp_path / "results" / "individual-repos" / "proj"
    folder.mkdir(parents=True)
    return folder


@pytest.fixture
def exits_zero_writing_nothing(monkeypatch) -> None:
    """Every process the runner starts exits 0 with no output and writes no
    file: a tool that did nothing and said it succeeded."""

    def run(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("scripts.core.tool_runner._run_bounded", run)


def _run(repo: Path, out: Path, *tools: str):
    return tool_loop.run_tools(
        tools=list(tools),
        target_type="repo",
        target=repo,
        target_label="proj",
        out_dir=out,
        timeout=60,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=ToolRunner,
        find_tool_func=lambda name: name,
        repo_root=repo,
    )


def test_a_stale_output_does_not_pass_as_written(repo, out, exits_zero_writing_nothing):
    """An earlier scan's trivy.json is in the folder; this scan's trivy exits 0
    and writes nothing. The row says so rather than vouching for the old file."""
    stale = out / "trivy.json"
    stale.write_bytes(b'{"Results": [{"Target": "old", "Vulnerabilities": []}]}')

    rows = _run(repo, out, "trivy")

    assert (rows["trivy"].state, rows["trivy"].reason) == (
        State.FAILED,
        Reason.NO_OUTPUT,
    ), rows["trivy"]
    assert not stale.exists(), "the earlier scan's file must not survive as this one's"


def test_the_scan_clears_every_output_file_of_the_tools_it_runs(
    repo, out, exits_zero_writing_nothing
):
    """`trivy.json`, `trivy.git.json` and `trivy.part<N>.json` are trivy's;
    `trivy-extra.json` is another tool's, and a tool not run this time is left
    alone (the report ignores it, its row not being there)."""
    for name in (
        "trivy.json",
        "trivy.git.json",
        "trivy.part1.json",
        "trivy.part12.json",
    ):
        (out / name).write_bytes(b"{}")
    keep = ("trivy-extra.json", "shellcheck.json", "notes.txt")
    for name in keep:
        (out / name).write_bytes(b"{}")

    _run(repo, out, "trivy")

    left = sorted(p.name for p in out.iterdir())
    assert left == sorted([*keep, "scan-timings.json"]), left


def test_a_scan_into_a_reused_results_dir_reports_only_what_it_ran(
    tmp_path, monkeypatch
):
    """Both halves through `jmo scan`: the earlier scan's `trivy.json` (not
    requested now) and `shellcheck.json` (requested, and rewritten) are in the
    folder, and `findings.json` holds this scan's shellcheck findings alone."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "run.sh").write_bytes(b"#!/bin/sh\necho $1\n")
    (tmp_path / "jmo.yml").write_bytes(b"outputs: [json]\n")
    results = tmp_path / "results"
    folder = results / "individual-repos" / "proj"
    folder.mkdir(parents=True)
    (folder / "trivy.json").write_bytes(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "package-lock.json",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": f"CVE-2026-000{i}",
                                "Severity": "HIGH",
                            }
                            for i in range(4)
                        ],
                    }
                ]
            }
        ).encode()
    )
    (folder / "shellcheck.json").write_bytes(b"[]")
    this_scan = json.dumps(
        [
            {
                "file": "run.sh",
                "line": 2 + i,
                "endLine": 2 + i,
                "column": 6,
                "endColumn": 8,
                "level": "info",
                "code": 2086,
                "message": f"Double quote to prevent globbing {i}",
            }
            for i in range(2)
        ]
    )

    def run(command, **_kwargs):
        return subprocess.CompletedProcess(command, 1, this_scan, "")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    monkeypatch.setattr(
        "scripts.cli.tool_manager.ToolManager._find_binary", lambda *a, **k: None
    )
    monkeypatch.setattr(
        "scripts.cli.scan_jobs.tool_loop.find_tool", lambda name, *a, **k: name
    )
    monkeypatch.setattr("scripts.core.tool_runner._run_bounded", run)
    monkeypatch.setenv("CI", "true")
    argv = [
        "jmo",
        "scan",
        "--repo",
        "proj",
        "--tools",
        "shellcheck",
        "--results-dir",
        str(results),
        "--history-db",
        str(tmp_path / "history.db"),
    ]
    with patch.object(sys, "argv", argv):
        args = jmo.parse_args()

    jmo.cmd_scan(args)

    document = json.loads((results / "summaries" / "findings.json").read_bytes())
    assert [f["tool"]["name"] for f in document["findings"]] == ["shellcheck"] * 2
