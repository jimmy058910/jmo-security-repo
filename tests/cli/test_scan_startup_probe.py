"""Startup asks only about the tools a scan can run (#1581).

Before a scan, `jmo scan` asks each requested tool for its version twice over:
the critical-update warning and the missing-tool pre-flight. It asked every
requested tool, whatever the targets. Measured on a first run: 44.5 s before
the first scan line, 25.9 s of it zap's `-version` (a JVM sized at
`-Xmx7008m`), on a repository scan where zap cannot run.

Now both ask only the requested tools that read a target type the scan has,
after discovery: a tool no target reads still gets its `skipped` row. Each test
records which tools the `ToolManager` was asked about.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.cli import jmo
from scripts.cli.tool_manager import ToolManager, ToolStatus


@pytest.fixture
def scan(tmp_path: Path, monkeypatch):
    """`jmo scan` in `tmp_path`, with a repository `proj`. Every tool reads as
    installed unless named in `missing`, and none is ever run."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "README.md").write_bytes(b"# proj\n")
    asked: list[str] = []
    missing: set[str] = set()

    def check_tool(_self, name, *_a, **_k):
        asked.append(name)
        return ToolStatus(name=name, installed=name not in missing)

    monkeypatch.setattr(ToolManager, "check_tool", check_tool)
    monkeypatch.setattr(
        "scripts.cli.scan_jobs.tool_loop.find_tool", lambda *_a, **_k: None
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    def run(*argv: str) -> int:
        full = [
            "jmo",
            "scan",
            *argv,
            "--results-dir",
            str(tmp_path / "results"),
            "--history-db",
            str(tmp_path / "history.db"),
        ]
        with patch.object(sys, "argv", full):
            return jmo.cmd_scan(jmo.parse_args())

    return types.SimpleNamespace(run=run, asked=asked, missing=missing, project=project)


def test_a_repository_scan_asks_nothing_of_the_url_tools(scan) -> None:
    scan.run(
        "--repo",
        str(scan.project),
        "--tools",
        "trivy",
        "zap",
        "nuclei",
        "--allow-missing-tools",
    )
    assert "trivy" in scan.asked
    assert not {"zap", "nuclei"} & set(scan.asked), scan.asked


def test_a_scan_with_a_url_still_asks_them(scan) -> None:
    scan.run(
        "--repo",
        str(scan.project),
        "--url",
        "http://127.0.0.1:9/",
        "--tools",
        "trivy",
        "zap",
        "nuclei",
        "--allow-missing-tools",
    )
    assert {"trivy", "zap", "nuclei"} <= set(scan.asked), scan.asked


def test_nothing_that_can_run_here_is_installed(scan) -> None:
    """zap is installed, but reads no repository: with trivy missing there is
    nothing to scan with, as when every requested tool is missing (#811)."""
    scan.missing.add("trivy")
    rc = scan.run(
        "--repo", str(scan.project), "--tools", "trivy", "zap", "--allow-missing-tools"
    )
    assert rc == 1
    assert "zap" not in scan.asked


def test_no_target_means_no_question(scan, tmp_path) -> None:
    """A target that does not exist is refused before any tool is asked."""
    rc = scan.run("--repo", str(tmp_path / "typo"), "--tools", "trivy")
    assert rc == 1
    assert scan.asked == []


def test_the_scan_gives_ctrl_c_back_when_it_ends(scan) -> None:
    """`cmd_scan` handles SIGINT and SIGTERM while it scans. Left installed,
    the next Ctrl-C (in `jmo ci`'s report, or a test session) was swallowed:
    it only set the scan's stop, and a second one quit at once."""
    import signal

    before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    scan.run("--repo", str(scan.project), "--tools", "trivy", "--allow-missing-tools")
    assert {s: signal.getsignal(s) for s in before} == before
