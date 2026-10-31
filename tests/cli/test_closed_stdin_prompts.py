"""Every prompt in ``jmo.py`` survives a closed stdin.

``jmo ... <&-`` starts Python with ``sys.stdin`` set to None, and ``isatty()``
raises on a closed file. Each prompt guard asked ``sys.stdin.isatty()`` bare, so
a closed stdin crashed the command at the question instead of answering it the
way every other "nobody is there" case is answered. A6 (#1506) fixed the Ko-fi
reminder with ``_stream_is_tty``; these are the four sites it did not touch:

* the missing-tool prompt -- its own ``except Exception`` swallowed the error, so
  the scan ran but said "Tool check failed: 'NoneType' ..." and lost the list
  of tools that would not run;
* the first-run email prompt -- ``jmo scan <&-`` died with a traceback before
  scanning anything;
* the resume prompt -- the same, once a resumable session existed;
* the MCP install prompt -- the same, after announcing the missing SDK.

Each test closes a stream, stubs ``input`` to fail, and asserts the guard took
the branch it takes for a pipe: the prompt was never shown. One control shows a
terminal is still asked.
"""

from __future__ import annotations

import io
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.cli.scan_session import ScanSession, compute_config_hash, save_session
from scripts.core.scan_timings import State, ToolRun


class _Tty(io.StringIO):
    """A text stream that is a terminal."""

    def isatty(self) -> bool:
        return True


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    """An empty home. The variables that make a run non-interactive are cleared,
    so a CI runner's own ``CI=true`` cannot decide a test."""
    for var in ("CI", "JMO_NON_INTERACTIVE", "DOCKER_CONTAINER"):
        monkeypatch.delenv(var, raising=False)
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))
    return fake_home


@pytest.fixture
def no_prompt(monkeypatch):
    """``input`` fails the test: a guard that let a prompt through is caught
    here, not by a hang."""

    def _fail(prompt: str = "") -> str:
        raise AssertionError(f"prompted with nobody to answer: {prompt!r}")

    monkeypatch.setattr("builtins.input", _fail)


@pytest.fixture
def closed_stdin(home, no_prompt, monkeypatch):
    """The process was started with stdin closed (``<&-``): ``sys.stdin`` is None."""
    monkeypatch.setattr(sys, "stdin", None)


def test_missing_tool_check_still_names_the_missing_tools(closed_stdin, caplog):
    """The error was swallowed by the pre-flight's ``except Exception``: the
    scan ran, and the only trace was a warning blaming the tool check, while the
    list the scan prints ("N requested tool(s) are not installed") came back
    empty."""
    args = SimpleNamespace(allow_missing_tools=False)
    missing = SimpleNamespace(name="trufflehog")

    with patch(
        "scripts.cli.tool_manager.get_missing_tools_for_scan",
        return_value=(["semgrep"], [missing]),
    ):
        got = jmo._check_scan_tools(args, ["semgrep", "trufflehog"])

    assert "Tool check failed" not in caplog.text
    assert got == (["semgrep", "trufflehog"], ["trufflehog"])


def test_first_run_email_prompt_is_skipped(closed_stdin, home, capsys):
    jmo._collect_email_opt_in(SimpleNamespace())

    assert capsys.readouterr().out == "", "the welcome banner was printed"
    assert not (home / ".jmo").exists()


def test_mcp_server_says_how_to_install_instead_of_asking(closed_stdin, capsys):
    with patch.object(
        jmo, "_check_mcp_dependencies", return_value=(False, "mcp_missing")
    ):
        rc = jmo.cmd_mcp_server(SimpleNamespace())

    err = capsys.readouterr().err
    assert rc == 1
    assert "Not installing automatically" in err
    assert "pip install 'mcp[cli]>=1.0.0'" in err


@pytest.fixture
def resumable_scan(tmp_path: Path, home: Path, monkeypatch):
    """Return ``run() -> (rc, scanned)`` for ``jmo scan`` with a session on disk
    that has one completed target, ``proj``: ``scanned`` is how many times
    ``proj`` was scanned, so 1 is a fresh scan and 0 is a resume."""
    (home / ".jmo").mkdir()
    (home / ".jmo" / "config.yml").write_text(
        "onboarding_completed: true\nscan_count: 0\n", encoding="utf-8"
    )
    repos_dir = tmp_path / "repos"
    (repos_dir / "proj").mkdir(parents=True)
    (repos_dir / "proj" / "README.md").write_bytes(b"# proj\n")
    results_dir = tmp_path / "results"
    # validate_session_results wants output behind a completed target.
    (results_dir / "individual-repos" / "proj").mkdir(parents=True)
    (results_dir / "individual-repos" / "proj" / "trufflehog.json").write_text(
        "[]", encoding="utf-8"
    )
    cfg_path = tmp_path / "jmo.yml"
    cfg_path.write_text(
        yaml.safe_dump({"tools": ["trufflehog"], "outputs": ["json"]}), encoding="utf-8"
    )
    row = {"trufflehog": ToolRun("trufflehog", State.RAN)}
    session = ScanSession(
        session_id="earlier",
        config_hash=compute_config_hash(cfg_path),
        started_at=time.time(),
        pid=1,
    )
    session.register_target("repo", "proj", ["trufflehog"])
    session.mark_target_complete("proj", row)
    save_session(session, tmp_path / ".jmo" / "scan-session.json")

    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    argv = [
        "jmo",
        "scan",
        "--repos-dir",
        str(repos_dir),
        "--results-dir",
        str(results_dir),
        "--config",
        str(cfg_path),
        "--tools",
        "trufflehog",
        "--no-store-history",
    ]

    def run() -> tuple[int, int]:
        with patch.object(sys, "argv", argv):
            args = jmo.parse_args()
        with patch("scripts.cli.scan_jobs.scan_repository") as scan_repository:
            scan_repository.return_value = ("proj", row)
            rc = jmo.cmd_scan(args)
        return rc, scan_repository.call_count

    return run


@pytest.mark.parametrize("closed", ["stdin", "stdout"])
def test_resume_prompt_starts_fresh(
    home, no_prompt, resumable_scan, monkeypatch, closed
):
    """The prompt asks about both streams, and a terminal on the other one does
    not make the closed one interactive."""
    monkeypatch.setattr(sys, "stdin", None if closed == "stdin" else _Tty())
    monkeypatch.setattr(sys, "stdout", None if closed == "stdout" else _Tty())

    rc, scanned = resumable_scan()

    assert rc == 0
    assert scanned == 1, "the completed target was skipped: the scan resumed"


def test_resume_prompt_still_asks_a_terminal(home, resumable_scan, monkeypatch):
    """The negative control: it fixes what ``scanned == 0`` means above, and
    "never ask" would pass every other test in this file."""
    monkeypatch.setattr(sys, "stdin", _Tty())
    monkeypatch.setattr(sys, "stdout", _Tty())
    asked: list[str] = []

    def _answer_yes(prompt: str = "") -> str:
        asked.append(prompt)
        return "y"

    monkeypatch.setattr("builtins.input", _answer_yes)

    rc, scanned = resumable_scan()

    assert rc == 0
    assert asked == ["Resume previous scan? [Y/n] "]
    assert scanned == 0
