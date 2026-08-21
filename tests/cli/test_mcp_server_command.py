"""`jmo mcp-server` must set the environment variables the server reads.

There were **no tests for `cmd_mcp_server` at all** before this file, which is
why the following survived: the command accepted `--api-key`, advertised it in
`--help` as "optional, enables production mode", and assigned it to
`MCP_API_KEY` -- a variable nothing under `scripts/jmo_mcp/` reads. The server
reads `JMO_MCP_API_KEYS`. So the flag set a value no code consulted, and the
misdirection was invisible because the only other thing `cmd_mcp_server` does is
call a blocking `mcp.run()`.

`--log-level` and `--human-logs` were exported as `MCP_LOG_LEVEL` /
`MCP_HUMAN_LOGS` and read by nothing either. Three advertised flags, zero
effect.

Every expectation here is DERIVED from the server module's own `os.getenv`
calls rather than restated, so a variable renamed on either side fails this
file instead of drifting silently. The extractor carries a meta-guard, because
an extractor that finds nothing passes every assertion built on it.
"""

from __future__ import annotations

import ast
import io
import os
from pathlib import Path
from unittest import mock

import pytest

from scripts.cli import jmo as cli

# Anchored to this file, not to the cwd. A relative path here would break in
# any worker where another test has chdir'd without restoring -- an
# intermittent failure that looks like a real regression.
REPO_ROOT = Path(__file__).resolve().parents[2]

SERVER_SOURCES = [
    REPO_ROOT / "scripts/jmo_mcp/jmo_server.py",
    REPO_ROOT / "scripts/jmo_mcp/utils/findings_loader.py",
    REPO_ROOT / "scripts/jmo_mcp/utils/rate_limiter.py",
    REPO_ROOT / "scripts/jmo_mcp/utils/source_context.py",
]


def env_vars_the_server_reads() -> set[str]:
    """Every literal passed to os.getenv/os.environ.get under scripts/jmo_mcp/.

    Derived by AST rather than by grep so a substring cannot masquerade as a
    hit -- `"MCP_API_KEY" in source` is True purely because `JMO_MCP_API_KEYS`
    contains it, which is a trap this file exists to avoid falling into.
    """
    names: set[str] = set()
    for path in SERVER_SOURCES:
        tree = ast.parse(path.read_bytes().decode("utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            attr = getattr(func, "attr", None)
            if attr not in ("getenv", "get"):
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                names.add(first.value)
    return names


class Args:
    """Stand-in for the parsed argparse namespace."""

    def __init__(self, **kw):
        self.results_dir = kw.get("results_dir", "./results")
        self.repo_root = kw.get("repo_root", ".")
        self.api_key = kw.get("api_key")
        self.log_level = kw.get("log_level")
        self.human_logs = kw.get("human_logs", False)


@pytest.fixture
def run_cmd(monkeypatch, tmp_path):
    """Invoke cmd_mcp_server with mcp.run() stubbed out, return the env delta."""

    def _run(**kw):
        kw.setdefault("results_dir", str(tmp_path / "results"))
        kw.setdefault("repo_root", str(tmp_path))
        for var in (
            "MCP_API_KEY",
            "JMO_MCP_API_KEYS",
            "MCP_LOG_LEVEL",
            "MCP_HUMAN_LOGS",
            "MCP_RESULTS_DIR",
            "MCP_REPO_ROOT",
        ):
            monkeypatch.delenv(var, raising=False)

        from scripts.jmo_mcp import jmo_server

        with mock.patch.object(jmo_server.mcp, "run", lambda *a, **k: None):
            with mock.patch.object(cli.sys, "stderr", io.StringIO()):
                rc = cli.cmd_mcp_server(Args(**kw))
        return rc, dict(os.environ)

    return _run


# ==============================================================================
# The extractor, and its meta-guard
# ==============================================================================


def test_the_extractor_actually_finds_the_server_env_vars():
    """Meta-guard: a silently-empty extractor passes everything below it."""
    names = env_vars_the_server_reads()

    assert len(names) >= 6, f"extractor found only {names}"
    for expected in (
        "MCP_RESULTS_DIR",
        "MCP_REPO_ROOT",
        "JMO_MCP_API_KEYS",
        "JMO_MCP_RATE_LIMIT_ENABLED",
        "MCP_LOG_LEVEL",
        "MCP_HUMAN_LOGS",
    ):
        assert expected in names, f"{expected} missing from {sorted(names)}"


def test_the_server_does_not_read_mcp_api_key():
    """The variable `--api-key` used to set. Nothing reads it; keep it that way.

    If this fails because the server started reading `MCP_API_KEY`, one of the
    two names is now redundant -- pick one rather than supporting both.
    """
    assert "MCP_API_KEY" not in env_vars_the_server_reads()


# ==============================================================================
# Every var the CLI exports must be one the server reads
# ==============================================================================


def test_every_env_var_the_cli_sets_is_one_the_server_reads(run_cmd):
    """The property that was violated, stated directly.

    Rather than listing which variables `cmd_mcp_server` should set, this
    compares what it *did* set against what the server *does* read.
    """
    _rc, after = run_cmd(api_key="prod-key", log_level="DEBUG", human_logs=True)

    read_by_server = env_vars_the_server_reads()
    set_by_cli = {
        var
        for var in after
        if var.startswith(("MCP_", "JMO_MCP_")) and after.get(var) is not None
    }
    # Only consider ones this command is responsible for.
    set_by_cli &= {
        "MCP_RESULTS_DIR",
        "MCP_REPO_ROOT",
        "MCP_API_KEY",
        "JMO_MCP_API_KEYS",
        "MCP_LOG_LEVEL",
        "MCP_HUMAN_LOGS",
    }

    assert set_by_cli, "cmd_mcp_server set no environment at all"
    orphans = sorted(set_by_cli - read_by_server)
    assert orphans == [], f"CLI sets variables the server never reads: {orphans}"


def test_api_key_lands_in_the_variable_the_server_reads(run_cmd):
    _rc, after = run_cmd(api_key="prod-key-123")

    assert after.get("JMO_MCP_API_KEYS") == "prod-key-123"
    assert "MCP_API_KEY" not in after


def test_log_level_and_human_logs_are_exported(run_cmd):
    _rc, after = run_cmd(log_level="DEBUG", human_logs=True)

    assert after.get("MCP_LOG_LEVEL") == "DEBUG"
    assert after.get("MCP_HUMAN_LOGS") == "1"


def test_no_flags_means_no_orphan_variables(run_cmd):
    """Negative control: without the flags, neither variable is invented."""
    _rc, after = run_cmd()

    assert "JMO_MCP_API_KEYS" not in after
    assert "MCP_LOG_LEVEL" not in after
    assert "MCP_HUMAN_LOGS" not in after
    # ...but the two positional-ish settings are always exported.
    assert "MCP_RESULTS_DIR" in after
    assert "MCP_REPO_ROOT" in after


def test_results_dir_and_repo_root_are_resolved_to_absolute_paths(run_cmd, tmp_path):
    _rc, after = run_cmd(results_dir="./results", repo_root=".")

    assert Path(after["MCP_RESULTS_DIR"]).is_absolute()
    assert Path(after["MCP_REPO_ROOT"]).is_absolute()


# ==============================================================================
# The server honours the exported logging variables
# ==============================================================================


@pytest.mark.parametrize(
    "level_name, expected",
    [("DEBUG", 10), ("INFO", 20), ("WARN", 30), ("WARNING", 30), ("ERROR", 40)],
)
def test_server_honours_mcp_log_level(monkeypatch, level_name, expected):
    """`--log-level` was parsed, advertised, exported, and discarded."""
    import importlib

    from scripts.jmo_mcp import jmo_server

    monkeypatch.setenv("MCP_LOG_LEVEL", level_name)
    importlib.reload(jmo_server)
    try:
        assert expected == jmo_server._LOG_LEVEL
    finally:
        monkeypatch.undo()
        importlib.reload(jmo_server)


def test_server_falls_back_to_info_on_a_nonsense_log_level(monkeypatch):
    """Negative control: a bad value must not crash the server at import."""
    import importlib
    import logging

    from scripts.jmo_mcp import jmo_server

    monkeypatch.setenv("MCP_LOG_LEVEL", "LOUDEST")
    importlib.reload(jmo_server)
    try:
        assert jmo_server._LOG_LEVEL == logging.INFO
    finally:
        monkeypatch.undo()
        importlib.reload(jmo_server)


@pytest.mark.parametrize(
    "value, expected",
    [("1", True), ("true", True), ("", False), ("0", False), ("false", False)],
)
def test_server_honours_mcp_human_logs(monkeypatch, value, expected):
    import importlib

    from scripts.jmo_mcp import jmo_server

    monkeypatch.setenv("MCP_HUMAN_LOGS", value)
    importlib.reload(jmo_server)
    try:
        assert jmo_server._HUMAN_LOGS is expected
    finally:
        monkeypatch.undo()
        importlib.reload(jmo_server)


# ==============================================================================
# The advertised surface
# ==============================================================================


def test_help_text_names_no_path_that_does_not_exist():
    """`--help` pointed at `uv run mcp dev scripts/mcp/server.py`.

    That path has never existed; the module is scripts/jmo_mcp/jmo_server.py.
    Six more sites in docs/MCP_SETUP.md named a second non-existent path,
    scripts/jmo_mcp/server.py, including two client config blocks meant to be
    copy-pasted.
    """
    import argparse
    import re

    parser = argparse.ArgumentParser(prog="jmo")
    sub = parser.add_subparsers(dest="cmd")
    mcp_parser = cli._add_mcp_args(sub)
    text = (mcp_parser.description or "") + " ".join(
        a.help or "" for a in mcp_parser._actions
    )

    referenced = re.findall(r"scripts/[\w/]+\.py", text)
    assert referenced, "help text no longer references the server module at all"
    for path in referenced:
        assert (
            REPO_ROOT / path
        ).exists(), f"--help names a path that does not exist: {path}"


def test_help_text_does_not_claim_authentication(run_cmd):
    """It said `--api-key` "enables production mode". It enables nothing."""
    import argparse

    parser = argparse.ArgumentParser(prog="jmo")
    sub = parser.add_subparsers(dest="cmd")
    mcp_parser = cli._add_mcp_args(sub)
    api_key_help = next(
        a.help for a in mcp_parser._actions if "--api-key" in (a.option_strings or [])
    )

    assert "NOT ENFORCED" in api_key_help
    assert "production mode" not in api_key_help
