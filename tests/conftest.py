#!/usr/bin/env python3
"""
Shared pytest fixtures and utilities for JMo Security tests.

This module provides:
- Cross-platform Python executable detection
- Platform-specific skip conditions
- Common test utilities
"""

import subprocess
import sys
from pathlib import Path

import pytest

# ============================================================================
# Platform Detection Constants
# ============================================================================

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform == "linux"
IS_MACOS = sys.platform == "darwin"


# ============================================================================
# Platform Skip Decorators
# ============================================================================
# Usage: @skip_on_windows("chmod doesn't work like Unix")

skip_on_windows = pytest.mark.skipif(
    IS_WINDOWS, reason="Test requires Unix-specific features"
)
skip_on_linux = pytest.mark.skipif(IS_LINUX, reason="Test not applicable on Linux")
skip_on_macos = pytest.mark.skipif(IS_MACOS, reason="Test not applicable on macOS")
windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only test")
unix_only = pytest.mark.skipif(IS_WINDOWS, reason="Unix-only test (Linux/macOS)")


# ============================================================================
# Cross-Platform Python Executable
# ============================================================================


def get_python_executable() -> str:
    """
    Get the Python executable path that works on all platforms.

    On Windows, 'python3' doesn't exist - only 'python.exe'.
    Using sys.executable ensures we use the same Python running the tests.

    Returns:
        Path to the Python executable (e.g., '/usr/bin/python3' or 'C:\\Python313\\python.exe')
    """
    return sys.executable


def run_jmo_command(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    """
    Run a JMo CLI command using the correct Python executable.

    This helper replaces patterns like:
        subprocess.run(["python3", "-m", "scripts.cli.jmo", ...])

    With a cross-platform version:
        run_jmo_command(["scan", "--help"])

    Args:
        args: JMo command arguments (without 'python3 -m scripts.cli.jmo' prefix)
        **kwargs: Additional arguments passed to subprocess.run

    Returns:
        subprocess.CompletedProcess result

    Example:
        >>> result = run_jmo_command(["scan", "--help"], capture_output=True, text=True)
        >>> assert result.returncode == 0
    """
    cmd = [sys.executable, "-m", "scripts.cli.jmo"] + args
    return subprocess.run(cmd, **kwargs)


@pytest.fixture
def python_executable() -> str:
    """
    Pytest fixture providing the Python executable path.

    Use this fixture in tests that need to spawn Python subprocesses:

        def test_something(python_executable):
            result = subprocess.run(
                [python_executable, "-m", "scripts.cli.jmo", "scan", "--help"],
                capture_output=True,
                text=True
            )
            assert result.returncode == 0

    Returns:
        Path to the Python executable
    """
    return sys.executable


@pytest.fixture
def jmo_runner(monkeypatch, tmp_path):
    """
    Pytest fixture providing a helper to run JMo commands.

    Use this fixture for cleaner test code:

        def test_scan_help(jmo_runner):
            result = jmo_runner(["scan", "--help"])
            assert result.returncode == 0
            assert "scan" in result.stdout

    Defaults the subprocess's home directory AND working directory to this
    test's tmp_path, closing two separate real-state leaks with two separate
    injection points:

    - `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
      resolves `Path.home()` with no injection point, so a bare
      `jmo_runner(["scan", ...])` would otherwise write to the developer's
      real `~/.jmo/config.yml`. Both HOME (Linux/macOS) and USERPROFILE
      (Windows -- see ntpath.expanduser) are set, since this fixture is
      shared across all three platform e2e suites; each platform's
      Path.home() reads only its own var and ignores the other.
    - History storage defaults to `Path(".jmo/history.db")`, relative to the
      process's cwd, whenever `store_history` is truthy (the CLI default)
      and no `--history-db` override is passed (#802). Redirecting HOME does
      NOT redirect this -- it is cwd-relative, not home-relative -- so the
      default `cwd` here is this test's tmp_path too, unless the caller
      passes its own `cwd=`.

    monkeypatch.setattr(Path, "home", ...) in a caller's own test body has
    NO effect here -- this spawns a real subprocess, and that patches only
    the parent process. A test that needs a *specific* home directory (e.g.
    test_userprofile_env_var) can still call monkeypatch.setenv("USERPROFILE"
    / "HOME", ...) itself: it runs after this default and wins. Likewise a
    test that needs a specific cwd can pass cwd= explicitly to the returned
    callable.

    Returns:
        Callable that runs JMo commands
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    def _run(
        args: list[str], timeout: int = 120, **kwargs
    ) -> subprocess.CompletedProcess:
        defaults = {
            "capture_output": True,
            "text": True,
            "timeout": timeout,
            "cwd": str(tmp_path),
        }
        defaults.update(kwargs)
        return run_jmo_command(args, **defaults)

    return _run


# ============================================================================
# Cross-Platform Error Message Patterns
# ============================================================================

# Pattern matching for "command not found" errors across platforms
# Windows: "cannot find the file specified", "is not recognized"
# Unix: "not found", "No such file or directory"
COMMAND_NOT_FOUND_PATTERNS = [
    "not found",
    "no such file",
    "cannot find",
    "is not recognized",
]


def is_command_not_found_error(stderr: str) -> bool:
    """
    Check if stderr indicates a command-not-found error (cross-platform).

    Args:
        stderr: The stderr output from subprocess

    Returns:
        True if stderr indicates the command was not found
    """
    stderr_lower = stderr.lower()
    return any(pattern in stderr_lower for pattern in COMMAND_NOT_FOUND_PATTERNS)


# ============================================================================
# Integration Test Fixtures
# ============================================================================


@pytest.fixture
def docker_available() -> bool:
    """
    Check if Docker is available for testing.

    Returns:
        True if Docker is available, False otherwise
    """
    try:
        result = subprocess.run(
            ["docker", "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Guard: the test suite must never destroy the developer's real installation.
# ---------------------------------------------------------------------------
#
# `_uninstall_tools` ends with `shutil.rmtree(Path.home() / ".jmo" / "bin")`.
# A test that exercises it without redirecting `Path.home()` deletes the real
# tool directory and still passes - measured: a sentinel file placed in
# `~/.jmo/bin` was gone after a single green test run, taking every installed
# scanner with it. Recovering costs a full `jmo tools install`, and until the
# developer notices, every scan silently under-reports because the tools that
# vanished are the ones being tested.
#
# Detection rather than prevention: redirecting `Path.home()` for the whole
# suite would break tests that legitimately read real user config. This notices
# the damage and names it, which is enough to stop it reaching a second person.


@pytest.fixture(scope="session", autouse=True)
def _guard_real_jmo_install():
    """Fail the run if a test deleted the real ~/.jmo/bin."""
    from pathlib import Path

    jmo_bin = Path.home() / ".jmo" / "bin"
    existed = jmo_bin.exists()

    yield

    if existed and not jmo_bin.exists():
        pytest.fail(
            f"A test deleted the real tool directory {jmo_bin}.\n"
            "Something called an uninstall path without redirecting "
            "Path.home(). Use:\n"
            "    monkeypatch.setattr(Path, 'home', staticmethod(lambda: tmp_path))\n"
            "and NOT monkeypatch.setenv('HOME', ...), which does not affect "
            "Path.home() on Windows.\n"
            "Recover with: jmo tools install --profile fast --yes",
            pytrace=False,
        )


# ---------------------------------------------------------------------------
# Guard: the test suite must never write to the developer's real state.
# ---------------------------------------------------------------------------
#
# Two real files a test can reach without deliberately trying to (#802, #933):
#
#   .jmo/history.db    - the auto-storage hook in report_orchestrator.py
#                         defaults to `Path(".jmo/history.db")` whenever
#                         `store_history` is truthy (the CLI default: it is
#                         `--no-store-history` that opts out) and no
#                         `history_db` override is passed.
#   ~/.jmo/config.yml  - `_show_kofi_reminder()` (scripts/cli/jmo.py),
#                         reached from `cmd_scan()`, has no injection point
#                         at all: it resolves `Path.home() / ".jmo" /
#                         "config.yml"` unconditionally and rewrites the
#                         whole file with `yaml.safe_dump`.
#
# Measured (#802) before any guard existed: +38 scans, +4240 findings,
# +33.8MB across three full-suite runs (~13 scans/run).
#
# Per-test attribution, not just a session-level pass/fail: a session-scoped
# check (`_guard_real_jmo_install`, above) can only tell you the suite
# dirtied state somewhere across ~8000 tests, not which one. The obvious
# per-test design for the DB - open a fresh read-only sqlite connection and
# COUNT(*) before and after every test - was measured against this repo's
# real 1.2GB WAL-mode history.db: 12.5ms/cycle, almost all of it
# `sqlite3.connect()` itself (COUNT(*) and PRAGMA data_version cost the same
# ~13ms on a fresh connection; the SAME query on a REUSED connection costs
# ~0.1ms). At 2 reads/test across ~8000 tests that projects to ~200s added
# to every suite half, paid whether or not anything is actually wrong.
#
# So the DB check is two-tier. A cheap tripwire runs on every test (measured
# ~0.004ms/os.stat(), ~0.07s projected across a full suite): compare
# (size, mtime_ns) of the db file AND its `-wal` sidecar - WAL-mode writes
# land in the sidecar and do not touch the main file's mtime until a
# checkpoint, so both must be watched or a write is invisible to this check.
# Only when the tripwire fires does the expensive tier run (one real
# connection, one COUNT(*)) to confirm the row count actually changed
# (ruling out e.g. VACUUM/ANALYZE-style housekeeping that touches the file
# without changing row counts) and to name the test that did it.
#
# The config.yml check has no such problem: read_bytes() on a file this
# small measured ~0.06ms/cycle, ~1s projected across a full suite - so it
# just compares bytes before and after every test directly.
#
# Known limitation under `-n 8`: two workers racing the same window can, in
# principle, misattribute one worker's write to the other's nodeid, because
# both are watching the same real shared file from separate processes. If
# this guard names a test, confirm with a serial rerun (`-n0 <nodeid>`)
# before treating the attribution as final.

_REAL_HISTORY_DB = Path(".jmo/history.db").resolve()
_REAL_JMO_CONFIG = Path.home() / ".jmo" / "config.yml"

_history_db_state: dict[str, object] = {}
_jmo_config_state: dict[str, object] = {}


def _history_db_probe(real_db: Path) -> tuple[int, int, int, int] | None:
    """Cheap fingerprint of the real DB: (size, mtime_ns) of the main file
    and its -wal sidecar. None if the main file does not exist."""
    if not real_db.exists():
        return None
    db_stat = real_db.stat()
    wal = real_db.with_name(real_db.name + "-wal")
    if wal.exists():
        wal_stat = wal.stat()
        wal_size, wal_mtime = wal_stat.st_size, wal_stat.st_mtime_ns
    else:
        wal_size, wal_mtime = 0, 0
    return (db_stat.st_size, db_stat.st_mtime_ns, wal_size, wal_mtime)


def _history_db_scans_count(real_db: Path) -> int:
    """Definitive (opens a real read-only connection) scans-table count."""
    import sqlite3

    conn = sqlite3.connect(f"file:{real_db.as_posix()}?mode=ro", uri=True)
    try:
        return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    finally:
        conn.close()


def _history_db_refresh() -> None:
    probe = _history_db_probe(_REAL_HISTORY_DB)
    count = _history_db_scans_count(_REAL_HISTORY_DB) if probe is not None else None
    _history_db_state["probe"] = probe
    _history_db_state["count"] = count


@pytest.fixture(autouse=True)
def _guard_real_history_db(request):
    """Fail the specific test that wrote to the real .jmo/history.db."""
    if "probe" not in _history_db_state:
        _history_db_refresh()
        if _history_db_state["probe"] is None:
            print(
                f"\n_guard_real_history_db: {_REAL_HISTORY_DB} does not "
                "exist -- nothing to guard this run (fresh clone or CI)."
            )

    before_probe = _history_db_state["probe"]
    before_count = _history_db_state["count"]

    yield

    after_probe = _history_db_probe(_REAL_HISTORY_DB)
    if after_probe == before_probe:
        return  # cheap path: file untouched during this test

    after_count = (
        _history_db_scans_count(_REAL_HISTORY_DB) if after_probe is not None else None
    )
    _history_db_state["probe"] = after_probe
    _history_db_state["count"] = after_count

    if before_count is None and after_count is not None:
        pytest.fail(
            f"{request.node.nodeid} created the real history database "
            f"{_REAL_HISTORY_DB}, which did not exist before this test.\n"
            "Use history_db=str(tmp_path / 'history.db') and patch "
            "store_scan -- see tests/unit/test_config_precedence.py.",
            pytrace=False,
        )
    elif before_count is not None and after_count is None:
        pytest.fail(
            f"{request.node.nodeid} deleted the real history database "
            f"{_REAL_HISTORY_DB} (had {before_count} scans).",
            pytrace=False,
        )
    elif before_count != after_count:
        pytest.fail(
            f"{request.node.nodeid} wrote to the real history database "
            f"{_REAL_HISTORY_DB}: scans {before_count} -> {after_count}.\n"
            "Use history_db=str(tmp_path / 'history.db') and patch "
            "store_scan -- see tests/unit/test_config_precedence.py.",
            pytrace=False,
        )
    # else: the probe tripped (e.g. WAL checkpoint / VACUUM housekeeping)
    # but the row count did not change -- not a violation. The cache above
    # is already refreshed so the next test compares against reality.


def _read_jmo_config_bytes() -> bytes | None:
    return _REAL_JMO_CONFIG.read_bytes() if _REAL_JMO_CONFIG.exists() else None


@pytest.fixture(autouse=True)
def _guard_real_jmo_config(request):
    """Fail the specific test that wrote to the real ~/.jmo/config.yml."""
    if "seen" not in _jmo_config_state:
        _jmo_config_state["seen"] = True
        _jmo_config_state["bytes"] = _read_jmo_config_bytes()
        if _jmo_config_state["bytes"] is None:
            print(
                f"\n_guard_real_jmo_config: {_REAL_JMO_CONFIG} does not "
                "exist -- nothing to guard this run (fresh clone or CI)."
            )

    before = _jmo_config_state["bytes"]

    yield

    after = _read_jmo_config_bytes()
    if after == before:
        return

    _jmo_config_state["bytes"] = after

    if before is None:
        pytest.fail(
            f"{request.node.nodeid} created the real config file "
            f"{_REAL_JMO_CONFIG}, which did not exist before this test.\n"
            "_show_kofi_reminder() (scripts/cli/jmo.py) resolves "
            "Path.home() unconditionally with no injection point -- patch "
            "it before calling cmd_scan()/main(['scan', ...]):\n"
            "    monkeypatch.setattr(Path, 'home', staticmethod(lambda: tmp_path))",
            pytrace=False,
        )
    else:
        pytest.fail(
            f"{request.node.nodeid} wrote to the real config file "
            f"{_REAL_JMO_CONFIG} ({len(before)} bytes -> "
            f"{len(after) if after is not None else 0} bytes).\n"
            "_show_kofi_reminder() (scripts/cli/jmo.py) resolves "
            "Path.home() unconditionally with no injection point -- patch "
            "it before calling cmd_scan()/main(['scan', ...]):\n"
            "    monkeypatch.setattr(Path, 'home', staticmethod(lambda: tmp_path))",
            pytrace=False,
        )


# ---------------------------------------------------------------------------
# Scan logging leaks out of the test that configured it.
# ---------------------------------------------------------------------------
# `configure_scan_logging()` sets a level and turns off propagation on the
# shared `logging.getLogger("scripts")`, process-globally. Any test that runs
# a scan - or calls `jmo.main()` with any subcommand, which configures it too
# - leaves those settings in place for the rest of the session.
#
# The level is what breaks `caplog`: an explicit WARNING on `scripts` makes
# every `scripts.*` child drop INFO records at the source, and
# `caplog.at_level(INFO)` cannot undo it because it raises the level of the
# *root* logger, which effective-level resolution never reaches.
#
# That is order-dependent pollution, and it is indistinguishable from a flake
# at the symptom level: the affected tests pass in isolation and fail in a
# full run or a shard. Six `test_policy_reporter` tests were dismissed as
# "load flakes" on exactly that evidence before the cause was found.
#
# Restore after every test rather than asking each scan test to remember.


@pytest.fixture(autouse=True)
def _restore_scan_logging():
    """Undo any `configure_scan_logging()` a test left behind."""
    yield

    from scripts.cli.jmo import reset_scan_logging

    reset_scan_logging()


# ---------------------------------------------------------------------------
# Timing a wall-clock budget without measuring the runner's mood.
# ---------------------------------------------------------------------------

# Windows clock granularity, measured on a dev box:
#
#     time.monotonic()       15.0000 ms
#     time.time()             0.5021 ms
#     time.perf_counter()     0.0001 ms
#
# `perf_counter` is the clock this repository standardised on after a "just use
# monotonic" change made a different flake 26.7% worse (see
# tests/unit/test_tool_runner.py).
#
# Granularity is necessary but not sufficient. One sample on a shared CI runner
# measures the runner as much as the code: #733 flaked at 15.62ms against a
# 10ms budget on a PR that touched only the Makefile - 1.6x over, which is well
# inside normal scheduling noise. Taking the median of several runs fixed it,
# measured spread 15x -> 1.08x (#736).
LATENCY_SAMPLES = 21


def median_seconds(operation, samples: int = LATENCY_SAMPLES) -> float:
    """Median wall time of `operation` in seconds, over `samples` runs.

    Median rather than mean: one descheduled run should not move the result,
    and that is exactly the failure being defended against.

    **Only for operations that can honestly be repeated.** Re-running something
    that mutates a database, or that populates a cache the next run then hits,
    measures a different code path after the first sample. Give those a fresh
    fixture per sample or leave them on a single measurement.
    """
    import statistics
    import time

    timings = []
    for _ in range(samples):
        start = time.perf_counter()
        operation()
        timings.append(time.perf_counter() - start)
    return statistics.median(timings)


# ---------------------------------------------------------------------------
# Repo walking that prunes during traversal, not after.
# ---------------------------------------------------------------------------


def iter_repo_files(
    root: Path,
    skip_dir_names: set[str],
    suffixes: set[str] | None = None,
) -> list[Path]:
    """Walk `root`, skipping `skip_dir_names` **during** descent.

    The obvious formulation is wrong in a way that hides behind a platform:

        for path in root.rglob("*"):
            if not path.is_file():          # <- stats every vendored file
                continue
            if any(p in SKIP for p in path.parts):   # <- far too late

    `rglob` descends into `node_modules` regardless of any later filter, and
    `is_file()` stats each entry it yields. Measured symptoms of that single
    bug, one per platform:

    - **Windows**: `OSError: [WinError 1920]` on the pnpm symlink farm under
      `scripts/dashboard/node_modules/.pnpm/`.
    - **Linux over /mnt/c (WSL)**: no error at all - the suite simply **times
      out** in `os.stat`, because stat-ing tens of thousands of vendored files
      across the 9p mount is glacial.

    Neither symptom points at the cause on its own, which is how it survived:
    each platform reads as its own quirk. `os.walk` with in-place `dirs`
    pruning never enters those trees.
    """
    import os

    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # In-place mutation is what prunes the walk; rebinding does nothing.
        dirnames[:] = [d for d in dirnames if d not in skip_dir_names]
        base = Path(dirpath)
        for name in filenames:
            path = base / name
            if suffixes is not None and path.suffix not in suffixes:
                continue
            found.append(path)
    return found
