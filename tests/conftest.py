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
# Guard: an unmarked test must never spawn a real scanner binary (#907).
# ---------------------------------------------------------------------------
#
# semgrep's production default (`--config auto`, repository_scanner.py
# ~line 288) fetches its ruleset from semgrep.dev over the network. It only
# fires when `_find_tool("semgrep")` resolves a real binary on PATH - true on
# this maintainer's machine (a `--user` pip install outside the project venv:
# `...\Python\Python312\Scripts\semgrep.EXE`), false on CI's sharded jobs. So
# an unmarked test that reaches the real scan path blocks on an undeclared
# network fetch locally, while silently taking a different path (tool
# missing -> dropped or stubbed) on CI - a test whose behaviour depends on
# the machine it happens to run on, with nothing declaring that dependency.
#
# Every tool invocation this codebase makes - semgrep's included - reaches
# the OS via `subprocess.Popen`, NOT `subprocess.run`: `_run_bounded()`
# (scripts/core/tool_runner.py) constructs `Popen` directly so it can
# `communicate(timeout=...)` and walk the whole process tree on expiry (see
# that function's docstring re: launcher scripts like dependency-check.bat
# spawning a grandchild `java` that outlives a killed direct child).
# Recording at `subprocess.run` - issue #907's own first suggestion - would
# silently miss every real scan invocation; confirmed by reading
# tool_runner.py, not assumed. Patching `Popen.__init__` catches both
# shapes, because `subprocess.run` itself builds a `Popen` under the hood.
#
# The matching/recording logic is plain, public functions
# (`scanner_binary_match`, `make_scanner_spawn_recorder`) rather than being
# folded into the fixture, specifically so
# tests/unit/test_scanner_spawn_guard.py can prove the recorder still
# detects a deliberate spawn without needing a real scanner binary
# installed, or a real process spawned, in CI - a real spawn would itself
# need `requires_tools`, which would make that self-test depend on the very
# exemption it exists to prove works.
#
# Scoped to semgrep only (#907's subject), not every scanner binary this
# suite might spawn - see task-8-report.md for the other real binaries this
# recorder observed and left alone, out of this task's scope.
#
# Two fixes are legitimate per the issue (mark `requires_tools`, or route the
# test through an explicit offline `per_tool_config`), and the second one
# means a REAL binary still gets spawned - just never reaching the network.
# A blanket "any unmarked spawn fails" rule cannot tell those apart, so it
# would force every offline-fixed test into `requires_tools` too, which is
# actively wrong for a test whose whole point is "this must hold with no
# tools installed" (see test_deep_scan_accounts_for_every_declared_tool's own
# docstring for why that test in particular must never carry that marker).
#
# So an unmarked spawn is allowed ONLY when BOTH hold: (a) its node ID is on
# the reviewed allowlist below, AND (b) none of its recorded argvs actually
# used the network-fetching `--config auto` default. (b) is what keeps this
# from degrading into "anything not literally auto is fine" for tests nobody
# reviewed: a node ID earns its place on the allowlist by a human reading
# task-8-report.md's reasoning for that specific test, not by an argv shape.
# And (b) alone, without (a), would silently re-open the exact hole this
# guard exists to close for any *new* test that happens to only ever probe
# `--version` (no --config at all) - the class of bug this task found 23 of,
# in the wizard's tool pre-flight check, none of which belong here.

_ALLOWED_OFFLINE_SCANNER_SPAWNS = {
    # Its own point is counting real `_find_binary` resolutions across a
    # profile that deliberately includes semgrep - removing semgrep from the
    # test entirely (skip-tools) would just make it assert nothing about
    # the tool it's most likely to regress on. Fixed via
    # `per_tool.semgrep.configs` pointing at a local rule file (task-8-report.md).
    "tests/integration/test_cli_profiles.py::test_scan_startup_probes_each_tool_at_most_once",
    #
    # The four below were invisible until the recorder stopped watching only
    # semgrep (#994). Each was read individually; none reaches the network.
    #
    # `bandit -r <tmp repo>`. The test's whole point is that an *available*
    # tool runs while missing ones are skipped, and bandit is a dev dependency
    # so it is available on every machine and in CI alike -- marking this
    # `requires_tools` would exclude it from the shards where it currently
    # passes, which is a coverage loss for no safety gain. Offline: bandit
    # fetches nothing.
    "tests/integration/test_cli_scan_ci.py::test_scan_skips_missing_tools_and_runs_available",
    #
    # `trufflehog --version`, three times. These are target-discovery tests --
    # they patch `_check_scan_tools` precisely so the tool pre-flight stops
    # deciding the outcome -- and the probe is what the pre-flight does before
    # discovery bails. A version probe fetches nothing.
    "tests/cli/test_jmo.py::TestScanExitsNonZeroWhenNothingWasScanned::test_missing_repo_path_fails",
    "tests/cli/test_jmo.py::TestScanExitsNonZeroWhenNothingWasScanned::test_no_target_flag_at_all_fails",
    "tests/cli/test_jmo.py::TestScanExitsNonZeroWhenNothingWasScanned::test_the_rejected_target_is_named_in_the_log",
    #
    # `.venv/bin/bandit` during a real end-to-end scan, one entry per platform.
    #
    # Found by CI, not locally, and that is the point worth recording: these are
    # platform-gated (`skipif(sys.platform != ...)`), so a Windows box cannot run
    # any of them and a clean local suite says nothing about them. **A change to
    # the recorder's scope must be verified on CI**, because widening it newly
    # covers tests the local platform never executes. Same shape as Phase 0's
    # "CI found 45 real-state writers a Windows box cannot see".
    #
    # Allowlisted rather than marked `requires_tools`: bandit is a dev
    # dependency, so it is present in the venv on every runner, and these are
    # the only end-to-end full-scan coverage each platform has. Marking them
    # would remove that from the shards where it currently runs, for no safety
    # gain. The spawn is offline. The WSL sibling is included pre-emptively --
    # it fires under `/mnt/c` and neither CI nor this machine's default shell
    # reaches it.
    "tests/e2e/test_cross_platform.py::TestCrossPlatformCompatibility::test_linux_full_scan",
    "tests/e2e/test_cross_platform.py::TestCrossPlatformCompatibility::test_macos_full_scan",
    "tests/e2e/test_cross_platform.py::TestCrossPlatformCompatibility::test_windows_wsl_full_scan",
    #
    # `trufflehog filesystem scripts/ tests/ .github/ --json --no-update`.
    #
    # This one must NOT get the marker either, for a different reason than the
    # opa case below: **no CI job covers `tests/security/`**. Every
    # `requires_tools` invocation in ci.yml and scheduled.yml is path-scoped,
    # and none of those paths includes this directory -- so marking it moved
    # the test from *visibly skipped* in the main shards to *invisibly
    # deselected* everywhere. Measured at Phase 6 closeout: 158
    # `requires_tools` tests exist, 157 are reachable by some job, and this was
    # the one that was not. It never executed on CI either way (bare
    # `trufflehog` is not on the runners' PATH, so it hits FileNotFoundError
    # and skips), but a skip is countable and a deselect is not.
    #
    # `--no-update` means it does not phone home; it is a local filesystem
    # scan. The underlying gap -- that `tests/security/` is outside every CI
    # path scope -- is filed separately.
    "tests/security/test_secrets_management.py::TestSecretsManagement::test_trufflehog_scan_no_verified_secrets",
    #
    # `opa version`. This one must NOT get the marker: it is deliberately not
    # skipped -- its point is that the skip guard and the product agree about
    # whether OPA is usable, on every machine including those without it, and
    # the defect it was written for was a guard that skipped. `requires_tools`
    # would exclude it from exactly the runs it exists to cover. The probe is
    # an availability check and fetches nothing.
    "tests/performance/test_policy_performance.py::test_availability_check_agrees_with_the_product",
    #
    # REMOVED 2026-08-28 (#1021): `test_debug_tool_binary_not_found` no longer
    # spawns `trivy --version`, so its entry is gone rather than kept as a
    # comfort. The spawn was never about trivy -- it was two inert mocks.
    # `cmd_tools_debug` re-imports `ToolManager` INSIDE its own body, so
    # `patch("scripts.cli.tool_commands.ToolManager")` replaced an attribute
    # the function never reads, and the mocked method (`check_tool`) is not one
    # it calls at all. The real resolver ran, found the real binary, and the
    # test's only assertion -- `result == 0` -- was true down both paths.
    #
    # The tests now patch `ToolManager._find_binary` on the class and assert on
    # OUTPUT, which is the only thing that differs between the branches. This
    # allowlist is what keeps that honest: putting the inert patch back makes
    # the recorder fire here rather than passing quietly.
    #
    # `/usr/local/bin/trufflehog --version`, eighteen times. Added 2026-08-28
    # from nightly run 33177110349 (#1039), where every one of the run's 18
    # errors was this same probe.
    #
    # **They are green on every PR because only the nightly installs the real
    # security tools.** The PR shards have no trufflehog on PATH, so
    # `_find_binary` returns None and nothing spawns. That makes the nightly a
    # THIRD environment, after the local box and PR CI, and a guard-scope
    # change is not finished being measured until it has run in all three --
    # #994 widened this recorder, verified locally and on PR CI, and these
    # eighteen were still invisible to both.
    #
    # Same reason as the three `test_jmo.py` entries above, at larger scale:
    # each runs a real `jmo scan` or `jmo ci` whose pre-flight version-checks
    # the tools it was asked for, and trufflehog is the tool these tests use.
    # The probe is the PRODUCT behaving correctly; the tests' invariants are
    # about scan accounting, exit codes and history, not about whether
    # trufflehog exists. `test_scan_startup_does_not_version_check_unrequested_tools`
    # is the clearest case: its subject IS the version check.
    #
    # `--version` fetches nothing. `requires_tools` is wrong for all of them:
    # it would remove the only end-to-end scan-accounting coverage the shards
    # have, on every runner, to silence a probe that is already offline.
    #
    # The durable alternative, if this list grows again: `_check_scan_tools`
    # reads `args._startup_tool_manager`, so a stub manager set there skips
    # the real resolver entirely. That is a change to eighteen call sites
    # rather than one, which is why it is recorded here instead of taken.
    "tests/cli/test_scan_runtime_accounting.py::TestAllowMissingToolsSaysWhatHappened::test_nothing_left_to_run_is_explained",
    "tests/cli/test_scan_runtime_accounting.py::TestProfileShortcutsStoreHistory::test_a_matching_profile_name_is_accepted",
    "tests/cli/test_scan_runtime_accounting.py::TestProfileShortcutsStoreHistory::test_jmo_fast_records_the_scan_in_history",
    "tests/cli/test_scan_runtime_accounting.py::TestProfileShortcutsStoreHistory::test_no_store_history_now_turns_it_off",
    "tests/cli/test_scan_runtime_accounting.py::TestScanExitCodeReflectsTargetOutcome::test_partial_target_exits_zero_but_says_so",
    "tests/cli/test_scan_runtime_accounting.py::TestScanExitCodeReflectsTargetOutcome::test_successful_target_still_exits_zero",
    "tests/cli/test_scan_runtime_accounting.py::TestScanExitCodeReflectsTargetOutcome::test_target_where_every_tool_failed_exits_non_zero",
    "tests/cli/test_scan_runtime_accounting.py::TestScanRecordsItsOwnDuration::test_a_scan_stores_a_duration_a_user_can_read",
    "tests/cli/test_scan_runtime_accounting.py::TestStubbedToolIsNotASuccess::test_a_fully_stubbed_target_still_exits_zero",
    "tests/cli/test_scan_runtime_accounting.py::TestStubbedToolIsNotASuccess::test_a_real_scan_reports_no_stubs",
    "tests/cli/test_scan_runtime_accounting.py::TestStubbedToolIsNotASuccess::test_the_end_of_scan_summary_names_the_stubbed_tools",
    "tests/cli/test_scan_runtime_accounting.py::TestStubbedToolIsNotASuccess::test_the_per_target_line_says_no_tool_ran",
    "tests/cli/test_scan_runtime_accounting.py::TestStubbedToolIsNotASuccess::test_the_scan_metadata_carries_which_tools_were_stubbed",
    "tests/integration/test_cli_profiles.py::test_scan_profile_include_exclude_only_scans_included",
    "tests/integration/test_cli_profiles.py::test_scan_startup_does_not_version_check_unrequested_tools",
    "tests/integration/test_cli_scan_ci.py::test_ci_composes_scan_and_report",
    "tests/integration/test_cli_scan_ci.py::test_ci_runs_the_report_phase_exactly_once",
    "tests/unit/test_signal_handling.py::test_cmd_scan_signal_stop",
}


def _basename(argv0: object) -> str:
    """The lowercased basename of *argv0*, on every platform.

    Splits on both `/` and `\\` explicitly rather than delegating to
    `pathlib.PurePosixPath`, which does not treat a backslash as a separator --
    so a Windows-style argv0 would silently fail to match on the Ubuntu and
    macOS shards even though the same code runs there.
    """
    return str(argv0).replace("\\", "/").rsplit("/", 1)[-1].lower()


def _profile_scanner_binaries() -> tuple[str, ...]:
    """Every binary a profile can invoke, derived from the tool registry.

    Was the literal ``("semgrep",)`` -- #907's subject -- and that scope was
    itself the blind spot #994 is about. #976 item 2 reported
    `test_no_deps_skips_menu` spawning a real `bandit`; running it produced no
    guard error, which read as "the issue is stale". It was not. A Popen-level
    recorder watching every spawn showed what was actually happening:

        uv.EXE pip install --python .venv/Scripts/python.exe --quiet bandit==1.9.4

    Not a spawn -- a real network package install into the developer's venv,
    from a unit test. **"No guard fired" was read as "nothing spawned", and the
    guard's scope made that reading wrong.**

    Derived from `PROFILE_TOOLS` and `TOOL_BINARY_NAMES` rather than listed, so
    a tool added to a profile is covered without a second edit. A hand-kept list
    is the same failure mode one level up: it is always missing whatever nobody
    thought of.
    """
    from scripts.core.tool_registry import PROFILE_TOOLS, TOOL_BINARY_NAMES

    names: set[str] = set()
    for tools in PROFILE_TOOLS.values():
        for tool in tools:
            binary = TOOL_BINARY_NAMES.get(tool, tool)
            # Strip a wrapper-script suffix: the registry records
            # `dependency-check.sh` and `zap.sh`, but the images symlink the
            # bare name too, and either form is a real spawn.
            names.add(binary)
            if "." in binary:
                names.add(binary.rsplit(".", 1)[0])
    return tuple(sorted(names))


SCANNER_BINARY_NAMES = _profile_scanner_binaries()

# The property, not a binary list: no test may spawn a process that installs a
# package or downloads a payload. A list of scanner names will always be
# missing whatever nobody thought of -- and in this case what nobody thought of
# was not a scanner at all, it was `uv`.
#
# Keyed on (basename, required argv tokens) so that `uv run` and `git` stay
# fine while `uv pip install` and `npm install` do not. curl and wget need no
# verb: fetching a payload during a unit test is the thing being forbidden.
_INSTALLER_ARGV_SHAPES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("uv", ("pip", "install")),
    ("uv", ("tool", "install")),
    ("uv", ("add",)),
    ("uv", ("sync",)),
    ("pip", ("install",)),
    ("pip3", ("install",)),
    ("npm", ("install",)),
    ("npm", ("i",)),
    ("npx", ()),
    ("yarn", ("add",)),
    ("pnpm", ("add",)),
    ("brew", ("install",)),
    ("cargo", ("install",)),
    ("gem", ("install",)),
    ("apt", ("install",)),
    ("apt-get", ("install",)),
    ("curl", ()),
    ("wget", ()),
)


def installer_argv_match(argv: list[str]) -> str | None:
    """Return a description of the install/download this argv performs, or None.

    Matches on the whole argv rather than argv[0], because the offending call
    was `uv pip install` -- `uv` itself is an ordinary, harmless binary and
    `uv run` is used legitimately.
    """
    if not argv:
        return None
    exe = _basename(argv[0])
    rest = [str(a) for a in argv[1:]]

    # `python -m pip install ...` reaches the same place by another route.
    if exe.startswith("python") and rest[:2] == ["-m", "pip"] and "install" in rest:
        return "python -m pip install"

    for name, required in _INSTALLER_ARGV_SHAPES:
        if exe not in (name, f"{name}.exe", f"{name}.cmd", f"{name}.bat"):
            continue
        if all(token in rest for token in required):
            return " ".join([name, *required]) if required else name
    return None


# Tests that may legitimately reach an installer or a downloader: they declare
# it. `docker` joins `requires_tools` here because a container test's whole
# point is a real image doing real work.
_SPAWN_DECLARING_MARKERS = ("requires_tools", "docker", "smoke")


def scanner_binary_match(argv0: object) -> str | None:
    """Return the matched entry of `SCANNER_BINARY_NAMES`, or None.

    Compares the resolved basename, case-insensitively, against each known
    scanner name and its Windows `.exe` form - so both a bare `semgrep` on
    PATH and `C:\\...\\semgrep.EXE` match, while something that merely
    *contains* the substring ("semgrep-action", a fixture path ending in
    `semgrep_report.json`) does not.

    Splits on both `/` and `\\` explicitly, rather than delegating to
    `pathlib.Path(...).name`: `PurePosixPath` does not treat a backslash as
    a separator, so a Windows-style argv0 would silently fail to match on
    the Ubuntu/macOS shards even though the same code is exercised there -
    the same class of cross-platform trap this repo has been bitten by
    before (see testing.cross-platform.rules.md's "Path Handling" section).
    This way the match is identical on every platform regardless of which
    platform's paths a given test hardcodes.
    """
    exe = _basename(argv0)
    for binary in SCANNER_BINARY_NAMES:
        if exe in (binary, f"{binary}.exe"):
            return binary
    return None


def make_scanner_spawn_recorder(delegate, sink: list[tuple[str, list[str]]]):
    """Build a `Popen.__init__` replacement that records matching spawns.

    Appends `(argv[0], argv)` to `sink` for every call whose argv[0] matches
    `scanner_binary_match`, then always calls `delegate` - so behaviour for
    every other `Popen` call (the overwhelming majority: pytest itself,
    coverage, the many tests that already mock subprocess execution) is
    completely untouched.
    """

    def _recording_init(self, args, *a, **kw):
        argv = list(args) if isinstance(args, (list, tuple)) else [args]
        strs = [str(x) for x in argv]
        if argv and (
            scanner_binary_match(argv[0]) is not None
            or installer_argv_match(strs) is not None
        ):
            sink.append((str(argv[0]), strs))
        return delegate(self, args, *a, **kw)

    return _recording_init


def semgrep_argv_uses_config_auto(argv: list[str]) -> bool:
    """True if `argv` passes semgrep the network-fetching `--config auto`
    default (repository_scanner.py's `semgrep_configs = ["auto"]`).

    A `--version` probe (no `--config` at all) and an explicit non-"auto"
    `--config` value (this task's own offline-config fixes) both return
    False. Deliberately narrow, not a general "does this reach the network"
    oracle: semgrep's `p/xxx` / `r/xxx` registry shortcuts also pull from
    semgrep.dev and would slip past this check. None of this task's fixes
    use them; see task-8-report.md.
    """
    if "--config" not in argv:
        return False
    idx = argv.index("--config")
    return idx + 1 < len(argv) and argv[idx + 1] == "auto"


@pytest.fixture(autouse=True)
def _guard_no_unmarked_scanner_spawn(request, monkeypatch):
    """Fail the specific test that spawned a real scanner binary without
    declaring `@pytest.mark.requires_tools` -- or, for the narrow case of a
    reviewed, still-offline spawn, without an entry in
    `_ALLOWED_OFFLINE_SCANNER_SPAWNS`.

    Per-test function scope, not session scope: each test gets its own
    fresh `Popen.__init__` patch and its own `sink` list, both local to this
    fixture instance's closure. Unlike the shared-file DB/config guards
    above, there is therefore no cross-worker attribution risk under
    `-n 8` - nothing here is state shared between processes or even between
    tests in the same process.

    Detection rather than prevention, matching the other guards in this
    file: the real spawn (if any) is still allowed to happen - this fixture
    only names the test that caused it, after the fact.

    Known blind spot, not fixed here: this can only see a `Popen` call made
    in THIS process. Several integration tests spawn the whole `jmo` CLI as
    a subprocess, which then spawns semgrep itself - two process hops away
    from anything patchable here. Those were found and fixed by a one-time
    measurement (task-8-report.md), not by this fixture, which cannot see
    them at all, before or after the fix.
    """
    spawns: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(
        subprocess.Popen,
        "__init__",
        make_scanner_spawn_recorder(subprocess.Popen.__init__, spawns),
    )

    yield

    if not spawns:
        return
    declared = any(
        request.node.get_closest_marker(m) is not None for m in _SPAWN_DECLARING_MARKERS
    )

    # Installs and downloads first, and they have NO allowlist. A unit test that
    # reaches the network to install a package is never acceptable, whatever the
    # reviewed reasoning -- and this is the class the semgrep-only scope hid:
    # six tests in tests/cli/test_wizard_tool_checker.py could reach
    # `ToolInstaller.install_tools_parallel`, only one patched it, and the
    # recorder reported nothing because `uv` is not a scanner (#994).
    installs = [
        (installer_argv_match(argv), argv)
        for _, argv in spawns
        if installer_argv_match(argv) is not None
    ]
    if installs and not declared:
        lines = "\n".join(f"  {kind}: {argv!r}" for kind, argv in installs)
        pytest.fail(
            f"{request.node.nodeid} spawned a process that installs or "
            f"downloads:\n{lines}\n"
            "A unit test must not reach the network to fetch a package. Patch "
            "the installer (see tests/cli/test_wizard_tool_checker.py's "
            "module-scoped autouse fixture), or mark the test "
            f"{'/'.join(_SPAWN_DECLARING_MARKERS)} if it genuinely needs the "
            "real thing. There is deliberately no allowlist for this. See #994.",
            pytrace=False,
        )

    if declared:
        return  # declared -- exactly what the markers are for

    reaches_network = any(semgrep_argv_uses_config_auto(argv) for _, argv in spawns)
    if not reaches_network and request.node.nodeid in _ALLOWED_OFFLINE_SCANNER_SPAWNS:
        return  # reviewed exemption, and this run's argv confirms it stayed offline

    names = sorted({name for name, _ in spawns})
    argv_lines = "\n".join(f"  {argv!r}" for _, argv in spawns)
    reason = (
        "used the network-fetching --config auto default"
        if reaches_network
        else "is not on the reviewed _ALLOWED_OFFLINE_SCANNER_SPAWNS allowlist"
    )
    pytest.fail(
        f"{request.node.nodeid} spawned a real scanner binary "
        f"({', '.join(names)}) without @pytest.mark.requires_tools, and {reason}:\n"
        f"{argv_lines}\n"
        "Either mark the test requires_tools (its point is genuinely "
        "running the real binary), or keep the real binary out of this "
        "test's path entirely (an explicit offline per_tool_config, or "
        "--skip-tools for a test whose invariant does not care which state "
        "a given tool lands in). A test that deliberately keeps a real, "
        "offline spawn needs a reviewed entry in "
        "_ALLOWED_OFFLINE_SCANNER_SPAWNS above, not just a non-auto config. "
        "See #907.",
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


def median_seconds_with_setup(
    setup, operation, samples: int = LATENCY_SAMPLES
) -> float:
    """Median wall time of `operation`, with `setup` run UNTIMED before each sample.

    The tool `median_seconds` is missing for the operations its own docstring
    excludes. Anything that mutates a database cannot be repeated in place --
    the second sample of an INSERT measures an UPDATE -- so the choice was a
    single sample or nothing. This is the third option: rebuild the
    precondition each time and time only the operation.

    `setup()` returns whatever state `operation(state)` needs, and its cost is
    outside the clock. That separation is the whole point: a conversion that
    folds fixture construction into the measurement reports the fixture, and
    #742 measured that shape costing 21 fresh databases per test.

    Use it when the measured region is stateful. Use `median_seconds` when it
    is not -- the extra fixture is waste, and `setup` returning a shared object
    would silently re-introduce the very problem this exists to avoid.
    """
    import statistics
    import time

    timings = []
    for _ in range(samples):
        state = setup()
        start = time.perf_counter()
        operation(state)
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
