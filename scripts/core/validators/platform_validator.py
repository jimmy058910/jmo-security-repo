"""Cross-Platform validator for the jmo validate system.

Validates path handling, subprocess security, file operations, SQLite,
environment variables, and process/threading across platforms.
Quick tier runs 33 checks; full tier adds 5 Docker/WSL checks (38 total).
"""

from __future__ import annotations

import ast
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from scripts.core.validators import (
    CategoryResult,
    CheckResult,
    CheckStatus,
    timed_check,
)

# Project root: walk up from this file to the repo root
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS_DIR = _PROJECT_ROOT / "scripts"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _project_root() -> Path:
    """Return the resolved project root directory."""
    return _PROJECT_ROOT


# ---------------------------------------------------------------------------
# 1. Path handling checks (8)
# ---------------------------------------------------------------------------


def _check_forward_slashes_in_pathlib() -> CheckResult | None:
    """Forward slashes work in pathlib."""
    p = Path("scripts/core/validators")
    if p.parts:
        return None  # PASS
    return CheckResult(
        name="path-forward-slashes",
        status=CheckStatus.FAIL,
        message="pathlib cannot parse forward-slash paths",
    )


def _check_mixed_separators() -> CheckResult | None:
    """Mixed separators (/ and \\\\) resolve correctly."""
    p1 = Path("scripts/core")
    p2 = Path("scripts\\core")
    if p1.resolve() == p2.resolve():
        return None
    return CheckResult(
        name="path-mixed-separators",
        status=CheckStatus.FAIL,
        message=f"Mixed separators differ: {p1.resolve()} != {p2.resolve()}",
    )


def _check_relative_path_resolve() -> CheckResult | None:
    """Relative paths resolve from project root."""
    resolved = Path(".").resolve()
    if resolved.is_dir():
        return None
    return CheckResult(
        name="path-relative-resolve",
        status=CheckStatus.FAIL,
        message=f"Resolved path is not a directory: {resolved}",
    )


def _check_long_paths() -> CheckResult | None:
    """Long paths (>200 chars) work."""
    with tempfile.TemporaryDirectory() as td:
        # Build a path >200 chars but stay within OS limits.
        # Windows MAX_PATH is 260 by default; temp dir prefix can be ~40-60 chars.
        # Use the extended-length prefix on Windows to support >260.
        base = Path(td)
        if sys.platform == "win32":
            # Use \\?\ prefix for extended-length paths on Windows
            base = Path(f"\\\\?\\{base.resolve()}")
        deep = base
        segment = "a" * 50
        for _ in range(4):
            deep = deep / segment
        deep.mkdir(parents=True, exist_ok=True)
        test_file = deep / "test.txt"
        test_file.write_text("ok", encoding="utf-8")
        content = test_file.read_text(encoding="utf-8")
        # Measure without the \\?\ prefix for consistent length check
        raw_len = len(str(test_file).replace("\\\\?\\", ""))
        if content == "ok" and raw_len > 200:
            return None
    return CheckResult(
        name="path-long-paths",
        status=CheckStatus.FAIL,
        message="Long path read/write failed",
    )


def _check_paths_with_spaces() -> CheckResult | None:
    """Paths with spaces work."""
    with tempfile.TemporaryDirectory() as td:
        spaced = Path(td) / "dir with spaces" / "sub dir"
        spaced.mkdir(parents=True, exist_ok=True)
        f = spaced / "file name.txt"
        f.write_text("spaces ok", encoding="utf-8")
        if f.read_text(encoding="utf-8") == "spaces ok":
            return None
    return CheckResult(
        name="path-spaces",
        status=CheckStatus.FAIL,
        message="Path with spaces failed",
    )


def _check_paths_with_unicode() -> CheckResult | None:
    """Paths with unicode characters work."""
    with tempfile.TemporaryDirectory() as td:
        uni_dir = Path(td) / "\u00e9\u00e8\u00ea_\u00fc\u00f6\u00e4"
        uni_dir.mkdir(parents=True, exist_ok=True)
        f = uni_dir / "t\u00e9st.txt"
        f.write_text("unicode ok", encoding="utf-8")
        if f.read_text(encoding="utf-8") == "unicode ok":
            return None
    return CheckResult(
        name="path-unicode",
        status=CheckStatus.FAIL,
        message="Path with unicode characters failed",
    )


def _check_temp_dir_creation_cleanup() -> CheckResult | None:
    """Temp dir creation and cleanup works."""
    import shutil

    td = tempfile.mkdtemp(prefix="jmo_platform_test_")
    td_path = Path(td)
    if not td_path.is_dir():
        return CheckResult(
            name="path-temp-dir",
            status=CheckStatus.FAIL,
            message="Temp dir not created",
        )
    # Create a file inside
    (td_path / "probe.txt").write_text("probe", encoding="utf-8")
    # Cleanup
    shutil.rmtree(td)
    if td_path.exists():
        return CheckResult(
            name="path-temp-dir",
            status=CheckStatus.FAIL,
            message="Temp dir not cleaned up",
        )
    return None


def _check_root_paths_valid() -> CheckResult | None:
    """pathlib.Path('/') and pathlib.Path('C:\\\\') are valid."""
    posix_root = Path("/")
    if not posix_root.parts:
        return CheckResult(
            name="path-root-valid",
            status=CheckStatus.FAIL,
            message="Path('/') has no parts",
        )
    if sys.platform == "win32":
        win_root = Path("C:\\")
        if not win_root.parts:
            return CheckResult(
                name="path-root-valid",
                status=CheckStatus.FAIL,
                message="Path('C:\\\\') has no parts on Windows",
            )
    return None


# ---------------------------------------------------------------------------
# 2. Subprocess security checks (4) - AST scanning
# ---------------------------------------------------------------------------


def _get_call_name(node: ast.Call) -> str:
    """Extract dotted call name like 'subprocess.run'."""
    func = node.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


_SUBPROCESS_CALLS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}


def _scan_ast_tree(tree: ast.AST) -> list[tuple[str, int, str]]:
    """Walk one AST and return (violation_type, lineno, detail) tuples."""
    violations: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _get_call_name(node)

        # shell=True check
        if call_name in _SUBPROCESS_CALLS:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                    if kw.value.value is True:
                        violations.append(
                            ("shell_true", node.lineno, f"{call_name} uses shell=True")
                        )

        # f-string / format as first arg to subprocess
        if call_name in _SUBPROCESS_CALLS and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.JoinedStr):
                violations.append(("fstring_cmd", node.lineno, f"{call_name}(f'...')"))
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
                violations.append(
                    ("format_cmd", node.lineno, f"{call_name}('...' % ...)")
                )

        # Check for calls that look like os.system
        if call_name == "os.system":
            violations.append(("os_system", node.lineno, "os.system(...)"))

    return violations


def _ast_scan_scripts() -> list[tuple[Path, list[tuple[str, int, str]]]]:
    """Parse all .py files under scripts/ and return (path, violations) pairs."""
    if not _SCRIPTS_DIR.is_dir():
        return []

    results: list[tuple[Path, list[tuple[str, int, str]]]] = []
    py_files = sorted(_SCRIPTS_DIR.rglob("*.py"))

    for path in py_files:
        if "__pycache__" in str(path):
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        violations = _scan_ast_tree(tree)
        if violations:
            results.append((path, violations))
    return results


# Cache AST scan results to avoid re-parsing for each check
_ast_cache: list[tuple[Path, list[tuple[str, int, str]]]] | None = None


def _get_ast_scan() -> list[tuple[Path, list[tuple[str, int, str]]]]:
    """Return cached AST scan results."""
    global _ast_cache  # noqa: PLW0603
    if _ast_cache is None:
        _ast_cache = _ast_scan_scripts()
    return _ast_cache


def _check_no_shell_true() -> CheckResult | None:
    """No shell=True in subprocess.run/call/Popen."""
    all_violations: list[str] = []
    for path, violations in _get_ast_scan():
        for vtype, lineno, detail in violations:
            if vtype == "shell_true":
                all_violations.append(f"{path}:{lineno} {detail}")
    if all_violations:
        return CheckResult(
            name="subprocess-no-shell-true",
            status=CheckStatus.FAIL,
            message=f"{len(all_violations)} shell=True violation(s)",
            details="\n".join(all_violations[:10]),
        )
    return None


def _check_no_fstring_cmd() -> CheckResult | None:
    """No string formatting in subprocess command args."""
    all_violations: list[str] = []
    for path, violations in _get_ast_scan():
        for vtype, lineno, detail in violations:
            if vtype in ("fstring_cmd", "format_cmd"):
                all_violations.append(f"{path}:{lineno} {detail}")
    if all_violations:
        return CheckResult(
            name="subprocess-no-fstring-cmd",
            status=CheckStatus.FAIL,
            message=f"{len(all_violations)} f-string command violation(s)",
            details="\n".join(all_violations[:10]),
        )
    return None


def _check_tool_exists_consistency() -> CheckResult | None:
    """tool_exists() used consistently (no raw shutil.which in scripts/)."""
    violations: list[str] = []
    if not _SCRIPTS_DIR.is_dir():
        return CheckResult(
            name="subprocess-tool-exists-consistency",
            status=CheckStatus.SKIP,
            message="scripts/ directory not found",
        )

    for path in sorted(_SCRIPTS_DIR.rglob("*.py")):
        if path.name == "scan_utils.py":
            continue
        if "__pycache__" in str(path):
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = _get_call_name(node)
                if call_name == "shutil.which":
                    violations.append(f"{path}:{node.lineno} shutil.which()")

    if violations:
        return CheckResult(
            name="subprocess-tool-exists-consistency",
            status=CheckStatus.WARN,
            message=(
                f"{len(violations)} raw shutil.which() call(s) "
                "(prefer tool_exists())"
            ),
            details="\n".join(violations[:10]),
        )
    return None


def _check_no_os_system() -> CheckResult | None:
    """No direct invocations of os.system() in scripts/."""
    all_violations: list[str] = []
    for path, violations in _get_ast_scan():
        for vtype, lineno, detail in violations:
            if vtype == "os_system":
                all_violations.append(f"{path}:{lineno} {detail}")
    if all_violations:
        return CheckResult(
            name="subprocess-no-os-system",
            status=CheckStatus.FAIL,
            message=f"{len(all_violations)} os.system() violation(s)",
            details="\n".join(all_violations[:10]),
        )
    return None


# ---------------------------------------------------------------------------
# 3. Home dir / config checks (3)
# ---------------------------------------------------------------------------


def _check_home_dir_valid() -> CheckResult | None:
    """Path.home() returns a valid directory."""
    home = Path.home()
    if home.is_dir():
        return None
    return CheckResult(
        name="home-dir-valid",
        status=CheckStatus.FAIL,
        message=f"Path.home() = {home} is not a directory",
    )


def _check_jmo_dir_creation() -> CheckResult | None:
    """.jmo/ directory can be created in a temp dir."""
    with tempfile.TemporaryDirectory() as td:
        jmo_dir = Path(td) / ".jmo"
        jmo_dir.mkdir()
        if jmo_dir.is_dir():
            return None
    return CheckResult(
        name="home-jmo-dir",
        status=CheckStatus.FAIL,
        message=".jmo directory creation failed",
    )


def _check_config_loading() -> CheckResult | None:
    """Config loading with load_config() works with platform-appropriate paths."""
    try:
        from scripts.core.config import load_config

        # Load with None (defaults)
        cfg = load_config(None)
        if cfg is not None:
            # Also try loading from the project root jmo.yml if it exists
            jmo_yml = _PROJECT_ROOT / "jmo.yml"
            if jmo_yml.is_file():
                cfg2 = load_config(str(jmo_yml))
                if cfg2 is None:
                    return CheckResult(
                        name="config-loading",
                        status=CheckStatus.FAIL,
                        message="load_config(jmo.yml) returned None",
                    )
            return None
    except ImportError:
        return CheckResult(
            name="config-loading",
            status=CheckStatus.SKIP,
            message="Could not import load_config",
        )
    return CheckResult(
        name="config-loading",
        status=CheckStatus.FAIL,
        message="load_config(None) returned None",
    )


# ---------------------------------------------------------------------------
# 4. File operations checks (5)
# ---------------------------------------------------------------------------


def _check_utf8_readwrite() -> CheckResult | None:
    """UTF-8 read/write to temp file works."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", encoding="utf-8", delete=False
    ) as f:
        f.write("Hello \u00e9\u00e8\u00ea \u4e16\u754c")
        tmp_path = f.name
    try:
        content = Path(tmp_path).read_text(encoding="utf-8")
        if "\u00e9" in content and "\u4e16" in content:
            return None
        return CheckResult(
            name="file-utf8-readwrite",
            status=CheckStatus.FAIL,
            message="UTF-8 content mismatch",
        )
    finally:
        os.unlink(tmp_path)


def _check_temp_directory() -> CheckResult | None:
    """Temp directory creation/cleanup."""
    with tempfile.TemporaryDirectory(prefix="jmo_test_") as td:
        if Path(td).is_dir():
            return None
    return CheckResult(
        name="file-temp-directory",
        status=CheckStatus.FAIL,
        message="Temp directory creation failed",
    )


def _check_bom_handling() -> CheckResult | None:
    """BOM handling (read file with BOM prefix)."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".txt", delete=False) as f:
        # Write UTF-8 BOM + content
        f.write(b"\xef\xbb\xbfHello BOM")
        tmp_path = f.name
    try:
        # Read with utf-8-sig to handle BOM
        content = Path(tmp_path).read_text(encoding="utf-8-sig")
        if content == "Hello BOM":
            return None
        return CheckResult(
            name="file-bom-handling",
            status=CheckStatus.FAIL,
            message=f"BOM not stripped: got {content!r}",
        )
    finally:
        os.unlink(tmp_path)


def _check_line_endings() -> CheckResult | None:
    r"""Line endings (\n vs \r\n) handled."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".txt", delete=False) as f:
        f.write(b"line1\r\nline2\nline3\r\n")
        tmp_path = f.name
    try:
        # text mode normalizes line endings
        content = Path(tmp_path).read_text(encoding="utf-8")
        lines = content.splitlines()
        if len(lines) == 3 and lines == ["line1", "line2", "line3"]:
            return None
        return CheckResult(
            name="file-line-endings",
            status=CheckStatus.FAIL,
            message=f"Line ending normalization failed: {lines!r}",
        )
    finally:
        os.unlink(tmp_path)


def _check_large_file() -> CheckResult | None:
    """File with >1MB content can be written/read."""
    content = "x" * (1024 * 1024 + 1)  # Just over 1MB
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", encoding="utf-8", delete=False
    ) as f:
        f.write(content)
        tmp_path = f.name
    try:
        read_back = Path(tmp_path).read_text(encoding="utf-8")
        if len(read_back) == len(content):
            return None
        return CheckResult(
            name="file-large-file",
            status=CheckStatus.FAIL,
            message=f"Size mismatch: wrote {len(content)}, read {len(read_back)}",
        )
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# 5. Environment variable checks (4)
# ---------------------------------------------------------------------------


def _check_jmo_threads_parsing() -> CheckResult | None:
    """JMO_THREADS parsing (numeric string -> int)."""
    old = os.environ.get("JMO_THREADS")
    try:
        os.environ["JMO_THREADS"] = "8"
        env_val = os.getenv("JMO_THREADS")
        result = max(1, int(env_val))  # type: ignore[arg-type]
        if result == 8:
            return None
        return CheckResult(
            name="env-jmo-threads",
            status=CheckStatus.FAIL,
            message=f"JMO_THREADS round-trip failed: got {result}",
        )
    except (ValueError, TypeError) as e:
        return CheckResult(
            name="env-jmo-threads",
            status=CheckStatus.FAIL,
            message=f"JMO_THREADS parsing failed: {e}",
        )
    finally:
        if old is not None:
            os.environ["JMO_THREADS"] = old
        elif "JMO_THREADS" in os.environ:
            del os.environ["JMO_THREADS"]


def _check_jmo_dedup_threshold_parsing() -> CheckResult | None:
    """JMO_DEDUP_THRESHOLD parsing (float string -> float)."""
    old = os.environ.get("JMO_DEDUP_THRESHOLD")
    try:
        os.environ["JMO_DEDUP_THRESHOLD"] = "0.75"
        env_val = os.getenv("JMO_DEDUP_THRESHOLD", "0.65")
        threshold = float(env_val)
        if 0.5 <= threshold <= 1.0 and threshold == 0.75:
            return None
        return CheckResult(
            name="env-jmo-dedup-threshold",
            status=CheckStatus.FAIL,
            message=f"Threshold mismatch: {threshold}",
        )
    except (ValueError, TypeError) as e:
        return CheckResult(
            name="env-jmo-dedup-threshold",
            status=CheckStatus.FAIL,
            message=f"JMO_DEDUP_THRESHOLD parsing failed: {e}",
        )
    finally:
        if old is not None:
            os.environ["JMO_DEDUP_THRESHOLD"] = old
        elif "JMO_DEDUP_THRESHOLD" in os.environ:
            del os.environ["JMO_DEDUP_THRESHOLD"]


def _check_jmo_profile_parsing() -> CheckResult | None:
    """JMO_PROFILE parsing (string value)."""
    old = os.environ.get("JMO_PROFILE")
    try:
        os.environ["JMO_PROFILE"] = "1"
        env_val = os.getenv("JMO_PROFILE")
        if env_val == "1":
            return None
        return CheckResult(
            name="env-jmo-profile",
            status=CheckStatus.FAIL,
            message=f"JMO_PROFILE mismatch: {env_val!r}",
        )
    finally:
        if old is not None:
            os.environ["JMO_PROFILE"] = old
        elif "JMO_PROFILE" in os.environ:
            del os.environ["JMO_PROFILE"]


def _check_docker_container_detection() -> CheckResult | None:
    """DOCKER_CONTAINER detection."""
    old = os.environ.get("DOCKER_CONTAINER")
    try:
        os.environ["DOCKER_CONTAINER"] = "1"
        detected = os.environ.get("DOCKER_CONTAINER") == "1"
        if detected:
            return None
        return CheckResult(
            name="env-docker-container",
            status=CheckStatus.FAIL,
            message="DOCKER_CONTAINER detection failed",
        )
    finally:
        if old is not None:
            os.environ["DOCKER_CONTAINER"] = old
        elif "DOCKER_CONTAINER" in os.environ:
            del os.environ["DOCKER_CONTAINER"]


# ---------------------------------------------------------------------------
# 6. SQLite platform checks (5)
# ---------------------------------------------------------------------------


def _safe_unlink(path: str) -> None:
    """Unlink a file if it exists, ignoring errors."""
    try:
        os.unlink(path)
    except OSError:
        pass


def _check_sqlite_in_memory() -> CheckResult | None:
    """In-memory DB creation works."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
    conn.execute("INSERT INTO test VALUES (1)")
    row = conn.execute("SELECT * FROM test").fetchone()
    conn.close()
    if row == (1,):
        return None
    return CheckResult(
        name="sqlite-in-memory",
        status=CheckStatus.FAIL,
        message=f"Unexpected row: {row}",
    )


def _check_sqlite_wal_mode() -> CheckResult | None:
    """WAL mode can be enabled."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        conn = sqlite3.connect(db_path)
        result = conn.execute("PRAGMA journal_mode=WAL").fetchone()
        conn.close()
        if result and result[0].lower() == "wal":
            return None
        return CheckResult(
            name="sqlite-wal-mode",
            status=CheckStatus.FAIL,
            message=f"WAL mode not enabled: {result}",
        )
    finally:
        _safe_unlink(db_path)
        _safe_unlink(db_path + "-wal")
        _safe_unlink(db_path + "-shm")


def _check_sqlite_timeout() -> CheckResult | None:
    """Timeout setting works."""
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA busy_timeout=5000")
    result = conn.execute("PRAGMA busy_timeout").fetchone()
    conn.close()
    if result and result[0] == 5000:
        return None
    return CheckResult(
        name="sqlite-timeout",
        status=CheckStatus.FAIL,
        message=f"Timeout not set: {result}",
    )


def _check_sqlite_vacuum() -> CheckResult | None:
    """VACUUM completes."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, data TEXT)")
        conn.execute("INSERT INTO test VALUES (1, 'hello')")
        conn.commit()
        conn.execute("VACUUM")
        conn.close()
        return None
    except sqlite3.Error as e:
        return CheckResult(
            name="sqlite-vacuum",
            status=CheckStatus.FAIL,
            message=f"VACUUM failed: {e}",
        )
    finally:
        _safe_unlink(db_path)
        _safe_unlink(db_path + "-wal")
        _safe_unlink(db_path + "-shm")


def _check_sqlite_lock_release() -> CheckResult | None:
    """Lock is released after connection close."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO test VALUES (1)")
        conn.commit()
        conn.close()

        # Verify we can reopen (lock released)
        conn2 = sqlite3.connect(db_path)
        row = conn2.execute("SELECT * FROM test").fetchone()
        conn2.close()
        if row == (1,):
            return None
        return CheckResult(
            name="sqlite-lock-release",
            status=CheckStatus.FAIL,
            message=f"Unexpected row after reopen: {row}",
        )
    finally:
        _safe_unlink(db_path)
        _safe_unlink(db_path + "-wal")
        _safe_unlink(db_path + "-shm")


# ---------------------------------------------------------------------------
# 7. Process / threading checks (4)
# ---------------------------------------------------------------------------


def _check_cpu_count() -> CheckResult | None:
    """os.cpu_count() returns a positive int."""
    count = os.cpu_count()
    if isinstance(count, int) and count > 0:
        return None
    return CheckResult(
        name="process-cpu-count",
        status=CheckStatus.FAIL,
        message=f"os.cpu_count() returned {count!r}",
    )


def _check_thread_pool_creation() -> CheckResult | None:
    """Thread pool creation works."""
    results: list[int] = []

    def work(x: int) -> int:
        return x * 2

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(work, i) for i in range(4)]
        for fut in futures:
            results.append(fut.result(timeout=5))

    if sorted(results) == [0, 2, 4, 6]:
        return None
    return CheckResult(
        name="process-thread-pool",
        status=CheckStatus.FAIL,
        message=f"Unexpected results: {results}",
    )


def _check_thread_pool_empty() -> CheckResult | None:
    """Thread pool doesn't hang on empty task list."""
    with ThreadPoolExecutor(max_workers=2):
        futures: list[Any] = []
        results = [f.result(timeout=5) for f in futures]
    if results == []:
        return None
    return CheckResult(
        name="process-thread-pool-empty",
        status=CheckStatus.FAIL,
        message="Empty pool returned unexpected results",
    )


def _check_signal_handling() -> CheckResult | None:
    """Signal handling: SIGINT behavior is defined."""
    handler = signal.getsignal(signal.SIGINT)
    if handler is not None:
        return None
    return CheckResult(
        name="process-signal-handling",
        status=CheckStatus.FAIL,
        message="No SIGINT handler defined",
    )


# ---------------------------------------------------------------------------
# Full-tier Docker/WSL checks (5)
# ---------------------------------------------------------------------------


def _check_docker_accessible() -> CheckResult | None:
    """Docker daemon accessible (docker info)."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=15,
        )
        if result.returncode == 0:
            return None
        return CheckResult(
            name="docker-accessible",
            status=CheckStatus.WARN,
            message="docker info returned non-zero",
            details=result.stderr.decode("utf-8", errors="replace")[:200],
        )
    except FileNotFoundError:
        return CheckResult(
            name="docker-accessible",
            status=CheckStatus.SKIP,
            message="Docker not installed",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="docker-accessible",
            status=CheckStatus.WARN,
            message="docker info timed out",
        )


def _check_docker_volume_mount() -> CheckResult | None:
    """Docker volume mount works."""
    try:
        with tempfile.TemporaryDirectory() as td:
            probe = Path(td) / "probe.txt"
            probe.write_text("hello", encoding="utf-8")
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{td}:/mnt/test",
                    "alpine:3.20",
                    "cat",
                    "/mnt/test/probe.txt",
                ],
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0 and b"hello" in result.stdout:
                return None
            return CheckResult(
                name="docker-volume-mount",
                status=CheckStatus.WARN,
                message="Volume mount test failed",
                details=result.stderr.decode("utf-8", errors="replace")[:200],
            )
    except FileNotFoundError:
        return CheckResult(
            name="docker-volume-mount",
            status=CheckStatus.SKIP,
            message="Docker not installed",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="docker-volume-mount",
            status=CheckStatus.WARN,
            message="Docker volume mount timed out",
        )


def _check_docker_jmo_version() -> CheckResult | None:
    """Container jmo --help returns successfully."""
    try:
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "ghcr.io/jimmy058910/jmo-security:balanced",
                "--help",
            ],
            capture_output=True,
            timeout=60,
        )
        if result.returncode == 0:
            return None
        return CheckResult(
            name="docker-jmo-version",
            status=CheckStatus.WARN,
            message="Container jmo --help failed",
            details=result.stderr.decode("utf-8", errors="replace")[:200],
        )
    except FileNotFoundError:
        return CheckResult(
            name="docker-jmo-version",
            status=CheckStatus.SKIP,
            message="Docker not installed",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="docker-jmo-version",
            status=CheckStatus.SKIP,
            message="Docker jmo timed out (image may not be pulled)",
        )


def _check_wsl_detection() -> CheckResult | None:
    """WSL detection works."""
    is_wsl = False
    if sys.platform == "linux":
        try:
            proc_version = Path("/proc/version").read_text(encoding="utf-8")
            is_wsl = (
                "microsoft" in proc_version.lower() or "wsl" in proc_version.lower()
            )
        except OSError:
            pass
    return CheckResult(
        name="wsl-detection",
        status=CheckStatus.PASS,
        message=f"WSL detected: {is_wsl}",
    )


def _check_wsl_path_access() -> CheckResult | None:
    """WSL path access to Windows drives."""
    if sys.platform != "linux":
        return CheckResult(
            name="wsl-path-access",
            status=CheckStatus.SKIP,
            message="Not running on Linux (WSL check N/A)",
        )
    for drive in ["/mnt/c", "/mnt/d"]:
        if Path(drive).is_dir():
            return CheckResult(
                name="wsl-path-access",
                status=CheckStatus.PASS,
                message=f"WSL drive mount found: {drive}",
            )
    try:
        proc_version = Path("/proc/version").read_text(encoding="utf-8")
        if "microsoft" in proc_version.lower():
            return CheckResult(
                name="wsl-path-access",
                status=CheckStatus.WARN,
                message="WSL detected but no Windows drive mount found",
            )
    except OSError:
        pass
    return CheckResult(
        name="wsl-path-access",
        status=CheckStatus.SKIP,
        message="Not running in WSL",
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def validate_platform(tier: str) -> CategoryResult:
    """Cross-Platform validator. Returns CategoryResult with name='Cross-Platform'.

    Args:
        tier: 'quick' for 33 checks, 'full' for all 38 checks.

    Returns:
        CategoryResult with all check results.
    """
    # Reset AST cache for fresh scan
    global _ast_cache  # noqa: PLW0603
    _ast_cache = None

    checks: list[CheckResult] = []

    # --- 1. Path handling (8 checks) ---
    checks.append(
        timed_check("path-forward-slashes", _check_forward_slashes_in_pathlib)
    )
    checks.append(timed_check("path-mixed-separators", _check_mixed_separators))
    checks.append(timed_check("path-relative-resolve", _check_relative_path_resolve))
    checks.append(timed_check("path-long-paths", _check_long_paths))
    checks.append(timed_check("path-spaces", _check_paths_with_spaces))
    checks.append(timed_check("path-unicode", _check_paths_with_unicode))
    checks.append(timed_check("path-temp-dir", _check_temp_dir_creation_cleanup))
    checks.append(timed_check("path-root-valid", _check_root_paths_valid))

    # --- 2. Subprocess security (4 checks) ---
    checks.append(timed_check("subprocess-no-shell-true", _check_no_shell_true))
    checks.append(timed_check("subprocess-no-fstring-cmd", _check_no_fstring_cmd))
    checks.append(
        timed_check(
            "subprocess-tool-exists-consistency", _check_tool_exists_consistency
        )
    )
    checks.append(timed_check("subprocess-no-os-system", _check_no_os_system))

    # --- 3. Home dir / config (3 checks) ---
    checks.append(timed_check("home-dir-valid", _check_home_dir_valid))
    checks.append(timed_check("home-jmo-dir", _check_jmo_dir_creation))
    checks.append(timed_check("config-loading", _check_config_loading))

    # --- 4. File operations (5 checks) ---
    checks.append(timed_check("file-utf8-readwrite", _check_utf8_readwrite))
    checks.append(timed_check("file-temp-directory", _check_temp_directory))
    checks.append(timed_check("file-bom-handling", _check_bom_handling))
    checks.append(timed_check("file-line-endings", _check_line_endings))
    checks.append(timed_check("file-large-file", _check_large_file))

    # --- 5. Environment variables (4 checks) ---
    checks.append(timed_check("env-jmo-threads", _check_jmo_threads_parsing))
    checks.append(
        timed_check("env-jmo-dedup-threshold", _check_jmo_dedup_threshold_parsing)
    )
    checks.append(timed_check("env-jmo-profile", _check_jmo_profile_parsing))
    checks.append(
        timed_check("env-docker-container", _check_docker_container_detection)
    )

    # --- 6. SQLite platform (5 checks) ---
    checks.append(timed_check("sqlite-in-memory", _check_sqlite_in_memory))
    checks.append(timed_check("sqlite-wal-mode", _check_sqlite_wal_mode))
    checks.append(timed_check("sqlite-timeout", _check_sqlite_timeout))
    checks.append(timed_check("sqlite-vacuum", _check_sqlite_vacuum))
    checks.append(timed_check("sqlite-lock-release", _check_sqlite_lock_release))

    # --- 7. Process / threading (4 checks) ---
    checks.append(timed_check("process-cpu-count", _check_cpu_count))
    checks.append(timed_check("process-thread-pool", _check_thread_pool_creation))
    checks.append(timed_check("process-thread-pool-empty", _check_thread_pool_empty))
    checks.append(timed_check("process-signal-handling", _check_signal_handling))

    # --- Full tier: Docker/WSL (5 checks) ---
    if tier == "full":
        checks.append(timed_check("docker-accessible", _check_docker_accessible))
        checks.append(timed_check("docker-volume-mount", _check_docker_volume_mount))
        checks.append(timed_check("docker-jmo-version", _check_docker_jmo_version))
        checks.append(timed_check("wsl-detection", _check_wsl_detection))
        checks.append(timed_check("wsl-path-access", _check_wsl_path_access))

    return CategoryResult(name="Cross-Platform", checks=checks)
