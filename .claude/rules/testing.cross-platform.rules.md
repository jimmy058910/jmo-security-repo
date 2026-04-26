---
title: Cross-Platform Testing (Windows/macOS/Linux)
paths:
  - tests/**/*.py
  - scripts/**/*.py
  - .github/workflows/ci.yml
references:
  - testing.rules.md (test infrastructure)
  - TEST.md (complete testing guide)
---

# Cross-Platform Testing & Windows Hang Prevention

**What this covers:** Path handling, platform-specific test skips, and critical rules to prevent Windows CI hangs that have historically plagued this project.

## Path Handling

- **Use forward slashes in code:** `path/to/file` works on Windows and Unix.
- **Use `pathlib.Path`** for path operations (handles both separators).
- **Docker paths require POSIX format:** `/c/Projects/...` or `/mnt/c/...` on WSL.

```python
from pathlib import Path

# CORRECT: Works on Windows, macOS, Linux
output_dir = Path("results") / "scan-001"
docker_path = str(output_dir).replace("\\", "/")

# WRONG: Backslashes fail on Unix
results_path = "results\\scan-001"
```

## Home Directory (Platform-Aware)

```python
# WRONG: Only works on Unix (HOME not set on Windows)
monkeypatch.setenv("HOME", str(tmp_path))

# CORRECT: Works on Windows, macOS, Linux
from pathlib import Path
monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
```

## Platform Detection & Skips

```python
from tests.conftest import IS_WINDOWS, IS_LINUX, IS_MACOS
from tests.conftest import skip_on_windows, unix_only

@skip_on_windows  # Skips with clear reason
def test_unix_permissions():
    pass

@unix_only        # Alias for skip_on_windows
def test_symlinks():
    pass

if IS_WINDOWS:
    # Skip certain assertions on Windows
    pass
```

## Command-Not-Found Error Matching (Cross-Platform)

```python
from tests.conftest import is_command_not_found_error

# Works on all platforms (different error messages per OS)
assert is_command_not_found_error(stderr)  # True if "not found" on Unix, "cannot find" on Windows
```

## Common Cross-Platform Issues

| Issue | Windows | Solution |
|-------|---------|----------|
| `chmod` permissions | No effect (no Unix execute bits) | Skip with `@skip_on_windows` |
| File locking | More aggressive | Close files before deletion |
| Process spawning | Different error codes | Test `!= 0`, not specific codes |
| TEMP directory | Uses `%TEMP%` | `Path.home() / "AppData" / "Local" / "Temp"` |

## Windows CI Architecture

**Pinned configuration:**

- `windows-2022` (stable, D: drive for fast I/O).
- `TEMP=D:\Temp` set via a CI step (30% I/O speedup).
- `-p no:xdist -p no:rerunfailures` (disables plugins that cause socket deadlocks).
- `--timeout=60` per test (halved from 120s for faster failure detection).
- `-m "not smoke and not requires_tools and not docker and not slow"`.
- Post-test cleanup: `Stop-Process` kills orphan processes.
- `timeout-minutes: 15` hard job-level safety net.

## CRITICAL: Windows Test Hang Prevention

This project has a documented history of Windows CI hangs. These rules are **mandatory**:

| Rule | Why | Example |
|------|-----|---------|
| **Always pass `timeout=` to `subprocess.run`** | No-timeout calls become orphan processes | `subprocess.run(cmd, timeout=60)` |
| **Always mock `ToolInstaller`** | Real installs spawn `cmd.exe`/`node.exe` that hang | `@patch("scripts.cli.tool_installer.ToolInstaller")` |
| **Use `-p no:xdist` on Windows/macOS CI** | pytest-rerunfailures 16.x + xdist deadlocks with pytest-timeout thread cleanup | CI sets `-p no:xdist` in `ci.yml` |
| **Use `join(timeout=N)` on threads** | Bare `.join()` blocks forever if the thread hangs | `thread.join(timeout=10)` |
| **Don't spawn >100 threads in tests** | Windows thread creation is expensive | Use `concurrent.futures` with `max_workers` |
| **Mark real-tool tests `@pytest.mark.requires_tools`** | CI excludes them; tools aren't installed | `-m "not requires_tools"` in `ci.yml` |

## Root Cause: pytest-timeout Thread Method on Windows

pytest-timeout uses `timeout_method = "thread"` on Windows (signal-based doesn't work). When a subprocess hangs:

1. The thread method can kill the Python test thread.
2. But NOT the child process (which becomes an orphan).
3. `--reruns` then retries the test, multiplying hang time.

**If Windows CI hangs:**

1. Check for missing `timeout=` in subprocess calls.
2. Check for missing mocks on `ToolInstaller` / `subprocess.run`.
3. Check for bare `.join()` on threads (must use `timeout=N`).
4. Check for tests spawning real tools without `@pytest.mark.requires_tools`.
5. If all else fails, verify `shell=False` explicitly in subprocess calls.

## Subprocess Testing Rules

1. **Always mock `subprocess.run`** for tests calling external commands.
2. **Never assume tools exist** — mock `tool_exists()` and `find_tool()` together.
3. **Use `shell=False`** in production code (security requirement).
4. **Verify mock signatures** — test `shell=False` explicitly.

## Docker Bind-Mount UID Mismatch (Linux CI)

GitHub Actions runners use **UID 1001**. JMo Docker containers run as **`USER jmo` (UID 1000)** by default. Bind-mounted host directories preserve host ownership, so:

- pytest's `tmp_path` is owned by UID 1001 with mode `0o700` (pytest default).
- Container code runs as UID 1000, treated as "other" relative to host UID.
- Without world-rwx bits, the container can't even `stat` mounted files → `EACCES`.
- **On Python 3.12+, `Path.exists()` propagates `PermissionError`** instead of silently returning False (3.11 behavior). Any code path calling `Path.exists()` on a non-traversable mount crashes.

**Fix pattern** for tests that bind-mount pytest `tmp_path`:

```python
def test_docker_thing(self, tmp_path: Path):
    # Create test fixtures under tmp_path...
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.py").write_text("...")

    # UID-mismatch fix (mirrors scheduled.yml:1083 pattern):
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(str(tmp_path), 0o777)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(str(src_dir), 0o777)

    result = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{tmp_path}:/scan", ...],
        ...
    )
```

**Why `0o777` and not something tighter:**

- `0o755` doesn't include write for "other" → container can't create result subdirs.
- `0o757` works but visually unusual.
- `0o777` is the established convention (matches `scheduled.yml:1083`).
- Marked with `# nosemgrep:` because it's intentional test infrastructure on a run-scoped tmp dir.

**Alternative when test doesn't fundamentally need non-root**: pass `--user 0:0` to docker run (run as root, traversal not blocked).

**Variant: arbitrary UID (`--user $(id -u):$(id -g)`)** — semgrep, scancode, and other tools that write to `~/.cache` will fail because no `/etc/passwd` entry exists for that UID, so `HOME` resolves to `/`. Set `-e HOME=/tmp` explicitly so the container has a writable home.

## Workflow Marker Filter Convention

Pytest invocations in CI workflows use these filter sets. Each filter is tuned to match the runner environment's actual capabilities (which tools/packages are installed).

| Workflow:Job | Filter | Rationale |
|---|---|---|
| `ci.yml` quick-checks (sharded ×4) | `-m "not smoke and not requires_tools and not docker"` | Excludes tests needing PyPI release, real scanners, or Docker daemon. |
| `ci.yml` Quick coverage check | `-m "not smoke and not requires_tools and not docker and not slow"` | Adds `not slow` for the coverage-only run (≥70% threshold). |
| `ci.yml` tool-contract-tests | `-m "requires_tools"` | Tools installed via the `Install tools` step earlier in the job. |
| `scheduled.yml` Nightly Extended | `-m "not requires_tools and not smoke"` | Includes slow tests intentionally (omit `not slow`) since nightly has the time budget. Excludes real-tool + smoke tests because runner doesn't install tools or install released package. |
| `scheduled.yml` Tool Smoke Tests | `-m "smoke"` | Runs only `@pytest.mark.smoke` tests against released `jmo-security` PyPI package. |
| `scheduled.yml` Integration matrix | `-m "integration and not slow"` | Per-component integration tests; `not slow` keeps matrix runtime bounded. |
| `scheduled.yml` E2E (×2 jobs) | `-m "not docker"` | E2E tests that don't require local Docker daemon (Released Package + general E2E). |
| `scheduled.yml` E2E real-tool scans | `-m "requires_tools"` | Real-tool tests after installing all profile tools. |
| `scheduled.yml` Tool Integration matrix | `-m "requires_tools"` | Same as E2E real-tool scans, sharded. |

**Why the filter matters**: Nightly Extended Tests fixes from 2026-04-26 added `-m "not requires_tools and not smoke"` after `pytest tests/` was running EVERY test including ones that need real tools (which the Nightly runner doesn't install). Without the filter, `test_advanced_targets.test_deep_profile_scan` (requires real scanners) and `test_released_package.test_cli_help_works` (requires `pip install jmo-security`) would fail by design.

**Convention rules-of-thumb**:

- **Always exclude `requires_tools` and `smoke`** unless the runner explicitly installs the prerequisite (real tool binaries or the released PyPI wheel).
- **Always exclude `docker`** unless the runner has a Docker daemon (Linux runners do; macOS/Windows runners require setup).
- **Include `slow`** only when the job has a generous timeout budget (nightly, full e2e). Exclude in PR-time CI (`ci.yml`).
- **Use `-m "<marker>"` to RUN only that marker**'s tests after installing prerequisites; use `-m "not <marker>"` to EXCLUDE.
