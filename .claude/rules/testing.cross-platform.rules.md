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
