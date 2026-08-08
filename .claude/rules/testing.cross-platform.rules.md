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

## Console Encoding (Windows) — the class that CI structurally cannot see

`ci.yml` sets `PYTHONUTF8: "1"` on its test steps. That forces UTF-8 for `open()`,
`read_text()` **and** stdio. On Linux/macOS it is a no-op (locale already UTF-8);
on Windows it substitutes an environment **no real user has**. CI was green for
releases while `jmo trends explain score` exited 1 for every Windows user.

**Keep `PYTHONUTF8=1` on the existing shards** — removing it reddens all four.
The guard is the additional `windows-native-encoding` job, which deliberately
omits it.

### What a Windows console codec actually is

| stdout is… | codec | contains box drawing? | contains emoji? |
|---|---|---|---|
| piped / redirected | ANSI codepage — `cp1252` on a US box | no | no |
| attached to a console | OEM codepage — `cp437` / `cp850` | **yes** | no |

Test all three. cp437/cp850 are the trap: they *do* have `─`, so any check that
probes with a box-drawing character declares them safe and then dies on an emoji.

### Rules for writing console output

1. **Never decide by encoding NAME.** `if encoding in ("cp1252", "ascii", ...)`
   cannot enumerate what you did not think of. Probe the real payload against the
   real codec: `text.encode(stream.encoding)`.
2. **`UNICODE_FALLBACKS` is a quality layer, not a guarantee.** It renders `[OK]`
   instead of `?`, and it will always be incomplete (`scripts/` emits ~74
   characters it does not list). The guarantee is a final
   `text.encode(enc, "replace")` — against the **stream's** codec, not `ascii`, so
   a codec keeps what it can genuinely render.
3. **Fix the stream, not the call sites.** `harden_console_streams()`
   (`scripts/core/unicode_utils.py`), called first in `jmo.main()`, does
   `reconfigure(errors="replace")` on stdout/stderr. That covers all 206 raw
   `sys.stdout.write` calls **plus** rich, argparse and third-party output no
   call-site audit reaches. It is a no-op on UTF-8. Never force
   `encoding="utf-8"` — on a cp437 console that is mojibake, not a fix.
4. **One implementation only.** Four modules had each grown a private copy of the
   same broken helper. `tests/cross_platform/test_encoding_drift_guard.py` walks
   `scripts/` with `ast` and fails if anything outside `unicode_utils.py`
   **defines** `safe_print`/`safe_write`/`_can_encode_unicode`/
   `harden_console_streams`. Importing and re-exporting stay legal.
5. **Machine-read output stays raw.** `json.dumps` defaults to
   `ensure_ascii=True`, so JSON is already pure ASCII; substituting into it would
   corrupt it.

### Subprocess tests: pin BOTH ends

`PYTHONIOENCODING` **overrides** `PYTHONUTF8` (measured: `utf8_mode == 1` while
`sys.stdout.encoding == 'cp1252'`). That is what lets an encoding guard bite on
every platform and inside every existing shard. But if you pin the child, you must
decode with the same codec:

```python
subprocess.run(cmd, capture_output=True, env=env,
               encoding=codec, errors="replace")   # NOT text=True
```

Bare `text=True` decodes with the **parent's** locale codec. On Linux that is
UTF-8, and cp850's `0x9E` (`×`) is not valid UTF-8 — the test dies in its own
plumbing while the CLI under test exits 0. On Windows the same decode happens in a
`subprocess` reader thread where the error is *swallowed* and captured output
silently goes missing.

### `ruff PLW1514` is a lower bound, not the scope

`PLW1514` (unspecified-encoding, requires `preview = true`; select it
**specifically**, never the `PLW` family — that re-creates the unpinned-ruleset
ambush #678 fixed) flags `p.read_text()` only when it can prove the receiver is a
`Path`. It does **not** flag `(tmp_path / "x.html").read_text()`, because it cannot
type a `/` division result — and that is the dominant pytest idiom. It reported
"All checks passed!" on `tests/reporters/test_html_security.py`, the source of all
22 errors in this class. An AST scan needing no inference finds **1198** sites
against ruff's **153**.

**Consequence:** a lint rule cannot be the durable guard here. The
`windows-native-encoding` job must run the **full suite**, not just
`-m native_encoding`.

### Verifying a change in this area

- **Diff failing-test ID sets, never counts.** The full suite read
  `43 failed / 22 errors` both before and after the write-side fix — it repaired
  exactly 3 tests and broke exactly 3 others. Counts can match by coincidence.
- **Prove the guard can fail**: remove the fix, watch it go red, restore. Do the
  mutation with a **file backup** — `git checkout -- <file>` discards any
  uncommitted work in that file, silently.
- **Assert more than one condition per guard.** The subprocess guard survived a
  broken capture only because it asserted `returncode == 0` as well as the absence
  of a traceback; returncode is independent of stdout decoding.

## Line Endings on Windows

This repo has **no `.gitattributes`** and `core.autocrlf=false`, so line endings
are stored byte-for-byte and are **mixed per file** (`scripts/cli/jmo.py` is LF;
`scripts/core/unicode_utils.py` is CRLF).

`pathlib.Path.write_text()` opens with `newline=None`, translating every `\n` to
`os.linesep` — `\r\n` on Windows. Reading a LF file and writing it back **converts
the whole file**, producing thousands of phantom line changes that bury the real
edit (7545 lines for a 7-line change; same class as the `update_versions.py` bug
fixed in #556). Use `write_bytes()`, or `open(..., newline="")`.

Detect it before committing — raw and EOL-insensitive counts must match:

```bash
for f in $(git diff origin/main HEAD --name-only); do
  a=$(git diff origin/main HEAD --numstat -- "$f" | cut -f1)
  b=$(git diff origin/main HEAD --ignore-cr-at-eol --numstat -- "$f" | cut -f1)
  [ "$a" != "$b" ] && echo "EOL FLIP $f: raw=+$a ignore-CR=+$b"
done
```

Do **not** check line endings with `grep -c $'\r'` — MSYS grep normalizes CR, and
the pattern also matches a literal `r`, so it reports CRLF for LF files. Use
`od -c` on the blob, or count `b"\r\n"` in Python.

## Workflow Marker Filter Convention

Pytest invocations in CI workflows use these filter sets. Each filter is tuned to match the runner environment's actual capabilities (which tools/packages are installed).

| Workflow:Job | Filter | Rationale |
|---|---|---|
| `ci.yml` test-sharded — Ubuntu ×4 (`:312`) | `-m "not smoke and not requires_tools and not docker"` | **The only job that produces coverage** (`--cov=scripts`). `coverage-aggregate` merges the four shard XMLs and enforces the 80% floor (`:734`). `slow` included. |
| `ci.yml` test-sharded — macOS (`:327`) | `-m "not smoke and not requires_tools and not docker"` | Same suite, **no coverage** — the step is literally named "Run tests (macOS, no coverage)". |
| `ci.yml` test-sharded — Windows (`:352`) | `-m "not smoke and not requires_tools and not docker and not slow"` | Adds `not slow` for runtime; also `-p no:xdist -p no:rerunfailures`, `--timeout=60`. **No coverage.** |
| `ci.yml` windows-native-encoding collection floor (`:448`) | `-m "not smoke and not requires_tools and not docker and not slow"` | `--collect-only` count guard, fails under 7800 collected. Not a test run; no coverage. |
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
- **`slow` is NOT excluded from PR-time CI.** The **Ubuntu and macOS** shards (`:312`, `:327`) run `-m "not smoke and not requires_tools and not docker"` — slow tests included. The **Windows** shard (`:352`) and the `windows-native-encoding` collection floor (`:448`) add `and not slow`; so does `nightly-cross-platform`, which lives in **`scheduled.yml:241`**, not `ci.yml`. Exclude it when the job's budget is tight, not because it is PR-time.
- **There is no "Quick coverage check" job.** The table above used to list one, with a `≥70% threshold` it did not have, citing `:352` — which is the Windows shard, a step named "no coverage". `ci.yml` has exactly one coverage gate: the `Verify coverage threshold` step of `coverage-aggregate` (`:734`). If you are hunting a coverage failure, that is the only place it can come from.
- **Use `-m "<marker>"` to RUN only that marker**'s tests after installing prerequisites; use `-m "not <marker>"` to EXCLUDE.

### Reproducing a shard locally

**Use the sharded filter, not the coverage filter.** They are not the same suite,
and the coverage one is strictly smaller:

```bash
# What the shards actually run -- this is the one to reproduce
pytest tests/ -p no:xdist -m "not smoke and not requires_tools and not docker"
```

Verifying with `and not slow` appended is verifying against fewer tests than gate
the PR. Measured on #722: a full local `tests/unit tests/cli` sweep came back
**4552 passed, 0 failed** with the coverage filter, while shard 3 failed on
`tests/integration/test_scan_accounting.py` — a `@pytest.mark.slow` test the
local filter had deselected. Two independent gaps compounded: the wrong marker
filter *and* omitting `tests/integration/` from the path list.

The bullet above this one used to say slow was excluded in PR-time CI, which is
what produced that run. It contradicted the table in this same section — when
they disagree, the table is generated from the workflows and wins.
