# Windows cp1252 Encoding Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make JMo Security correct on a default Windows console (cp1252) rather than only under `PYTHONUTF8=1`, and add a CI job that keeps it that way.

**Architecture:** Three independent defect classes, fixed in dependency order. (1) *Write-side*: production code writes non-ASCII to `sys.stdout`, crashing real users — fixed by routing through the existing `safe_print()`. (2) *Read-side*: 153 `open()`/`read_text()` calls omit `encoding=`, inheriting the locale codec — fixed by ruff's `PLW1514` autofix, then enforced permanently. (3) *Guard*: a new Windows CI job that deliberately omits `PYTHONUTF8` so this class can never silently return.

**Tech Stack:** Python 3.12, pytest, ruff 0.16.0 (preview rules), GitHub Actions (`windows-2022`).

## Global Constraints

- **Never remove `PYTHONUTF8: "1"` from the existing shards** (`.github/workflows/ci.yml:299`, `:318`, `:343`). The new job is *additional*. Removing it would redden all four shards until every task here lands.
- **`PLW1514` requires ruff preview mode.** `select = ["PLW1514"]` alone silently no-ops with `warning: Selection PLW1514 has no effect because preview is not enabled`.
- Ruff's `PLW1514` fixes are classified **unsafe** — they need `--unsafe-fixes`, and every hunk must be eyeballed for binary-mode reads.
- Pre-commit order is **Black before Ruff** (`.pre-commit-config.yaml`). `ruff format` is *not* a hook here; do not run it — it reflows unrelated code.
- Conventional commits. No AI-attribution markers.
- Work in a **git worktree**; the primary checkout at `C:\Projects\jmo-security-repo` is shared with an always-on peer agent. In a worktree `.git` is a *file*; write scratch files to the scratchpad, not the repo.
- `make` is not installed in this Git Bash. Run recipe bodies directly. `make lint` wraps every step in `|| true` and swallows exit codes — invoke the tools directly and read real exit codes.

## Background: why CI never caught this

`.github/workflows/ci.yml` sets `PYTHONUTF8: "1"` on the test steps. That enables Python UTF-8 Mode, which overrides the locale encoding for `open()`, `read_text()`, **and** stdio. On Linux/macOS the default is already UTF-8, so the variable only changes Windows behaviour — and it changes it to something no ordinary user has.

Measured on a stock Windows box with the variable unset, against `main` at `15c9bcb`:

```text
43 failed, 93 passed, 5 skipped, 3 deselected, 22 errors
```

Identical result on mcp 1.29.0 and mcp 2.0, with byte-identical failing-test ID sets — so this is long-standing and unrelated to the recent dependency work.

| Class | Count | Detectable by | Severity |
|---|---|---|---|
| Write-side encode (`UnicodeEncodeError`) | 6 failures | No linter — manual audit | **Crashes real users** |
| Read-side decode (`UnicodeDecodeError`) | 36 failures + 22 errors | `ruff PLW1514` (153 sites) | Test-only, but masks the above |
| Residual (non-encoding) | 2 failures | — | Needs triage |

## Corrections — measured during execution (2026-07-29)

Seven claims above and below were checked against the machine and did not hold.
Each correction here is a measurement, not a preference.

1. **Task 1's reproduction was vacuous.** `jmo trends --results-dir <tmp>` exits
   **2** at argparse (`invalid choice`) and never reaches `trend_commands.py:140`,
   so `assert "UnicodeEncodeError" not in result.stderr` passes on every platform
   forever. `jmo trends explain all` is the real reproduction — it needs no history
   database and exits 1.

2. **It is not only cp1252.** Piped stdout gets the ANSI codepage (cp1252); a real
   console gets the OEM codepage (**cp437/cp850**). Those two *contain* the
   box-drawing character `─` that every copy of `_can_encode_unicode()` probed
   with, so the probe answered "safe" and the write crashed anyway. Deciding by
   encoding *name* cannot work; probe the actual text against the stream's codec.

3. **`safe_print()` itself crashed.** For any character absent from
   `UNICODE_FALLBACKS`, its `except` handler re-ran the same substitution (a no-op)
   and printed again, raising a second time uncaught. `scripts/` emits ~74 such
   characters, so the table can never be the guarantee — it is a quality layer, and
   the guarantee is a final `errors="replace"` pass.

4. **Four copies of the helper existed, not one** — `diff_commands`,
   `history_commands`, `trend_commands`, `wizard_flows/ui_helpers`. Consolidated
   into `unicode_utils`, with an AST drift guard so a fifth fails CI.

5. **`safe_stdout_write` + a 206-call-site audit is the wrong mechanism.**
   `sys.stdout.reconfigure(errors="replace")` at the CLI entry point covers all of
   them at once, plus `rich`, argparse and third-party output that no call-site
   audit reaches. Measured: no-op on UTF-8, and JSON output is unaffected because
   `format_json_report` already emits pure ASCII via `ensure_ascii=True`.

6. **`PYTHONIOENCODING` overrides `PYTHONUTF8`.** Measured: with `PYTHONUTF8=1`
   set, `sys.flags.utf8_mode == 1` yet `sys.stdout.encoding == 'cp1252'`. Pinning
   `PYTHONIOENCODING` in the child therefore makes the write-side guard
   load-bearing on *every* platform and inside *every* existing shard — not only on
   a Windows box with `PYTHONUTF8` unset.

7. **`PLW1514` does not cover the read-side class.** Ruff flags `p.read_text()`
   only when it can prove the receiver is a `Path`; it does **not** flag
   `(tmp_path / "x.html").read_text()`, because it cannot type a `/` division
   result — and that is the dominant idiom in pytest. `test_html_security.py`
   reports "All checks passed!" while being the source of all 22 errors. An AST
   scan that needs no type inference finds **1198** unspecified-encoding sites
   against ruff's 153. Consequences: fixing the 153 alone does not reach 0
   failures, and a lint rule cannot be the durable guard — the
   `windows-native-encoding` CI job must run the **full suite**, not just
   `-m native_encoding`, or it cannot see this class at all.

8. **There are three residual non-encoding failures, not two.**
   `test_cli_history_repair` is unlisted. Precise split of the 43:
   **42 `UnicodeDecodeError`**, **3 `UnicodeEncodeError`**, **3 `AssertionError`**.

Sequencing consequence: because the CI job must run the full suite, it goes red
until the read-side work lands, so it ships in the **last** PR, not the first.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `.github/workflows/ci.yml` | CI definition | **Modify** — add `windows-native-encoding` job |
| `pyproject.toml` | pytest markers, ruff config | **Modify** — register `native_encoding` marker; enable ruff preview + `PLW1514` |
| `tests/cross_platform/__init__.py` | Makes the new test dir a package (repo convention) | **Create** |
| `tests/cross_platform/test_native_encoding.py` | Reproduces the user-facing crash on a cp1252 console | **Create** |
| `scripts/cli/trend_commands.py` | `jmo trends` output | **Modify** — route stdout through `safe_print` |
| `scripts/core/unicode_utils.py` | Fallback table + `safe_print()` | **Modify** — add `safe_stdout_write()` |
| `tests/unit/test_unicode_utils.py` | Unit tests for the above | **Modify** |
| `scripts/**/*.py` (49 sites) | Production read-side | **Modify** — add `encoding="utf-8"` |
| `tests/**/*.py` (104 sites) | Test read-side | **Modify** — add `encoding="utf-8"` |

---

### Task 1: Reproduce the user-facing crash as a test

The bug is real but currently unprovable in CI. Write the reproduction first so every later task has a pass/fail signal.

**Files:**
- Create: `tests/cross_platform/__init__.py` (empty) and `tests/cross_platform/test_native_encoding.py`
- Modify: `pyproject.toml` (markers list)

> `tests/cross_platform/` is a **new** directory. Every existing test package here carries an `__init__.py` (`tests/e2e/__init__.py`, `tests/integration/__init__.py`, …); omitting it breaks module resolution. Create the empty `__init__.py` first.

**Interfaces:**
- Produces: pytest marker `native_encoding`, selected by Task 5's CI job via `-m "native_encoding"`.

- [ ] **Step 1: Register the marker**

In `pyproject.toml`, append to the `markers = [` list:

```toml
    "native_encoding: runs the CLI under the host's native console encoding (no PYTHONUTF8). Windows cp1252 regression guard.",
```

- [ ] **Step 2: Write the failing test**

Create `tests/cross_platform/test_native_encoding.py`:

```python
"""Guards against UnicodeEncodeError on a default Windows console.

CI's main shards set PYTHONUTF8=1, which forces UTF-8 for stdio and file I/O.
Real users do not have it set, so those shards cannot see this bug class. These
tests deliberately scrub PYTHONUTF8/PYTHONIOENCODING from the child environment
to reproduce what a user actually gets.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.native_encoding


def _native_env() -> dict[str, str]:
    """Child env with UTF-8 Mode forced OFF, as a real console would be."""
    env = os.environ.copy()
    env.pop("PYTHONUTF8", None)
    env.pop("PYTHONIOENCODING", None)
    env["PYTHONUTF8"] = "0"
    return env


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "scripts.cli.jmo", *args],
        capture_output=True,
        text=True,
        timeout=120,
        env=_native_env(),
        check=False,
    )


def test_trends_does_not_crash_on_native_encoding(tmp_path):
    """`jmo trends` must not die writing its own output.

    Regression: trend_commands.py wrote the report straight to sys.stdout. On a
    cp1252 console the magnifying-glass emoji in the header raised
    UnicodeEncodeError and the command exited 1.
    """
    result = _run("trends", "--results-dir", str(tmp_path))

    assert "UnicodeEncodeError" not in result.stderr, (
        "jmo trends crashed encoding its own output on a native console:\n"
        f"{result.stderr[-2000:]}"
    )


def test_help_does_not_crash_on_native_encoding():
    """--help is the single most-run path; it must survive a cp1252 console."""
    result = _run("--help")

    assert "UnicodeEncodeError" not in result.stderr, (
        f"jmo --help crashed on a native console:\n{result.stderr[-2000:]}"
    )
    assert result.returncode == 0, f"jmo --help exited {result.returncode}"
```

- [ ] **Step 3: Run it and confirm it FAILS on Windows**

```bash
./.venv/Scripts/python.exe -m pytest tests/cross_platform/test_native_encoding.py -q
```

Expected on Windows: `test_trends_does_not_crash_on_native_encoding` FAILS with `UnicodeEncodeError ... '\U0001f50d'`.
Expected on Linux/macOS: both PASS (the locale is already UTF-8) — that is correct, this guard is Windows-specific by nature.

> If it passes on Windows, **stop**. Confirm `PYTHONUTF8` is genuinely unset in your shell (`echo $PYTHONUTF8`) before assuming the bug is gone.

- [ ] **Step 4: Commit the failing test**

```bash
git add tests/cross_platform/__init__.py tests/cross_platform/test_native_encoding.py pyproject.toml
git commit -m "test(windows): reproduce the cp1252 console crash in jmo trends"
```

---

### Task 2: Add `safe_stdout_write()` and fix the crash

**Files:**
- Modify: `scripts/core/unicode_utils.py`
- Modify: `scripts/cli/trend_commands.py:136-140`
- Modify: `tests/unit/test_unicode_utils.py`

**Interfaces:**
- Consumes: `UNICODE_FALLBACKS`, `safe_print` (existing, `scripts/core/unicode_utils.py`).
- Produces: `safe_stdout_write(text: str, fallbacks: dict[str, str] | None = None) -> None` — the write-side analogue of `safe_print`, for callers that manage their own newlines. Task 3 uses it.

- [ ] **Step 1: Write the failing unit test**

Append to `tests/unit/test_unicode_utils.py`:

```python
def test_safe_stdout_write_degrades_on_cp1252(monkeypatch, capsys):
    """Non-encodable characters fall back instead of raising."""
    from scripts.core import unicode_utils

    class _Cp1252Stdout:
        encoding = "cp1252"

        def __init__(self):
            self.written = []

        def write(self, s):
            s.encode("cp1252")  # raises exactly as a real cp1252 stream would
            self.written.append(s)

        def flush(self):
            pass

    fake = _Cp1252Stdout()
    monkeypatch.setattr(unicode_utils.sys, "stdout", fake)

    unicode_utils.safe_stdout_write("scan \U0001f50d done\n")

    assert fake.written == ["scan [?] done\n"]


def test_safe_stdout_write_preserves_unicode_on_utf8(monkeypatch):
    """On a UTF-8 stream the text passes through untouched."""
    from scripts.core import unicode_utils

    class _Utf8Stdout:
        encoding = "utf-8"

        def __init__(self):
            self.written = []

        def write(self, s):
            self.written.append(s)

        def flush(self):
            pass

    fake = _Utf8Stdout()
    monkeypatch.setattr(unicode_utils.sys, "stdout", fake)

    unicode_utils.safe_stdout_write("scan \U0001f50d done\n")

    assert fake.written == ["scan \U0001f50d done\n"]
```

- [ ] **Step 2: Run it to verify it fails**

```bash
./.venv/Scripts/python.exe -m pytest tests/unit/test_unicode_utils.py -q -k safe_stdout_write
```

Expected: FAIL — `AttributeError: module 'scripts.core.unicode_utils' has no attribute 'safe_stdout_write'`.

- [ ] **Step 3: Implement `safe_stdout_write`**

Append to `scripts/core/unicode_utils.py`:

```python
def safe_stdout_write(text: str, fallbacks: dict[str, str] | None = None) -> None:
    """Write to stdout with Unicode fallback, without appending a newline.

    The write-side analogue of safe_print(), for callers that build their own
    fully-formatted block (e.g. rich-rendered reports) and must not have a
    newline added.

    Why this exists: a bare sys.stdout.write() of non-ASCII text raises
    UnicodeEncodeError on a Windows console using cp1252. CI does not see it
    because the workflow sets PYTHONUTF8=1, which real users do not have.

    Args:
        text: Text to write (may contain Unicode characters).
        fallbacks: Optional custom mapping. Defaults to UNICODE_FALLBACKS.
    """
    if fallbacks is None:
        fallbacks = UNICODE_FALLBACKS

    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    if encoding.lower() in ("cp1252", "ascii", "latin-1", "iso-8859-1"):
        for unicode_char, ascii_fallback in fallbacks.items():
            text = text.replace(unicode_char, ascii_fallback)

    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        # Encoding advertised as safe but wasn't, or a character is missing from
        # the fallback table. Degrade rather than crash the command.
        for unicode_char, ascii_fallback in fallbacks.items():
            text = text.replace(unicode_char, ascii_fallback)
        sys.stdout.write(text.encode("ascii", "replace").decode("ascii"))
```

- [ ] **Step 4: Run the unit tests to verify they pass**

```bash
./.venv/Scripts/python.exe -m pytest tests/unit/test_unicode_utils.py -q
```

Expected: PASS.

- [ ] **Step 5: Fix the production call site**

In `scripts/cli/trend_commands.py`, add to the imports:

```python
from scripts.core.unicode_utils import safe_stdout_write
```

Then replace lines 136-140:

```python
        if output_format == "json":
            sys.stdout.write(format_json_report(analysis) + "\n")
        elif output_format == "terminal":
            # Use rich-based terminal formatter with sparklines and charts
            formatted_output = format_terminal_report(analysis, verbose=verbose)
            safe_stdout_write(formatted_output)
```

> Leave the `json` branch on the raw `sys.stdout.write`. JSON output is machine-read; silently substituting `[?]` for a character would corrupt it. `format_json_report` should emit `\uXXXX` escapes — Task 6 verifies that.

- [ ] **Step 6: Verify Task 1's reproduction now passes**

```bash
./.venv/Scripts/python.exe -m pytest tests/cross_platform/test_native_encoding.py -q
```

Expected: PASS (both tests).

- [ ] **Step 7: Commit**

```bash
git add scripts/core/unicode_utils.py scripts/cli/trend_commands.py tests/unit/test_unicode_utils.py
git commit -m "fix(cli): stop jmo trends crashing on a cp1252 console"
```

---

### Task 3: Audit the remaining raw stdout writes

`safe_print` has 59 call sites; raw `sys.stdout.write` has 206. Most are safe (ASCII-only, or JSON). This task finds the ones that are not.

**Files:**
- Modify: whichever `scripts/**/*.py` the audit implicates.
- Create: `tests/cross_platform/test_no_unguarded_unicode_stdout.py`

**Interfaces:**
- Consumes: `safe_stdout_write` from Task 2.

- [ ] **Step 1: Produce the candidate list**

```bash
# Non-ASCII literals in files that also write to stdout directly.
grep -rln "sys\.stdout\.write(" scripts/ --include=*.py > /tmp/writers.txt
while read -r f; do
  if grep -qP '[^\x00-\x7F]' "$f"; then echo "$f"; fi
done < /tmp/writers.txt
```

Each hit is a file that both writes to stdout and contains non-ASCII source text. Inspect each: if the non-ASCII text can reach a `sys.stdout.write`, it is a defect.

- [ ] **Step 2: Write the drift guard**

Create `tests/cross_platform/test_no_unguarded_unicode_stdout.py`:

```python
"""Drift guard: production code must not write non-ASCII straight to stdout.

The fix pattern (scripts/core/unicode_utils.safe_stdout_write) already exists;
this keeps new code from bypassing it and reintroducing the cp1252 crash that
CI cannot see, because CI sets PYTHONUTF8=1.

ALLOWLIST holds writes that are provably safe. Adding an entry is a deliberate
claim -- state which one applies in the comment:
  (a) the payload is machine-read (JSON/SARIF) where substitution would corrupt
      it, and the serializer escapes non-ASCII;
  (b) the payload is ASCII-only by construction.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"

# path -> reason. See the module docstring before adding.
ALLOWLIST: dict[str, str] = {
    "scripts/cli/trend_commands.py": (
        "(a) the sole remaining raw write is the --format json branch; "
        "json.dumps escapes non-ASCII as \\uXXXX. The terminal branch uses "
        "safe_stdout_write."
    ),
}

NON_ASCII = re.compile(r"[^\x00-\x7F]")


def test_no_unguarded_unicode_stdout_writes() -> None:
    offenders: list[str] = []

    for path in sorted(SCRIPTS.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in ALLOWLIST:
            continue
        text = path.read_text(encoding="utf-8")
        if "sys.stdout.write(" not in text:
            continue
        if NON_ASCII.search(text):
            offenders.append(rel)

    assert not offenders, (
        "These files write directly to sys.stdout AND contain non-ASCII text, "
        "which raises UnicodeEncodeError on a Windows cp1252 console:\n  "
        + "\n  ".join(offenders)
        + "\n\nUse scripts.core.unicode_utils.safe_stdout_write(), or add an "
        "ALLOWLIST entry stating why the write is safe."
    )
```

- [ ] **Step 3: Run it and fix every offender**

```bash
./.venv/Scripts/python.exe -m pytest tests/cross_platform/test_no_unguarded_unicode_stdout.py -q
```

For each offender: if the non-ASCII text can reach stdout, swap that call to `safe_stdout_write`. If it genuinely cannot (ASCII-only payload, or machine-read JSON), add an `ALLOWLIST` entry naming reason (a) or (b). Re-run until green.

- [ ] **Step 4: Commit**

```bash
git add tests/cross_platform/test_no_unguarded_unicode_stdout.py scripts/
git commit -m "fix(cli): route remaining unicode stdout writes through safe_stdout_write"
```

---

### Task 4: Clear the 153 read-side sites

**Files:**
- Modify: `scripts/**/*.py` (49 sites), `tests/**/*.py` (104 sites)
- Modify: `pyproject.toml` (`[tool.ruff.lint]`)

- [ ] **Step 1: Record the starting count**

```bash
./.venv/Scripts/ruff.exe check --preview --select PLW1514 --statistics . | tail -3
```

Expected: `153  PLW1514  unspecified-encoding`.

- [ ] **Step 2: Apply the autofix to `scripts/` first**

```bash
./.venv/Scripts/ruff.exe check --preview --select PLW1514 --fix --unsafe-fixes scripts/
./.venv/Scripts/ruff.exe check --preview --select PLW1514 --statistics scripts/
```

Expected after: no `PLW1514` remaining under `scripts/`.

- [ ] **Step 3: Review every hunk before trusting it**

```bash
git diff --stat scripts/
git diff scripts/
```

The fix is classified *unsafe* for a reason. Confirm for each hunk:
- The file is genuinely **text** mode. If a call is `open(p, "rb")` ruff should not have touched it — if it did, revert that hunk.
- The file is genuinely **UTF-8**. Anything reading a Windows-produced artifact in another codepage needs that codepage, not `utf-8`.
- No call already passed `encoding=` via a variable (double-specify is a `TypeError`).

- [ ] **Step 4: Run the full suite against `scripts/` changes**

```bash
./.venv/Scripts/python.exe -m pytest -q -p no:randomly -m "not smoke and not requires_tools and not docker" > /tmp/after_scripts.txt 2>&1
tail -1 /tmp/after_scripts.txt
```

Compare against the documented pre-change baseline: `43 failed, 22 errors` on a native-encoding Windows box. The count must go **down**, never up.

- [ ] **Step 5: Commit `scripts/` separately**

```bash
git add scripts/
git commit -m "fix(core): specify utf-8 encoding on all file reads in scripts/"
```

> Separate commits for `scripts/` and `tests/` keep the production-behaviour change reviewable on its own. A single 153-file commit buries it.

- [ ] **Step 6: Apply to `tests/` and review**

```bash
./.venv/Scripts/ruff.exe check --preview --select PLW1514 --fix --unsafe-fixes tests/
git diff tests/ | head -200   # spot-check; apply the same three checks from Step 3
./.venv/Scripts/ruff.exe check --preview --select PLW1514 --statistics . | tail -3
```

Expected: `All checks passed!`.

- [ ] **Step 7: Enforce the rule permanently**

In `pyproject.toml` under `[tool.ruff.lint]`, add `preview = true` and extend `select`:

```toml
[tool.ruff.lint]
# PLW1514 (unspecified-encoding) is a preview rule in ruff 0.16.0. Without this
# flag `select = ["PLW1514"]` silently no-ops -- ruff warns and moves on.
preview = true

select = [
    # ... existing entries unchanged ...
    "PLW1514", # unspecified encoding -- inherits the locale codec, which is
    #            cp1252 on Windows. CI hides this behind PYTHONUTF8=1.
]
```

> Select **`PLW1514` specifically**, not the whole `PLW` family. Enabling `PLW` wholesale under `preview = true` pulls in the entire preview ruleset for that family — exactly the unpinned-ruleset ambush PR #678 was written to prevent.

- [ ] **Step 8: Verify the whole gate is green**

```bash
./.venv/Scripts/black.exe --check scripts/ tests/ ; echo "BLACK=$?"
./.venv/Scripts/ruff.exe check . ; echo "RUFF=$?"
./.venv/Scripts/python.exe -m pytest -q -p no:randomly -m "not smoke and not requires_tools and not docker" > /tmp/after_all.txt 2>&1
tail -1 /tmp/after_all.txt
```

Expected: Black 0, Ruff 0, and the failure count down to at most the 2 residual items in Task 6.

- [ ] **Step 9: Commit**

```bash
git add tests/ pyproject.toml
git commit -m "fix(tests): specify utf-8 on file reads and enforce PLW1514"
```

---

### Task 5: Add the CI guard job

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the `native_encoding` marker from Task 1.

- [ ] **Step 1: Add the job**

Append to the `jobs:` block in `.github/workflows/ci.yml`. The setup steps below mirror the existing test job verbatim (`ci.yml:261-278`) — that job does **not** use a composite action; it pins `astral-sh/setup-uv@v9.0.0` with `version: "0.11.15"`, then puts the project venv on `PATH`. Copy those three steps exactly as written there, including the pinned uv version (the single-uv-version convention from PR #488 — a stale pin here resolves differently from every other job):

```yaml
  windows-native-encoding:
    name: Windows native console encoding
    runs-on: windows-2022
    timeout-minutes: 15
    steps:
      - name: Checkout repository
        uses: actions/checkout@v7

      - name: Set up uv
        uses: astral-sh/setup-uv@v9.0.0
        with:
          version: "0.11.15"  # pinned: single uv version across all sites (PR #488)
          python-version: '3.12'  # preserves the pin actions/setup-python held
          enable-cache: true

      # Copy the "Install dependencies" and "Put the project venv on PATH"
      # steps verbatim from the existing test job (ci.yml:278-288). On Windows
      # the PATH step needs `cygpath -w` before writing to $GITHUB_PATH.

      - name: Run native-encoding guard
        # PYTHONUTF8 is DELIBERATELY NOT SET here, and must never be added.
        # Every other test step sets PYTHONUTF8=1, which forces UTF-8 for stdio
        # and file I/O and therefore cannot see the cp1252 bug class a real
        # Windows user hits. This job is the only place that reproduces a stock
        # console. Setting it here would make the job silently vacuous.
        env:
          CI: "true"
          SKIP_REACT_BUILD_CHECK: "true"
        run: |
          python -m pytest -m "native_encoding" -q --timeout=120 -p no:xdist -p no:rerunfailures
```

> `-p no:xdist -p no:rerunfailures` is mandatory on Windows here — the repo has a documented history of xdist/rerunfailures socket deadlocks with pytest-timeout (`.claude/rules/testing.cross-platform.rules.md`).

- [ ] **Step 2: Verify the job is NOT continue-on-error**

```bash
grep -n -A3 "windows-native-encoding" .github/workflows/ci.yml | grep -i "continue-on-error" && echo "REMOVE IT" || echo "OK - failures will be enforced"
```

The existing `windows-2022` shard carries `continue-on-error: true` and reports a green tick over real failures. This guard must **not** inherit that, or it is decorative.

- [ ] **Step 3: Confirm the marker actually selects tests**

```bash
./.venv/Scripts/python.exe -m pytest -m "native_encoding" --collect-only -q | tail -2
```

Expected: `2 tests collected`. **`0 tests collected` is a silent failure and exits 0** — a marker typo would make this job permanently, invisibly vacuous.

- [ ] **Step 4: Confirm the new marker did not shift the main shards**

```bash
./.venv/Scripts/python.exe -m pytest -q -p no:randomly -m "not smoke and not requires_tools and not docker" 2>&1 | tail -1
```

The `native_encoding` tests are *not* excluded by that filter, so the collected total should rise by exactly 2. Any other movement means the marker changed selection somewhere unintended.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(windows): add a native-console-encoding guard job"
```

---

### Task 6: Triage the two residual failures

Neither is an encoding defect; both were merely co-occurring in the same run. Investigate before assuming they are environmental.

**Files:**
- Investigate: `tests/integration/test_cli_scan_ci.py:49`, `tests/e2e/test_cross_platform.py::test_windows_wsl_full_scan`

- [ ] **Step 1: Reproduce each in isolation**

```bash
./.venv/Scripts/python.exe -m pytest tests/integration/test_cli_scan_ci.py::test_scan_skips_missing_tools_and_runs_available -q
./.venv/Scripts/python.exe -m pytest "tests/e2e/test_cross_platform.py::TestCrossPlatformCompatibility::test_windows_wsl_full_scan" -q
```

- [ ] **Step 2: Classify `test_scan_skips_missing_tools_and_runs_available`**

It fails with `AssertionError: Expected at least one output file in ...\individual-repos\repo1` (`assert 0 > 0`). Note this test was **previously misattributed to mcp 2.0**, then re-diagnosed as a `GITHUB_PATH` POSIX-path bug fixed in `f605ac2` — yet it still fails locally, so at least one of those diagnoses is incomplete. Determine which:

- Does it pass in CI on `main`? (It does — so it is environment-dependent, not a code regression.)
- Does the scan write output when *no* scanner binaries are installed? If the test assumes at least one tool exists, it needs `@pytest.mark.requires_tools`.

Outcome is either a marker fix or a genuine bug. Do not paper over it with a skip.

- [ ] **Step 3: Classify `test_windows_wsl_full_scan`**

It asserts `"WSL uses Unix-style paths"`. Determine whether it requires a working WSL install. If so it needs a guard that skips when WSL is absent, in the style of `tests/conftest.py`'s existing `skip_on_windows` helpers — not an unconditional skip.

- [ ] **Step 4: Fix or file**

If either is a real bug, fix it with a regression test. If either is genuinely environment-gated, add the guard with a comment naming the required environment. If a fix needs research beyond this plan's scope, open a GitHub issue with the `technical-debt` label and add a `# TODO(issue-#):` comment at the site — per `CLAUDE.md`'s issue-handling protocol, never silently defer.

- [ ] **Step 5: Commit**

```bash
git add tests/
git commit -m "test: correct environment gating for the two residual native-encoding failures"
```

---

### Task 7: Verify end-to-end and open the PR

- [ ] **Step 1: Full local verification on a native-encoding console**

```bash
echo "PYTHONUTF8=${PYTHONUTF8:-<unset>}"   # must be unset or 0
./.venv/Scripts/python.exe -m pytest -q -p no:randomly -m "not smoke and not requires_tools and not docker" > /tmp/final.txt 2>&1
tail -1 /tmp/final.txt
```

Expected: **0 failed, 0 errors** — down from `43 failed, 22 errors`.

- [ ] **Step 2: Confirm the guard still fails when the fix is reverted**

```bash
git stash push scripts/cli/trend_commands.py
./.venv/Scripts/python.exe -m pytest tests/cross_platform/test_native_encoding.py -q ; echo "EXIT=$? (expect 1)"
git stash pop
```

A guard that cannot fail is not a guard. If this exits 0, the test is vacuous — fix it before merging.

- [ ] **Step 3: Lint gate**

```bash
./.venv/Scripts/black.exe --check scripts/ tests/ ; echo "BLACK=$?"
./.venv/Scripts/ruff.exe check . ; echo "RUFF=$?"
```

Both must be 0. Do **not** run `ruff format` — it is not a hook here and reflows unrelated code.

- [ ] **Step 4: Open the PR and verify CI by log, not by tick**

Use the `merge-pr` skill. When CI completes, read the `windows-2022` shard log directly:

```bash
JOB=$(gh pr checks <PR> | grep "Test windows-2022" | head -1 | grep -oE "job/[0-9]+" | cut -d/ -f2)
gh run view --job "$JOB" --log | grep -E "passed|failed" | tail -3
```

That shard is `continue-on-error: true` and reports **pass over a real exit-code-1 failure**. Compare against the `main` baseline of **`7815 passed, 94 skipped, 229 deselected`**. Skipped must stay `94`; the passed total should rise by the number of tests added here. A *shifted skip count is as much a signal as a failure* — it means something stopped being collected.

- [ ] **Step 5: Confirm the new job actually ran and was not vacuous**

```bash
gh pr checks <PR> | grep "native console encoding"
```

It must appear and pass. If it is missing, the job did not trigger; if it passed in under ~30s, suspect `0 tests collected`.

---

## Self-Review

**Spec coverage**

| Requirement | Task |
|---|---|
| Fix the user-facing `jmo trends` crash | 2 |
| Audit the other 206 raw stdout writes | 3 |
| Fix all 153 `PLW1514` read sites | 4 |
| Enforce the rule so it cannot regress | 4 (ruff), 3 (stdout drift guard) |
| Add one non-UTF8 Windows CI job | 5 |
| Keep `PYTHONUTF8=1` on existing shards | Global Constraints; Task 5 adds only |
| Account for the 2 non-encoding failures | 6 |

**Known risks**

1. **`--unsafe-fixes` is unsafe by design.** Task 4 Steps 3 and 6 mandate hunk review. The specific hazards are binary-mode reads and files that are genuinely not UTF-8.
2. **`preview = true` widens ruff's surface.** Mitigated by selecting `PLW1514` explicitly rather than the `PLW` family — see Task 4 Step 7. Re-run `ruff check .` after enabling and treat any *new* unrelated finding as a signal the scope widened further than intended.
3. **Task 6 may uncover a real bug** rather than an environment gate. That is a legitimate outcome; the plan says file it rather than skip it.
4. **These guards only bite on Windows.** On Linux/macOS Task 1's tests pass trivially because the locale is already UTF-8. That is expected — the CI job in Task 5 is what makes them load-bearing.
