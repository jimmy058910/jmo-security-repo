---
title: Windows Encoding & Line Endings
paths:
  - scripts/cli/**/*.py
  - scripts/core/unicode_utils.py
  - scripts/core/reporters/**/*.py
  - scripts/dev/**/*.py
  - tests/**/*.py
references:
  - testing.cross-platform.rules.md (Windows CI hangs, markers, Docker UID)
  - scripts/core/unicode_utils.py (harden_console_streams, safe_write)
---

# Windows Encoding & Line Endings

**What this covers:** console codecs on Windows, the `PYTHONUTF8` blind spot CI
structurally cannot see, and the `read_text`/`write_text` newline translation that
turns a 7-line edit into a 7545-line diff. Scoped to code that **writes output or
rewrites files** — not to every module under `scripts/`.

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

   **That guard had two blind spots, and two copies survived it for months.**
   It scans for `def <guarded name>` — the *shape the bug had last time* — while
   what is actually forbidden is *deciding encodability from a codec's name*,
   which can appear anywhere under any name:

   | Survivor | How it slipped through |
   |---|---|
   | `policy_commands.py` defined `_safe_print` | **underscored** — `GUARDED_NAMES` lists `safe_print` |
   | `jmo.py` inlined the branch inside `_log()` | defined **no** guarded helper at all |

   Measured impact before the fix, on `--human-logs`:

   | console codec | what it is | denylist fires? | rendered |
   |---|---|---|---|
   | `cp1252` | piped / redirected | yes | `[v]` `[x]` |
   | **`cp437` / `cp850`** | **a real console** | **no** | **`?` `?`** |

   Not a crash — `harden_console_streams` guarantees that — but the fallback
   table silently skipped **in the exact environment it was written for**. The
   name list can never be right: it must enumerate codecs nobody thought of.

   So there is now a second, **behavioural** guard,
   `test_no_module_branches_on_the_encodings_name`, which fails on any
   comparison against a codec-name literal anywhere in `scripts/`, regardless of
   the enclosing function's name. Both holes are mutation-tested.

   **The transferable lesson: a guard that scans for last time's syntax will be
   walked around. Assert the property, not the pattern.**
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

### A coarse clock hides bugs a fine one exposes

The habitual lesson in this repo is "green on Linux, broken on Windows".
**Chunk 19 hit the inverse**, which is the more dangerous shape because the
platform that looks fine is not.

`ProvenanceGenerator.generate` read the wall clock for `finishedOn` before
`startedOn`, producing an attestation that had finished before it began — a
CRITICAL `TIMESTAMP_ANOMALY` by JMo's own tamper detector.

| platform | clock granularity | how it presented |
|---|---|---|
| Windows | ~1 ms | both reads land in one tick, strings come out **equal**, `<=` accepts. 300 consecutive local generations were **all** equal-tick. A rare flake, and only under `-n 8`. |
| Ubuntu ×4, macOS | ~1 µs | the reads straddle a tick nearly always. **Deterministic failure on all five shards.** |

Two things follow:

1. **A repeat-loop is not a substitute for a finer clock.** Running the
   generation 300 times locally produced 0 inversions *and* 0 strictly-ordered
   results — every sample was equal-tick, so the experiment could not
   distinguish "ordered" from "lucky" at all. It looked like confirmation and
   carried no information.
2. **Do not loosen a timing assertion to stop a flake.** `startedOn <=
   finishedOn` was the assertion that caught this. The fix is to make the guard
   *deterministic* — patch the clock so it advances on every read — not to widen
   the tolerance. That is what makes the mutation test possible.

```python
class Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        return base + timedelta(seconds=next(ticks))

with patch("scripts.core.attestation.provenance.datetime", Clock):
    ...
```

Same root cause as the known `time.monotonic` coarseness on Windows (15 ms vs
`time.time`'s ~1 ms; use `perf_counter()`), opposite consequence: there,
coarseness made a duration read as zero, and here it made an ordering defect
invisible.

## Line Endings on Windows

This repo has **no `.gitattributes`** and `core.autocrlf=false`, so line endings
are stored byte-for-byte and are **mixed per file** (`scripts/cli/jmo.py` is LF;
`scripts/core/unicode_utils.py` is CRLF).

`pathlib.Path.write_text()` opens with `newline=None`, translating every `\n` to
`os.linesep` — `\r\n` on Windows. Reading a LF file and writing it back **converts
the whole file**, producing thousands of phantom line changes that bury the real
edit (7545 lines for a 7-line change; same class as the `update_versions.py` bug
fixed in #556). Use `write_bytes()`, or `open(..., newline="")`.

**`write_bytes()` alone is not enough — `read_text()` flips the other way.** It
also opens with `newline=None`, and *universal newlines* converts `\r\n` to `\n`
**on the way in**. So the obvious application of the paragraph above —

```python
s = path.read_text(encoding="utf-8")     # CRLF -> LF, silently, right here
s = s.replace(old, new)
path.write_bytes(s.encode("utf-8"))      # persists LF for the whole file
```

— converts a CRLF file to LF while looking like it avoided the problem. Measured
in chunk 18: four CRLF test files flattened by a patch script written this way,
**+3661/-2592 raw against +1402/-333 EOL-insensitive — 2259 phantom lines**.

Read bytes on both ends when you are rewriting a file programmatically:

```python
raw = path.read_bytes()
s = raw.decode("utf-8")                  # no newline translation
path.write_bytes(s.replace(old, new).encode("utf-8"))
```

Or pass `newline=""` to `open()`, which disables translation in both directions.
The Edit tool does not have this problem; only scripts do.

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
