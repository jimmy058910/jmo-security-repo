---
title: Testing Infrastructure & Patterns
paths:
  - tests/**/*.py
  - pyproject.toml
  - Makefile
references:
  - TEST.md (complete testing guide)
  - testing.cross-platform.rules.md (Windows/macOS/Linux compatibility)
  - pytest-timeout, pytest-xdist configuration
---

# Testing Infrastructure & Patterns

**What this covers:** Test organization, pytest command patterns, mocking strategies, and coverage requirements. For cross-platform Windows/macOS/Linux issues, see [testing.cross-platform.rules.md](testing.cross-platform.rules.md).

## Test Coverage & CI Requirements

**The only enforced coverage floor is 80%**, in `.github/workflows/ci.yml:734`:

```python
if coverage_pct < 80:
    sys.exit(1)
```

`--cov-fail-under` is set **nowhere** — not in `make test` (`Makefile:132` runs
`pytest --cov --cov-report=term-missing`, no threshold), not in
`[tool.coverage.report]`, not in any workflow. Tracked as **#756**.

- All new code must include tests.
- Use `--cov=scripts --cov-report=term-missing` to identify gaps.
- **Compare against the previous run, not against a constant.** Because nothing
  fails between 80% and the current level, a regression in that band is invisible
  to CI — diffing the number yourself is the only thing that catches it.

> This section previously read "**Mandatory:** `pytest --cov-fail-under=85` in
> CI" and "Aim for >87% (current baseline)". Both were unenforced, and the 87%
> was never measured in-repo. A stated guarantee is a claim to verify — the same
> failure class as #747 (pinned version drift) and #750 (prose version headers).

## `.test_durations` — why it is committed, and how to regenerate it

The Ubuntu shards split with `--splits 4 --group N --splitting-algorithm
least_duration`. **Without a durations file that algorithm has nothing to
balance against and silently falls back to splitting evenly by count**, which
clusters the slow tests. Measured before this file existed:

| | shard 1 | shard 2 | shard 3 | shard 4 |
|---|---|---|---|---|
| even by count | 6.7 min | 6.8 min | **17.9 min** | **16.5 min** |
| with durations | 12.0 min | 12.0 min | 12.0 min | 12.0 min |

A 2.7x spread, and it is why `ubuntu-latest Shard 4/4` timed out intermittently
on unrelated PRs for weeks (#828). pytest-split announces the fallback in its
own output — `[pytest-split] No test durations found` — which is worth grepping
for if the shards look lopsided again.

Regenerate after adding or removing a lot of tests:

```bash
# Merges into the existing file; run in chunks so no single run is killed.
pytest tests/adapters -n 8 -q --store-durations -m "not smoke and not requires_tools and not docker"
pytest tests/unit tests/core -n 8 -q --store-durations -m "not smoke and not requires_tools and not docker"
# ...and so on for the remaining directories, then:
pytest tests/performance -q -p no:randomly --store-durations   # serially: contention distorts perf timings
```

**The trap: a durations file generated on Windows records every
Windows-skipped test at ~0.0005 s**, so pytest-split treats them as free. That
is *worse than no entry*, and it hits exactly the tests that matter —
`test_history_list_performance_10k_scans` is skipped on Windows and takes
**305 s** (measured with the `skipif` bypassed). Its entry is hand-corrected to
that value. The three `tests/e2e/test_cross_platform.py` entries are
Linux/macOS-only and still carry placeholder durations; regenerating on Linux
is the durable fix if the shards drift again.

## Running Tests Locally

```bash
# Recommended: Parallel execution (3-5x faster)
make test-fast                          # Fastest dev loop (no coverage)
make test-parallel                      # With coverage (CI-like)
pytest -n auto tests/unit/              # Direct pytest with parallelism

# Sequential (original, for debugging)
make test                               # Full coverage report
pytest tests/adapters/ -v               # Adapter tests only
pytest tests/cli/ -v                    # CLI tests only
```

## Test Markers

Use pytest markers to categorize and filter tests:

```python
@pytest.mark.slow           # Long-running tests (>5s)
@pytest.mark.requires_tools # Needs external tools installed
@pytest.mark.docker         # Requires Docker daemon
@pytest.mark.smoke          # Basic functionality check
```

**CI excludes these via:** `-m "not smoke and not requires_tools and not docker and not slow"`.

## Mocking Subprocess

**Rule:** Always mock `subprocess.run` for tests calling external commands.

```python
from unittest.mock import patch
from tests.conftest import mock_subprocess_success

with (
    patch("module.tool_exists", return_value=True),
    patch("module.find_tool", return_value="/usr/bin/tool"),
    patch("subprocess.run") as mock_run,
):
    mock_run.return_value = mock_subprocess_success(returncode=0)
    # ... test code ...
```

**Why:** Tests should not depend on external tools being installed. Real-tool tests get `@pytest.mark.requires_tools`.

## Mocking ToolInstaller (CRITICAL on Windows)

**Rule:** Always mock `ToolInstaller` in tests to prevent real installations.

```python
@patch("scripts.cli.tool_installer.ToolInstaller")
def test_scan_with_missing_tool(mock_installer):
    # Real installs spawn cmd.exe/node.exe that hang on Windows
    pass
```

## Timeout Configuration

- All tests have a **120s timeout** by default (configurable in `pyproject.toml`).
- Use `@pytest.mark.timeout(300)` for legitimately slow tests.
- Set `PYTEST_TIMEOUT=0` to disable during local debugging.

## Test File Organization

```text
tests/
├── unit/                   # Fast, self-contained
├── adapters/               # Adapter-specific (test_*_adapter.py)
├── reporters/              # Reporter-specific
├── cli/                    # CLI commands
├── integration/            # Multi-component scenarios
├── conftest.py             # Shared fixtures, markers, helpers
├── fixtures/               # Fixture data (JSON, YAML, etc.)
└── e2e/                    # End-to-end with real tools
```

**Reference:** [TEST.md](../../TEST.md) for the complete testing guide.

## `--maxfail` Truncation & Bug Archeology

The Nightly Extended Tests pytest invocation uses `--maxfail=20` (raised from 5 in v1.0.5; cross-platform jobs likewise). **This historically created a "bug archeology" pattern where deeper test failures were invisible until shallower ones were fixed** — most acute at the lower threshold.

When iterating on test fixes for nightly:

1. Each fix-and-validate cycle can reveal NEW failures from deeper in pytest's alphabetical order — failures that were always there but masked by the truncation cutoff.
2. Don't assume "it's just one bug left" until a clean run with 0 failures actually happens.
3. Each layer typically takes its own targeted fix PR; the post-v1.0.3 stabilization went through 5 such layers at `--maxfail=5` (PRs #343 → #344 → #345 → #346 → #347). v1.0.5 raised the cap to 20 to make this much rarer in practice.

**v1.0.5 mitigations** (PR shipping `--maxfail=20`):

- Added `--json-report --json-report-file=pytest-report.json` to nightly-extended-tests.
- Added a `Summarize pytest failures` step that renders the full failure list (capped at 50 entries to fit GHA's ~1MB Summary cap) into the run's `$GITHUB_STEP_SUMMARY`. So when truncation does happen, every caught failure is still visible in one place with its traceback.
- `pytest-report.json` is now also archived in the `nightly-test-results-${{ github.run_id }}` artifact bundle for fully post-hoc analysis.

**Iterating efficiently** — manual workflow dispatch instead of waiting for cron:

```bash
# Trigger Nightly Extended Tests on demand (~12-15 min vs 24 h cron)
gh workflow run scheduled.yml --ref main -f task=nightly

# Watch for completion
gh run list --workflow scheduled.yml --event workflow_dispatch --limit 1
```

The `task=nightly` input gates `nightly-extended-tests` and `lint-full` jobs in `scheduled.yml`. Other `task` choices: `e2e`, `performance`, `docker`, `all`.

**Diagnosing a truncated run:** If pytest output ends with `=== N failed in M.Ns ===` and N == 20 (or 5 on smoke / 3 on requires_tools), you're at the truncation cap. The Summary tab on the run page should list all N captured failures. Fix the visible ones, dispatch again, repeat until N drops below the cap or hits 0.

## Test Threshold Drift After Profile Changes

When changing `PROFILE_TOOLS` (or `MANUAL_INSTALL_TOOLS`) in `scripts/core/tool_registry.py`, several test/workflow constants need cascading updates:

- `tests/e2e/test_docker_workflows.py::DOCKER_VARIANTS` (per-variant `expected_tools` count)
- `tests/e2e/test_docker_workflows.py::DEEP_EXPECTED_TOOLS`, `BALANCED_EXPECTED_TOOLS`, etc. (named tool lists)
- `tests/e2e/test_docker_workflows.py::DEEP_ONLY_TOOLS` (tools that should NOT appear in lighter variants)
- `.github/workflows/scheduled.yml`'s `validate-variants` matrix (`expected_tools: <N>`)

Bearer's removal in PR #262 (April 2026) needed cascading updates that took multiple follow-up PRs to fully sync. **When changing `PROFILE_TOOLS`, grep for variant counts (`14`, `18`, `25`) and `expected_tools` simultaneously across `tests/` and `.github/workflows/`.**

## Deliberate Verification Gaps

Areas the suite does not cover, recorded so nobody mistakes silence for a pass.
Coverage percentage says nothing about these — there is no line to miss.

| Gap | Why it is untested | If you touch this area |
|---|---|---|
| **Cron persistence across reboot** | Install/uninstall is verified under WSL; a reboot test is too disruptive to automate on the dev box. Standard crontab behaviour, so risk is low. | Verify by hand on a real reboot before changing `cron_installer.py`. |
| **MCP server memory over long sessions** | The server starts, serves, and shuts down cleanly, but no extended profiling has been run. stdio is single-client and sessions are short, so growth would need a long-lived client to matter. | Profile if you add caching or any per-request accumulation. |
| **Concurrent scans on Windows** | Requires two real scans racing on one results directory. SQLite has its own locking and scan outputs are write-once, so the risk is low — but it is untested, not proven. | Exercise it manually with separate `--results-dir` values, then with shared ones. |

The user-facing half of these is in [docs/KNOWN_LIMITATIONS.md](../../docs/KNOWN_LIMITATIONS.md). Keep the two in step: if a gap here becomes something a user can hit, it belongs there too.

## `uv sync` disarms tests by uninstalling what is not in the lock

`uv sync --group dev` prunes every package absent from `uv.lock`. Some of those
are packages tests depend on, and the tests then **skip green** rather than
fail — so a baseline taken after a sync is not comparable to one taken before.

Measured 2026-08-18, immediately after a routine `uv sync --group dev`:

| package | why it was there | tests | shows up as |
|---|---|---:|---|
| `yara-python` | installed by `jmo tools install`, never in `uv.lock` | **7** | `could not import 'yara'` in `tests/unit/test_yara_runner.py` |
| `psutil` | **not in `uv.lock` at all** — `scheduled.yml:1410` runs `uv pip install psutil` for the benchmark job only | **2** | `psutil not installed` in `tests/performance/test_benchmarks.py` and `test_stress.py` |

Half A went `7434 passed / 65 skipped` to `7427 / 72`; half B went `1128 / 40`
to `1126 / 42`. **Collected counts were identical in both halves** — nothing was
lost, 9 tests moved from passed to skipped. A comparison that looks only at
`passed` reads this as a regression; one that looks only at `collected` reads it
as no change. Both are wrong, which is why the section below insists on
comparing like with like.

Two consequences worth carrying:

- **~~`psutil` is deliberate~~ — CORRECTED 2026-08-25 (#977). It was a defect,
  and this bullet said not to fix it.** The reasoning above ("the benchmark job
  installs psutil itself, so those 2 skips are correct behaviour and must not be
  'fixed'") was measured wrong by the bullet three below this one, written five
  days later: the job that installs psutil runs `test_benchmarks.py` only, while
  `test_stress.py` is collected by a *different* step that installs nothing and
  swallows its exit code. So the skips were not correct behaviour anywhere.

  The fix was smaller than adding psutil to the lock file. `test_stress.py`'s
  assertion had already moved to `tracemalloc` (stdlib) when #792 was fixed — it
  used psutil only for an informational RSS line, so it was skipping for a
  dependency it no longer needed. It now runs everywhere with psutil optional.
  `test_benchmarks.py`'s memory benchmark was **deleted**: it never called any
  processing function between its baseline and peak reads, and its fixture wrote
  CommonFinding-shaped objects into `individual-repos/*.json` where adapters
  expect raw tool output, so `gather_results` returned **0 findings** (measured).
  It asserted a 500MB budget on work that did not happen.

  Measured before/after with psutil blocked: **13 passed / 2 skipped** →
  **14 passed / 0 skipped**.

  **The transferable part: a bullet saying "this is correct, do not fix it" ages
  worse than one recording a measurement.** Prefer stating what was measured and
  when; let the reader draw the conclusion.
- **`yara-python` is collateral.** The 7 yara skips are a real cost: a security
  tool's Python module gets removed from the venv by a dependency sync.
  Reinstall with `jmo tools install yara` when those tests matter.
- **#792 does not "fail to reproduce" in a synced environment — it *skips*.**
  `test_30k_findings_memory_usage` (named `test_100k_findings_memory_usage`
  until #792/#767 were fixed — see below) lives in `test_stress.py` behind the
  psutil guard. "Did not reproduce" and "did not run" are different claims and
  only the second is true. Say which mode produced the result.
- **The skip isn't confined to PR-time — check every job that touches the file,
  not just the one that names it.** `scheduled.yml` has *two* steps that could
  plausibly run `test_stress.py`: the dedicated `performance-benchmarks` job
  (targets `tests/performance/test_benchmarks.py` only, installs psutil itself)
  and `nightly-extended-tests`'s own `Run performance benchmarks` step (targets
  the whole `tests/performance/` directory — *this* one collects
  `test_stress.py` too). Measured 2026-08-23: the second step does **not**
  install psutil, so the skip fires there as well, and the step is piped
  through `|| echo "Performance tests completed with warnings"` — swallowing
  the exit code regardless. This memory test currently produces zero signal
  anywhere in CI, not just at PR time. Grep for the test **file's path**, not
  the job name you already suspect, before concluding a gate is nightly-only.

## Memory-gate negative controls: a second container is not a second allocation

Fixing #792 replaced what was then `test_100k_findings_memory_usage`'s psutil
RSS-delta assertion with `tracemalloc.get_traced_memory()` peak — RSS spread
429.6-540.4MB across 4 runs on one box for byte-identical code (machine-state
noise); tracemalloc peak agreed to <0.01MB across the same 4 runs, including
one under `-n 4` xdist contention. (The numbers in this section are all at the
100k-finding scale that test used at the time; #767 below later resized it to
30k, so the *current* file reads smaller numbers against a smaller budget —
same mechanism, different scale.)

Verifying the new gate could still fail needed a negative control: mutate
`gather_results` to retain everything it reads. First attempt appended the
already-referenced `fut.result()` list to a second, never-cleared module-level
list — and **the assertion did not move at all** (680.7MB before, 680.7MB
after). A Python list stores references, not copies: a second container
holding the same objects `findings` already extended costs only its own
pointer array (~800KB for 100k entries), not the payload. The mutation looked
exactly like a real leak in code review and asserted nothing. Switching to
`_TEMP_NEGATIVE_CONTROL_LEAK.append(copy.deepcopy(result))` forced genuine new
allocation and moved peak to 827.2MB, correctly tripping the (then-)750MB
budget. Re-run again after #767 resized the fixture to 30k: same shape, smaller
numbers (170.2MB mutated vs a 150MB budget, 126.3MB restored).

**When writing a memory-regression negative control, deep-copy, don't
re-reference — the same trap the fix itself exists to catch will hide inside
the control that's supposed to prove the fix works.**

## #767: fixing what a test *reports* does not fix what it *allocates*

`test_stress.py::TestExtremeLoad`'s memory test (see above — renamed
`test_100k_findings_memory_usage` → `test_30k_findings_memory_usage`) crashed
an xdist worker under `-n auto` (`worker 'gwN' crashed ... node down: Not
properly terminated`), and pytest-cov lost that worker's coverage data as a
result (`ci.yml`'s aggregate TOTAL read as low as 13% on this box — worse than
the 32% the issue itself cited). #792's fix (RSS delta → tracemalloc peak,
above) landed **first** and did **not** stop the crash: re-measured with the
tracemalloc version installed, the same worker still died on the same test.
That is not a bug in the #792 fix — the two issues are different questions.
**A measurement fix changes what a test *reports*; it does not change what the
test *allocates*.** `gather_results` still builds and holds the same 100k-item
structure either way. Whatever you change to make a number more honest, ask
separately whether the underlying code still does the same amount of real work
— fixing the gate and fixing the crash are two different patches, and treating
the first as having discharged the second is exactly the wrong assumption to
carry into a report.

**Check real headroom, not just the test's own footprint, before assuming a
crash is the test being wasteful.** `systeminfo`/`wmic OS get
FreePhysicalMemory` on this box read 16,069MB total RAM and only
~428-660MB free even near-idle (background apps, IDE, the agent session
itself). Twenty concurrent `-n auto` workers plus one needing several hundred
extra MB is a genuine OOM-adjacent condition on a box in that state — xdist's
`-n auto` sizes off `os.cpu_count()`, which has no idea how much RAM is
actually free.

**The fix that actually stopped the crash: reduce the real allocation, not
just its reported figure.** Fixture size 100k → 30k findings. 100,000 was a
round number, not a measured requirement, and the peak-vs-size relationship
between 50k-100k is **not linear** on this workload (measured via a standalone
probe script, same `gather_results` code path: 50k→242MB, 75k→504MB,
100k→680MB — a jump disproportionate to the input growth, most likely GC/
allocator threshold effects during JSON parsing + dedup, not confirmed further
since it didn't need to be to pick a safe size). 30k landed at 126.3MB, ~5x
below the crash-prone 680MB, while staying 3x the 10k reference size in
`test_error_recovery.py`'s `test_large_findings_batch_handling` (which,
notably, did **not** crash its worker in the same `-n auto` run — only the
100k-scale test did, even though the original #767 report listed two
crashers; a smaller-scale sibling test doing similar work is evidence the
crash is about scale, not about the operation itself).

## Counting tests: compare like with like

A terminal summary's `skipped` count includes **collection-level** skips, which
are not test nodes. So `passed + skipped` from the summary can legitimately
exceed the number of tests collected, and the two numbers are not comparable.

Measured on the half-B directories (`tests/` minus
`unit`/`cli`/`core`/`adapters`):

| source | number |
|---|---:|
| terminal summary | `1128 passed, 40 skipped` = **1168** |
| `--collect-only -q` | **1167** selected (210 deselected) |
| `--json-report` `summary` | `{"passed": 1128, "skipped": 39, "total": 1167, "collected": 1167}` |

The odd one out is a module-level `pytest.importorskip`:

```text
SKIPPED [1] tests\e2e	est_dashboard_visual.py:29:
  could not import 'playwright': No module named 'playwright'
```

Diffing the run's node ids against the collected ids is **empty in both
directions** — there is no extra test, only an extra line in the tally.

**What to do:** compare a collection count against a collection count, or take
`summary.total` from `--json-report`. Do not reconcile a recorded
`--collect-only` baseline against a fresh terminal summary.

This was filed as a bug (#878) and closed after measuring. The campaign already
applies like-with-like discipline to run-vs-run comparisons across trees; this
is the same rule one level down, and it cost an issue to re-learn.

## A mirror of a mirror: why enumerating tests miss a whole class

**Symptom:** a hand-written list restates something the code already defines —
an argparse parser, a set of writers, a config schema — and a full test file
covers it, green, while the two have silently drifted apart.

Found three times in the v1.1.0 campaign. The worst was `cmd_ci`, which
re-marshalled its arguments through two hand-written classes built entirely
from `getattr(a, "<literal>", <default>)`. `jmo ci` **parsed** nine flags and
advertised them in `--help`, and the mirrors had never listed them, so
`--skip-tools` ran the tool anyway and `--no-store-raw-findings` wrote secrets
to the history database. A string literal is invisible to mypy, so there was no
type error. `test_ci_orchestrator.py` had **24 tests over `cmd_ci` and not one
used the real parser** — two of them enumerated the 26 and 20 fields the mirrors
manufactured, one assertion each.

> **A test that lists what the mirror *set* has no way to notice what it did
> not.** The test is a mirror of the mirror; both were written from the same
> wrong assumption, on the same day, by the same person.

The same shape, elsewhere: `test_wizard_generators.py` asserted the strings
`wizard_generators.py` emits, *verbatim* — comparing the template to itself. It
was green for **13** generated `jmo ci`/`jmo report` commands that exit 2.

### What to do instead

1. **Derive from the authority, do not restate it.** Read the parser's dests,
   AST-scan the consumer, ask the real parser whether a generated command
   parses. `KNOWN_OUTPUTS` (chunk 10), `test_ci_arg_forwarding.py` and
   `test_wizard_generated_commands_parse.py` are the worked examples.
2. **Give every derivation a meta-guard.** An extractor that silently finds
   nothing passes every assertion built on it. Assert a floor on what it found
   *and* name a few items it must contain.
3. **Add a negative control.** Prove the oracle still rejects the pre-fix input,
   or "the parser accepts everything" reads as "everything is fine".
4. **Keep any list that survives minimal and justified.** `_SCAN_REQUIRED` /
   `_REPORT_REQUIRED` in `ci_orchestrator.py` are 7 entries, each because its
   consumer reads it as a bare `args.X` with no default — and a test derives
   that set by AST and fails if the lists drift in **either** direction. 49
   hand-written fields became 7 measured ones.

**And an oracle earns its keep immediately.** The first version of the wizard
fix rewrote six `report --profile <value>` sites to `--profile-name` — a flag
`jmo report` does not define either. The new parser-oracle guard failed 11 cases
on its first run. Same lesson as chunk 8's mutation testing: *a fix can carry
its own live bug, and only an independent oracle finds it.*
