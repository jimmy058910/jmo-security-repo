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
