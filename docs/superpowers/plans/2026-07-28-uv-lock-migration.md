# uv.lock Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the dual-writer dev-dependency system (`requirements-dev.in` + generated `requirements-dev.txt` + a duplicate `[project.optional-dependencies] dev` extra) with a single PEP 735 `[dependency-groups] dev` declaration in `pyproject.toml` plus a tracked, universal `uv.lock`.

**Architecture:** `pyproject.toml` becomes the only place dev deps are declared. `uv.lock` becomes the only lockfile, and it is universal by construction (all platform markers preserved), which makes the `pywin32`-dropped-on-Windows class structurally impossible. Every install site — local, CI, pre-commit, devcontainer — runs the same `uv sync` against that lock. Dependabot switches from the `pip` ecosystem (Linux-only pip resolver, edits the generated file directly) to the native `uv` ecosystem (regenerates the lock *with uv*), so bot and human PRs pass the identical freshness gate for the first time.

**Tech Stack:** Python 3.12+, uv 0.11.15 (pinned), `astral-sh/setup-uv@v9`, GitHub Actions, pre-commit, pytest.

**Source spec:** [`docs/superpowers/specs/2026-07-28-uv-lock-migration-design.md`](../specs/2026-07-28-uv-lock-migration-design.md) — the spec is the authority for all decisions. This plan does not re-litigate them.

---

## Global Constraints

Every task's requirements implicitly include this section.

- **Work only in the worktree** `C:\Projects\jmo-security-repo-uv-migration` (branch `feat/uv-lock-migration`, based on `origin/main`). NEVER stage, commit, or checkout in `C:\Projects\jmo-security-repo` — it is shared with an always-on peer agent.
- **In a worktree, `.git` is a FILE, not a directory.** Write temp files and commit messages to the scratchpad (`C:\Users\Jimmy\AppData\Local\Temp\claude\C--Projects-jmo-security-repo\58b23cf7-76b8-4158-89b1-5248c43f5320\scratchpad`), never to `.git/`.
- **Never run `pip install -e .` in this worktree** — it poisons imports for every other worktree on this machine. The primary repo's `.venv` is broken (silent 0-test false-green). Local verification uses `uv` in the worktree only.
- **uv is pinned to `0.11.15` at every site**, including `setup-uv`'s `version:` input (PR #488 convention). One version string, no exceptions.
- **`astral-sh/setup-uv@v9.0.0`** — pinned to the exact release, not a floating major. astral-sh publishes bare major tags only through `v7`; `v8` and `v9` exist as full semver only, so `@v9` fails with `Unable to resolve action astral-sh/setup-uv@v9, unable to find version v9` (hit on the first CI run of PR #683). An exact pin also matches this repo's pin-everything convention, and Dependabot's github-actions ecosystem will bump it.
- **`uv export --format requirements.txt`** — the format value is dotted. The spec wrote `requirements-txt`, which uv rejects. Verified against uv 0.11.19's CLI (`--format <FORMAT> [possible values: requirements.txt, pylock.toml, cyclonedx1.5]`).
- **Preserve both pip-audit ignores, verbatim:** `PYSEC-2025-183` (disputed pyjwt advisory, transitive dev-only via `mcp`) and `GHSA-qp9x-wp8f-qgjj` (tuf<7 capped by sigstore, tracked in issue #539).
- **Conventional commits** (`feat:`, `fix:`, `chore:`, `ci:`, `docs:`, `test:`, `refactor:`). **No AI-attribution markers** in any commit message or PR body.
- **Windows/Git Bash trap:** MSYS mangles `<ref>:<path>` colon revspecs. Use `MSYS_NO_PATHCONV=1 git show origin/main:file` or `git ls-tree`.
- **Do NOT edit (historical records):** `CHANGELOG.md`, existing files under `docs/superpowers/plans/` and `docs/superpowers/specs/` (this plan file is new, which is fine), `dev-only/archive/`.
- **Two PRs, direct to main, squash-merge**, `dev` synced from `main` afterward via the `merge-pr` skill. PR 1 must be fully green on its own.

### Corrections to the spec's blast-radius list (discovered while reading the tree)

These are facts, not decisions — the spec's intent is unchanged, its file list was incomplete.

| Spec said | Reality |
|---|---|
| `docs/COMPLETENESS_ANALYZER.md` (6 refs) | **Does not exist.** No file matches `**/COMPLETENESS*`. Drop from PR 2. |
| (not listed) | **`hooks/pre-push` (6 refs)** — has a live `requirements-dev.in`-vs-`.txt` sync check that breaks. PR 1. |
| (not listed) | **`.devcontainer/devcontainer.json` (1 ref)** — `postCreateCommand` installs from `requirements-dev.txt`. PR 1. |
| (not listed) | **`scripts/dev/update_dependencies.py` (21 refs)** — the script that *generates* `requirements-dev.txt`. PR 1 deletes it (see Task 6). |

### Finding: issue #539's tuf ignore is probably now closeable (do NOT act on it here)

The fresh resolve produced **`tuf==7.0.0`** alongside `sigstore==4.5.0`. `GHSA-qp9x-wp8f-qgjj` is *fixed* in tuf 7.0.0, and the ignore's stated justification — "every sigstore release caps `tuf<7.0.0`" — no longer holds at sigstore 4.5.0.

The spec says preserve both ignores, so this plan preserves both. An ignore for an advisory that is no longer present is inert (pip-audit does not error on unused ignores), so keeping it costs nothing and keeps this PR's scope honest. **Report it in the PR 1 body as a follow-up**, so issue #539 can be closed and the ignore dropped in a separate, properly-scoped change. Do not drop it here — that would be an unreviewed security-posture change riding along in a migration PR.

---

## File Structure

### Created

| File | Responsibility |
|---|---|
| `uv.lock` | The single lockfile. Universal (all platform markers). Generated by uv 0.11.15, tracked in git, regenerated by Dependabot with uv. |
| `scripts/dev/audit_deps.sh` | One implementation of "export the lock and run pip-audit with the project's two ignores", shared by `ci.yml` and `.pre-commit-config.yaml`. Replaces two copies of an inline invocation that had already drifted apart in comment text. |
| `tests/unit/test_uv_lock_platform_coverage.py` | Regression guard for the invariant this whole migration protects: the lock must carry `pywin32` under a `sys_platform == 'win32'` marker. |
| `tests/unit/test_dep_audit_drift.py` | Drift guard: both CVE ignores survive, both call sites go through `audit_deps.sh`, and exactly one uv version is pinned across all sites. |

### Modified

| File | Change |
|---|---|
| `pyproject.toml` | Add `[dependency-groups] dev` (union of `requirements-dev.in`'s 30 entries). Delete `dev` from `[project.optional-dependencies]`. |
| `.gitignore` | Remove the 5-line `uv.lock` ignore block (lines 190–194). |
| `.github/dependabot.yml` | `package-ecosystem: "pip"` → `"uv"`. |
| `.github/workflows/ci.yml` | 3 install sites → `setup-uv` + `uv sync`. Replace 2 gate steps with `uv lock --check`. pip-audit → `audit_deps.sh`. |
| `.github/workflows/scheduled.yml` | 10 install sites → `setup-uv` + `uv sync`. Drop `deps-compile` from the pre-commit `SKIP` list. |
| `.github/workflows/maintenance.yml` | Delete the self-heal recompile step + its `git add` entry + 2 prose references. 1 install site. |
| `.github/workflows/release.yml` | 2 install sites. |
| `.github/actions/setup-python-jmo/action.yml` | Composite action → `setup-uv` + `uv sync`; cache key moves to `uv.lock`. |
| `.pre-commit-config.yaml` | `deps-compile` hook → `uv-lock` hook. `pip-audit` hook → `audit_deps.sh`. |
| `Makefile` | `deps-compile`/`deps-sync`/`deps-refresh`/`deps-validate`/`deps-check-outdated` → `deps-sync`/`deps-lock`/`deps-upgrade`. `dev-deps`/`dev-setup` → uv. |
| `hooks/pre-push` | Delete the requirements-dev sync check. |
| `.devcontainer/devcontainer.json` | `postCreateCommand` → uv. |
| `CLAUDE.md` | Development Setup command (accuracy-critical, PR 1). |
| `CONTRIBUTING.md` | Setup commands (PR 1) + the rest of the 14 refs (PR 2). |
| `docs/internal/DEPENDENCY_MANAGEMENT.md` | **Rewrite** (597 lines, 33 refs) — PR 2. |
| `docs/internal/PRE_COMMIT_HOOKS.md` | 12 refs — PR 2. |
| `docs/RELEASE.md`, `docs/TROUBLESHOOTING.md`, `docs/VERSION_MANAGEMENT.md`, `TEST.md` | 1 ref each — PR 2. |
| `.claude/rules/release.rules.md` | 2 refs incl. the stale drift troubleshooting entry — PR 2. |

### Deleted

| File | Why |
|---|---|
| `requirements-dev.in` | Superseded by `[dependency-groups] dev`. |
| `requirements-dev.txt` | Superseded by `uv.lock`. The second writer whose removal is the point of this migration. |
| `scripts/dev/update_dependencies.py` | Sole purpose is generating/validating `requirements-dev.txt`. Its two checks die with the file: the "Python version header" check reads a `uv pip compile` header that no longer exists, and `pip check` conflict detection exists only because flattening all dev deps into one requirements file surfaces ~10 theoretical conflicts between tools that never share a Python environment (see `requirements-dev.in`'s own header comment). `uv.lock` resolves a real dependency graph, so conflicts are impossible by construction. |

---

## Reference: the canonical CI install block

Every install site in Tasks 7–10 is replaced by this exact block. It appears ~16 times; keep it byte-identical so a future `grep` finds all of them.

```yaml
      - name: Set up uv
        uses: astral-sh/setup-uv@v9.0.0
        with:
          version: "0.11.15"  # pinned: single uv version across all sites (PR #488)
          python-version: '3.12'  # preserves the pin actions/setup-python held
          enable-cache: true
          cache-dependency-glob: "uv.lock"

      - name: Install dependencies
        run: uv sync --locked --group dev

      - name: Put the project venv on PATH
        shell: bash
        # Keeps every existing bare `pytest` / `black` / `ruff` invocation working
        # unchanged. Windows runners put scripts in .venv/Scripts, POSIX in .venv/bin;
        # the conditional means a job that later gains a Windows matrix entry does
        # not silently break.
        run: |
          if [ -d .venv/Scripts ]; then
            echo "$PWD/.venv/Scripts" >> "$GITHUB_PATH"
          else
            echo "$PWD/.venv/bin" >> "$GITHUB_PATH"
          fi
```

Notes that apply to every site:

- The `actions/setup-python@v7` step it replaces is **deleted**, along with its `cache: pip` / `cache-dependency-path: requirements-dev.txt` inputs. uv provisions Python instead, via setup-uv's `python-version` input.
- **`python-version: '3.12'` is mandatory at every site.** Without it uv picks the newest interpreter satisfying `requires-python = ">=3.12"` — verified locally, where `uv sync` chose CPython 3.14.3. That would silently move CI off the 3.12 that `actions/setup-python@v7` pinned, making the migration behavioral rather than mechanical. Sites that parameterize the version (`nightly-cross-platform`) pass `${{ matrix.python-version }}` instead.
- `uv sync` installs the project (editable) as well, which `pip install -r requirements-dev.txt` never did. Sites that previously ran a separate `pip install -e .` lose that line. If a job breaks because it does *not* want the project installed, `--no-install-project` is the escape hatch.
- `--locked` hard-fails if `uv.lock` is stale. That is deliberate in CI; local `make deps-sync` uses plain `uv sync` (spec §Approved decisions 5).

---

## PR 1 — Functional migration

### Task 1: Declare dev deps in `pyproject.toml` and generate the lock

**Files:**
- Modify: `pyproject.toml:56-80` (delete `dev` from `[project.optional-dependencies]`), and append a new `[dependency-groups]` table after `[project.optional-dependencies]`
- Modify: `.gitignore:190-194` (delete the block)
- Create: `uv.lock` (generated)
- Test: `tests/unit/test_uv_lock_platform_coverage.py`

**Interfaces:**
- Produces: a `[dependency-groups] dev` group named exactly `dev`, consumed by every `uv sync --group dev` / `uv export` in Tasks 2–11. A tracked `uv.lock` at the repo root.

- [ ] **Step 1: Write the failing test**

This test encodes the invariant the entire migration exists to protect. `pywin32` reaches the graph transitively through `mcp`, and Dependabot's Linux-only pip resolver silently dropped it — breaking `mcp` on the maintainer's Windows dev box. A universal lock cannot drop it; this test proves the lock stayed universal.

Create `tests/unit/test_uv_lock_platform_coverage.py`:

```python
#!/usr/bin/env python3
"""Drift guard: uv.lock must stay universal (all platform markers preserved).

The migration to a tracked `uv.lock` exists to make one specific failure
impossible. Before it, `requirements-dev.txt` was generated by
`uv pip compile --universal` but *edited in place* by Dependabot's Linux-only
pip resolver. That resolver dropped platform-conditional entries — notably:

    pywin32==312 ; sys_platform == 'win32'   # via mcp

so a fresh install on Windows omitted `pywin32` and broke `mcp`. The bug was
invisible on CI's Linux runners and only bit the maintainer, who develops on
Windows.

`uv.lock` is universal by construction, so this cannot recur silently. This
test is the alarm if someone regenerates the lock in a
platform-restricted way (e.g. adds `--python-platform linux`, or hand-edits).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
UV_LOCK = REPO_ROOT / "uv.lock"


@pytest.fixture(scope="module")
def lock_text() -> str:
    if not UV_LOCK.exists():
        pytest.fail(
            "uv.lock is missing. It is the project's only lockfile and MUST be "
            "tracked in git. Regenerate with: uv lock"
        )
    return UV_LOCK.read_text(encoding="utf-8")


def test_lock_contains_windows_only_dependency(lock_text: str) -> None:
    """pywin32 (win32-only, transitive via mcp) must be present in the lock."""
    assert re.search(r'^name = "pywin32"$', lock_text, re.MULTILINE), (
        "pywin32 is absent from uv.lock. This is the exact regression the "
        "migration away from requirements-dev.txt was built to prevent: a "
        "platform-restricted resolve drops win32-only transitive deps, and "
        "`mcp` then fails to import on Windows. Regenerate the lock with a "
        "plain `uv lock` (no --python-platform restriction)."
    )


def test_lock_carries_win32_platform_markers(lock_text: str) -> None:
    """The lock must carry sys_platform == 'win32' markers, not just resolve for Linux."""
    assert "sys_platform == 'win32'" in lock_text, (
        "uv.lock has no sys_platform == 'win32' markers, which means it was "
        "resolved for a single platform instead of universally. Cross-platform "
        "dev installs (Windows/macOS) will be silently wrong."
    )


def test_lock_carries_darwin_platform_markers(lock_text: str) -> None:
    """macOS markers prove the resolve is genuinely universal, not just win32-aware."""
    assert "sys_platform == 'darwin'" in lock_text, (
        "uv.lock has no sys_platform == 'darwin' markers. CI runs a macOS "
        "test shard; a lock without darwin markers will resolve differently there."
    )


def test_requirements_dev_files_are_gone() -> None:
    """The dual-writer files must stay deleted — re-adding one re-arms the drift bug."""
    for stale in ("requirements-dev.in", "requirements-dev.txt"):
        assert not (REPO_ROOT / stale).exists(), (
            f"{stale} is back. It was deleted deliberately: a second "
            "dependency file with a second writer (Dependabot's pip resolver) "
            "is the root cause of the deps-compile drift class. Declare dev "
            "deps in pyproject.toml's [dependency-groups] instead."
        )
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd C:/Projects/jmo-security-repo-uv-migration && uv run --no-sync python -m pytest tests/unit/test_uv_lock_platform_coverage.py -v`

Expected: FAIL. `uv.lock` does not exist yet, so the fixture calls `pytest.fail("uv.lock is missing...")` for the three lock tests, and `test_requirements_dev_files_are_gone` fails because both files still exist.

(If `uv run` cannot start because there is no environment yet, run `uv sync --group dev` first — Step 4 does this anyway; re-run the test afterward and confirm it still fails on `test_requirements_dev_files_are_gone` at minimum.)

- [ ] **Step 3: Add `[dependency-groups] dev` to `pyproject.toml`**

Delete the entire `dev = [...]` entry from `[project.optional-dependencies]` (`pyproject.toml:56-80`), leaving `reporting`, `email`, `mcp`, `attestation`, and `visual` intact. Then insert this block immediately after the closing `]` of the `visual` extra (i.e. after what is currently line 55), before `[project.scripts]`:

```toml
# PEP 735 dependency group. This is the SINGLE declaration of dev dependencies
# for this project — install with `uv sync --group dev`.
#
# It replaces two prior sources that had already diverged: a
# `[project.optional-dependencies] dev` extra (19 packages) and
# `requirements-dev.in` (30). The extra was a strict subset, so the documented
# `pip install -e ".[dev]"` produced a smaller environment than CI used — which
# is how PR #361 shipped a scheduled job broken by a missing pytest-benchmark.
[dependency-groups]
dev = [
    # Testing
    "pytest",
    "pytest-cov",
    "pytest-split>=0.9.0",          # Test sharding for CI parallelization
    "pytest-timeout>=2.3.0",        # Safety net to prevent infinite test hangs
    "hypothesis",
    "pytest-rerunfailures",
    "pytest-xdist>=3.5.0",          # Parallel test execution with -n auto
    "pytest-json-report>=1.5.0",    # Machine-readable test output for CI scheduled jobs
    # Performance benchmark plugin (--benchmark-json/--benchmark-only) used by
    # scheduled.yml's Performance Benchmarks job + scripts/dev/compare_benchmarks.py
    "pytest-benchmark>=4.0.0",
    # Linting & formatting
    "ruff",
    "bandit",
    "black",
    "pre-commit",
    "mypy>=2.2.0",                  # mypy 2.x — sandbox-verified 0 errors on scripts/ (supersedes #634, #487)
    # Required for tests
    "pyyaml",
    "jsonschema",
    # Type stubs
    "types-PyYAML",
    "types-tabulate",
    "types-requests",
    "croniter",
    "types-croniter",
    # MCP Server dependencies (Feature #2: AI Remediation)
    "mcp[cli]>=1.0.0",              # Official Anthropic MCP SDK with FastMCP framework
    # Security floors for mcp's transitive web deps (pip-audit fixable CVEs, 2026-06):
    #   starlette>=1.3.1: CVE-2026-48817/48818/54282/54283
    #   python-multipart>=0.0.31: CVE-2026-53538/53539/53540
    "starlette>=1.3.1",
    "python-multipart>=0.0.31",
    # Security floor for click (transitive via black + mcp[cli]'s typer):
    #   click>=8.3.3: PYSEC-2026-2132
    "click>=8.3.3",
    # Policy-as-Code (Feature #5). OPA binary installs separately via scripts/dev/install_tools.sh.
    "packaging",                    # Version comparison in OPA version checks
    # SLSA Attestation (Feature #6, v1.0.0)
    "sigstore>=2.0.0",              # Keyless signing (Fulcio + Rekor)
    "cryptography>=48.0.1",         # >=48.0.1: GHSA-537c-gmf6-5ccf
    # Platform-specific transitive deps kept top-level so they are guaranteed to
    # appear in the lock. uv.lock is universal, so pywin32's
    # sys_platform == "win32" marker (via mcp) is preserved natively —
    # see tests/unit/test_uv_lock_platform_coverage.py.
    "colorama",
    "pytz",
]
```

Verify the count is 30 entries, matching `requirements-dev.in` exactly. The `# Diamond Dependency Conflicts (Non-Blocking)` header comment from `requirements-dev.in` is deliberately NOT carried over — it described an artifact of flattening all deps into one requirements file with `pip-compile`, which no longer happens.

- [ ] **Step 4: Remove the `uv.lock` ignore and generate the lock**

Delete `.gitignore:190-194` entirely (the comment block and the `uv.lock` line):

```gitignore
# uv lockfile: the canonical dev-dep lockfile is requirements-dev.txt (pip-tools).
# Tracking uv.lock duplicates resolution and makes Dependabot emit uv-group PRs
# whose resolver diverges from the CI pip-tools resolver. Users who prefer uv
# can regenerate their own local uv.lock from requirements-dev.in.
uv.lock
```

Then generate the lock and sync, using the pinned uv:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
uv lock
uv sync --group dev
```

- [ ] **Step 5: Verify the Windows invariant explicitly (verification bar item (a))**

This is verification requirement (a) from the spec and must be demonstrated, not assumed. Run in the worktree on this Windows machine:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
uv sync --group dev
uv run python -c "import win32api, mcp; print('pywin32 OK:', win32api.GetVersionEx()[:2]); print('mcp OK')"
uv run python -c "import pytest_benchmark, sigstore, starlette; print('divergent-package set OK')"
```

Expected: all three lines print without ImportError. `pywin32 OK: (10, 0)` (or similar version tuple) proves `pywin32` installed on Windows — the invariant. The third command proves packages that were missing from the old `[dev]` extra are now present.

Record the exact output; it is quoted in the PR 1 body.

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd C:/Projects/jmo-security-repo-uv-migration && uv run python -m pytest tests/unit/test_uv_lock_platform_coverage.py -v`

Expected: `test_lock_contains_windows_only_dependency`, `test_lock_carries_win32_platform_markers`, `test_lock_carries_darwin_platform_markers` PASS. `test_requirements_dev_files_are_gone` still FAILS — those files are deleted in Task 6. That is expected and correct at this point; do not delete them early to make the test green.

- [ ] **Step 7: Commit**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add pyproject.toml .gitignore uv.lock tests/unit/test_uv_lock_platform_coverage.py
git commit -m "feat(deps): declare dev deps via PEP 735 dependency-groups and track uv.lock"
```

---

### Task 2: Shared pip-audit wrapper

**Files:**
- Create: `scripts/dev/audit_deps.sh`
- Test: `tests/unit/test_dep_audit_drift.py`

**Interfaces:**
- Consumes: `uv.lock` and the `dev` group from Task 1.
- Produces: `scripts/dev/audit_deps.sh` — takes no arguments, exits 0 when clean and non-zero when a non-ignored CVE is present. Called by `.github/workflows/ci.yml` (Task 7) and `.pre-commit-config.yaml` (Task 5).

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_dep_audit_drift.py`:

```python
#!/usr/bin/env python3
"""Drift guards for the dependency-audit path and the pinned-uv convention.

Two invariants that have each been broken before and are invisible until CI
goes red for an unrelated-looking reason:

1. The two pip-audit `--ignore-vuln` advisories must survive refactors. Both are
   load-bearing: PYSEC-2025-183 is a disputed pyjwt advisory with no fix
   version, and GHSA-qp9x-wp8f-qgjj cannot be resolved while sigstore caps
   tuf<7 (tracked in #539). Dropping either turns every CI run red with no
   available remediation.

2. Exactly one uv version is pinned across every site (the PR #488 convention).
   The uv.lock migration multiplied the number of pinned sites from ~4 to ~16;
   a single stale pin means one job resolves differently from the rest, which
   is precisely the class of bug this migration removes.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

AUDIT_SCRIPT = REPO_ROOT / "scripts" / "dev" / "audit_deps.sh"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PRE_COMMIT = REPO_ROOT / ".pre-commit-config.yaml"

REQUIRED_IGNORES = ("PYSEC-2025-183", "GHSA-qp9x-wp8f-qgjj")

# The single pinned uv version. Bump here and everywhere in one commit.
PINNED_UV_VERSION = "0.11.15"

# Files that pin a uv version and must all agree.
UV_PIN_SITES = (
    ".github/workflows/ci.yml",
    ".github/workflows/scheduled.yml",
    ".github/workflows/maintenance.yml",
    ".github/workflows/release.yml",
    ".github/actions/setup-python-jmo/action.yml",
    ".pre-commit-config.yaml",
    "Makefile",
    ".devcontainer/devcontainer.json",
)

# Matches a pinned uv version in any of the forms used across the repo:
#   version: "0.11.15"      (setup-uv input)
#   uv==0.11.15             (pip install)
UV_VERSION_PATTERN = re.compile(r"uv==(\d+\.\d+\.\d+)|astral-sh/setup-uv")


def test_audit_script_exists_and_is_executable_shell() -> None:
    assert AUDIT_SCRIPT.exists(), (
        "scripts/dev/audit_deps.sh is missing. It is the single implementation "
        "of the pip-audit invocation shared by CI and pre-commit."
    )
    assert AUDIT_SCRIPT.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash")


def test_audit_script_preserves_both_ignores() -> None:
    text = AUDIT_SCRIPT.read_text(encoding="utf-8")
    for advisory in REQUIRED_IGNORES:
        assert advisory in text, (
            f"{advisory} is no longer ignored in audit_deps.sh. Both ignores are "
            "load-bearing and unresolvable upstream — see the script's header "
            "comment and issue #539 before removing either."
        )


def test_both_call_sites_use_the_shared_script() -> None:
    """CI and pre-commit must call the script, not re-inline pip-audit.

    Two inlined copies is what let their explanatory comments drift apart in
    the first place.
    """
    for path in (CI_WORKFLOW, PRE_COMMIT):
        text = path.read_text(encoding="utf-8")
        assert "scripts/dev/audit_deps.sh" in text, (
            f"{path.name} does not call scripts/dev/audit_deps.sh. Do not "
            "re-inline the pip-audit invocation — the ignores drift."
        )
        assert "pip-audit -r requirements-dev.txt" not in text, (
            f"{path.name} still references the deleted requirements-dev.txt."
        )


def test_single_pinned_uv_version_across_all_sites() -> None:
    """Every uv pin in the repo agrees on one version (PR #488 convention)."""
    mismatches: list[str] = []
    for rel in UV_PIN_SITES:
        path = REPO_ROOT / rel
        if not path.exists():
            continue
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            for found in re.findall(r"uv==(\d+\.\d+\.\d+)", line):
                if found != PINNED_UV_VERSION:
                    mismatches.append(f"{rel}:{lineno} pins uv=={found}")
            # setup-uv's version input sits on a nearby line; catch a literal
            # version string that is not the pin only when uv is the subject.
            m = re.search(r'^\s*version:\s*"(\d+\.\d+\.\d+)"', line)
            if m and m.group(1) != PINNED_UV_VERSION and "setup-uv" in path.read_text(
                encoding="utf-8"
            ):
                mismatches.append(f"{rel}:{lineno} setup-uv version {m.group(1)}")

    assert not mismatches, (
        "uv version pins disagree across sites:\n  "
        + "\n  ".join(mismatches)
        + f"\nAll sites must pin {PINNED_UV_VERSION} (PR #488 convention). "
        "Bump every site in one commit, including this test's PINNED_UV_VERSION."
    )
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd C:/Projects/jmo-security-repo-uv-migration && uv run python -m pytest tests/unit/test_dep_audit_drift.py -v`

Expected: FAIL — `audit_deps.sh` does not exist; `test_both_call_sites_use_the_shared_script` fails because `ci.yml` still has `pip-audit -r requirements-dev.txt`.

- [ ] **Step 3: Write `scripts/dev/audit_deps.sh`**

```bash
#!/usr/bin/env bash
# Audit the project's locked dependencies for known CVEs (OSV database).
#
# Single implementation shared by .github/workflows/ci.yml and
# .pre-commit-config.yaml. Previously each inlined its own `pip-audit -r
# requirements-dev.txt` call, and their explanatory comments had already
# drifted apart. Keep it that way: one script, two callers.
#
# pip-audit needs a requirements file, and uv.lock is not one, so we export an
# ephemeral requirements.txt to a temp path. It is deliberately NOT committed —
# any tracked requirements*.txt is a file Dependabot would try to manage, which
# is the exact second-writer problem this migration removed.
#
# Ignored advisories (both unresolvable upstream — do not drop without reading):
#
#   PYSEC-2025-183 (CVE-2025-45768) "pyjwt weak encryption" — DISPUTED by the
#     maintainer ("key length is chosen by the application that uses the
#     library"). No fix version exists. pyjwt is a transitive dev-only dep via
#     `mcp`, not used in production paths.
#     https://api.osv.dev/v1/vulns/PYSEC-2025-183
#
#   GHSA-qp9x-wp8f-qgjj "tuf platform-dependent delegation path matching"
#     (CVSS 4.0 medium) — fixed in tuf 7.0.0 but NOT adoptable: tuf is a
#     transitive dev-only dep via `sigstore` (SLSA attestation), and every
#     sigstore release caps tuf<7.0.0. Drop this ignore once sigstore catches
#     up. Tracking: #539.
#     https://github.com/advisories/GHSA-qp9x-wp8f-qgjj
#
# Usage: scripts/dev/audit_deps.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

REQ_FILE="$(mktemp -t jmo-audit-XXXXXX.txt)"
trap 'rm -f "$REQ_FILE"' EXIT

# --frozen: audit the lock as committed. Lock freshness is a separate gate
#           (`uv lock --check`), so this never double-reports a stale lock.
# --no-emit-project: the project itself is not a PyPI dependency to audit.
# --no-hashes: pip-audit resolves names/versions; hashes add nothing here.
uv export \
  --frozen \
  --format requirements.txt \
  --no-emit-project \
  --no-hashes \
  --output-file "$REQ_FILE"

pip-audit -r "$REQ_FILE" --progress-spinner=off \
  --ignore-vuln PYSEC-2025-183 \
  --ignore-vuln GHSA-qp9x-wp8f-qgjj
```

Mark it executable so the git mode bit is right:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git update-index --add --chmod=+x scripts/dev/audit_deps.sh 2>/dev/null || chmod +x scripts/dev/audit_deps.sh
```

- [ ] **Step 4: Run the script and confirm it works end-to-end**

Run: `cd /c/Projects/jmo-security-repo-uv-migration && uv tool run pip-audit --version && bash scripts/dev/audit_deps.sh; echo "exit=$?"`

Expected: `exit=0`, with pip-audit reporting no non-ignored vulnerabilities. If pip-audit is not on PATH, install it into the tool env first: `uv tool install pip-audit`.

- [ ] **Step 5: Run the drift test to verify partial pass**

Run: `cd C:/Projects/jmo-security-repo-uv-migration && uv run python -m pytest tests/unit/test_dep_audit_drift.py -v`

Expected: `test_audit_script_exists_and_is_executable_shell` and `test_audit_script_preserves_both_ignores` PASS. `test_both_call_sites_use_the_shared_script` still FAILS (Tasks 5 and 7 wire up the callers). `test_single_pinned_uv_version_across_all_sites` PASSES (existing pins are already 0.11.15).

- [ ] **Step 6: Commit**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add scripts/dev/audit_deps.sh tests/unit/test_dep_audit_drift.py
git commit -m "feat(ci): add shared audit_deps.sh wrapper for pip-audit over uv.lock"
```

---

### Task 3: Makefile targets

**Files:**
- Modify: `Makefile:28-31` (help text), `Makefile:193-220` (targets), `Makefile:243-245` (`dev-setup`)

**Interfaces:**
- Produces: `make deps-sync`, `make deps-lock`, `make deps-upgrade` — the local developer surface referenced by CONTRIBUTING.md in Task 12.

- [ ] **Step 1: Replace the help lines**

In the `help:` block, replace these four lines (`Makefile:28-31`):

```make
	@echo "  deps-compile - Use uv to compile requirements-dev.in -> requirements-dev.txt (universal, all platforms)"
	@echo "  deps-sync    - Use uv to sync the environment to requirements-dev.txt"
	@echo "  deps-refresh - Recompile + sync dev deps (uv)"
	@echo "  deps-validate - Validate requirements-dev.txt Python version and conflicts"
	@echo "  deps-upgrade  - Upgrade all dependencies to latest versions (use with caution)"
	@echo "  deps-check-outdated - Check for outdated packages"
```

with:

```make
	@echo "  deps-sync    - Install/refresh the dev environment from uv.lock (uv sync)"
	@echo "  deps-lock    - Regenerate uv.lock from pyproject.toml (uv lock)"
	@echo "  deps-upgrade - Upgrade all locked deps to latest compatible (uv lock --upgrade)"
```

Also update the `dev-deps` help line (`Makefile:26`) from `"  dev-deps  - Install Python dev dependencies"` — keep the text, the target's body changes below.

- [ ] **Step 2: Replace the targets**

Replace `Makefile:193-220` (from `dev-deps:` through the end of `deps-check-outdated:`) with:

```make
dev-deps: deps-sync

upgrade-pip:
	$(PY) -m pip install -U pip setuptools wheel

# Local dev uses plain `uv sync` (not --locked) on purpose: it refreshes a stale
# lock automatically and the change shows up in `git diff`. CI and pre-commit use
# the strict form (`uv sync --locked` / `uv lock --check`) so a stale lock can
# never merge. A local hard-fail would add a manual step protecting nothing the
# CI gate does not already cover.
deps-sync:
	@command -v uv >/dev/null 2>&1 || $(PY) -m pip install uv==0.11.15  # pinned (PR #488)
	uv sync --group dev

deps-lock:
	@command -v uv >/dev/null 2>&1 || $(PY) -m pip install uv==0.11.15  # pinned (PR #488)
	uv lock

deps-upgrade:
	@echo "WARNING: This will upgrade ALL locked dependencies to latest compatible versions"
	@echo "Press Ctrl+C to cancel, or Enter to continue..."
	@read dummy
	@command -v uv >/dev/null 2>&1 || $(PY) -m pip install uv==0.11.15  # pinned (PR #488)
	uv lock --upgrade
```

Note `deps-refresh`, `deps-validate`, and `deps-check-outdated` are gone: `deps-refresh` was `compile + sync` and `uv sync` does both; the other two were wrappers around `update_dependencies.py`, deleted in Task 6.

- [ ] **Step 3: Replace `dev-setup`**

Replace `Makefile:241-245`:

```make
# Convenience target: install dev deps and the package in editable mode so
# `from scripts...` imports work without tweaking PYTHONPATH.
dev-setup:
	$(PY) -m pip install -r requirements-dev.txt
	$(PY) -m pip install -e .
```

with:

```make
# Convenience target: `uv sync` installs the dev group AND the project itself in
# editable mode, so `from scripts...` imports work without tweaking PYTHONPATH.
dev-setup: deps-sync
```

- [ ] **Step 4: Verify the targets run**

Run: `cd /c/Projects/jmo-security-repo-uv-migration && make deps-lock && make deps-sync && git diff --stat uv.lock`

Expected: both targets succeed. `git diff --stat uv.lock` shows no change (the lock from Task 1 is already current) — proving `deps-lock` is idempotent.

- [ ] **Step 5: Commit**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add Makefile
git commit -m "refactor(make): replace deps-compile targets with uv sync/lock/upgrade"
```

---

### Task 4: Local developer hooks — pre-push and devcontainer

**Files:**
- Modify: `hooks/pre-push:39-52`
- Modify: `.devcontainer/devcontainer.json:5`

**Interfaces:**
- Consumes: `make deps-sync` from Task 3.

- [ ] **Step 1: Delete the stale pre-push check**

`hooks/pre-push` has a check that warns when `requirements-dev.in` changed without `requirements-dev.txt`. Both files are gone, so it can never fire. Delete lines 39–52 in their entirety:

```bash
# 3. Verify requirements-dev.txt is in sync (if requirements-dev.in was modified)
if git diff --name-only @{u} HEAD 2>/dev/null | grep -q "requirements-dev.in"; then
  echo "  Checking requirements-dev.txt is in sync..."
  if ! git diff --name-only @{u} HEAD 2>/dev/null | grep -q "requirements-dev.txt"; then
    echo "WARNING: requirements-dev.in modified but requirements-dev.txt not updated"
    echo "Fix: Run 'make deps-compile' and commit requirements-dev.txt"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      exit 1
    fi
  fi
fi
```

No replacement is needed — the `uv-lock` pre-commit hook (Task 5) enforces lock freshness at commit time, which is strictly earlier and non-interactive.

- [ ] **Step 2: Update the devcontainer**

In `.devcontainer/devcontainer.json:5`, the `postCreateCommand` begins with `pip install -r requirements-dev.txt || true && bash -lc '...`. Replace only that leading segment so the rest of the command (the security-tool installs) is untouched:

- Before: `"postCreateCommand": "pip install -r requirements-dev.txt || true && bash -lc 'set -euo pipefail; apt-get update ...`
- After: `"postCreateCommand": "pip install uv==0.11.15 && uv sync --group dev || true && bash -lc 'set -euo pipefail; apt-get update ...`

The `uv==0.11.15` pin matches every other site (PR #488 convention) and is asserted by `test_single_pinned_uv_version_across_all_sites` from Task 2.

- [ ] **Step 3: Verify JSON validity**

Run: `cd /c/Projects/jmo-security-repo-uv-migration && uv run python -c "import json,pathlib; d=json.loads(pathlib.Path('.devcontainer/devcontainer.json').read_text()); print(d['postCreateCommand'][:80])"`

Expected: prints `pip install uv==0.11.15 && uv sync --group dev || true && bash -lc 'set -euo p` — valid JSON, correct prefix.

- [ ] **Step 4: Commit**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add hooks/pre-push .devcontainer/devcontainer.json
git commit -m "chore(dev): point pre-push and devcontainer at uv.lock workflow"
```

---

### Task 5: Pre-commit hooks

**Files:**
- Modify: `.pre-commit-config.yaml:134-153` (the `deps-compile` hook)
- Modify: `.pre-commit-config.yaml:155-174` (the `pip-audit` hook)

**Interfaces:**
- Consumes: `scripts/dev/audit_deps.sh` (Task 2), `uv.lock` (Task 1).

- [ ] **Step 1: Replace the `deps-compile` hook with a `uv-lock` hook**

Replace `.pre-commit-config.yaml:134-153` in full:

```yaml
  # Local hook: keep uv.lock consistent with pyproject.toml.
  #
  # This is a LOCAL hook rather than astral-sh/uv-pre-commit on purpose:
  # maintenance.yml runs `pre-commit autoupdate` weekly, which would bump a
  # third-party hook's rev independently of the uv version pinned at every other
  # site — reintroducing exactly the resolver-divergence this migration removed.
  - repo: local
    hooks:
      - id: uv-lock
        name: uv-lock (uv.lock matches pyproject.toml)
        language: system
        files: ^(pyproject\.toml|uv\.lock)$
        pass_filenames: false
        # Strategy: prefer `python`, fall back to `python3`, verify it is a real
        # interpreter (Windows ships a stub `python` that exits non-zero).
        entry: >-
          bash -c 'PY=""; for p in python python3; do
            if command -v "$p" >/dev/null 2>&1 && "$p" --version >/dev/null 2>&1; then PY="$p"; break; fi;
          done;
          [ -z "$PY" ] && { echo "ERROR: Python not found"; exit 1; };
          command -v uv >/dev/null 2>&1 || $PY -m pip install --quiet uv==0.11.15;
          uv lock --check ||
          { echo "ERROR: uv.lock is out of date with pyproject.toml. Run: make deps-lock"; exit 1; }'
```

- [ ] **Step 2: Replace the `pip-audit` hook**

Replace `.pre-commit-config.yaml:155-174` in full:

```yaml
  # Local hook: scan the locked dependency set for CVEs via pip-audit (OSV).
  # Mirrors CI's audit step by calling the same script, so a CVE-introducing dep
  # bump fails locally before it reaches CI. (The 2026-04-15 Dependabot triage
  # session hit 4 CVE cascades mid-flight; catching at commit time prevents that.)
  # Only runs when the dependency declaration or the lock changes.
  - repo: local
    hooks:
      - id: pip-audit
        name: pip-audit (CVE scan of uv.lock)
        language: python
        additional_dependencies: ["pip-audit>=2.9"]
        entry: bash scripts/dev/audit_deps.sh
        pass_filenames: false
        files: ^(pyproject\.toml|uv\.lock)$
```

The two `--ignore-vuln` flags now live once, in `audit_deps.sh`, with their full reasoning. `tests/unit/test_dep_audit_drift.py` asserts they survive.

- [ ] **Step 3: Verify both hooks run**

Run:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
uv run pre-commit run uv-lock --all-files
uv run pre-commit run pip-audit --all-files
```

Expected: both report `Passed`. If `pre-commit` is not yet available, `uv sync --group dev` first (it is in the dev group).

If `pre-commit` refuses to install hooks because `core.hooksPath` is set, unsetting a repo-local `core.hooksPath` that already points at `.git/hooks` is explicitly permitted by CLAUDE.md's Git Configuration guardrail. Do not change any other git config.

- [ ] **Step 4: Confirm the drift test's call-site assertion advances**

Run: `cd C:/Projects/jmo-security-repo-uv-migration && uv run python -m pytest tests/unit/test_dep_audit_drift.py -v`

Expected: still FAILS on `test_both_call_sites_use_the_shared_script`, because `ci.yml` is not updated until Task 7. The failure message should now name only `ci.yml`, not `.pre-commit-config.yaml` — confirming this task's half landed.

- [ ] **Step 5: Commit**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add .pre-commit-config.yaml
git commit -m "ci(pre-commit): replace deps-compile hook with uv lock --check"
```

---

### Task 6: Delete the dual-writer files

**Files:**
- Delete: `requirements-dev.in`, `requirements-dev.txt`, `scripts/dev/update_dependencies.py`

**Interfaces:**
- Consumes: nothing. All callers were removed in Tasks 3–5, except `ci.yml`'s `--validate` step, which Task 7 removes.

- [ ] **Step 1: Confirm there are no remaining functional callers**

Run:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git grep -n "update_dependencies" -- ':!CHANGELOG.md' ':!docs/' ':!.claude/'
```

Expected: exactly one hit — `.github/workflows/ci.yml:68`. Documentation hits are handled in PR 2. If any *other* functional file appears, stop and resolve it before deleting.

- [ ] **Step 2: Delete the three files**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git rm requirements-dev.in requirements-dev.txt scripts/dev/update_dependencies.py
```

- [ ] **Step 3: Run the platform-coverage test to verify it now fully passes**

Run: `cd C:/Projects/jmo-security-repo-uv-migration && uv run python -m pytest tests/unit/test_uv_lock_platform_coverage.py -v`

Expected: all four tests PASS, including `test_requirements_dev_files_are_gone`, which was the intentionally-red one from Task 1.

- [ ] **Step 4: Commit**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git commit -m "refactor(deps): delete requirements-dev.in/.txt and update_dependencies.py"
```

---

### Task 7: `ci.yml`

**Files:**
- Modify: `.github/workflows/ci.yml:65-68` (delete the `--validate` step), `:70-89` (replace the freshness gate), `:91-116` (pip-audit), `:155-159` (lint preview install), `:273-300` (test-sharded install), `:792-806` (tool-contract-tests install)

**Interfaces:**
- Consumes: `scripts/dev/audit_deps.sh` (Task 2), `uv.lock` (Task 1).

- [ ] **Step 1: Replace the two gate steps with one lock check**

Delete both the `Validate requirements-dev.txt Python version` step (`ci.yml:65-68`) and the `Check deps-compile freshness` step (`:70-89`) in full, and insert this single step in their place:

```yaml
      - name: Check uv.lock freshness
        # Semantic check: "is uv.lock consistent with pyproject.toml?" This runs
        # UNCONDITIONALLY, unlike the deps-compile byte-diff gate it replaces.
        # That gate had to be scoped to non-Dependabot pull_request events because
        # Dependabot's pip resolver emitted a structurally different file than
        # `uv pip compile` — so the gate could not be trusted on push or on bot
        # PRs, and main routinely sat in a format that failed the next human PR.
        # With the uv ecosystem, Dependabot regenerates uv.lock *with uv*, so bot
        # and human PRs are resolver-symmetric and pass the identical gate.
        # History: PR #321, #323, #677, #682.
        uses: astral-sh/setup-uv@v9.0.0
        with:
          version: "0.11.15"  # pinned: single uv version across all sites (PR #488)
          enable-cache: true
          cache-dependency-glob: "uv.lock"

      - name: Verify uv.lock is up to date
        run: uv lock --check
```

- [ ] **Step 2: Replace the pip-audit step**

Replace `ci.yml:91-116` (the whole `Audit Python dependencies for vulnerabilities` step, including its long comment block) with:

```yaml
      - name: Audit Python dependencies for vulnerabilities
        # Ignored advisories and their reasoning live in the script — one place,
        # two callers (this job and the pip-audit pre-commit hook).
        run: |
          pip install pip-audit
          bash scripts/dev/audit_deps.sh
```

The `|| { echo "::warning::..."; exit 1; }` wrapper is dropped: it printed a warning annotation and then failed anyway, so the annotation added noise without changing the outcome. `set -e` in the script plus the default `bash -e` step shell already fail the job.

- [ ] **Step 3: Replace the `Lint Preview` install lines**

In the `Lint Preview (subset of lint-full)` step (`ci.yml:155-174`), replace the first two install lines:

```yaml
          # Install lint dependencies
          python -m pip install --upgrade 'pip<25.3'
          pip install -r requirements-dev.txt
```

with:

```yaml
          # Lint deps come from the uv-synced venv (already on PATH).
```

and insert the canonical install block (see "Reference: the canonical CI install block") immediately *before* this step. Since `quick-checks` already has a `setup-uv` step from Step 1, only these two steps are needed there:

```yaml
      - name: Install dependencies
        run: uv sync --locked --group dev

      - name: Put the project venv on PATH
        shell: bash
        run: |
          if [ -d .venv/Scripts ]; then
            echo "$PWD/.venv/Scripts" >> "$GITHUB_PATH"
          else
            echo "$PWD/.venv/bin" >> "$GITHUB_PATH"
          fi
```

Place them right after the `Verify uv.lock is up to date` step so every later step in `quick-checks` (mypy, ruff, the SARIF validator's `jsonschema`/`requests` imports) resolves from the synced venv. The separate `pip install jsonschema requests` in the `Validate SARIF schema` step (`ci.yml:181`) can stay — it is harmless and outside this migration's scope.

- [ ] **Step 4: Replace the `test-sharded` install**

Replace both the `Set up Python 3.12` step (`ci.yml:273-278`) and the `Install dependencies (with retry)` step (`:280-300`) with the canonical block. The retry loop goes away — uv's own network retries plus the cache make the 3-attempt pip loop obsolete, and `uv sync` is a single atomic operation rather than two independent `pip install` calls.

```yaml
      - name: Set up uv
        uses: astral-sh/setup-uv@v9.0.0
        with:
          version: "0.11.15"  # pinned: single uv version across all sites (PR #488)
          python-version: '3.12'  # preserves the pin actions/setup-python held
          enable-cache: true
          cache-dependency-glob: "uv.lock"

      - name: Install dependencies
        run: uv sync --locked --group dev

      - name: Put the project venv on PATH
        shell: bash
        # Windows runners use .venv/Scripts, POSIX .venv/bin. This matrix has all three OSes.
        run: |
          if [ -d .venv/Scripts ]; then
            echo "$PWD/.venv/Scripts" >> "$GITHUB_PATH"
          else
            echo "$PWD/.venv/bin" >> "$GITHUB_PATH"
          fi
```

The job's existing `defaults: run: shell: bash` (`ci.yml:242-244`) means the later `python -m pytest` invocations keep working unchanged on all three OSes.

- [ ] **Step 5: Replace the `tool-contract-tests` install**

Replace the `Set up Python 3.12` step (`ci.yml:792-798`) and the `Install JMo Security and test dependencies` step (`:800-805`) with the canonical block, preserving the existing `if: steps.changes.outputs.versions == 'true'` condition on each of the three new steps.

- [ ] **Step 6: Validate the workflow syntax**

Run:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
uv run pre-commit run actionlint --all-files
uv run pre-commit run yamllint --all-files
```

Expected: both `Passed`. actionlint catches malformed `uses:`/`with:` blocks and shell issues; yamllint enforces the 140-char line limit (the `cache-dependency-glob` lines are well under).

- [ ] **Step 7: Run the drift test — now fully green**

Run: `cd C:/Projects/jmo-security-repo-uv-migration && uv run python -m pytest tests/unit/test_dep_audit_drift.py -v`

Expected: all four tests PASS. `test_both_call_sites_use_the_shared_script` now finds `scripts/dev/audit_deps.sh` in both `ci.yml` and `.pre-commit-config.yaml`, and no `pip-audit -r requirements-dev.txt` anywhere.

- [ ] **Step 8: Commit**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add .github/workflows/ci.yml
git commit -m "ci: migrate ci.yml to uv sync and replace deps-compile gate with uv lock --check"
```

---

### Task 8: `scheduled.yml` and the composite action

**Files:**
- Modify: `.github/workflows/scheduled.yml` — 10 install sites at lines ~64-75, ~245-256, ~290-301, ~387-398, ~513-519, ~568-579, ~686-697, ~787-798, ~843-854, ~927-938, ~1120-1130; plus the `SKIP:` list at `:546`
- Modify: `.github/actions/setup-python-jmo/action.yml` (all 33 lines)

**Interfaces:**
- Consumes: `uv.lock` (Task 1). The composite action is used by `scheduled.yml:1026` (`e2e-visual`).

- [ ] **Step 1: Rewrite the composite action**

Replace `.github/actions/setup-python-jmo/action.yml` in full:

```yaml
name: 'Setup Python for JMo'
description: 'Install the JMo Security dev environment from uv.lock'

inputs:
  python-version:
    description: 'Python version for uv to provision'
    required: false
    default: '3.12'
  cache-dependency-glob:
    description: 'Glob controlling the uv cache key'
    required: false
    default: 'uv.lock'
  install-dev-deps:
    description: 'Whether to install development dependencies'
    required: false
    default: 'true'

runs:
  using: composite
  steps:
    - name: Set up uv
      uses: astral-sh/setup-uv@v9.0.0
      with:
        version: "0.11.15"  # pinned: single uv version across all sites (PR #488)
        python-version: ${{ inputs.python-version }}
        enable-cache: true
        cache-dependency-glob: ${{ inputs.cache-dependency-glob }}

    - name: Install dependencies
      if: inputs.install-dev-deps == 'true'
      shell: bash
      run: uv sync --locked --group dev

    - name: Put the project venv on PATH
      if: inputs.install-dev-deps == 'true'
      shell: bash
      run: |
        if [ -d .venv/Scripts ]; then
          echo "$PWD/.venv/Scripts" >> "$GITHUB_PATH"
        else
          echo "$PWD/.venv/bin" >> "$GITHUB_PATH"
        fi
```

The `cache-dependency-path` input is renamed to `cache-dependency-glob` to match setup-uv's vocabulary. Its only caller (`scheduled.yml:1026`) passes no inputs, so no call site changes.

- [ ] **Step 2: Replace all 11 install sites in `scheduled.yml`**

Each site is the same two-step pattern — an `actions/setup-python@v7` step with `cache: pip` / `cache-dependency-path: requirements-dev.txt`, followed by an `Install ...` step running some combination of `pip install --upgrade pip`, `pip install -e .`, and `pip install -r requirements-dev.txt`. Replace both steps at each site with the canonical block from the Reference section.

Sites, by job (line numbers are pre-edit; work bottom-up so earlier line numbers stay valid):

| Job | `name:` | Approx. lines |
|---|---|---|
| `nightly-extended-tests` | Nightly Extended Tests | 64–75 |
| `nightly-cross-platform` | Cross-Platform Tests | 245–256 |
| `nightly-security-regression` | Security Regression Tests | 290–301 |
| `tool-smoke-tests` | Tool Smoke Tests | 387–398 |
| `lint-full` | Lint (full pre-commit suite) | 513–519 |
| `integration-tests` | Integration Tests | 568–579 |
| `e2e-ubuntu` | E2E Ubuntu Tests | 686–697 |
| `e2e-macos` | E2E macOS Tests | 787–798 |
| `e2e-tool-integration` | E2E Tool Integration Tests | 843–854 |
| `tool-contract-tests` | Tool Output Contract Tests | 927–938 |
| `performance-benchmarks` | Performance Benchmarks | 1120–1130 |

Two per-site details:

- **`nightly-cross-platform`** (line 245) parameterizes Python via `python-version: ${{ matrix.python-version }}`. Preserve it by adding `python-version: ${{ matrix.python-version }}` to the `setup-uv` `with:` block.
- **`performance-benchmarks`** (line 1126) also runs `pip install psutil`, which is not in the dev group. Keep it as a follow-on step, changed to `uv pip install psutil` so it lands in the synced venv:

  ```yaml
      - name: Install benchmark-only extras
        run: uv pip install psutil
  ```

  `e2e-ubuntu` (line 697) additionally runs `jmo --help || echo "jmo CLI not available"` — keep that line; `uv sync` installs the project so `jmo` is now genuinely on PATH.

- [ ] **Step 3: Drop the stale `deps-compile` SKIP**

At `scheduled.yml:541-546`, the `lint-full` job's `env:` block has a 6-line comment explaining why `deps-compile` is skipped, ending in `SKIP: bandit,yamllint,deps-compile`. The hook no longer exists and the new `uv-lock` hook must NOT be skipped — it is the whole point that the check is now safe to run on `main`.

Replace the comment lines and the `SKIP` value:

```yaml
          # Skip bandit (already covered by make lint)
          # Skip yamllint to avoid validating external pre-commit cache files
          # NOTE: uv-lock is deliberately NOT skipped. Its predecessor
          # (deps-compile) had to be skipped on main because Dependabot's pip
          # resolver left requirements-dev.txt in a non-canonical format after
          # every bot merge. Dependabot now regenerates uv.lock with uv, so the
          # lock on main is canonical by construction and the check must run.
          SKIP: bandit,yamllint
```

- [ ] **Step 4: Validate**

Run:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
uv run pre-commit run actionlint --all-files
uv run pre-commit run yamllint --all-files
git grep -n "requirements-dev" -- .github/workflows/scheduled.yml .github/actions/
```

Expected: actionlint and yamllint `Passed`; the `git grep` returns **no output** (exit 1), proving all 20 references in `scheduled.yml` and both in the composite action are gone.

- [ ] **Step 5: Commit**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add .github/workflows/scheduled.yml .github/actions/setup-python-jmo/action.yml
git commit -m "ci: migrate scheduled.yml and setup-python-jmo composite action to uv sync"
```

---

### Task 9: `maintenance.yml` and `release.yml`

**Files:**
- Modify: `.github/workflows/maintenance.yml:174-185` (delete the self-heal recompile), `:198-199` (`git add`), `:215` (commit message), `:264` (PR body), `:572-585` (install site)
- Modify: `.github/workflows/release.yml:316-328` (install site), `:396-402` (build-backend job's cache config)

- [ ] **Step 1: Delete the self-heal recompile step**

Delete `maintenance.yml:174-185` in full — the `Recompile requirements-dev.txt with pinned uv (self-heal Dependabot drift)` step and its 9-line comment. There is nothing left to heal: Dependabot writes `uv.lock` with uv, so `main` is canonical by construction.

- [ ] **Step 2: Fix the `git add` and the two prose references**

At `maintenance.yml:198-199`, drop `requirements-dev.txt` from the staged paths:

```yaml
          git add versions.yaml Dockerfile.deep Dockerfile.balanced Dockerfile.slim Dockerfile.fast \
                 .pre-commit-config.yaml
```

At `maintenance.yml:214-216`, the commit-message body currently reads:

```text
          Automated weekly update of security tools, pre-commit hooks, and a
          canonical recompile of requirements-dev.txt (pinned uv 0.11.15) that
          clears any Dependabot-introduced lockfile drift.
```

Replace with:

```text
          Automated weekly update of security tools and pre-commit hooks.
```

At `maintenance.yml:264`, delete this line from the PR-body generator entirely:

```yaml
            echo "- **Python lockfile**: \`requirements-dev.txt\` recompiled with pinned \`uv 0.11.15\` to clear Dependabot-format drift"
```

Also remove the `Co-Authored-By: Claude <noreply@anthropic.com>` trailer at `maintenance.yml:218` if present in the block being edited — no AI-attribution markers (Global Constraints). Leave the surrounding heredoc structure intact.

- [ ] **Step 3: Replace the `maintenance.yml` install site**

Replace `maintenance.yml:575-585` (the `Set up Python 3.12` step and the `Install dependencies` step in the completeness-analysis job) with the canonical block.

- [ ] **Step 4: Replace the `release.yml` install site**

Replace `release.yml:317-328` (the `pre-release-check` job's `Set up Python 3.12` + `Install dependencies` steps) with the canonical block.

At `release.yml:397-402`, the `pypi-publish` job's `Set up Python 3.12` step carries `cache: pip` / `cache-dependency-path: requirements-dev.txt` but only installs `build` and `twine` — it does not need the dev environment at all. Keep `actions/setup-python@v7` there and delete only the two cache lines:

```yaml
      - name: Set up Python 3.12
        uses: actions/setup-python@v7
        with:
          python-version: '3.12'

      - name: Install build backend
        run: |
          python -m pip install --upgrade pip
          pip install build twine
```

This keeps the publish job's dependency surface minimal — deliberately *not* migrating it to uv, because it must build the distribution the same way PyPI consumers will.

- [ ] **Step 5: Validate and confirm zero functional references remain**

Run:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
uv run pre-commit run actionlint --all-files
uv run pre-commit run yamllint --all-files
git grep -n "requirements-dev\|deps-compile" -- .github/ Makefile hooks/ .pre-commit-config.yaml .devcontainer/ scripts/
```

Expected: lint `Passed`; the `git grep` returns **no output**. Every functional reference across CI, Make, hooks, pre-commit, devcontainer, and scripts is gone. Remaining references live only in docs (PR 2) and `CHANGELOG.md` (never edited).

- [ ] **Step 6: Commit**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add .github/workflows/maintenance.yml .github/workflows/release.yml
git commit -m "ci: drop deps self-heal from maintenance.yml and migrate release.yml install"
```

---

### Task 10: Dependabot ecosystem switch

**Files:**
- Modify: `.github/dependabot.yml:11-37`

- [ ] **Step 1: Switch the pip entry to uv**

Replace `.github/dependabot.yml:12-13`:

```yaml
  # Python dependencies (requirements-dev.txt via uv pip compile --universal)
  - package-ecosystem: "pip"
```

with:

```yaml
  # Python dependencies (pyproject.toml [dependency-groups] + uv.lock).
  # The `uv` ecosystem regenerates uv.lock WITH uv, so bot output is canonical
  # by construction — Dependabot and CI use the same resolver for the first time.
  # Under the old `pip` ecosystem, Dependabot rewrote the uv-generated
  # requirements-dev.txt with its own Linux-only pip resolver, which dropped
  # platform-conditional deps (pywin32 via mcp) and failed the next human PR's
  # freshness gate. See PRs #677, #682.
  - package-ecosystem: "uv"
```

Everything else in that entry is unchanged: `directory: "/"`, the weekly Monday 09:00 schedule, `open-pull-requests-limit: 5`, the `jimmy058910` reviewer, the `dependencies` + `python` labels, the `deps(python)` commit prefix, and the `python-minor-patch` group (minor/patch grouped, majors solo). Security updates work natively on the uv ecosystem (shipped 2025-12-16).

- [ ] **Step 2: Update the trailing note**

At `.github/dependabot.yml:118-124`, the "Important notes" block is still accurate; no change needed. Verify by reading it — it discusses binary tools, Docker-pinned security tools, and `update_versions.py`, none of which this migration touches.

- [ ] **Step 3: Validate**

Run: `cd /c/Projects/jmo-security-repo-uv-migration && uv run pre-commit run yamllint --files .github/dependabot.yml && uv run python -c "import yaml,pathlib; d=yaml.safe_load(pathlib.Path('.github/dependabot.yml').read_text()); print([u['package-ecosystem'] for u in d['updates']])"`

Expected: yamllint `Passed`, and the ecosystem list prints `['uv', 'docker', 'github-actions', 'npm', 'npm']`.

- [ ] **Step 4: Commit**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add .github/dependabot.yml
git commit -m "ci(deps): switch Dependabot from pip to the uv ecosystem"
```

---

### Task 11: Accuracy-critical doc lines, then open PR 1

**Files:**
- Modify: `CLAUDE.md:93`
- Modify: `CONTRIBUTING.md:22`

Only these two lines change in PR 1. Both are *commands a reader would run and that would now fail* — the rest of the documentation pass is PR 2.

- [ ] **Step 1: Update `CLAUDE.md`'s Development Setup**

At `CLAUDE.md:93`, replace:

```bash
pip install -e ".[dev]"                # Install in editable mode with dev deps
```

with:

```bash
uv sync --group dev                    # Install dev deps + project (editable) from uv.lock
```

- [ ] **Step 2: Update `CONTRIBUTING.md`'s setup block**

At `CONTRIBUTING.md:22`, make the identical replacement.

- [ ] **Step 3: Verify doc links still resolve**

Run: `cd /c/Projects/jmo-security-repo-uv-migration && uv run python scripts/dev/check_doc_links.py`

Expected: exit 0. This matters because `docs/internal/DEPENDENCY_MANAGEMENT.md` links to `scripts/dev/update_dependencies.py`, which Task 6 deleted. If the checker flags it, that link is in a file PR 2 rewrites — but `check_doc_links.py` only scans `CLAUDE.md` and `docs/index.md` (see `FILES_TO_CHECK` at `scripts/dev/check_doc_links.py:19-22`), so it should pass. If it fails on a link this migration broke, fix that link now rather than deferring.

- [ ] **Step 4: Run the full local verification gate**

Run:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
uv run pre-commit run --all-files
uv run python -m pytest tests/unit/test_uv_lock_platform_coverage.py tests/unit/test_dep_audit_drift.py -v
```

Expected: pre-commit all `Passed` (or files auto-fixed by black/ruff — re-stage and re-run until clean). Both new test modules fully green.

Do **not** run the full 8,000-test suite locally; CI shards it. Running it here on Windows will take far longer than the CI feedback loop.

- [ ] **Step 5: Commit and push**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add CLAUDE.md CONTRIBUTING.md docs/superpowers/plans/2026-07-28-uv-lock-migration.md
git commit -m "docs: point setup commands at uv sync --group dev"
git push -u origin feat/uv-lock-migration
```

- [ ] **Step 6: Open PR 1**

Write the PR body to the scratchpad first (never to `.git/` — in a worktree `.git` is a file):

```bash
BODY="$HOME/AppData/Local/Temp/claude/C--Projects-jmo-security-repo/58b23cf7-76b8-4158-89b1-5248c43f5320/scratchpad/pr1-body.md"
```

The body MUST contain these sections:

1. **What changed** — the four structural moves: single declaration in `[dependency-groups]`, tracked `uv.lock`, `uv sync` everywhere, Dependabot on the `uv` ecosystem.
2. **Why — the two defects it closes.** (a) deps-compile drift: `requirements-dev.txt` had two writers with different serializers; Dependabot's pip resolver rewrote it non-canonically and the next human PR failed a byte-equality gate with an unrelated-looking red (twice on 2026-07-28: PRs #677, #682, re-armed by #680). Not cosmetic — the pip resolve dropped `pywin32==312 ; sys_platform == 'win32'`, breaking `mcp` on Windows. (b) Dual declaration divergence: the `[dev]` extra had 19 packages, `requirements-dev.in` had 30; the documented `pip install -e ".[dev]"` produced a smaller env than CI used, which is how PR #361 shipped a broken scheduled job.
3. **Reversing the `.gitignore` decision — explicit, three points** (spec §1). The removed block claimed: (i) *"the canonical dev-dep lockfile is requirements-dev.txt (pip-tools)"* — factually stale, CI never used pip-tools; `ci.yml:88` and `Makefile:200-202` both ran `uv pip compile`. (ii) *"Tracking uv.lock duplicates resolution"* — true only while `requirements-dev.txt` remained canonical; this PR deletes it, so `uv.lock` is the only lockfile and nothing is duplicated. (iii) *"makes Dependabot emit uv-group PRs whose resolver diverges from the CI pip-tools resolver"* — now inverted: the divergence ran the *other* way (Dependabot's pip vs CI's uv), and adopting `uv.lock` makes them the same resolver for the first time.
4. **Verification evidence** — paste the literal output from Task 1 Step 5 proving `uv sync --group dev` installs `pywin32` on Windows.
5. **Scope note** — deletions include `scripts/dev/update_dependencies.py` (its two checks were artifacts of the generated file: a `uv pip compile` header-version check, and `pip check` conflict detection that only surfaced because flattening all dev deps into one requirements file exposes conflicts between tools that never share an environment). Docs pass follows in PR 2.

Then:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
gh pr create --base main --head feat/uv-lock-migration \
  --title "feat(deps): migrate dev deps to PEP 735 dependency-groups + tracked uv.lock" \
  --body-file "$BODY"
```

- [ ] **Step 7: Verify CI green — all five bar items**

Watch to completion: `gh pr checks --watch`

Required before merge (spec "Verification bar"):

- **(a)** Windows `uv sync --group dev` installs `pywin32` — done in Task 1 Step 5, evidence in the PR body.
- **(b)** Full CI green including **all 6 test shards**: `ubuntu-latest` ×4, `macos-latest`, `windows-2022`. Confirm each shard individually, not just the aggregate check. Note `windows-2022` carries `continue-on-error: true` (`ci.yml:346`) — read its actual log, do not accept a green tick as proof it passed.
- **(c)** pip-audit still fails on a real CVE. Prove it, then revert:
  ```bash
  cd /c/Projects/jmo-security-repo-uv-migration
  # Pin a known-vulnerable version, regenerate, confirm red, then revert.
  # Use a dep already in the graph so the resolve stays valid.
  uv add --group dev 'jinja2==3.1.2'   # GHSA-h5c8-rqwp-cp95 et al.
  bash scripts/dev/audit_deps.sh; echo "exit=$?"   # MUST be non-zero
  git checkout -- pyproject.toml uv.lock
  uv lock --check                                   # confirm clean revert
  ```
  Record the non-zero exit and the advisory pip-audit reported. Confirm the run did **not** report `PYSEC-2025-183` or `GHSA-qp9x-wp8f-qgjj` — proving both ignores still apply.
- **(d)** `quick-checks` passes on **both** the `push` and `pull_request` events for the same commit. `ci.yml` triggers on both, so pushing the branch produces two runs for one SHA. Verify both:
  ```bash
  gh run list --branch feat/uv-lock-migration --json databaseId,event,conclusion,headSha \
    --jq '.[] | select(.headSha=="'"$(git rev-parse HEAD)"'") | "\(.event) \(.conclusion)"'
  ```
  Expected: both `push success` and `pull_request success`. Event-scoped logic is the only thing that can differ for an identical commit — this exact diagnostic isolated the original bug, and the `uv lock --check` gate is now unconditional precisely so the two can no longer disagree.
- **(e)** Post-merge drift check — Task 14.

If any shard is red, use `superpowers:systematic-debugging` before changing anything. Do not adjust a threshold or add a skip to make a job green.

- [ ] **Step 8: Merge PR 1**

Use the `merge-pr` skill (squash-merge to `main`, then sync `dev` from `main`, then clean up branches). Do not merge manually — the skill encodes the project's PR-direct-to-main + squash + dev-mirrors-main policy.

---

## PR 2 — Documentation pass

Branch fresh from the updated `main` after PR 1 merges.

- [ ] **Setup: new branch off the merged main**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git fetch origin
git checkout -b docs/uv-lock-migration origin/main
```

### Task 12: Rewrite `docs/internal/DEPENDENCY_MANAGEMENT.md`

**Files:**
- Modify: `docs/internal/DEPENDENCY_MANAGEMENT.md` (597 lines, 33 refs — **rewrite**)

- [ ] **Step 1: Read the whole document first**

Run: `cd /c/Projects/jmo-security-repo-uv-migration && cat docs/internal/DEPENDENCY_MANAGEMENT.md`

This document is *about* the workflow being deleted. A find-replace produces prose describing a two-file compile step that no longer exists. Identify which sections describe (i) the mechanism (rewrite), (ii) policy that survives (keep), (iii) history (keep, marked as history).

- [ ] **Step 2: Rewrite**

Target structure — the surviving policy, re-grounded on uv:

- **Single source of truth.** `pyproject.toml` declares runtime deps in `[project] dependencies`, optional runtime extras in `[project.optional-dependencies]`, and dev deps in `[dependency-groups] dev` (PEP 735). `uv.lock` is generated, tracked, and universal.
- **Daily commands.** `make deps-sync` (install/refresh from the lock), `make deps-lock` (regenerate after editing `pyproject.toml`), `make deps-upgrade` (float everything to latest compatible).
- **Lock strictness is deliberately asymmetric.** Local `uv sync` refreshes a stale lock and surfaces the change in `git diff`; CI and pre-commit use `uv sync --locked` / `uv lock --check` and hard-fail. Explain why: a local hard-fail adds a manual step protecting nothing the CI gate does not already cover.
- **Security auditing.** `scripts/dev/audit_deps.sh` exports the lock to an ephemeral requirements file and runs pip-audit with two permanent ignores; document both and link issue #539. State explicitly that the exported file is never committed — a tracked `requirements*.txt` is a file Dependabot would try to manage, which is the second-writer problem this migration removed.
- **Dependabot.** Weekly Monday 09:00 on the `uv` ecosystem; minor/patch grouped as `python-minor-patch`, majors solo; security updates native. Note that bot PRs now pass the *same* freshness gate humans do.
- **History (keep, clearly marked).** A short section recording the `requirements-dev.in`/`.txt` + `deps-compile` era and why it was retired, so the CHANGELOG's references remain interpretable. Do not delete this — future readers hitting old PRs need the map.

Delete outright: every `update_dependencies.py` invocation (the script is gone), the Python-3.12-interpreter-hunting recipes that existed only because the compile step needed a specific interpreter, and the "diamond dependency conflicts" section (an artifact of flattening deps into one requirements file).

- [ ] **Step 3: Verify no stale references and links resolve**

Run:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git grep -n "requirements-dev\|deps-compile\|update_dependencies" -- docs/internal/DEPENDENCY_MANAGEMENT.md
uv run pre-commit run markdownlint-cli2 --files docs/internal/DEPENDENCY_MANAGEMENT.md
```

Expected: `git grep` output contains **only** lines inside the clearly-marked History section; markdownlint `Passed`. Any link to `scripts/dev/update_dependencies.py` must be gone (the file is deleted).

- [ ] **Step 4: Commit**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add docs/internal/DEPENDENCY_MANAGEMENT.md
git commit -m "docs(deps): rewrite DEPENDENCY_MANAGEMENT.md for the uv.lock workflow"
```

---

### Task 13: Remaining docs and the stale rules entry

**Files:**
- Modify: `docs/internal/PRE_COMMIT_HOOKS.md` (12 refs), `CONTRIBUTING.md` (13 remaining refs), `docs/RELEASE.md` (1), `docs/TROUBLESHOOTING.md` (1), `docs/VERSION_MANAGEMENT.md` (1), `TEST.md` (1), `.claude/rules/release.rules.md` (2)

- [ ] **Step 1: `docs/internal/PRE_COMMIT_HOOKS.md`**

Two hooks changed. Replace the `deps-compile` hook's section with the `uv-lock` hook (`uv lock --check`, triggers on `pyproject.toml` or `uv.lock`, fix is `make deps-lock`), and update the `pip-audit` section to say it calls `scripts/dev/audit_deps.sh` and triggers on the same two files. Delete the Python-3.12-interpreter troubleshooting recipe at line ~304 — it existed only for the compile step.

- [ ] **Step 2: `CONTRIBUTING.md`**

Rewrite the "Dependency management" section (`CONTRIBUTING.md:42-89`):

- `make dev-setup` / `make dev-deps` now both resolve to `uv sync --group dev`. Delete the claim that `requirements-dev.txt` "is intentionally lightweight" and the "Reproducible dev deps (uv)" subsection describing `make deps-compile`.
- Replace the CI note at line 89 — "Pull requests include an automated check that `requirements-dev.txt` matches `requirements-dev.in`" — with: PRs check that `uv.lock` is consistent with `pyproject.toml` (`uv lock --check`); if it fails, run `make deps-lock`, commit `uv.lock`, and push.
- Line 157: dev tooling is managed via `[dependency-groups] dev` and pre-commit; update via `pre-commit autoupdate` and `make deps-sync`.
- Lines 771 and 802-811: the "out-of-sync requirements files" troubleshooting entry and the "when modifying requirements-dev.in" recipe both become "when modifying `pyproject.toml` dependencies → `make deps-lock` → commit `uv.lock`".
- Lines 834, 856, 943-960: the CI-failure categories and the "Requirements Drift (deps-compile freshness)" troubleshooting section. Replace the latter with a `uv.lock` staleness entry: symptom `error: The lockfile at uv.lock needs to be updated`, fix `make deps-lock && git add uv.lock`. Delete the `grep "/home/" requirements-dev.txt` absolute-path check — `uv.lock` records no absolute paths.

- [ ] **Step 3: The four 1-ref files**

- `TEST.md`, `docs/VERSION_MANAGEMENT.md`, `docs/TROUBLESHOOTING.md`: replace the `pip install -r requirements-dev.txt` / `requirements-dev.txt` mention with `uv sync --group dev` / `uv.lock` as context requires.
- `docs/RELEASE.md:32`: delete the entire numbered item. It is a Windows recipe for making the `deps-compile` pre-commit hook work (venv with Python 3.12, `uv==0.11.15`, `PYTHONUTF8=1`, compile from the branch worktree). Every part of it is obsolete — the hook, the script that printed the cp1252-hostile `≥`, and the `# via` annotation drift are all gone. Renumber the surrounding list.

- [ ] **Step 4: `.claude/rules/release.rules.md`**

Two edits:

- **Line 37**, the "Scheduled job pattern" paragraph, currently mandates `pip install -r requirements-dev.txt` and `cache-dependency-path: requirements-dev.txt` for every `scheduled.yml` job running pytest. Replace with: every such job MUST use the `astral-sh/setup-uv@v9` + `uv sync --locked --group dev` + venv-on-PATH block (reference job: `e2e-tool-integration`). Omitting dev deps still causes `--json-report` to fail silently.
- **Line 93**, the `Dependabot PR fails deps-compile freshness` troubleshooting row. Per spec §6, replace it with a description of the *old* failure mode and how the migration removed it — do not simply delete it, because the CHANGELOG and old PRs still reference the symptom. Suggested replacement row:

  | Issue | Solution |
  |-------|----------|
  | `Dependabot PR fails deps-compile freshness` (historical — cannot recur) | **Removed by the uv.lock migration.** Until 2026-07-28, `requirements-dev.txt` was generated by `uv pip compile --universal` but *edited in place* by Dependabot's Linux-only pip resolver. The two serializers disagreed, so after every Dependabot merge `main` held a non-canonical lockfile and the next human PR failed a byte-equality gate with an unrelated-looking red (PRs #677, #682 on the same day; #680 re-armed it). Worse, the pip resolve dropped `pywin32 ; sys_platform == 'win32'` (via `mcp`), silently breaking Windows dev installs. Successive attempts to scope the gate (PR #321 authorship check, PR #323 branch-ref check, then a single event-scoped predicate) all treated the symptom. The fix was removing the second writer: dev deps now live only in `pyproject.toml`'s `[dependency-groups]`, `uv.lock` is the only lockfile, and Dependabot runs on the `uv` ecosystem so it regenerates the lock *with uv*. The gate is now `uv lock --check`, runs **unconditionally** on every event and author, and bot and human PRs are resolver-symmetric. If it fails: `make deps-lock && git add uv.lock`. |

- [ ] **Step 5: Verify the docs are clean**

Run:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git grep -n "requirements-dev\|deps-compile\|update_dependencies" -- ':!CHANGELOG.md' ':!docs/superpowers'
uv run pre-commit run --all-files
uv run python scripts/dev/check_doc_links.py
```

Expected: `git grep` returns only lines inside explicitly-marked historical sections (DEPENDENCY_MANAGEMENT.md's History section and release.rules.md's historical troubleshooting row). Everything else clean; pre-commit and the link checker pass.

- [ ] **Step 6: Commit, open PR 2, merge**

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git add -A
git commit -m "docs: complete uv.lock migration documentation pass"
git push -u origin docs/uv-lock-migration
```

PR 2 body: state that it is the documentation half of the migration landed in PR 1, list the files touched, and note that `DEPENDENCY_MANAGEMENT.md` was rewritten rather than find-replaced because it documented the deleted workflow end to end. Watch CI to green, then merge via the `merge-pr` skill.

---

## Post-merge

### Task 14: Local-only files, cleanup, and the drift verification

These are **not** in either PR (the paths are gitignored) but the spec calls them out explicitly: without them the CI-debugger skill keeps recommending a `make deps-compile` target that no longer exists.

**Files (all in the PRIMARY checkout `C:\Projects\jmo-security-repo` — file edits only, NO git operations):**
- `.claude/skills/jmo-ci-debugger/` (SKILL.md + its `references/`)
- `.claude/skills/jmo-systematic-debugging/references/jmo-common-failure-modes.md`
- `.claude/agents/dependency-analyzer.md`, `.claude/agents/release-readiness.md`, `.claude/agents/security-auditor.md`
- `.claude/known-issues.md`
- Delete: `.claude/HANDOFF-uv-lock-migration.md`

- [ ] **Step 1: Find every stale reference in the local-only files**

Run: `cd /c/Projects/jmo-security-repo && grep -rn "requirements-dev\|deps-compile\|update_dependencies" .claude/ 2>/dev/null`

- [ ] **Step 2: Update each hit**

Apply the same substitutions as the docs pass: `make deps-compile` → `make deps-lock`; `pip install -r requirements-dev.txt` → `uv sync --group dev`; the deps-compile freshness failure mode → the `uv lock --check` failure mode with fix `make deps-lock && git add uv.lock`. In `.claude/known-issues.md`, the "deps-compile Diamond Dependencies" entry should be marked resolved — the conflicts were an artifact of flattening all dev deps into one requirements file, and `uv.lock` resolves a real graph.

- [ ] **Step 3: Delete the handoff**

The migration is done; the handoff's open questions are all resolved and its blast-radius list is superseded by this plan (which corrected three entries).

```bash
rm /c/Projects/jmo-security-repo/.claude/HANDOFF-uv-lock-migration.md
```

- [ ] **Step 4: Verification bar item (e) — post-merge drift check**

Confirm a Dependabot-style change introduces no drift on `main`. Either wait for the Monday 09:00 run, or simulate it immediately:

```bash
cd /c/Projects/jmo-security-repo-uv-migration
git fetch origin && git checkout -B test/uv-drift-probe origin/main
uv lock --upgrade-package pytest      # a single-package bump, exactly what Dependabot emits
git diff --stat uv.lock               # should touch only pytest and its transitive pins
uv lock --check                       # MUST pass — this is the gate Dependabot's PR will face
git checkout -- uv.lock && git checkout main && git branch -D test/uv-drift-probe
```

Expected: `uv lock --check` passes on the bumped lock. That is the whole point — a bot-shaped change now satisfies the same gate a human change does, which the old byte-equality gate could never do.

When the real Dependabot PR appears, confirm it (i) is labeled `dependencies` + `python`, (ii) carries the `deps(python)` commit prefix, (iii) groups minor/patch under `python-minor-patch`, and (iv) shows `quick-checks` **green** rather than skipped.

- [ ] **Step 5: Save a memory entry**

Write `C:\Users\Jimmy\.claude\projects\C--Projects-jmo-security-repo\memory\uv-lock-migration-landed-2026-07-28.md` with frontmatter `type: project`, recording: the migration landed in two PRs; `requirements-dev.in`/`.txt`/`update_dependencies.py` are deleted and must not be resurrected; `uv.lock` is tracked and Dependabot runs on the `uv` ecosystem; the freshness gate is `uv lock --check` running unconditionally; `release.rules.md`'s drift troubleshooting entry was rewritten as a historical record. Link `[[weekly-maintenance-2026-07-27-formatter-reflow-and-nightly-pipaudit]]` and `[[ruff-unpinned-ruleset-ci-timebomb-2026-07-28]]`. Add the one-line pointer to `MEMORY.md`.

---

## Self-Review

**Spec coverage.** Every numbered section of the spec maps to a task: §1 single source of truth → Task 1; §2 CI install pattern (~20 sites) → Tasks 7, 8, 9 (composite action in Task 8); §3 gates replaced — `uv lock --check` → Task 7 Step 1, maintenance self-heal deleted → Task 9 Step 1, pip-audit rework → Tasks 2/5/7, `--validate` step retired → Task 7 Step 1 + Task 6 (the spec left this "decide in plan after reading the script"; decided: retire and delete the script, rationale in the File Structure table), Makefile targets → Task 3; §4 Dependabot → Task 10; §5 deletions → Tasks 1 (gitignore), 5 (hook), 6 (files); §6 PR split → Task 11 (PR 1 boundary), Tasks 12–13 (PR 2), Task 14 (local-only); §7 out of scope — Dockerfiles, npm/docker/actions Dependabot entries, and non-dev extras are untouched. All five verification-bar items are Task 11 Step 7 and Task 14 Step 4.

**Placeholder scan.** No "TBD", no "add appropriate error handling", no "similar to Task N". Every code step carries the literal content. The one place judgment is delegated — Task 12's rewrite — gives a target section structure and an explicit delete list rather than "rewrite it".

**Type consistency.** `[dependency-groups] dev` is named `dev` in Task 1 and referenced as `--group dev` in Tasks 3, 5, 7, 8, 9, 11. `scripts/dev/audit_deps.sh` has one spelling everywhere (Tasks 2, 5, 7, and the drift test's `AUDIT_SCRIPT`). `uv==0.11.15` / `version: "0.11.15"` is identical at all sites and is asserted by `test_single_pinned_uv_version_across_all_sites`, whose `PINNED_UV_VERSION` constant matches. Make targets `deps-sync` / `deps-lock` / `deps-upgrade` are defined in Task 3 and referenced by that exact spelling in Tasks 12, 13, and 14.
