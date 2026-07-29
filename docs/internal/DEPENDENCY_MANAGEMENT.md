# Dependency Management Guide

## Overview

JMo Security declares its dependencies in **one place** and locks them in **one file**:

| What | Where |
|------|-------|
| Runtime dependencies | `pyproject.toml` → `[project] dependencies` |
| Optional runtime extras | `pyproject.toml` → `[project.optional-dependencies]` (`reporting`, `email`, `mcp`, `attestation`, `visual`) |
| Development dependencies | `pyproject.toml` → `[dependency-groups] dev` (PEP 735) |
| The resolved lockfile | `uv.lock` — generated, tracked in git, **universal** |

`uv.lock` is universal by construction: it records every platform's wheels and every platform-conditional dependency edge in a single file. That is what makes a Windows, macOS and Linux install resolve from the same source of truth.

**Critical rule:** never hand-edit `uv.lock`, and never add a second dependency file. One declaration, one lock.

---

## Quick Reference

| Task | Command | When to Use |
|------|---------|-------------|
| **Install / refresh your environment** | `make deps-sync` | After pulling, after switching branches |
| **Regenerate the lock** | `make deps-lock` | After editing dependencies in `pyproject.toml` |
| **Upgrade everything** | `make deps-upgrade` | Deliberate refresh to latest compatible versions |
| **Audit for CVEs** | `bash scripts/dev/audit_deps.sh` | Runs automatically in CI and pre-commit |

`make deps-sync` installs the `dev` group **and** the project itself in editable mode, so `from scripts...` imports work with no `PYTHONPATH` fiddling. There is no separate `pip install -e .` step.

---

## Lock strictness is deliberately asymmetric

| Context | Command | Behavior on a stale lock |
|---------|---------|--------------------------|
| Local development | `uv sync` (via `make deps-sync`) | Refreshes the lock automatically; the change appears in `git diff` |
| CI | `uv sync --locked` | **Hard fail** |
| Pre-commit | `uv lock --check` (the `uv-lock` hook) | **Hard fail** |

This is intentional, not an oversight. A stale lock cannot merge — CI and pre-commit both block it. Making the *local* command hard-fail as well would only add a manual `make deps-lock` step that protects nothing the CI gate does not already cover, while interrupting the edit-test loop.

---

## Development Workflow

### Adding a dependency

```bash
# 1. Add it to the right table in pyproject.toml:
#      runtime      -> [project] dependencies
#      dev-only     -> [dependency-groups] dev
#      optional     -> [project.optional-dependencies] <extra>
#    Use a floor (>=1.0.0), not an exact pin, unless you can say why in a comment.

# 2. Regenerate the lock and install
make deps-lock
make deps-sync

# 3. Test
make test

# 4. Commit BOTH files -- the declaration and the lock
git add pyproject.toml uv.lock
git commit -m "deps: add new-package for [purpose]"
```

`uv add --group dev 'new-package>=1.0.0'` does steps 1 and 2 in one command if you prefer.

### Removing a dependency

Delete the line from `pyproject.toml`, then `make deps-lock && make deps-sync`. Transitive dependencies that nothing else needs drop out of the lock automatically, and `uv sync` uninstalls them from your environment. Commit `pyproject.toml` and `uv.lock` together.

### Upgrading one package

```bash
uv lock --upgrade-package pytest
git diff uv.lock          # review what moved
make deps-sync && make test
git add pyproject.toml uv.lock
```

### Upgrading everything

`make deps-upgrade` (prompts for confirmation) floats every dependency to the latest version compatible with the declared constraints. Review `git diff uv.lock`, run `make test` and `make lint`, then commit.

### Upper bounds: only to hold back a known-breaking major

Constraints are floors by default. The one deliberate cap today is `mcp[cli]>=1.0.0,<2`: mcp 2.0 replaces `httpx` with `httpx2` and drops `pydantic-settings` and `httpx-sse`, which changes what roughly a hundred tests collect and breaks `tests/integration/test_cli_scan_ci.py`. The cap holds the project on the 1.x line until that upgrade is done deliberately, with the test work attached. Dependabot will keep proposing it as an ungrouped major bump.

This matters generally, because **an unbounded declaration means the next from-scratch `uv lock` is an upgrade, not a translation.** The migration's first resolve moved 30 of 94 packages this way. If you ever regenerate the lock from nothing, diff the resulting package set against the previous one before assuming they are equivalent:

```bash
uv export --frozen --quiet --format requirements.txt --no-emit-project --no-hashes -o new.txt
# compare package names first, then versions for the shared names
```

---

## Security Auditing

[scripts/dev/audit_deps.sh](../../scripts/dev/audit_deps.sh) is the single implementation of the CVE scan, called by both `.github/workflows/ci.yml` and the `pip-audit` pre-commit hook. It exports the lock to a temporary requirements file and runs `pip-audit` against it.

**The exported file is never committed.** Any tracked `requirements*.txt` is a file Dependabot would try to manage, which recreates the second-writer problem described under *History* below.

The export is universal, so the audited set includes platform-conditional entries such as `pywin32==312 ; sys_platform == 'win32'` no matter which OS runs the audit. A Linux-only audit would silently skip Windows-only dependencies.

### The ignore policy

**An `--ignore-vuln` is only justified while there is nothing to adopt.** The moment a fix becomes reachable, the ignore stops protecting you and starts hiding a regression — so it must be removed, not kept "just in case".

One advisory is currently ignored, documented with full reasoning in the script's header:

| Advisory | Why it is ignored |
|----------|-------------------|
| `PYSEC-2025-183` | Disputed pyjwt "weak encryption" advisory. **No fix version exists**, so the ignore is the only available lever. The maintainer's position is that key length is the calling application's choice. Transitive dev-only via `mcp`. Not firing at pyjwt 2.13.0, but retained in case a future resolve lands on a covered version. |

**Retired — do not re-add:**

| Advisory | Why it was dropped |
|----------|--------------------|
| `GHSA-qp9x-wp8f-qgjj` | tuf delegation path matching. Adopted when every sigstore release capped `tuf<7`, making the fix unreachable. sigstore 4.5.0 lifted that cap and the lock now resolves **tuf 7.0.0** — the fixed version — so the ignore was masking regressions rather than papering over an unfixable finding. Removed 2026-07-29, closing [#539](https://github.com/jimmy058910/jmo-security-repo/issues/539). Verified: forcing `tuf<7` back into the lock makes pip-audit report it with fix version 7.0.0 available. |

`tests/unit/test_dep_audit_drift.py` enforces both directions — the unfixable ignore must survive refactors, and the retired one must not come back.

---

## CI Integration

### The freshness gate

```yaml
- name: Verify uv.lock is up to date
  run: uv lock --check
```

This runs in `quick-checks` on **every event and every author** — pushes, pull requests, manual dispatches, human and bot alike. If it fails:

```bash
make deps-lock
git add uv.lock
```

### The install pattern

Every CI job that needs the dev environment uses the same block:

```yaml
- name: Set up uv
  uses: astral-sh/setup-uv@v9.0.0
  with:
    version: "0.11.15"
    python-version: '3.12'
    enable-cache: true
    cache-dependency-glob: "uv.lock"

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

Two details that are easy to get wrong:

- **`python-version` is required.** Without it uv selects the newest interpreter satisfying `requires-python = ">=3.12"`, which silently moves CI off 3.12.
- **uv is pinned to a single version across every site** (the [PR #488](https://github.com/jimmy058910/jmo-security-repo/pull/488) convention). `tests/unit/test_dep_audit_drift.py` fails if any site disagrees. Bump every site in one commit.

### Dependabot

[.github/dependabot.yml](../../.github/dependabot.yml) runs the **`uv` ecosystem** weekly (Monday 09:00 UTC): it reads `[dependency-groups]` and regenerates `uv.lock` *with uv*. Minor and patch bumps are grouped into one `python-minor-patch` PR; majors arrive individually. Security updates are native.

Because Dependabot and CI now use the same resolver, bot PRs face the identical `uv lock --check` gate humans do. Review and test them like any other PR.

---

## Troubleshooting

### `The lockfile at uv.lock needs to be updated, but --check was provided`

The declaration in `pyproject.toml` and the lock disagree. Run `make deps-lock` and commit `uv.lock`.

### `uv sync --locked` fails in CI but works locally

Local `make deps-sync` uses plain `uv sync`, which silently refreshes a stale lock. Run `uv lock --check` locally to see what CI sees, then `make deps-lock` and commit the result.

### A dependency is missing on Windows or macOS

Check that `uv.lock` still carries the relevant platform markers and wheels. `tests/unit/test_uv_lock_platform_coverage.py` guards this. The usual cause is a `[tool.uv] environments` key narrowing the resolve — remove it and run `make deps-lock`. Note that `uv lock` has no `--python-platform` flag, so the lock cannot be narrowed from the command line.

### `uv: command not found`

Every Make target installs the pinned version if it is missing. To do it by hand: `python -m pip install uv==0.11.15`.

---

## Best Practices

### DO

- Declare dependencies in `pyproject.toml` and commit `uv.lock` alongside every change to them
- Use floors (`>=1.0.0`) rather than exact pins, and add a comment whenever you pin
- Review `git diff uv.lock` before committing an upgrade
- Run `make test` after any dependency change
- Bump the pinned uv version at every site in a single commit

### DON'T

- Don't hand-edit `uv.lock`
- Don't add a second dependency file — no `requirements*.txt`, no re-added `dev` extra
- Don't commit `pyproject.toml` dependency changes without the regenerated `uv.lock`
- Don't add `[tool.uv] environments` — it narrows the resolve and breaks cross-platform installs
- Don't blindly accept Dependabot PRs; review and test them

---

## History: the `requirements-dev` era (retired 2026-07-29)

Kept because `CHANGELOG.md` and older PRs still reference this workflow.

Until 2026-07-29 dev dependencies lived in `requirements-dev.in`, were compiled to `requirements-dev.txt` by `uv pip compile --universal`, and were installed with `pip install -r`. A `deps-compile` gate compared a fresh compile byte-for-byte against the committed file, and `scripts/dev/update_dependencies.py` wrapped the compile with Python-version and `pip check` validation.

Two defects ended it, both rooted in the same cause — **the generated file had two writers with different serializers**:

1. **Drift.** Dependabot ran on the `pip` ecosystem and edited `requirements-dev.txt` directly with its own Linux-only resolver. After every bot merge `main` held a non-canonical file, and the next human PR failed the byte-equality gate with an unrelated-looking red. This happened twice on 2026-07-28 alone (PRs #677 and #682, re-armed by #680). It was not cosmetic: the pip resolve dropped `pywin32==312 ; sys_platform == 'win32'` (transitive via `mcp`), so a fresh Windows install omitted `pywin32` and broke `mcp` — invisible on CI's Linux runners. Three attempts to scope the gate (#321, #323, and a later event-scoped predicate) all treated the symptom.
2. **Divergence.** Dev dependencies were declared twice — a 19-package `[project.optional-dependencies] dev` extra and a 30-package `requirements-dev.in`. The extra was a strict subset, so the documented `pip install -e ".[dev]"` produced a smaller environment than CI used. That is how PR #361 shipped a scheduled job broken by a missing `pytest-benchmark`.

Removing the second writer removed both. `update_dependencies.py` went with the file: its Python-version check read a `uv pip compile` header that no longer exists, and its `pip check` conflict detection only ever fired because flattening every dev dependency into one requirements file puts tools together that never share a Python environment (checkov, prowler and semgrep all run in isolated venvs at runtime). `uv.lock` resolves a real dependency graph, so those conflicts cannot arise.

---

## References

- **Audit script:** [scripts/dev/audit_deps.sh](../../scripts/dev/audit_deps.sh)
- **CI workflow:** [.github/workflows/ci.yml](../../.github/workflows/ci.yml)
- **Dependabot config:** [.github/dependabot.yml](../../.github/dependabot.yml)
- **Pre-commit hooks:** [.pre-commit-config.yaml](../../.pre-commit-config.yaml), documented in [PRE_COMMIT_HOOKS.md](PRE_COMMIT_HOOKS.md)
- **Drift guards:** `tests/unit/test_uv_lock_platform_coverage.py`, `tests/unit/test_dep_audit_drift.py`
- **PEP 735 (dependency groups):** <https://peps.python.org/pep-0735/>
- **uv documentation:** <https://docs.astral.sh/uv/>
