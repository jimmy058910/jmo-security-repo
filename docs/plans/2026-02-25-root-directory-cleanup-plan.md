# Root Directory Cleanup Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce root from 49 to 40 tracked files for open-source release readiness.

**Architecture:** Surgical cleanup in 6 independent tasks: delete dead files, move misplaced files, consolidate configs into pyproject.toml, update references, clean local disk. Each task is independently committable.

**Tech Stack:** git, pyproject.toml (TOML), pre-commit, Makefile, GitHub Actions YAML

**Design doc:** `docs/plans/2026-02-25-root-directory-cleanup-design.md`

---

### Task 1: Delete tracked dead files (7 files)

**Files:**
- Delete: `Dockerfile.bare`
- Delete: `docker-entrypoint.sh`
- Delete: `jmo-scan.sh` (already staged)
- Delete: `custom-scan.sh`
- Delete: `package.json`
- Delete: `package-lock.json`
- Delete: `.markdownlint.json`

**Step 1: Remove files from git tracking**

```bash
git rm Dockerfile.bare docker-entrypoint.sh custom-scan.sh package.json package-lock.json .markdownlint.json
```

Note: `jmo-scan.sh` is already staged for deletion. Verify with `git status`.

**Step 2: Verify no breakage**

```bash
make lint
```

Expected: PASS (none of these files are referenced by linting tools)

**Step 3: Commit**

```bash
git add -A
git commit -m "chore: remove 7 unused root files (Dockerfile.bare, docker-entrypoint.sh, jmo-scan.sh, custom-scan.sh, package.json, package-lock.json, .markdownlint.json)"
```

---

### Task 2: Move AGENTS.md and mkdocs.yml

**Files:**
- Move: `AGENTS.md` -> `dev-only/AGENTS.md`
- Move: `mkdocs.yml` -> `docs/mkdocs.yml`
- Modify: `.readthedocs.yaml:8`

**Step 1: Move files**

```bash
git mv AGENTS.md dev-only/AGENTS.md
git mv mkdocs.yml docs/mkdocs.yml
```

**Step 2: Update .readthedocs.yaml**

In `.readthedocs.yaml`, change line 8 from:
```yaml
  configuration: mkdocs.yml
```
to:
```yaml
  configuration: docs/mkdocs.yml
```

**Step 3: Verify mkdocs.yml paths still resolve**

Open `docs/mkdocs.yml` and verify `docs_dir` setting. Since mkdocs.yml is now inside `docs/`, the relative `docs_dir` path may need adjustment. Check if the nav entries like `index.md`, `USER_GUIDE.md` resolve correctly from the new location. If mkdocs.yml has no explicit `docs_dir`, the default is `docs/` relative to the config file location -- which would become `docs/docs/`. If so, add:
```yaml
docs_dir: .
```
to `docs/mkdocs.yml` so it looks in `docs/` itself.

**Step 4: Commit**

```bash
git add -A
git commit -m "chore: move AGENTS.md to dev-only/, mkdocs.yml to docs/"
```

---

### Task 3: Consolidate .coveragerc into pyproject.toml

**Files:**
- Modify: `pyproject.toml:160-173` (existing `[tool.coverage.*]` sections)
- Delete: `.coveragerc`

**Step 1: Replace pyproject.toml coverage sections**

Replace the existing `[tool.coverage.run]` section (lines 160-164) with the merged config:

```toml
[tool.coverage.run]
branch = true
source = ["scripts"]
omit = [
    # Data-only files with no executable logic
    "scripts/core/compliance_frameworks.py",
    # CLI entry points (tested via integration tests)
    "scripts/cli/jmo.py",
    "scripts/cli/jmotools.py",
    "scripts/cli/clone_from_tsv.py",
    # Dashboard generator (standalone HTML builder)
    "scripts/core/generate_dashboard.py",
    # MCP server - separate integration
    "scripts/jmo_mcp/*",
    # Email service requires SMTP infrastructure
    "scripts/core/email_service.py",
    # Interactive wizard - difficult to test comprehensively
    "scripts/cli/wizard.py",
    "scripts/cli/wizard_flows/policy_flow.py",
    # Experimental policy engine
    "scripts/core/policy_engine.py",
    # Path sanitizers utility
    "scripts/cli/path_sanitizers.py",
]
```

Replace the existing `[tool.coverage.report]` section (lines 166-173) with the merged config:

```toml
[tool.coverage.report]
show_missing = true
skip_empty = true
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "if TYPE_CHECKING:",
    "raise AssertionError",
    "raise NotImplementedError",
    "^if __name__ == ['\"]__main__['\"]:",
]
omit = [
    "scripts/cli/jmo.py",
    "scripts/cli/jmotools.py",
    "scripts/cli/clone_from_tsv.py",
    "scripts/core/generate_dashboard.py",
    "scripts/jmo_mcp/*",
    "scripts/core/email_service.py",
    "scripts/cli/wizard.py",
    "scripts/cli/wizard_flows/policy_flow.py",
    "scripts/core/policy_engine.py",
    "scripts/cli/path_sanitizers.py",
]
```

**Step 2: Delete .coveragerc**

```bash
git rm .coveragerc
```

**Step 3: Verify coverage still works**

```bash
pytest tests/unit/test_constants.py --cov=scripts --cov-report=term-missing -q
```

Expected: PASS with coverage report showing `scripts` as source, omitted files excluded.

**Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "refactor: consolidate .coveragerc into pyproject.toml [tool.coverage]"
```

---

### Task 4: Consolidate bandit.yaml into pyproject.toml

**Files:**
- Modify: `pyproject.toml` (add new `[tool.bandit]` section after `[tool.ruff]`)
- Delete: `bandit.yaml`
- Modify: `.pre-commit-config.yaml:96`
- Modify: `Makefile:106-108`
- Modify: `.github/workflows/scheduled-tests.yml:95`

**Step 1: Add [tool.bandit] to pyproject.toml**

Add after the `[tool.ruff]` section (after line 177):

```toml
[tool.bandit]
exclude_dirs = [
    ".venv",
    ".venv-pypi",
    ".post-release-venv",
    "venv",
    "docs",
    "samples",
    "assets",
    "archive",
    "tests",
    "dev",
]
skips = [
    "B404",  # import subprocess - expected in CLI wrappers
    "B603",  # subprocess without shell=True is SECURE (list args)
    "B606",  # os.startfile - guarded and platform-specific
    "B607",  # start_process_with_partial_path - well-known tools
    "B110",  # try_except_pass - intentional for cleanup/optional ops
    "B112",  # try_except_continue - intentional for parsing resilience
    "B608",  # SQL injection false positives - parameterized queries
    "B101",  # assert_used - acceptable in dev scripts
    "B202",  # tarfile extractall - official tool downloads from trusted sources
    "B324",  # MD5 for dedup fingerprinting, not security
]
```

**Step 2: Update .pre-commit-config.yaml**

Change the bandit hook args from:
```yaml
        args: ["-q", "-r", "scripts", "-c", "bandit.yaml", "--format", "json"]
```
to:
```yaml
        args: ["-q", "-r", "scripts", "--format", "json"]
```

(Remove `-c`, `bandit.yaml` from args. Bandit auto-discovers `[tool.bandit]` in pyproject.toml.)

**Step 3: Update Makefile**

Change line 108 from:
```makefile
		bandit -q -r scripts -c bandit.yaml || true ; \
```
to:
```makefile
		bandit -q -r scripts || true ; \
```

**Step 4: Update scheduled-tests.yml**

Change line 95 from:
```yaml
          bandit -r scripts/ -c bandit.yaml
```
to:
```yaml
          bandit -r scripts/
```

**Step 5: Delete bandit.yaml**

```bash
git rm bandit.yaml
```

**Step 6: Verify bandit still reads config**

```bash
bandit -q -r scripts 2>&1 | head -5
```

Expected: No errors. Bandit should silently pick up `[tool.bandit]` from pyproject.toml and apply the same skips.

**Step 7: Commit**

```bash
git add pyproject.toml .pre-commit-config.yaml Makefile .github/workflows/scheduled-tests.yml
git commit -m "refactor: consolidate bandit.yaml into pyproject.toml [tool.bandit]"
```

---

### Task 5: Clean local disk (untracked artifacts)

**Files:**
- Delete (untracked): 8x results-* dirs, logs, generated files, node_modules, egg-info

**Step 1: Run cleanup command**

```bash
cd /c/Projects/jmo-security-repo
rm -rf results-docker/ results-docker-test/ results-enc/ results-enc2/ \
       results-failon-test/ results-meta/ results-noraw/ results-ps-test/ \
       results-scenario3/ test-juice-results/ node_modules/ jmo_security.egg-info/ \
       docker-build.log docker-build-v2.log scenario3-scan.log \
       diff-report.sarif test_trend_report.html \
       dependency-images.txt detected-images.txt pipeline-images.txt
```

**Step 2: Verify nothing tracked was deleted**

```bash
git status
```

Expected: Only staged/modified files from previous tasks. No unexpected deletions.

No commit needed -- these are all gitignored/untracked files.

---

### Task 6: Final verification

**Step 1: Count root files**

```bash
git ls-files | grep -cE '^[^/]+$'
```

Expected: 40 (down from 49)

**Step 2: Run full lint + test**

```bash
make fmt && make lint && make test-fast
```

Expected: All pass. No regressions from config consolidation or file moves.

**Step 3: Visual check**

```bash
git ls-files | grep -E '^[^/]+$' | sort
```

Verify the clean root listing matches the "After" state from the design doc:
- No `.coveragerc`, `.markdownlint.json`, `bandit.yaml`
- No `AGENTS.md`, `mkdocs.yml`
- No `Dockerfile.bare`, `docker-entrypoint.sh`
- No `jmo-scan.sh`, `custom-scan.sh`
- No `package.json`, `package-lock.json`

**Step 4: Verify pre-commit hooks pass**

```bash
pre-commit run --all-files
```

Expected: All hooks pass. Bandit reads from pyproject.toml, markdownlint uses .markdownlint-cli2.jsonc, coverage uses pyproject.toml.
