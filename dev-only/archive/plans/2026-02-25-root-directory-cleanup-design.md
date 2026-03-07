# Root Directory Cleanup Design

> **Date:** 2026-02-25
> **Goal:** Clean up root directory for open-source release readiness (49 -> 40 tracked files)
> **Philosophy:** Remove dead weight, consolidate configs, move misplaced files. Keep Docker + standard OSS files at root per convention.

## 1. File Deletions (7 tracked files)

| File | Reason |
|------|--------|
| `Dockerfile.bare` | Not in release matrix, CI, or Makefile. Never shipped. |
| `docker-entrypoint.sh` | Orphaned - no Dockerfile references it (all use `ENTRYPOINT ["jmo"]`) |
| `jmo-scan.sh` | Already staged for deletion. Wizard-generated example artifact. |
| `custom-scan.sh` | Duplicate of above. Zero references in codebase. |
| `package.json` | Only declared unused Playwright devDep. Never integrated. |
| `package-lock.json` | Artifact of orphaned package.json. |
| `.markdownlint.json` | Exact duplicate of config already in `.markdownlint-cli2.jsonc` |

## 2. File Moves (2 files)

| File | Destination | Required Updates |
|------|-------------|------------------|
| `AGENTS.md` | `dev-only/AGENTS.md` | None - internal AI guidance, no code references |
| `mkdocs.yml` | `docs/mkdocs.yml` | `.readthedocs.yaml` line 8: change to `configuration: docs/mkdocs.yml` |

## 3. Config Consolidation (2 files into pyproject.toml)

### 3a. `.coveragerc` -> `pyproject.toml [tool.coverage.*]`

Merge all settings from `.coveragerc` into existing `[tool.coverage.run]` and `[tool.coverage.report]` sections:
- Add `branch = true`, `source = ["scripts"]` to `[tool.coverage.run]`
- Add `show_missing = true`, `skip_empty = true` to `[tool.coverage.report]`
- Merge omit lists (union of both files)
- Merge exclude_lines (union of both files)
- Delete `.coveragerc`

### 3b. `bandit.yaml` -> `pyproject.toml [tool.bandit]`

Add new section:
```toml
[tool.bandit]
exclude_dirs = [".venv", ".venv-pypi", ".post-release-venv", "venv", "docs", "samples", "assets", "archive", "tests", "dev"]
skips = ["B404", "B603", "B606", "B607", "B110", "B112", "B608", "B101", "B202", "B324"]
```

Update 3 references to remove `-c bandit.yaml`:
- `.pre-commit-config.yaml:96`
- `Makefile:108`
- `.github/workflows/scheduled-tests.yml`

## 4. Local Disk Cleanup (untracked/gitignored artifacts)

```bash
rm -rf results-docker/ results-docker-test/ results-enc/ results-enc2/ \
       results-failon-test/ results-meta/ results-noraw/ results-ps-test/ \
       results-scenario3/ test-juice-results/ node_modules/ jmo_security.egg-info/ \
       docker-build.log docker-build-v2.log scenario3-scan.log \
       diff-report.sarif test_trend_report.html \
       dependency-images.txt detected-images.txt pipeline-images.txt
```

**Keep:** `nightshift.yaml` (symlink), `PRODUCT_DEFINITION.md` (private planning), `.env` (local config)

## 5. Reference Updates Summary

| Change | Files to Update |
|--------|-----------------|
| Remove `.markdownlint.json` | None - `.markdownlint-cli2.jsonc` is what pre-commit and CI use |
| Remove `bandit.yaml` | `.pre-commit-config.yaml`, `Makefile`, `scheduled-tests.yml` |
| Remove `.coveragerc` | None - pyproject.toml takes over automatically |
| Move `mkdocs.yml` | `.readthedocs.yaml` |
| Move `AGENTS.md` | None |

## 6. Result

**Before:** 49 tracked root files
**After:** 40 tracked root files (-9)

Root files removed/moved: `.coveragerc`, `.markdownlint.json`, `bandit.yaml`, `AGENTS.md`, `mkdocs.yml`, `Dockerfile.bare`, `docker-entrypoint.sh`, `jmo-scan.sh`, `custom-scan.sh`, `package.json`, `package-lock.json`
