# Technical Debt Tracking

This file tracks temporarily disabled checks and features that need to be fixed.

## 🔴 Critical - Disabled CI Checks

### 1. Mypy Type Checking (56 errors across 11 files)

**Status:** Disabled in `.pre-commit-config.yaml`
**Disabled in:** Commit 2cb9bf2
**Priority:** Medium
**Estimated effort:** 4-6 hours

**Affected files:**
- `scripts/cli/wizard.py` (28 errors) - Missing type annotations for repos, profile_name, config dict access
- `scripts/core/generate_dashboard.py` (13 errors) - Collection types, operator issues
- `scripts/core/adapters/*.py` (5 errors) - Optional[Any] assignments
- `scripts/core/normalize_and_report.py` (5 errors) - Collection types, return annotations
- `scripts/cli/jmo.py` (4 errors) - Type annotations, exception handling
- `scripts/cli/jmotools.py` (1 error) - Return type

**Tasks:**
- [ ] Fix wizard.py type annotations (repos list, profile_name, config dict)
- [ ] Fix generate_dashboard.py Collection[Any] → List types
- [ ] Fix adapter Optional[Any] → proper int/str types
- [ ] Fix normalize_and_report.py PROFILE_TIMINGS, by_path, by_name annotations
- [ ] Fix jmo.py TimeoutExpired exception type
- [ ] Remove unused `type: ignore` comments
- [ ] Re-enable mypy in `.pre-commit-config.yaml` lines 53-59
- [ ] Verify: `mypy --config-file=pyproject.toml scripts/`

---

### 2. Markdownlint (MD031/MD029 violations)

**Status:** Disabled in `.pre-commit-config.yaml`
**Disabled in:** Commit 4f103c1
**Priority:** Low
**Estimated effort:** 1-2 hours

**Issues:**
- `docs/examples/wizard-examples.md` - MD031 (blank lines around fences) and MD029 (list numbering)
- `.markdownlint.json` config not being picked up by pre-commit hook

**Tasks:**
- [ ] Fix blank lines around code fences in wizard-examples.md
- [ ] Fix ordered list numbering inconsistencies
- [ ] Test markdownlint config loading in pre-commit
- [ ] Re-enable markdownlint in `.pre-commit-config.yaml` lines 35-38

---

## 🟡 Medium - Docker Build Issues

### 3. Docker Build Tool Verification Failure

**Status:** Failing in CI (exit code 127)
**Priority:** Medium
**Estimated effort:** 2-3 hours

**Error:** `exit code: 127` during tool verification step in Dockerfile

**Potential causes:**
- Tool not found in PATH after installation
- Missing library dependencies for ARM64 builds
- Incorrect verification command syntax

**Tasks:**
- [ ] Review Dockerfile tool installation steps
- [ ] Check if tools are in PATH
- [ ] Test ARM64 build locally with QEMU
- [ ] Simplify verification step or remove problematic tools
- [ ] Verify: Docker builds complete successfully

**Workaround:** Docker workflow now only runs on tags (saves 8min CI time per push)

---

## 🟢 Completed

- ✅ Fixed deps-compile-check.yml (Python 3.10 requirements)
- ✅ Fixed shellcheck issues in docker-build.yml
- ✅ Fixed actionlint YAML validation
- ✅ Configured Docker workflow to only run on tags/manual triggers

---

## Notes

- **Re-enabling checks:** Before re-enabling any disabled check, test locally first:
  ```bash
  # Mypy
  mypy --config-file=pyproject.toml scripts/

  # Markdownlint
  markdownlint docs/

  # Pre-commit all hooks
  pre-commit run --all-files
  ```

- **Adding new checks:** Always test comprehensively before merging to main
- **CI time:** Current CI runs ~2-3 minutes without Docker builds (was 10+ minutes)
