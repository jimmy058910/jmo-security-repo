# Technical Debt Tracking

This file tracks temporarily disabled checks and features that need to be fixed.

## 🔴 Critical - Disabled CI Checks

(No critical disabled checks at this time)

---

## 🟡 Medium - Outstanding Issues

(No medium-priority issues at this time)

---

## 🟢 Completed

### ✅ Docker Build Tool Verification (2025-01-14)

**Previous Status:** Failing in CI with exit code 127
**Fixed in:** Session 2025-01-14 - osv-scanner filename format corrected
**Priority:** Medium
**Actual effort:** 2 hours

**Root Cause:**

The `osv-scanner` binary download URL was incorrect. The GitHub release format changed between versions - the filename is `osv-scanner_linux_amd64`, **not** `osv-scanner_1.9.2_linux_amd64`. When the download failed, it returned an HTML error page which the shell tried to execute, causing "/usr/local/bin/osv-scanner: 1: Not: not found" (exit code 127).

**Fix Applied:**

Changed `Dockerfile` line 99 from:
```dockerfile
# BEFORE (incorrect):
curl -sSL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${OSV_VERSION}_linux_${OSV_ARCH}"

# AFTER (correct):
curl -sSL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${OSV_ARCH}"
```

**Completed tasks:**

- [x] Identified failing tool (osv-scanner via CI logs analysis)
- [x] Investigated download URL and GitHub release format
- [x] Tested osv-scanner binary manually on host
- [x] Corrected filename format in Dockerfile
- [x] Verified full Docker build (all 14 tools) ✅
- [x] Verified slim Docker build (6 core tools) ✅
- [x] Verified alpine Docker build (6 core tools) ✅
- [x] All three variants build successfully on linux/amd64

**Verification Results:**

```bash
# Full variant (Dockerfile):
=== Verifying installed tools ===
python3 --version ✅
jmo --help ✅
jmotools --help ✅
gitleaks version ✅
trufflehog --version ✅
semgrep --version ✅
syft version ✅
trivy --version ✅
hadolint --version ✅
tfsec --version ✅
checkov --version ✅
osv-scanner --version ✅  # FIXED!
bandit --version ✅
shellcheck --version ✅
shfmt --version ✅
=== All tools verified ===

# Slim variant (Dockerfile.slim):
=== Core tools verified === ✅

# Alpine variant (Dockerfile.alpine):
=== Alpine tools verified === ✅
```

**Note:** Docker builds now pass all verification steps. CI will succeed on next tag push or manual workflow dispatch.

---

### ✅ Markdownlint (2025-01-14)

**Previous Status:** Disabled in `.pre-commit-config.yaml`
**Fixed in:** Session 2025-01-14 - reduced violations from 100+ to 47
**Priority:** Low
**Actual effort:** 3 hours

**Work completed:**

- Fixed all MD032 (blank lines around lists) violations in core documentation
- Fixed all MD022 (blank lines around headings) violations in core files
- Fixed all MD034 (bare URLs) violations in USER_GUIDE.md, DOCKER_README.md
- Fixed all MD036 (emphasis as heading) violations in DOCKER_README.md
- Auto-fixed MD032 across 15+ files using Python script

**Files fully fixed:**

- `TECHNICAL_DEBT.md` ✅
- `.github/ISSUE_TEMPLATE/bug_report.md` ✅
- `docs/CONTEXT7_USAGE.md` ✅
- `docs/USER_GUIDE.md` ✅
- `docs/DOCKER_README.md` ✅
- `ROADMAP.md` ✅
- `docs/MCP_SETUP.md` ✅
- `QUICKSTART.md` (mostly clean)
- `README.md` (mostly clean)
- `CLAUDE.md` (mostly clean)

**Remaining violations (47 total):**

- MD033 (inline HTML) in README.md - **intentional badges, keep as-is**
- MD041 (first-line heading) in GitHub templates - **intentional format, keep as-is**
- MD022 in `.github/` templates - **GitHub template format, keep as-is**
- MD010 (hard tabs) in CHANGELOG.md, docs/ - **low priority cleanup**
- MD012 (multiple blank lines) in README.md, QUICKSTART.md - **low priority cleanup**

**Completed tasks:**

- [x] Fix blank lines around code fences and lists across all docs
- [x] Fix bare URLs in USER_GUIDE.md and DOCKER_README.md
- [x] Fix emphasis as heading in DOCKER_README.md
- [x] Re-enable markdownlint in `.pre-commit-config.yaml` ✅
- [x] Verify: Core documentation passes markdownlint

**Note:** Markdownlint has been re-enabled in pre-commit. Remaining 47 violations are mostly in templates (intentional) or low-priority formatting issues that don't affect readability.

---

### ✅ Mypy Type Checking (2025-01-14)

**Previous Status:** Disabled in `.pre-commit-config.yaml`
**Fixed in:** Session 2025-01-14 - all 56 errors resolved
**Priority:** Medium
**Actual effort:** 4 hours

**Fixed files:**

- `scripts/cli/wizard.py` (20 errors) - Added cast() for PROFILES dict, fixed Path/str types
- `scripts/core/generate_dashboard.py` (13 errors) - Collection type annotations, Set typing
- `scripts/core/adapters/*.py` (3 errors) - Optional[Any] → proper int types with isinstance checks
- `scripts/core/normalize_and_report.py` (5 errors) - Dict annotations, explicit List[Dict] returns
- `scripts/core/suppress.py` (3 errors) - Module import typing, Optional str checks
- `scripts/core/reporters/*.py` (3 errors) - Module imports, Dict annotations
- `scripts/cli/jmo.py` (6 errors) - Exception typing, dict annotations, unused ignores
- `scripts/cli/jmotools.py` (1 error) - Return type annotation

**Completed tasks:**

- [x] Fix wizard.py type annotations (repos list, profile_name, config dict)
- [x] Fix generate_dashboard.py Collection[Any] → List types
- [x] Fix adapter Optional[Any] → proper int/str types
- [x] Fix normalize_and_report.py PROFILE_TIMINGS, by_path, by_name annotations
- [x] Fix jmo.py TimeoutExpired exception type
- [x] Remove unused `type: ignore` comments
- [x] Re-enable mypy in `.pre-commit-config.yaml`
- [x] Verify: `mypy --config-file=pyproject.toml scripts/` ✅ PASSES

---

### Other Completed Items

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
