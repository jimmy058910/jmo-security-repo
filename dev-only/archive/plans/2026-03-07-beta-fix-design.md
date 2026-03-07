# v1.0.0 Beta Fix — Execution Design

**Date:** 2026-03-07
**Source:** [1.0.0-Beta-Fix.md](1.0.0-Beta-Fix.md) (17 categories, 20 blockers, 38 warnings)
**Approach:** Single branch (dev), dispatched parallel agents with strict file ownership
**Decomposition:** Large file refactoring deferred to separate plan (post-release)

---

## Execution Strategy

### Approach: Single Branch + Parallel Subagents

- All work on `dev` branch
- 7 streams grouped by file ownership (no two agents touch the same file)
- 4 phases: independent streams first, dependent streams after
- One commit per stream for clean git history

### Phase Map

```text
Phase 1 (parallel):  S1-Docker  |  S2-Docs  |  S3-Code  |  S5-CI
Phase 2 (parallel):  S4-Tests (after S3)
Phase 3 (serial):    S6-Code-Quality (touches S3 files)
Phase 4 (serial):    S7-Procedural (final cleanup + verify)
```

---

## Stream Definitions

### S1: Docker & Compose (Categories 1, 6, 8, 2.7)

**Files owned:** `Dockerfile`, `Dockerfile.fast`, `Dockerfile.slim`, `Dockerfile.balanced`, `docker-compose.yml`

| Task | Category | Detail |
|------|----------|--------|
| Run `update_versions.py --sync` | 1.1-1.3 | Sync yara-python, prowler, scancode-toolkit versions |
| Verify Dockerfile versions match versions.yaml | 1.1-1.3 | Post-sync validation |
| Fix Ubuntu version comments (22.04 -> 24.04) | 6 | All 4 Dockerfiles line 2 |
| Fix tool count comments in Dockerfile | 2.7 | Lines 1, 186, 358 |
| Fix docker-compose --profile flag | 8.1 | Line 44: add `balanced` value |
| Fix :alpine tag reference | 8.2 | Line 69: change to valid tag or remove |
| Remove deprecated version key | 8.3 | Line 8: remove `version: '3.8'` |

### S2: Documentation (Categories 2.1-2.6, 3, 4, 5, 14.1)

**Files owned:** `README.md`, `CLAUDE.md`, `docs/PROFILES_AND_TOOLS.md`, `docs/DOCKER_README.md`, `docs/CLI_REFERENCE.md`, `docs/USER_GUIDE.md`, `docs/RESULTS_GUIDE.md`, `CHANGELOG.md`, `docs/index.md`, `docs/RELEASE.md`, `docs/internal/TESTING_MATRIX.md`

| Task | Category | Detail |
|------|----------|--------|
| Fix tool counts in README.md | 2.1 | fast=9, deep=29, "29 tools", add missing tools to list |
| Fix tool count in CLAUDE.md | 2.2 | deep=29 |
| Fix tool counts in PROFILES_AND_TOOLS.md | 2.3 | 6 locations: headers + quick ref |
| Add OPA to YAML tool lists | 2.4 | All 4 profile lists |
| Fix tool counts in DOCKER_README.md | 2.5 | 5 locations |
| Fix tool count in CLI_REFERENCE.md | 2.6 | Line 18 |
| Fix jmo_version in example JSON | 3.1 | USER_GUIDE.md:835, RESULTS_GUIDE.md:1408 |
| Fix CHANGELOG placeholder date | 3.2 | CHANGELOG.md:268 |
| Remove OSV-Scanner ghost references | 4.1 | README.md:87, docs/index.md:151 |
| Fix dependency-check profile assignment | 4.2 | DOCKER_README.md:459 |
| Fix broken internal link in RELEASE.md | 5 | Line 158 |
| Fix broken links in TESTING_MATRIX.md | 5 | Lines 24, 391 |
| Update README "Last Updated" date | 14.1 | Line 362 |

### S3: Code Fixes (Categories 9.1, 9.3, 10.1-10.4, 14.2)

**Files owned:** `scripts/core/history_db.py`, `scripts/core/reporters/html_reporter.py`, `scripts/core/reporters/sarif_reporter.py`, `scripts/cli/wizard_flows/tool_checker.py`, `scripts/jmo_mcp/jmo_server.py`, plus files with `shutil.which()` calls

| Task | Category | Detail |
|------|----------|--------|
| Replace 27 raw shutil.which() with tool_exists() | 9.1 | Codebase-wide (excluding test files) |
| Investigate path traversal pattern | 9.3 | Confirm test fixture or add validation |
| Route get_query_plan() through _validate_readonly_query() | 10.1 | history_db.py:1941 |
| Add _escape_html(str(total)) for defense-in-depth | 10.2 | html_reporter.py:107-169 |
| Add safety comment to shlex.split() usage | 10.3 | tool_checker.py:988 |
| Add security TODO to apply_fix() stub | 10.4 | jmo_server.py:276-358 |
| Update SARIF reporter version to 1.0.0 | 14.2 | sarif_reporter.py:151 |

### S4: Tests & Coverage (Categories 11, 16)

**Files owned:** `tests/` (new and modified test files only)

| Task | Category | Detail |
|------|----------|--------|
| Create test_install_config.py | 11.1 | Dedicated tests for install_config.py |
| Create test_unicode_utils.py | 11.1 | Dedicated tests for unicode_utils.py |
| Create test_progress_ui.py | 11.1 | Dedicated tests for progress.py |
| Create test_config_models.py | 11.1 | Dedicated tests for config_models.py |
| Investigate test_no_github_tokens_in_code | 16.6 | May be false positive from requirements-dev.txt |
| Fix test_path_normalization_cross_platform | 16.5 | Cross-platform path handling |
| Fix test_bad_jmo_threads_fallback | 16.3 | Environment variable handling |
| Fix test_allow_missing_tools_stubs_all | 16.3 | Mock/environment issue |
| Add skip markers for infra-dependent tests | 16.1-16.2 | Proper `@pytest.mark.skipif` for Docker/tool tests |

### S5: CI/CD (Categories 13.1-13.2)

**Files owned:** `.github/workflows/ci.yml`, `.github/workflows/scheduled-tests.yml`

| Task | Category | Detail |
|------|----------|--------|
| Add TruffleHog step to ci.yml push/PR | 13.1 | Copy from scheduled-tests.yml:99, adapt for PR |
| Add critical integration tests to PR workflow | 13.2 | Run dedup accuracy tests with mocked tools on PR |

### S6: Code Quality (Categories 12.3, 12.4, 12.6 — scoped)

**Files owned:** Same as S3 files + `scripts/cli/jmo.py`, `scripts/core/generate_dashboard.py`, `scripts/core/email_service.py`, `scripts/core/developer_attribution.py`, `scripts/core/history_migrations.py`, `scripts/core/attestation/tamper_detector.py`

| Task | Category | Detail |
|------|----------|--------|
| Add return type hints to 37 public functions | 12.4 | jmo.py (27), generate_dashboard.py (7), tool_checker.py (3) |
| Guard print() statements in scripts/core/ | 12.6 | 30 instances — wrap in `if __name__ == "__main__"` or replace with logger |
| Add comments to broad except clauses | 12.3 | 31 occurrences — document why each is acceptable |
| Create GitHub issues for deferred refactoring | 12.1, 12.2, 12.5 | File splitting, function decomposition, WizardConfig |

### S7: Procedural & Cleanup (Categories 7, 13.3, 15, 17)

**Runs last — no file ownership conflicts**

| Task | Category | Detail |
|------|----------|--------|
| Commit or discard requirements-dev.txt | 7.1 | Resolve dirty working tree |
| Verify Bearer 2.0.0 exists as release | 14.3 | Check GitHub releases, update versions.yaml if needed |
| Document Bearer EOL in versions.yaml | 13.3 | Add comment noting archived status |
| Document deps-compile conflicts | 15.1 | Add note to CONTRIBUTING.md or known-issues |
| Document Sigstore OIDC known limitation | 17 | Add to KNOWN_ISSUES.md or release notes |
| Run `make fmt && make lint && make test` | — | Final verification |
| Prepare PR dev -> main | 7.2 | After all fixes land |

---

## Cat 12 Deferred Items (Separate Plan)

These will be documented in `docs/plans/YYYY-MM-DD-monolith-decomposition-design.md` after v1.0.0 ships:

| Item | File | Scope |
|------|------|-------|
| Split CLI entry point | jmo.py (3,803 lines) | Extract subcommand handlers to modules |
| Split SQLite layer | history_db.py (3,209 lines) | Extract query builders, migrations, encryption |
| Split tool installer | tool_installer.py (2,634 lines) | Extract per-strategy installers |
| Decompose store_scan() | history_db.py (~353 lines) | Break into stages |
| Decompose run_wizard() | wizard.py (~368 lines) | Extract to WizardConfig dataclass + smaller methods |
| Decompose _get_tool_version() | tool_manager.py (~266 lines) | Strategy pattern per tool |

---

## Success Criteria

- [ ] All 20 blockers resolved
- [ ] All actionable warnings addressed
- [ ] `make fmt && make lint && make test` passes
- [ ] `jmo validate` shows 253/253 (0 warnings)
- [ ] Coverage >= 85%
- [ ] Clean git history (1 commit per stream)
- [ ] Deferred items tracked as GitHub issues
