# Design: Remove Bearer CLI + Create Tool Removal Guide

**Date:** 2026-04-03
**Status:** Draft
**Scope:** Remove EOL Bearer tool from all touchpoints; document the process as a reusable guide

## Context

Bearer CLI was acquired by Cycode in April 2024. v2.0.1 (Feb 2026) is the final open-source release. The project will receive no further rule updates, making it a liability in a security scanner orchestrator. JMo Security already annotates Bearer as EOL in 5+ locations.

**Why remove (not replace):** Bearer's unique value was PII data-type flow tracking (GDPR/CCPA). No open-source CLI tool replicates this. Bearer's SAST security findings (SQLi, XSS, etc.) are already covered by Semgrep `auto`. Keeping a stale scanner creates false confidence.

**Secondary deliverable:** A `docs/TOOL_REMOVAL_GUIDE.md` documenting the removal checklist so future EOL tools can be removed consistently.

## Profile Impact

Removing bearer changes tool counts:

| Profile | Before | After | Delta |
|---------|--------|-------|-------|
| fast    | 9      | 9     | 0     |
| slim    | 14     | 13    | -1    |
| balanced| 18     | 17    | -1    |
| deep    | 29     | 28    | -1    |

No replacement tool is added. Counts in CLAUDE.md, CONTRIBUTING.md, docs, and comments must be updated.

## Removal Inventory

### Layer 1: Core Code (6 files)

| File | What to Remove | Notes |
|------|---------------|-------|
| `scripts/core/adapters/bearer_adapter.py` | Delete entire file | Primary adapter |
| `scripts/core/constants.py` | Remove `TOOL_BEARER` constant (line 78), remove from `ALL_TOOLS` (line 138), `PROFILE_SLIM_TOOLS` (line 220), `PROFILE_BALANCED_TOOLS` (line 241), `PROFILE_DEEP_TOOLS` (line 269). Update tool count comments. | 5 references |
| `scripts/core/tool_registry.py` | Remove `"bearer"` from `slim`, `balanced`, `deep` profile lists (lines 55, 75, 102). Remove platform restrictions entry (lines 298-303). Update tool count comments. | 5 references |
| `scripts/core/rule_equivalence.py` | Remove 4 bearer tuples from equivalence groups: `python_sql_injection`, `javascript_xss`, `python_os_command_injection`, `python_path_traversal` (lines 164, 170, 177, 182) | Groups retain semgrep+bandit coverage |
| `scripts/core/install_config.py` | Remove `BINARY_URLS["bearer"]` entry (lines 147-151) | Binary download URLs |
| `scripts/dev/generate_comprehensive_test_data.py` | Remove `"bearer"` from test data generator weights (line 53) | Synthetic data |

### Layer 2: CLI Code (5 files)

| File | What to Remove | Notes |
|------|---------------|-------|
| `scripts/cli/scan_jobs/repository_scanner.py` | Remove bearer scan block (lines 863-892), remove from module docstring (line 28) | ~30 lines |
| `scripts/cli/tool_manager.py` | Remove bearer version regex (line 88), version check command (line 141), install commands per platform (lines 321-327), Windows notice (lines 420-424) | 4 sections |
| `scripts/cli/tool_installer.py` | Remove `EOL_TOOLS` dict entry for bearer (lines 437-444). If bearer was the only EOL tool, remove the entire `EOL_TOOLS` block or leave structure for future use. | Keep `EOL_TOOLS` dict structure (empty) for reuse |
| `scripts/cli/wizard_flows/profile_config.py` | Remove bearer scan time estimate (line 84) | Estimated time |
| `scripts/cli/wizard_flows/tool_checker.py` | Remove bearer from `WINDOWS_INCOMPATIBLE_TOOLS` (line 204), remove Windows reason string (line 229) | 2 references |

### Layer 3: Tests (5 files)

| File | What to Remove | Notes |
|------|---------------|-------|
| `tests/adapters/test_bearer_adapter.py` | Delete entire file | 22 tests |
| `tests/adapters/test_adapter_malformed.py` | Remove `BearerAdapter` from parameterized import (line 58) | Shared malformed test |
| `tests/integration/test_tool_smoke.py` | Remove bearer `ToolSmokeConfig` entry (lines 233-246) | Smoke test config |
| `tests/unit/test_tool_installer_urls.py` | Remove bearer URL tests (lines 167-181, 322-336) | 2 test blocks |
| `tests/cli/test_tool_manager.py` | Update `not_installed` lists that include bearer (lines 1351, 1414, 1454, 1462) | Mock data |
| `tests/core/test_tool_registry.py` | Update Windows tool count expectation (line 213) | Count assertion |

### Layer 4: Docker (3 files)

| File | What to Remove | Notes |
|------|---------------|-------|
| `Dockerfile` (deep) | Remove bearer download block (~lines 131-137), COPY statement (line 302), PATH verification (line 320), smoke test (line 387) | 4 sections |
| `Dockerfile.balanced` | Remove bearer download block (~lines 97-103), COPY (line 220), PATH verify (line 235), smoke test (line 279) | 4 sections |
| `Dockerfile.slim` | Remove bearer download block (~lines 78-84), COPY (line 180), PATH verify (line 194), smoke test (line 234) | 4 sections |

### Layer 5: Configuration (1 file)

| File | What to Remove | Notes |
|------|---------------|-------|
| `versions.yaml` | Remove entire `bearer:` block (lines 199-212). Remove from `non_critical_tools` update group (lines 370-385). Remove version history entry (lines 656-658). | 3 sections |

### Layer 6: Documentation (10+ files)

| File | What to Update | Notes |
|------|---------------|-------|
| `CLAUDE.md` | Update profile tool counts (fast=9, slim=13, balanced=17, deep=28). Update "28+ scanners" → "27+ scanners" in overview. | Project-wide reference |
| `CONTRIBUTING.md` | Update profile table tool counts | Contributor guide |
| `docs/PROFILES_AND_TOOLS.md` | Remove bearer from slim/balanced/deep tool lists (lines 125, 147, 172). Remove from tool matrix (line 216). Remove cross-reference (line 501). Update section on SAST tools (line 426). Update tool counts in headers. | Primary tool docs |
| `docs/DOCKER_README.md` | Update tool table removing bearer | Docker docs |
| `docs/USER_GUIDE.md` | Remove "bearer" from slim profile description (line 368) | User guide |
| `docs/USAGE_MATRIX.md` | Remove bearer row from tool role table | Usage matrix |
| `docs/MANUAL_INSTALLATION.md` | Remove bearer install instructions (lines 217-230) | Install guide |
| `docs/CLI_REFERENCE.md` | Remove bearer references | CLI docs |
| `CHANGELOG.md` | Add removal entry under next version | Changelog |
| `DOCKER_HUB_README.md` | Update tool description | Marketing |
| `PRODUCT_DEFINITION.md` | Update tool categorization | Product doc |
| `README.md` | Update scanner count if mentioned | Project readme |

### Layer 7: Misc References

| File | Action | Notes |
|------|--------|-------|
| `packaging/winget/manifests/.../locale.en-US.yaml` | Update if bearer is mentioned in description | WinGet manifest |
| `docs/examples/custom-policy-examples.md` | Remove bearer examples if any | Example policies |
| `docs/examples/ci-cd-trends.md` | Remove bearer references if any | CI examples |
| `docs/internal/TESTING_MATRIX.md` | Remove bearer from test matrix | Internal docs |
| `docs/internal/BUILD_OPTIMIZATION.md` | Remove bearer build notes | Internal docs |

## What NOT to Touch

- `scripts/core/validation.py` — References "Bearer" HTTP auth token redaction (not the tool)
- `scripts/core/attestation/signer.py` — Uses HTTP `Authorization: Bearer {token}` (not the tool)
- `tests/security/test_secrets_management.py` — Bearer token regex patterns (HTTP auth)
- `tests/unit/test_validation.py` — Bearer HTTP token sanitization tests (HTTP auth)

These all reference the HTTP Bearer authentication scheme, not the Bearer CLI tool.

## Execution Strategy

**Approach:** Bottom-up removal (tests first, then core, then docs) so we can verify nothing breaks at each layer.

**Phase 1 — Tests (delete/update test files)**
- Delete `test_bearer_adapter.py`
- Update shared test files that reference bearer
- Run `make test-fast` — confirm no import errors or broken parameterizations

**Phase 2 — Core code (remove adapter, constants, registry, scanner)**
- Delete `bearer_adapter.py`
- Remove from constants, tool_registry, install_config, rule_equivalence
- Remove scanner block, tool_manager, installer, wizard entries
- Run `make test-fast` — confirm all passing

**Phase 3 — Docker**
- Remove bearer from all 3 Dockerfiles
- No build verification needed (CI handles this)

**Phase 4 — Configuration**
- Remove from `versions.yaml`
- Clean up `EOL_TOOLS` dict

**Phase 5 — Documentation**
- Update all tool counts, profile tables, and references
- Update CLAUDE.md profile counts

**Phase 6 — Tool Removal Guide**
- Create `docs/TOOL_REMOVAL_GUIDE.md` documenting this 7-layer checklist
- Reference this Bearer removal as the first worked example

## Tool Removal Guide — Outline

The guide (`docs/TOOL_REMOVAL_GUIDE.md`) will document the generalized checklist:

```markdown
# Tool Removal Guide

## When to Remove a Tool
- Project archived/EOL with no successor
- Acquired and folded into commercial product
- Superseded by another tool already in JMo
- Persistent reliability issues with no fix path

## Pre-Removal Checklist
1. Confirm EOL status (check GitHub, releases, announcements)
2. Identify coverage gap — is another tool in JMo covering this?
3. Check for replacement candidates (same niche, wrappable CLI)
4. Document decision in CHANGELOG.md

## Removal Checklist (7 Layers)
### Layer 1: Core Code
- [ ] Delete adapter file (`scripts/core/adapters/<tool>_adapter.py`)
- [ ] Remove constant from `scripts/core/constants.py`
- [ ] Remove from profile lists in `scripts/core/tool_registry.py`
- [ ] Remove from rule equivalence mappings in `scripts/core/rule_equivalence.py`
- [ ] Remove from install config in `scripts/core/install_config.py`
- [ ] Remove from test data generator in `scripts/dev/generate_comprehensive_test_data.py`

### Layer 2: CLI Code
- [ ] Remove scan block from relevant scanner (`scripts/cli/scan_jobs/`)
- [ ] Remove from `scripts/cli/tool_manager.py` (version check, install commands)
- [ ] Remove from `scripts/cli/tool_installer.py` (EOL dict, install strategy)
- [ ] Remove from wizard flows (`profile_config.py`, `tool_checker.py`)

### Layer 3: Tests
- [ ] Delete adapter test file (`tests/adapters/test_<tool>_adapter.py`)
- [ ] Remove from shared test parameterizations (`test_adapter_malformed.py`)
- [ ] Remove smoke test config (`test_tool_smoke.py`)
- [ ] Remove URL tests (`test_tool_installer_urls.py`)
- [ ] Update mock data in tool manager tests
- [ ] Update tool count assertions in registry tests

### Layer 4: Docker
- [ ] Remove download block from each Dockerfile variant that includes the tool
- [ ] Remove COPY statement in multi-stage builds
- [ ] Remove from PATH verification blocks
- [ ] Remove from smoke test commands

### Layer 5: Configuration
- [ ] Remove from `versions.yaml` (version block, update group, version history)
- [ ] Remove from `jmo.yml` if tool has per-tool config

### Layer 6: Documentation
- [ ] Update profile tool counts in CLAUDE.md, CONTRIBUTING.md
- [ ] Update docs/PROFILES_AND_TOOLS.md (tool lists, matrix, cross-reference)
- [ ] Update docs/DOCKER_README.md, USER_GUIDE.md, USAGE_MATRIX.md
- [ ] Update docs/MANUAL_INSTALLATION.md
- [ ] Add CHANGELOG.md entry
- [ ] Update README.md scanner count

### Layer 7: Verify
- [ ] `make test-fast` passes
- [ ] `make lint` passes
- [ ] `grep -ri "<tool_name>" scripts/ tests/` returns only false positives (HTTP Bearer, etc.)
- [ ] Profile counts match across all sources

## Post-Removal
- Update CLAUDE.md memory/project notes
- Commit with `chore(tools): remove <tool> (EOL)`
```

## Resolved During Review

- **CONTRIBUTING.md deep profile says 28 tools** (line 38) but code has 29. This is existing doc drift. After bearer removal, deep = 28, which coincidentally matches the current doc. No CONTRIBUTING.md update needed for deep count.
- **`EOL_TOOLS` dict structure** — Bearer is currently the only entry. **Decision: Keep the empty dict** as infrastructure for future EOL tools.

## Resolved

- **CHANGELOG.md** — Entry goes under v1.0.1 section. This removal is part of the v1.0.1 release.
