# Tool Removal Guide

How to cleanly remove a security tool from JMo Security. This 7-layer checklist ensures no orphaned references remain. Based on the Bearer CLI removal (v1.0.1), and updated for the v2.0.0 structure: one tool list (`TOOL_MATRIX`), one `Dockerfile`, no scan profiles.

## When to Remove a Tool

- **Project archived/EOL** with no further rule updates (stale scanners create false confidence)
- **Acquired and folded** into a commercial product with no maintained OSS edition
- **Superseded** by another tool already in JMo with equivalent coverage
- **Persistent reliability issues** with no fix path

**Before removing:** Confirm there is no drop-in open-source CLI replacement. As an orchestrator, JMo can only wrap tools that exist as standalone binaries.

## Pre-Removal

1. Confirm EOL status: check GitHub repo, releases page, announcements
2. Identify coverage gap: is another tool in JMo already covering this tool's findings?
3. Search for replacement candidates: same niche, wrappable CLI, actively maintained
4. Write a design spec: `docs/superpowers/specs/YYYY-MM-DD-<tool>-removal-design.md`
5. Document decision rationale in CHANGELOG.md

## Removal Checklist (7 Layers)

Work bottom-up: tests first, then code, then Docker/config/docs. Run `make test-fast` after each code layer to catch breakage early.

### Layer 1: Tests

Remove tests first so deleting production code doesn't cause import errors.

- [ ] Delete adapter test: `tests/adapters/test_<tool>_adapter.py`
- [ ] Delete golden fixtures: `tests/fixtures/golden/<tool>/`
- [ ] Remove from `ALL_ADAPTERS` in `tests/adapters/test_adapter_malformed.py`
- [ ] Remove smoke config from `tests/integration/test_tool_smoke.py`
- [ ] Remove URL tests from `tests/unit/test_tool_installer_urls.py`
- [ ] Update mock data in `tests/cli/test_tool_manager.py`
- [ ] Update the pinned `TOOL_MATRIX` set in `tests/unit/test_tool_registry.py` and any count assertions in `tests/core/test_tool_registry.py`
- [ ] Run `make test-fast` to verify

### Layer 2: Core Code

- [ ] Delete adapter: `scripts/core/adapters/<tool>_adapter.py`
- [ ] Remove from `TOOL_MATRIX` in `scripts/core/tool_registry.py`. This is the one list `jmo scan` considers, `jmo tools install` installs and the image carries
- [ ] Remove from every other per-tool table in `scripts/core/tool_registry.py` (`TOOL_BINARY_NAMES`, `TOOL_SCAN_TYPES` and the rest; `grep -n '"<tool>"' scripts/core/tool_registry.py` finds them)
- [ ] Remove from rule equivalence groups in `scripts/core/rule_equivalence.py` (if present)
- [ ] Remove from `BINARY_URLS`, `ISOLATED_TOOLS` and the other install tables in `scripts/core/install_config.py` (if present)
- [ ] Update `EXPECTED_ADAPTER_COUNT` in `scripts/core/validators/scan_validator.py`
- [ ] Run `make test-fast` to verify

### Layer 3: CLI Code

- [ ] Remove scan block from `scripts/cli/scan_jobs/<scanner_type>_scanner.py`
- [ ] Update scanner docstring tool numbering
- [ ] Remove from `VERSION_PATTERNS` in `scripts/cli/tool_manager.py`
- [ ] Remove from `VERSION_COMMANDS` in `scripts/cli/tool_manager.py`
- [ ] Remove from `REMEDIATION_COMMANDS` in `scripts/cli/tool_manager.py`
- [ ] Remove from `PLATFORM_MANUAL_TOOLS` in `scripts/cli/tool_manager.py`
- [ ] Remove from `EOL_TOOLS` in `scripts/cli/tool_installer.py` (if still present)
- [ ] Remove from the wizard's scan-time estimates (`TOOL_TIME_ESTIMATES` under `scripts/cli/wizard_flows/`)
- [ ] Remove from `scripts/cli/wizard_flows/tool_checker.py` (windows_reasons + WINDOWS_INCOMPATIBLE_TOOLS)
- [ ] Run `make test-fast` to verify

### Layer 4: Docker

There is one image, built from `Dockerfile`. In it:

- [ ] Remove download/install RUN block
- [ ] Remove COPY statement (multi-stage builds)
- [ ] Remove from chmod PATH-verification block
- [ ] Remove from smoke test command chain

When removing lines from multi-line RUN commands, ensure `&&` chaining and `\` line continuations remain valid.

### Layer 5: Configuration

- [ ] Remove tool block from `versions.yaml`
- [ ] Remove from update schedule group in `versions.yaml`
- [ ] Remove from version history in `versions.yaml`
- [ ] Remove the tool's entry from the top-level `per_tool:` block in `jmo.yml` (if present)
- [ ] Remove the tool's output or cache directories from `.gitignore` (if present)

### Layer 6: Documentation

Primary docs:

- [ ] `CLAUDE.md` -- scanner count, adapter count
- [ ] `CONTRIBUTING.md` -- adapter count, naming examples
- [ ] `README.md` -- scanner count, tool table
- [ ] `PRODUCT_DEFINITION.md` -- tool categorization table
- [ ] `DOCKER_HUB_README.md` -- tool count and list
- [ ] `CHANGELOG.md` -- add removal entry under target version
- [ ] `docs/TOOLS.md` -- the tool matrix, when each tool runs, target types, installation; add the tool to the removed list with a one-line reason
- [ ] `docs/DOCKER_README.md` -- tool table
- [ ] `docs/USER_GUIDE.md` -- tool mentions and examples
- [ ] `docs/CLI_REFERENCE.md` -- tool list examples, platform-skipped examples

Secondary docs:

- [ ] `docs/MANUAL_INSTALLATION.md` -- install instructions, platform table, Windows notes
- [ ] `docs/examples/custom-policy-examples.md` -- example policies
- [ ] `packaging/winget/.../locale.en-US.yaml` -- WinGet manifest description

### Layer 7: Verify

- [ ] `make test-fast` passes
- [ ] `make lint` passes
- [ ] Grep confirms no orphaned references:

```bash
grep -ri "<tool_name>" scripts/ tests/ --include="*.py"
```

- [ ] Scanner-count claims in the docs match `len(TOOL_MATRIX)` (`tests/unit/test_tool_catalogue_count_claims.py` checks them)
- [ ] Update CLAUDE.md project memory if applicable

## False Positives to Ignore

Some tool names overlap with other concepts:

| Tool Name | False Positive Context | Why It's Safe |
|-----------|----------------------|---------------|
| bearer | HTTP `Authorization: Bearer <token>` | Authentication scheme, not the tool |
| trivy | Other security contexts mentioning "trivy" | Check if it's the tool or a typo |
| bandit | The repository's own pre-commit hook and `make lint` step | Removed as a JMo scanner in v2.0.0, kept as the repo's self-lint |

## Worked Example: Bearer CLI (v1.0.1)

Bearer (data privacy/SAST scanner) was removed in v1.0.1 after Cycode acquired the project and released v2.0.1 as the final open-source version.

- **Coverage gap:** Bearer's SAST findings were already covered by Semgrep `auto`. The unique PII data-flow tracking has no OSS CLI replacement.
- **Profile impact:** slim (14 to 13), balanced (18 to 17), deep (29 to 28)
- **Files touched:** ~30 files across all 7 layers
- **Design spec:** `docs/superpowers/specs/2026-04-03-bearer-removal-design.md`
- **Implementation plan:** `docs/superpowers/plans/2026-04-03-bearer-removal.md`
- **Commits:** 7 commits following the layer order (tests, core, CLI, Docker, config, primary docs, secondary docs)

## Worked Example: the v2.0.0 cut

v2.0.0 removed 16 tools in one change: kubescape, semgrep-secrets, bandit, trivy-rbac, checkov-cicd, noseyparker, prowler, akto, scancode, cdxgen, dependency-check, horusec, falco (with falcoctl), afl++, mobsf and lynis. The one-line reasons are in [TOOLS.md](TOOLS.md#removed-in-v200). The same change deleted scan profiles, which is why this checklist is shorter than the Bearer one: a removal used to touch four profile lists, four Dockerfiles and the `jmo.yml` profiles, and now touches one `TOOL_MATRIX` entry and one `Dockerfile`.

- **bandit is a split case.** The scanner went; the repository's own pre-commit hook and `make lint` step stayed. `grep -ri bandit` still finds those, and they are correct.
- **checkov-cicd folded by deletion.** checkov already scans `.github/workflows`, so no coverage moved.
- **Implementation plan:** `docs/superpowers/plans/2026-09-23-phase-2-cut.md`
