# CLAUDE.md

Guidance for Claude Code when working with the JMo Security Audit Tool Suite repository.

> **Path-scoped rules** live in [`.claude/rules/`](.claude/rules/). They load automatically when Claude touches files matching their `paths:` frontmatter. See the [Path-Scoped Rules](#path-scoped-rules) section below for the full index.

## Project Overview

JMo Security is a terminal-first security audit toolkit orchestrating 27+ scanners with unified CLI, normalized outputs, and HTML dashboard.

**Version:** v1.0.0 (Production Release)
**Philosophy:** Two-phase architecture: scan (invoke tools) → report (normalize, dedupe, output)
**Test Coverage:** 8,000+ tests, 87% coverage, CI requires ≥85% (sharded across 4 parallel jobs)

**Key v1.0 Features:**

- SQLite historical storage for scan persistence and trend analysis
- Machine-readable diffs for comparing scans and detecting regressions
- Trend analysis with Mann-Kendall statistical significance testing
- CSV export and dual-mode HTML dashboard for reporting
- Cross-tool deduplication with 30-40% noise reduction

## AI Assistant Quality Standards

**CRITICAL:** Quality and correctness take precedence over speed. Always verify changes before proposing them.

### Mandatory Guardrails

1. **Pre-commit Order:** Black MUST run before Ruff (see `.pre-commit-config.yaml`)
2. **Test Coverage:** CI requires ≥85% (`pytest --cov-fail-under=85`)
3. **Subprocess Security:** NEVER use `shell=True` in subprocess calls. See [.claude/rules/python-safety.rules.md](.claude/rules/python-safety.rules.md)
4. **Conventional Commits:** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `perf:`, `ci:`
5. **Path Security:** Validate all user paths against directory traversal
6. **Cross-Platform Testing:** Tests MUST pass on Windows, Linux, macOS. See [.claude/rules/testing.cross-platform.rules.md](.claude/rules/testing.cross-platform.rules.md)

### Before Every Commit

```bash
make fmt && make lint && make test
```

### Artifact Guardrails (CI blocks these)

- No `venv/`, `__pycache__/`, `build/`, `dist/` in git
- No files >10MB (`check-added-large-files` hook)
- No secrets (detect-private-key pre-commit hook + TruffleHog CI scan)

### Proactive Issue Resolution

**CRITICAL:** When encountering issues (test failures, deprecation warnings, linting errors), address them immediately rather than deferring. Technical debt compounds quickly.

**Decision Framework:**

| Issue Type | Scale | Action |
|------------|-------|--------|
| Small & Simple | Single clear solution | **Fix immediately** - deprecation warnings, threshold adjustments, typos |
| Complex OR Multiple Solutions | Architectural impact or trade-offs | **Stop & discuss first** - get alignment before implementing |
| Blocking | CI broken, security vulnerability | **Fix immediately** - but document reasoning |

**Issue Handling Protocol:**

1. **Fix Now (Small & Simple):** If the fix is straightforward with one clear solution
   - Deprecation warnings: Update to recommended API
   - Performance test thresholds: Adjust with documented reasoning
   - Linting errors: Apply the fix
   - Single failing test: Fix the root cause

2. **Stop & Discuss (Complex/Multiple Solutions):** If any of these apply:
   - Multiple valid approaches exist
   - Fix affects architecture or public API
   - Uncertainty about the right solution
   - Change scope is larger than expected
   - **Action:** Present the issue, options, and recommendation before proceeding

3. **Document If Deferring:** If fix requires significant research/refactoring but isn't blocking:
   - Create GitHub issue with `tech-debt` or `enhancement` label
   - Add `# TODO(issue-#):` comment in code at the relevant location
   - Document in `.claude/known-issues.md` with description, root cause, proposed fix, priority (P0-P3)

4. **Never Ignore:** Warnings, deprecations, and flaky tests become bugs over time
5. **Rule of Three:** If the same approach fails 3 times, stop and change something fundamental — different angle, fresh start, or escalate to the user

### Plan Mode Format

When creating plans (via `/plan` or plan mode): be extremely concise, present a single recommended approach, include exact file paths (e.g. `scripts/core/adapters/foo.py:45`), and end with unresolved questions if any ambiguity remains.

## Quick Reference

### Development Setup

```bash
pip install -e ".[dev]"                # Install in editable mode with dev deps
make pre-commit-install                # Setup pre-commit hooks
jmo tools install --profile balanced   # Install security tools
make test-fast                         # Fast parallel tests (recommended for dev)
```

> **Note:** `make test` runs sequentially with coverage. Use `make test-fast` for 3-5x faster parallel execution during development. Requires `pytest-xdist` (included in dev deps).

### Essential Commands

| Command | Purpose |
|---------|---------|
| `jmo wizard` | Interactive setup wizard |
| `jmo scan --profile balanced` | Production scan (17 tools, 18-25 min) |
| `jmo scan --image nginx:latest` | Container image scan |
| `jmo report ./results` | Generate reports from scan |
| `jmo ci --fail-on HIGH` | CI/CD mode with threshold |
| `jmo tools check` | Check tool installation status |
| `jmo tools install --profile balanced` | Install tools (parallel by default, 3-4x faster) |
| `jmo tools clean --force` | Remove isolated venvs (pip conflict tools) |
| `jmo diff results-A/ results-B/` | Compare scans |
| `jmo history list` | View scan history |
| `jmo validate` | Pre-release validation scorecard (quick tier) |
| `jmo validate --tier full` | Full validation with real tools |
| `make fmt` | Format code (Black + Ruff) |
| `make lint` | Lint checks |
| `make test-fast` | Parallel tests, no coverage (fastest dev loop) |
| `make test-parallel` | Parallel tests with coverage (CI-like) |
| `make test` | Sequential tests with coverage (original) |
| `make test-e2e` | E2E tests (pytest-native) |
| `make test-e2e-visual` | Dashboard visual tests (Playwright) |
| `make test-e2e-report` | E2E tests with JSON report |
| `python scripts/dev/test_wizard_tools.py` | Test wizard tool detection (non-interactive) |

> **Note:** `jmo tools install` uses parallel installation by default. Use `--sequential` for debugging or `--jobs N` to adjust workers (default: 4, max: 8).
>
> **Wizard Testing:** Run `python scripts/dev/test_wizard_tools.py --profile balanced` before `jmo wizard` to verify tool infrastructure. The script tests isolated venvs, version detection, and dependency checks (Java, Node.js, bash) non-interactively.

### Version Management (CRITICAL)

```bash
python3 scripts/dev/update_versions.py --check-latest  # Check updates
python3 scripts/dev/update_versions.py --sync          # Sync Dockerfiles
```

**NEVER manually edit tool versions in Dockerfiles!** See [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md)

## AI Tooling Ecosystem

JMo Security includes agents, skills, and an MCP server for AI-assisted development.

### MCP Server (Security Findings API)

- `get_security_findings` - Query with filters (severity, tool, path)
- `apply_fix` - Apply AI-suggested patches (use `dry_run=True` first!)
- `mark_resolved` - Mark as fixed/false_positive/wont_fix

### Key Agents (invoke naturally)

| Agent | Purpose |
|-------|---------|
| `coverage-gap-finder` | Find untested code paths, missing test categories |
| `release-readiness` | Pre-release checklist verification |
| `code-quality-auditor` | Technical debt, refactoring opportunities |
| `security-auditor` | Security vulnerability analysis |
| `dependency-analyzer` | Impact analysis for changes |

### Key Skills (invoke with /skill-name)

- `/jmo-adapter-generator` - Generate new tool adapters with tests
- `/jmo-test-fabricator` - Create comprehensive test suites
- `/jmo-ci-debugger` - Debug CI/CD pipeline failures
- `/jmo-e2e-verify` - AI-driven e2e verification with parallel sub-agents

**Full documentation:** [.claude/skills/INDEX.md](.claude/skills/INDEX.md) (15 skills, 7 agents) | **Personas:** [.claude/PERSONA_GUIDELINES.md](.claude/PERSONA_GUIDELINES.md)

### Parallel Work: Agent Teams vs Subagents

| Use **Agent Teams** when | Use **Subagents** when |
|--------------------------|------------------------|
| Multi-file refactors spanning 3+ modules | Focused research or single-file tasks |
| Cross-layer changes (CLI + core + adapters + tests) | Quick searches, file reads, code exploration |
| Competing hypotheses during debugging | Tasks where only the result matters |
| Parallel code review (security + perf + coverage) | Sequential work with dependencies |

**Decision rule:** If teammates need to communicate findings with each other or coordinate across file boundaries, use agent teams. If work can be fire-and-forget with results reported back, use subagents.

> Agent teams require `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` in settings.json (experimental).

## Architecture Overview

### Two-Phase Workflow

1. **Scan Phase:** Invokes tools in parallel, writes raw JSON to `results/individual-{type}/`
2. **Report Phase:** Normalizes to CommonFinding schema, deduplicates, then enriches all findings with compliance frameworks via single-pass `enrich_findings_with_compliance()`, and outputs

**Enrichment Architecture:** Compliance enrichment (OWASP, CWE, CIS, NIST, PCI DSS, MITRE ATT&CK) is handled centrally in `normalize_and_report.py` after all findings are collected. Adapters return raw findings without enrichment.

### Directory Structure

```text
scripts/
├── cli/             # CLI commands (jmo.py, scan/report orchestrators, wizard)
│   ├── installers/  # Tool installation strategies (Strategy pattern)
│   └── ui/          # UI components (progress reporters)
├── core/            # Core logic (normalize_and_report.py, config.py, history_db.py)
│   ├── adapters/    # Tool parsers (see .claude/rules/adapters.rules.md)
│   └── reporters/   # Output formatters (see .claude/rules/reporters.rules.md)
└── dev/             # Helper scripts (update_versions.py)

tests/               # 8,000+ tests across unit/adapters/reporters/integration
.github/workflows/   # CI/CD (see .claude/rules/release.rules.md)
Dockerfile.*         # 4 variants (see .claude/rules/docker.rules.md)
```

### Key Files

| File | Purpose |
|------|---------|
| `scripts/cli/jmo.py` | Main CLI entry point |
| `scripts/cli/tool_installer.py` | Tool installation orchestrator |
| `scripts/cli/installers/` | Strategy pattern installers (pip, npm, brew, binary) |
| `scripts/core/normalize_and_report.py` | Aggregation engine |
| `scripts/core/common_finding.py` | CommonFinding schema v1.2.0 |
| `scripts/core/schema_validator.py` | JSON schema validation for findings |
| `scripts/core/install_config.py` | Installation URLs, timeouts, isolated tools config |
| `docs/schemas/common_finding.v1.json` | CommonFinding JSON Schema (Draft 2020-12) |
| `scripts/core/adapters/*.py` | Tool output parsers (27 adapters) |
| `jmo.yml` | Main configuration |
| `versions.yaml` | Tool version registry |
| `Dockerfile.*` | Docker variants: `Dockerfile.deep` (heavyweight, also tagged `:latest`), `.fast`, `.slim`, `.balanced` |

## Scan Profiles

> **Canonical Reference:** [docs/PROFILES_AND_TOOLS.md](docs/PROFILES_AND_TOOLS.md) - Complete tool lists, tool selection philosophy, content-triggered execution, scan type matrices, dependencies, manual installation

| Profile | Tools | Time | Use Case | Docker Tag |
|---------|-------|------|----------|------------|
| `fast` | 9 | 5-10 min | Pre-commit, PR validation | `:fast` |
| `slim` | 13 | 12-18 min | Cloud/IaC, AWS/Azure/GCP/K8s | `:slim` |
| `balanced` | 17 | 18-25 min | Production scans, CI/CD | `:balanced` |
| `deep` | 28 | 40-70 min | Compliance audits, pentests | `:deep` (default) |

**Note:** The heavyweight image lives at `Dockerfile.deep` (also pulled via `:latest` and `:deep` bare tags). See PROFILES_AND_TOOLS.md for complete tool lists.

## Path-Scoped Rules

Detailed guidelines for specific parts of the codebase. These load automatically when Claude touches matching files:

| Rule File | Applies To | Key Topics |
|-----------|-----------|-----------|
| [adapters.rules.md](.claude/rules/adapters.rules.md) | `scripts/core/adapters/`, `tests/adapters/` | New tool adapters, naming conventions, compliance enrichment |
| [reporters.rules.md](.claude/rules/reporters.rules.md) | `scripts/core/reporters/`, `tests/reporters/` | Output reporters, CommonFinding normalization |
| [python-safety.rules.md](.claude/rules/python-safety.rules.md) | All Python code | Subprocess security (CWE-78), secrets, logging |
| [testing.rules.md](.claude/rules/testing.rules.md) | `tests/**/*.py` | Test organization, pytest patterns, mocking, coverage |
| [testing.cross-platform.rules.md](.claude/rules/testing.cross-platform.rules.md) | Windows/macOS/Linux tests | Path handling, hang prevention, platform skips |
| [release.rules.md](.claude/rules/release.rules.md) | `.github/workflows/`, release scripts | CI/CD pipelines, version management, troubleshooting |
| [docker.rules.md](.claude/rules/docker.rules.md) | `Dockerfile*`, container code | Volumes, multi-arch, registries, arm64 limitations |

## Configuration

### Core Files

| File | Purpose |
|------|---------|
| `jmo.yml` | Main JMo config (referenced throughout codebase) |
| `jmo.suppress.yml` | Suppression rules |
| `versions.yaml` | Tool versions (NEVER edit manually; use `update_versions.py`) |
| `.pre-commit-config.yaml` | Pre-commit hooks (Black before Ruff) |

### jmo.yml Key Settings

| Key | Type | Description |
|-----|------|-------------|
| `default_profile` | string | Default scan profile (fast/balanced/deep) |
| `fail_on` | string | Severity threshold for CI failures |
| `retries` | int | Retries for failed tool invocations |
| `per_tool` | object | Per-tool configuration overrides |
| `profiles` | object | Custom profile definitions with tool lists |
| `email` | object | Email notification settings (SMTP, recipients) |
| `schedule` | object | Scheduled scan configuration (cron expressions) |
| `deduplication.similarity_threshold` | float | Cross-tool clustering threshold (0.5-1.0, default: 0.65) |

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for complete configuration reference.

## Troubleshooting (Quick Lookup)

| Issue | Solution |
|-------|----------|
| Tests failing | `make test --maxfail=1`, check coverage ≥85% |
| Tool not found | `jmo tools check`, then `jmo tools install` |
| Tool startup crash | `jmo tools clean --force && jmo tools install <tool>` |
| Pre-commit fails | `make fmt`, `make lint` |
| CI failures | Check matrix tests, coverage, pre-commit |
| SQLite locked | `jmo history vacuum` |
| Docker persistence | Mount `.jmo/` volume |

For release-specific issues, see [.claude/rules/release.rules.md](.claude/rules/release.rules.md). For Windows hang issues, see [.claude/rules/testing.cross-platform.rules.md](.claude/rules/testing.cross-platform.rules.md). For contributing-specific CI troubleshooting, see [CONTRIBUTING.md#ci-troubleshooting](CONTRIBUTING.md#ci-troubleshooting).

## Documentation References

**Core:** [README.md](README.md) | [QUICKSTART.md](QUICKSTART.md) | [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) | [CONTRIBUTING.md](CONTRIBUTING.md) | [TEST.md](TEST.md)

**Features:** [docs/PROFILES_AND_TOOLS.md](docs/PROFILES_AND_TOOLS.md) | [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md) | [docs/DOCKER_README.md](docs/DOCKER_README.md) | [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md)

**Operations:** [docs/RELEASE.md](docs/RELEASE.md) | [docs/SCHEDULE_GUIDE.md](docs/SCHEDULE_GUIDE.md) | [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md)

**Internal (Dev-Only):** `dev-only/` - Plans, archive, and internal documentation (not published)

**Plans:** [dev-only/plans/README.md](dev-only/plans/README.md)

## Notes

- Agent threads reset cwd between bash calls - use absolute paths
- Avoid emojis unless explicitly requested
- CommonFinding v1.2.0 includes compliance mappings (OWASP, CWE, CIS, NIST, PCI DSS, MITRE)
- Cross-tool dedup uses similarity clustering (configurable via `deduplication.similarity_threshold`, default: 0.65)
- Only create documentation with long-term value; use `.claude/` for temporary work
- **Scope Discipline:** When given a bounded task (e.g., "root directory files only", "just these 13 bugs"), stay strictly within that scope — do not expand to adjacent directories, related systems, or broader reorganizations unless explicitly asked
