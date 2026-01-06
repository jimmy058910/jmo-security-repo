# CLAUDE.md

Guidance for Claude Code when working with the JMo Security Audit Tool Suite repository.

## Project Overview

JMo Security is a terminal-first security audit toolkit orchestrating 28+ scanners with unified CLI, normalized outputs, and HTML dashboard.

**Version:** v1.0.0 (Production Release)
**Philosophy:** Two-phase architecture: scan (invoke tools) → report (normalize, dedupe, output)
**Test Coverage:** 5,000+ tests, 87% coverage, CI requires ≥85% (sharded across 4 parallel jobs)

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
3. **Subprocess Security:** NEVER use `shell=True` in subprocess calls
4. **Conventional Commits:** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `perf:`, `ci:`
5. **Path Security:** Validate all user paths against directory traversal

### Before Every Commit

```bash
make fmt && make lint && make test
```

### Artifact Guardrails (CI blocks these)

- No `venv/`, `__pycache__/`, `build/`, `dist/` in git
- No files >10MB (`check-added-large-files` hook)
- No secrets (TruffleHog + detect-private-key hooks)

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
   - Document in `.claude/known-issues.md` with:
     - Description of the issue
     - Root cause analysis (if known)
     - Proposed fix approach
     - Priority (P0-P3)

4. **Never Ignore:** Warnings, deprecations, and flaky tests become bugs over time

**Example - Performance Test Thresholds (Simple Fix):**

```python
# BAD: Arbitrary threshold without context
assert elapsed < 0.05  # <50ms target

# GOOD: Documented threshold with platform considerations
assert elapsed < 0.2, f"Insert took {elapsed:.3f}s (target: <200ms)"
# Note: Windows ~100-150ms, Linux ~30-50ms, threshold allows 4x variance
```

**Example - Complex Fix (Stop & Discuss):**

```text
Issue: Database queries are slow with 10k+ findings
Options:
  A) Add indexes (simple, may not scale)
  B) Implement pagination (API change, better long-term)
  C) Add caching layer (complex, best performance)
Recommendation: B - discuss with user before proceeding
```

## Quick Reference

### Development Setup

```bash
pip install -e ".[dev]"                # Install in editable mode with dev deps
make pre-commit-install                # Setup pre-commit hooks
jmo tools install --profile balanced   # Install security tools
make test                              # Run tests with coverage
```

### Essential Commands

| Command | Purpose |
|---------|---------|
| `jmo wizard` | Interactive setup wizard |
| `jmo scan --profile balanced` | Production scan (18 tools, 18-25 min) |
| `jmo scan --image nginx:latest` | Container image scan |
| `jmo report ./results` | Generate reports from scan |
| `jmo ci --fail-on HIGH` | CI/CD mode with threshold |
| `jmo tools check` | Check tool installation status |
| `jmo diff results-A/ results-B/` | Compare scans |
| `jmo history list` | View scan history |
| `make fmt` | Format code (Black + Ruff) |
| `make lint` | Lint checks |

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

**Full documentation:** [.claude/skills/INDEX.md](.claude/skills/INDEX.md) (14 skills, 7 agents)

## Architecture Overview

### Two-Phase Workflow

1. **Scan Phase:** Invokes tools in parallel, writes raw JSON to `results/individual-{type}/`
2. **Report Phase:** Normalizes to CommonFinding schema, deduplicates, then enriches all findings with compliance frameworks via single-pass `enrich_findings_with_compliance()`, and outputs

**Enrichment Architecture:** Compliance enrichment (OWASP, CWE, CIS, NIST, PCI DSS, MITRE ATT&CK) is handled centrally in `normalize_and_report.py` after all findings are collected. Adapters return raw findings without enrichment.

### Directory Structure

```text
scripts/
├── cli/             # CLI commands (jmo.py, scan/report orchestrators, wizard)
├── core/            # Core logic (normalize_and_report.py, config.py, history_db.py)
│   ├── adapters/    # Tool parsers (plugin architecture with @adapter_plugin)
│   └── reporters/   # Output formatters (JSON/MD/HTML/SARIF/CSV)
└── dev/             # Helper scripts (update_versions.py)

tests/               # 5,000+ tests across unit/adapters/reporters/integration
```

### Key Files

| File | Purpose |
|------|---------|
| `scripts/cli/jmo.py` | Main CLI entry point |
| `scripts/core/normalize_and_report.py` | Aggregation engine |
| `scripts/core/common_finding.py` | CommonFinding schema v1.2.0 |
| `scripts/core/schema_validator.py` | JSON schema validation for findings |
| `docs/schemas/common_finding.v1.json` | CommonFinding JSON Schema (Draft 2020-12) |
| `scripts/core/adapters/*.py` | Tool output parsers (28 adapters) |
| `jmo.yml` | Main configuration |
| `versions.yaml` | Tool version registry |
| `Dockerfile*` | Docker variants (main=deep, .fast, .slim, .balanced) |

## Scan Profiles

> **Canonical Reference:** [docs/PROFILES_AND_TOOLS.md](docs/PROFILES_AND_TOOLS.md) - Complete tool lists, dependencies, manual installation

| Profile | Tools | Time | Use Case | Docker Tag |
|---------|-------|------|----------|------------|
| `fast` | 7 | 5-10 min | Pre-commit, PR validation | `:fast` |
| `slim` | 14 | 12-18 min | Cloud/IaC, AWS/Azure/GCP/K8s | `:slim` |
| `balanced` | 18 | 18-25 min | Production scans, CI/CD | `:balanced` |
| `deep` | 28 | 40-70 min | Compliance audits, pentests | `:deep` (default) |

**Note:** Main `Dockerfile` = deep variant. See PROFILES_AND_TOOLS.md for complete tool lists.

## Development Guidelines

### Adding New Tool Adapter

1. Create `scripts/core/adapters/<tool>_adapter.py` with `@adapter_plugin` decorator
2. **Use `safe_load_json_file()` from `scripts/core/adapters/common.py`** for consistent JSON loading
3. **Use `map_tool_severity()` from `scripts/core/common_finding.py`** for severity normalization (add to `TOOL_SEVERITY_MAPPINGS` if tool has custom severity levels)
4. Map tool output to CommonFinding schema
5. Add test in `tests/adapters/test_<tool>_adapter.py`
6. Update documentation

**Important:** Adapters should NOT handle compliance enrichment. Return raw findings and let `normalize_and_report.py` handle enrichment centrally via `enrich_findings_with_compliance()`. This single-pass batch operation is more efficient than per-adapter enrichment.

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed workflow.

### Tool Invocation Security

```python
# CORRECT: List arguments (default shell=False)
subprocess.run(["trivy", "image", image_name], capture_output=True)

# WRONG: String with shell=True - SECURITY VULNERABILITY
subprocess.run(f"trivy image {image_name}", shell=True)  # CWE-78
```

### Logging

- JSON logs by default (stderr)
- Human logs with `--human-logs`
- Never log to stdout

### Testing

```bash
pytest tests/unit/ -v                              # Unit tests
pytest tests/adapters/ -v                          # Adapter tests
pytest --cov=scripts --cov-report=term-missing     # With coverage
```

**Cross-Platform Testing (CRITICAL):** Tests MUST pass on Windows, Linux, and macOS. See below for platform-specific patterns.

See [TEST.md](TEST.md) for complete testing guide.

## Configuration

### Core Files

| File | Purpose |
|------|---------|
| `jmo.yml` | Main JMo config (referenced throughout codebase) |
| `jmo.suppress.yml` | Suppression rules |
| `versions.yaml` | Tool versions (referenced by CI) |
| `.pre-commit-config.yaml` | Pre-commit hooks |

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

## CI/CD & Release

### GitHub Actions Example

```yaml
- run: jmo scan --repo . --results-dir results-baseline
- run: jmo scan --repo . --results-dir results-current
- run: jmo diff results-baseline/ results-current/ --format md > diff.md
```

### Release Process

**CRITICAL:** All tools MUST be updated before release (CI enforces this).

1. **Automated (Recommended):** GitHub Actions → Automated Release workflow
2. **Manual:** Update tools → bump version → tag → push

See [docs/RELEASE.md](docs/RELEASE.md) for details.

## Docker & Registries

### Volume Mounts (CRITICAL)

```bash
# MUST mount .jmo/history.db for scan persistence
docker run -v $PWD/.jmo:/scan/.jmo -v $PWD:/scan ghcr.io/jimmy058910/jmo-security:balanced scan
```

### Container Registries

| Registry | Image | Purpose |
|----------|-------|---------|
| **GHCR** (Primary) | `ghcr.io/jimmy058910/jmo-security` | CI/CD, unlimited pulls |
| **Docker Hub** | `jmogaming/jmo-security` | Discoverability |
| **ECR Public** | `public.ecr.aws/m2d8u2k1/jmo-security` | AWS users |

See [docs/DOCKER_README.md](docs/DOCKER_README.md) for registry selection guidance.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Tests failing | `make test --maxfail=1`, check coverage ≥85% |
| Tool not found | `jmo tools check`, then `jmo tools install` |
| Pre-commit fails | `make fmt`, `make lint` |
| CI failures | Check matrix tests, coverage, pre-commit |
| SQLite locked | `jmo history vacuum` |
| Docker persistence | Mount `.jmo/` volume |

See [CONTRIBUTING.md#ci-troubleshooting](CONTRIBUTING.md#ci-troubleshooting) for detailed solutions.

## Platform Notes (Windows/WSL)

### Path Handling

- Use forward slashes in code (`path/to/file`), Windows handles both
- Docker paths require POSIX format (`/c/Projects/...` or `/mnt/c/...`)

### Docker Desktop

- Enable WSL 2 backend for performance
- Mount volumes: `-v "$(pwd):/scan"` works in Git Bash/WSL

### Pre-commit

- Install via pip, not system package manager
- May need `git config core.autocrlf false` for line ending issues

### Cross-Platform Testing Guidelines

**Test Infrastructure (tests/conftest.py):**

```python
# Platform detection
from tests.conftest import IS_WINDOWS, IS_LINUX, IS_MACOS

# Skip decorators - use when tests require platform-specific features
from tests.conftest import skip_on_windows, unix_only

@skip_on_windows  # Skips on Windows with clear reason
def test_unix_permissions():
    pass

# Error pattern matching
from tests.conftest import is_command_not_found_error
assert is_command_not_found_error(stderr)  # Works on all platforms

# Subprocess mocking helpers
from tests.conftest import mock_subprocess_success
mock_run.return_value = mock_subprocess_success(returncode=0)
```

**Common Cross-Platform Issues:**

| Issue | Windows Behavior | Solution |
|-------|-----------------|----------|
| `chmod` permissions | No effect (no Unix execute bits) | Skip test with `@skip_on_windows` |
| Command not found errors | "cannot find the file specified" | Use `is_command_not_found_error()` |
| Path separators | Uses backslashes `\` | Use `pathlib.Path` or forward slashes |
| File locking | More aggressive locking | Close files before deletion |
| Process spawning | Different error codes | Test for `!= 0` not specific codes |

**Subprocess Testing Rules:**

1. **ALWAYS mock `subprocess.run`** for tests calling external commands
2. **Never assume tools exist** - mock `tool_exists()` and `find_tool()` together
3. **Use `shell=False`** in production code (security requirement)
4. **Verify mock signatures** - test `shell=False` explicitly

```python
# CORRECT: Mock both tool existence checks
with (
    patch("module.tool_exists", return_value=True),
    patch("module.find_tool", return_value="/usr/bin/tool"),
    patch("subprocess.run") as mock_run,
):
    mock_run.return_value = mock_subprocess_success()
    # ... test code ...

# WRONG: Missing find_tool mock causes None command
with patch("module.tool_exists", return_value=True):
    # find_tool returns None → command is None → hangs or crashes
```

**pytest-timeout Safety Net:**

- All tests have 120s timeout (configurable in pyproject.toml)
- Use `@pytest.mark.timeout(300)` for legitimately slow tests
- Set `PYTEST_TIMEOUT=0` to disable during local debugging

## Documentation References

**Core:** [README.md](README.md) | [QUICKSTART.md](QUICKSTART.md) | [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | [CONTRIBUTING.md](CONTRIBUTING.md) | [TEST.md](TEST.md)

**Features:** [docs/PROFILES_AND_TOOLS.md](docs/PROFILES_AND_TOOLS.md) | [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md) | [docs/DOCKER_README.md](docs/DOCKER_README.md) | [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md)

**Operations:** [docs/RELEASE.md](docs/RELEASE.md) | [docs/SCHEDULE_GUIDE.md](docs/SCHEDULE_GUIDE.md) | [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md)

## Notes

- Agent threads reset cwd between bash calls - use absolute paths
- Avoid emojis unless explicitly requested
- CommonFinding v1.2.0 includes compliance mappings (OWASP, CWE, CIS, NIST, PCI DSS, MITRE)
- Cross-tool dedup uses similarity clustering (configurable via `deduplication.similarity_threshold`, default: 0.65)
- Only create documentation with long-term value; use `.claude/` for temporary work

For detailed information on any topic, refer to the documentation links above.
