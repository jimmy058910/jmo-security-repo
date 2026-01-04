# CLAUDE.md

Guidance for Claude Code when working with the JMo Security Audit Tool Suite repository.

## Project Overview

JMo Security is a terminal-first security audit toolkit orchestrating 28+ scanners with unified CLI, normalized outputs, and HTML dashboard.

**Version:** v1.0.0 (Production Release)
**Philosophy:** Two-phase architecture: scan (invoke tools) → report (normalize, dedupe, output)
**Test Coverage:** 2,981 tests, 87% coverage, CI requires ≥85%

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

tests/               # 2,981 tests across unit/adapters/reporters/integration
```

### Key Files

| File | Purpose |
|------|---------|
| `scripts/cli/jmo.py` | Main CLI entry point |
| `scripts/core/normalize_and_report.py` | Aggregation engine |
| `scripts/core/common_finding.py` | CommonFinding schema v1.2.0 |
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
