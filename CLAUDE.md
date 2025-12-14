# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working with the JMo Security Audit Tool Suite repository.

## Project Overview

JMo Security is a terminal-first security audit toolkit orchestrating 28+ scanners with unified CLI, normalized outputs, and HTML dashboard.

**Version:** v1.0.0 (Production Release)
**Philosophy:** Two-phase architecture: scan (invoke tools) → report (normalize, dedupe, output)
**Key Features:**

- 28 security scanners with plugin adapter architecture
- SQLite historical storage for trend analysis (v1.0.0)
- Machine-readable diffs for CI/CD integration (v1.0.0)
- Profile-based scanning (fast/slim/balanced/deep) - 4 unified profiles
- Multi-target support: repos, containers, IaC, URLs, GitLab, K8s
- Cross-tool deduplication (30-40% noise reduction)
- 6 compliance framework mappings (OWASP, CWE, CIS, NIST, PCI DSS, MITRE)

**Test Coverage:** 2,981 tests, 87% coverage, CI requires ≥85%

## Quick Reference

### Development Setup

```bash
pip install -e ".[dev]"                # Install in editable mode with dev deps
make pre-commit-install                # Setup pre-commit hooks
jmo tools install --profile balanced   # Install security tools
make test                              # Run tests with coverage
```

### Common Commands

| Command | Purpose |
|---------|---------|
| `jmo wizard` | Interactive setup wizard |
| `jmo wizard --yes` | Non-interactive with defaults |
| `jmo scan --profile fast` | Quick scan, 8 tools (5-10 min) |
| `jmo scan --profile slim` | Cloud/IaC scan, 14 tools (12-18 min) |
| `jmo scan --profile balanced` | Production scan, 18 tools (18-25 min) |
| `jmo scan --profile deep` | Comprehensive audit, 28 tools (40-70 min) |
| `jmo scan --image nginx:latest` | Scan container image |
| `jmo scan --url https://api.com` | DAST scanning |
| `jmo report ./results` | Generate reports from scan |
| `jmo ci --fail-on HIGH` | CI/CD mode with threshold |
| `jmo tools check --profile balanced` | Check tool installation status |
| `jmo tools install --profile balanced` | Install missing tools |
| `jmo tools update` | Update outdated tools |
| `jmo tools outdated` | Show outdated tools |
| `jmo tools uninstall --all` | Uninstall JMo and tools |
| `jmo diff results-A/ results-B/` | Compare scans |
| `jmo history list` | View scan history |
| `jmo trends analyze --days 30` | Trend analysis |
| `make fmt` | Format code |
| `make lint` | Lint code |
| `pytest tests/unit/test_foo.py -v` | Run specific test |

### Version Management (CRITICAL)

```bash
python3 scripts/dev/update_versions.py --check-latest  # Check updates
python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0
python3 scripts/dev/update_versions.py --sync         # Sync Dockerfiles
```

**NEVER manually edit tool versions in Dockerfiles!** See [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md)

## Architecture Overview

### Two-Phase Workflow

1. **Scan Phase:** Invokes tools in parallel, writes raw JSON to `results/individual-{type}/`
2. **Report Phase:** Normalizes to CommonFinding schema, deduplicates, enriches, outputs

### Directory Structure

```text
scripts/
├── cli/             # CLI commands (jmo.py, scan/report orchestrators, wizard)
├── core/            # Core logic (normalize_and_report.py, config.py, history_db.py)
│   ├── adapters/    # Tool parsers (plugin architecture)
│   └── reporters/   # Output formatters (JSON/MD/HTML/SARIF/CSV)
└── dev/             # Helper scripts (update_versions.py)

tests/               # 2,981 tests across unit/adapters/reporters/integration
```

### CommonFinding Schema

All findings normalized to unified schema v1.2.0 with fingerprint-based deduplication.
See [docs/schemas/common_finding.v1.json](docs/schemas/common_finding.v1.json)

### Plugin Architecture

Adapters use `@adapter_plugin` decorator. See existing adapters for patterns.

## Key Files

| File | Purpose |
|------|---------|
| `scripts/cli/jmo.py` | Main CLI entry point |
| `scripts/cli/tool_commands.py` | Tool management CLI handlers (v1.0.0) |
| `scripts/cli/tool_manager.py` | Tool status/version checking (v1.0.0) |
| `scripts/cli/tool_installer.py` | Cross-platform tool installation (v1.0.0) |
| `scripts/core/tool_registry.py` | Tool info from versions.yaml (v1.0.0) |
| `scripts/core/normalize_and_report.py` | Aggregation engine |
| `scripts/core/config.py` | Config loader for jmo.yml |
| `scripts/core/common_finding.py` | CommonFinding schema |
| `scripts/core/history_db.py` | SQLite storage (v1.0.0) |
| `scripts/core/diff_engine.py` | Diff computation (v1.0.0) |
| `scripts/core/adapters/*.py` | Tool output parsers |
| `scripts/core/reporters/*.py` | Output formatters |
| `scripts/dev/update_versions.py` | Version management |
| `jmo.yml` | Main configuration |
| `versions.yaml` | Tool version registry |
| `Dockerfile*` | Docker variants matching CLI profiles (fast/slim/balanced/deep) |

## Development Tasks

### Adding New Tool Adapter

1. Create `scripts/core/adapters/<tool>_adapter.py` with `@adapter_plugin` decorator
2. Map tool output to CommonFinding schema
3. Add test in `tests/adapters/test_<tool>_adapter.py`
4. Update documentation

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed workflow.

### Modifying Output Formats

Reporters in `scripts/core/reporters/`. All must include v1.0.0 metadata wrapper.

### Testing

```bash
pytest tests/unit/ -v              # Unit tests
pytest tests/adapters/ -v          # Adapter tests
pytest --cov=scripts --cov-report=term-missing  # With coverage
```

See [TEST.md](TEST.md) for complete testing guide.

## Important Conventions

### Tool Invocation

- No `shell=True` in subprocess calls
- Respect tool exit codes (0/1/2 treated as success for some tools)
- Timeout enforcement via jmo.yml

### Logging

- JSON logs by default (stderr)
- Human logs with `--human-logs`
- Never log to stdout

### Security

- Pre-commit hooks check for secrets
- Bandit scans for vulnerabilities
- All paths validated

### Docker Volumes (CRITICAL)

```bash
# MUST mount .jmo/history.db for persistence
docker run -v $PWD/.jmo:/scan/.jmo -v $PWD:/scan jmo-security:latest scan
```

### Results Directory Layout

```text
results/
├── individual-repos/      # Repository scans
├── individual-images/     # Container scans
├── individual-iac/        # IaC scans
├── individual-web/        # DAST scans
├── individual-gitlab/     # GitLab scans
├── individual-k8s/        # K8s scans
└── summaries/            # Aggregated reports
    ├── findings.json     # With v1.0.0 metadata wrapper
    ├── dashboard.html    # Interactive dashboard
    └── findings.sarif    # SARIF 2.1.0
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- run: jmo scan --repo . --results-dir results-baseline
- run: jmo scan --repo . --results-dir results-current
- run: jmo diff results-baseline/ results-current/ --format md > diff.md
```

### Release Process

1. **Automated (Recommended):** GitHub Actions → Automated Release workflow
2. **Manual:** Update tools → bump version → tag → push

**CRITICAL:** All tools MUST be updated before release (CI enforces this).
See [docs/RELEASE.md](docs/RELEASE.md) for details.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Tests failing | `make test --maxfail=1`, check coverage ≥85% |
| Tool not found | `jmo tools check`, then `jmo tools install` |
| Tool outdated | `jmo tools update` or `jmo tools update --critical-only` |
| Pre-commit fails | `make fmt`, `make lint` |
| CI failures | Check matrix tests, coverage, pre-commit |
| SQLite locked | `jmo history vacuum` |
| Docker persistence | Mount `.jmo/history.db` volume |

See [docs/CI_TROUBLESHOOTING.md](docs/CI_TROUBLESHOOTING.md) for detailed solutions.

## Unified Scan Profiles (v1.0.0)

CLI profiles and Docker variants are unified - same 4 profiles, same tools:

| Profile | Tools | Time | Use Case | Docker Tag |
|---------|-------|------|----------|------------|
| `fast` | 8 | 5-10 min | Pre-commit, PR validation | `jmo-security:fast` |
| `slim` | 14 | 12-18 min | Cloud/IaC, AWS/Azure/GCP/K8s | `jmo-security:slim` |
| `balanced` | 18 | 18-25 min | Production scans, CI/CD | `jmo-security:balanced` |
| `deep` | 28 | 40-70 min | Compliance audits, pentests | `jmo-security:deep` |

**Fast (8 tools):** trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, shellcheck

**Slim (14 tools):** Fast + prowler, kubescape, grype, bearer, horusec, dependency-check

**Balanced (18 tools):** Slim + zap, scancode, cdxgen, gosec

**Deep (28 tools):** Balanced + noseyparker, semgrep-secrets, bandit, trivy-rbac, checkov-cicd, akto, yara, falco, afl++, mobsf, lynis

## Configuration Files

| File | Purpose | Moveable |
|------|---------|----------|
| `jmo.yml` | Main JMo config | ❌ Hardcoded in 50+ files |
| `jmo.suppress.yml` | Suppression rules | ❌ Scanned during report |
| `versions.yaml` | Tool versions | ❌ Referenced by CI |
| `.pre-commit-config.yaml` | Pre-commit hooks | ❌ Must be in root |
| `Dockerfile*` | Docker variants | ❌ Docker convention |

## jmo.yml Configuration Keys

The main configuration file `jmo.yml` supports these keys:

| Key | Type | Description | Example |
|-----|------|-------------|---------|
| `default_profile` | string | Default scan profile (fast/balanced/deep) | `balanced` |
| `fail_on` | string | Severity threshold for CI failures | `HIGH` |
| `retries` | int | Number of retries for failed tool invocations | `2` |
| `email` | object | Email notification settings | `{smtp_host: ...}` |
| `schedule` | object | Scheduled scan configuration | `{cron: "0 2 * * *"}` |
| `profiles` | object | Custom scan profile definitions | `{quick: {tools: [...]}}` |
| `per_tool` | object | Per-tool configuration overrides | `{trivy: {timeout: 600}}` |

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for complete configuration reference.

## Documentation References

**Core Guides:**

- [README.md](README.md) - Project overview
- [QUICKSTART.md](QUICKSTART.md) - 5-minute setup
- [docs/USER_GUIDE.md](docs/USER_GUIDE.md) - Comprehensive reference
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development setup
- [TEST.md](TEST.md) - Testing guide

**Feature Docs:**

- [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md) - Tool version management
- [docs/DOCKER_README.md](docs/DOCKER_README.md) - Docker deep-dive
- [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md) - Results and output formats
- [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md) - Compliance mappings

**Operations:**

- [docs/RELEASE.md](docs/RELEASE.md) - Release process
- [docs/CI_TROUBLESHOOTING.md](docs/CI_TROUBLESHOOTING.md) - CI/CD debugging
- [docs/SCHEDULE_GUIDE.md](docs/SCHEDULE_GUIDE.md) - Scheduled scans

## Document Management Policy

**CRITICAL:** Only create documentation that provides long-term value.

- ❌ NO session summaries, temporary analysis, one-off troubleshooting docs
- ✅ YES to updating existing docs, adding to USER_GUIDE.md, CONTRIBUTING.md
- Use `.claude/` or `dev-only/` for temporary work (gitignored)

When updating docs:

1. Check for existing content first
2. Prefer editing existing files over creating new ones
3. Run markdownlint: `make pre-commit-run`
4. Update docs/index.md if adding new files

## Notes

- Agent threads reset cwd between bash calls - use absolute paths
- Avoid emojis unless explicitly requested
- CommonFinding v1.2.0 includes compliance mappings
- v1.0.0 outputs include metadata wrapper
- Cross-tool dedup uses similarity clustering (0.75 threshold)
- Skills/agents in `.claude/` are gitignored development aids

For detailed information on any topic, refer to the documentation links above rather than this summary.
