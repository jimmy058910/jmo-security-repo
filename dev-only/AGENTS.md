# AGENTS.md

AI tooling documentation for JMo Security. This file describes the agents, skills, and MCP server available for AI-assisted development.

## Project

JMo Security is a terminal-first security audit toolkit orchestrating 28+ scanners with unified CLI, normalized outputs (CommonFinding schema v1.2.0), and HTML dashboard. Two-phase architecture: scan (invoke tools) → report (normalize, dedupe, output).

## Build / Test / Lint

```bash
make fmt          # Format (Black + Ruff)
make lint         # Lint checks
make test-fast    # Parallel tests, no coverage (fastest)
make test         # Sequential tests with coverage
```

## Agents

Agents run autonomously when invoked in conversation.

| Agent | Purpose |
|-------|---------|
| `coverage-gap-finder` | Find untested code paths and missing test categories |
| `release-readiness` | Pre-release checklist verification |
| `code-quality-auditor` | Technical debt and refactoring opportunities |
| `security-auditor` | Security vulnerability analysis |
| `dependency-analyzer` | Impact analysis for code changes |
| `doc-sync-checker` | Documentation-code sync verification |
| `codebase-explorer` | Architecture and pattern understanding |

Agent definitions: [.claude/agents/](.claude/agents/)

## Skills

Skills are invoked with `/skill-name` in Claude Code.

| Skill | Slash Command | Purpose |
|-------|--------------|---------|
| Adapter Generator | `/jmo-adapter-generator` | Generate new security tool adapters |
| Test Fabricator | `/jmo-test-fabricator` | Generate pytest test suites (85%+ coverage) |
| CI Debugger | `/jmo-ci-debugger` | Diagnose GitHub Actions CI failures |
| Target Type Expander | `/jmo-target-type-expander` | Add new scan target types |
| Compliance Mapper | `/jmo-compliance-mapper` | Map findings to 6 compliance frameworks |
| Profile Optimizer | `/jmo-profile-optimizer` | Optimize scan profile performance |
| Security Hardening | `/jmo-security-hardening` | Implement OWASP/CWE security fixes |
| Systematic Debugging | `/jmo-systematic-debugging` | Four-phase debugging framework |
| Refactoring Assistant | `/jmo-refactoring-assistant` | Complex refactoring with test preservation |
| Documentation Updater | `/jmo-documentation-updater` | Keep docs synchronized with code |
| Dashboard Builder | `/jmo-dashboard-builder` | Build React security dashboard |
| Content Generator | `/content-generator` | Generate marketing content |
| Community Manager | `/community-manager` | Track community engagement |
| Skill Optimizer | `/jmo-skill-optimizer` | Review and upgrade skills |

Skill definitions: [.claude/skills/](.claude/skills/)

## MCP Server

The JMo Security MCP server provides programmatic access to security scan results.

| Tool | Purpose |
|------|---------|
| `get_security_findings` | Query findings with filters (severity, tool, path) |
| `apply_fix` | Apply AI-suggested patches (use `dry_run=True` first) |
| `mark_resolved` | Mark finding as fixed/false_positive/wont_fix |
| `get_server_info` | Server metadata and scan summary |

Setup: [docs/MCP_SETUP.md](docs/MCP_SETUP.md)

## Key Conventions

- **Subprocess security:** Never use `shell=True` — always pass command as list
- **Adapter naming:** `PluginMetadata.name` uses underscores matching filename
- **Compliance enrichment:** Handled centrally in `normalize_and_report.py`, not in adapters
- **Test coverage:** CI requires ≥85% (`pytest --cov-fail-under=85`)
- **Conventional commits:** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`

## Documentation

- [CLAUDE.md](CLAUDE.md) — Full development guide
- [CONTRIBUTING.md](CONTRIBUTING.md) — Contribution workflow
- [TEST.md](TEST.md) — Testing guide
- [docs/USER_GUIDE.md](docs/USER_GUIDE.md) — User documentation
