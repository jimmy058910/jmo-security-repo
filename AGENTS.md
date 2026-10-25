# AGENTS.md

AI tooling documentation for JMo Security. This file describes the agents, skills, and MCP server available for AI-assisted development.

## Project

JMo Security is a terminal-first security audit toolkit orchestrating 15 scanners with unified CLI, normalized outputs (CommonFinding schema v1.2.0), and HTML dashboard. Two-phase architecture: scan (invoke tools) → report (normalize, dedupe, output).

## Build / Test / Lint

```bash
make fmt          # Format (ruff format + shfmt)
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

Agent definitions: [.claude/agents/](.claude/agents/) — persona conventions in [.claude/PERSONA_GUIDELINES.md](.claude/PERSONA_GUIDELINES.md)

## Skills

No skills ship with the repository at present: the twelve contributor skills were
retired in 2026-10, and maintainer-only workflows (triage, merges, releases,
marketing) are deliberately not published. See
[.claude/skills/INDEX.md](.claude/skills/INDEX.md) for the boundary, how it is
enforced, and where the retired skills' useful content moved.

## MCP Server

The JMo Security MCP server provides programmatic access to security scan results.

| Tool | Purpose |
|------|---------|
| `get_security_findings` | Query findings with filters (severity, tool, path) |
| `apply_fix` | **Preview** an AI-suggested patch. Applying is not implemented |
| `mark_resolved` | Record a resolution as an expiring `jmo.suppress.yml` entry |
| `query_findings_db` | Read-only SQL (SELECT / EXPLAIN / WITH) against the scan history database |
| `get_server_info` | Server metadata and scan summary |

Setup: [docs/MCP_SETUP.md](docs/MCP_SETUP.md)

## Key Conventions

- **Subprocess security:** Never use `shell=True` — always pass command as list
- **Adapter naming:** `PluginMetadata.name` uses underscores matching filename
- **Compliance enrichment:** Handled centrally in `normalize_and_report.py`, not in adapters
- **Test coverage:** CI's only enforced floor is **85%** (`coverage-aggregate`'s "Verify coverage threshold" step). Nothing sets `--cov-fail-under` anywhere (#756)
- **Conventional commits:** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`

## Documentation

- [CLAUDE.md](CLAUDE.md) — Full development guide
- [CONTRIBUTING.md](CONTRIBUTING.md) — Contribution workflow
- [TEST.md](TEST.md) — Testing guide
- [docs/USER_GUIDE.md](docs/USER_GUIDE.md) — User documentation
- [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) — Deliberate and environment-bound behaviour
