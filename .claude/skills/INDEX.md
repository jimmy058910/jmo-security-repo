# JMo Security - AI Tooling Ecosystem

JMo Security ships **7 agents** and an **MCP server** for AI-assisted security
development. Everything listed here is in the repository, so a fresh clone gets
working tooling.

## What is here, and what is not

This directory is scoped to **contributors**. It publishes no skills at present:
the twelve contributor skills that used to ship here were retired in 2026-10.
None was being used, and several described files and flags that no longer
exist. What was still useful moved to where it is read:

- adding an adapter: CONTRIBUTING.md's "Adding Tool Adapters" section and
  [adapters.rules.md](../rules/adapters.rules.md)
- the five required adapter-test categories: the `coverage-gap-finder` agent
- which docs exist and who reads them: the `doc-sync-checker` agent
- `scan-timings.json` versus `timings.json`:
  [docs/SCAN_OPTIMIZATION.md](../../docs/SCAN_OPTIMIZATION.md)

Maintainer workflows -- issue and PR triage, dependency sweeps, merges, releases,
marketing -- are deliberately **not** published. They need `gh` write access or
push rights to `main`, so they would be unusable to a contributor even if present.
They live on the maintainer's machine under this same directory, untracked.

The split is mechanical, not a matter of memory: `.gitignore` carries an explicit
per-skill allowlist under `.claude/`, and `scripts/dev/check_doc_links.py` fails CI
and pre-commit if any tracked file links to a path a clone does not receive.

## MCP Server (Security Findings API)

The JMo Security MCP server provides programmatic access to security findings for AI-assisted remediation.

### Available Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `get_security_findings` | Query findings with filters | `severity`, `tool`, `path`, `rule_id`, `limit` |
| `apply_fix` | **Preview** an AI patch; applying is not implemented | `finding_id`, `patch`, `confidence`, `explanation`, `dry_run` |
| `mark_resolved` | Record a resolution as a `jmo.suppress.yml` entry | `finding_id`, `resolution`, `comment`, `expires_days` |
| `query_findings_db` | Read-only SQL against the scan history database (`mode=ro` plus statement validation) | `query`, `params` |
| `get_server_info` | Server metadata | (none) |

### Usage Examples

```python
# Query high/critical findings
get_security_findings(severity=["HIGH", "CRITICAL"], limit=10)

# Preview a fix. There is no apply step yet: dry_run=False writes nothing
# and returns success=False. `confidence` and `explanation` are REQUIRED.
apply_fix(
    finding_id="fingerprint-abc123",
    patch="--- a/src/app.js\n+++ b/src/app.js\n@@ -42,1 +42,1 @@\n-old\n+new\n",
    confidence=0.95,
    explanation="Added input sanitization",
    dry_run=True,
)

# Mark as false positive -> appends an entry to jmo.suppress.yml that
# expires in 90 days (365 max; there is no permanent option here).
mark_resolved(
    finding_id="fingerprint-abc123",
    resolution="false_positive",
    comment="Test file, not production",
)
```

### Resolution Types

- `fixed` - Vulnerability remediated. **Writes no suppression**: re-scan to
  confirm it is gone, because hiding it would mask a fix that did not take.
- `false_positive` - Not a real vulnerability
- `wont_fix` - Accepted risk (document why)
- `risk_accepted` - Business decision to accept

For MCP setup, see [docs/MCP_SETUP.md](../../docs/MCP_SETUP.md).

---

## Agents

Agents are invoked naturally in conversation. Each one completes a specialized task end-to-end in a single invocation, then reports back; they do not pause mid-task for confirmation. All seven are read-only analysis over this codebase.

| Agent | Purpose | When to Use |
|-------|---------|-------------|
| `coverage-gap-finder` | Find untested code paths, missing test categories | Before releases, after major changes |
| `release-readiness` | Pre-release checklist verification | Before tagging versions |
| `code-quality-auditor` | Technical debt, refactoring opportunities | Periodic codebase health checks |
| `security-auditor` | Security vulnerability analysis | After security-relevant changes |
| `dependency-analyzer` | Impact analysis for changes | Before refactoring, API changes |
| `doc-sync-checker` | Documentation-code sync verification | After feature implementations |
| `codebase-explorer` | Architecture and pattern understanding | When onboarding or exploring |

Agent definitions are in [.claude/agents/](../agents/); the persona conventions they
follow are in [.claude/PERSONA_GUIDELINES.md](../PERSONA_GUIDELINES.md).

---

## Shared References

- [AGENTS.md](../../AGENTS.md) — Repo-root AI tooling summary
- [CLAUDE.md](../../CLAUDE.md) — Full development guide

---

**Skills:** 0 | **Agents:** 7 | **MCP Tools:** 5
