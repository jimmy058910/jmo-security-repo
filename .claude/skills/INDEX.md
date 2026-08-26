# JMo Security - AI Tooling Ecosystem

JMo Security ships **12 skills**, **7 agents**, and an **MCP server** for AI-assisted
security development. Everything listed here is in the repository, so a fresh clone
gets working tooling.

## What is here, and what is not

This directory is scoped to **contributors**. Skills that generate a new adapter,
fabricate tests, debug a CI failure, or map compliance frameworks ship with the
repo, because those are the paths a contributor actually walks.

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

## Skills Quick Reference

| Skill | Slash Command | Purpose |
|-------|--------------|---------|
| [Adapter Generator](jmo-adapter-generator/SKILL.md) | `/jmo-adapter-generator` | Generate new security tool adapters |
| [Target Type Expander](jmo-target-type-expander/SKILL.md) | `/jmo-target-type-expander` | Add new scan target types |
| [Test Fabricator](jmo-test-fabricator/SKILL.md) | `/jmo-test-fabricator` | Generate pytest test suites (85%+ coverage) |
| [Compliance Mapper](jmo-compliance-mapper/SKILL.md) | `/jmo-compliance-mapper` | Map findings to 6 compliance frameworks |
| [Profile Optimizer](jmo-profile-optimizer/SKILL.md) | `/jmo-profile-optimizer` | Tune profile config from report-phase timings |
| [CI Debugger](jmo-ci-debugger/SKILL.md) | `/jmo-ci-debugger` | Diagnose GitHub Actions CI failures |
| [Documentation Updater](jmo-documentation-updater/SKILL.md) | `/jmo-documentation-updater` | Keep docs synchronized with code |
| [Systematic Debugging](jmo-systematic-debugging/SKILL.md) | `/jmo-systematic-debugging` | Four-phase debugging framework |
| [Dashboard Builder](jmo-dashboard-builder/SKILL.md) | `/jmo-dashboard-builder` | Build React security dashboard |
| [Refactoring Assistant](jmo-refactoring-assistant/SKILL.md) | `/jmo-refactoring-assistant` | Complex refactoring with test preservation |
| [Security Hardening](jmo-security-hardening/SKILL.md) | `/jmo-security-hardening` | Implement OWASP/CWE security fixes |
| [E2E Verify](jmo-e2e-verify/SKILL.md) | `/jmo-e2e-verify [quick\|full\|visual\|scan-only]` | AI-orchestrated e2e verification with parallel sub-agents, failure analysis, and visual dashboard inspection |

---

## Common Skill Workflows

These workflows describe how skills compose together for end-to-end features.

### Add New Tool (Full Stack)

1. `/jmo-adapter-generator` — Create adapter and tests
2. `/jmo-test-fabricator` — Expand test suite to 85%+ coverage
3. `/jmo-compliance-mapper` — Add tool-specific rule mappings
4. `/jmo-documentation-updater` — Update docs

### Add New Target Type

1. `/jmo-target-type-expander` — Implement target collection and scan jobs
2. `/jmo-test-fabricator` — Write integration tests
3. `/jmo-documentation-updater` — Update USER_GUIDE.md

### Performance Investigation

1. `/jmo-profile-optimizer` — Analyze report-phase timings, identify parse bottlenecks
2. `/jmo-ci-debugger` — Fix CI timeout configuration
3. `/jmo-documentation-updater` — Document tuning in USER_GUIDE.md

### Security Vulnerability Fix

1. `/jmo-systematic-debugging` — Investigate root cause
2. `/jmo-security-hardening` — Implement OWASP best practices fix
3. `/jmo-test-fabricator` — Generate security tests
4. `/jmo-documentation-updater` — Update security documentation

### Code Refactoring

1. `/jmo-systematic-debugging` — Analyze complexity and dependencies
2. `/jmo-refactoring-assistant` — Extract classes, split files
3. `/jmo-test-fabricator` — Update tests, maintain 85%+ coverage
4. `/jmo-documentation-updater` — Update architecture docs

---

## Shared References

- [Memory Integration Pattern](references/memory-integration-pattern.md) — Cross-skill memory guide
- [AGENTS.md](../../AGENTS.md) — Repo-root AI tooling summary
- [CLAUDE.md](../../CLAUDE.md) — Full development guide

---

**Skills:** 12 | **Agents:** 7 | **MCP Tools:** 4
