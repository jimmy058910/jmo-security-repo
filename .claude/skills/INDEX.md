# JMo Security - AI Tooling Ecosystem

JMo Security includes a comprehensive AI tooling ecosystem: **21 skills**, **7 agents**, and an **MCP server** for AI-assisted security development.

## MCP Server (Security Findings API)

The JMo Security MCP server provides programmatic access to security findings for AI-assisted remediation.

### Available Tools

| Tool | Purpose | Key Parameters |
|------|---------|----------------|
| `get_security_findings` | Query findings with filters | `severity`, `tool`, `path`, `rule_id`, `limit` |
| `apply_fix` | Apply AI-suggested patches | `finding_id`, `patch`, `confidence`, `dry_run` |
| `mark_resolved` | Mark finding status | `finding_id`, `resolution`, `comment` |
| `get_server_info` | Server metadata | (none) |

### Usage Examples

```python
# Query high/critical findings
get_security_findings(severity=["HIGH", "CRITICAL"], limit=10)

# Preview a fix before applying (ALWAYS use dry_run first!)
apply_fix(
    finding_id="fingerprint-abc123",
    patch="diff --git a/src/app.js...",
    confidence=0.95,
    explanation="Added input sanitization",
    dry_run=True  # Preview first!
)

# Mark as false positive
mark_resolved(
    finding_id="fingerprint-abc123",
    resolution="false_positive",
    comment="Test file, not production"
)
```

### Resolution Types

- `fixed` - Vulnerability remediated
- `false_positive` - Not a real vulnerability
- `wont_fix` - Accepted risk (document why)
- `risk_accepted` - Business decision to accept

For MCP setup, see [docs/MCP_SETUP.md](../../docs/MCP_SETUP.md).

---

## Key Agents

Agents are invoked naturally in conversation. Each one completes a specialized task end-to-end in a single invocation, then reports back; they do not pause mid-task for confirmation.

| Agent | Purpose | When to Use |
|-------|---------|-------------|
| `coverage-gap-finder` | Find untested code paths, missing test categories | Before releases, after major changes |
| `release-readiness` | Pre-release checklist verification | Before tagging versions |
| `code-quality-auditor` | Technical debt, refactoring opportunities | Periodic codebase health checks |
| `security-auditor` | Security vulnerability analysis | After security-relevant changes |
| `dependency-analyzer` | Impact analysis for changes | Before refactoring, API changes |
| `doc-sync-checker` | Documentation-code sync verification | After feature implementations |
| `codebase-explorer` | Architecture and pattern understanding | When onboarding or exploring |

Agent definitions are in [.claude/agents/](../agents/).

---

## Skills Quick Reference

| Skill | Slash Command | Purpose |
|-------|--------------|---------|
| [Adapter Generator](jmo-adapter-generator/SKILL.md) | `/jmo-adapter-generator` | Generate new security tool adapters |
| [Target Type Expander](jmo-target-type-expander/SKILL.md) | `/jmo-target-type-expander` | Add new scan target types |
| [Test Fabricator](jmo-test-fabricator/SKILL.md) | `/jmo-test-fabricator` | Generate pytest test suites (85%+ coverage) |
| [Compliance Mapper](jmo-compliance-mapper/SKILL.md) | `/jmo-compliance-mapper` | Map findings to 6 compliance frameworks |
| [Profile Optimizer](jmo-profile-optimizer/SKILL.md) | `/jmo-profile-optimizer` | Optimize scan profile performance |
| [CI Debugger](jmo-ci-debugger/SKILL.md) | `/jmo-ci-debugger` | Diagnose GitHub Actions CI failures |
| [Documentation Updater](jmo-documentation-updater/SKILL.md) | `/jmo-documentation-updater` | Keep docs synchronized with code |
| [Systematic Debugging](jmo-systematic-debugging/SKILL.md) | `/jmo-systematic-debugging` | Four-phase debugging framework |
| [Dashboard Builder](jmo-dashboard-builder/SKILL.md) | `/jmo-dashboard-builder` | Build React security dashboard |
| [Refactoring Assistant](jmo-refactoring-assistant/SKILL.md) | `/jmo-refactoring-assistant` | Complex refactoring with test preservation |
| [Security Hardening](jmo-security-hardening/SKILL.md) | `/jmo-security-hardening` | Implement OWASP/CWE security fixes |
| [Content Generator](content-generator/SKILL.md) | `/content-generator` | Generate marketing content |
| [Community Manager](community-manager/SKILL.md) | `/community-manager` | Track community engagement |
| [Skill Optimizer](jmo-skill-optimizer/SKILL.md) | `/jmo-skill-optimizer` | Review and upgrade skills |
| [E2E Verify](jmo-e2e-verify/SKILL.md) | `/jmo-e2e-verify [quick\|full\|visual\|scan-only]` | AI-orchestrated e2e verification with parallel sub-agents, failure analysis, and visual dashboard inspection |
| [Merge PR](merge-pr/SKILL.md) | `/merge-pr [PR-title-override]` | Push branch, open PR to main, watch CI, squash-merge, sync dev, cleanup local + remote |
| [Dependabot Triage](jmo-dependabot-triage/SKILL.md) | `/jmo-dependabot-triage [--dry-run\|--execute]` | Sweep open Dependabot PRs + security alerts; classify merge/close/dismiss/defer; project-policy-aware (no auto-merge, conservative bumps) |
| [Issue Triage](jmo-issue-triage/SKILL.md) | `/jmo-issue-triage [--dry-run\|--execute]` | Sweep manual bug/enhancement/tech-debt/docs issues; classify READY-TO-WORK / NEEDS-INFO / ROADMAP-TRACKING / STALE-NEGLECTED / DUPLICATE |
| [Tool Update Triage](jmo-tool-update-triage/SKILL.md) | `/jmo-tool-update-triage [--dry-run\|--execute]` | Sweep `app/github-actions` tool-version update issues; classify BATCH-MINOR / MAJOR-BUMP-READABLE / MAJOR-BUMP-MIGRATION / MANUAL-TOOL / PLACEHOLDER-CURRENT |
| [Roadmap Sync](jmo-roadmap-sync/SKILL.md) | `/jmo-roadmap-sync [--dry-run\|--execute]` | Align ROADMAP.md, `phase-*` labels, and the GitHub Project board after releases or quarterly reviews |
| [Maintenance Monday](maintenance-monday/SKILL.md) | `/maintenance-monday [--dry-run\|--execute]` | Orchestrate all three triage skills (issue + Dependabot + tool-update) in one consolidated plan with per-section approval. Weekly cadence. |

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

1. `/jmo-profile-optimizer` — Analyze timings, identify bottlenecks
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

### Weekly Maintenance (Consolidated Triage)

1. `/maintenance-monday` — Discover backlog across all three triage scopes (manual issues, Dependabot PRs, tool-version issues), present one consolidated plan with per-section approval, execute approved sections

The super-skill is preferred over invoking the three child skills sequentially when the whole backlog is being reviewed. To pick at a single scope, invoke the child skill (`/jmo-issue-triage`, `/jmo-dependabot-triage`, or `/jmo-tool-update-triage`) directly.

---

## Shared References

- [Memory Integration Pattern](references/memory-integration-pattern.md) — Cross-skill memory guide
- [AGENTS.md](../../AGENTS.md) — Repo-root AI tooling summary
- [CLAUDE.md](../../CLAUDE.md) — Full development guide

---

**Skills Count:** 20 | **Agents:** 7 | **MCP Tools:** 4
