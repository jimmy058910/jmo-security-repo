# Ralph CLI Testing - Operational Guide

## Unified Auto Mode v2.0

The Ralph Loop now uses a unified state management system with dual-mode wizard scanning.

### Quick Start

```powershell
# Run the unified auto loop
.\tools\ralph-testing\loop.ps1 -SkipPermissions

# With circuit breakers
.\tools\ralph-testing\loop.ps1 -SkipPermissions -MaxDurationMinutes 240 -MaxIterations 50

# Force fresh start (ignore cooldowns)
.\tools\ralph-testing\loop.ps1 -SkipPermissions -Force
```

### Auto Mode Decision Engine

The loop cycles through phases in this priority order:

1. **BUILD** - If open tasks exist in `IMPLEMENTATION_PLAN.md`
2. **WIZARD-SCAN** - If wizard needs attention (repo OR image mode)
3. **AUDIT** - If audit targets are off cooldown
4. **COMPLETE** - If all criteria met

### Completion Criteria

Auto mode exits when ALL are true:
- No open tasks in `IMPLEMENTATION_PLAN.md`
- Wizard REPO: 3 consecutive successes
- Wizard IMAGE: 3 consecutive successes
- All 6 audit targets on cooldown

### Unified State File

**File:** `tools/ralph-testing/unified-state.json`

```json
{
  "wizard_scan": {
    "repo": { "consecutive_successes": 0, "status": "in_progress", ... },
    "image": { "consecutive_successes": 0, "status": "not_started", ... },
    "required_successes": 3
  },
  "audits": {
    "wizard": { "status": "clean", "last_audit": "2026-01-29", ... },
    "cli": { "status": "partial", ... },
    ...
  },
  "tasks": { "open": 1, "resolved": 29, ... },
  "completion": { "is_complete": false, ... }
}
```

### Dual-Mode Wizard Scanning

| Mode | Target | Tests |
|------|--------|-------|
| **REPO** | `fixtures/juice-shop` (cloned repo) | SAST, secrets, SCA, IaC |
| **IMAGE** | `bkimminich/juice-shop:latest` | Container scanning, SBOM |

Selection logic runs whichever mode has fewer successes (repo if tied).

---

## Essential Commands

```bash
# Run tests (default)
python -m pytest tests/cli_ralph/ -v --tb=short

# Single test
python -m pytest tests/cli_ralph/test_help_version.py::test_version -v

# Skip slow tests
python -m pytest tests/cli_ralph/ -v -m "not slow"

# CLI commands
python -m scripts.cli.jmo --version
python -m scripts.cli.jmo tools check
python -m scripts.cli.jmo history list --db tools/ralph-testing/fixtures/test-history.db

# Migrate old state files to unified format
python tools/ralph-testing/migrate_state.py
```

## Commit Pattern

```bash
git add -A && git commit -m "test(wizard): description"
```

## Platform Notes (Windows)

- **Excluded tools:** falco, afl++, mobsf, akto
- **Tool paths:** Use `find_tool()`, not `shutil.which()` (OPA installs to `~/.jmo/bin/`)
- **HOME mocking:** Use `Path.home()` monkeypatch, not `HOME` env var

## Testing Infrastructure

- Fixtures: `tools/ralph-testing/fixtures/`
- Coverage target: `scripts/cli/wizard_flows/`
- Allow missing tools: `--allow-missing-tools`

## State Files

| File | Purpose |
|------|---------|
| `unified-state.json` | Single source of truth (v2.0) |
| `IMPLEMENTATION_PLAN.md` | Task tracking |
| `audit-state.json` | Legacy (read for backwards compat) |
| `wizard-scan-progress.md` | Legacy (human-readable backup) |

## Cross-Iteration Learnings

Read `tools/ralph-testing/iteration-logs/learnings.txt` for discoveries from previous tasks.
Append new learnings after completing each task (max 3 per task).

## Audit Targets

| Target | Focus | Cooldown |
|--------|-------|----------|
| security | CWE hunting across codebase | 7 days (clean) |
| core | history_db, normalize, dedup | 7 days (clean) |
| cli | jmo.py, scan_orchestrator | 7 days (clean) |
| adapters | 29 tool adapters | 7 days (clean) |
| reporters | 13 output formatters | 7 days (clean) |
| wizard | wizard.py, wizard_flows/ | 7 days (clean) |

Status-based cooldowns: clean=7 days, partial=3 days, issues=0 days

## Current Status

- 94+ tests, ~4 min runtime
- Tests: `tests/cli_ralph/*.py`
- Plan: `tools/ralph-testing/IMPLEMENTATION_PLAN.md`
- State: `tools/ralph-testing/unified-state.json`
