# Pre-Release Validation System Design

**Date:** 2026-02-26
**Status:** Approved
**Approach:** Monolithic `jmo validate` command (Approach A)

## Summary

A new `jmo validate` CLI subcommand that orchestrates 207 validation checks across 4 categories, producing a terminal scorecard with GO/NO-GO verdict. Two tiers: `--quick` (fixture-based, no tools needed) and `--full` (real tools, real scans).

## Architecture

### File Layout

```text
scripts/
├── cli/
│   └── validate_commands.py       # CLI dispatcher + terminal scorecard renderer
└── core/
    └── validators/
        ├── __init__.py            # ValidatorResult, CheckResult, base protocol
        ├── cli_validator.py       # CLI completeness checks (45)
        ├── scan_validator.py      # Adapter parsing, dedup, normalization (72)
        ├── platform_validator.py  # Cross-platform behavior checks (38)
        └── release_validator.py   # Version, CHANGELOG, Docker, docs (52)
```

### Integration Pattern

- Lazy import from `main()` in `jmo.py` (same pattern as `tool_commands.py`)
- New `_add_validate_args(sub)` function in `jmo.py`
- New `cmd_validate(args)` route in `main()`
- Absorbs and replaces `scripts/dev/pre_release_check.py` and `scripts/dev/verify_release_readiness.py`

### CLI Interface

```text
jmo validate [OPTIONS]

Options:
  --tier {quick|full}              Validation tier (default: quick)
  --category CAT[,CAT...]         Run specific categories only
                                   Values: cli, scans, platform, release
  --verbose, -v                    Show individual check details
  --fail-fast                      Stop on first failure
  --json                           Machine-readable JSON output
```

### Exit Codes

- 0 = all checks pass (GO)
- 1 = one or more failures (NO-GO)
- 2 = validation system error

### Output Format (Terminal Scorecard)

```text
JMo Security Validation Report
═══════════════════════════════════════════════════
Tier: quick | Platform: Windows 11 | Python: 3.12.1

CLI Completeness                          [45/45 PASS]
  ✓ 13 main subcommands have valid --help
  ✓ 27 sub-subcommands have valid --help
  ✓ 12 required-arg commands reject missing args
  ✓ 6 invalid-arg scenarios produce exit code 2
  ✓ 4 mutually exclusive groups enforced
  ✓ 6 flag type validations correct
  ✓ 3 version/identity checks pass
  ✓ 4 exit code contracts honored

Scan Correctness                          [72/72 PASS]
  ✓ 28 adapters load and parse fixture data
  ✓ 3 severity mapping checks pass
  ✓ 5 CommonFinding schema validations pass
  ✓ 6 empty/malformed input handlers work
  ✓ 12 deduplication pipeline checks pass
  ✓ 8 compliance enrichment checks pass
  ✓ 4 SBOM enrichment checks pass
  ✓ 8 reporter output checks pass

Cross-Platform                            [38/38 PASS]
  ✓ 8 path handling checks pass
  ✓ 4 subprocess security checks pass
  ✓ 3 home directory/config checks pass
  ✓ 5 file operation checks pass
  ✓ 4 environment variable checks pass
  ✓ 5 SQLite platform checks pass
  ✓ 4 process/threading checks pass

Release Artifacts                         [52/52 PASS]
  ✓ 6 version consistency checks pass
  ✓ 6 documentation link checks pass
  ✓ 4 tool version checks pass
  ✓ 2 badge accuracy checks pass
  ✓ 5 git hygiene checks pass
  ✓ 6 security checks pass
  ✓ 6 code quality checks pass
  ✓ 6 test health checks pass
  ✓ 5 schema/config file checks pass

═══════════════════════════════════════════════════
Result: 207/207 PASS | 0 WARN | 0 FAIL
Verdict: GO
```

## Validator Protocol

```python
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

class CheckStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"

@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    message: str = ""
    details: str = ""  # verbose-only extra info
    duration_ms: float = 0.0

@dataclass
class CategoryResult:
    name: str
    checks: list[CheckResult]

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def total(self) -> int:
        return len(self.checks)

class Validator(Protocol):
    def run(self, tier: str) -> CategoryResult: ...
```

## Check Inventory (207 total)

### Category 1: CLI Completeness (45 checks)

**Quick tier (37):**

| Group | Count | Checks |
|-------|-------|--------|
| Subcommand --help | 13 | wizard, scan, report, ci, fast, balanced, full, setup, tools, history, trends, diff, policy, adapters, schedule, mcp-server, attest, verify, build |
| Sub-subcommand --help | 27 | tools (8), history (13), trends (8), policy (5), schedule (9), build (3) |
| Required arg enforcement | 12 | history show/prune/query, policy validate/test/show/install, attest, verify, schedule create, trends show/compare |
| Invalid arg rejection | 6 | Across scan, report, tools, history, wizard, build |
| Mutually exclusive groups | 4 | scan targets, wizard execution mode, scan session, diff mode |
| Flag type validation | 6 | --threads, --timeout, --profile, --fail-on, --format, --jobs |
| Version/identity | 3 | Version match, format, semver valid |
| Exit code contracts | 4 | --help=0, missing-arg=2, no-findings=0, threshold-breach=1 |

**Full tier adds (8):**
tools check, tools list --profiles, adapters list, history stats, build validate, policy list, trends explain, diff --auto

### Category 2: Scan Correctness (72 checks)

**Quick tier (60):**

| Group | Count | Checks |
|-------|-------|--------|
| Adapter registry | 6 | All load, registry complete, naming correct, no duplicates, fallback works |
| Fixture parsing | 28 | Each adapter parses fixture → valid CommonFinding |
| Severity mapping | 3 | All adapters mapped, all tool severities covered, unknown handled |
| CommonFinding schema | 5 | Required fields, nested types, numeric ranges, extra fields, schema file valid |
| Empty/malformed input | 6 | Empty dict, empty list, None, truncated JSON, NUL bytes, 10k+ findings |
| Deduplication | 12 | Phase 1 exact, Phase 2 similarity, path normalization, threshold config, algorithm selection, consensus generation, determinism |
| Compliance enrichment | 8 | OWASP, CWE, CIS, NIST, PCI DSS, MITRE, unmapped findings, empty compliance |
| SBOM enrichment | 4 | Trivy-Syft cross, missing data, case-insensitive, multi-match |
| Reporter output | 8 | JSON, MD, HTML inline, HTML external, SARIF, CSV, empty findings, UTF-8 |

**Full tier adds (12):**
Real scan, E2E pipeline, real dedup reduction, dashboard renders, SARIF validates, JSON round-trips, >1000 findings mode, real compliance, priority enrichment, fingerprint stability, dedup determinism, consensus stability

### Category 3: Cross-Platform (38 checks)

**Quick tier (33):**

| Group | Count | Checks |
|-------|-------|--------|
| Path handling | 8 | Forward slashes, pathlib, mixed separators, relative, long, spaces, unicode, temp dir |
| Subprocess security | 4 | No shell=True, list args, no string formatting, tool_exists consistency |
| Home dir/config | 3 | Path.home(), .jmo/ creation, config path resolution |
| File operations | 5 | UTF-8, temp dirs, BOM, line endings, large files |
| Environment variables | 4 | JMO_THREADS, JMO_DEDUP_THRESHOLD, JMO_PROFILE, DOCKER_CONTAINER |
| SQLite platform | 5 | DB creation, WAL mode, timeout, VACUUM, lock release |
| Process/threading | 4 | cpu_count, thread pool, no hangs, Ctrl+C |

**Full tier adds (5):**
Docker daemon, volume mount, container jmo --version, WSL detection, WSL path access

### Category 4: Release Artifacts (52 checks)

**Quick tier (46):**

| Group | Count | Checks |
|-------|-------|--------|
| Version consistency | 6 | pyproject↔jmo.py, CHANGELOG entry, recent date, requires-python, semver, no pre-release |
| Documentation links | 6 | docs/*.md, README, CONTRIBUTING, QUICKSTART, anchors, external (full only) |
| Tool versions | 4 | versions.yaml valid, all tools have entries, no critical outdates, format valid |
| Badge accuracy | 2 | PyPI version, Python version |
| Git hygiene | 5 | Clean status, correct branch, no untracked scripts, no conflicts, signing |
| Security | 6 | No secrets, no shell=True, no large files, no artifacts tracked, path validation, suppression safe |
| Code quality | 6 | fmt clean, lint passes, import direction, no circular, pre-commit order, types |
| Test health | 6 | Test count, coverage >=85%, skip reasons, no sleeps, markers registered, conftest works |
| Schema/config | 5 | JSON schema valid, fields match, jmo.yml valid, suppress.yml valid, pre-commit valid |

**Full tier adds (6):**
4 Dockerfiles build, pip install, entry point works

## Design Decisions

1. **Lazy import** from main() — keeps `jmo scan` startup unaffected
2. **Each check is independent** — fail-fast is optional, default runs all
3. **No external dependencies** — quick tier needs only stdlib + project code
4. **Replaces pre_release_check.py and verify_release_readiness.py** — single source of truth
5. **JSON output** enables Claude Code to parse results programmatically
6. **Category filter** enables focused validation during development
7. **Timing per check** — identifies slow checks for optimization

## Implementation Strategy

Agent teams with isolated file ownership:
- **Lead**: Wires CLI (`jmo.py` + `validate_commands.py` + `__init__.py`)
- **Agent 1**: `cli_validator.py` (45 checks)
- **Agent 2**: `scan_validator.py` (72 checks)
- **Agent 3**: `platform_validator.py` (38 checks)
- **Agent 4**: `release_validator.py` (52 checks)
- **Agent 5**: Test suite (`tests/cli/test_validate_commands.py`, `tests/core/test_validators.py`)

## Test Plan

- Unit tests for each validator module
- Integration test: `jmo validate --quick` runs all 176 quick checks
- Integration test: `jmo validate --category cli` runs only CLI checks
- Integration test: `jmo validate --json` produces valid JSON
- Integration test: `jmo validate --fail-fast` stops on first failure
- Cross-platform: CI matrix runs validate on Windows + Linux + macOS
