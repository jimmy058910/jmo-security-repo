---
name: jmo-security-hardening
description: Implement security fixes following OWASP/CWE best practices for CSRF, command injection, path traversal, and missing security headers. Use when security audit findings need remediation.
argument-hint: <CWE-ID or vulnerability-type>
user-invocable: true
context: fork
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

## Execution

Harden against: **$ARGUMENTS**

---

## Purpose

Implement security fixes following OWASP/CWE best practices for JMo Security codebase by:

1. **Implementing OWASP-compliant fixes** for HIGH/MEDIUM findings
2. **Generating security test suites** with fuzzing and edge cases
3. **Adding input validation** and sanitization layers
4. **Applying defense-in-depth** patterns

---

**Approach:** Evaluate from an attacker's perspective -- 'what is the simplest exploit path?' -- then implement the fix with least code change.

## When to Use This Skill

Use this skill when you encounter security findings from:

- **Security audit reports** (Bandit, Semgrep, Trufflehog scans)
- **Manual code review** (identified vulnerabilities)
- **Penetration testing** results
- **CVE advisories** affecting dependencies

**Primary Use Cases:**

| Finding | Vulnerability | Target |
|---------|--------------|--------|
| HIGH-001 | CSRF Protection | Express API (Cloudflare Turnstile) |
| HIGH-002 | Shell Injection | wizard.py (shell=True -> list args) |
| MEDIUM-001 | Path Traversal | jmo.py (6 target types) |
| MEDIUM-002 | Missing Headers | html_reporter.py (CSP, X-Frame-Options) |
| MEDIUM-005 | Try-except-pass | Various (add logging) |

---

## How It Works

### Phase 1: Vulnerability Analysis

- Read target file(s), identify vulnerability type (CSRF, injection, traversal, etc.)
- Map attack surface (user input points, dangerous operations)
- Determine OWASP/CWE categorization

### Phase 2: Fix Generation

- Generate security patches based on best practices
- Create validation/sanitization functions
- Implement defense-in-depth layers

### Phase 3: Test Generation

- Security test suite (120-150 total tests for comprehensive fixes)
- Fuzzing tests (100-120 parametrized malicious inputs)
- Unit tests (8-12 tests for normal/edge cases)
- Integration + regression tests

### Phase 4: Validation

- Run security scanners (Bandit, Semgrep)
- Verify fix effectiveness and check for bypass techniques

---

## Usage

### Basic Invocation

```bash
# Fix CSRF vulnerability
claude skill jmo-security-hardening \
  --finding-id HIGH-001 \
  --target scripts/api/subscribe_endpoint.js \
  --vulnerability csrf
```

### Advanced Options

```bash
# Fix path traversal with custom sanitization across all targets
claude skill jmo-security-hardening \
  --finding-id MEDIUM-001 \
  --target scripts/cli/jmo.py \
  --vulnerability path_traversal \
  --sanitizer-name _sanitize_path_component \
  --apply-to-all-targets
```

### Batch Fix

```bash
# Fix all HIGH findings at once
claude skill jmo-security-hardening \
  --findings HIGH-001,HIGH-002 \
  --auto-detect-targets \
  --dry-run  # Preview fixes first
```

---

## Parameters

### Required

- `--finding-id ID`: Security finding ID from audit report (e.g., HIGH-001)
- `--target PATH`: File to patch
- `--vulnerability TYPE`: Type of vulnerability to fix

### Vulnerability Types

| Type | CWE | Description |
|------|-----|-------------|
| `csrf` | CWE-352 | CSRF token validation, CAPTCHA verification |
| `shell_injection` | CWE-78 | Replace shell=True with list-based args, input sanitization |
| `path_traversal` | CWE-22 | Sanitization functions, path validation |
| `missing_headers` | CWE-693 | CSP, X-Frame-Options, X-Content-Type-Options |
| `try_except_pass` | CWE-703 | Add logging, replace broad exceptions |
| `input_validation` | - | Validation decorators, edge case tests |

### Optional

- `--sanitizer-name NAME`: Custom name for sanitization function (default: auto-generated)
- `--apply-to-all-targets`: Apply fix to all similar code patterns
- `--security-level LEVEL`: Strictness (paranoid/strict/balanced/lenient, default: strict)
- `--dry-run`: Preview fixes without applying
- `--skip-tests`: Skip test generation (not recommended)
- `--generate-docs`: Generate security documentation

---

## Examples

Two key examples are shown below. For all vulnerability types with full generated code,
see [examples/vulnerability-fix-examples.md](examples/vulnerability-fix-examples.md).

### Shell Injection Fix (HIGH-002)

```bash
claude skill jmo-security-hardening \
  --finding-id HIGH-002 \
  --target scripts/cli/wizard.py \
  --vulnerability shell_injection
```

Replaces `shell=True` with list-based subprocess args via `generate_docker_args()`,
validates all command arguments, and generates 50-input fuzzing test suite.

### Path Traversal Fix (MEDIUM-001)

```bash
claude skill jmo-security-hardening \
  --finding-id MEDIUM-001 \
  --target scripts/cli/jmo.py \
  --vulnerability path_traversal \
  --apply-to-all-targets
```

Creates `_sanitize_path_component()` and `_validate_output_path()` utilities,
applies to all 6 target types, and generates 100-input fuzzing test suite.

---

## Output

### 1. Patched Source Files

- Security fixes applied with input validation and sanitization
- Security comments explaining each fix

### 2. Security Test Suite

- Positive tests (valid inputs accepted)
- Negative tests (malicious inputs blocked)
- Fuzzing tests (100+ malicious inputs)
- Regression tests (vulnerability stays fixed)

### 3. Security Report

Generated at `dev-only/security-fix-[FINDING-ID].md` with vulnerability summary,
fix details, validation results, and deployment checklist.

### 4. Security Documentation

- Threat model updates, Security.md updates, monitoring recommendations

---

## Best Practices

### Before Applying Fixes

1. **Understand the vulnerability:** Read finding details, not just ID
2. **Review attack scenarios:** Know how exploit works
3. **Check existing mitigations:** Don't duplicate defenses
4. **Commit current work:** `git commit` before security changes
5. **Check Python compatibility:** See [references/python-compat.md](references/python-compat.md)

### During Fix Application

1. **Start with --dry-run:** Preview changes
2. **One vulnerability at a time:** Don't batch HIGH + MEDIUM
3. **Verify fix effectiveness:** Test with malicious inputs

### After Applying Fixes

1. **Run security scanners:** `bandit`, `semgrep`, `trufflehog`
2. **Test exploit prevention:** Try actual attack
3. **Prepare rollback plan:** See [references/rollback-performance.md](references/rollback-performance.md)
4. **Commit with security context:** See [templates/security-commit-template.md](templates/security-commit-template.md)

---

## Integration with Other Skills

| Order | Skill | Purpose |
|-------|-------|---------|
| BEFORE | security-auditor | Discover vulnerabilities, get finding IDs |
| WITH | coverage-gap-finder | Ensure >90% coverage for security paths |
| AFTER | jmo-test-fabricator | Expand security tests with edge cases |
| AFTER | security-auditor (re-run) | Validate fixes, confirm 0 HIGH findings |

---

## Success Metrics

After using this skill, you should see:

- **0 HIGH security findings** (from 2)
- **0 MEDIUM security findings** (from 6)
- **Security test coverage:** 100% for patched code
- **Scanners clean:** Bandit, Semgrep, Trufflehog green
- **Fuzzing resistant:** 100+ malicious inputs blocked

---

## Example Workflow

```bash
# Phase 0: Fix HIGH findings
claude skill jmo-security-hardening --finding-id HIGH-001 --target scripts/api/subscribe_endpoint.js --vulnerability csrf
claude skill jmo-security-hardening --finding-id HIGH-002 --target scripts/cli/wizard.py --vulnerability shell_injection

# Phase 1: Fix MEDIUM findings
claude skill jmo-security-hardening --finding-id MEDIUM-001 --target scripts/cli/jmo.py --vulnerability path_traversal --apply-to-all-targets
claude skill jmo-security-hardening --finding-id MEDIUM-002 --target scripts/core/reporters/html_reporter.py --vulnerability missing_headers

# Validate all fixes
bandit -r scripts/ -f json
semgrep --config=auto scripts/
make test
```

---

## Reference Documents

| Document | Contents |
|----------|----------|
| [examples/vulnerability-fix-examples.md](examples/vulnerability-fix-examples.md) | Full fix examples with generated code for all 4 vulnerability types |
| [references/browser-compat.md](references/browser-compat.md) | Browser support matrix, fallback strategies for web security fixes |
| [references/python-compat.md](references/python-compat.md) | Python version compatibility patterns (Path.is_relative_to, etc.) |
| [references/rollback-performance.md](references/rollback-performance.md) | Rollback procedures, gradual rollout, performance overhead, optimization |
| [references/limitations.md](references/limitations.md) | Known limitations, edge cases, troubleshooting |
| [references/memory-integration.md](references/memory-integration.md) | Memory caching for OWASP fixes, CWE patterns, test templates |
| [templates/security-commit-template.md](templates/security-commit-template.md) | Standardized security commit message format |
| [templates/security-test-naming.md](templates/security-test-naming.md) | Test naming conventions, class organization, docstring templates |

---

## Related Findings

This skill addresses: HIGH-001 (CSRF), HIGH-002 (Shell Injection), MEDIUM-001 (Path Traversal), MEDIUM-002 (Missing Headers), MEDIUM-005 (Try-except-pass) -- 2 HIGH + 3 MEDIUM = 5 security issues.
