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

### Basic invocation

```text
/jmo-security-hardening csrf in scripts/api/subscribe_endpoint.js (HIGH-001)
```

### Naming a sanitizer, or a whole class of sites

```text
/jmo-security-hardening path_traversal in scripts/cli/jmo.py (MEDIUM-001),
reusing _sanitize_path_component, across every target type
```

### Several findings at once

```text
/jmo-security-hardening HIGH-001 and HIGH-002 -- show me each patch before
anything is written
```

Everything after the skill name is one string, so ask for what you want in that
sentence. See [Invocation](#invocation) for what asking does and does not
guarantee.

---

## Invocation

This is a Claude Code skill, not a command-line program. There is no argument
parser: the frontmatter declares `argument-hint: <CWE-ID or vulnerability-type>`,
and `$ARGUMENTS` (line 12) receives everything after the skill name as one
string.

```text
/jmo-security-hardening shell_injection in scripts/cli/wizard.py (HIGH-002)
```

Name the vulnerability, the file and the finding id in plain language. The
vocabulary below belongs in that sentence; it is not a flag set.

> **Removed, not reworded.** Earlier revisions documented `--finding-id`,
> `--target`, `--vulnerability`, `--sanitizer-name`, `--apply-to-all-targets`,
> `--security-level`, `--dry-run`, `--skip-tests`, `--generate-docs`,
> `--findings` and `--auto-detect-targets` as options, and showed
> `claude skill jmo-security-hardening ...` as the way to run it. **None was
> ever implemented** -- nothing in this repository parses any of them, and that
> is not the invocation form either. They are deleted rather than corrected
> because `--dry-run` reads as a guarantee that nothing is written, `--skip-tests`
> reads as a supported way to ship a security fix without tests, and
> `--security-level ... (default: strict)` reads as a default that is being
> applied. All three are false, and the last two are false about a security tool.

### Vulnerability Types

| Type | CWE | Description |
|------|-----|-------------|
| `csrf` | CWE-352 | CSRF token validation, CAPTCHA verification |
| `shell_injection` | CWE-78 | Replace shell=True with list-based args, input sanitization |
| `path_traversal` | CWE-22 | Sanitization functions, path validation |
| `missing_headers` | CWE-693 | CSP, X-Frame-Options, X-Content-Type-Options |
| `try_except_pass` | CWE-703 | Add logging, replace broad exceptions |
| `input_validation` | - | Validation decorators, edge case tests |

### Scope and Safety

File access is whatever `allowed-tools` grants (`Read, Write, Edit, Glob, Grep,
Bash`), mediated by Claude Code's permission prompts. The expectations behind the
removed flags are worth keeping -- as working rules for whoever runs the skill,
not as settings that enforce themselves:

| Working rule | What actually enforces it |
|---|---|
| Preview before writing | **Nothing.** Ask for the patch in your prompt and read it, or commit first so `git diff` is the preview |
| A security fix ships with tests | **Nothing.** The tests are this skill's value; if you skip them, say so in the commit rather than in a flag |
| Apply the strictest safe fix | **Nothing.** There is no strictness setting; state the level you want in the sentence |
| Reuse the existing sanitizers | `scripts/cli/path_sanitizers.py` already has `_sanitize_path_component` and `_validate_output_path`. Do not write a second pair |

---

## Examples

Two key examples are shown below. For all vulnerability types with full generated code,
see [examples/vulnerability-fix-examples.md](examples/vulnerability-fix-examples.md).

### Shell Injection Fix (HIGH-002)

```text
/jmo-security-hardening shell_injection in scripts/cli/wizard.py (HIGH-002)
```

Replaces `shell=True` with list-based subprocess args via `generate_docker_args()`,
validates all command arguments, and generates 50-input fuzzing test suite.

### Path Traversal Fix (MEDIUM-001)

```text
/jmo-security-hardening path_traversal in scripts/cli/jmo.py (MEDIUM-001), across every target type
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
5. **Reuse the existing helpers:** path validation already lives in
   `scripts/cli/path_sanitizers.py` (`_sanitize_path_component`,
   `_validate_output_path`) -- don't write a second one

### During Fix Application

1. **Ask for the patch first:** read it before it is written -- nothing previews for you
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
- **0 MEDIUM security findings** (from 3)
- **Security test coverage:** 100% for patched code
- **Scanners clean:** Bandit, Semgrep, Trufflehog green
- **Fuzzing resistant:** 100+ malicious inputs blocked

---

## Example Workflow

```text
Phase 0, the HIGH findings, one invocation each:

  /jmo-security-hardening csrf in scripts/api/subscribe_endpoint.js (HIGH-001)
  /jmo-security-hardening shell_injection in scripts/cli/wizard.py (HIGH-002)

Phase 1, the MEDIUM findings:

  /jmo-security-hardening path_traversal in scripts/cli/jmo.py (MEDIUM-001), across every target type
  /jmo-security-hardening missing_headers in scripts/core/reporters/html_reporter.py (MEDIUM-002)
```

Then validate, which is a real shell:

```bash

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
| [references/rollback-performance.md](references/rollback-performance.md) | Rollback procedures, gradual rollout, performance overhead, optimization |
| [references/limitations.md](references/limitations.md) | Known limitations, edge cases, troubleshooting |
| [references/memory-integration.md](references/memory-integration.md) | Memory caching for OWASP fixes, CWE patterns, test templates |
| [templates/security-commit-template.md](templates/security-commit-template.md) | Standardized security commit message format |
| [templates/security-test-naming.md](templates/security-test-naming.md) | Test naming conventions, class organization, docstring templates |

---

## Related Findings

This skill addresses: HIGH-001 (CSRF), HIGH-002 (Shell Injection), MEDIUM-001 (Path Traversal), MEDIUM-002 (Missing Headers), MEDIUM-005 (Try-except-pass) -- 2 HIGH + 3 MEDIUM = 5 security issues.
