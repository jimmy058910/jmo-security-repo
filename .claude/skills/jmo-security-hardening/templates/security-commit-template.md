# Security Commit Message Templates

Use this standardized template for all security fix commits.

---

## Template

```bash
git commit -m "$(cat <<'EOF'
fix(security): [FINDING-ID] Short description (CWE-XXX)

Security Fix: [FINDING-ID] - [Vulnerability Type]
CWE: CWE-XXX ([Weakness Name])
OWASP: [Category] ([Year])
Severity: [HIGH/MEDIUM/LOW]

Changes:
- Created [file.py] with sanitization functions
- Updated [file.py] to apply [defense mechanism]
- Added [X] security tests ([Y] fuzzing tests)

Defense Layers:
- Layer 1: [Sanitization/Validation/etc.]
- Layer 2: [Defense-in-depth mechanism]

Testing:
- [X]/[X] tests passing
- Bandit: 0 findings (was [N])
- Fuzzing: [Y]/[Y] malicious inputs blocked

Impact:
- Files changed: [N]
- Tests added: [X]
- Security posture: [BEFORE] -> [AFTER]

References:
- Finding: dev-only/security-fix-[ID].md
- CWE-XXX: https://cwe.mitre.org/data/definitions/XXX.html
- OWASP: [link]

Co-Authored-By: [Security Reviewer] <email>
EOF
)"
```

---

## Example: Path Traversal Fix

```bash
git commit -m "$(cat <<'EOF'
fix(security): MEDIUM-001 path traversal prevention (CWE-22)

Security Fix: MEDIUM-001 - Path Traversal in Directory Creation
CWE: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
OWASP: A01:2021 - Broken Access Control
Severity: MEDIUM

Changes:
- Created scripts/cli/path_sanitizers.py with _sanitize_path_component() and _validate_output_path()
- Updated scripts/cli/jmo.py to apply sanitization across all 6 target types
- Added 123 security tests (106 fuzzing tests)

Defense Layers:
- Layer 1: Input sanitization (removes traversal sequences, path separators, dangerous chars)
- Layer 2: Path validation (ensures output stays within results directory)

Testing:
- 123/123 tests passing
- Bandit: 0 findings (was 6 vulnerable code patterns)
- Fuzzing: 106/106 malicious inputs blocked

Impact:
- Files changed: 3 (1 new, 1 updated, 1 test file)
- Tests added: 123
- Security posture: 6 vulnerable target types -> 0 vulnerabilities

References:
- Finding: dev-only/security-fix-MEDIUM-001.md
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- OWASP A01: https://owasp.org/Top10/A01_2021-Broken_Access_Control/

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"
```
