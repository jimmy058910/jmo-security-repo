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
- make fmt && make lint && make test: clean
- [X]/[X] tests passing
- Coverage: [NN]% (CI floor: 85%)
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
- make fmt && make lint && make test: clean
- 123/123 tests passing
- Coverage: 87% (CI floor: 85%)
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
EOF
)"
```

---

## Two rules this template must not break

**No AI-attribution trailers.** The example above deliberately ends at the
references block. This repo's commit convention is conventional-commit subject
lines with **no AI-attribution markers** in commits or PRs, so a
`Co-Authored-By: Claude ...` line does not belong in a JMo commit. The
`Co-Authored-By` slot in the template is for a **human** security reviewer, and
only after that person has agreed — a copied trailer otherwise attributes
authorship to someone who never saw the change.

**The coverage numbers above are reported, not gated.** Grepping for the
threshold is misleading here: `--cov-fail-under=85` appears in `.claude/` prose
but in no executable path. `make test` runs `pytest ... --cov
--cov-report=term-missing` with no `--cov-fail-under`, and
`[tool.coverage.report]` in `pyproject.toml` sets no `fail_under`. The only
enforced floor is **85%**, in `coverage-aggregate`'s "Verify coverage threshold" step. Put the real
measured percentage in the commit; do not claim a gate that will not fire.
