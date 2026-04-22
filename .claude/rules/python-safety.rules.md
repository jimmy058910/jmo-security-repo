---
title: Python Safety & Security Standards
paths:
  - scripts/**/*.py
  - tests/**/*.py
  - "!tests/fixtures/**/*"
references:
  - CWE-78 (Improper Neutralization of Special Elements)
  - testing.cross-platform.rules.md (Windows hang prevention)
---

# Python Safety & Security Standards

**What this covers:** Subprocess security, secrets prevention, error-handling patterns, and code-review checkpoints for Python code across `scripts/` and `tests/`.

## Subprocess Invocation (CRITICAL SECURITY)

**CORRECT: List arguments (`shell=False` is default)**

```python
subprocess.run(["trivy", "image", image_name], capture_output=True, timeout=60)
```

**WRONG: String with `shell=True` — SECURITY VULNERABILITY (CWE-78)**

```python
subprocess.run(f"trivy image {image_name}", shell=True)  # DO NOT USE
```

**Why:** User input in shell commands allows injection attacks. Always use list form with `shell=False`.

## Subprocess Timeout (CRITICAL for Windows)

**ALWAYS pass `timeout=`** on every `subprocess.run()` call:

```python
# CORRECT
subprocess.run(cmd, timeout=60, capture_output=True)

# WRONG: No timeout → orphan processes on Windows
subprocess.run(cmd, capture_output=True)
```

See [testing.cross-platform.rules.md](testing.cross-platform.rules.md) for full Windows hang-prevention rules.

## Logging Standards

- JSON logs by default (stderr).
- Human-readable logs with the `--human-logs` CLI flag.
- Never log to stdout (reserved for programmatic output).
- Never log secrets, API keys, or auth tokens.

## Artifact Guardrails (enforced by pre-commit)

- No `venv/`, `__pycache__/`, `build/`, `dist/` in git.
- No files larger than 10MB (`check-added-large-files` hook).
- No secrets (`detect-private-key` hook + TruffleHog CI scan).

## Module Imports (Quality)

- Avoid circular imports.
- Use absolute imports: `from scripts.core import ...`, not `from . import ...`.
- Lazy-import expensive modules (e.g., `import trivy_parser` only inside the Trivy adapter function).

## Type Hints (Encouraged)

- Add type hints to public APIs.
- Use `from typing import ...` or PEP 585 generics (Python 3.9+).
- Internal functions don't strictly require hints, but public interfaces should have them.
