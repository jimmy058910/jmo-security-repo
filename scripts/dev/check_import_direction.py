#!/usr/bin/env python3
"""
Dependency direction linter: enforces that core/MCP layers never import from CLI layer.

Rules:
  - scripts/core/** must NOT import from scripts/cli/
  - scripts/jmo_mcp/** must NOT import from scripts/cli/

Exit code 0 = clean, 1 = violations found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Directories whose files must not import from the CLI layer
RESTRICTED_DIRS = [
    REPO_ROOT / "scripts" / "core",
    REPO_ROOT / "scripts" / "jmo_mcp",
]

# Patterns that indicate a forbidden import from scripts.cli
FORBIDDEN_PATTERNS = [
    re.compile(r"^\s*from\s+scripts\.cli[\.\s]"),
    re.compile(r"^\s*import\s+scripts\.cli\b"),
]


def check_file(path: Path) -> list[str]:
    """Return list of violation messages for a single file."""
    violations: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return violations

    for lineno, line in enumerate(lines, 1):
        for pattern in FORBIDDEN_PATTERNS:
            if pattern.search(line):
                try:
                    rel = path.relative_to(REPO_ROOT)
                except ValueError:
                    rel = path
                violations.append(f"  {rel}:{lineno}: {line.strip()}")
    return violations


def main() -> int:
    violations: list[str] = []

    for directory in RESTRICTED_DIRS:
        if not directory.exists():
            continue
        for py_file in sorted(directory.rglob("*.py")):
            violations.extend(check_file(py_file))

    if violations:
        print("Dependency direction violations (core/MCP must not import from cli):")
        for v in violations:
            print(v)
        print(f"\n{len(violations)} violation(s) found.")
        return 1

    print("Import direction check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
