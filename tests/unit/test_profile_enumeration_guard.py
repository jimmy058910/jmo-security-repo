#!/usr/bin/env python3
"""Guard: no module may hardcode a partial list of scan profile names.

Regression guard for #721. The `slim` profile was added to
`tool_registry.PROFILE_TOOLS` but never propagated to the eight places that
enumerated profiles by hand, so slim scans were rejected by the history
database, both wizard flows, `jmo schedule create/update --profile`, and
`jmo history store/list --profile`.

Fixing those eight sites fixes the instance. This test fixes the class: adding
a ninth profile to the registry now fails here rather than silently producing a
half-supported profile.

The check is deliberately narrow -- it flags only a literal sequence whose
elements are *all* profile names and which is a *proper subset* of the
registry. `sorted(PROFILE_TOOLS)` and unrelated string lists are untouched.
"""

from __future__ import annotations

import ast
from pathlib import Path

from scripts.core.tool_registry import PROFILE_TOOLS

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"


def _literal_string_sequences(tree: ast.AST):
    """Yield (lineno, tuple-of-strings) for every list/tuple/set literal."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = []
            for element in node.elts:
                if isinstance(element, ast.Constant) and isinstance(element.value, str):
                    values.append(element.value)
                else:
                    break
            else:
                if values:
                    yield node.lineno, tuple(values)


# A deliberately curated subset declares itself at the site. The wizard flows
# offer narrowed choices on purpose (CI/CD should not run `deep`; a production
# deployment should not run `fast`), and that is design, not drift. Requiring
# the marker keeps intent distinguishable from an enumeration nobody updated.
EXEMPTION_MARKER = "curated-profile-subset:"


def _is_exempt(lines: list[str], lineno: int) -> bool:
    """True if the marker appears on the literal's line or the two above it."""
    start = max(0, lineno - 3)
    return any(EXEMPTION_MARKER in line for line in lines[start:lineno])


def find_partial_profile_enumerations(scripts_dir: Path | None = None) -> list[str]:
    """Return 'path:line -> [...]' for each hardcoded partial profile list."""
    scripts_dir = scripts_dir or SCRIPTS_DIR
    known = set(PROFILE_TOOLS)
    violations: list[str] = []

    for path in sorted(scripts_dir.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue  # templates and generated files are not our concern

        lines = source.splitlines()
        for lineno, values in _literal_string_sequences(tree):
            unique = set(values)
            if len(unique) >= 2 and unique < known and not _is_exempt(lines, lineno):
                rel = path.relative_to(scripts_dir.parent).as_posix()
                violations.append(f"{rel}:{lineno} -> {list(values)}")

    return violations


def test_no_module_hardcodes_a_partial_profile_list():
    """Every profile enumeration must derive from PROFILE_TOOLS.

    Fails if a module lists some-but-not-all profile names literally. Derive
    from the registry instead:

        choices=sorted(PROFILE_TOOLS)
    """
    violations = find_partial_profile_enumerations()
    assert not violations, (
        "these modules hardcode a partial profile list and will silently "
        "exclude any profile added to PROFILE_TOOLS (#721):\n  "
        + "\n  ".join(violations)
    )


def test_guard_detects_a_planted_violation(tmp_path):
    """The guard must be able to fail.

    A guard that cannot fail is indistinguishable from no guard -- which is
    exactly how the original enumeration survived. This plants a violation and
    asserts it is caught.
    """
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir(parents=True)
    partial = sorted(PROFILE_TOOLS)[:2]
    (scripts_dir / "planted.py").write_text(
        f"choices = {partial!r}\n", encoding="utf-8"
    )

    violations = find_partial_profile_enumerations(scripts_dir)
    assert any(
        "planted.py" in v for v in violations
    ), f"guard failed to detect a planted partial enumeration {partial}"


def test_guard_allows_the_full_registry(tmp_path):
    """Deriving from the registry must not be flagged.

    Without this, the guard could be "passed" by listing every profile
    literally, which would drift again on the next addition.
    """
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir(parents=True)
    (scripts_dir / "derived.py").write_text(
        "from scripts.core.tool_registry import PROFILE_TOOLS\n"
        "choices = sorted(PROFILE_TOOLS)\n",
        encoding="utf-8",
    )

    assert find_partial_profile_enumerations(scripts_dir) == []
