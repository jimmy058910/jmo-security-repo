"""Everything in the wizard's modules must be something `jmo wizard` can reach.

Five scan-flow classes (RepoFlow, EntireStackFlow, CICDFlow, DeploymentFlow,
DependencyFlow) lived here for releases with no caller outside their own tests
(issue #1301). Their tests passed, `docs/examples/wizard-examples.md` described
their recommendations as wizard features, and no user could reach any of it.
The wizard's own Dockerfile count disagreed with the scan's (issue #1411), and
nobody noticed, because only those unreachable flows ever counted.

The same held for `wizard_generators.py`: `generate_gitlab_ci` and
`generate_docker_compose` had only test callers, and so had the four
`generate_makefile_target` templates no caller selected.

The check is by name: a definition with no other mention anywhere under
`scripts/` has no caller. A mention in a docstring or an unrelated object of
the same name lets a definition through, so this can miss dead code, but it
cannot fail on live code. The package `__init__`'s re-exports do not count as
use: re-exporting is how the five survived.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PACKAGE = REPO / "scripts" / "cli" / "wizard_flows"
# The modules checked: the package (its __init__ only re-exports) and the
# artifact generators the wizard writes files with.
MODULES = [
    *(m for m in sorted(PACKAGE.glob("*.py")) if m.name != "__init__.py"),
    REPO / "scripts" / "cli" / "wizard_generators.py",
]


def _sources() -> dict[Path, str]:
    return {
        p: p.read_text(encoding="utf-8")
        for p in (REPO / "scripts").rglob("*.py")
        if p != PACKAGE / "__init__.py"
    }


def _top_level_definitions() -> list[tuple[Path, str]]:
    found = []
    for module in MODULES:
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                found.append((module, node.name))
    return found


def test_every_top_level_definition_has_a_caller() -> None:
    sources = _sources()
    unused = []
    for module, name in _top_level_definitions():
        word = re.compile(rf"\b{re.escape(name)}\b")
        # The definition itself is one mention in its own module.
        mentions = sum(len(word.findall(text)) for text in sources.values()) - 1
        if mentions == 0:
            unused.append(f"{module.relative_to(REPO)}: {name}")
    assert unused == [], (
        "defined in a wizard module but never used under scripts/ "
        "(jmo wizard cannot reach it; delete it with its tests):\n" + "\n".join(unused)
    )


def test_every_public_method_has_a_caller() -> None:
    """A method is used through an attribute: `.name` somewhere under scripts/.

    TargetDetector's Dockerfile and lock-file globs disagreed with the scan's own
    file selection (issue #1411), and the only callers they ever had were the
    five unreachable flows. A class that is used keeps its dead methods alive
    under the top-level check above, so this asks the same question per method.
    """
    sources = _sources()
    unused = []
    for module in MODULES:
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            for member in node.body:
                if not isinstance(member, ast.FunctionDef) or member.name.startswith(
                    "_"
                ):
                    continue
                attribute = re.compile(rf"\.{re.escape(member.name)}\b")
                if not any(attribute.search(text) for text in sources.values()):
                    unused.append(
                        f"{module.relative_to(REPO)}: {node.name}.{member.name}"
                    )
    assert unused == [], (
        "public methods in a wizard module that nothing under scripts/ calls:\n"
        + "\n".join(unused)
    )
