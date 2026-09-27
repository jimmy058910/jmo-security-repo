"""#1176: no class in the Docker e2e suite may shadow `DOCKER_REGISTRY`.

`tests/e2e/test_docker_workflows.py` reads `DOCKER_REGISTRY` from
`JMO_DOCKER_REGISTRY` at module level, so the whole suite can be pointed at an
image built from the working tree -- ci.yml's docker-smoke sets it to the image
it just built from the PR. `TestDockerCLIWorkflows` redefined the name as a
class attribute holding the published GHCR repo, and its one reader,
`self.DOCKER_REGISTRY`, resolved to that. Its seven cases therefore always
tested the published image and ignored the override, with no warning: a run
that looked like it audited working-tree code partly did not.

The check reads the file's AST, so it needs no Docker daemon and runs in every
shard, while the suite it protects runs only where a daemon exists.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_no_class_in_docker_workflows_shadows_the_registry():
    tree = ast.parse((REPO_ROOT / "tests/e2e/test_docker_workflows.py").read_bytes())
    shadows = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        for stmt in node.body
        if isinstance(stmt, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "DOCKER_REGISTRY" for t in stmt.targets
        )
    ]
    assert shadows == []
