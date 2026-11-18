"""The built-in policies reach an installed wheel, and one resolver finds them.

The five Rego policies live at `policies/builtin/` in the repository root,
outside the `scripts` package. Until setup.py copied them, no wheel carried a
single `.rego` file: `jmo policy list` from an installed wheel printed "No
policies found" and `jmo report --policy zero-secrets` with enforcement on
exited 0 over a verified secret. An in-tree run cannot show that, because the
editable install imports the checkout, where a walk up to the repository root
succeeds.

These tests read the packaging declarations, so they run on every shard,
Windows included. The wheel itself is built and installed in
tests/integration/test_wheel_install.py, which is `slow`: the Ubuntu and macOS
shards run it, and the Windows shard does not.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "policies" / "builtin"


def _tracked_policies() -> list[str]:
    names = sorted(
        p.relative_to(REPO_ROOT).as_posix() for p in POLICY_DIR.glob("*.rego")
    )
    # A glob that finds nothing would make every check below vacuous.
    assert names, f"no .rego file under {POLICY_DIR}"
    assert "policies/builtin/zero-secrets.rego" in names, names
    return names


def _setup_py_globs() -> dict[str, str]:
    """setup.py's SHIPPED_GLOBS, read without running setup()."""
    tree = ast.parse((REPO_ROOT / "setup.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "SHIPPED_GLOBS" for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("setup.py defines no SHIPPED_GLOBS")


def test_setup_py_copies_every_builtin_policy_where_the_resolver_looks() -> None:
    """Each tracked policy matches a SHIPPED_GLOBS pattern whose wheel directory
    is the one `builtin_policies_dir()` reads in an installed wheel."""
    from scripts.core import policy_engine

    packaged = Path(policy_engine.__file__).resolve().parent / "policies" / "builtin"
    wanted = packaged.relative_to(REPO_ROOT).as_posix()
    globs = _setup_py_globs()
    # Matched as setup.py matches them, with Path.glob from the repository root.
    copied = {
        p.relative_to(REPO_ROOT).as_posix()
        for pattern, dest in globs.items()
        if dest == wanted
        for p in REPO_ROOT.glob(pattern)
    }
    uncovered = sorted(set(_tracked_policies()) - copied)
    assert not uncovered, (
        f"setup.py SHIPPED_GLOBS = {globs} does not copy {uncovered} into {wanted}"
    )


def test_the_sdist_carries_every_builtin_policy() -> None:
    """The release builds its wheel from the sdist, so setup.py there sees only
    what MANIFEST.in put in it."""
    includes = [
        pattern
        for line in (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
        if line.startswith("include ")
        for pattern in line.split()[1:]
    ]
    # Path.glob, not fnmatch: fnmatch's `*` crosses `/`, MANIFEST.in's does not.
    carried = {
        p.relative_to(REPO_ROOT).as_posix()
        for pattern in includes
        for p in REPO_ROOT.glob(pattern)
    }
    missing = sorted(set(_tracked_policies()) - carried)
    assert not missing, f"MANIFEST.in include lines {includes} miss {missing}"


def test_only_policy_engine_builds_the_builtin_policy_path() -> None:
    """Four modules each built `.../policies/builtin` from their own __file__,
    and each was wrong from a wheel. The property: one module resolves it.
    An AST scan for `<expr> / "builtin"` where the left side ends in
    "policies", so a docstring or comment naming the path is not counted."""
    builders = []
    for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
        # The dashboard's node_modules is vendored, untracked and not ours.
        if "node_modules" in path.parts:
            continue
        tree = ast.parse(path.read_bytes().decode("utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.BinOp)
                and isinstance(node.op, ast.Div)
                and isinstance(node.right, ast.Constant)
                and node.right.value == "builtin"
                and isinstance(node.left, ast.BinOp)
                and isinstance(node.left.right, ast.Constant)
                and node.left.right.value == "policies"
            ):
                builders.append(
                    f"{path.relative_to(REPO_ROOT).as_posix()}:{node.lineno}"
                )
    modules = {b.split(":")[0] for b in builders}
    # Meta-guard: the scan must still see the one legitimate builder.
    assert "scripts/core/policy_engine.py" in modules, builders
    assert modules == {"scripts/core/policy_engine.py"}, (
        f"build the path with policy_engine.builtin_policies_dir(): {builders}"
    )


def test_the_resolver_prefers_a_packaged_copy(tmp_path, monkeypatch) -> None:
    """Laid out as a wheel installs it: no repository root above site-packages."""
    from scripts.core import policy_engine

    module = tmp_path / "site-packages" / "scripts" / "core" / "policy_engine.py"
    packaged = module.parent / "policies" / "builtin"
    packaged.mkdir(parents=True)
    (packaged / "zero-secrets.rego").write_bytes(b"package jmo.policy.secrets\n")
    monkeypatch.setattr(policy_engine, "__file__", str(module))

    assert policy_engine.builtin_policies_dir() == packaged


def test_the_resolver_falls_back_to_the_checkout() -> None:
    """The source checkout, the editable install and the Docker image have no
    packaged copy and read policies/builtin/ itself."""
    from scripts.core.policy_engine import builtin_policies_dir

    assert builtin_policies_dir().resolve() == POLICY_DIR.resolve()
