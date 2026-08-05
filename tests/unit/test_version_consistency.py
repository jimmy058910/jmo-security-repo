#!/usr/bin/env python3
"""The three places the version is written must agree.

A release bumps `pyproject.toml`, `scripts/cli/jmo.py` and
`scripts/jmo_mcp/__init__.py` **by hand**, and until this test existed nothing
checked that all three moved together. A partial bump is not loud: the package
publishes under the new version while `jmo --version` keeps reporting the old
one, and the MCP server reports a third. Every consumer that pins behaviour to
a reported version - support triage, the docs' compatibility table, anything
reading the MCP handshake - is then working from a number that is wrong in a
way nothing announces.

The version is read from the source text with `ast`, not by importing the
modules. Importing `scripts.jmo_mcp` executes its package init and would tie
this guard to whether `mcp` is installed - the same coupling that turned an
ImportError into 235 silently uncollected tests during the mcp 2.0 rename. A
guard that a dependency problem can switch off is not a guard.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Every module carrying a hand-maintained copy of the version.
VERSION_SITES = (
    "scripts/cli/jmo.py",
    "scripts/jmo_mcp/__init__.py",
)


def _module_version(rel_path: str) -> str:
    """Return the module-level `__version__` literal, without importing."""
    source = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    for node in ast.parse(source).body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__version__":
                return str(ast.literal_eval(node.value))
    raise AssertionError(f"{rel_path} declares no module-level __version__")


def _pyproject_version() -> str:
    # tomllib needs bytes or a text handle; read_text keeps the encoding
    # explicit, which the repo requires everywhere.
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def test_all_version_sites_match_pyproject() -> None:
    """`pyproject.toml` is canonical; the other sites must equal it."""
    canonical = _pyproject_version()

    actual = {rel: _module_version(rel) for rel in VERSION_SITES}
    mismatched = {rel: got for rel, got in actual.items() if got != canonical}

    assert not mismatched, (
        f"pyproject.toml declares version {canonical!r}, but "
        f"{len(mismatched)} site(s) disagree: {mismatched}.\n"
        f"A release bumps all of these together - update the stragglers rather "
        f"than changing this test."
    )


def test_every_version_site_is_readable() -> None:
    """Guard the guard: a renamed or moved site must fail loudly.

    Without this, deleting `__version__` from a module - or moving the file -
    would make the comparison above vacuous rather than red.
    """
    for rel in VERSION_SITES:
        assert (REPO_ROOT / rel).is_file(), f"version site {rel} no longer exists"
        assert _module_version(rel), f"version site {rel} has an empty __version__"
