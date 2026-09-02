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

## The prose headers (#750)

Three code sites were never the whole surface. Documentation states the version
too, in a header or a footer, and nothing checked those - so `README.md` said
**v1.0.1** and `QUICKSTART.md` said **v1.0.0** while the project shipped 1.0.8,
across four releases. #750 was filed against `docs/CLI_REFERENCE.md`; by the
time Phase 8 reached it that one header had been corrected by hand at `92650ec`
and annotated as tracking `__version__`, while **eight others had gone stale**.
Fixing a header without a guard buys one release.

Only *current-release* claims are checked, and only in their three anchored
shapes. A **floor** is a different statement and stays exempt:
`docs/SAMPLE_OUTPUTS.md`'s `**Version:** v1.0.0+` says "1.0.0 or later", which
is still true and would be wrong to bump. Archival records are exempt for the
same reason they are in `check_doc_links` - a dated plan quoting the README's
v1.0.0 subtitle is reporting history, not claiming a version.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_CHECKER = REPO_ROOT / "scripts" / "dev" / "check_doc_links.py"

# Every module carrying a hand-maintained copy of the version.
VERSION_SITES = (
    "scripts/cli/jmo.py",
    "scripts/jmo_mcp/__init__.py",
)

# Anchored to the line shape, because prose legitimately names old versions:
# CLAUDE.md discusses v1.0.4 release archaeology, and CHANGELOG.md is nothing
# but old version numbers. Each of these says "this document describes the
# current release" and nothing else does.
_CURRENT_VERSION_CLAIMS = (
    re.compile(r"^\*\*Version:\*\*\s+v?(\d+\.\d+\.\d+)(?!\+)"),
    re.compile(r"^\*\*v(\d+\.\d+\.\d+)\*\*\s*\|"),
    re.compile(r"\|\s*\*\*JMo Security v(\d+\.\d+\.\d+)\*\*"),
    # Three more shapes that said "current release" and were never checked
    # (#1102): SECURITY.md's status heading read "(v1.0.0)" for eight
    # releases, and ROADMAP.md's two lines were correct only until the next
    # bump, which nothing would have caught.
    re.compile(r"^### Current Status \(v(\d+\.\d+\.\d+)\)"),
    re.compile(r"^\*\*Latest Stable Release:\*\*\s+v(\d+\.\d+\.\d+)"),
    re.compile(r"^\*\*Last Updated:\*\*.*\(v(\d+\.\d+\.\d+)\)"),
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


def _doc_link_checker():
    """Reuse the repo's own "tracked" and "archival" definitions, not a copy."""
    spec = importlib.util.spec_from_file_location("check_doc_links", str(DOC_CHECKER))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _documented_versions() -> list[tuple[str, int, str]]:
    """Every (file, line, version) where a tracked doc states a current release."""
    mod = _doc_link_checker()
    docs = sorted(
        p
        for p in mod.tracked_paths()
        if p.endswith(".md") and not p.startswith(mod.ARCHIVAL_PREFIXES)
    )
    # Coverage comes from git, so a gitignored file cannot make this red locally
    # and green in CI - the failure mode the #855 guard hit on its first run.
    assert len(docs) >= 100, f"doc discovery looks wrong: {len(docs)}"

    claims: list[tuple[str, int, str]] = []
    for rel in docs:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern in _CURRENT_VERSION_CLAIMS:
                match = pattern.search(line)
                if match:
                    claims.append((rel, lineno, match.group(1)))
    return claims


def test_documentation_version_headers_match_pyproject() -> None:
    """Regression for #750: a prose version header nothing checked."""
    canonical = _pyproject_version()
    claims = _documented_versions()

    # Meta-guard: an extractor that matches nothing passes on everything. These
    # three files are the ones whose headers were verified by hand.
    covered = {rel for rel, _, _ in claims}
    for expected in (
        "CLAUDE.md",
        "README.md",
        "docs/CLI_REFERENCE.md",
        "SECURITY.md",
        "ROADMAP.md",
    ):
        assert expected in covered, f"no version header found in {expected}"

    stale = [
        f"{rel}:{lineno}: states {found}, project is {canonical}"
        for rel, lineno, found in claims
        if found != canonical
    ]
    assert not stale, (
        "documentation states a project version that is not the current one. "
        "A release bumps these with pyproject.toml; a floor claim (v1.0.0+) is "
        "a different statement and is not matched here:\n" + "\n".join(stale)
    )
