"""A filesystem probe on a user-supplied target must not crash the scan (#1163).

``Path.exists()`` is not a total function. Through Python 3.11 it swallowed
every ``OSError`` from the underlying ``stat`` and answered ``False``; 3.12
narrowed that to ``ValueError`` only, so ``PermissionError`` now *propagates*.
Nothing in target discovery guarded for it, so a path the process may not stat
produced an unhandled traceback and exit 1 instead of either a scan or a
legible refusal.

That is not a CI artifact. The published images run as ``USER jmo`` (uid 1000);
a user who bind-mounts a host directory owned by any other uid -- the default
for essentially every non-root host account -- hits it on the first run. It
shipped in v1.1.0.

The same shape appears at thirteen places in ``scan_orchestrator``: eight
``exists()`` probes, ``is_dir()`` and ``iterdir()`` on ``--repos-dir``, and the
three ``read_text()`` calls that consume a list file. A path the process cannot
stat is a path it cannot read, so the read side fails the same way from the
same cause. Fixing one flag is what makes the next one of these get filed, so
all thirteen go through the helpers and
``test_no_discovery_method_probes_the_filesystem_directly`` fails when a
fourteenth appears.

The discriminator that keeps the fix honest is
``test_a_missing_path_is_still_reported_as_missing``: swallowing the error and
calling everything "does not exist" would pass every other test in this file
while destroying the only signal that tells a typo apart from a mount problem.
"""

from __future__ import annotations

import ast
import inspect
import os
from pathlib import Path

import pytest

from scripts.cli.scan_orchestrator import ScanConfig, ScanOrchestrator

skip_as_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root bypasses the directory permissions this test relies on",
)
unix_only = pytest.mark.skipif(
    os.name == "nt",
    reason="chmod 0o000 does not deny traversal on Windows",
)


class _Args:
    """Only the attributes discovery reads; everything else defaults to None."""

    def __init__(self, **kw):
        defaults = {
            "repo": None,
            "repos_dir": None,
            "targets": None,
            "image": None,
            "images_file": None,
            "url": None,
            "urls_file": None,
            "api_spec": None,
            "terraform_state": None,
            "cloudformation": None,
            "k8s_manifest": None,
            "include": None,
            "exclude": None,
        }
        defaults.update(kw)
        for k, v in defaults.items():
            setattr(self, k, v)


@pytest.fixture
def orch(tmp_path):
    """ScanOrchestrator needs a ScanConfig; discovery does not read it."""
    return ScanOrchestrator(
        ScanConfig(tools=["trufflehog"], results_dir=tmp_path / "results")
    )


def _raise_on(monkeypatch, target: Path, method: str) -> None:
    """Make ``Path.<method>`` raise ``PermissionError`` for ``target`` only.

    Patching ``Path.exists`` outright would also break the probes this test is
    not about, and would let a fix that simply never probes anything pass. The
    error is what the kernel returns for EACCES; the assertions below are all
    on the orchestrator's own behaviour, never on this patch.
    """
    real = getattr(Path, method)

    def fake(self, *a, **kw):
        if self == target:
            raise PermissionError(13, "Permission denied")
        return real(self, *a, **kw)

    monkeypatch.setattr(Path, method, fake)


# --------------------------------------------------------------------------
# The real thing, with no patching at all
# --------------------------------------------------------------------------


@unix_only
@skip_as_root
def test_a_path_under_an_unreadable_directory_is_rejected_not_raised(tmp_path, orch):
    """The container's situation, reproduced on the host filesystem.

    A directory with no execute bit cannot be traversed, so ``stat`` on
    anything inside it returns EACCES -- which is exactly what a uid-1000
    container gets from a bind mount owned by uid 1001. No mock is involved:
    pre-fix this call raises ``PermissionError`` out of ``discover_targets``.
    """
    locked = tmp_path / "locked"
    locked.mkdir()
    inner = locked / "repo"
    inner.mkdir()
    os.chmod(str(locked), 0o000)
    try:
        targets = orch.discover_targets(_Args(repo=str(inner)))
    finally:
        os.chmod(str(locked), 0o700)

    assert targets.repos == [], "an unreadable path was accepted as a scan target"
    assert targets.rejected, "an unreadable path was dropped without comment"
    reason = "\n".join(targets.rejected)
    assert "--repo" in reason
    assert "uid 1000" in reason, (
        f"the refusal must name the ownership cause, or a user reads it as a "
        f"missing path and re-types it: {reason!r}"
    )


# --------------------------------------------------------------------------
# Every path-valued flag, one site each
# --------------------------------------------------------------------------

# Written out rather than derived from the orchestrator, so that emptying or
# renaming something in production cannot silently empty this list too.
PATH_FLAGS = [
    ("repo", "--repo"),
    ("repos_dir", "--repos-dir"),
    ("targets", "--targets"),
    ("images_file", "--images-file"),
    ("urls_file", "--urls-file"),
    ("api_spec", "--api-spec"),
    ("terraform_state", "--terraform-state"),
    ("cloudformation", "--cloudformation"),
    ("k8s_manifest", "--k8s-manifest"),
]


def test_the_flag_list_still_covers_every_path_valued_flag():
    """Canary for the parametrization below.

    A parametrize over an empty list reports one SKIPPED at exit 0, so the
    suite stays green while testing nothing (#1061). This is the assertion
    that cannot be satisfied by emptiness.
    """
    assert len(PATH_FLAGS) == 9, PATH_FLAGS


@pytest.mark.parametrize("attr, flag", PATH_FLAGS, ids=[f for _, f in PATH_FLAGS])
def test_an_unstattable_target_is_rejected_not_raised(
    attr, flag, tmp_path, monkeypatch, orch
):
    target = tmp_path / "target"
    target.mkdir()
    _raise_on(monkeypatch, target, "exists")

    targets = orch.discover_targets(_Args(**{attr: str(target)}))

    assert targets.rejected, f"{flag} dropped an unstattable path without comment"
    joined = "\n".join(targets.rejected)
    assert flag in joined, joined
    assert "Permission denied" in joined, joined


# --------------------------------------------------------------------------
# The sites a single exists() probe does not reach
# --------------------------------------------------------------------------


def test_a_repos_dir_that_cannot_be_typed_is_rejected(tmp_path, monkeypatch, orch):
    """``is_dir()`` raises from the same stat that ``exists()`` survived."""
    base = tmp_path / "repos"
    base.mkdir()
    _raise_on(monkeypatch, base, "is_dir")

    targets = orch.discover_targets(_Args(repos_dir=str(base)))

    assert targets.repos == []
    assert "Permission denied" in "\n".join(targets.rejected), targets.rejected


def test_a_repos_dir_that_cannot_be_listed_is_rejected(tmp_path, monkeypatch, orch):
    """``iterdir()`` is a third syscall, and fails independently of the first two."""
    base = tmp_path / "repos"
    (base / "alpha").mkdir(parents=True)
    _raise_on(monkeypatch, base, "iterdir")

    targets = orch.discover_targets(_Args(repos_dir=str(base)))

    assert targets.repos == []
    assert "Permission denied" in "\n".join(targets.rejected), targets.rejected


def test_a_listed_path_inside_a_targets_file_is_rejected_individually(
    tmp_path, monkeypatch, orch
):
    """The file is readable; one path it names is not.

    The other listed repo must still be scanned -- one bad entry is not a
    reason to discard the run.
    """
    good = tmp_path / "good"
    good.mkdir()
    bad = tmp_path / "bad"
    bad.mkdir()
    listing = tmp_path / "targets.txt"
    listing.write_text(f"{good}\n{bad}\n", encoding="utf-8")
    _raise_on(monkeypatch, bad, "exists")

    targets = orch.discover_targets(_Args(targets=str(listing)))

    assert [p.name for p in targets.repos] == ["good"], targets.rejected
    assert "Permission denied" in "\n".join(targets.rejected), targets.rejected


READ_FLAGS = [
    ("targets", "--targets"),
    ("images_file", "--images-file"),
    ("urls_file", "--urls-file"),
]


@pytest.mark.parametrize("attr, flag", READ_FLAGS, ids=[f for _, f in READ_FLAGS])
def test_a_list_file_that_stats_but_cannot_be_read_is_rejected(
    attr, flag, tmp_path, monkeypatch, orch
):
    """``exists()`` answering True does not promise ``read_text()`` will work.

    A traversable directory holding a mode-000 file gives exactly this: the
    stat succeeds, the open does not.
    """
    listing = tmp_path / "list.txt"
    listing.write_text("# empty\n", encoding="utf-8")
    _raise_on(monkeypatch, listing, "read_text")

    targets = orch.discover_targets(_Args(**{attr: str(listing)}))

    joined = "\n".join(targets.rejected)
    assert flag in joined, joined
    assert "Permission denied" in joined, joined


# --------------------------------------------------------------------------
# The discriminator, and the structural guard
# --------------------------------------------------------------------------


def test_a_missing_path_is_still_reported_as_missing(tmp_path, orch):
    """The negative control this fix is most likely to break.

    Catching ``OSError`` and reporting everything as unreadable would satisfy
    every other test here and destroy the distinction a user needs: a typo and
    a permissions problem have different fixes.
    """
    targets = orch.discover_targets(_Args(repo=str(tmp_path / "nope")))

    joined = "\n".join(targets.rejected)
    assert "does not exist" in joined, joined
    assert (
        "uid 1000" not in joined
    ), f"a merely absent path was blamed on ownership: {joined!r}"


def test_no_discovery_method_probes_the_filesystem_directly():
    """Guards the decision, not just today's thirteen call sites.

    #1163 left open whether the guard covers one flag or all of them. The
    answer was all, so a bare ``.exists()`` added to discovery later is a
    regression -- this fails when one appears rather than waiting for the next
    user to hit it. The helpers are module-level, so scoping the walk to the
    ``_discover_*`` methods leaves them free to make the calls for real.
    """
    import scripts.cli.scan_orchestrator as mod

    unguarded = {"exists", "is_dir", "iterdir", "read_text"}
    tree = ast.parse(inspect.getsource(mod))
    visited: list[str] = []
    offenders: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith(
            "_discover_"
        ):
            continue
        visited.append(node.name)
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr in unguarded
            ):
                offenders.append(
                    f"{node.name} line {inner.lineno}: .{inner.func.attr}()"
                )

    assert len(visited) >= 6, (
        f"the walk found only {visited} -- if discovery was renamed this guard "
        f"is inert, not passing"
    )
    assert not offenders, (
        "filesystem probes in discovery must go through _probe/_probe_children/"
        "_read_lines so an OSError becomes a rejection: " + "; ".join(offenders)
    )
