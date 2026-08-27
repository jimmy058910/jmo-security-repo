"""The spawn recorder must not be scoped to last time's binary (#994).

The recorder added under #907 watched `semgrep` and nothing else, and that
scope was itself a blind spot. #976 item 2 reported `test_no_deps_skips_menu`
spawning a real `bandit`; running it produced **no guard error**, which read as
"the issue is stale". It was not. A Popen-level recorder watching every spawn
showed what was actually happening:

    uv.EXE pip install --python .venv/Scripts/python.exe --quiet bandit==1.9.4

Not a spawn -- a real network package install into the developer's venv, from a
unit test. A static sweep found **6** tests in
`tests/cli/test_wizard_tool_checker.py` able to reach
`ToolInstaller.install_tools_parallel`; only 1 patched it.

**"No guard fired" was read as "nothing spawned", and the guard's scope made
that reading wrong.** Same shape as the encoding-drift guard that scanned for
`def safe_print` while the actual rule was "do not branch on a codec's name" --
a guard that checks last time's syntax gets walked around.

Two changes, and the second is the one that generalises:

1. `SCANNER_BINARY_NAMES` is **derived** from `PROFILE_TOOLS` and
   `TOOL_BINARY_NAMES` instead of listed, so a tool added to a profile is
   covered with no second edit.
2. A separate check asserts the **property** -- no test may spawn a process
   that installs a package or downloads a payload -- because a list of scanner
   names would never have caught `uv`, which is not a scanner.
"""

from __future__ import annotations

import pytest

from scripts.core.tool_registry import PROFILE_TOOLS
from tests.conftest import (
    SCANNER_BINARY_NAMES,
    installer_argv_match,
    scanner_binary_match,
)

# ---------------------------------------------------------------------------
# 1. The scanner set is derived, not listed.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "binary",
    ["semgrep", "bandit", "trivy", "trufflehog", "checkov", "syft", "hadolint"],
)
def test_every_profile_scanner_is_watched(binary: str) -> None:
    """The recorder used to see exactly one of these."""
    assert scanner_binary_match(binary) == binary
    assert scanner_binary_match(f"C:\\tools\\{binary}.EXE") == binary


def test_the_watched_set_covers_every_tool_in_every_profile() -> None:
    """Derived, so it cannot fall behind the registry.

    Stated over the whole registry rather than the seven names above: a tool
    added to a profile tomorrow must be watched without anyone remembering to
    edit a list.
    """
    from scripts.core.tool_registry import TOOL_BINARY_NAMES

    unwatched = sorted(
        tool
        for tools in PROFILE_TOOLS.values()
        for tool in tools
        if scanner_binary_match(TOOL_BINARY_NAMES.get(tool, tool)) is None
    )

    assert not unwatched, f"profile tools nothing watches: {unwatched}"


def test_the_derivation_actually_found_something() -> None:
    """Meta-guard: an empty set makes every assertion above vacuous."""
    assert len(SCANNER_BINARY_NAMES) >= 20, sorted(SCANNER_BINARY_NAMES)
    assert "semgrep" in SCANNER_BINARY_NAMES


@pytest.mark.parametrize(
    "argv0", ["git", "pytest", "python", "semgrep-action", "trivy_report.json", "node"]
)
def test_unrelated_binaries_are_not_matched(argv0: str) -> None:
    """The negative control.

    A recorder that matches everything fails every test that shells out at all,
    gets silenced, and takes the real check with it. Substring matches
    (`semgrep-action`, a fixture path ending `trivy_report.json`) must not
    count.
    """
    assert scanner_binary_match(argv0) is None


# ---------------------------------------------------------------------------
# 2. The property: no installs, no downloads.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        # The measured offender, verbatim.
        (
            [
                "uv.EXE",
                "pip",
                "install",
                "--python",
                ".venv/Scripts/python.exe",
                "--quiet",
                "bandit==1.9.4",
            ],
            "uv pip install",
        ),
        (["uv", "tool", "install", "graphifyy"], "uv tool install"),
        (["uv", "add", "requests"], "uv add"),
        (["uv", "sync", "--group", "dev"], "uv sync"),
        (["pip", "install", "bandit"], "pip install"),
        (["pip3", "install", "bandit"], "pip3 install"),
        (["python", "-m", "pip", "install", "bandit"], "python -m pip install"),
        (["npm", "install", "-g", "@cyclonedx/cdxgen"], "npm install"),
        (["npx", "something"], "npx"),
        (["brew", "install", "trivy"], "brew install"),
        (["curl", "-fsSL", "https://example.test/install.sh"], "curl"),
        (["wget", "https://example.test/tool.tar.gz"], "wget"),
    ],
)
def test_an_install_or_download_is_recognised(argv: list[str], expected: str) -> None:
    """Matched on the whole argv, not argv[0].

    `uv` is an ordinary binary and `uv run` is used legitimately -- the verb is
    what makes it an install, which is why argv[0] alone was never going to be
    the right key.
    """
    assert installer_argv_match(argv) == expected


@pytest.mark.parametrize(
    "argv",
    [
        ["uv", "run", "pytest"],
        ["uv", "lock", "--check"],
        ["git", "rev-parse", "HEAD"],
        ["python", "-c", "print(1)"],
        ["python", "-m", "pytest"],
        ["npm", "run", "build"],
        ["semgrep", "--version"],
        ["docker", "run", "--rm", "img"],
        [],
    ],
)
def test_an_ordinary_command_is_not_an_install(argv: list[str]) -> None:
    """The negative control for the property check.

    `uv run` and `uv lock` are how this repo runs its own tooling; a guard that
    flagged them would fire constantly and be turned off.
    """
    assert installer_argv_match(argv) is None


def test_the_recorder_captures_an_installer_spawn(monkeypatch) -> None:
    """End to end through the recorder, not just the matcher.

    The matcher being right is not the same as the recorder consulting it --
    that gap is precisely what #976's "no guard fired" reading was.
    """
    from tests.conftest import make_scanner_spawn_recorder

    sink: list[tuple[str, list[str]]] = []
    calls: list[list[str]] = []

    def fake_delegate(_self, args, *_a, **_kw):
        calls.append(list(args))
        return None

    recorder = make_scanner_spawn_recorder(fake_delegate, sink)
    recorder(object(), ["uv", "pip", "install", "bandit==1.9.4"])
    recorder(object(), ["git", "status"])

    assert [argv for _, argv in sink] == [["uv", "pip", "install", "bandit==1.9.4"]]
    assert len(calls) == 2, "the recorder must always delegate, matched or not"
