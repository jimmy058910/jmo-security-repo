#!/usr/bin/env python3
"""Guard: the #907 unmarked-scanner-spawn recorder must still detect spawns.

`tests/conftest.py`'s `_guard_no_unmarked_scanner_spawn` fixture wraps
`subprocess.Popen.__init__` for every test and fails the ones that spawn a
real scanner binary (currently just `semgrep`, #907's subject) without
declaring `@pytest.mark.requires_tools`. A guard that cannot fail is worse
than no guard - it is confidence without substance (see
tests/unit/test_conftest_import_guard.py for the same argument applied to a
different guard in this suite) - so this proves the underlying detection
logic (`scanner_binary_match`, `make_scanner_spawn_recorder`) still fires.

Deliberately does not spawn a real process anywhere in this file: doing so
would itself need `@pytest.mark.requires_tools`, which would make this
self-test depend on the very exemption path it exists to prove works, and
would tie its result to whether a scanner binary happens to be installed on
whichever machine runs it. `test_recorder_detects_a_deliberate_spawn...`
below proves the wrapper fires using a fake delegate instead of the real
`Popen.__init__`.
"""

from __future__ import annotations

import pytest

from tests.conftest import (
    make_scanner_spawn_recorder,
    scanner_binary_match,
    semgrep_argv_uses_config_auto,
)


@pytest.mark.parametrize(
    "argv0",
    [
        "semgrep",
        "semgrep.exe",
        "SEMGREP.EXE",
        "Semgrep.Exe",
        r"C:\Users\Jimmy\AppData\Roaming\Python\Python312\Scripts\semgrep.EXE",
        "/usr/local/bin/semgrep",
        "./semgrep",
        r".\semgrep.exe",
    ],
)
def test_scanner_binary_match_detects_semgrep_variants(argv0):
    """Bare name, `.exe` suffix, mixed case, and both path-separator styles
    all resolve to the same match - the styles that actually appear across
    this suite's platforms (Windows argv0s use backslashes; Linux/macOS use
    forward slashes), not just the one style whichever OS runs this test
    happens to produce natively."""
    assert scanner_binary_match(argv0) == "semgrep"


@pytest.mark.parametrize(
    "argv0",
    [
        # `trufflehog` used to be here, asserting the narrow scope. It IS a
        # profile scanner, and the recorder watching only semgrep is the defect
        # #994 fixed -- so a test pinning its absence pinned the bug. The
        # watched set is now derived from PROFILE_TOOLS; see
        # tests/unit/test_spawn_guard_scope.py.
        "black",
        "python",
        "semgrep-action",  # a different binary that merely starts with the name
        "not-semgrep",
        "/scratch/semgrep_report.json",  # a path that merely CONTAINS the substring
        r"C:\fixtures\semgrep\repo",  # "semgrep" as a directory component, not the exe
        "",
    ],
)
def test_scanner_binary_match_ignores_unrelated_binaries(argv0):
    assert scanner_binary_match(argv0) is None


def test_recorder_detects_a_deliberate_spawn_without_a_real_process():
    """The recorder's floor: prove it fires on a matching argv and stays
    silent on a non-matching one, using a fake delegate so no real process
    is spawned and no scanner binary needs to be installed on the machine
    running this test.
    """
    delegate_calls: list[list[str]] = []

    def _fake_delegate(self, args, *a, **kw):
        delegate_calls.append(list(args))
        # Deliberately builds no real Popen - this proves the recording
        # half of the wrapper, not the OS-level spawn.

    sink: list[tuple[str, list[str]]] = []
    recording_init = make_scanner_spawn_recorder(_fake_delegate, sink)

    fake_self = object()
    recording_init(fake_self, ["semgrep", "--config", "auto"])
    recording_init(fake_self, ["black", "--check", "."])

    assert sink == [("semgrep", ["semgrep", "--config", "auto"])]
    assert delegate_calls == [
        ["semgrep", "--config", "auto"],
        ["black", "--check", "."],
    ], "the wrapper must still call through to the real init every time"


def test_recorder_ignores_an_empty_argv():
    """Defensive: an empty argv list must not raise IndexError inside the
    match check - `subprocess.Popen([])` is invalid usage, but the recorder
    must not be what crashes on it."""
    sink: list[tuple[str, list[str]]] = []
    recording_init = make_scanner_spawn_recorder(
        lambda self, args, *a, **kw: None, sink
    )
    recording_init(object(), [])
    assert sink == []


def test_recorder_handles_a_string_command_defensively():
    """`Popen` accepts a bare string as `args` (only meaningful with
    shell=True, which this repo forbids) - the recorder must not raise on
    that shape even though it should never see it in practice."""
    sink: list[tuple[str, list[str]]] = []
    recording_init = make_scanner_spawn_recorder(
        lambda self, args, *a, **kw: None, sink
    )
    recording_init(object(), "semgrep")
    assert sink == [("semgrep", ["semgrep"])]


@pytest.mark.parametrize(
    "argv",
    [
        ["semgrep", "--config", "auto", "--json", "--output", "out.json", "."],
        ["semgrep", "--config", "auto"],
    ],
)
def test_semgrep_argv_uses_config_auto_detects_the_network_default(argv):
    assert semgrep_argv_uses_config_auto(argv) is True


@pytest.mark.parametrize(
    "argv",
    [
        ["semgrep", "--version"],  # the wizard's tool pre-flight probe, #907
        ["semgrep", "--config", "/tmp/offline-rule.yml", "--json"],  # this task's fix
        ["semgrep"],
        [],
        ["semgrep", "--config"],  # malformed/truncated -- must not IndexError
    ],
)
def test_semgrep_argv_uses_config_auto_ignores_everything_else(argv):
    assert semgrep_argv_uses_config_auto(argv) is False
