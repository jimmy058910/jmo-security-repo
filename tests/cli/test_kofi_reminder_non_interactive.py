"""A scan nobody is watching leaves ``~/.jmo/config.yml`` alone (#1506).

``cmd_scan`` called ``_show_kofi_reminder()`` on every run. It created
``~/.jmo``, read ``config.yml``, bumped ``scan_count`` and rewrote the file,
whether or not anyone was there to read the reminder it prints every third
scan. A scan run by CI, cron, a pipe or a redirect therefore edited the
maintainer's real config, and every e2e test that spawned ``jmo scan`` did too.
``jmo_runner`` points HOME at a scratch directory first for that reason; it
keeps doing so (#1517) for the EPSS and KEV caches a scan with findings writes
under ``~/.jmo/cache``.

The tests run ``cmd_scan`` to the reminder -- the tool pre-flight and the
per-target scan are stubbed, nothing else -- with ``Path.home()`` redirected to
a directory holding a config at ``scan_count: 2``, so the next scan is the one
that prints.

The pass condition for the non-interactive cases is more than "no reminder":
the file must be byte-identical (the count was not bumped either) and where no
``~/.jmo`` existed none may appear.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.core.scan_timings import State, ToolRun

REMINDER = "Enjoying JMo Security"
SEED = "onboarding_completed: true\nscan_count: 2\n"


class _Stream(io.StringIO):
    """A text stream that says whether it is a terminal."""

    def __init__(self, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    """An empty home. The variables that make a run non-interactive are cleared,
    so a CI runner's own ``CI=true`` cannot decide a test."""
    for var in ("CI", "JMO_NON_INTERACTIVE", "DOCKER_CONTAINER"):
        monkeypatch.delenv(var, raising=False)
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))
    return fake_home


@pytest.fixture
def scan(tmp_path: Path, monkeypatch):
    """Return ``run(stdin_tty=, stdout_tty=) -> (rc, stdout_text)``.

    ``stdin_tty=None`` is a process started with stdin closed: ``sys.stdin`` is
    None, as under ``jmo scan <&-``.
    """
    repos_dir = tmp_path / "repos"
    (repos_dir / "proj").mkdir(parents=True)
    (repos_dir / "proj" / "README.md").write_bytes(b"# proj\n")
    results_dir = tmp_path / "results"
    cfg_path = tmp_path / "jmo.yml"
    cfg_path.write_text(
        yaml.safe_dump({"tools": ["trufflehog"], "outputs": ["json"]}), encoding="utf-8"
    )
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    monkeypatch.setattr(
        "scripts.cli.tool_manager.ToolManager._find_binary", lambda *a, **k: None
    )
    # Relative, as in tests/integration/test_scan_accounting.py: with
    # DOCKER_CONTAINER set the scan refuses a drive-letter --repos-dir as
    # MSYS-mangled, which on native Windows is every tmp_path, and the scan
    # would stop before the reminder.
    monkeypatch.chdir(tmp_path)
    argv = [
        "jmo",
        "scan",
        "--repos-dir",
        repos_dir.name,
        "--results-dir",
        str(results_dir),
        "--config",
        str(cfg_path),
        "--tools",
        "trufflehog",
        "--no-store-history",
    ]

    def run(*, stdin_tty: bool | None, stdout_tty: bool) -> tuple[int, str]:
        stdout = _Stream(stdout_tty)
        stdin = None if stdin_tty is None else _Stream(stdin_tty)
        monkeypatch.setattr(sys, "stdin", stdin)
        monkeypatch.setattr(sys, "stdout", stdout)
        with patch.object(sys, "argv", argv):
            args = jmo.parse_args()
        with patch("scripts.cli.scan_jobs.scan_repository") as scan_repository:
            scan_repository.return_value = (
                "proj",
                {"trufflehog": ToolRun("trufflehog", State.RAN)},
            )
            rc = jmo.cmd_scan(args)
        # `.scan_metadata.json` is written after the reminder: a scan that
        # bailed earlier would leave the config alone for the wrong reason.
        assert (results_dir / ".scan_metadata.json").exists(), "scan never finished"
        return rc, stdout.getvalue()

    return run


# (stdin is a terminal, stdout is a terminal, environment) -- one reason each
# for nobody to be there.
NON_INTERACTIVE = [
    pytest.param(True, False, {}, id="stdout-not-a-tty"),
    pytest.param(False, True, {}, id="stdin-not-a-tty"),
    pytest.param(True, True, {"CI": "true"}, id="CI-set"),
    pytest.param(
        True, True, {"JMO_NON_INTERACTIVE": "1"}, id="JMO_NON_INTERACTIVE-set"
    ),
    pytest.param(True, True, {"DOCKER_CONTAINER": "1"}, id="DOCKER_CONTAINER-set"),
]


@pytest.mark.parametrize(("stdin_tty", "stdout_tty", "env"), NON_INTERACTIVE)
def test_non_interactive_scan_leaves_the_config_byte_identical(
    home, scan, monkeypatch, stdin_tty, stdout_tty, env
):
    config = home / ".jmo" / "config.yml"
    config.parent.mkdir()
    config.write_text(SEED, encoding="utf-8")
    before = config.read_bytes()
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    rc, out = scan(stdin_tty=stdin_tty, stdout_tty=stdout_tty)

    assert rc == 0
    assert config.read_bytes() == before
    assert REMINDER not in out


def test_non_interactive_scan_creates_no_jmo_directory(home, scan):
    """What ``jmo_runner`` does: both streams captured, a home with no ``.jmo``."""
    rc, out = scan(stdin_tty=False, stdout_tty=False)

    assert rc == 0
    assert not (home / ".jmo").exists()
    assert REMINDER not in out


def test_a_scan_started_with_stdin_closed_still_finishes(home, scan):
    """``sys.stdin`` is None there. The reminder runs after the scan and asks
    whether stdin is a terminal; a crash in it would lose the report phase of a
    scan that had already succeeded (rc 0 before #1506, 1 with a bare
    ``sys.stdin.isatty()``)."""
    config = home / ".jmo" / "config.yml"
    config.parent.mkdir()
    config.write_text(SEED, encoding="utf-8")
    before = config.read_bytes()

    rc, out = scan(stdin_tty=None, stdout_tty=True)

    assert rc == 0
    assert config.read_bytes() == before
    assert REMINDER not in out


@pytest.mark.parametrize(
    ("seeded", "counted", "reminded"),
    [(2, 3, True), (0, 1, False)],
    ids=["third-scan-reminds", "first-scan-only-counts"],
)
def test_interactive_scan_still_counts_and_reminds_every_third(
    home, scan, seeded, counted, reminded
):
    config = home / ".jmo" / "config.yml"
    config.parent.mkdir()
    config.write_text(
        f"onboarding_completed: true\nscan_count: {seeded}\n", encoding="utf-8"
    )

    rc, out = scan(stdin_tty=True, stdout_tty=True)

    assert rc == 0
    assert yaml.safe_load(config.read_text(encoding="utf-8"))["scan_count"] == counted
    assert (REMINDER in out) is reminded
