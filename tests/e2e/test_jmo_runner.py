#!/usr/bin/env python3
"""What the `jmo_runner` fixture hands the `jmo` process it spawns (#1517).

`jmo_runner` gives the process a home directory of its own, so that a scan's
EPSS and KEV caches land in the test's `tmp_path` and not in the developer's
`~/.jmo`. A bare home hid everything a scan reads from the real one:

- the scanners (`~/.jmo/bin`), their venvs, the yara rules and the OSV
  database, so a scan "passed" having run nothing, and
- the scanners' own caches. trivy and grype look under the home for their
  vulnerability databases, so with `~/.jmo/bin` on PATH each of five scan tests
  fetched trivy's 1.6 GB and grype's 3.2 GB into its own home: 24 GB in 6 min
  57 s, against 5.0 MB in 11 s when no scanner was found at all.

The fixture now links the real tool directories into the test's home and points
both databases at the developer's own cache. These tests pin that. The class
runs everywhere, against a pretend developer home; the two functions after it
run real scanners and are `requires_tools`.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.conftest import (
    IS_LINUX,
    assert_no_jmo_traceback,
    scanner_installed,
    scanner_states,
)

SCANNER_DIRS = ("bin", "tools", "yara-rules", "osv-db")
CACHE_VARIABLES = ("TRIVY_CACHE_DIR", "GRYPE_DB_CACHE_DIR", "XDG_CACHE_HOME")


def skip_without_symlinks(tmp_path: Path) -> None:
    """Skip where this account cannot link (Windows without Developer Mode)."""
    probe = tmp_path / "probe-link"
    try:
        probe.symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symlinks")
    probe.unlink()


class TestAgainstAPretendDeveloperHome:
    """The fixture's environment, read against a home built for each test."""

    @pytest.fixture
    def real_home(self, request, tmp_path):
        """Overrides tests/conftest.py's, which is the real one, for this class."""
        home = tmp_path / "developer"
        for name in getattr(request, "param", SCANNER_DIRS):
            (home / ".jmo" / name).mkdir(parents=True)
        return home

    @pytest.fixture
    def no_cache_settings(self, monkeypatch):
        """Drop the developer's own cache variables, so the defaults are read."""
        for var in CACHE_VARIABLES:
            monkeypatch.delenv(var, raising=False)

    @pytest.fixture
    def configured_trivy_cache(self, monkeypatch, tmp_path):
        monkeypatch.setenv("TRIVY_CACHE_DIR", str(tmp_path / "chosen"))

    @pytest.fixture
    def symlinks_refused(self, monkeypatch):
        """What a Windows account without Developer Mode gets from `symlink_to`."""

        def refuse(self, target, target_is_directory=False):
            raise OSError("A required privilege is not held by the client")

        monkeypatch.setattr(Path, "symlink_to", refuse)
        monkeypatch.setenv("PATH", os.pathsep.join(["/somewhere", "/else"]))

    def test_the_process_gets_a_home_of_its_own(self, jmo_runner, tmp_path):
        """The reason for the override: cache writes stay out of the real `~/.jmo`."""
        assert Path(os.environ["HOME"]) == tmp_path / "home"
        assert Path(os.environ["USERPROFILE"]) == tmp_path / "home"

    @pytest.mark.usefixtures("jmo_runner")
    @pytest.mark.parametrize("name", SCANNER_DIRS)
    def test_the_installed_scanner_directories_are_the_developers(
        self, name, real_home, tmp_path
    ):
        skip_without_symlinks(tmp_path)

        link = tmp_path / "home" / ".jmo" / name
        assert link.is_symlink(), f"{link} is not a link to the developer's {name}"
        assert link.resolve() == (real_home / ".jmo" / name).resolve()

    @pytest.mark.usefixtures("jmo_runner")
    @pytest.mark.parametrize("real_home", [("bin",)], indirect=True)
    def test_a_directory_the_developer_lacks_is_not_linked(self, real_home, tmp_path):
        """No dangling link: a scan reads an absent database as absent."""
        skip_without_symlinks(tmp_path)

        jmo_dir = tmp_path / "home" / ".jmo"
        assert (jmo_dir / "bin").is_symlink()
        assert not (jmo_dir / "osv-db").is_symlink()
        assert not (jmo_dir / "osv-db").exists()

    def test_without_symlinks_the_real_bin_directory_goes_on_path(
        self, symlinks_refused, jmo_runner, real_home, tmp_path
    ):
        """Tool lookup reads PATH as well as `~/.jmo/bin` (measured), so a refused
        link costs the venvs, the rules and the OSV database but not the scanners."""
        path = os.environ["PATH"].split(os.pathsep)

        assert Path(path[0]) == real_home / ".jmo" / "bin"
        assert path[1:] == ["/somewhere", "/else"]
        assert not (tmp_path / "home" / ".jmo" / "bin").exists()

    def test_scanner_caches_are_the_developers_not_a_fresh_one(
        self, no_cache_settings, jmo_runner, real_home, tmp_path
    ):
        """trivy and grype read their databases from one place for the whole run."""
        trivy = Path(os.environ["TRIVY_CACHE_DIR"])
        grype = Path(os.environ["GRYPE_DB_CACHE_DIR"])

        for cache in (trivy, grype):
            assert not cache.is_relative_to(tmp_path / "home"), (
                f"{cache} is inside the test's home, so each test would fetch its own"
            )
        if IS_LINUX:
            assert trivy == real_home / ".cache" / "trivy"
            assert grype == real_home / ".cache" / "grype" / "db"

    def test_a_cache_the_developer_configured_is_kept(
        self, configured_trivy_cache, jmo_runner
    ):
        assert Path(os.environ["TRIVY_CACHE_DIR"]).name == "chosen"


@pytest.mark.requires_tools
@pytest.mark.skipif(
    not (scanner_installed("hadolint") and scanner_installed("gitleaks")),
    reason="hadolint and gitleaks are not both installed",
)
def test_a_scan_runs_the_scanners_the_developer_installed(jmo_runner, tmp_path):
    """The point of the links: both live in `~/.jmo/bin` and nowhere on PATH."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_bytes(b"FROM ubuntu:latest\n")
    results = tmp_path / "results"

    result = jmo_runner(
        [
            "scan",
            "--tools",
            "hadolint",
            "gitleaks",
            "--repo",
            str(repo),
            "--results-dir",
            str(results),
        ],
        timeout=100,
    )

    assert_no_jmo_traceback(result.stdout + result.stderr)
    assert result.returncode in (0, 1), result.stderr[-2000:]
    assert scanner_states(results) == {"hadolint": "ran", "gitleaks": "ran"}
    # Captured output is not a terminal, so no Ko-fi counter is written (#1506),
    # not even into the test's own home.
    assert not (tmp_path / "home" / ".jmo" / "config.yml").exists()


@pytest.mark.requires_tools
@pytest.mark.timeout(900)
@pytest.mark.skipif(
    not (IS_LINUX and scanner_installed("trivy") and scanner_installed("grype")),
    reason="Linux with trivy and grype installed",
)
def test_trivy_and_grype_use_the_developers_databases(jmo_runner, tmp_path):
    """Neither scanner unpacks a database of its own under the test's home.

    A database that moved on since the last scan is fetched into the developer's
    cache, once, which is what their own `jmo scan` does; grype's took 92 s.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_bytes(b"requests==2.19.0\n")
    results = tmp_path / "results"

    result = jmo_runner(
        [
            "scan",
            "--tools",
            "trivy",
            "grype",
            "--repo",
            str(repo),
            "--results-dir",
            str(results),
        ],
        timeout=800,
    )

    assert result.returncode in (0, 1), result.stderr[-2000:]
    assert scanner_states(results) == {"trivy": "ran", "grype": "ran"}
    cache = tmp_path / "home" / ".cache"
    assert not (cache / "trivy").exists(), "trivy fetched its database into the test"
    assert not (cache / "grype").exists(), "grype fetched its database into the test"
