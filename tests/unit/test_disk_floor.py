#!/usr/bin/env python3
"""A test run stops before it fills the disk.

On 2026-11-25 the workstation's disk filled three times during test runs, and
everything else on the machine failed with it. The floor in tests/conftest.py is
the backstop for the next cause of that.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import MIN_FREE_ENV, disk_floor_setting, disk_floor_shortfall

REPO_ROOT = Path(__file__).resolve().parents[2]
GIB = 1024**3


def _filesystem(total_gib: float, free_gib: float):
    """A `shutil.disk_usage` that reports this filesystem for any path."""
    total, free = total_gib * GIB, free_gib * GIB
    return lambda _path: (total, total - free, free)


@pytest.mark.parametrize(
    ("total", "free", "stops"),
    [
        pytest.param(185.0, 9.9, True, id="large-disk-short"),
        pytest.param(185.0, 10.1, False, id="large-disk-with-room"),
        # A tmpfs /tmp: asked for 10 GiB, it could never be used.
        pytest.param(13.7, 1.9, False, id="small-disk-with-a-tenth"),
        pytest.param(13.7, 1.3, True, id="small-disk-short"),
    ],
)
def test_the_default_floor(tmp_path: Path, total: float, free: float, stops: bool):
    short = disk_floor_shortfall(None, (tmp_path,), _filesystem(total, free))

    assert (short is not None) is stops, short


def test_an_asked_floor_is_used_as_given(tmp_path: Path):
    """Not cut to a tenth of the filesystem, as the default is."""
    short = disk_floor_shortfall(5.0, (tmp_path,), _filesystem(13.7, 4.0))

    assert short is not None
    assert MIN_FREE_ENV in short, "the message must say how to change the floor"


def test_every_path_is_checked_even_before_it_exists(tmp_path: Path):
    """The home may have room while a named basetemp, not yet made, does not."""
    home = tmp_path / "home"
    other = tmp_path / "other-disk"
    home.mkdir()
    other.mkdir()
    basetemp = other / "bt" / "popen-gw0"
    measured = []

    def usage(path: Path):
        measured.append(path)
        free = 1.0 if path == other else 100.0
        return _filesystem(185.0, free)(path)

    short = disk_floor_shortfall(None, (home, basetemp), usage)

    assert measured == [home, other]
    assert short is not None
    assert str(basetemp) in short


@pytest.mark.parametrize(
    ("environment", "floor"),
    [
        pytest.param({}, None, id="default"),
        pytest.param({"CI": "true"}, 0.0, id="off-on-ci"),
        pytest.param({"CI": "true", MIN_FREE_ENV: "3"}, 3.0, id="asked-beats-ci"),
        pytest.param({MIN_FREE_ENV: "0"}, 0.0, id="asked-off"),
    ],
)
def test_the_floor_asked_for(
    monkeypatch: pytest.MonkeyPatch,
    environment: dict[str, str],
    floor: float | None,
):
    for name in ("CI", MIN_FREE_ENV):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    assert disk_floor_setting() == floor


@pytest.mark.parametrize("number", range(8))
def test_probe(number: int):
    """Passes. The child sessions below run these eight and nothing else."""


def _run_probes(
    tmp_path: Path, floor: str, workers: list[str]
) -> subprocess.CompletedProcess:
    # Not the parent's PYTEST_ADDOPTS, which may name its basetemp (#1501).
    environment = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    environment[MIN_FREE_ENV] = floor
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            f"{Path(__file__)}::test_probe",
            "-q",
            "-p",
            "no:cacheprovider",
            f"--basetemp={tmp_path / 'bt'}",
            *workers,
        ],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=90,
    )


@pytest.mark.parametrize(
    "workers", [[], ["-n", "2"]], ids=["one-process", "two-workers"]
)
def test_a_run_below_the_floor_stops_and_says_why(tmp_path: Path, workers: list[str]):
    result = _run_probes(tmp_path, "1000000000", workers)

    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "free-space floor" in output, output
    assert "passed" not in output, output
    # It stops: one test in each process reports it, not all eight.
    assert "8 errors" not in output, output


def test_a_run_with_the_floor_off_is_untouched(tmp_path: Path):
    result = _run_probes(tmp_path, "0", [])

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "8 passed" in output, output
