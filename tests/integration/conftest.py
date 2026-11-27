#!/usr/bin/env python3
"""
Shared pytest fixtures for integration tests.

This module provides fixtures used across integration tests, including:
- short_tmp_path: Shorter temp path for Windows MAX_PATH avoidance
- Various setup and teardown helpers
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from tests.conftest import use_trivy_cache


@pytest.fixture(autouse=True)
def _one_trivy_database(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    real_home: Path,
) -> None:
    """Every requires_tools test reads the developer's trivy databases.

    trivy keeps its database (1.8 GB) under the home, and many of these tests
    give a scan a home of its own (HOME=tmp_path for a subprocess, or a patched
    Path.home) without `jmo_runner`, which arranges this for its own callers.
    Each trivy scan in such a test then fetched the whole database into its tmp
    directory: one run of the requires_tools tests here wrote 25 GB and filled
    the workstation's disk (2026-11-25), the #1517 class outside jmo_runner.
    Sharing the whole cache instead failed scans under -n 4 on its lock, so
    each test process gets a cache of its own that links the databases
    (`trivy_cache`).
    """
    if request.node.get_closest_marker("requires_tools") is None:
        return
    use_trivy_cache(monkeypatch, request.getfixturevalue("trivy_cache"), real_home)


# Path to fixtures
PROJECT_ROOT = Path(__file__).parent.parent.parent
BASELINES_DIR = PROJECT_ROOT / "tests" / "integration" / "baselines"
SAMPLES_DIR = PROJECT_ROOT / "tests" / "fixtures" / "samples"


@pytest.fixture
def short_tmp_path(tmp_path: Path):
    """Provide a shorter temp path on Windows to avoid MAX_PATH (260 chars).

    On Windows, pytest's tmp_path is ~70+ chars. Repos like juice-shop have
    deep node_modules paths that easily exceed 260 chars when combined.
    This fixture uses C:/tmp/jmo-XXX (~20 chars) instead.

    On non-Windows, delegates to the standard tmp_path.
    """
    if sys.platform != "win32":
        yield tmp_path
        return

    short_base = Path("C:/tmp")
    short_base.mkdir(exist_ok=True)
    short_dir = Path(tempfile.mkdtemp(prefix="jmo-", dir=short_base))
    yield short_dir
    shutil.rmtree(short_dir, ignore_errors=True)


@pytest.fixture
def baselines_dir() -> Path:
    """Provide path to baseline files directory."""
    if not BASELINES_DIR.exists():
        pytest.skip(f"Baselines directory not found: {BASELINES_DIR}")
    return BASELINES_DIR


@pytest.fixture
def samples_dir() -> Path:
    """Provide path to sample fixtures directory."""
    if not SAMPLES_DIR.exists():
        pytest.skip(f"Samples directory not found: {SAMPLES_DIR}")
    return SAMPLES_DIR
