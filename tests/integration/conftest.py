#!/usr/bin/env python3
"""
Shared pytest fixtures for integration tests.

This module provides fixtures used across integration tests, including:
- juice_shop_fixture: Path to the juice-shop minimal test fixture
- short_tmp_path: Shorter temp path for Windows MAX_PATH avoidance
- Various setup and teardown helpers
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

# Path to fixtures
PROJECT_ROOT = Path(__file__).parent.parent.parent
JUICE_SHOP_FIXTURE = PROJECT_ROOT / "tests" / "integration" / "juice_shop_fixture"
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
def juice_shop_fixture() -> Path:
    """
    Provide path to juice-shop minimal fixture directory.

    This fixture provides a lightweight (~5MB) subset of the OWASP Juice Shop
    application for smoke testing security tools. It contains intentionally
    vulnerable code patterns for testing tool detection capabilities.

    The fixture includes:
    - package.json/package-lock.json: Known vulnerable npm dependencies
    - Dockerfile: Dockerfile linting targets
    - lib/insecurity.ts: SQL injection, weak crypto, hardcoded secrets
    - routes/*.ts: Authentication bypass, path traversal, IDOR
    - config/default.ts: Hardcoded API keys and credentials
    - frontend/src/app/: XSS vulnerabilities
    - vulnerable.sh: Shell script issues
    - k8s-deployment.yaml: Kubernetes misconfigurations
    - terraform/main.tf: AWS/IaC misconfigurations

    Returns:
        Path to the juice_shop_fixture directory

    Raises:
        pytest.skip: If the fixture directory doesn't exist

    Example:
        def test_semgrep_finds_sql_injection(juice_shop_fixture):
            result = run_semgrep(juice_shop_fixture)
            assert "sql-injection" in result
    """
    if not JUICE_SHOP_FIXTURE.exists():
        pytest.skip(
            f"juice_shop_fixture directory not found at {JUICE_SHOP_FIXTURE}. "
            f"This fixture should be committed to the repository."
        )
    return JUICE_SHOP_FIXTURE


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
