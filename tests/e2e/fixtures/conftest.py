"""Session-scoped fixture data loaders for e2e tests.

Replaces setup_fixtures.sh. Provides verified fixture paths
for IaC, Python, JavaScript, and config test files.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent


@pytest.fixture(scope="session")
def iac_fixtures() -> dict[str, Path]:
    """Return paths to IaC test fixtures."""
    iac_dir = FIXTURES_DIR / "iac"
    fixtures = {
        "terraform": iac_dir / "aws-s3-public.tf",
        "k8s": iac_dir / "k8s-privileged-pod.yaml",
        "dockerfile": iac_dir / "Dockerfile.bad",
        "docker_compose": iac_dir / "docker-compose.insecure.yml",
    }
    for name, path in fixtures.items():
        assert path.exists(), f"Missing IaC fixture: {name} at {path}"
    return fixtures


@pytest.fixture(scope="session")
def python_fixtures() -> dict[str, Path]:
    """Return paths to Python test fixtures."""
    py_dir = FIXTURES_DIR / "python"
    return {"vulnerable_app": py_dir / "vulnerable_app.py"}


@pytest.fixture(scope="session")
def javascript_fixtures() -> dict[str, Path]:
    """Return paths to JavaScript test fixtures."""
    js_dir = FIXTURES_DIR / "javascript"
    return {
        "package_json": js_dir / "package.json",
        "vulnerable_app": js_dir / "vulnerable_app.js",
    }


@pytest.fixture(scope="session")
def config_fixtures() -> dict[str, Path]:
    """Return paths to config test fixtures."""
    cfg_dir = FIXTURES_DIR / "configs"
    return {
        "secrets_yaml": cfg_dir / "secrets.yaml",
    }
