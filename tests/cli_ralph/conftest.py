#!/usr/bin/env python3
"""
Shared pytest fixtures for Ralph CLI Testing.

Provides:
- Ralph-specific fixtures (baseline/current results, history DB)
- CLI runner helpers
- Platform-aware tool expectations
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

# Re-export platform detection from main conftest
from tests.conftest import (
    IS_WINDOWS,
    IS_MACOS,
)


# ============================================================================
# Ralph Fixture Paths
# ============================================================================

RALPH_FIXTURES_DIR = (
    Path(__file__).parent.parent.parent / "tools" / "ralph-testing" / "fixtures"
)

# Tools that NEVER work on Windows
WINDOWS_EXCLUDED_TOOLS = ["falco", "afl++", "mobsf", "akto"]

# Tools that may have issues on Windows
WINDOWS_PROBLEMATIC_TOOLS = ["lynis", "noseyparker"]


# ============================================================================
# Fixture Path Fixtures
# ============================================================================


@pytest.fixture(scope="session")
def ralph_fixtures_dir() -> Path:
    """Return the Ralph CLI Testing fixtures directory."""
    return RALPH_FIXTURES_DIR


@pytest.fixture(scope="session")
def baseline_fixtures_dir(ralph_fixtures_dir: Path) -> Path:
    """Return the baseline results fixtures directory."""
    return ralph_fixtures_dir / "results-baseline"


@pytest.fixture(scope="session")
def current_fixtures_dir(ralph_fixtures_dir: Path) -> Path:
    """Return the current results fixtures directory."""
    return ralph_fixtures_dir / "results-current"


@pytest.fixture(scope="session")
def history_db_fixture(ralph_fixtures_dir: Path) -> Path:
    """Return the test history database path."""
    return ralph_fixtures_dir / "test-history.db"


# ============================================================================
# Isolated Test Fixtures (copied to temp)
# ============================================================================


@pytest.fixture
def baseline_results(baseline_fixtures_dir: Path, tmp_path: Path) -> Path:
    """
    Copy baseline results to temp directory for isolated testing.

    Returns path to temp results directory.
    """
    dest = tmp_path / "results-baseline"
    shutil.copytree(baseline_fixtures_dir, dest)
    return dest


@pytest.fixture
def current_results(current_fixtures_dir: Path, tmp_path: Path) -> Path:
    """
    Copy current results to temp directory for isolated testing.

    Returns path to temp results directory.
    """
    dest = tmp_path / "results-current"
    shutil.copytree(current_fixtures_dir, dest)
    return dest


@pytest.fixture
def test_history_db(history_db_fixture: Path, tmp_path: Path) -> Path:
    """
    Copy test history database to temp directory for isolated testing.

    Returns path to temp database file.
    """
    dest = tmp_path / "history.db"
    shutil.copy2(history_db_fixture, dest)
    return dest


@pytest.fixture
def jmo_dir(tmp_path: Path, test_history_db: Path) -> Path:
    """
    Create a .jmo directory with history database for testing.

    Returns path to .jmo directory.
    """
    jmo_path = tmp_path / ".jmo"
    jmo_path.mkdir(exist_ok=True)
    shutil.copy2(test_history_db, jmo_path / "history.db")
    return jmo_path


# ============================================================================
# Platform-Aware Tool Expectations
# ============================================================================


@pytest.fixture
def expected_tool_count() -> dict[str, Any]:
    """
    Return expected tool counts for current platform.

    Returns:
        Dictionary with min, max, and excluded tools
    """
    if IS_WINDOWS:
        return {
            "min": 16,
            "max": 24,
            "excluded": WINDOWS_EXCLUDED_TOOLS,
            "problematic": WINDOWS_PROBLEMATIC_TOOLS,
        }
    elif IS_MACOS:
        return {
            "min": 20,
            "max": 26,
            "excluded": [],
            "problematic": [],
        }
    else:  # Linux
        return {
            "min": 24,
            "max": 28,
            "excluded": [],
            "problematic": [],
        }


@pytest.fixture
def fast_profile_tools() -> list[str]:
    """Return tools in the 'fast' profile."""
    return [
        "trivy",
        "gitleaks",
        "trufflehog",
        "semgrep",
        "bandit",
        "hadolint",
        "shellcheck",
        "checkov",
    ]


# ============================================================================
# CLI Runner Helpers
# ============================================================================


@pytest.fixture
def jmo_runner_with_env(tmp_path: Path) -> Callable[..., subprocess.CompletedProcess]:
    """
    JMo runner that supports custom environment variables.

    Useful for setting JMO_HISTORY_DB, etc.
    """

    def _run(
        args: list[str],
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess:
        import os

        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        cmd = [sys.executable, "-m", "scripts.cli.jmo"] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=run_env,
            cwd=str(cwd) if cwd else None,
            timeout=timeout,
        )

    return _run


@pytest.fixture
def run_jmo_with_history(
    jmo_runner: Callable[..., subprocess.CompletedProcess],
    test_history_db: Path,
) -> Callable[..., subprocess.CompletedProcess]:
    """
    JMo runner pre-configured with test history database.

    Adds --db flag to commands for history/trends operations.
    """

    def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
        # Add --db flag to point to test database
        db_args = args + ["--db", str(test_history_db)]
        return jmo_runner(db_args, **kwargs)

    return _run


# ============================================================================
# Results Validation Helpers
# ============================================================================


@pytest.fixture
def validate_findings_json() -> Callable[[Path], dict[str, Any]]:
    """
    Return a function that validates findings.json format.

    Raises AssertionError if invalid.
    """

    def _validate(findings_path: Path) -> dict[str, Any]:
        assert findings_path.exists(), f"findings.json not found at {findings_path}"

        with open(findings_path) as f:
            data = json.load(f)

        # Validate meta section
        assert "meta" in data, "Missing 'meta' section"
        meta = data["meta"]
        assert "schema_version" in meta, "Missing schema_version"
        assert (
            meta["schema_version"] == "1.2.0"
        ), f"Unexpected schema: {meta['schema_version']}"
        assert "finding_count" in meta, "Missing finding_count"

        # Validate findings array
        assert "findings" in data, "Missing 'findings' array"
        assert isinstance(data["findings"], list), "findings is not an array"
        assert len(data["findings"]) == meta["finding_count"], "finding_count mismatch"

        return data

    return _validate


@pytest.fixture
def validate_html_dashboard() -> Callable[[Path], bool]:
    """
    Return a function that validates dashboard.html exists and is valid HTML.
    """

    def _validate(dashboard_path: Path) -> bool:
        assert dashboard_path.exists(), f"dashboard.html not found at {dashboard_path}"

        content = dashboard_path.read_text(encoding="utf-8")
        assert "<html" in content.lower(), "Missing <html> tag"
        assert "</html>" in content.lower(), "Missing </html> tag"
        assert "<body" in content.lower(), "Missing <body> tag"

        return True

    return _validate


# ============================================================================
# JSON Output Helpers
# ============================================================================


@pytest.fixture
def parse_json_output() -> Callable[[str], dict[str, Any]]:
    """
    Return a function that safely parses JSON from command output.

    Handles cases where output might have non-JSON prefix/suffix.
    """

    def _parse(output: str) -> dict[str, Any]:
        # Try direct parse first
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            pass

        # Try to find JSON object in output
        start = output.find("{")
        end = output.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(output[start:end])
            except json.JSONDecodeError:
                pass

        # Try to find JSON array
        start = output.find("[")
        end = output.rfind("]") + 1
        if start >= 0 and end > start:
            try:
                return {"data": json.loads(output[start:end])}
            except json.JSONDecodeError:
                pass

        raise ValueError(f"Could not parse JSON from output: {output[:200]}...")

    return _parse


# ============================================================================
# Scan Fixture Paths
# ============================================================================


@pytest.fixture
def python_vulnerable_fixture() -> Path:
    """Return path to python-vulnerable sample fixture."""
    return Path("tests/fixtures/samples/python-vulnerable")


@pytest.fixture
def dockerfile_issues_fixture() -> Path:
    """Return path to dockerfile-issues sample fixture."""
    return Path("tests/fixtures/samples/dockerfile-issues")


@pytest.fixture
def terraform_misconfig_fixture() -> Path:
    """Return path to terraform-misconfig sample fixture."""
    return Path("tests/fixtures/samples/terraform-misconfig")


@pytest.fixture
def secrets_exposed_fixture() -> Path:
    """Return path to secrets-exposed sample fixture."""
    return Path("tests/fixtures/samples/secrets-exposed")


# ============================================================================
# Docker Availability Check
# ============================================================================


@pytest.fixture(scope="session")
def docker_available() -> bool:
    """Check if Docker is available for container scanning tests."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


@pytest.fixture
def skip_without_docker(docker_available: bool):
    """Skip test if Docker is not available."""
    if not docker_available:
        pytest.skip("Docker not available")


# ============================================================================
# Test Data Generators
# ============================================================================


@pytest.fixture
def sample_finding() -> dict[str, Any]:
    """Return a sample CommonFinding v1.2.0 object."""
    return {
        "schemaVersion": "1.2.0",
        "id": "fp-test-0001",
        "ruleId": "CWE-79",
        "severity": "HIGH",
        "tool": {"name": "semgrep", "version": "1.45.0"},
        "location": {
            "path": "src/app.js",
            "startLine": 42,
            "endLine": 42,
        },
        "message": "Potential XSS vulnerability",
        "title": "Cross-Site Scripting",
    }
