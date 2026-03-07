# Pre-Release Validation System Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement `jmo validate` with 207 checks across 4 categories, two tiers (quick/full), and terminal scorecard output.

**Architecture:** Monolithic CLI subcommand with lazy import, 4 validator modules following a shared protocol, plus a CLI dispatcher with scorecard renderer. Mirrors the `jmo tools` pattern (separate module, lazy import from `main()`).

**Tech Stack:** Python 3.12+, stdlib only (no new deps). argparse for CLI, subprocess for CLI exercising, ast for code scanning, pathlib for cross-platform paths.

**Design doc:** `docs/plans/2026-02-26-pre-release-validation-design.md`

---

## Task 1: Shared Types & Validator Protocol

**Files:**
- Create: `scripts/core/validators/__init__.py`
- Test: `tests/core/test_validators_base.py`

**Step 1: Write failing tests for shared types**

```python
# tests/core/test_validators_base.py
"""Tests for validator base types and protocol."""

import pytest

from scripts.core.validators import (
    CheckResult,
    CheckStatus,
    CategoryResult,
    run_validators,
)


class TestCheckStatus:
    def test_status_values(self):
        assert CheckStatus.PASS.value == "pass"
        assert CheckStatus.FAIL.value == "fail"
        assert CheckStatus.WARN.value == "warn"
        assert CheckStatus.SKIP.value == "skip"
        assert CheckStatus.ERROR.value == "error"


class TestCheckResult:
    def test_basic_creation(self):
        result = CheckResult(name="test", status=CheckStatus.PASS)
        assert result.name == "test"
        assert result.status == CheckStatus.PASS
        assert result.message == ""
        assert result.details == ""
        assert result.duration_ms == 0.0

    def test_with_message(self):
        result = CheckResult(
            name="test",
            status=CheckStatus.FAIL,
            message="Something failed",
            details="More info here",
        )
        assert result.message == "Something failed"
        assert result.details == "More info here"


class TestCategoryResult:
    def test_counts(self):
        checks = [
            CheckResult(name="a", status=CheckStatus.PASS),
            CheckResult(name="b", status=CheckStatus.PASS),
            CheckResult(name="c", status=CheckStatus.FAIL),
            CheckResult(name="d", status=CheckStatus.WARN),
            CheckResult(name="e", status=CheckStatus.SKIP),
        ]
        result = CategoryResult(name="test", checks=checks)
        assert result.passed == 2
        assert result.failed == 1
        assert result.warned == 1
        assert result.skipped == 1
        assert result.total == 5

    def test_empty(self):
        result = CategoryResult(name="empty", checks=[])
        assert result.passed == 0
        assert result.failed == 0
        assert result.total == 0

    def test_all_pass(self):
        checks = [CheckResult(name="a", status=CheckStatus.PASS)]
        result = CategoryResult(name="test", checks=checks)
        assert result.passed == 1
        assert result.failed == 0


class TestRunValidators:
    def test_runs_all_categories(self):
        def fake_cli(tier):
            return CategoryResult(
                name="CLI",
                checks=[CheckResult(name="help", status=CheckStatus.PASS)],
            )

        def fake_scan(tier):
            return CategoryResult(
                name="Scans",
                checks=[CheckResult(name="adapter", status=CheckStatus.PASS)],
            )

        results = run_validators(
            validators=[fake_cli, fake_scan],
            tier="quick",
        )
        assert len(results) == 2
        assert results[0].name == "CLI"
        assert results[1].name == "Scans"

    def test_fail_fast_stops_on_failure(self):
        call_count = 0

        def pass_validator(tier):
            nonlocal call_count
            call_count += 1
            return CategoryResult(
                name="Pass",
                checks=[CheckResult(name="ok", status=CheckStatus.FAIL)],
            )

        def never_reached(tier):
            nonlocal call_count
            call_count += 1
            return CategoryResult(
                name="Never",
                checks=[CheckResult(name="x", status=CheckStatus.PASS)],
            )

        results = run_validators(
            validators=[pass_validator, never_reached],
            tier="quick",
            fail_fast=True,
        )
        assert call_count == 1
        assert len(results) == 1

    def test_category_filter(self):
        def cli_validator(tier):
            return CategoryResult(
                name="CLI Completeness",
                checks=[CheckResult(name="help", status=CheckStatus.PASS)],
            )

        def scan_validator(tier):
            return CategoryResult(
                name="Scan Correctness",
                checks=[CheckResult(name="adapter", status=CheckStatus.PASS)],
            )

        results = run_validators(
            validators=[cli_validator, scan_validator],
            tier="quick",
            categories=["cli"],
        )
        assert len(results) == 1
        assert results[0].name == "CLI Completeness"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/core/test_validators_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.core.validators'`

**Step 3: Implement shared types**

```python
# scripts/core/validators/__init__.py
"""Shared types and runner for the jmo validate system.

This module provides the protocol, result types, and orchestration
for the 4 validator categories (CLI, Scan, Platform, Release).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

# Category name → short key mapping for --category filter
CATEGORY_KEYS: dict[str, str] = {
    "CLI Completeness": "cli",
    "Scan Correctness": "scans",
    "Cross-Platform": "platform",
    "Release Artifacts": "release",
}


class CheckStatus(Enum):
    """Status of a single validation check."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class CheckResult:
    """Result of a single validation check."""

    name: str
    status: CheckStatus
    message: str = ""
    details: str = ""  # verbose-only extra info
    duration_ms: float = 0.0


@dataclass
class CategoryResult:
    """Aggregated result of a validator category."""

    name: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def warned(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.WARN)

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.SKIP)

    @property
    def errored(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.ERROR)

    @property
    def total(self) -> int:
        return len(self.checks)


# Type alias for a validator function
ValidatorFn = Callable[[str], CategoryResult]


def run_validators(
    validators: list[ValidatorFn],
    tier: str = "quick",
    fail_fast: bool = False,
    categories: list[str] | None = None,
) -> list[CategoryResult]:
    """Run validator functions and collect results.

    Args:
        validators: List of validator functions (each returns CategoryResult).
        tier: "quick" or "full".
        fail_fast: Stop after first category with failures.
        categories: Optional list of category short keys to run (e.g., ["cli", "scans"]).

    Returns:
        List of CategoryResult from each validator that ran.
    """
    results: list[CategoryResult] = []

    for validator in validators:
        # Run once to get the category name for filtering
        # Each validator is cheap to call - it returns its name from the result
        category_result = validator(tier)

        # Apply category filter
        if categories:
            key = CATEGORY_KEYS.get(category_result.name, "")
            if key not in categories:
                continue

        results.append(category_result)

        if fail_fast and category_result.failed > 0:
            break

    return results


def timed_check(name: str, fn: Callable[[], CheckResult | None]) -> CheckResult:
    """Run a check function with timing.

    If fn returns a CheckResult, return it with timing added.
    If fn raises, return an ERROR result.
    """
    start = time.perf_counter()
    try:
        result = fn()
        if result is None:
            result = CheckResult(name=name, status=CheckStatus.PASS)
        elapsed = (time.perf_counter() - start) * 1000
        result.duration_ms = elapsed
        return result
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return CheckResult(
            name=name,
            status=CheckStatus.ERROR,
            message=str(exc),
            duration_ms=elapsed,
        )
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/core/test_validators_base.py -v`
Expected: all PASS

**Step 5: Commit**

```bash
git add scripts/core/validators/__init__.py tests/core/test_validators_base.py
git commit -m "feat(validate): add shared types and validator protocol"
```

---

## Task 2: CLI Dispatcher & Scorecard Renderer

**Files:**
- Create: `scripts/cli/validate_commands.py`
- Modify: `scripts/cli/jmo.py:1763-1834` (add `_add_validate_args` + wire in `parse_args` and `main`)
- Test: `tests/cli/test_validate_commands.py`

**Step 1: Write failing tests for the dispatcher**

```python
# tests/cli/test_validate_commands.py
"""Tests for jmo validate CLI dispatcher and scorecard renderer."""

import argparse
import json
from io import StringIO
from unittest.mock import patch

import pytest

from scripts.cli.validate_commands import cmd_validate, render_scorecard
from scripts.core.validators import CategoryResult, CheckResult, CheckStatus


class TestRenderScorecard:
    def test_all_pass(self, capsys):
        results = [
            CategoryResult(
                name="CLI Completeness",
                checks=[
                    CheckResult(name="help works", status=CheckStatus.PASS),
                    CheckResult(name="version", status=CheckStatus.PASS),
                ],
            ),
        ]
        exit_code = render_scorecard(results, verbose=False)
        captured = capsys.readouterr()
        assert "CLI Completeness" in captured.out
        assert "2/2 PASS" in captured.out
        assert "GO" in captured.out
        assert exit_code == 0

    def test_with_failures(self, capsys):
        results = [
            CategoryResult(
                name="Release Artifacts",
                checks=[
                    CheckResult(name="version", status=CheckStatus.PASS),
                    CheckResult(
                        name="changelog",
                        status=CheckStatus.FAIL,
                        message="Missing entry",
                    ),
                ],
            ),
        ]
        exit_code = render_scorecard(results, verbose=False)
        captured = capsys.readouterr()
        assert "1 FAIL" in captured.out
        assert "NO-GO" in captured.out
        assert exit_code == 1

    def test_warnings_non_blocking(self, capsys):
        results = [
            CategoryResult(
                name="Cross-Platform",
                checks=[
                    CheckResult(name="paths", status=CheckStatus.PASS),
                    CheckResult(
                        name="docker",
                        status=CheckStatus.WARN,
                        message="Docker not running",
                    ),
                ],
            ),
        ]
        exit_code = render_scorecard(results, verbose=False)
        captured = capsys.readouterr()
        assert "GO" in captured.out
        assert exit_code == 0

    def test_verbose_shows_details(self, capsys):
        results = [
            CategoryResult(
                name="CLI Completeness",
                checks=[
                    CheckResult(
                        name="help works",
                        status=CheckStatus.PASS,
                        message="13 subcommands verified",
                    ),
                ],
            ),
        ]
        render_scorecard(results, verbose=True)
        captured = capsys.readouterr()
        assert "help works" in captured.out

    def test_json_output(self, capsys):
        results = [
            CategoryResult(
                name="CLI",
                checks=[CheckResult(name="test", status=CheckStatus.PASS)],
            ),
        ]
        render_scorecard(results, verbose=False, json_output=True)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["verdict"] == "GO"
        assert data["categories"][0]["name"] == "CLI"

    def test_empty_results(self, capsys):
        exit_code = render_scorecard([], verbose=False)
        captured = capsys.readouterr()
        assert "0/0" in captured.out or "no checks" in captured.out.lower()
        assert exit_code == 0


class TestCmdValidate:
    def test_quick_tier_default(self):
        args = argparse.Namespace(
            tier="quick",
            category=None,
            verbose=False,
            fail_fast=False,
            json=False,
        )
        # Should run without error; actual validators tested separately
        with patch(
            "scripts.cli.validate_commands._get_validators"
        ) as mock_get:
            mock_get.return_value = []
            result = cmd_validate(args)
            assert result == 0

    def test_category_filter_passed(self):
        args = argparse.Namespace(
            tier="quick",
            category="cli,scans",
            verbose=False,
            fail_fast=False,
            json=False,
        )
        with patch(
            "scripts.cli.validate_commands._get_validators"
        ) as mock_get:
            mock_get.return_value = []
            cmd_validate(args)
            # Verify categories were parsed and passed through
            mock_get.assert_called_once()


class TestJmoValidateArgs:
    """Test that jmo validate is wired into the CLI."""

    def test_validate_in_parse_args(self):
        """Verify 'validate' is a recognized subcommand."""
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate", "--help"]):
            # --help causes SystemExit(0)
            with pytest.raises(SystemExit) as exc_info:
                parse_args()
            assert exc_info.value.code == 0

    def test_validate_default_tier(self):
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate"]):
            args = parse_args()
            assert args.cmd == "validate"
            assert args.tier == "quick"

    def test_validate_full_tier(self):
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate", "--tier", "full"]):
            args = parse_args()
            assert args.tier == "full"

    def test_validate_category_flag(self):
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate", "--category", "cli,scans"]):
            args = parse_args()
            assert args.category == "cli,scans"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/cli/test_validate_commands.py -v`
Expected: FAIL with `ModuleNotFoundError`

**Step 3: Implement dispatcher and scorecard**

Create `scripts/cli/validate_commands.py` with:
- `cmd_validate(args)` — main dispatcher, parses categories, calls `run_validators`, renders scorecard
- `render_scorecard(results, verbose, json_output)` — terminal output with color-coded pass/fail/warn per category, summary line, GO/NO-GO verdict
- `_get_validators()` — returns list of validator functions (initially empty, filled in Tasks 3-6)

Wire into `scripts/cli/jmo.py`:
- Add `_add_validate_args(sub)` function after `_add_tools_args`
- Call `_add_validate_args(sub)` in `parse_args()` between tools and build
- Add `elif args.cmd == "validate":` route in `main()` with lazy import

Flags:
- `--tier {quick,full}` (default: quick)
- `--category CAT` (comma-separated string, optional)
- `--verbose, -v` (bool)
- `--fail-fast` (bool)
- `--json` (bool)

**Step 4: Run tests to verify they pass**

Run: `pytest tests/cli/test_validate_commands.py -v`
Expected: all PASS

**Step 5: Commit**

```bash
git add scripts/cli/validate_commands.py scripts/cli/jmo.py tests/cli/test_validate_commands.py
git commit -m "feat(validate): add CLI dispatcher and scorecard renderer"
```

---

## Task 3: CLI Completeness Validator (45 checks)

**Files:**
- Create: `scripts/core/validators/cli_validator.py`
- Test: `tests/core/test_cli_validator.py`

**Implementation approach:** Use `subprocess.run([sys.executable, "-m", "scripts.cli.jmo", ...])` to exercise CLI commands in a subprocess. This tests the real CLI end-to-end without mocking.

**Check groups to implement:**

1. **Subcommand --help (13 checks):** Loop over all main subcommands, run `jmo <cmd> --help`, assert exit code 0.
2. **Sub-subcommand --help (27 checks):** Loop over nested commands (`tools check`, `history list`, etc.), same approach.
3. **Required arg enforcement (12 checks):** Run commands that need required args without them, assert exit code 2.
4. **Invalid arg rejection (6 checks):** Run with `--nonexistent-flag`, assert exit code 2.
5. **Mutually exclusive groups (4 checks):** Run with conflicting flags, assert exit code 2.
6. **Flag type validation (6 checks):** Run with wrong types (`--threads abc`), assert exit code 2.
7. **Version/identity (3 checks):** Run `jmo --version`, parse output, compare with pyproject.toml.
8. **Exit code contracts (4 checks):** Verify specific exit code scenarios.
9. **Full tier (8 checks):** Actually run tools check, adapters list, etc. and verify output.

**Key pattern for all subprocess checks:**

```python
def _run_jmo(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run jmo CLI command in subprocess."""
    return subprocess.run(
        [sys.executable, "-m", "scripts.cli.jmo", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
```

**Tests:** Test the validator function itself by mocking subprocess to avoid spawning real processes during unit tests. Integration test (marked `@pytest.mark.integration`) runs the real validator.

**Step 1:** Write tests for `validate_cli(tier)` → `CategoryResult`
**Step 2:** Run, verify fail
**Step 3:** Implement `validate_cli` with all check groups
**Step 4:** Run, verify pass
**Step 5:** Commit

```bash
git add scripts/core/validators/cli_validator.py tests/core/test_cli_validator.py
git commit -m "feat(validate): add CLI completeness validator (45 checks)"
```

---

## Task 4: Scan Correctness Validator (72 checks)

**Files:**
- Create: `scripts/core/validators/scan_validator.py`
- Test: `tests/core/test_scan_validator.py`

**Implementation approach:** Direct Python imports (no subprocess). Import adapters, dedup engine, compliance mapper, schema validator, and reporters. Exercise them against fixture data.

**Check groups to implement:**

1. **Adapter registry (6 checks):** Import `get_plugin_registry()`, verify count, naming conventions, no duplicates.
2. **Fixture parsing (28 checks):** For each adapter, load its golden fixture from `tests/fixtures/golden/<tool>/`, parse through adapter, verify non-empty findings list.
3. **Severity mapping (3 checks):** Check `TOOL_SEVERITY_MAPPINGS` has entries for all adapters, all tool-specific severities map to standard set.
4. **CommonFinding schema (5 checks):** Use `validate_findings()` from `schema_validator.py` against parsed fixtures.
5. **Empty/malformed input (6 checks):** Pass `{}`, `[]`, `None`, truncated JSON to adapters.
6. **Deduplication (12 checks):** Load `tests/fixtures/cross_tool_findings.json`, run dedup, verify reduction, path normalization, threshold behavior, algorithm selection.
7. **Compliance enrichment (8 checks):** Run `enrich_findings_with_compliance()` on sample findings, verify OWASP/CWE/CIS/NIST/PCI/MITRE fields populated.
8. **SBOM enrichment (4 checks):** Verify Trivy-Syft cross-enrichment on fixture data.
9. **Reporter output (8 checks):** Generate each reporter output (JSON, MD, HTML, SARIF, CSV) from fixture findings, verify valid format.
10. **Full tier (12 checks):** Real scan, E2E pipeline, determinism, stability checks.

**Key import references:**

```python
from scripts.core.plugin_loader import get_plugin_registry, get_plugin_loader
from scripts.core.schema_validator import validate_findings, load_schema
from scripts.core.common_finding import TOOL_SEVERITY_MAPPINGS, map_tool_severity
from scripts.core.compliance_mapper import enrich_findings_with_compliance
from scripts.core.normalize_and_report import deduplicate_findings_memory_efficient
```

**Step 1:** Write tests
**Step 2:** Run, verify fail
**Step 3:** Implement `validate_scans(tier)` with all check groups
**Step 4:** Run, verify pass
**Step 5:** Commit

```bash
git add scripts/core/validators/scan_validator.py tests/core/test_scan_validator.py
git commit -m "feat(validate): add scan correctness validator (72 checks)"
```

---

## Task 5: Cross-Platform Validator (38 checks)

**Files:**
- Create: `scripts/core/validators/platform_validator.py`
- Test: `tests/core/test_platform_validator.py`

**Implementation approach:** Mix of Python introspection (check pathlib, os, platform), AST scanning (find shell=True), and runtime checks (create temp dirs, test SQLite).

**Check groups to implement:**

1. **Path handling (8 checks):** Verify pathlib operations, mixed separators, long paths, spaces, unicode.
2. **Subprocess security (4 checks):** AST scan all `.py` files under `scripts/` for `shell=True` in `subprocess.run/call/Popen`. Also check for string formatting in subprocess args.
3. **Home dir/config (3 checks):** `Path.home()` works, `.jmo/` can be created in temp, config loads with platform paths.
4. **File operations (5 checks):** UTF-8 read/write, temp dirs, BOM handling, line endings, large file.
5. **Environment variables (4 checks):** Parse and validate `JMO_THREADS`, `JMO_DEDUP_THRESHOLD`, `JMO_PROFILE`, `DOCKER_CONTAINER`.
6. **SQLite platform (5 checks):** Create in-memory DB, enable WAL, test timeout, VACUUM, verify lock release.
7. **Process/threading (4 checks):** `os.cpu_count()`, thread pool, no hang detection, signal handling.
8. **Full tier (5 checks):** Docker daemon check, volume mount test, WSL detection.

**Key pattern for AST scanning:**

```python
import ast

def _check_no_shell_true(py_files: list[Path]) -> list[CheckResult]:
    """Scan Python files for shell=True in subprocess calls."""
    results = []
    for path in py_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                        if kw.value.value is True:
                            results.append(CheckResult(
                                name=f"shell=True in {path.name}:{node.lineno}",
                                status=CheckStatus.FAIL,
                                message=f"Found shell=True at line {node.lineno}",
                            ))
    return results
```

**Step 1:** Write tests
**Step 2:** Run, verify fail
**Step 3:** Implement `validate_platform(tier)`
**Step 4:** Run, verify pass
**Step 5:** Commit

```bash
git add scripts/core/validators/platform_validator.py tests/core/test_platform_validator.py
git commit -m "feat(validate): add cross-platform validator (38 checks)"
```

---

## Task 6: Release Artifacts Validator (52 checks)

**Files:**
- Create: `scripts/core/validators/release_validator.py`
- Test: `tests/core/test_release_validator.py`

**Implementation approach:** File parsing (TOML, YAML, Markdown), git commands (status, log), pattern matching (badge versions, secret patterns), and existing script integration.

**Check groups to implement:**

1. **Version consistency (6 checks):** Parse `pyproject.toml` (`tomllib`), read `__version__` from `jmo.py`, parse CHANGELOG.md header.
2. **Documentation links (6 checks):** Parse all `.md` files, extract `[text](path)` links, verify internal links resolve. External URLs are full-tier only.
3. **Tool versions (4 checks):** Parse `versions.yaml`, verify all deep-profile tools present, check format.
4. **Badge accuracy (2 checks):** Regex-extract PyPI badge version from README, compare with pyproject.toml.
5. **Git hygiene (5 checks):** `git status --porcelain`, check branch, no untracked in scripts/, no conflicts.
6. **Security (6 checks):** Pattern scan for secrets, verify no shell=True (cross-ref with platform), no large files, no artifact dirs tracked.
7. **Code quality (6 checks):** Run `black --check`, `ruff check`, import direction check, pre-commit order.
8. **Test health (6 checks):** Parse pytest collection output for test count, parse coverage report, check markers.
9. **Schema/config (5 checks):** Validate JSON schema file, YAML configs.
10. **Full tier (6 checks):** Docker builds, pip install, entry point.

**Key pattern for version parsing:**

```python
import tomllib

def _get_pyproject_version() -> str:
    with open("pyproject.toml", "rb") as f:
        data = tomllib.load(f)
    return data["project"]["version"]
```

**Step 1:** Write tests
**Step 2:** Run, verify fail
**Step 3:** Implement `validate_release(tier)`
**Step 4:** Run, verify pass
**Step 5:** Commit

```bash
git add scripts/core/validators/release_validator.py tests/core/test_release_validator.py
git commit -m "feat(validate): add release artifacts validator (52 checks)"
```

---

## Task 7: Wire All Validators Together

**Files:**
- Modify: `scripts/cli/validate_commands.py` (update `_get_validators()` to import all 4)
- Modify: `scripts/core/validators/__init__.py` (add convenience imports)
- Test: `tests/cli/test_validate_integration.py`

**Step 1: Write integration test**

```python
# tests/cli/test_validate_integration.py
"""Integration tests for jmo validate end-to-end."""

import subprocess
import sys

import pytest


@pytest.mark.integration
class TestValidateIntegration:
    def test_quick_tier_runs(self):
        """jmo validate --tier quick should complete without crashing."""
        result = subprocess.run(
            [sys.executable, "-m", "scripts.cli.jmo", "validate", "--tier", "quick"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode in (0, 1)  # pass or fail, not crash
        assert "Validation Report" in result.stdout

    def test_json_output(self):
        """jmo validate --json should produce valid JSON."""
        import json

        result = subprocess.run(
            [sys.executable, "-m", "scripts.cli.jmo", "validate", "--json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        data = json.loads(result.stdout)
        assert "verdict" in data
        assert "categories" in data

    def test_category_filter(self):
        """jmo validate --category cli should only run CLI checks."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.cli.jmo",
                "validate",
                "--category",
                "cli",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert "CLI Completeness" in result.stdout
        # Other categories should NOT appear
        assert "Scan Correctness" not in result.stdout

    def test_verbose_flag(self):
        """jmo validate -v should show per-check details."""
        result = subprocess.run(
            [sys.executable, "-m", "scripts.cli.jmo", "validate", "-v"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        # Verbose should show individual check names
        assert result.returncode in (0, 1)
```

**Step 2: Update `_get_validators()` in validate_commands.py**

```python
def _get_validators() -> list[ValidatorFn]:
    from scripts.core.validators.cli_validator import validate_cli
    from scripts.core.validators.scan_validator import validate_scans
    from scripts.core.validators.platform_validator import validate_platform
    from scripts.core.validators.release_validator import validate_release

    return [validate_cli, validate_scans, validate_platform, validate_release]
```

**Step 3: Run integration tests**

Run: `pytest tests/cli/test_validate_integration.py -v -m integration`
Expected: PASS (may have some validation failures, but no crashes)

**Step 4: Commit**

```bash
git add scripts/cli/validate_commands.py scripts/core/validators/__init__.py tests/cli/test_validate_integration.py
git commit -m "feat(validate): wire all 4 validators into jmo validate"
```

---

## Task 8: Documentation & Cleanup

**Files:**
- Modify: `CLAUDE.md` (add validate to essential commands table)
- Modify: `docs/CLI_REFERENCE.md` (add validate subcommand)
- Modify: `docs/RELEASE.md` (reference jmo validate in release process)
- Remove: `scripts/dev/pre_release_check.py` (superseded)
- Remove: `scripts/dev/verify_release_readiness.py` (superseded)

**Step 1: Update CLAUDE.md essential commands table**

Add row: `| jmo validate | Pre-release validation scorecard |`
Add row: `| jmo validate --tier full | Full validation with real tools |`

**Step 2: Update CLI_REFERENCE.md**

Add `validate` section with flags, examples, and output format.

**Step 3: Update RELEASE.md**

Replace references to `pre_release_check.py` and `verify_release_readiness.py` with `jmo validate`.

**Step 4: Remove superseded scripts**

```bash
git rm scripts/dev/pre_release_check.py scripts/dev/verify_release_readiness.py
```

**Step 5: Run full test suite**

Run: `make test-fast`
Expected: all PASS, no regressions

**Step 6: Commit**

```bash
git add -A
git commit -m "docs: add jmo validate to CLI reference and release process

Removes superseded pre_release_check.py and verify_release_readiness.py."
```

---

## Execution Strategy: Agent Teams

This plan is designed for parallel implementation with agent teams:

| Agent | Task | File Ownership |
|-------|------|----------------|
| **Lead** | Tasks 1, 2, 7, 8 | `jmo.py`, `validate_commands.py`, `__init__.py`, docs |
| **Agent A** | Task 3 | `cli_validator.py` + `test_cli_validator.py` |
| **Agent B** | Task 4 | `scan_validator.py` + `test_scan_validator.py` |
| **Agent C** | Task 5 | `platform_validator.py` + `test_platform_validator.py` |
| **Agent D** | Task 6 | `release_validator.py` + `test_release_validator.py` |

**Dependencies:**
- Task 1 (shared types) must complete before Tasks 3-6 start
- Tasks 3-6 can run in parallel
- Task 7 (wiring) requires Tasks 3-6 complete
- Task 8 (docs) requires Task 7 complete

**Estimated check counts after implementation:**
- Quick tier: 176 checks (no external tools needed)
- Full tier: 207 checks (requires tools + Docker)
