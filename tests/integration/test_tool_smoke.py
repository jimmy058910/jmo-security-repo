#!/usr/bin/env python3
"""
Tool smoke tests: verify tools complete within timeout and produce parseable output.

These tests run each tool on the juice_shop_fixture and verify:
1. Tool completes within configured timeout (catches hangs like cdxgen 9+ min)
2. Tool produces valid output that the adapter can parse
3. Adapter returns at least some minimum expected findings

Unlike contract tests (structural validation) or baseline tests (full vulnerability coverage),
these smoke tests focus on:
- Fast feedback: Each tool tested in isolation with enforced timeout
- Hang detection: Catches tools that hang due to NVD downloads, network issues, etc.
- Adapter integration: Verifies end-to-end tool -> adapter -> findings flow

Usage:
    # Run all smoke tests (requires tools installed)
    pytest tests/integration/test_tool_smoke.py -v -m smoke

    # Run specific tool's smoke test
    pytest tests/integration/test_tool_smoke.py -v -k "semgrep"

    # Run with explicit timeout (catch hangs faster)
    pytest tests/integration/test_tool_smoke.py -v --timeout=60

Schedule:
    These tests run nightly in scheduled-tests.yml (not on every PR - requires tools)
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from scripts.core.plugin_loader import get_plugin_registry
from scripts.core.tool_registry import PROFILE_TOOLS

logger = logging.getLogger(__name__)

# Path to juice-shop fixture
PROJECT_ROOT = Path(__file__).parent.parent.parent
JUICE_SHOP_FIXTURE = PROJECT_ROOT / "tests" / "integration" / "juice_shop_fixture"

# JMo bin directory for installed tools
JMO_BIN_DIR = Path.home() / ".jmo" / "bin"


def get_tool_path(tool_name: str) -> Path | None:
    """
    Find the full path to a tool, checking both PATH and ~/.jmo/bin/.

    Args:
        tool_name: Name of the tool binary

    Returns:
        Path to the tool, or None if not found
    """
    # Check PATH first
    path = shutil.which(tool_name)
    if path:
        return Path(path)

    # Check ~/.jmo/bin/ (where jmo tools install puts binaries)
    if JMO_BIN_DIR.exists():
        # Try exact name
        jmo_path = JMO_BIN_DIR / tool_name
        if jmo_path.exists():
            return jmo_path

        # Try with .exe suffix on Windows
        jmo_path_exe = JMO_BIN_DIR / f"{tool_name}.exe"
        if jmo_path_exe.exists():
            return jmo_path_exe

        # Try in subdirectory (e.g., zap/zap.sh)
        jmo_subdir = JMO_BIN_DIR / tool_name
        if jmo_subdir.is_dir():
            # Look for launcher script
            for launcher in [f"{tool_name}.sh", f"{tool_name}.bat", tool_name]:
                launcher_path = jmo_subdir / launcher
                if launcher_path.exists():
                    return launcher_path

    return None


def get_env_with_jmo_bin() -> dict[str, str]:
    """Get environment with ~/.jmo/bin/ added to PATH."""
    env = os.environ.copy()
    if JMO_BIN_DIR.exists():
        current_path = env.get("PATH", "")
        env["PATH"] = f"{JMO_BIN_DIR}{os.pathsep}{current_path}"
    return env


@dataclass
class ToolSmokeConfig:
    """Configuration for a tool smoke test."""

    name: str
    timeout: int  # seconds
    min_findings: int  # Minimum expected findings (0 = just check tool runs)
    command_template: list[str]  # Command with {target} and {output} placeholders
    output_format: str = "json"  # json, ndjson, or stdout
    description: str = ""
    skip_reason: str | None = None  # Skip with this reason if set


# Tool configurations for balanced profile smoke tests
# Command templates match the patterns used in scripts/cli/scan_jobs/repository_scanner.py
# Each tool has a timeout based on expected runtime + safety margin
SMOKE_TEST_CONFIGS: dict[str, ToolSmokeConfig] = {
    "trufflehog": ToolSmokeConfig(
        name="trufflehog",
        timeout=90,
        min_findings=0,  # Secrets detection varies - just check tool runs
        command_template=[
            "trufflehog",
            "filesystem",  # Use filesystem mode for non-git fixture
            "{target}",
            "--json",
            "--no-update",
        ],
        output_format="ndjson",
        description="Secrets scanner",
    ),
    "semgrep": ToolSmokeConfig(
        name="semgrep",
        timeout=180,
        min_findings=0,  # Findings vary by ruleset - just check tool runs
        command_template=[
            "semgrep",
            "--config",
            "auto",
            "--json",
            "--output",
            "{output}",
            "{target}",
        ],
        description="Multi-language SAST",
    ),
    "hadolint": ToolSmokeConfig(
        name="hadolint",
        timeout=30,
        min_findings=5,  # Dockerfile has many intentional issues
        command_template=[
            "hadolint",
            "-f",
            "json",
            "{target}/Dockerfile",
        ],
        output_format="stdout",
        description="Dockerfile linter",
    ),
    "shellcheck": ToolSmokeConfig(
        name="shellcheck",
        timeout=30,
        min_findings=5,  # vulnerable.sh has many issues
        command_template=[
            "shellcheck",
            "--format=json",
            "{target}/vulnerable.sh",
        ],
        output_format="stdout",
        description="Shell script linter",
    ),
    "trivy": ToolSmokeConfig(
        name="trivy",
        timeout=180,
        min_findings=0,  # Findings vary - just check tool runs and parses
        command_template=[
            "trivy",
            "fs",
            "-q",
            "-f",
            "json",
            "--scanners",
            "vuln,secret,misconfig",
            "{target}",
            "-o",
            "{output}",
        ],
        description="Vulnerability and misconfiguration scanner",
    ),
    "grype": ToolSmokeConfig(
        name="grype",
        timeout=180,
        min_findings=0,  # Findings vary - just check tool runs
        command_template=[
            "grype",
            "dir:{target}",
            "-o",
            "json",
            "--file",
            "{output}",
        ],
        description="Vulnerability scanner",
    ),
    "syft": ToolSmokeConfig(
        name="syft",
        timeout=120,
        min_findings=5,  # Should find npm packages as SBOM components
        command_template=[
            "syft",
            "dir:{target}",
            "-o",
            "json",
        ],
        output_format="stdout",  # Syft outputs to stdout, CLI captures it
        description="SBOM generator",
    ),
    "checkov": ToolSmokeConfig(
        name="checkov",
        timeout=180,
        min_findings=0,  # Findings vary - just check tool runs
        command_template=[
            "checkov",
            "-d",
            "{target}",
            "-o",
            "json",
        ],
        output_format="stdout",  # Checkov outputs to stdout, CLI captures it
        description="IaC scanner",
    ),
    "bearer": ToolSmokeConfig(
        name="bearer",
        timeout=180,
        min_findings=0,  # Findings vary - just check tool runs
        command_template=[
            "bearer",
            "scan",
            "{target}",
            "--format",
            "json",
            "--output",
            "{output}",
        ],
        description="Data privacy scanner",
    ),
    "horusec": ToolSmokeConfig(
        name="horusec",
        timeout=240,
        min_findings=0,  # Findings vary - just check tool runs
        command_template=[
            "horusec",
            "start",
            "-p",
            "{target}",
            "-o",
            "json",
            "-O",
            "{output}",
            "-D",  # Disable docker tools for faster execution
        ],
        description="Multi-language SAST",
    ),
    "kubescape": ToolSmokeConfig(
        name="kubescape",
        timeout=120,
        min_findings=0,  # Findings vary - just check tool runs
        command_template=[
            "kubescape",
            "scan",
            "{target}/k8s-deployment.yaml",
            "--format",
            "json",
            "--output",
            "{output}",
        ],
        description="Kubernetes security scanner",
    ),
    "prowler": ToolSmokeConfig(
        name="prowler",
        timeout=180,
        min_findings=0,  # May not find issues without AWS credentials
        command_template=[
            "prowler",
            "--output-formats",
            "json",
            "--output-directory",
            "{output_dir}",
        ],
        description="Cloud security scanner",
        skip_reason="Requires cloud credentials",
    ),
    "gosec": ToolSmokeConfig(
        name="gosec",
        timeout=120,
        min_findings=0,  # No Go code in fixture
        command_template=[
            "gosec",
            "-fmt=json",
            "-out={output}",
            "{target}/...",
        ],
        description="Go security scanner",
        skip_reason="No Go code in juice-shop fixture",
    ),
    "scancode": ToolSmokeConfig(
        name="scancode",
        timeout=240,
        min_findings=5,  # License detection
        command_template=[
            "scancode",
            "--license",
            "--copyright",
            "--json-pp",
            "{output}",
            "{target}",
        ],
        description="License scanner",
        skip_reason="Complex installation on Windows - requires isolated venv",
    ),
    "cdxgen": ToolSmokeConfig(
        name="cdxgen",
        timeout=180,  # With optimizations, should complete in <3 min
        min_findings=1,  # SBOM should have at least one component
        command_template=[
            "cdxgen",
            "--no-install-deps",  # Don't install dependencies (major speedup)
            "--required-only",  # Only required deps, skip optional/dev
            "-o",
            "{output}",
            "{target}",
        ],
        description="CycloneDX SBOM generator",
    ),
    "zap": ToolSmokeConfig(
        name="zap",
        timeout=240,
        min_findings=0,  # DAST requires running server
        command_template=[
            "zap.sh",
            "-cmd",
            "-quickurl",
            "http://localhost:3000",
            "-quickout",
            "{output}",
        ],
        description="DAST scanner",
        skip_reason="Requires running application server",
    ),
    "nuclei": ToolSmokeConfig(
        name="nuclei",
        timeout=180,
        min_findings=0,  # Network scanner, may not find anything on static files
        command_template=[
            "nuclei",
            "-t",
            "cves/",
            "-target",
            "http://localhost:3000",
            "-je",
            "{output}",
        ],
        description="Vulnerability scanner",
        skip_reason="Requires running application server",
    ),
    "opa": ToolSmokeConfig(
        name="opa",
        timeout=60,
        min_findings=0,  # Policy engine, needs policies to evaluate
        command_template=[
            "opa",
            "eval",
            "--format",
            "json",
            "data.main.deny",
        ],
        description="Policy engine",
        skip_reason="Requires OPA policies to evaluate",
    ),
}


def tool_available(tool_name: str) -> bool:
    """Check if a tool is available in PATH or ~/.jmo/bin/."""
    config = SMOKE_TEST_CONFIGS.get(tool_name)
    if not config:
        return False

    # Get the base command (first word)
    command = config.command_template
    base_cmd = command[0] if command else tool_name

    return get_tool_path(base_cmd) is not None


def run_tool(
    config: ToolSmokeConfig, target: Path, output_dir: Path
) -> tuple[subprocess.CompletedProcess, Path | None]:
    """
    Run a tool against the target directory.

    Args:
        config: Tool configuration
        target: Path to scan (juice_shop_fixture)
        output_dir: Directory for output files

    Returns:
        Tuple of (CompletedProcess, output_file_path or None)
    """
    output_file = output_dir / f"{config.name}-output.json"

    # Build command with substitutions
    command = []
    for i, part in enumerate(config.command_template):
        part = part.replace("{target}", str(target))
        part = part.replace("{output}", str(output_file))
        part = part.replace("{output_dir}", str(output_dir))

        # For the first element (the tool name), resolve to full path
        if i == 0:
            tool_path = get_tool_path(part)
            if tool_path:
                part = str(tool_path)

        command.append(part)

    logger.info(f"Running smoke test: {' '.join(command)}")

    # Get environment with ~/.jmo/bin/ in PATH
    env = get_env_with_jmo_bin()

    # Run the tool with timeout
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=config.timeout,
        cwd=PROJECT_ROOT,
        env=env,
    )

    # Determine output file based on format
    actual_output = None
    if config.output_format == "json" and output_file.exists():
        actual_output = output_file
    elif config.output_format == "stdout":
        # Write stdout to file for parsing
        stdout_file = output_dir / f"{config.name}-stdout.json"
        stdout_file.write_text(result.stdout or "[]")
        actual_output = stdout_file
    elif config.output_format == "ndjson":
        # Write stdout (NDJSON) to file for parsing
        ndjson_file = output_dir / f"{config.name}-ndjson.json"
        ndjson_file.write_text(result.stdout or "")
        actual_output = ndjson_file

    return result, actual_output


def parse_with_adapter(tool_name: str, output_file: Path) -> list[dict[str, Any]]:
    """
    Parse tool output using the appropriate adapter.

    Args:
        tool_name: Name of the tool (adapter name)
        output_file: Path to tool output file

    Returns:
        List of findings (CommonFinding dicts)
    """
    registry = get_plugin_registry()

    # Try different name formats
    adapter_names = [
        tool_name,
        tool_name.replace("-", "_"),
        tool_name.replace("_", "-"),
    ]

    adapter_class = None
    for name in adapter_names:
        adapter_class = registry.get(name)
        if adapter_class is not None:
            break

    if adapter_class is None:
        raise ValueError(f"No adapter found for {tool_name}")

    # Create adapter instance and parse
    adapter = adapter_class()

    # Handle different adapter interfaces
    if hasattr(adapter, "parse"):
        return adapter.parse(output_file)
    elif hasattr(adapter, "parse_output"):
        with open(output_file) as f:
            content = f.read()
        return adapter.parse_output(content)
    else:
        raise ValueError(f"Adapter {tool_name} has no parse method")


# Get tools in balanced profile for parametrization
BALANCED_TOOLS = PROFILE_TOOLS.get("balanced", [])


@pytest.fixture
def juice_shop_fixture() -> Path:
    """Provide path to juice-shop fixture directory."""
    if not JUICE_SHOP_FIXTURE.exists():
        pytest.skip("juice_shop_fixture directory not found")
    return JUICE_SHOP_FIXTURE


@pytest.fixture
def smoke_output_dir(tmp_path: Path) -> Path:
    """Provide temporary directory for tool output files."""
    output_dir = tmp_path / "smoke_output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


@pytest.mark.smoke
@pytest.mark.requires_tools
class TestToolSmoke:
    """Smoke tests for security tools in the balanced profile."""

    @pytest.mark.timeout(300)  # Global timeout safety net
    @pytest.mark.parametrize("tool_name", BALANCED_TOOLS)
    def test_tool_completes_and_produces_output(
        self, tool_name: str, juice_shop_fixture: Path, smoke_output_dir: Path
    ):
        """
        Smoke test: tool runs within timeout and produces parseable output.

        This test catches:
        - Tools that hang (e.g., cdxgen taking 9+ minutes)
        - Tools that crash or produce invalid output
        - Adapter parsing failures

        Args:
            tool_name: Name of tool from balanced profile
            juice_shop_fixture: Path to test fixture
            smoke_output_dir: Temporary output directory
        """
        # Get tool configuration
        config = SMOKE_TEST_CONFIGS.get(tool_name)

        if config is None:
            pytest.skip(f"No smoke test config for {tool_name}")

        if config.skip_reason:
            pytest.skip(config.skip_reason)

        # Check tool is installed
        if not tool_available(tool_name):
            pytest.skip(f"{tool_name} not installed")

        # Run the tool
        try:
            result, output_file = run_tool(config, juice_shop_fixture, smoke_output_dir)
        except subprocess.TimeoutExpired:
            pytest.fail(
                f"{tool_name} timed out after {config.timeout}s "
                f"(expected: <{config.timeout}s). "
                f"This indicates the tool is hanging or taking unexpectedly long."
            )
        except FileNotFoundError as e:
            pytest.skip(f"{tool_name} not found: {e}")

        # Log result for debugging
        logger.info(
            f"{tool_name}: returncode={result.returncode}, "
            f"stdout_len={len(result.stdout)}, stderr_len={len(result.stderr)}"
        )

        # Allow return codes 0 and 1 (many tools use 1 for "findings found")
        # Fail on return codes 2+ which typically indicate errors
        assert result.returncode in (
            0,
            1,
        ), f"{tool_name} failed with returncode {result.returncode}: {result.stderr[:500]}"

        # Verify output exists for tools that write files
        if config.output_format != "ndjson" and output_file:
            assert (
                output_file.exists()
            ), f"{tool_name} did not produce output file at {output_file}"

    @pytest.mark.timeout(300)
    @pytest.mark.parametrize(
        "tool_name",
        [
            t
            for t in BALANCED_TOOLS
            if t in SMOKE_TEST_CONFIGS and not SMOKE_TEST_CONFIGS[t].skip_reason
        ],
    )
    def test_adapter_parses_output(
        self, tool_name: str, juice_shop_fixture: Path, smoke_output_dir: Path
    ):
        """
        Integration test: adapter successfully parses tool output.

        This test verifies the adapter can handle real tool output,
        catching schema changes or parsing bugs.
        """
        config = SMOKE_TEST_CONFIGS.get(tool_name)
        if config is None or config.skip_reason:
            pytest.skip(f"Skipped: {tool_name}")

        if not tool_available(tool_name):
            pytest.skip(f"{tool_name} not installed")

        # Run tool
        try:
            result, output_file = run_tool(config, juice_shop_fixture, smoke_output_dir)
        except subprocess.TimeoutExpired:
            pytest.fail(f"{tool_name} timed out")
        except FileNotFoundError:
            pytest.skip(f"{tool_name} not found")

        if result.returncode not in (0, 1):
            pytest.skip(f"{tool_name} failed with returncode {result.returncode}")

        if not output_file or not output_file.exists():
            # For tools that might not produce output on clean targets
            if config.min_findings == 0:
                pytest.skip(f"{tool_name} produced no output (acceptable)")
            pytest.fail(f"{tool_name} produced no output file")

        # Parse with adapter
        try:
            findings = parse_with_adapter(tool_name, output_file)
        except Exception as e:
            pytest.fail(f"{tool_name} adapter failed to parse output: {e}")

        # Verify findings structure
        assert isinstance(
            findings, list
        ), f"{tool_name} adapter returned {type(findings)}, expected list"

        # Check minimum findings if configured
        if config.min_findings > 0:
            assert len(findings) >= config.min_findings, (
                f"{tool_name} found {len(findings)} findings, "
                f"expected at least {config.min_findings}. "
                f"This may indicate tool misconfiguration or missing vulnerabilities in fixture."
            )

        # Verify finding structure (spot check first few)
        for finding in findings[:3]:
            if isinstance(finding, dict):
                # Should have at least some identifying information
                has_id = "ruleId" in finding or "id" in finding or "check_id" in finding
                has_severity = "severity" in finding or "level" in finding
                assert (
                    has_id or has_severity
                ), f"Finding missing identification: {finding.keys()}"


class TestSmokeTestInfrastructure:
    """Tests for smoke test infrastructure itself."""

    def test_juice_shop_fixture_exists(self):
        """Verify juice_shop_fixture directory exists."""
        assert JUICE_SHOP_FIXTURE.exists(), f"Fixture not found: {JUICE_SHOP_FIXTURE}"

    def test_fixture_has_required_files(self):
        """Verify fixture has key files for testing."""
        required_files = [
            "package.json",
            "Dockerfile",
            "lib/insecurity.ts",
            "config/default.ts",
            "vulnerable.sh",
            "k8s-deployment.yaml",
        ]

        missing = []
        for filename in required_files:
            if not (JUICE_SHOP_FIXTURE / filename).exists():
                missing.append(filename)

        if missing:
            pytest.fail(f"Missing fixture files: {missing}")

    def test_all_balanced_tools_have_config(self):
        """Verify all balanced profile tools have smoke test configs."""
        missing = []
        for tool in BALANCED_TOOLS:
            if tool not in SMOKE_TEST_CONFIGS:
                missing.append(tool)

        # This is informational, not a failure (some tools may not be testable)
        if missing:
            logger.warning(f"Tools without smoke configs: {missing}")

    def test_configs_have_reasonable_timeouts(self):
        """Verify timeout values are within reasonable bounds."""
        for name, config in SMOKE_TEST_CONFIGS.items():
            # Minimum 30s, maximum 5 minutes
            assert 30 <= config.timeout <= 300, (
                f"{name} has unreasonable timeout: {config.timeout}s. "
                f"Expected 30-300s."
            )


# Allow running directly for debugging
if __name__ == "__main__":
    print("Tool Smoke Test Configuration")
    print("=" * 60)

    for tool_name in BALANCED_TOOLS:
        config = SMOKE_TEST_CONFIGS.get(tool_name)
        available = tool_available(tool_name) if config else False

        status = ""
        if config is None:
            status = "NO CONFIG"
        elif config.skip_reason:
            status = f"SKIP: {config.skip_reason}"
        elif not available:
            status = "NOT INSTALLED"
        else:
            status = "READY"

        print(f"\n{tool_name}:")
        print(f"  Status: {status}")
        if config:
            print(f"  Timeout: {config.timeout}s")
            print(f"  Min findings: {config.min_findings}")
            print(f"  Description: {config.description}")
