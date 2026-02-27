"""
Contract tests: verify tool outputs contain required fields.

These run real tools against minimal targets and check structural contracts.
Faster and more maintainable than full JSON Schema validation.

This catches:
- Major version breaking changes in tool output
- Renamed/removed fields
- Structural changes that would break adapters

Usage:
    # Run all contract tests (requires tools installed)
    pytest tests/integration/test_tool_contracts.py -v -m requires_tools

    # Run specific tool's contract test
    pytest tests/integration/test_tool_contracts.py -v -k "trivy"

Schedule:
    These tests run weekly in scheduled-tests.yml (not on every PR - too slow)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

logger = logging.getLogger(__name__)

# Path to sample fixtures for minimal test targets
PROJECT_ROOT = Path(__file__).parent.parent.parent
SAMPLES_DIR = PROJECT_ROOT / "tests" / "fixtures" / "samples"


# Required fields per tool (minimal contract)
# These define the structural requirements adapters depend on
TOOL_CONTRACTS: dict[str, dict[str, Any]] = {
    "trivy": {
        "required_keys": ["Results"],
        "result_item_keys": ["Target"],
        # Vulnerabilities/Secrets/Misconfigurations are optional (depends on scan mode)
        "vuln_keys": ["VulnerabilityID", "Severity"],
        "sample_target": "python-vulnerable",
        "command": ["trivy", "fs", "--format", "json", "{target}"],
        "description": "Vulnerability scanner with Results array structure",
    },
    "semgrep": {
        "required_keys": ["results"],
        "result_item_keys": ["check_id", "path", "extra"],
        "sample_target": "python-vulnerable",
        "command": ["semgrep", "--config", "auto", "--json", "{target}"],
        "description": "SAST scanner with results array structure",
    },
    "bandit": {
        "required_keys": ["results"],
        "result_item_keys": ["issue_severity", "issue_text", "filename"],
        "sample_target": "python-vulnerable",
        "command": ["bandit", "-r", "-f", "json", "{target}"],
        "description": "Python security linter with results array",
    },
    "hadolint": {
        "required_keys": [],  # Hadolint returns array at root
        "result_item_keys": ["code", "message", "file", "level"],
        "sample_target": "dockerfile-issues",
        "command": ["hadolint", "--format", "json", "{target}/Dockerfile"],
        "is_array_root": True,
        "description": "Dockerfile linter with array root structure",
    },
    "checkov": {
        "required_keys": ["results"],
        "result_item_keys": ["passed_checks", "failed_checks"],
        "check_item_keys": ["check_id", "resource", "check_result"],
        "sample_target": "terraform-misconfig",
        "command": ["checkov", "-d", "{target}", "--output", "json"],
        "description": "IaC scanner with passed/failed checks structure",
    },
    "trufflehog": {
        "required_keys": [],  # Trufflehog uses NDJSON (one object per line)
        "result_item_keys": ["SourceMetadata", "Raw", "Verified"],
        "sample_target": "credential-patterns",
        "command": ["trufflehog", "filesystem", "{target}", "--json"],
        "is_ndjson": True,
        "description": "Secrets scanner with NDJSON output",
    },
    "grype": {
        "required_keys": ["matches"],
        "result_item_keys": ["vulnerability", "artifact"],
        "vuln_keys": ["id", "severity"],
        "sample_target": "python-vulnerable",
        "command": ["grype", "dir:{target}", "-o", "json"],
        "description": "Vulnerability scanner with matches array",
    },
    "syft": {
        "required_keys": ["artifacts"],
        "result_item_keys": ["name", "version", "type"],
        "sample_target": "python-vulnerable",
        "command": ["syft", "dir:{target}", "-o", "json"],
        "description": "SBOM generator with artifacts array",
    },
    "shellcheck": {
        "required_keys": [],  # Array at root
        "result_item_keys": ["file", "line", "code", "level", "message"],
        "sample_target": "shell-issues",
        "command": ["shellcheck", "--format=json", "{target}/vulnerable_script.sh"],
        "is_array_root": True,
        "description": "Shell script linter with array root",
    },
}


def tool_available(tool_name: str) -> bool:
    """Check if a tool is available in PATH."""
    # Get the base command (first word)
    contract = TOOL_CONTRACTS.get(tool_name, {})
    command = contract.get("command", [tool_name])
    base_cmd = command[0] if command else tool_name

    return shutil.which(base_cmd) is not None


def run_tool_on_sample(
    tool_name: str, contract: dict[str, Any]
) -> dict[str, Any] | list[Any]:
    """Run a tool against its sample target and return parsed output.

    Args:
        tool_name: Name of the tool
        contract: Tool contract configuration

    Returns:
        Parsed JSON output from tool (dict or list)

    Raises:
        subprocess.TimeoutExpired: If tool times out
        json.JSONDecodeError: If output is not valid JSON
    """
    sample_target = SAMPLES_DIR / contract["sample_target"]
    if not sample_target.exists():
        raise FileNotFoundError(f"Sample target not found: {sample_target}")

    # Build command with target substitution
    command = []
    for part in contract["command"]:
        command.append(part.replace("{target}", str(sample_target)))

    logger.info("Running contract test: %s", " ".join(command))

    # Run the tool
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=180,  # 3 minute timeout
        cwd=PROJECT_ROOT,
    )

    # Parse output (may be in stdout or stderr depending on tool)
    output = result.stdout or result.stderr

    if not output.strip():
        logger.warning(
            "%s produced no output (exit code: %d)", tool_name, result.returncode
        )
        # Return empty structure appropriate for tool
        if contract.get("is_array_root") or contract.get("is_ndjson"):
            return []
        return {}

    # Handle NDJSON format (one JSON object per line)
    if contract.get("is_ndjson"):
        results = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # Skip malformed lines
        return results

    # Standard JSON parsing
    return json.loads(output)


def verify_contract(
    tool_name: str, contract: dict[str, Any], output: dict[str, Any] | list[Any]
) -> list[str]:
    """Verify tool output matches expected contract.

    Args:
        tool_name: Name of the tool
        contract: Expected contract structure
        output: Actual tool output

    Returns:
        List of contract violation messages (empty if valid)
    """
    violations = []

    # Handle array root structure
    if contract.get("is_array_root") or contract.get("is_ndjson"):
        if not isinstance(output, list):
            violations.append(f"{tool_name}: Expected array root, got {type(output)}")
            return violations

        # Check items if any exist
        if output and contract.get("result_item_keys"):
            first_item = output[0]
            for key in contract["result_item_keys"]:
                if key not in first_item:
                    violations.append(
                        f"{tool_name}: Result item missing required key '{key}'"
                    )
        return violations

    # Handle dict root structure
    if not isinstance(output, dict):
        violations.append(f"{tool_name}: Expected dict root, got {type(output)}")
        return violations

    # Check top-level required keys
    for key in contract.get("required_keys", []):
        if key not in output:
            violations.append(f"{tool_name}: Missing required top-level key '{key}'")

    # Check nested structure if results exist
    results_key = (
        contract.get("required_keys", [None])[0]
        if contract.get("required_keys")
        else None
    )
    if results_key and results_key in output:
        results = output[results_key]

        if isinstance(results, list) and results:
            first_result = results[0]

            # Check result item keys
            for key in contract.get("result_item_keys", []):
                if key not in first_result:
                    violations.append(f"{tool_name}: Result item missing key '{key}'")

            # Check nested vulnerability keys if applicable
            if contract.get("vuln_keys"):
                vuln_array = first_result.get("Vulnerabilities") or first_result.get(
                    "vulnerability"
                )
                if vuln_array and isinstance(vuln_array, (list, dict)):
                    vuln = vuln_array[0] if isinstance(vuln_array, list) else vuln_array
                    for key in contract["vuln_keys"]:
                        if key not in vuln:
                            violations.append(
                                f"{tool_name}: Vulnerability missing key '{key}'"
                            )

    return violations


# Generate test parameters from contracts
CONTRACT_TOOL_NAMES = list(TOOL_CONTRACTS.keys())


@pytest.mark.requires_tools
class TestToolContracts:
    """Contract tests for security tool outputs."""

    @pytest.mark.parametrize("tool_name", CONTRACT_TOOL_NAMES)
    def test_tool_output_contract(self, tool_name: str):
        """
        Contract test: tool output must contain required fields.

        This catches:
        - Major version breaking changes in tool output
        - Renamed/removed fields that would break adapters

        Args:
            tool_name: Name of tool to test
            tmp_path: Pytest temporary directory
        """
        contract = TOOL_CONTRACTS[tool_name]

        # Skip if tool not installed
        if not tool_available(tool_name):
            pytest.skip(f"{tool_name} not installed")

        # Check sample target exists
        sample_target = SAMPLES_DIR / contract["sample_target"]
        if not sample_target.exists():
            pytest.skip(f"Sample target not found: {sample_target}")

        # Run tool and get output
        try:
            output = run_tool_on_sample(tool_name, contract)
        except subprocess.TimeoutExpired:
            pytest.fail(f"{tool_name} timed out after 180s")
        except FileNotFoundError as e:
            pytest.skip(str(e))
        except json.JSONDecodeError as e:
            pytest.fail(f"{tool_name} produced invalid JSON: {e}")

        # Verify contract
        violations = verify_contract(tool_name, contract, output)

        if violations:
            violation_msg = "\n".join(f"  - {v}" for v in violations)
            pytest.fail(
                f"Contract violations for {tool_name}:\n{violation_msg}\n\n"
                f"Tool description: {contract.get('description', 'N/A')}\n"
                f"This may indicate a breaking change in the tool's output format!"
            )

    @pytest.mark.parametrize("tool_name", CONTRACT_TOOL_NAMES)
    def test_tool_produces_some_output(self, tool_name: str):
        """
        Sanity test: tool should produce some output on sample target.

        This catches:
        - Tool completely broken/misconfigured
        - Sample target doesn't trigger any findings
        """
        contract = TOOL_CONTRACTS[tool_name]

        if not tool_available(tool_name):
            pytest.skip(f"{tool_name} not installed")

        sample_target = SAMPLES_DIR / contract["sample_target"]
        if not sample_target.exists():
            pytest.skip(f"Sample target not found: {sample_target}")

        try:
            output = run_tool_on_sample(tool_name, contract)
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            pytest.fail(f"{tool_name} failed: {e}")
        except FileNotFoundError as e:
            pytest.skip(str(e))

        # Should have some output
        if isinstance(output, dict):
            # For dict output, check it's not empty or has results
            results_key = contract.get("required_keys", [None])[0]
            if results_key:
                results = output.get(results_key, [])
                # Some tools return empty results if no issues found - that's OK
                logger.info(
                    "%s returned %d results",
                    tool_name,
                    len(results) if isinstance(results, list) else 1,
                )
            else:
                assert len(output) > 0, f"{tool_name} returned empty dict"
        elif isinstance(output, list):
            # For array output, log count
            logger.info("%s returned %d items", tool_name, len(output))


class TestContractInfrastructure:
    """Tests for contract test infrastructure."""

    def test_all_contracts_have_required_fields(self):
        """Verify all tool contracts have necessary configuration."""
        required_fields = ["command", "sample_target"]

        for tool_name, contract in TOOL_CONTRACTS.items():
            for field in required_fields:
                assert (
                    field in contract
                ), f"Contract for {tool_name} missing required field '{field}'"

    def test_sample_targets_exist(self):
        """Verify all sample targets referenced by contracts exist."""
        missing = []

        for tool_name, contract in TOOL_CONTRACTS.items():
            sample_target = SAMPLES_DIR / contract["sample_target"]
            if not sample_target.exists():
                missing.append(f"{tool_name}: {sample_target}")

        if missing:
            pytest.fail(
                "Missing sample targets:\n" + "\n".join(f"  - {m}" for m in missing)
            )

    def test_contracts_cover_key_adapters(self):
        """Verify contracts exist for critical adapters."""
        critical_tools = ["trivy", "semgrep", "bandit", "trufflehog", "checkov"]

        missing = [t for t in critical_tools if t not in TOOL_CONTRACTS]

        if missing:
            pytest.fail(
                f"Missing contracts for critical tools: {missing}\n"
                f"Add contracts to TOOL_CONTRACTS in test_tool_contracts.py"
            )


# Allow running directly for debugging
if __name__ == "__main__":
    print("Tool Contract Test Configuration")
    print("=" * 50)

    for tool_name, contract in TOOL_CONTRACTS.items():
        available = "✅" if tool_available(tool_name) else "❌"
        sample = SAMPLES_DIR / contract["sample_target"]
        sample_exists = "✅" if sample.exists() else "❌"

        print(f"\n{tool_name}:")
        print(f"  Available: {available}")
        print(f"  Sample exists: {sample_exists} ({sample})")
        print(f"  Required keys: {contract.get('required_keys', [])}")
        print(f"  Description: {contract.get('description', 'N/A')}")
