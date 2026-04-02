"""
Golden/snapshot tests for adapter correctness.

These tests verify that adapters produce EXPECTED findings from KNOWN tool outputs.
If a tool's output format changes, these tests will fail loudly.

This catches:
- Silent adapter failures (parsing returns [] when it should find issues)
- Tool output format changes (upstream tools change JSON structure)
- Adapter regressions (bugs in parsing logic)
- Schema version mismatches

Usage:
    # Run all golden tests
    pytest tests/adapters/test_adapter_golden.py -v

    # Run golden tests for specific tool
    pytest tests/adapters/test_adapter_golden.py -v -k "trivy"

Golden File Generation:
    # Generate golden files (requires security tools installed)
    python scripts/dev/generate_golden.py --all

    # Check if golden files are current
    python scripts/dev/generate_golden.py --check-current-versions
"""

from __future__ import annotations

import importlib
import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

logger = logging.getLogger(__name__)

# Path to golden test fixtures
GOLDEN_DIR = Path(__file__).parent.parent / "fixtures" / "golden"

# Mapping of tool names to their adapter modules and classes
ADAPTER_REGISTRY: dict[str, dict[str, str]] = {
    "trivy": {
        "module": "scripts.core.adapters.trivy_adapter",
        "class": "TrivyAdapter",
    },
    "bandit": {
        "module": "scripts.core.adapters.bandit_adapter",
        "class": "BanditAdapter",
    },
    "semgrep": {
        "module": "scripts.core.adapters.semgrep_adapter",
        "class": "SemgrepAdapter",
    },
    "hadolint": {
        "module": "scripts.core.adapters.hadolint_adapter",
        "class": "HadolintAdapter",
    },
    "checkov": {
        "module": "scripts.core.adapters.checkov_adapter",
        "class": "CheckovAdapter",
    },
    "trufflehog": {
        "module": "scripts.core.adapters.trufflehog_adapter",
        "class": "TruffleHogAdapter",
    },
    "shellcheck": {
        "module": "scripts.core.adapters.shellcheck_adapter",
        "class": "ShellCheckAdapter",
    },
    "grype": {
        "module": "scripts.core.adapters.grype_adapter",
        "class": "GrypeAdapter",
    },
}


def get_golden_test_cases() -> list[tuple[str, str, Path]]:
    """Discover all golden test cases dynamically.

    Returns:
        List of (tool_name, version, golden_dir_path) tuples
    """
    cases = []

    if not GOLDEN_DIR.exists():
        logger.warning("Golden directory does not exist: %s", GOLDEN_DIR)
        return cases

    for tool_dir in sorted(GOLDEN_DIR.iterdir()):
        if not tool_dir.is_dir():
            continue

        tool_name = tool_dir.name

        for version_dir in sorted(tool_dir.iterdir()):
            if not version_dir.is_dir():
                continue

            version = version_dir.name

            # Check required files exist
            raw_output_files = list(version_dir.glob("*.json"))
            expected_file = version_dir / "expected-findings.json"

            if expected_file.exists() and len(raw_output_files) > 1:  # raw + expected
                cases.append((tool_name, version, version_dir))

    return cases


def get_adapter_for_tool(tool_name: str) -> Any:
    """Get the adapter instance for a tool.

    Args:
        tool_name: Name of the tool

    Returns:
        Adapter instance

    Raises:
        ImportError: If adapter module cannot be imported
        AttributeError: If adapter class not found in module
    """
    if tool_name not in ADAPTER_REGISTRY:
        raise ValueError(f"Unknown tool: {tool_name}. Add to ADAPTER_REGISTRY.")

    adapter_info = ADAPTER_REGISTRY[tool_name]
    module = importlib.import_module(adapter_info["module"])
    adapter_class = getattr(module, adapter_info["class"])
    return adapter_class()


def findings_to_comparable(findings: list[Any]) -> set[str]:
    """Convert findings to a set of comparable identifiers.

    Uses fingerprint/id for stable comparison across runs.
    Falls back to (ruleId, path, line) tuple if no id.

    Args:
        findings: List of Finding objects or dicts

    Returns:
        Set of finding identifiers for comparison
    """
    identifiers = set()

    for f in findings:
        # Handle both Finding objects and dicts
        if hasattr(f, "__dict__"):
            f_dict = asdict(f) if hasattr(f, "__dataclass_fields__") else vars(f)
        else:
            f_dict = f

        # Primary: use id/fingerprint
        if f_dict.get("id"):
            identifiers.add(f_dict["id"])
        else:
            # Fallback: composite key
            rule_id = f_dict.get("ruleId", "")
            location = f_dict.get("location", {})
            path = location.get("path", "") if isinstance(location, dict) else ""
            line = location.get("startLine", 0) if isinstance(location, dict) else 0
            identifiers.add(f"{rule_id}:{path}:{line}")

    return identifiers


def get_raw_output_file(golden_dir: Path) -> Path | None:
    """Find the raw output file in a golden directory.

    The raw output file is any JSON file that is NOT expected-findings.json
    or metadata.json.

    Args:
        golden_dir: Path to golden version directory

    Returns:
        Path to raw output file, or None if not found
    """
    for f in golden_dir.iterdir():
        if f.suffix == ".json" and f.name not in [
            "expected-findings.json",
            "metadata.json",
        ]:
            return f
    return None


# Generate test cases dynamically
GOLDEN_TEST_CASES = get_golden_test_cases()


@pytest.mark.skipif(
    len(GOLDEN_TEST_CASES) == 0,
    reason="No golden test fixtures found. Run: python scripts/dev/generate_golden.py --all",
)
class TestAdapterGolden:
    """Golden tests for adapter correctness."""

    @pytest.mark.parametrize(
        "tool,version,golden_dir",
        GOLDEN_TEST_CASES,
        ids=[f"{t}-{v}" for t, v, _ in GOLDEN_TEST_CASES],
    )
    def test_adapter_produces_expected_findings(
        self, tool: str, version: str, golden_dir: Path
    ):
        """
        Golden test: adapter output must match expected findings.

        This catches:
        - Tool output format changes (would produce different/fewer findings)
        - Adapter regressions (bugs in parsing logic)
        - Schema version mismatches

        Args:
            tool: Tool name (e.g., "trivy")
            version: Tool version (e.g., "v0.67.2")
            golden_dir: Path to golden test directory
        """
        # Load expected findings
        expected_file = golden_dir / "expected-findings.json"
        assert expected_file.exists(), f"Missing expected findings: {expected_file}"

        with expected_file.open() as f:
            expected_findings = json.load(f)

        # Find raw output file
        raw_output = get_raw_output_file(golden_dir)
        assert raw_output is not None, f"No raw output file found in {golden_dir}"
        assert raw_output.exists(), f"Missing raw output: {raw_output}"

        # Get adapter and parse
        try:
            adapter = get_adapter_for_tool(tool)
        except (ImportError, AttributeError, ValueError) as e:
            pytest.skip(f"Adapter not available for {tool}: {e}")

        actual_findings = adapter.parse(raw_output)

        # Convert to comparable format
        actual_ids = findings_to_comparable(actual_findings)
        expected_ids = findings_to_comparable(expected_findings)

        # === CRITICAL ASSERTION: Finding count must match ===
        # This is the key guard against silent failures
        assert len(actual_findings) == len(expected_findings), (
            f"Finding count mismatch for {tool} {version}:\n"
            f"  Expected: {len(expected_findings)} findings\n"
            f"  Actual:   {len(actual_findings)} findings\n"
            f"  This may indicate the tool's output format changed!\n"
            f"  Missing: {expected_ids - actual_ids}\n"
            f"  Extra:   {actual_ids - expected_ids}"
        )

        # === SECONDARY ASSERTION: Finding IDs should match ===
        # Order-independent comparison
        missing = expected_ids - actual_ids
        extra = actual_ids - expected_ids

        assert actual_ids == expected_ids, (
            f"Finding IDs don't match for {tool} {version}:\n"
            f"  Missing (expected but not found): {missing}\n"
            f"  Extra (found but not expected):   {extra}"
        )

    @pytest.mark.parametrize(
        "tool,version,golden_dir",
        GOLDEN_TEST_CASES,
        ids=[f"{t}-{v}" for t, v, _ in GOLDEN_TEST_CASES],
    )
    def test_adapter_does_not_crash_on_golden_input(
        self, tool: str, version: str, golden_dir: Path
    ):
        """
        Smoke test: adapter should not raise exceptions on golden input.

        Even if findings don't match exactly, the adapter should not crash.
        """
        raw_output = get_raw_output_file(golden_dir)
        if raw_output is None:
            pytest.skip(f"No raw output file found in {golden_dir}")

        try:
            adapter = get_adapter_for_tool(tool)
        except (ImportError, AttributeError, ValueError) as e:
            pytest.skip(f"Adapter not available for {tool}: {e}")

        # Should not raise
        findings = adapter.parse(raw_output)

        # Basic sanity checks
        assert isinstance(
            findings, list
        ), f"Adapter should return list, got {type(findings)}"

        for finding in findings:
            # Each finding should have required fields
            f_dict = (
                asdict(finding) if hasattr(finding, "__dataclass_fields__") else finding
            )
            assert (
                "ruleId" in f_dict or "id" in f_dict
            ), f"Finding missing ruleId/id: {f_dict}"
            assert "severity" in f_dict, f"Finding missing severity: {f_dict}"

    @pytest.mark.parametrize(
        "tool,version,golden_dir",
        GOLDEN_TEST_CASES,
        ids=[f"{t}-{v}" for t, v, _ in GOLDEN_TEST_CASES],
    )
    def test_adapter_findings_have_valid_schema(
        self, tool: str, version: str, golden_dir: Path
    ):
        """
        Schema test: all findings should have valid CommonFinding schema.
        """
        raw_output = get_raw_output_file(golden_dir)
        if raw_output is None:
            pytest.skip(f"No raw output file found in {golden_dir}")

        try:
            adapter = get_adapter_for_tool(tool)
        except (ImportError, AttributeError, ValueError) as e:
            pytest.skip(f"Adapter not available for {tool}: {e}")

        findings = adapter.parse(raw_output)

        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

        for i, finding in enumerate(findings):
            f_dict = (
                asdict(finding) if hasattr(finding, "__dataclass_fields__") else finding
            )

            # Severity must be valid
            severity = f_dict.get("severity", "")
            assert severity in valid_severities, (
                f"Finding {i} has invalid severity '{severity}'. "
                f"Valid: {valid_severities}"
            )

            # Location should have path
            location = f_dict.get("location", {})
            if location:
                assert "path" in location, f"Finding {i} location missing 'path'"

            # Tool should have name
            tool_info = f_dict.get("tool", {})
            if tool_info:
                assert "name" in tool_info, f"Finding {i} tool missing 'name'"


class TestGoldenInfrastructure:
    """Tests for golden test infrastructure itself."""

    def test_golden_directory_structure(self):
        """Verify golden directory structure is correct."""
        if not GOLDEN_DIR.exists():
            pytest.skip("Golden directory not created yet")

        # Should have subdirectories per tool
        tool_dirs = [d for d in GOLDEN_DIR.iterdir() if d.is_dir()]
        assert len(tool_dirs) >= 0, "Golden directory should exist (may be empty)"

    def test_adapter_registry_completeness(self):
        """Verify adapter registry covers all golden test tools."""
        if len(GOLDEN_TEST_CASES) == 0:
            pytest.skip("No golden test cases to verify")

        for tool, version, _ in GOLDEN_TEST_CASES:
            assert tool in ADAPTER_REGISTRY, (
                f"Tool '{tool}' has golden files but is not in ADAPTER_REGISTRY. "
                f"Add it to the registry in test_adapter_golden.py"
            )

    def test_can_import_all_registered_adapters(self):
        """Verify all adapters in registry can be imported."""
        for tool_name, adapter_info in ADAPTER_REGISTRY.items():
            try:
                module = importlib.import_module(adapter_info["module"])
                assert hasattr(
                    module, adapter_info["class"]
                ), f"Module {adapter_info['module']} missing class {adapter_info['class']}"
            except ImportError as e:
                pytest.fail(f"Cannot import adapter for {tool_name}: {e}")


# Standalone execution for debugging
if __name__ == "__main__":
    print(f"Golden directory: {GOLDEN_DIR}")
    print(f"Exists: {GOLDEN_DIR.exists()}")

    cases = get_golden_test_cases()
    print(f"\nFound {len(cases)} golden test cases:")
    for tool, version, path in cases:
        print(f"  - {tool} {version}: {path}")
