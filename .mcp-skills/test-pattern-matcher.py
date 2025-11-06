#!/usr/bin/env python3
"""
Test Pattern Matcher

Analyzes existing test files to extract common testing patterns.
Use this to understand how to structure tests for new adapters.

Usage:
    python3 .mcp-skills/test-pattern-matcher.py <adapter_name>

Example:
    python3 .mcp-skills/test-pattern-matcher.py trivy
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any


def analyze_test_file(test_path: Path) -> Dict[str, Any]:
    """Extract key patterns from a test file."""
    content = test_path.read_text()

    patterns = {
        "test_file": test_path.name,
        "adapter_tested": extract_adapter_name(test_path),
        "test_count": count_tests(content),
        "fixtures": extract_fixtures(content),
        "mock_patterns": extract_mock_patterns(content),
        "assertions": extract_assertion_patterns(content),
        "edge_cases": extract_edge_cases(content),
        "imports": extract_key_imports(content),
    }

    return patterns


def extract_adapter_name(test_path: Path) -> str:
    """Extract adapter name from test file name."""
    # test_trivy_adapter.py -> trivy
    match = re.match(r'test_(.+)_adapter\.py', test_path.name)
    return match.group(1) if match else "unknown"


def count_tests(content: str) -> int:
    """Count test functions."""
    return len(re.findall(r'^def test_', content, re.MULTILINE))


def extract_fixtures(content: str) -> List[str]:
    """Extract fixture patterns."""
    fixtures = []

    # Look for @pytest.fixture
    fixture_matches = re.findall(r'@pytest\.fixture.*?\ndef (\w+)\(', content, re.DOTALL)
    fixtures.extend(fixture_matches)

    # Look for tmp_path usage
    if 'tmp_path' in content:
        fixtures.append("tmp_path (pytest builtin)")

    # Look for JSON fixtures
    json_fixtures = re.findall(r'(\w+)\.json', content)
    if json_fixtures:
        fixtures.append(f"JSON fixtures: {', '.join(set(json_fixtures[:3]))}")

    return fixtures


def extract_mock_patterns(content: str) -> List[str]:
    """Extract mocking patterns."""
    patterns = []

    # Check for common mocks
    if '@patch' in content:
        patches = re.findall(r"@patch\(['\"](.+?)['\"]\)", content)
        patterns.extend([f"@patch: {p}" for p in patches[:5]])

    if 'MagicMock' in content:
        patterns.append("MagicMock usage")

    if 'mock_open' in content:
        patterns.append("mock_open (file I/O)")

    return patterns


def extract_assertion_patterns(content: str) -> Dict[str, int]:
    """Extract assertion types and counts."""
    assertions = {}

    assert_types = [
        "assert len(",
        "assert isinstance(",
        "assert ==",
        "assert !=",
        "assert in",
        "assert not in",
        "assert is None",
        "assert is not None",
    ]

    for assert_type in assert_types:
        count = content.count(assert_type)
        if count > 0:
            assertions[assert_type] = count

    return assertions


def extract_edge_cases(content: str) -> List[str]:
    """Extract tested edge cases."""
    edge_cases = []

    # Look for test function names indicating edge cases
    edge_patterns = [
        (r'test_.*empty', 'Empty input handling'),
        (r'test_.*missing', 'Missing file/data handling'),
        (r'test_.*invalid', 'Invalid data handling'),
        (r'test_.*error', 'Error conditions'),
        (r'test_.*malformed', 'Malformed data'),
        (r'test_.*None', 'None value handling'),
    ]

    for pattern, description in edge_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            edge_cases.append(description)

    return edge_cases


def extract_key_imports(content: str) -> List[str]:
    """Extract key testing imports."""
    imports = []

    key_patterns = [
        'import pytest',
        'from unittest.mock import',
        'from pathlib import Path',
        'import json',
        'from scripts.core.adapters',
    ]

    for pattern in key_patterns:
        if pattern in content:
            # Extract full line
            for line in content.split('\n'):
                if pattern in line:
                    imports.append(line.strip())
                    break

    return imports


def calculate_coverage_estimate(patterns: Dict[str, Any]) -> Dict[str, Any]:
    """Estimate coverage based on test patterns."""
    test_count = patterns.get("test_count", 0)
    edge_cases = len(patterns.get("edge_cases", []))

    # Rough estimate
    if test_count >= 10 and edge_cases >= 3:
        estimate = "85%+ (comprehensive)"
    elif test_count >= 5 and edge_cases >= 2:
        estimate = "70-85% (good coverage)"
    elif test_count >= 3:
        estimate = "50-70% (basic coverage)"
    else:
        estimate = "<50% (needs improvement)"

    return {
        "estimate": estimate,
        "test_count": test_count,
        "edge_cases_tested": edge_cases,
        "recommendation": "Add more edge case tests" if edge_cases < 3 else "Coverage looks good"
    }


def suggest_test_template(adapter_name: str) -> str:
    """Suggest which test file to use as template."""
    # Reference implementations with good coverage
    excellent_templates = {
        "secrets": "test_trufflehog_adapter.py",
        "sast": "test_semgrep_adapter.py",
        "vulnerability": "test_trivy_adapter.py",
        "container": "test_syft_adapter.py",
    }

    # Default to trivy as it's comprehensive
    return excellent_templates.get(adapter_name, "test_trivy_adapter.py")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 .mcp-skills/test-pattern-matcher.py <adapter_name>")
        print("\nExample:")
        print("  python3 .mcp-skills/test-pattern-matcher.py trivy")
        sys.exit(1)

    adapter_name = sys.argv[1]
    test_path = Path(f"tests/adapters/test_{adapter_name}_adapter.py")

    if not test_path.exists():
        print(f"Error: {test_path} not found", file=sys.stderr)
        print(f"\nSuggested template: {suggest_test_template(adapter_name)}", file=sys.stderr)
        sys.exit(1)

    patterns = analyze_test_file(test_path)
    coverage = calculate_coverage_estimate(patterns)

    result = {
        "patterns": patterns,
        "coverage_estimate": coverage,
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
