#!/usr/bin/env python3
"""
Quick Coverage Analyzer

Fast coverage check for a specific module without running full test suite.

Usage:
    python3 .mcp-skills/quick-coverage.py <module_path>

Example:
    python3 .mcp-skills/quick-coverage.py scripts/core/adapters/trivy_adapter.py
"""

import json
import subprocess
import sys
from pathlib import Path


def get_module_coverage(module_path: str) -> dict:
    """Run pytest coverage for specific module."""
    # Convert file path to module path
    if module_path.endswith(".py"):
        module_path = module_path[:-3]

    module_path = module_path.replace("/", ".")

    # Run pytest with coverage
    cmd = [
        "python3",
        "-m",
        "pytest",
        f"--cov={module_path}",
        "--cov-report=json",
        "--cov-report=term",
        "-q",
        "--no-header",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        # Parse coverage.json if it exists
        coverage_json = Path("coverage.json")
        if coverage_json.exists():
            with open(coverage_json) as f:
                coverage_data = json.load(f)

            # Extract relevant info
            files = coverage_data.get("files", {})
            total_coverage = coverage_data.get("totals", {}).get("percent_covered", 0)

            return {
                "success": True,
                "coverage": f"{total_coverage:.1f}%",
                "files_analyzed": len(files),
                "stdout": result.stdout,
            }
        else:
            return {
                "success": False,
                "error": "coverage.json not generated",
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout after 30 seconds"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 .mcp-skills/quick-coverage.py <module_path>")
        print("\nExample:")
        print(
            "  python3 .mcp-skills/quick-coverage.py scripts/core/adapters/trivy_adapter.py"
        )
        sys.exit(1)

    module_path = sys.argv[1]
    result = get_module_coverage(module_path)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
