#!/usr/bin/env python3
"""
Adapter Pattern Analyzer

Analyzes existing JMo Security adapters to extract common implementation patterns.
Use this to understand how to structure new tool adapters.

Usage:
    python3 .mcp-skills/adapter-pattern-analyzer.py <tool_name>

Example:
    python3 .mcp-skills/adapter-pattern-analyzer.py trivy
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any


def analyze_adapter(adapter_path: Path) -> Dict[str, Any]:
    """Extract key patterns from an adapter implementation."""
    content = adapter_path.read_text()

    patterns = {
        "adapter_name": adapter_path.stem,
        "decorator_used": "@adapter_plugin" in content,
        "plugin_metadata": extract_plugin_metadata(content),
        "parse_method": extract_method_signature(content, "parse"),
        "finding_creation": extract_finding_patterns(content),
        "error_handling": extract_error_patterns(content),
        "json_structure": extract_json_structure(content),
        "imports": extract_imports(content),
        "helper_functions": extract_helper_functions(content),
    }

    return patterns


def extract_plugin_metadata(content: str) -> Dict[str, str]:
    """Extract PluginMetadata fields from adapter."""
    metadata = {}

    # Extract metadata block
    metadata_match = re.search(
        r"@adapter_plugin\(PluginMetadata\((.*?)\)\)", content, re.DOTALL
    )

    if metadata_match:
        metadata_str = metadata_match.group(1)

        # Extract individual fields
        for field in [
            "name",
            "version",
            "tool_name",
            "schema_version",
            "output_format",
        ]:
            field_match = re.search(rf'{field}=["\'](.*?)["\']', metadata_str)
            if field_match:
                metadata[field] = field_match.group(1)

    return metadata


def extract_method_signature(content: str, method_name: str) -> Dict[str, Any]:
    """Extract method signature and return type."""
    pattern = rf"def {method_name}\(self,\s*(.*?)\)\s*->\s*(.+?):"
    match = re.search(pattern, content)

    if match:
        return {
            "parameters": match.group(1),
            "return_type": match.group(2).strip(),
        }
    return {}


def extract_finding_patterns(content: str) -> List[str]:
    """Extract common Finding creation patterns."""
    patterns = []

    # Look for Finding() instantiations
    finding_matches = re.finditer(r"Finding\((.*?)\)", content, re.DOTALL)

    for match in finding_matches:
        # Get first 200 chars of Finding creation
        pattern = match.group(1)[:200]
        if pattern not in patterns:
            patterns.append(pattern.strip())

    return patterns[:3]  # Return top 3 patterns


def extract_error_patterns(content: str) -> List[str]:
    """Extract error handling patterns."""
    patterns = []

    # Look for common error handling
    if "try:" in content and "except" in content:
        patterns.append("try-except blocks")
    if "if not output_path.exists():" in content:
        patterns.append("file existence check")
    if "logging.warning" in content or "logging.error" in content:
        patterns.append("logging")

    return patterns


def extract_json_structure(content: str) -> str:
    """Infer JSON structure from parsing logic."""
    if "json.load(" in content:
        # Try to find key access patterns
        keys = re.findall(r'data\[["\'](.*?)["\']\]', content)
        if keys:
            return f"Top-level keys accessed: {', '.join(set(keys[:5]))}"

    if ".readlines()" in content:
        return "NDJSON format (newline-delimited JSON)"

    return "Unknown structure - review code manually"


def extract_imports(content: str) -> List[str]:
    """Extract key imports."""
    imports = []

    import_lines = [
        line
        for line in content.split("\n")
        if line.strip().startswith("import ") or line.strip().startswith("from ")
    ]

    # Filter to most relevant
    for line in import_lines[:5]:
        imports.append(line.strip())

    return imports


def extract_helper_functions(content: str) -> List[str]:
    """Extract helper function names."""
    functions = re.findall(r"^def (_[a-z_]+)\(", content, re.MULTILINE)
    return functions[:5]  # Top 5 helpers


def compare_adapters(adapter_names: List[str]) -> Dict[str, Any]:
    """Compare multiple adapters to find common patterns."""
    adapters_dir = Path("scripts/core/adapters")

    results = {}
    for name in adapter_names:
        adapter_path = adapters_dir / f"{name}_adapter.py"
        if adapter_path.exists():
            results[name] = analyze_adapter(adapter_path)
        else:
            print(f"Warning: {adapter_path} not found", file=sys.stderr)

    return results


def suggest_similar_adapters(tool_type: str) -> List[str]:
    """Suggest which adapters to study based on tool type."""
    suggestions = {
        "sast": ["semgrep", "bandit", "gosec"],
        "secrets": ["trufflehog", "noseyparker"],
        "vulnerability": ["trivy", "grype", "osv_scanner"],
        "iac": ["checkov", "trivy"],
        "container": ["trivy", "syft"],
        "dast": ["zap", "nuclei"],
    }

    return suggestions.get(tool_type.lower(), ["trivy", "semgrep", "trufflehog"])


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 .mcp-skills/adapter-pattern-analyzer.py <tool_name>")
        print("\nExample:")
        print("  python3 .mcp-skills/adapter-pattern-analyzer.py trivy")
        print("\nOr compare multiple:")
        print("  python3 .mcp-skills/adapter-pattern-analyzer.py trivy semgrep bandit")
        sys.exit(1)

    adapter_names = sys.argv[1:]

    if len(adapter_names) == 1:
        # Single adapter analysis
        adapter_path = Path(f"scripts/core/adapters/{adapter_names[0]}_adapter.py")

        if not adapter_path.exists():
            print(f"Error: {adapter_path} not found", file=sys.stderr)
            print("\nDid you mean to analyze a similar adapter?", file=sys.stderr)
            sys.exit(1)

        patterns = analyze_adapter(adapter_path)
        print(json.dumps(patterns, indent=2))
    else:
        # Comparison mode
        comparison = compare_adapters(adapter_names)
        print(json.dumps(comparison, indent=2))


if __name__ == "__main__":
    main()
