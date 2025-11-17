#!/usr/bin/env python3
"""
Quick test script to verify React dashboard integration.
Tests both inline mode (≤1000 findings) and external mode (>1000 findings).
"""
import json
from pathlib import Path
from scripts.core.reporters.html_reporter import write_html, INLINE_THRESHOLD


# Create test findings
def create_test_finding(i):
    return {
        "schemaVersion": "1.2.0",
        "id": f"fingerprint-{i}",
        "ruleId": f"TEST-{i:03d}",
        "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"][i % 5],
        "message": f"Test finding {i}",
        "tool": {"name": "test-tool", "version": "1.0.0"},
        "location": {
            "path": f"test-{i}.ts",
            "startLine": i * 10,
            "endLine": i * 10 + 5,
            "startColumn": 1,
            "endColumn": 20,
        },
    }


# Test inline mode (≤1000 findings)
print("Testing inline mode (100 findings)...")
inline_findings = [create_test_finding(i) for i in range(100)]
inline_output = Path("test-inline-dashboard.html")
write_html(inline_findings, inline_output)
assert inline_output.exists(), "Inline dashboard not created"
inline_content = inline_output.read_text()
assert "window.__FINDINGS__ = [{" in inline_content, "Inline data not embedded"
# Note: "findings.json" appears in JavaScript export functions, which is OK
# We just verify that inline data is embedded
print(f"✅ Inline mode works! Size: {inline_output.stat().st_size / 1024:.1f} KB")

# Test external mode (>1000 findings)
print(f"\nTesting external mode ({INLINE_THRESHOLD + 100} findings)...")
external_findings = [create_test_finding(i) for i in range(INLINE_THRESHOLD + 100)]
external_output = Path("test-external-dashboard.html")
write_html(external_findings, external_output)
assert external_output.exists(), "External dashboard not created"
external_json = external_output.parent / "findings.json"
assert external_json.exists(), "findings.json not created for external mode"
external_content = external_output.read_text()
assert (
    "window.__FINDINGS__ = []" in external_content
), "Should use empty array in external mode"
assert "Loaded via fetch()" in external_content, "Should have fetch() comment"
print(
    f"✅ External mode works! Dashboard: {external_output.stat().st_size / 1024:.1f} KB, JSON: {external_json.stat().st_size / 1024:.1f} KB"
)

# Verify JSON structure
loaded_json = json.loads(external_json.read_text())
assert len(loaded_json) == INLINE_THRESHOLD + 100, "External JSON has wrong count"
print(f"✅ External JSON valid with {len(loaded_json)} findings")

# Test React build exists
from scripts.core.reporters.html_reporter import Path as ReporterPath

dashboard_dir = ReporterPath(__file__).parent / "scripts" / "dashboard"
react_build = dashboard_dir / "dist" / "index.html"
assert react_build.exists(), f"React build not found at {react_build}"
print(f"✅ React build found at {react_build}")

# Verify placeholder replacement
react_template = react_build.read_text()
assert "window.__FINDINGS__ = []" in react_template, "React build missing placeholder"
print("✅ React build has placeholder")

# Cleanup
inline_output.unlink()
external_output.unlink()
external_json.unlink()
print("\n🎉 All tests passed! React dashboard integration complete.")
