#!/usr/bin/env python3
"""
Create a test HTML file with embedded sample findings for dashboard testing.
"""
import json
from pathlib import Path

# Read sample findings
sample_findings = json.loads(Path("sample-findings.json").read_text())

# Read built dashboard
dashboard_html = Path("dist/index.html").read_text()

# Inject sample data (inline mode simulation)
findings_json = json.dumps(sample_findings).replace("</script>", "<\\/script>")
test_html = dashboard_html.replace(
    'window.__FINDINGS__ = []',
    f'window.__FINDINGS__ = {findings_json}'
)

# Write test file
Path("test-dashboard.html").write_text(test_html)

print("✅ Created test-dashboard.html with 5 sample findings")
print("   Open in browser: file://" + str(Path.cwd() / "test-dashboard.html"))
