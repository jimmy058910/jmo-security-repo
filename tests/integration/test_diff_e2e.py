"""End-to-end integration tests for jmo diff workflows."""

import json
import subprocess
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_workspace(tmp_path):
    """Create a temporary workspace with baseline and current scan directories."""
    baseline_dir = tmp_path / "baseline-results"
    current_dir = tmp_path / "current-results"
    baseline_dir.mkdir()
    current_dir.mkdir()

    # Create summaries directories
    (baseline_dir / "summaries").mkdir()
    (current_dir / "summaries").mkdir()

    return {
        "workspace": tmp_path,
        "baseline": baseline_dir,
        "current": current_dir,
    }


@pytest.fixture
def sample_findings():
    """Generate sample findings for testing."""
    def _create_finding(finding_id, severity, tool, path, line, message):
        return {
            "schemaVersion": "1.2.0",
            "id": finding_id,
            "severity": severity,
            "ruleId": f"TEST-{finding_id[:8]}",
            "tool": {"name": tool, "version": "1.0.0"},
            "location": {"path": path, "startLine": line},
            "message": message,
            "compliance": {},
            "risk": {}
        }
    return _create_finding


def test_e2e_directory_diff_json(temp_workspace, sample_findings):
    """
    End-to-end: Directory diff to JSON.

    Workflow:
    1. Create baseline and current scan results
    2. Run jmo diff with JSON output
    3. Validate JSON structure
    """
    # Setup: Create findings
    baseline_findings = [
        sample_findings("baseline001", "HIGH", "semgrep", "src/app.py", 10, "SQL injection"),
        sample_findings("baseline002", "MEDIUM", "trivy", "src/config.py", 20, "Hardcoded secret"),
        sample_findings("shared001", "HIGH", "semgrep", "src/auth.py", 30, "Authentication bypass"),
    ]

    current_findings = [
        sample_findings("current001", "CRITICAL", "semgrep", "src/api.py", 15, "Command injection"),
        sample_findings("shared001", "HIGH", "semgrep", "src/auth.py", 30, "Authentication bypass"),
    ]

    # Write findings
    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff
    output_path = temp_workspace["workspace"] / "diff.json"
    result = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "json",
            "--output", str(output_path)
        ],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0, f"Diff failed: {result.stderr}"
    assert output_path.exists()

    # Validate JSON structure
    with open(output_path) as f:
        diff = json.load(f)

    assert "meta" in diff
    assert "statistics" in diff
    assert "new_findings" in diff
    assert "resolved_findings" in diff
    assert "modified_findings" in diff

    # Validate statistics
    stats = diff["statistics"]
    assert stats["total_new"] == 1  # current001
    assert stats["total_resolved"] == 2  # baseline001, baseline002
    assert stats["total_unchanged"] == 1  # shared001
    assert stats["net_change"] == -1  # Improving
    assert stats["trend"] == "improving"


def test_e2e_sqlite_diff_md(temp_workspace):
    """
    End-to-end: SQLite diff to Markdown.

    Workflow:
    1. Store two scans in SQLite
    2. Compare using scan IDs
    3. Validate Markdown output
    """
    pytest.skip("SQLite diff requires history_db integration - tested in test_history_commands.py")


def test_e2e_modification_detection(temp_workspace, sample_findings):
    """
    End-to-end: Modification detection enabled.

    Workflow:
    1. Create baseline with MEDIUM severity finding
    2. Create current with same finding but HIGH severity
    3. Run diff with modification detection
    4. Verify severity upgrade detected
    """
    # Setup: Same finding, different severity
    finding_id = "modified001"

    baseline_findings = [
        {
            **sample_findings(finding_id, "MEDIUM", "semgrep", "src/app.py", 10, "SQL injection"),
            "risk": {"cwe": "CWE-89"}
        }
    ]

    current_findings = [
        {
            **sample_findings(finding_id, "HIGH", "semgrep", "src/app.py", 10, "SQL injection"),
            "risk": {"cwe": "CWE-89"}
        }
    ]

    # Write findings
    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff
    output_path = temp_workspace["workspace"] / "diff.json"
    result = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "json",
            "--output", str(output_path)
        ],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    # Validate modification detected
    with open(output_path) as f:
        diff = json.load(f)

    assert diff["statistics"]["total_modified"] == 1
    assert len(diff["modified_findings"]) == 1

    modified = diff["modified_findings"][0]
    assert modified["fingerprint"] == finding_id
    assert "severity" in modified["changes"]
    assert modified["changes"]["severity"] == ["MEDIUM", "HIGH"]
    assert modified["risk_delta"] in ["worsened", "unchanged"]


def test_e2e_ci_workflow(temp_workspace, sample_findings):
    """
    End-to-end: Simulate CI workflow with security gate.

    Workflow:
    1. Scan baseline
    2. Scan current
    3. Diff with CRITICAL/HIGH filter
    4. Check exit code based on new findings
    """
    # Setup: Create findings with new CRITICAL
    baseline_findings = [
        sample_findings("baseline001", "MEDIUM", "semgrep", "src/app.py", 10, "Info leak"),
    ]

    current_findings = [
        sample_findings("baseline001", "MEDIUM", "semgrep", "src/app.py", 10, "Info leak"),
        sample_findings("current001", "CRITICAL", "trivy", "src/config.py", 20, "RCE vulnerability"),
    ]

    # Write findings
    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff
    output_path = temp_workspace["workspace"] / "diff.json"
    result = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "json",
            "--output", str(output_path),
            "--severity", "CRITICAL,HIGH"
        ],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    # Validate filtering worked
    with open(output_path) as f:
        diff = json.load(f)

    # Should only see CRITICAL finding
    assert diff["statistics"]["total_new"] == 1
    assert len(diff["new_findings"]) == 1
    assert diff["new_findings"][0]["severity"] == "CRITICAL"

    # Simulate CI gate check
    new_critical = diff["statistics"]["new_by_severity"].get("CRITICAL", 0)
    new_high = diff["statistics"]["new_by_severity"].get("HIGH", 0)
    gate_total = new_critical + new_high

    # Gate should fail (1 CRITICAL found)
    assert gate_total > 0, "CI gate should have failed with new CRITICAL finding"


def test_e2e_filtering_combinations(temp_workspace, sample_findings):
    """Test combining multiple filters (--severity, --tool, --only)."""
    # Setup: Mixed findings
    baseline_findings = [
        sample_findings("b1", "CRITICAL", "semgrep", "src/a.py", 1, "Issue A"),
        sample_findings("b2", "HIGH", "trivy", "src/b.py", 2, "Issue B"),
        sample_findings("b3", "MEDIUM", "semgrep", "src/c.py", 3, "Issue C"),
    ]

    current_findings = [
        sample_findings("c1", "HIGH", "semgrep", "src/d.py", 4, "Issue D"),
        sample_findings("c2", "MEDIUM", "trivy", "src/e.py", 5, "Issue E"),
    ]

    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff with: --severity HIGH --tool semgrep --only new
    output_path = temp_workspace["workspace"] / "diff.json"
    result = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "json",
            "--output", str(output_path),
            "--severity", "HIGH",
            "--tool", "semgrep",
            "--only", "new"
        ],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    with open(output_path) as f:
        diff = json.load(f)

    # Should only see: c1 (HIGH + semgrep + new)
    assert diff["statistics"]["total_new"] == 1
    assert len(diff["new_findings"]) == 1
    assert diff["new_findings"][0]["id"] == "c1"

    # Resolved/modified should be empty (--only new)
    assert diff["statistics"]["total_resolved"] == 0
    assert diff["statistics"]["total_modified"] == 0


def test_e2e_no_modifications_flag(temp_workspace, sample_findings):
    """Test --no-modifications flag disables modification detection."""
    # Setup: Same finding with severity change
    finding_id = "shared001"

    baseline_findings = [
        sample_findings(finding_id, "MEDIUM", "semgrep", "src/app.py", 10, "Issue"),
    ]

    current_findings = [
        sample_findings(finding_id, "HIGH", "semgrep", "src/app.py", 10, "Issue"),
    ]

    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff WITH modifications (default)
    output_with = temp_workspace["workspace"] / "diff-with.json"
    result_with = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "json",
            "--output", str(output_with)
        ],
        capture_output=True,
        text=True
    )

    # Run diff WITHOUT modifications
    output_without = temp_workspace["workspace"] / "diff-without.json"
    result_without = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "json",
            "--output", str(output_without),
            "--no-modifications"
        ],
        capture_output=True,
        text=True
    )

    assert result_with.returncode == 0
    assert result_without.returncode == 0

    # Validate difference
    with open(output_with) as f:
        diff_with = json.load(f)

    with open(output_without) as f:
        diff_without = json.load(f)

    # With modifications: should detect severity change
    assert diff_with["statistics"]["total_modified"] == 1
    assert len(diff_with["modified_findings"]) == 1

    # Without modifications: should treat as unchanged
    assert diff_without["statistics"]["total_modified"] == 0
    assert len(diff_without["modified_findings"]) == 0
    assert diff_without["statistics"]["total_unchanged"] == 1


def test_e2e_html_output(temp_workspace, sample_findings):
    """Test HTML output generation."""
    # Setup: Simple findings
    baseline_findings = [
        sample_findings("b1", "HIGH", "semgrep", "src/a.py", 1, "Issue A"),
    ]

    current_findings = [
        sample_findings("c1", "CRITICAL", "trivy", "src/b.py", 2, "Issue B"),
    ]

    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff with HTML output
    output_path = temp_workspace["workspace"] / "diff-report.html"
    result = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "html",
            "--output", str(output_path)
        ],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    assert output_path.exists()

    # Validate HTML structure
    html_content = output_path.read_text()
    assert "<!DOCTYPE html>" in html_content
    assert "Security Diff Report" in html_content
    assert "window.DIFF_DATA" in html_content or "diff-data.json" in html_content

    # Security headers
    assert "Content-Security-Policy" in html_content


def test_e2e_markdown_output(temp_workspace, sample_findings):
    """Test Markdown output generation."""
    # Setup: Findings
    baseline_findings = []
    current_findings = [
        sample_findings("c1", "HIGH", "semgrep", "src/api.py", 15, "SQL injection"),
    ]

    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff with Markdown output
    output_path = temp_workspace["workspace"] / "diff.md"
    result = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "md",
            "--output", str(output_path)
        ],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    assert output_path.exists()

    # Validate Markdown structure
    md_content = output_path.read_text()
    assert "# 🔍 Security Diff Report" in md_content
    assert "## 📊 Summary" in md_content
    assert "## ⚠️ New Findings" in md_content
    assert "SQL injection" in md_content


def test_e2e_sarif_output(temp_workspace, sample_findings):
    """Test SARIF output generation."""
    # Setup: Findings
    baseline_findings = [
        sample_findings("b1", "MEDIUM", "semgrep", "src/old.py", 5, "Old issue"),
    ]
    current_findings = [
        sample_findings("c1", "HIGH", "trivy", "src/new.py", 10, "New issue"),
    ]

    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff with SARIF output
    output_path = temp_workspace["workspace"] / "diff.sarif"
    result = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "sarif",
            "--output", str(output_path)
        ],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    assert output_path.exists()

    # Validate SARIF structure
    with open(output_path) as f:
        sarif = json.load(f)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "runs" in sarif
    assert len(sarif["runs"]) > 0

    # Check results
    results = sarif["runs"][0]["results"]
    assert len(results) == 2  # 1 new + 1 resolved

    # Validate baselineState
    baseline_states = [r.get("baselineState") for r in results]
    assert "new" in baseline_states
    assert "absent" in baseline_states
