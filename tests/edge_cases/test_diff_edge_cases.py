"""Edge case tests for jmo diff workflows."""

import json
import subprocess
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
def sample_finding():
    """Generate a single sample finding."""
    def _create(finding_id, severity, tool, path, line, message):
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
    return _create


def test_empty_baseline(temp_workspace, sample_finding):
    """Handle empty baseline (all current findings are new)."""
    # Empty baseline
    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    baseline_json.write_text(json.dumps([], indent=2))

    # Current has 50 findings
    current_findings = [
        sample_finding(f"c{i:03d}", "HIGH", "semgrep", f"src/file{i}.py", i, f"Issue {i}")
        for i in range(50)
    ]
    current_json = temp_workspace["current"] / "summaries" / "findings.json"
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

    with open(output_path) as f:
        diff = json.load(f)

    # All current findings are new
    assert diff["statistics"]["total_new"] == 50
    assert diff["statistics"]["total_resolved"] == 0
    assert diff["statistics"]["total_unchanged"] == 0
    assert diff["statistics"]["net_change"] == 50
    assert diff["statistics"]["trend"] == "worsening"


def test_empty_current(temp_workspace, sample_finding):
    """Handle empty current (all baseline findings resolved)."""
    # Baseline has 30 findings
    baseline_findings = [
        sample_finding(f"b{i:03d}", "MEDIUM", "trivy", f"src/old{i}.py", i, f"Old issue {i}")
        for i in range(30)
    ]
    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    baseline_json.write_text(json.dumps(baseline_findings, indent=2))

    # Empty current
    current_json = temp_workspace["current"] / "summaries" / "findings.json"
    current_json.write_text(json.dumps([], indent=2))

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

    with open(output_path) as f:
        diff = json.load(f)

    # All baseline findings resolved
    assert diff["statistics"]["total_new"] == 0
    assert diff["statistics"]["total_resolved"] == 30
    assert diff["statistics"]["total_unchanged"] == 0
    assert diff["statistics"]["net_change"] == -30
    assert diff["statistics"]["trend"] == "improving"


def test_identical_scans(temp_workspace, sample_finding):
    """Handle identical scans (no changes)."""
    # Same 20 findings in both
    findings = [
        sample_finding(f"shared{i:03d}", "HIGH", "semgrep", f"src/app{i}.py", i, f"Shared issue {i}")
        for i in range(20)
    ]

    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(findings, indent=2))
    current_json.write_text(json.dumps(findings, indent=2))

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

    with open(output_path) as f:
        diff = json.load(f)

    # No changes
    assert diff["statistics"]["total_new"] == 0
    assert diff["statistics"]["total_resolved"] == 0
    assert diff["statistics"]["total_unchanged"] == 20
    assert diff["statistics"]["total_modified"] == 0
    assert diff["statistics"]["net_change"] == 0
    assert diff["statistics"]["trend"] == "stable"


def test_large_diff_10k_findings(temp_workspace, sample_finding):
    """Performance test: 10K findings."""
    import time

    # Baseline: 5K findings
    baseline_findings = [
        sample_finding(f"b{i:05d}", "MEDIUM", "trivy", f"src/b{i}.py", i, f"Baseline {i}")
        for i in range(5000)
    ]

    # Current: Different 5K findings
    current_findings = [
        sample_finding(f"c{i:05d}", "HIGH", "semgrep", f"src/c{i}.py", i, f"Current {i}")
        for i in range(5000)
    ]

    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff with timing
    output_path = temp_workspace["workspace"] / "diff.json"
    start = time.time()
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
        text=True,
        timeout=10  # 10s timeout (should be <2s per spec)
    )
    elapsed = time.time() - start

    assert result.returncode == 0
    assert elapsed < 5.0, f"Diff took {elapsed:.2f}s (expected <5s for 10K findings)"

    with open(output_path) as f:
        diff = json.load(f)

    assert diff["statistics"]["total_new"] == 5000
    assert diff["statistics"]["total_resolved"] == 5000
    assert diff["statistics"]["net_change"] == 0


def test_unicode_in_messages(temp_workspace, sample_finding):
    """Handle Unicode in finding messages."""
    # Findings with Unicode characters
    baseline_findings = [
        sample_finding("b001", "HIGH", "semgrep", "src/app.py", 10, "SQL注入漏洞"),
        sample_finding("b002", "MEDIUM", "trivy", "src/auth.py", 20, "Безопасность ошибка"),
        sample_finding("b003", "LOW", "checkov", "iac/main.tf", 5, "🔒 Security misconfiguration"),
    ]

    current_findings = [
        sample_finding("c001", "CRITICAL", "semgrep", "src/api.py", 15, "XSS脆弱性 (cross-site scripting)"),
        sample_finding("b002", "MEDIUM", "trivy", "src/auth.py", 20, "Безопасность ошибка"),  # Unchanged
    ]

    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2, ensure_ascii=False))
    current_json.write_text(json.dumps(current_findings, indent=2, ensure_ascii=False))

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

    with open(output_path, encoding="utf-8") as f:
        diff = json.load(f)

    # Verify Unicode preserved
    assert diff["statistics"]["total_new"] == 1
    assert diff["statistics"]["total_resolved"] == 2
    assert diff["statistics"]["total_unchanged"] == 1

    # Check Unicode in new findings
    new_finding = diff["new_findings"][0]
    assert "XSS脆弱性" in new_finding["message"]


def test_malformed_findings_json(temp_workspace):
    """Handle malformed findings.json gracefully."""
    # Malformed JSON in baseline
    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    baseline_json.write_text("{invalid json")

    # Valid current
    current_json = temp_workspace["current"] / "summaries" / "findings.json"
    current_json.write_text(json.dumps([], indent=2))

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

    # Should fail gracefully
    assert result.returncode != 0
    assert "parse" in result.stderr.lower() or "json" in result.stderr.lower()


def test_mixed_schema_versions(temp_workspace, sample_finding):
    """Handle mixed CommonFinding schema versions."""
    # Baseline: schemaVersion 1.0.0 (older)
    baseline_findings = [
        {
            "schemaVersion": "1.0.0",
            "id": "b001",
            "severity": "HIGH",
            "ruleId": "TEST-001",
            "tool": {"name": "semgrep", "version": "1.0.0"},
            "location": {"path": "src/app.py", "startLine": 10},
            "message": "SQL injection",
            # Missing compliance/risk fields (not in v1.0.0)
        }
    ]

    # Current: schemaVersion 1.2.0 (current)
    current_findings = [
        sample_finding("c001", "CRITICAL", "trivy", "src/api.py", 15, "RCE vulnerability"),
    ]

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

    with open(output_path) as f:
        diff = json.load(f)

    # Should handle gracefully
    assert diff["statistics"]["total_new"] == 1
    assert diff["statistics"]["total_resolved"] == 1


def test_modification_detection_disabled(temp_workspace, sample_finding):
    """Verify --no-modifications flag disables modification detection."""
    # Same finding ID, different severity
    finding_id = "shared001"

    baseline_findings = [
        sample_finding(finding_id, "MEDIUM", "semgrep", "src/app.py", 10, "SQL injection"),
    ]

    current_findings = [
        sample_finding(finding_id, "HIGH", "semgrep", "src/app.py", 10, "SQL injection"),
    ]

    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff WITHOUT modifications
    output_path = temp_workspace["workspace"] / "diff.json"
    result = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "json",
            "--output", str(output_path),
            "--no-modifications"
        ],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    with open(output_path) as f:
        diff = json.load(f)

    # Should treat as unchanged (no modification detection)
    assert diff["statistics"]["total_modified"] == 0
    assert diff["statistics"]["total_unchanged"] == 1
    assert len(diff["modified_findings"]) == 0


def test_filter_combinations(temp_workspace, sample_finding):
    """Test combining multiple filters (--severity + --tool + --only)."""
    # Mixed findings
    baseline_findings = [
        sample_finding("b1", "CRITICAL", "semgrep", "src/a.py", 1, "Issue A"),
        sample_finding("b2", "HIGH", "trivy", "src/b.py", 2, "Issue B"),
        sample_finding("b3", "MEDIUM", "semgrep", "src/c.py", 3, "Issue C"),
    ]

    current_findings = [
        sample_finding("c1", "HIGH", "semgrep", "src/d.py", 4, "Issue D"),
        sample_finding("c2", "MEDIUM", "trivy", "src/e.py", 5, "Issue E"),
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


def test_missing_findings_json(temp_workspace):
    """Handle missing findings.json files gracefully."""
    # Neither baseline nor current has findings.json
    # (summaries directories exist but are empty)

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

    # Should fail with clear error
    assert result.returncode != 0
    assert "findings.json" in result.stderr.lower()


def test_only_new_filter(temp_workspace, sample_finding):
    """Test --only new filter excludes resolved/unchanged."""
    baseline_findings = [
        sample_finding("b1", "HIGH", "semgrep", "src/old.py", 1, "Old issue"),
        sample_finding("shared1", "MEDIUM", "trivy", "src/shared.py", 2, "Shared issue"),
    ]

    current_findings = [
        sample_finding("c1", "CRITICAL", "semgrep", "src/new.py", 3, "New issue"),
        sample_finding("shared1", "MEDIUM", "trivy", "src/shared.py", 2, "Shared issue"),
    ]

    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff with --only new
    output_path = temp_workspace["workspace"] / "diff.json"
    result = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "json",
            "--output", str(output_path),
            "--only", "new"
        ],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    with open(output_path) as f:
        diff = json.load(f)

    # Only new findings
    assert diff["statistics"]["total_new"] == 1
    assert len(diff["new_findings"]) == 1
    assert diff["new_findings"][0]["id"] == "c1"

    # Resolved/unchanged filtered out
    assert len(diff["resolved_findings"]) == 0
    assert diff["statistics"]["total_resolved"] == 0


def test_only_resolved_filter(temp_workspace, sample_finding):
    """Test --only resolved filter excludes new/unchanged."""
    baseline_findings = [
        sample_finding("b1", "HIGH", "semgrep", "src/old.py", 1, "Resolved issue"),
        sample_finding("shared1", "MEDIUM", "trivy", "src/shared.py", 2, "Shared issue"),
    ]

    current_findings = [
        sample_finding("c1", "CRITICAL", "semgrep", "src/new.py", 3, "New issue"),
        sample_finding("shared1", "MEDIUM", "trivy", "src/shared.py", 2, "Shared issue"),
    ]

    baseline_json = temp_workspace["baseline"] / "summaries" / "findings.json"
    current_json = temp_workspace["current"] / "summaries" / "findings.json"

    baseline_json.write_text(json.dumps(baseline_findings, indent=2))
    current_json.write_text(json.dumps(current_findings, indent=2))

    # Run diff with --only resolved
    output_path = temp_workspace["workspace"] / "diff.json"
    result = subprocess.run(
        [
            "python3", "-m", "scripts.cli.jmo",
            "diff",
            str(temp_workspace["baseline"]),
            str(temp_workspace["current"]),
            "--format", "json",
            "--output", str(output_path),
            "--only", "resolved"
        ],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    with open(output_path) as f:
        diff = json.load(f)

    # Only resolved findings
    assert diff["statistics"]["total_resolved"] == 1
    assert len(diff["resolved_findings"]) == 1
    assert diff["resolved_findings"][0]["id"] == "b1"

    # New/unchanged filtered out
    assert len(diff["new_findings"]) == 0
    assert diff["statistics"]["total_new"] == 0
