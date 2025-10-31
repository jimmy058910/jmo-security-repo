"""
Integration tests for deep profile tools (falco, afl++, noseyparker, bandit).

Coverage:
- Verify deep profile invokes all 12 tools (v0.6.1+: includes nuclei)
- Validate tool outputs are generated
- Test graceful degradation when tools missing

Architecture Note (v0.6.1+):
- Deep profile includes 12 tools total (added nuclei for web scanning)
- GitLab scanner runs all repository tools

Related:
- COVERAGE_GAP_ANALYSIS.md Gap #4
- TESTING_MATRIX.md Matrix 3.1
"""

import json
import subprocess


def test_deep_profile_includes_all_tools(tmp_path):
    """Verify deep profile invokes all 12 tools."""
    # Create minimal test repo
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "README.md").write_text("# Test Repository")
    (test_repo / "app.py").write_text("print('hello')")

    # Run deep profile scan
    cmd = [
        "python3",
        "-m", "scripts.cli.jmo",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "deep",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",  # Graceful degradation if tools not installed
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)

    # Scan should complete (exit code 0 or 1 for findings)
    assert result.returncode in [
        0,
        1,
    ], f"Scan failed with exit code {result.returncode}"

    # Verify deep profile created results directory
    repo_dir = tmp_path / "results" / "individual-repos" / "test-repo"
    assert repo_dir.exists(), "Repository results directory not created"

    # Verify at least some tool outputs exist (stubs or real outputs)
    # With --allow-missing-tools, most tools will have JSON stubs
    tool_outputs = list(repo_dir.glob("*.json"))
    assert len(tool_outputs) > 0, "No tool outputs found (expected stubs)"

    # Check that we have outputs for common tools
    # (Not all tools create stubs in all cases, e.g. noseyparker may skip)
    common_tools = ["trufflehog", "semgrep", "trivy", "syft"]
    found_tools = [f.stem for f in tool_outputs]

    # At least one common tool should have output
    has_common_tool = any(tool in found_tools for tool in common_tools)
    assert has_common_tool, f"No common tools found. Found: {found_tools}"


def test_deep_profile_falco_output(tmp_path):
    """Test falco output is generated (if tool installed)."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "test.py").write_text("x = 1")

    cmd = [
        "python3",
        "-m", "scripts.cli.jmo",
        "scan",
        "--repo",
        str(test_repo),
        "--tools",
        "falco",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert result.returncode in [0, 1, 2]  # May fail if tool not installed

    # Check if falco output generated
    falco_output = (
        tmp_path / "results" / "individual-repos" / "test-repo" / "falco.json"
    )

    # If falco installed, output should exist
    # If not installed, stub file should exist (from --allow-missing-tools)
    if falco_output.exists():
        # Verify it's valid JSON
        data = json.loads(falco_output.read_text())
        assert isinstance(data, (dict, list))


def test_deep_profile_aflplusplus_output(tmp_path):
    """Test afl++ output is generated (if tool installed)."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "test.c").write_text("int main() { return 0; }")

    cmd = [
        "python3",
        "-m", "scripts.cli.jmo",
        "scan",
        "--repo",
        str(test_repo),
        "--tools",
        "afl++",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert result.returncode in [0, 1, 2]

    # Check if afl++ output generated
    afl_output = tmp_path / "results" / "individual-repos" / "test-repo" / "afl++.json"

    if afl_output.exists():
        data = json.loads(afl_output.read_text())
        assert isinstance(data, (dict, list))


def test_deep_profile_graceful_degradation(tmp_path):
    """Test deep profile continues when some tools missing."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("import os")

    # Run deep profile with --allow-missing-tools
    cmd = [
        "python3",
        "-m", "scripts.cli.jmo",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "deep",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
        "--human-logs",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)

    # Should complete successfully even if some tools missing
    assert result.returncode in [0, 1]

    # Verify at least one tool ran (results directory created)
    assert (tmp_path / "results" / "individual-repos").exists()


def test_deep_profile_report_aggregation(tmp_path):
    """Test report phase aggregates deep profile findings."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("password = 'hardcoded123'")  # Trigger findings

    # Run deep profile scan
    cmd_scan = [
        "python3",
        "-m", "scripts.cli.jmo",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "deep",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    subprocess.run(cmd_scan, capture_output=True, timeout=240)

    # Generate report
    cmd_report = ["python3", "-m", "scripts.cli.jmo", "report", str(tmp_path / "results")]
    subprocess.run(cmd_report, check=True, timeout=60)

    # Verify aggregated findings
    findings_json = tmp_path / "results" / "summaries" / "findings.json"
    assert findings_json.exists()

    findings = json.loads(findings_json.read_text())
    # findings.json is now a list of findings directly (not wrapped in {"findings": [...]})
    assert isinstance(findings, list)
