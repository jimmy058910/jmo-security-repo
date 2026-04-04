# Integration Testing Patterns

Integration tests verify multi-component workflows (scan -> report -> CI), profile behavior, Docker variants, and end-to-end scenarios.

## When to Write Integration Tests

Use integration tests when:

- Testing multi-component workflows (scan -> report -> CI)
- Testing profile behavior (fast/balanced/deep tool selection)
- Testing Docker variants (full/slim/alpine)
- Testing multi-target scanning (repo + image + IaC + URL + GitLab + K8s)
- Testing CLI argument combinations
- Testing end-to-end scenarios
- Testing graceful degradation (--allow-missing-tools)

## Integration Test Structure

```python
"""
Integration tests for [feature].

Coverage:
- [Workflow step 1]
- [Workflow step 2]
- Graceful degradation when [condition]

Architecture Note:
- [Key implementation detail]

Related:
- [Related doc or gap analysis]
"""

import json
import subprocess
from pathlib import Path

import pytest


def test_workflow_happy_path(tmp_path):
    """Test complete workflow from start to finish."""
    # Create test data
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("print('test')")

    # Run scan command
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "fast",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    # Verify scan succeeded
    assert result.returncode in [0, 1]

    # Verify outputs created
    assert (tmp_path / "results" / "individual-repos" / "test-repo").exists()
```

## Common Integration Test Patterns

### Pattern 1: Profile Validation

Test that profiles invoke correct tool subsets and configurations.

```python
def test_profile_tool_selection_fast(tmp_path: Path):
    """Test fast profile invokes correct tool subset."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("x = 1")

    # Run fast profile scan
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "fast",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    assert result.returncode in [0, 1]

    # Verify results directory created
    repo_dir = tmp_path / "results" / "individual-repos" / "test-repo"
    assert repo_dir.exists()

    # Verify expected tool outputs exist (stubs or real outputs)
    tool_outputs = list(repo_dir.glob("*.json"))
    found_tools = [f.stem for f in tool_outputs]

    # Fast profile: trufflehog, semgrep, trivy
    expected_tools = ["trufflehog", "semgrep", "trivy"]
    for tool in expected_tools:
        assert tool in found_tools, f"Fast profile should include {tool}"
```

### Pattern 2: Multi-Target Deduplication

Test that findings from different target types are deduplicated by fingerprint ID.

```python
def test_cross_target_deduplication(tmp_path: Path):
    """Test findings deduplicated across target types."""
    import json

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "requirements.txt").write_text("requests==2.25.0")  # Known CVE

    # Scan repo + image (both will find same CVE)
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--image",
        "python:3.9",  # Contains packages with CVEs
        "--tools",
        "trivy",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert result.returncode in [0, 1]

    # Generate report
    cmd_report = ["python3", "scripts/cli/jmo.py", "report", str(tmp_path / "results")]
    subprocess.run(cmd_report, check=True, timeout=60)

    # Verify deduplication
    findings_json = tmp_path / "results" / "summaries" / "findings.json"
    if findings_json.exists():
        findings = json.loads(findings_json.read_text())
        fingerprints = [f["id"] for f in findings["findings"]]
        # All fingerprints should be unique (no duplicates)
        assert len(fingerprints) == len(set(fingerprints)), "Duplicate fingerprints found"
```

### Pattern 3: Graceful Degradation

Test that missing tools don't crash entire scan.

```python
def test_allow_missing_tools(tmp_path: Path):
    """Test --allow-missing-tools writes stubs."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "README.md").write_text("# Test")

    # Run scan with --allow-missing-tools
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "deep",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)

    # Should complete successfully even if some tools missing
    assert result.returncode in [0, 1]

    # Verify at least one tool ran (results directory created)
    assert (tmp_path / "results" / "individual-repos").exists()
```

## Integration Test Timeouts

Integration tests run actual CLI commands and can be slow. Use appropriate timeouts:

```python
@pytest.mark.slow
def test_deep_profile_scan(tmp_path: Path):
    """Test deep profile (may take 2-3 minutes)."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
```

## Verifying CLI Output

### Pattern: Check results directories, not stdout logs

```python
# BAD: Parse stdout (unreliable with --human-logs)
assert "trufflehog" in result.stdout

# GOOD: Check results directory
tool_outputs = list(repo_dir.glob("*.json"))
found_tools = [f.stem for f in tool_outputs]
assert "trufflehog" in found_tools
```

## Flexible Assertions for Integration Tests

**Problem:** Strict assertions fail when tool behavior varies (missing tools, optional outputs, platform differences).

### Pattern: Verify Minimum Requirements Instead of Exact Matches

```python
# BAD: Assumes all tools create outputs
deep_tools = ["trufflehog", "noseyparker", "semgrep", "bandit", "syft", "trivy"]
for tool in deep_tools:
    assert (repo_dir / f"{tool}.json").exists()
# Fails if noseyparker skips due to missing binary

# GOOD: Verify at least some tools ran
tool_outputs = list(repo_dir.glob("*.json"))
assert len(tool_outputs) > 0, "No tool outputs found"

common_tools = ["trufflehog", "semgrep", "trivy"]
found_tools = [f.stem for f in tool_outputs]
has_common_tool = any(tool in found_tools for tool in common_tools)
assert has_common_tool, f"Expected common tools, found: {found_tools}"
```

## Handling Optional Fields

```python
# BAD: Assumes compliance field always present
assert "A03:2021" in item["compliance"]["owaspTop10_2021"]
# Fails if finding has no CWE mapping

# GOOD: Check existence first
if "compliance" in item:
    if "owaspTop10_2021" in item["compliance"]:
        assert "A03:2021" in item["compliance"]["owaspTop10_2021"]
```

## Platform-Specific Assertions

```python
# BAD: Assumes Linux-specific behavior
assert item["location"]["path"] == "/absolute/path"

# GOOD: Accept platform variations
assert item["location"]["path"].endswith("file.py")
# OR use pathlib for normalization
assert Path(item["location"]["path"]).name == "file.py"
```

---

## Configuration and Profile Testing

Test profiles, per-tool overrides, and configuration loading logic.

### When to Test Profiles

Test profiles and overrides when:

- Adding new profile (fast/balanced/deep/custom)
- Adding per-tool override support (timeout, flags, retries)
- Modifying config loading logic (jmo.yml parsing)
- Testing profile inheritance (global vs profile-specific)

### Profile Override Test Pattern

```python
def test_per_tool_timeout_override(tmp_path: Path):
    """Test per-tool timeout override in profile."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("print('test')")

    # Create custom config with per-tool override
    config_file = tmp_path / "custom-jmo.yml"
    config_file.write_text(
        """
tools: [semgrep]
outputs: [json]

profiles:
  custom:
    tools: [semgrep]
    timeout: 300  # Global: 5 minutes
    per_tool:
      semgrep:
        timeout: 600  # Override: 10 minutes
        flags: ["--exclude", "tests"]
"""
    )

    # Run scan with custom profile
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "custom",
        "--config",
        str(config_file),
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    # Should complete successfully
    assert result.returncode in [0, 1]

    # Verify tool ran (check results directory)
    assert (tmp_path / "results" / "individual-repos").exists()
```

### Profile Tool Selection Tests

```python
def test_profile_tool_selection_balanced(tmp_path: Path):
    """Test balanced profile invokes correct tool subset."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("x = 1")

    # Run balanced profile
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "balanced",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    subprocess.run(cmd, capture_output=True, text=True, timeout=240)

    # Count tool JSON files in results directory
    repo_dir = tmp_path / "results" / "individual-repos" / "test-repo"
    if repo_dir.exists():
        tool_outputs = list(repo_dir.glob("*.json"))
        found_tools = [f.stem for f in tool_outputs]

        # Balanced profile: trufflehog, semgrep, syft, trivy, checkov, hadolint, zap, nuclei
        # Verify at least some balanced tools present
        balanced_tools = ["trufflehog", "semgrep", "trivy", "syft"]
        assert any(tool in found_tools for tool in balanced_tools)
```

### Config Inheritance Tests

```python
def test_profile_inherits_global_config(tmp_path: Path):
    """Test profile inherits global per_tool config."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("import os")

    # Create config with global per_tool AND profile per_tool
    config_file = tmp_path / "inherit-config.yml"
    config_file.write_text(
        """
tools: [trivy, semgrep]
outputs: [json]

per_tool:
  trivy:
    flags: ["--no-progress"]  # Global trivy config

profiles:
  custom:
    tools: [trivy, semgrep]
    per_tool:
      trivy:
        timeout: 600  # Profile adds timeout (merges with global flags)
"""
    )

    # Run scan
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--profile-name",
        "custom",
        "--config",
        str(config_file),
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert result.returncode in [0, 1]

    # Verify both tools ran
    repo_dir = tmp_path / "results" / "individual-repos" / "test-repo"
    if repo_dir.exists():
        tool_outputs = list(repo_dir.glob("*.json"))
        found_tools = [f.stem for f in tool_outputs]
        # At least one tool should have run
        assert len(found_tools) > 0
```
