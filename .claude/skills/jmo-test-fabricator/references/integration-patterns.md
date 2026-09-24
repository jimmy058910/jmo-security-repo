# Integration Testing Patterns

Integration tests verify multi-component workflows (scan -> report -> CI), tool selection, the Docker image, and end-to-end scenarios.

## When to Write Integration Tests

Use integration tests when:

- Testing multi-component workflows (scan -> report -> CI)
- Testing tool selection (`--tools`, `--skip-tools`, a `tools:` list in `jmo.yml`)
- Testing the Docker image (the one image built from `Dockerfile`)
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
        "--tools",
        "trufflehog",
        "semgrep",
        "trivy",
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

### Pattern 1: Tool Selection

Test that `--tools` narrows the default matrix to the tools asked for.

```python
def test_tools_flag_selects_tools(tmp_path: Path):
    """Test --tools runs the requested subset."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("x = 1")

    # Run a scan narrowed to three tools
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--tools",
        "trufflehog",
        "semgrep",
        "trivy",
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

    expected_tools = ["trufflehog", "semgrep", "trivy"]
    for tool in expected_tools:
        assert tool in found_tools, f"--tools should have run {tool}"
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

    # Verify deduplication.
    #
    # Assert the report EXISTS before reading it. Guarding this block with
    # `if findings_json.exists():` means a scan or report that wrote nothing
    # produces a green test that checked no deduplication at all - the failure
    # mode is indistinguishable from success, which is the specific thing this
    # repository keeps getting caught by.
    findings_json = tmp_path / "results" / "summaries" / "findings.json"
    assert findings_json.exists(), (
        f"report wrote no findings.json to {findings_json.parent}; "
        f"nothing was deduplicated because nothing was produced"
    )

    findings = json.loads(findings_json.read_text(encoding="utf-8"))
    fingerprints = [f["id"] for f in findings["findings"]]
    assert fingerprints, "findings.json is empty - deduplication was never exercised"
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

    # Run scan with --allow-missing-tools (the whole default matrix)
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
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
def test_default_matrix_scan(tmp_path: Path):
    """Test a scan with the whole default matrix (may take 2-3 minutes)."""
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
all_tools = ["trufflehog", "semgrep", "syft", "trivy", "yara"]
for tool in all_tools:
    assert (repo_dir / f"{tool}.json").exists()
# Fails if yara skips due to missing binary

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

## Configuration Testing

Test top-level settings, per-tool overrides, and configuration loading logic.

### When to Test Configuration

Test configuration and overrides when:

- Adding a top-level `jmo.yml` key (`threads`, `timeout`, `tools`, ...)
- Adding per-tool override support (timeout, flags, retries)
- Modifying config loading logic (jmo.yml parsing)
- Testing precedence (`--tools` over a `tools:` list over the default matrix)

### Per-Tool Override Test Pattern

```python
def test_per_tool_timeout_override(tmp_path: Path):
    """Test per-tool timeout override of the top-level timeout."""
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
timeout: 300  # Global: 5 minutes
per_tool:
  semgrep:
    timeout: 600  # Override: 10 minutes
    flags: ["--exclude", "tests"]
"""
    )

    # Run scan with the custom config
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
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

### Config Precedence Tests

```python
def test_cli_tools_override_config_tools(tmp_path: Path):
    """Test --tools on the command line wins over a tools: list in jmo.yml."""
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("import os")

    # Config narrows the matrix to two tools
    config_file = tmp_path / "precedence-config.yml"
    config_file.write_text(
        """
tools: [trivy, semgrep]
outputs: [json]

per_tool:
  trivy:
    flags: ["--no-progress"]
"""
    )

    # The CLI narrows it further, to one
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--config",
        str(config_file),
        "--tools",
        "semgrep",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert result.returncode in [0, 1]

    # Note the assertion is NOT inside an `if repo_dir.exists():` guard - a
    # scan that produced no directory at all would then pass this test having
    # checked nothing.
    repo_dir = tmp_path / "results" / "individual-repos" / "test-repo"
    assert repo_dir.exists(), f"scan produced no output directory at {repo_dir}"

    found_tools = [f.stem for f in repo_dir.glob("*.json")]
    assert "semgrep" in found_tools, f"--tools semgrep did not run; got {found_tools}"
    assert "trivy" not in found_tools, "the config's tools: list overrode --tools"
```
