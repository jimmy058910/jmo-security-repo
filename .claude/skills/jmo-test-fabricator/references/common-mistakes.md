# Common Mistakes and How to Avoid Them

This section captures common pitfalls from real-world test development.

## Mistake 1: Hardcoding Expected Values

**Problem**: Tests break when tool output format changes slightly.

```python
# BAD: Hardcoded exact match
def test_bad(tmp_path):
    out = load_tool(path)
    assert len(out) == 3  # Breaks if tool adds extra finding
    assert out[0]["message"] == "Exact message here"  # Breaks on whitespace changes
```

**Solution**: Use flexible assertions with minimum requirements.

```python
# GOOD: Flexible assertions
def test_good(tmp_path):
    out = load_tool(path)
    assert len(out) >= 1, "Expected at least 1 finding"
    assert "Expected keyword" in out[0]["message"]
```

## Mistake 2: Not Testing Error Paths

**Problem**: Adapter crashes on malformed JSON, empty files, missing fields.

```python
# INCOMPLETE: Only tests happy path
def test_basic(tmp_path):
    sample = {"results": [{"id": "1", "severity": "high"}]}
    path = write_tmp(tmp_path, "tool.json", json.dumps(sample))
    out = load_tool(path)
    assert len(out) == 1
```

**Solution**: Add Category 2 tests for all error conditions.

```python
# COMPLETE: Tests error paths
def test_empty_file(tmp_path):
    """Test adapter handles empty file gracefully."""
    path = write_tmp(tmp_path, "tool.json", "")
    out = load_tool(path)
    assert out == []  # Returns empty list, not crash

def test_missing_severity(tmp_path):
    """Test adapter defaults severity when missing."""
    sample = {"results": [{"id": "1"}]}  # No severity field
    path = write_tmp(tmp_path, "tool.json", json.dumps(sample))
    out = load_tool(path)
    assert out[0]["severity"] == "UNKNOWN"  # Default fallback
```

## Mistake 3: Integration Tests Without Timeouts

**Problem**: CI hangs indefinitely when tool subprocess freezes.

```python
# DANGEROUS: No timeout
def test_scan(tmp_path):
    result = subprocess.run(["jmo", "scan", "--repo", str(repo)], capture_output=True)
    assert result.returncode == 0
```

**Solution**: Always set timeout in subprocess.run() and pytest.mark.

```python
# SAFE: Timeout protection
@pytest.mark.slow
def test_scan(tmp_path):
    result = subprocess.run(
        ["jmo", "scan", "--repo", str(repo)],
        capture_output=True,
        timeout=120  # 2-minute safety timeout
    )
    assert result.returncode in [0, 1]
```

## Mistake 4: Platform-Specific Assertions

**Problem**: Tests pass on Linux but fail on macOS/WSL due to path differences.

```python
# FRAGILE: Assumes Linux path separators
def test_path(tmp_path):
    out = load_tool(path)
    assert out[0]["location"]["path"] == "src/app.py"  # Fails on Windows (src\app.py)
```

**Solution**: Use pathlib for cross-platform paths or flexible matching.

```python
# ROBUST: Platform-agnostic assertions
def test_path(tmp_path):
    out = load_tool(path)
    path_str = out[0]["location"]["path"]
    # Check filename, not full path
    assert path_str.endswith("app.py") or "app.py" in path_str
```

## Mistake 5: Not Reading Module Before Testing

**Problem**: Missing test coverage because you didn't identify all code branches.

```python
# INCOMPLETE: Didn't read adapter, missed try/except block
def test_basic(tmp_path):
    # Only tests happy path
    sample = {"results": [{"id": "1"}]}
    path = write_tmp(tmp_path, "tool.json", json.dumps(sample))
    out = load_tool(path)
    assert len(out) == 1
```

**Solution**: ALWAYS follow Pre-Test Development Workflow.

```bash
# Step 1: Read module to identify branches
cat scripts/core/adapters/tool_adapter.py

# Found try/except block at line 42:
# try:
#     data = json.loads(content)
# except JSONDecodeError:
#     return []

# Step 2: Write test for exception branch
def test_invalid_json(tmp_path):
    """Test adapter handles invalid JSON."""
    path = write_tmp(tmp_path, "tool.json", "{invalid json")
    out = load_tool(path)
    assert out == []  # Returns empty list on parse error
```

## Mistake 6: Ignoring Optional Fields

**Problem**: Adapter crashes when optional field is missing.

```python
# CRASHES: Assumes 'remediation' always exists
def load_tool(path):
    for item in data["results"]:
        finding["remediation"] = item["remediation"]["fix"]  # KeyError if missing
```

**Solution**: Use .get() with defaults for optional fields.

```python
# SAFE: Handles missing optional fields
def load_tool(path):
    for item in data["results"]:
        remediation = item.get("remediation", {})
        finding["remediation"] = remediation.get("fix", "No fix available")
```

## Mistake 7: Not Testing Schema Versions

**Problem**: Tests pass for v1.0.0 findings but fail when v1.2.0 compliance added.

```python
# BRITTLE: Assumes specific schema version
def test_finding(tmp_path):
    out = load_tool(path)
    assert out[0]["schemaVersion"] == "1.0.0"  # Breaks when upgraded to 1.2.0
```

**Solution**: Accept any supported schema version.

```python
# FLEXIBLE: Accepts any valid schema
def test_finding(tmp_path):
    out = load_tool(path)
    assert out[0]["schemaVersion"] in ["1.0.0", "1.1.0", "1.2.0"]
```

---

## Python 3.8 Compatibility Requirements

**CRITICAL: JMo Security supports Python 3.8-3.12. Python 3.8 does NOT support `|` union syntax (added in Python 3.10).**

### Required Imports

```python
from typing import Any, Dict, List, Optional, Union
```

### Type Hint Patterns

| Python 3.10+ (avoid) | Python 3.8+ (use) |
|-----------------------|--------------------|
| `def func(x: str \| None)` | `def func(x: Optional[str])` |
| `def func(x: int \| str)` | `def func(x: Union[int, str])` |
| `items: list[str]` | `items: List[str]` |
| `data: dict[str, Any]` | `data: Dict[str, Any]` |
| `tuple[int, str]` | `Tuple[int, str]` |

### Compatibility Checklist

Before creating any test file:

- [ ] Import `Optional` from `typing` if using optional parameters
- [ ] Never use `Type1 | Type2` syntax (use `Union[Type1, Type2]` or `Optional[Type]`)
- [ ] Never use `dict[str, Any]` (use `Dict[str, Any]` with capital D)
- [ ] Never use `list[str]` (use `List[str]` with capital L)
- [ ] Use `from __future__ import annotations` if needed for forward references
