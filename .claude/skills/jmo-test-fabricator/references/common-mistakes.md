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

**Solution**: Set `timeout=` on `subprocess.run()`. If the test legitimately
needs longer than the suite's 120s default, raise it with
`@pytest.mark.timeout()`.

```python
# SAFE: Timeout protection
@pytest.mark.timeout(300)  # raises pytest's 120s default; THIS is the timeout
@pytest.mark.slow          # SELECTION only - see below
def test_scan(tmp_path):
    result = subprocess.run(
        ["jmo", "scan", "--repo", str(repo)],
        capture_output=True,
        timeout=120  # kills the child process; pytest cannot do this for you
    )
    assert result.returncode in [0, 1]
```

> **`@pytest.mark.slow` is not timeout protection.** It selects tests, nothing
> more, and in this repository it does not even mean "slow" — it means **"runs
> in the PR shards but not the quick coverage gate"**, which is the only job
> that adds `not slow`. `tests/integration/test_scan_accounting.py` picked it
> over `requires_tools` for exactly that reason, and says so in its module
> docstring. Marking a test `slow` changes *where it runs*; it never bounds how
> long it runs.
>
> Order the two protections by what they can kill: `subprocess.run(timeout=)`
> is the only one that stops the child process. pytest-timeout uses the thread
> method on Windows, which can kill the test thread and leave the subprocess
> orphaned — see `.claude/rules/testing.cross-platform.rules.md`.

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

## Python Version and Type Hints

**JMo Security requires Python 3.12+.** `pyproject.toml` declares
`requires-python = ">=3.12"`, and every CI job pins `python-version: '3.12'`.

This section used to say "supports Python 3.8-3.12" and forbade `|` union
syntax. That was wrong in the harmful direction: `scripts/core/` already uses
`str | None` and `list[str]` throughout, so following the old rule produced test
files written in a style the codebase does not use, and did so in the name of a
version that cannot even parse the modules under test.

### Type Hint Patterns

Use the modern built-in generics. `typing.Optional`, `Union`, `Dict` and `List`
are not errors, but they are not the house style.

| Use | Not |
|---|---|
| `def func(x: str \| None)` | `def func(x: Optional[str])` |
| `def func(x: int \| str)` | `def func(x: Union[int, str])` |
| `items: list[str]` | `items: List[str]` |
| `data: dict[str, Any]` | `data: Dict[str, Any]` |
| `tuple[int, str]` | `Tuple[int, str]` |

### Checklist

Before creating any test file:

- [ ] Match the surrounding module's style; `scripts/core/` is `X | None` and
      lowercase generics
- [ ] `from __future__ import annotations` at the top, as the rest of the
      codebase does - it keeps annotations lazy and is required by some of the
      older call sites
- [ ] Do not add `typing` imports you do not need
