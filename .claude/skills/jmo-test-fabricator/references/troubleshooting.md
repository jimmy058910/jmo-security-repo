# Debugging and Troubleshooting Test Failures

## Debugging Checklist

When tests fail, follow this systematic debugging workflow:

### Step 1: Read the Error Message

```bash
# Run single failing test with verbose output
pytest tests/adapters/test_tool_adapter.py::test_basic -vv

# Typical error patterns:
# - KeyError: Missing required field in fabricated JSON
# - AssertionError: Expected value doesn't match
# - JSONDecodeError: Invalid JSON syntax in test fixture
# - FileNotFoundError: Incorrect tmp_path usage
```

### Step 2: Verify Test Fixture

```python
# Add debug print to see actual JSON being tested
def test_basic(tmp_path):
    sample = {"results": [...]}
    print(f"DEBUG: Sample JSON: {json.dumps(sample, indent=2)}")
    path = write_tmp(tmp_path, "tool.json", json.dumps(sample))
    out = load_tool(path)
```

### Step 3: Inspect Adapter Output

```python
# Print adapter output to see what it returns
def test_basic(tmp_path):
    out = load_tool(path)
    print(f"DEBUG: Adapter returned {len(out)} findings:")
    for idx, finding in enumerate(out):
        print(f"  Finding {idx}: {finding}")
    assert len(out) >= 1
```

### Step 4: Check Adapter Implementation

```bash
# Read adapter source to verify field extraction logic
cat scripts/core/adapters/tool_adapter.py

# Common issues:
# - Adapter expects different JSON structure than fabricated
# - Severity mapping differs from expected
# - Nested field extraction uses wrong key path
```

### Step 5: Compare with Real Tool Output

```bash
# Run actual tool to see real output format
tool scan . -o json > real_output.json
cat real_output.json | jq .

# Compare with fabricated JSON in test
# Ensure nested structure matches exactly
```

### Step 6: Verify Schema Compliance

```python
# Check if finding matches CommonFinding schema
def test_schema_compliance(tmp_path):
    out = load_tool(path)
    finding = out[0]

    # Required fields (v1.0.0+)
    assert "schemaVersion" in finding
    assert "id" in finding  # Fingerprint
    assert "ruleId" in finding
    assert "severity" in finding
    assert "tool" in finding
    assert "location" in finding
    assert "message" in finding

    # Location subfields
    assert "path" in finding["location"]
    assert "startLine" in finding["location"]
```

### Step 7: Run with Coverage

```bash
# Identify untested branches
pytest tests/adapters/test_tool_adapter.py --cov=scripts/core/adapters/tool_adapter --cov-report=term-missing

# Output shows:
# Name                                    Stmts   Miss  Cover   Missing
# ---------------------------------------------------------------------
# scripts/core/adapters/tool_adapter.py      42      8    81%   15-18, 25, 32

# Lines 15-18 not covered -> Add test for that branch
```

### Step 8: Isolate Failing Assertion

```python
# Break down complex assertion into steps
def test_debug(tmp_path):
    out = load_tool(path)

    # Step 1: Verify list returned
    assert isinstance(out, list), f"Expected list, got {type(out)}"

    # Step 2: Verify non-empty
    assert len(out) > 0, f"Expected findings, got empty list"

    # Step 3: Verify first item structure
    item = out[0]
    assert "severity" in item, f"Missing severity. Keys: {item.keys()}"

    # Step 4: Verify severity value
    assert item["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
```

---

## Common Debug Patterns

### Pattern 1: pytest.set_trace() Breakpoint

```python
def test_debug(tmp_path):
    out = load_tool(path)
    import pytest; pytest.set_trace()  # Drop into debugger
    assert len(out) == 1
```

### Pattern 2: Temporary File Inspection

```python
def test_debug(tmp_path):
    sample = {"results": [...]}
    path = write_tmp(tmp_path, "tool.json", json.dumps(sample))

    # Print path to manually inspect
    print(f"DEBUG: Temp file at {path}")
    print(f"Content: {path.read_text()}")

    out = load_tool(path)
```

### Pattern 3: Adapter Exception Handling

```python
def test_debug(tmp_path):
    try:
        out = load_tool(path)
    except Exception as e:
        print(f"DEBUG: Adapter raised {type(e).__name__}: {e}")
        raise  # Re-raise to see full traceback
```

---

## Troubleshooting Test Failures

### Issue 1: "JSONDecodeError: Expecting value"

**Cause:** Malformed JSON in test sample

**Fix:**

```python
# Bad: Unescaped quotes
sample = {"message": "Test \"quote\" fails"}

# Good: Use json.dumps
sample = {"message": 'Test "quote" works'}
path = write_tmp(tmp_path, "test.json", json.dumps(sample))
```

### Issue 2: "AssertionError: Expected 1, got 0"

**Cause:** Adapter skipping finding due to missing required field

**Debug:**

```python
# Add debug output
out = load_<tool>(path)
print(f"DEBUG: Adapter returned {len(out)} findings")
print(f"DEBUG: Raw content: {path.read_text()}")
```

### Issue 3: "KeyError: 'compliance'"

**Cause:** Compliance field is optional, test assumes it's always present

**Fix:**

```python
# Bad: Assumes field exists
assert item["compliance"]["owaspTop10_2021"] is not None

# Good: Check existence first
if "compliance" in item:
    assert "owaspTop10_2021" in item["compliance"]
```

---

## Test Execution Time Guidelines

Manage test performance to keep CI fast and developer-friendly.

### Time Budgets by Test Category

| Test Type | Target Time | Max Acceptable | Notes |
|-----------|-------------|----------------|-------|
| Unit test (adapter) | <0.1s per test | 0.5s | Pure Python, no I/O |
| Integration test (subprocess) | 5-10s per test | 30s | Tool invocation overhead |
| Multi-target test | 10-20s per test | 60s | Parallel tool execution |
| Docker variant test | 20-40s per test | 120s | Docker build/pull time |
| Performance profiling test | 30-60s per test | 180s | Multiple profile runs |

### Timeout Configuration

**pytest.ini Configuration:**

```ini
[pytest]
timeout = 300  # Global 5-minute timeout for all tests
```

**Per-Test Timeouts:**

```python
# Fast unit tests (no timeout needed)
def test_adapter_basic(tmp_path):
    out = load_tool(path)
    assert len(out) == 1

# Integration tests (explicit timeout)
@pytest.mark.timeout(60)  # 1-minute timeout
def test_scan_integration(tmp_path):
    result = subprocess.run(["jmo", "scan", ...], timeout=45)
    assert result.returncode == 0

# Slow tests (marked explicitly)
@pytest.mark.slow
@pytest.mark.timeout(180)  # 3-minute timeout
def test_deep_profile(tmp_path):
    result = subprocess.run(["jmo", "scan", "--profile-name", "deep", ...], timeout=150)
    assert result.returncode in [0, 1]
```

### Optimizing Slow Tests

#### Strategy 1: Use Minimal Test Repos

```python
# SLOW: Large test repo
def test_scan(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    # Create 100 Python files
    for i in range(100):
        (repo / f"app{i}.py").write_text("print('test')")
    # Scan takes 30 seconds

# FAST: Minimal test repo
def test_scan(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('test')")  # Single file
    # Scan takes 5 seconds
```

#### Strategy 2: Parallel Execution

```bash
# Run tests in parallel using pytest-xdist
pytest tests/adapters/ -n auto  # Use all CPU cores

# Typical speedup:
# Sequential: 2 minutes (120 tests x 1s each)
# Parallel (8 cores): 20 seconds (120 tests / 8 cores)
```
