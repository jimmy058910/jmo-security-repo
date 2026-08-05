# Coverage Improvement Strategies

## Coverage Improvement Workflow

Systematically increase coverage from current level to 85%+ target.

### Step 1: Measure Current Coverage

```bash
# Generate coverage report
pytest tests/adapters/test_tool_adapter.py \
  --cov=scripts/core/adapters/tool_adapter \
  --cov-report=term-missing

# Example output:
# Name                                    Stmts   Miss  Cover   Missing
# ---------------------------------------------------------------------
# scripts/core/adapters/tool_adapter.py      42     15    64%   18-22, 35-38, 45
```

**Interpretation:**

- **64% coverage** -- Need 21% more to reach 85%
- **Lines 18-22** -- First uncovered block (5 lines)
- **Lines 35-38** -- Second uncovered block (4 lines)
- **Line 45** -- Single uncovered line (6 lines total)

### Step 2: Identify Uncovered Branches

Read the adapter source and map missing lines to logic branches:

```python
# scripts/core/adapters/tool_adapter.py
def load_tool(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():  # Line 18 (covered)
        return []

    content = path.read_text()
    if not content.strip():  # Line 22 (NOT COVERED - empty file branch)
        return []

    try:
        data = json.loads(content)
    except JSONDecodeError:  # Line 35 (NOT COVERED - invalid JSON branch)
        return []

    findings = []
    for item in data.get("results", []):
        severity = item.get("severity", "UNKNOWN")  # Line 45 (NOT COVERED - missing severity)
        findings.append(...)

    return findings
```

### Step 3: Write Tests for Uncovered Branches

Map each missing line to a test function:

```python
# tests/adapters/test_tool_adapter.py

# Covers lines 22-24 (empty file branch)
def test_tool_empty_file(tmp_path):
    """Test adapter handles empty file."""
    path = write_tmp(tmp_path, "tool.json", "")
    out = load_tool(path)
    assert out == []

# Covers lines 35-37 (invalid JSON branch)
def test_tool_invalid_json(tmp_path):
    """Test adapter handles malformed JSON."""
    path = write_tmp(tmp_path, "tool.json", "{invalid")
    out = load_tool(path)
    assert out == []

# Covers line 45 (missing severity fallback)
def test_tool_missing_severity(tmp_path):
    """Test default severity when field missing."""
    sample = {"results": [{"id": "1"}]}  # No severity
    path = write_tmp(tmp_path, "tool.json", json.dumps(sample))
    out = load_tool(path)
    assert out[0]["severity"] == "UNKNOWN"
```

### Step 4: Re-Measure Coverage

```bash
pytest tests/adapters/test_tool_adapter.py \
  --cov=scripts/core/adapters/tool_adapter \
  --cov-report=term-missing

# New output:
# Name                                    Stmts   Miss  Cover   Missing
# ---------------------------------------------------------------------
# scripts/core/adapters/tool_adapter.py      42      3    93%   52-54
```

**Progress:** 64% -> 93% -- Added 29% coverage with 3 tests

### Step 5: Target Remaining Lines

```python
# Line 52-54: CWE extraction from nested metadata
# if "metadata" in item["extra"]:
#     cwes = item["extra"]["metadata"].get("cwe", [])
#     finding["risk"]["cwe"] = cwes

# Test for CWE extraction
def test_tool_cwe_metadata(tmp_path):
    """Test CWE extraction from nested metadata."""
    sample = {
        "results": [{
            "id": "1",
            "severity": "high",
            "extra": {
                "metadata": {"cwe": ["CWE-89", "CWE-79"]}
            }
        }]
    }
    path = write_tmp(tmp_path, "tool.json", json.dumps(sample))
    out = load_tool(path)
    assert "CWE-89" in out[0]["risk"]["cwe"]
```

### Step 6: Verify 85%+ Coverage

```bash
pytest tests/adapters/test_tool_adapter.py \
  --cov=scripts/core/adapters/tool_adapter \
  --cov-report=term-missing

# Final output:
# Name                                    Stmts   Miss  Cover   Missing
# ---------------------------------------------------------------------
# scripts/core/adapters/tool_adapter.py      42      0   100%
```

---

## Incremental Coverage Strategy

If starting from low coverage (e.g., 35%), use incremental milestones:

### Phase 1: Quick Wins (35% -> 60%)

- Add Category 1 (basic valid input) tests -- 5-10 tests
- Target: Cover main happy path and common fields

### Phase 2: Error Handling (60% -> 75%)

- Add Category 2 (error paths) tests -- 3-5 tests
- Target: Cover all try/except, if/else branches

### Phase 3: Schema Features (75% -> 85%)

- Add Category 3 (v1.1.0 risk) + Category 4 (v1.2.0 compliance) -- 2-4 tests
- Target: Cover optional field extraction logic

### Phase 4: Edge Cases (85% -> 90%+)

- Add Category 5 (tool-specific) tests -- 2-3 tests
- Target: Cover unusual data patterns (multiline, empty arrays, nested paths)

**Time Estimates:**

- Phase 1: 1 hour (10 tests x 6 min each)
- Phase 2: 30 min (5 tests x 6 min each)
- Phase 3: 20 min (3 tests x 6-7 min each)
- Phase 4: 15 min (2 tests x 7-8 min each)
- **Total: ~2 hours to go from 35% to 90% coverage**

---

## Achieving 85%+ Coverage

**Coverage Dimensions:**

1. **Statement Coverage** -- Every line of adapter code executed
2. **Branch Coverage** -- Every if/else path taken
3. **Edge Case Coverage** -- Unusual inputs handled

**Strategy:**

```python
# Example: Branch coverage for severity mapping
def test_<tool>_all_severity_levels(tmp_path: Path):
    """Test all severity level mappings."""
    severities = [
        ("CRITICAL", "CRITICAL"),
        ("ERROR", "HIGH"),
        ("HIGH", "HIGH"),
        ("WARNING", "MEDIUM"),
        ("MEDIUM", "MEDIUM"),
        ("INFO", "LOW"),
        ("LOW", "LOW"),
        ("NOTE", "INFO"),
    ]

    for tool_sev, expected_sev in severities:
        sample = {
            "results": [
                {
                    "ruleId": f"test-{tool_sev}",
                    "message": "Test",
                    "severity": tool_sev,
                    "path": "test.py",
                    "line": 1,
                }
            ]
        }
        path = write_tmp(tmp_path, f"<tool>_{tool_sev}.json", json.dumps(sample))
        out = load_<tool>(path)
        assert len(out) == 1
        assert out[0]["severity"] == expected_sev, f"{tool_sev} should map to {expected_sev}"
```

## Running Coverage Reports

```bash
# Run with coverage reporting
pytest tests/adapters/test_<tool>_adapter.py \
    --cov=scripts/core/adapters/<tool>_adapter \
    --cov-report=term-missing \
    --cov-report=html

# View HTML report
open htmlcov/index.html

# Fail if below 85%
pytest tests/adapters/test_<tool>_adapter.py \
    --cov=scripts/core/adapters/<tool>_adapter \
    --cov-fail-under=85
```

## Identifying Uncovered Code

```bash
# Show missing lines
pytest tests/adapters/test_<tool>_adapter.py \
    --cov=scripts/core/adapters/<tool>_adapter \
    --cov-report=term-missing

# Output example:
# Name                                    Stmts   Miss  Cover   Missing
# ---------------------------------------------------------------------
# scripts/core/adapters/tool_adapter.py      45      7    84%   23-25, 40, 67-69
```

**Addressing Uncovered Lines:**

1. **Lines 23-25** -- Likely error handling branch -> Add malformed input test
2. **Line 40** -- Alternative field fallback -> Add missing field test
3. **Lines 67-69** -- Optional feature extraction -> Add feature-present test

---

## Coverage Targets by Module Type

| Module Type | Minimum | Target | Exceptional |
|-------------|---------|--------|-------------|
| **Adapters** | 85% | 90% | 95%+ |
| **Reporters** | 85% | 95% | 98%+ |
| **Mappers** | 85% | 95% | 98%+ |
| **Services** | 85% | 90% | 95%+ |
| **Config** | 85% | 95% | 98%+ |
| **CLI Helpers** | 90% | 98% | 100% |

### Acceptable Missing Coverage

- **Logging branches** -- Different log levels (DEBUG/INFO/WARN)
- **Error message formatting** -- Specific wording of exceptions
- **Unreachable defensive code** -- `if x is None` when x is always set
- **OS-specific branches** -- Windows vs Linux paths (test on Linux)
- **Version compatibility shims** -- Python 3.8 vs 3.12 differences

### Unacceptable Missing Coverage

- **Error handling** -- try/except blocks MUST be tested
- **Business logic branches** -- if/else for feature behavior
- **Data validation** -- Type checking, range validation
- **Edge cases** -- Empty inputs, null values, malformed data

---

## Parametrized Tests (Advanced)

```python
import pytest

@pytest.mark.parametrize(
    "severity,expected",
    [
        ("CRITICAL", "CRITICAL"),
        ("ERROR", "HIGH"),
        ("WARNING", "MEDIUM"),
        ("INFO", "LOW"),
    ],
)
def test_<tool>_severity_mapping(tmp_path: Path, severity: str, expected: str):
    """Test all severity mappings using parametrization."""
    sample = {
        "results": [
            {
                "ruleId": "test",
                "message": "Test",
                "severity": severity,
                "path": "test.py",
                "line": 1,
            }
        ]
    }
    path = write_tmp(tmp_path, f"test_{severity}.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1
    assert out[0]["severity"] == expected
```
