---
name: jmo-test-fabricator
description: Generate comprehensive pytest test suites with fabricated fixtures, integration tests, and platform validation checklists ensuring 85%+ coverage. Use when writing tests for adapters or any module.
argument-hint: <module-or-adapter-name>
user-invocable: true
context: fork
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

## Execution

Generate tests for: **$ARGUMENTS**

**Current test count:**
!python -m pytest tests/ --co -q 2>/dev/null | tail -1 || echo "n/a"

---

## Purpose

Generate comprehensive pytest test suites for JMo Security with fabricated fixtures, integration tests, CI/CD examples, and platform validation checklists, ensuring 85%+ coverage.

**Approach:** Generate tests that catch real bugs, not tests that merely increase coverage numbers.

## When to Use

**Adapter Testing:** Creating/expanding tests for adapters, validating format changes, debugging parsing issues.

**Reporter Testing:** Basic reporters, compliance reporters, SARIF reporters, HTML dashboard output validation.

**Service Testing:** External API clients, network failure handling, retries, authentication.

**Mapper Testing:** Compliance mappers (CWE to OWASP/Top 25/CIS/NIST/PCI DSS/MITRE ATT&CK).

**Config/CLI Testing:** Config loaders, YAML parsing, field validation, multi-target helpers, argument parsing.

**General:** CI coverage below 85%, new CommonFinding schema features, improving coverage for any module.

---

## Quick Reference Table

| I Need To... | Reference File | Typical File | Time |
|--------------|----------------|--------------|------|
| Test new tool adapter | [required-test-functions](references/required-test-functions.md) | tests/adapters/test_tool.py | 2-3h |
| Test integration workflow | [integration-patterns](references/integration-patterns.md) | tests/integration/test_workflow.py | 1-2h |
| Create CI/CD example | [ci-platform-validation](references/ci-platform-validation.md) | docs/examples/.gitlab-ci.yml | 1h |
| Write manual test checklist | [ci-platform-validation](references/ci-platform-validation.md) | docs/RELEASE.md (section) | 1-2h |
| Debug test failure | [troubleshooting](references/troubleshooting.md) | N/A | 15-30m |
| Improve coverage | [coverage-strategies](references/coverage-strategies.md) | N/A | 30-60m |
| Fabricate JSON fixtures | [fabricating-json](examples/fabricating-json.md) | N/A | 15-30m |
| Mock subprocess/services | [mock-patterns](references/mock-patterns.md) | N/A | 15m |
| Avoid common pitfalls | [common-mistakes](references/common-mistakes.md) | N/A | 10m |

**Common Time Savers:**

- Use helper functions -- Save 50%+ lines of code
- Copy existing similar test -- Save 30-60 minutes
- Read module before writing tests -- Prevent 1-2 hours of rework
- Use flexible assertions -- Prevent platform-specific failures

---

## Testing Philosophy

1. **Write fabricated data first** -- Understand the data format before writing code
2. **Test edge cases comprehensively** -- Empty inputs, malformed data, missing fields, alternative structures
3. **Cover all schema versions** -- v1.0.0 basic, v1.1.0 risk/context, v1.2.0 compliance
4. **Preserve raw tool output** -- Always verify `raw` field contains original payload (adapters only)
5. **Fast test execution** -- All tests should complete in <5 seconds total
6. **Test actual behavior, not ideal behavior** -- Test what the code does now, not what it should do
7. **Python 3.8 compatibility required** -- No `|` union syntax, use `Optional[T]` and `Union[T1, T2]`
8. **Unicode handling is mandatory** -- All text-processing modules must handle emoji, CJK, Cyrillic
9. **Read the module first** -- Always read the actual module code before writing tests
10. **Fix all technical debt immediately** -- When you find linting issues or failing tests, fix ALL of them

---

## Pre-Test Development Workflow

**CRITICAL: ALWAYS follow this sequence before writing tests:**

### Step 1: Read the Module Under Test

Look for: all branches (if/else, try/except), field extraction logic, severity mapping, alternative field names, error handling.

### Step 2: Read Existing Tests (If Any)

Look for: what's already covered, helper functions to reuse, test naming patterns, gaps in coverage.

### Step 3: Check Similar Adapter Tests

Reuse patterns for similar tool types. Copy-paste helper functions if applicable.

### Step 4: Draft Test Outline

```python
# Category 1: Basic Valid Input (TODO)
# Category 2: Error Handling (TODO)
# Category 3: v1.1.0 Features (TODO)
# Category 4: v1.2.0 Compliance (TODO)
# Category 5: Tool-Specific Edge Cases (TODO)
```

### Step 5: Implement Tests Incrementally

```bash
pytest tests/adapters/test_tool.py::test_tool_basic -v   # Start with Category 1
pytest tests/adapters/test_tool.py -v                     # After each category
pytest tests/adapters/test_tool.py --cov=scripts/core/adapters/tool_adapter --cov-report=term-missing
```

---

## Test File Structure

Every adapter test file MUST follow this structure with **standardized category headers**.

### Test Category Header Convention

```python
# ========== Category 1: Basic Valid Input ==========
def test_tool_basic(tmp_path: Path): ...
def test_tool_multiple_findings(tmp_path: Path): ...

# ========== Category 2: Error Handling ==========
def test_tool_empty_file(tmp_path: Path): ...
def test_tool_malformed_json(tmp_path: Path): ...

# ========== Category 3: Schema v1.1.0 Features (Risk, Context, Autofix) ==========
def test_tool_v110_risk_fields(tmp_path: Path): ...

# ========== Category 4: Schema v1.2.0 Compliance ==========
def test_tool_compliance_enrichment(tmp_path: Path): ...

# ========== Category 5: Tool-Specific Edge Cases ==========
def test_tool_nested_paths(tmp_path: Path): ...
```

**Integration Test Categories:**

```python
# ========== Test Category: Profile Validation ==========
# ========== Test Category: Multi-Target Deduplication ==========
# ========== Test Category: Error Handling ==========
```

### Complete Test File Template

```python
import json
from pathlib import Path

from scripts.core.adapters.<tool>_adapter import load_<tool>


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# Test Category 1: Basic Valid Input
def test_<tool>_basic(tmp_path: Path):
    """Test basic valid finding with all required fields."""

# Test Category 2: Error Handling
def test_<tool>_empty_and_malformed(tmp_path: Path):
    """Test error handling for empty and malformed inputs."""

# Test Category 3: Schema v1.1.0 Features
def test_<tool>_v110_autofix_remediation(tmp_path: Path):
    """Test v1.1.0 autofix remediation structure."""

# Test Category 4: Schema v1.2.0 Compliance
def test_<tool>_compliance_enrichment(tmp_path: Path):
    """Test that findings are enriched with compliance mappings."""

# Test Category 5: Tool-Specific Edge Cases
def test_<tool>_alternative_severity_field(tmp_path: Path):
    """Test severity from alternative field location."""
```

**File Location:** `tests/adapters/test_<tool>_adapter.py`

**Naming Convention:** File: `test_<tool>_adapter.py` | Functions: `test_<tool>_<scenario>` | Fixtures: `write_tmp`

---

## Required Test Functions (5 Categories)

Every adapter test suite MUST include these 5 categories. Each has detailed templates, code examples, and tool-specific variants.
See [detailed required test functions](references/required-test-functions.md) for complete patterns and code templates.

**Summary:**

| Category | Purpose | Key Tests |
|----------|---------|-----------|
| 1: Basic Valid Input | Happy path parsing | Field mapping, schema version, fingerprint, raw preservation |
| 2: Error Handling | Resilience to bad input | Empty file, malformed JSON, missing file, non-dict items, Unicode |
| 3: v1.1.0 Features | Risk/remediation/context | Autofix dict, string remediation, CWE metadata, likelihood/impact, code context |
| 4: v1.2.0 Compliance | Compliance enrichment | 6 framework mappings, multiple CWEs, no-CWE graceful handling |
| 5: Tool-Specific | Output format variations | Alt field names, missing optional fields, tags, NDJSON, nested arrays |

---

## Integration Testing Patterns

Multi-component workflow tests (scan -> report -> CI), profile validation, and graceful degradation.
See [detailed integration patterns](references/integration-patterns.md) for complete examples including profile validation, multi-target deduplication, config inheritance, and flexible assertions.

---

## CI/CD and Platform Validation

GitLab CI, Jenkins, GitHub Actions examples and platform-specific validation checklists (WSL, macOS, Docker).
See [CI/CD and platform validation patterns](references/ci-platform-validation.md) for complete templates.

---

## Fabricating Realistic JSON

Guidelines for creating sample JSON matching real tool output: Results Array, Flat Array, SARIF, and Nested Targets patterns plus complete Snyk and Semgrep examples.
See [fabricating JSON fixtures](examples/fabricating-json.md) for all patterns and real-world examples.

---

## Mock Patterns

Subprocess mocking with `mock_subprocess_success()`, explicit attribute setting for MagicMock, service client mocking, and standard helper function conventions.
See [detailed mock patterns](references/mock-patterns.md) for complete examples and anti-patterns.

---

## Common Mistakes

Seven common pitfalls (hardcoded values, missing error paths, no timeouts, platform-specific assertions, skipping module reading, ignoring optional fields, brittle schema versions) plus Python 3.8 compatibility requirements.
See [common mistakes and anti-patterns](references/common-mistakes.md) for solutions with code examples.

---

## Debugging and Troubleshooting

8-step systematic debugging workflow, common debug patterns (breakpoints, file inspection, exception handling), and test execution time guidelines with timeout configuration.
See [troubleshooting guide](references/troubleshooting.md) for the complete checklist.

---

## Coverage Strategies

6-step workflow from current coverage to 85%+, incremental strategy (35% -> 90% in ~2 hours), parametrized tests, coverage targets by module type, and what's acceptable vs unacceptable to leave uncovered.
See [coverage improvement strategies](references/coverage-strategies.md) for the complete workflow.

---

## Pytest Best Practices

### Fixture Usage

```python
# Use tmp_path fixture (modern, thread-safe)
def test_example(tmp_path: Path):
    test_file = tmp_path / "test.json"
    test_file.write_text('{"data": "value"}')

# DON'T use tmpdir (deprecated)
```

### Test Organization

```python
# Use descriptive test names
def test_<tool>_basic(tmp_path: Path):  # Clear
def test_1(tmp_path: Path):  # Unclear -- avoid
```

---

## Reference Implementations

Real test files from this project to use as examples:

**Adapters:**
- `tests/adapters/test_trufflehog_adapter.py` -- Secrets tool pattern
- `tests/adapters/test_semgrep_adapter.py` -- SAST tool pattern
- `tests/adapters/test_gitleaks_adapter.py` -- NDJSON handling

**Reporters:**
- `tests/reporters/test_compliance_reporter.py` -- 96% coverage, PCI DSS + MITRE ATT&CK
- `tests/reporters/test_sarif_reporter_comprehensive.py` -- 95% coverage, SARIF 2.1.0

**Mappers:**
- `tests/unit/test_compliance_mapper_direct.py` -- 96% coverage, all 6 frameworks

**Config:**
- `tests/unit/test_config_comprehensive.py` -- 97% coverage, YAML validation

**CLI:**
- `tests/cli/test_multi_target_helpers.py` -- 100% coverage, multi-target scanning

---

## Real-World Testing Insights

1. **Helper functions save 50%+ lines** -- `create_finding()` helper reduces 40 lines to 5-10 per test
2. **Category-based organization** -- Easy navigation, clear coverage, review-friendly
3. **Unicode testing catches real bugs** -- Found missing `encoding="utf-8"` in file writes
4. **"Edge cases" are common** -- `threads: 0`, empty strings, lowercase enums happen in 8-67% of configs
5. **Mock clients need state tracking** -- Track `last_params` and `call_count`, not just `assert_called_once()`
6. **Docstrings document intent** -- Failures become self-documenting, refactoring is safer
7. **Coverage correlates with helpers + systematic edge cases** -- Not with test count alone

---

## Checklist

### Setup

- [ ] Test file created: `tests/adapters/test_<tool>_adapter.py`
- [ ] `write_tmp()` helper function included
- [ ] Import statement: `from scripts.core.adapters.<tool>_adapter import load_<tool>`

### Test Categories (5 Required)

- [ ] **Category 1:** Basic valid input test (`test_<tool>_basic`)
- [ ] **Category 2:** Error handling tests (empty, malformed, missing file, non-dict items)
- [ ] **Category 3:** v1.1.0 feature tests (autofix, CWE, likelihood/impact, code context)
- [ ] **Category 4:** v1.2.0 compliance enrichment test
- [ ] **Category 5:** Tool-specific edge case tests (alternative fields, NDJSON, nested arrays, etc.)

### Coverage

- [ ] All tests pass: `pytest tests/adapters/test_<tool>_adapter.py -v`
- [ ] Coverage >=85%: `pytest ... --cov=scripts/core/adapters/<tool>_adapter --cov-fail-under=85`
- [ ] Coverage report reviewed: `--cov-report=term-missing` shows no critical gaps

### Code Quality

- [ ] Pre-commit hooks pass
- [ ] No hardcoded paths (use `tmp_path` fixture)
- [ ] All JSON samples valid (use `json.dumps()`)
- [ ] Test names descriptive, docstrings present

---

## Self-Learning Triggers

Update this skill when:

1. **New test pattern emerges** -- Same type written 3+ times across modules
2. **Common mistake repeated** -- Same pitfall hits twice
3. **Coverage gap identified** -- CI failure reveals undocumented gap
4. **New test category required** -- Schema upgrade or architecture change
5. **Tool output format changes** -- External tool updates JSON structure
6. **CI/CD environment issues** -- Tests pass locally but fail in CI
7. **Performance degradation** -- Test suite >20% slower

---

## Trigger Patterns

Use this skill when you see these phrases:

- "Write tests for [tool] adapter"
- "Create test suite for [adapter]"
- "Improve test coverage for [file]"
- "Generate test fixtures for [tool]"
- "How do I test an adapter?"
- "Coverage is below 85%"
- "Add tests for v1.2.0 compliance enrichment"

**When in Doubt:** Check existing adapter tests in `tests/adapters/` for patterns.

---

## Memory Integration

Cached test patterns in `.jmo/memory/test-patterns/` provide 40% faster repeated test writing by reusing JSON schemas, coverage strategies, and fabricated fixtures.
See [memory integration details](references/memory-integration.md) for storage format, workflow, and cache management.

---

## Notes

- Use `tmp_path` fixture (not `tmpdir`) -- Modern pytest, thread-safe
- Always use `json.dumps()` -- Ensures valid JSON syntax
- Test files should be self-contained -- No external deps, no network calls
- Fabricated JSON: minimal but realistic -- Match real tool output structure
- Error handling is critical -- Adapters must never crash, always return `[]`
- Schema versions: v1.0.0 basic, v1.1.0 risk/context/autofix, v1.2.0 compliance (6 frameworks)
- Most adapters output v1.1.0 or v1.2.0 after enrichment -- Tests should accept both
