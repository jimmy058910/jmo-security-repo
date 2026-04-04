# Mock Patterns and Anti-Patterns

## Pattern 1: Explicit Attribute Setting

**Problem:** MagicMock auto-creates attributes, leading to false positives when testing for `None`.

```python
# BAD: MagicMock auto-creates attributes
args = MagicMock()
print(args.image)  # Returns <MagicMock name='mock.image'> (NOT None!)
assert args.image is None  # FAILS!

# GOOD: Explicit attribute setting
def create_mock_args(**kwargs: Any) -> MagicMock:
    args = MagicMock(spec=[])  # Empty spec prevents auto-creation

    # Define ALL expected attributes with None defaults
    all_attrs = {
        "image": None,
        "images_file": None,
        "url": None,
        "repos_dir": None,
        # ... all other CLI arguments
    }

    # Override with provided values
    all_attrs.update(kwargs)

    # Explicitly set attributes
    for key, value in all_attrs.items():
        setattr(args, key, value)

    return args

# Usage
args = create_mock_args(image="nginx:latest")
assert args.image == "nginx:latest"
assert args.repos_dir is None  # Now correctly None!
```

## Pattern 2: Service Client Mocking

```python
def create_mock_service_class(should_fail: bool = False, exception: Optional[Exception] = None):
    """Helper to create mock external service clients."""
    class MockServiceClient:
        def __init__(self, should_fail: bool = False, exception: Optional[Exception] = None):
            self.should_fail = should_fail
            self.exception = exception
            self.last_params: Optional[Dict[str, Any]] = None

        def send(self, params: Dict[str, Any]):
            self.last_params = params
            if self.exception:
                raise self.exception
            if self.should_fail:
                raise ValueError("Simulated failure")
            return {"id": "test-id-123"}

    return MockServiceClient(should_fail, exception)
```

## Anti-Pattern 1: Not Verifying Mock Calls

```python
# BAD: Doesn't verify the function was called correctly
mock_service = MagicMock()
service.send_email(mock_service, "test@example.com")
# Test passes even if send_email never called the mock!

# GOOD: Verify call signature
mock_service = MagicMock()
service.send_email(mock_service, "test@example.com")
mock_service.send.assert_called_once()
assert mock_service.send.call_args[0][0]["to"] == "test@example.com"
```

## Anti-Pattern 2: Incomplete Mock State

```python
# BAD: Mock returns MagicMock when dict expected
mock_obj = MagicMock()
result = parse_data(mock_obj.field)  # mock_obj.field is MagicMock!
assert "key" in result  # May pass even though result is wrong type

# GOOD: Mock returns correct type
mock_obj = MagicMock()
mock_obj.field = {"expected": "data"}
result = parse_data(mock_obj.field)
assert result["expected"] == "data"
```

---

## Helper Function Naming Conventions

| Module Type | Helper Name | Purpose |
|-------------|-------------|---------|
| **Adapters** | `write_tmp(tmp_path, name, content)` | Write temp JSON files |
| **Services** | `create_mock_<service>()` | Mock external API clients |
| **Reporters** | `create_finding(**kwargs)` | Fabricate CommonFinding dicts |
| **Mappers** | `create_finding(**kwargs)` | Fabricate findings for mapping |
| **Config** | `write_yaml_file(tmp_path, name, content)` | Write temp YAML configs |
| **CLI** | `create_mock_args(**kwargs)` | Mock argparse Namespace |

## Standard Helper Patterns

**Adapter Tests:**

```python
def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    """Write temporary JSON file for adapter testing."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p
```

**Reporter Tests:**

```python
def create_finding(
    rule_id: str = "test-rule",
    severity: str = "HIGH",
    **kwargs: Any,
) -> Dict[str, Any]:
    """Create test finding for reporter testing."""
    finding: Dict[str, Any] = {
        "schemaVersion": "1.2.0",
        "id": f"test-{rule_id}",
        "ruleId": rule_id,
        "severity": severity,
        "message": "Test finding",
        "tool": {"name": "test-tool", "version": "1.0.0"},
        "location": {"path": "test.py", "startLine": 1},
        "tags": [],
    }
    finding.update(kwargs)
    return finding
```

**Config Tests:**

```python
def write_yaml_file(tmp_path: Path, filename: str, content: str) -> Path:
    """Write temporary YAML config file."""
    yaml_file = tmp_path / filename
    yaml_file.write_text(content, encoding="utf-8")
    return yaml_file
```

**Service Tests:**

```python
def create_mock_email_client(should_fail: bool = False) -> MagicMock:
    """Create mock email service client."""
    mock = MagicMock()
    if should_fail:
        mock.send.side_effect = Exception("API Error")
    else:
        mock.send.return_value = {"id": "test-id"}
    return mock
```

---

## Subprocess Mocking (from conftest.py)

```python
# CORRECT: Mock both tool existence checks
with (
    patch("module.tool_exists", return_value=True),
    patch("module.find_tool", return_value="/usr/bin/tool"),
    patch("subprocess.run") as mock_run,
):
    mock_run.return_value = mock_subprocess_success()
    # ... test code ...

# WRONG: Missing find_tool mock causes None command
with patch("module.tool_exists", return_value=True):
    # find_tool returns None -> command is None -> hangs or crashes
```

## Optimizing Slow Tests with Mocks

```python
# FAST: Mock subprocess for unit tests
def test_tool_invocation(tmp_path, monkeypatch):
    def fake_run(cmd, *args, **kwargs):
        # Simulate tool output without actually running
        return FakeCompletedProcess(returncode=0, stdout='{"results": []}')

    monkeypatch.setattr(subprocess, "run", fake_run)
    # Test completes in <0.1s instead of 10s
```
