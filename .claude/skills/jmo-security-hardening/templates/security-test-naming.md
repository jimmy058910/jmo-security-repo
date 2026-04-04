# Security Test Naming Conventions

Follow these naming conventions for security tests to improve maintainability and searchability.

---

## Pattern: `test_[component]_[behavior]_[attack_type]`

```python
# Sanitization tests
def test_sanitize_blocks_traversal(self):
    """Path traversal sequences should be neutralized."""

def test_sanitize_blocks_hidden_files(self):
    """Hidden file prefixes should be removed."""

def test_sanitize_allows_normal_names(self):
    """Normal repository names should pass through unchanged."""

# Validation tests
def test_validate_blocks_absolute_paths(self):
    """Absolute paths outside base should be rejected."""

def test_validate_blocks_symlink_escape(self):
    """Symlinks pointing outside base should be rejected."""

def test_validate_allows_child_paths(self):
    """Paths within base directory should be allowed."""

# Integration tests
def test_integration_repo_scanning_with_traversal(self):
    """Real repo scanning should handle malicious repo names."""

def test_integration_image_scanning_with_injection(self):
    """Real image scanning should handle malicious image tags."""

# Fuzzing tests
@pytest.mark.parametrize("malicious_input", [...])
def test_fuzz_blocks_traversal(self, malicious_input):
    """Parametrized fuzzing: blocks path traversal attempts."""

@pytest.mark.parametrize("malicious_input", [...])
def test_fuzz_blocks_injection(self, malicious_input):
    """Parametrized fuzzing: blocks command injection attempts."""
```

---

## Test Class Organization

```python
class TestSanitizePathComponent:
    """Test _sanitize_path_component() against path traversal attacks."""

    # Normal behavior tests
    def test_sanitize_normal_names(self):
        """Normal inputs should pass through safely."""

    def test_sanitize_empty_inputs(self):
        """Empty inputs should return fallback value."""

    # Security tests (attack types)
    def test_sanitize_traversal_sequences(self):
        """Path traversal sequences (..) should be removed."""

    def test_sanitize_hidden_files(self):
        """Hidden file prefixes (.) should be stripped."""

    def test_sanitize_special_characters(self):
        """Special characters should be replaced with underscores."""

    # Application-specific tests
    def test_sanitize_container_images(self):
        """Container image names (with :, /) should be sanitized."""

    def test_sanitize_gitlab_paths(self):
        """GitLab paths (group/repo) should be sanitized."""


class TestValidateOutputPath:
    """Test _validate_output_path() defense-in-depth validation."""

    # Positive tests
    def test_validate_allowed_paths(self):
        """Paths within base directory should be allowed."""

    # Negative tests (blocks attacks)
    def test_validate_blocks_traversal(self):
        """Paths escaping base via .. should be blocked."""

    def test_validate_blocks_absolute_path_outside_base(self):
        """Absolute paths outside base should be blocked."""

    def test_validate_blocks_symlinks(self):
        """Symlinks pointing outside base should be blocked."""


class TestPathTraversalFuzzing:
    """Fuzzing tests with 100+ malicious path inputs."""

    @pytest.mark.parametrize("malicious_input", [
        "../../../etc/passwd",
        "..\\..\\Windows\\System32",
        # ... 100+ more cases
    ])
    def test_fuzz_sanitize_blocks_malicious(self, malicious_input):
        """Single test, 100+ executions via parametrization."""
        result = _sanitize_path_component(malicious_input)
        assert ".." not in result
        assert "/" not in result
        assert "\\" not in result


class TestIntegrationWithJmoPy:
    """Integration tests simulating real jmo.py usage."""

    def test_integration_repo_scanning(self):
        """Repo scanning with malicious repo name should succeed safely."""

    def test_integration_image_scanning(self):
        """Image scanning with malicious image tag should succeed safely."""
```

---

## Docstring Template for Security Tests

```python
def test_sanitize_traversal_sequences(self):
    """Path traversal sequences should be neutralized.

    Security: CWE-22 (Path Traversal)
    Attack Vectors: ../, ../../, ../../../, etc.
    Expected: Traversal sequences replaced with _
    """
    assert _sanitize_path_component("../etc/passwd") == "___etc_passwd"
```
