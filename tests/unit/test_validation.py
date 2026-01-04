#!/usr/bin/env python3
"""
Comprehensive tests for the centralized validation module.

Tests cover:
- Version string validation (URL injection prevention)
- Path validation (path traversal prevention)
- Profile name validation
- Tool name validation
- Cron expression validation
- URL validation (protocol injection prevention)
- Container image validation
- Integer range validation
- Schedule name validation

Security Philosophy:
- All tests verify that dangerous inputs are REJECTED
- Legitimate inputs should pass through
- Edge cases are thoroughly covered
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.core.validation import (
    # Version validation
    validate_version,
    VERSION_PATTERN,
    DANGEROUS_VERSION_CHARS,
    # Path validation
    validate_path_safe,
    validate_path_within_base,
    sanitize_path_component,
    # Profile validation
    validate_profile,
    get_valid_profiles,
    VALID_PROFILES,
    # Tool name validation
    validate_tool_name,
    TOOL_NAME_PATTERN,
    # Cron validation
    validate_cron_expression,
    CRON_SCHEDULE_PATTERN,
    # URL validation
    validate_url,
    # Container image validation
    validate_container_image,
    # Integer validation
    validate_positive_int,
    validate_non_negative_int,
    # Schedule name validation
    validate_schedule_name,
    # Output sanitization
    sanitize_subprocess_output,
    sanitize_error_message,
    sanitize_url_for_logging,
    OUTPUT_SANITIZATION_PATTERNS,
)


class TestVersionValidation:
    """Test version string validation for URL injection prevention."""

    @pytest.mark.parametrize(
        "version",
        [
            "1.0.0",
            "v1.0.0",
            "1.2.3",
            "v1.2.3",
            "1.0.0-rc1",
            "1.0.0-alpha.1",
            "1.0.0-beta",
            "1.0.0+build123",
            "2.0.0-rc1+build456",
            "10.20.30",
            "1",
            "1.0",
            "0.0.1",
        ],
    )
    def test_valid_versions(self, version):
        """Valid semver-like versions should pass."""
        assert validate_version(version, "test-tool") is True

    @pytest.mark.parametrize(
        "version",
        [
            "",  # Empty
            "../etc/passwd",  # Path traversal
            "1.0.0?malicious",  # Query injection
            "1.0.0#anchor",  # Fragment injection
            "1.0.0&evil=true",  # Parameter injection
            "1.0.0;rm -rf /",  # Command injection
            "1.0.0|cat /etc/passwd",  # Pipe injection
            "1.0.0$HOME",  # Variable expansion
            "1.0.0`whoami`",  # Command substitution
            "1.0.0\nmalicious",  # Newline injection
            "1.0.0\rmalicious",  # Carriage return injection
            "not-a-version",  # Invalid format
            "abc",  # Non-numeric
            "-1.0.0",  # Leading dash
        ],
    )
    def test_invalid_versions(self, version):
        """Invalid or malicious versions should fail."""
        assert validate_version(version, "test-tool") is False

    def test_dangerous_chars_constant(self):
        """Verify dangerous characters list is comprehensive."""
        assert "../" in DANGEROUS_VERSION_CHARS
        assert "..\\" in DANGEROUS_VERSION_CHARS
        assert "?" in DANGEROUS_VERSION_CHARS
        assert "#" in DANGEROUS_VERSION_CHARS


class TestPathValidation:
    """Test path validation for path traversal prevention."""

    @pytest.mark.parametrize(
        "path",
        [
            "/valid/path",
            "relative/path",
            "simple",
            "/home/user/repos",
            "C:/Projects/repo",  # Windows absolute path is OK
        ],
    )
    def test_valid_paths(self, path):
        """Valid paths should pass."""
        assert validate_path_safe(path, "test") is True

    @pytest.mark.parametrize(
        "path",
        [
            "../etc/passwd",
            "../../etc/shadow",
            "../../../etc",
            "repo/../../../etc",
            "path/with/../traversal",
            "path\x00null",  # Null byte
            "path<html>",  # HTML injection
            "path>redirect",
            "path|pipe",
            "path?query",
            "path*glob",
            'path"quote',
        ],
    )
    def test_invalid_paths(self, path):
        """Paths with traversal or dangerous chars should fail."""
        assert validate_path_safe(path, "test") is False

    def test_path_within_base(self, tmp_path):
        """Test path confinement validation."""
        base = tmp_path / "results"
        base.mkdir()

        # Valid paths within base
        assert validate_path_within_base(base / "repo1", base) is True
        assert validate_path_within_base(base / "sub" / "repo", base) is True

        # Invalid paths outside base
        assert validate_path_within_base(base / ".." / "etc", base) is False
        assert validate_path_within_base(Path("/etc/passwd"), base) is False


class TestSanitizePathComponent:
    """Test path component sanitization."""

    @pytest.mark.parametrize(
        "input_val,expected_contains",
        [
            ("normal-repo", "normal-repo"),
            ("my_project", "my_project"),
            ("nginx:latest", "nginx_latest"),
            ("ghcr.io/owner/repo", "ghcr.io_owner_repo"),
        ],
    )
    def test_sanitize_normal_inputs(self, input_val, expected_contains):
        """Normal inputs should be sanitized correctly."""
        result = sanitize_path_component(input_val)
        assert expected_contains in result

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "../etc/passwd",
            "../../etc/shadow",
            "..\\Windows\\System32",
            "/etc/passwd",
            "C:\\Windows\\System32",
            "file; rm -rf /",
            "file | cat /etc/passwd",
            "file\x00null",
        ],
    )
    def test_sanitize_blocks_traversal(self, malicious_input):
        """Malicious inputs should be sanitized to remove traversal."""
        result = sanitize_path_component(malicious_input)
        assert ".." not in result
        assert "/" not in result
        assert "\\" not in result
        assert result  # Should not be empty

    def test_sanitize_empty_input(self):
        """Empty input should return 'unknown'."""
        assert sanitize_path_component("") == "unknown"
        assert sanitize_path_component(".") == "unknown"


class TestProfileValidation:
    """Test scan profile validation."""

    @pytest.mark.parametrize(
        "profile",
        ["fast", "slim", "balanced", "deep"],
    )
    def test_valid_profiles(self, profile):
        """Valid profiles should pass."""
        assert validate_profile(profile) is True

    @pytest.mark.parametrize(
        "profile",
        [
            "",
            "invalid",
            "FAST",  # Case sensitive
            "fast; rm -rf /",
            "../etc",
            "slow",
        ],
    )
    def test_invalid_profiles(self, profile):
        """Invalid profiles should fail."""
        assert validate_profile(profile) is False

    def test_get_valid_profiles(self):
        """Should return sorted list of valid profiles."""
        profiles = get_valid_profiles()
        assert "fast" in profiles
        assert "balanced" in profiles
        assert "deep" in profiles
        assert "slim" in profiles
        assert len(profiles) == len(VALID_PROFILES)


class TestToolNameValidation:
    """Test tool name validation."""

    @pytest.mark.parametrize(
        "tool_name",
        [
            "trivy",
            "semgrep",
            "afl++",
            "grype",
            "tool-name",
            "tool_name",
            "nuclei",
        ],
    )
    def test_valid_tool_names(self, tool_name):
        """Valid tool names should pass."""
        assert validate_tool_name(tool_name) is True

    @pytest.mark.parametrize(
        "tool_name",
        [
            "",
            "; rm -rf /",
            "tool; evil",
            "../etc/passwd",
            "tool|pipe",
            "123tool",  # Starts with number
            "-tool",  # Starts with dash
        ],
    )
    def test_invalid_tool_names(self, tool_name):
        """Invalid tool names should fail."""
        assert validate_tool_name(tool_name) is False

    def test_tool_name_length_limit(self):
        """Tool names over 50 chars should fail."""
        long_name = "a" * 51
        assert validate_tool_name(long_name) is False


class TestCronValidation:
    """Test cron expression validation."""

    @pytest.mark.parametrize(
        "cron_expr",
        [
            "0 2 * * *",  # Daily at 2 AM
            "*/15 * * * *",  # Every 15 minutes
            "0 0 * * 0",  # Weekly on Sunday
            "0 0 1 * *",  # Monthly on 1st
            "30 4 1,15 * *",  # 1st and 15th at 4:30
            "0 0-6 * * *",  # Every hour 0-6
        ],
    )
    def test_valid_cron_expressions(self, cron_expr):
        """Valid cron expressions should pass."""
        assert validate_cron_expression(cron_expr) is True

    @pytest.mark.parametrize(
        "cron_expr",
        [
            "",
            "0 2 * * *; rm -rf /",  # Command injection
            "0 2 * * * | cat /etc/passwd",  # Pipe injection
            "0 2 * * * & echo pwned",  # Background injection
            "0 2 * * *$(whoami)",  # Command substitution
            "0 2 * * *`id`",  # Backtick substitution
            "0 2 * * *\nmalicious",  # Newline injection
            "not a cron",  # Invalid format
            "* * * *",  # Only 4 fields
        ],
    )
    def test_invalid_cron_expressions(self, cron_expr):
        """Invalid or malicious cron expressions should fail."""
        assert validate_cron_expression(cron_expr) is False


class TestURLValidation:
    """Test URL validation for DAST scanning."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com",
            "http://localhost:8080",
            "https://api.example.com/v1",
            "http://192.168.1.1:3000",
            "https://example.com/path?query=value",
        ],
    )
    def test_valid_urls(self, url):
        """Valid http/https URLs should pass."""
        assert validate_url(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "",
            "file:///etc/passwd",  # File protocol
            "javascript:alert(1)",  # JavaScript
            "data:text/html,<script>",  # Data URL
            "ftp://example.com",  # FTP
            "//example.com",  # Protocol-relative
            "not-a-url",  # Invalid format
            "example.com",  # Missing protocol
        ],
    )
    def test_invalid_urls(self, url):
        """Invalid or dangerous URLs should fail."""
        assert validate_url(url) is False


class TestContainerImageValidation:
    """Test container image reference validation."""

    @pytest.mark.parametrize(
        "image",
        [
            "nginx",
            "nginx:latest",
            "nginx:1.25.0",
            "ghcr.io/owner/repo:v1.0.0",
            "registry.k8s.io/kube-proxy:v1.28.0",
            "ubuntu@sha256:abcd1234" + "a" * 56,  # SHA256 digest
        ],
    )
    def test_valid_images(self, image):
        """Valid container image references should pass."""
        assert validate_container_image(image) is True

    @pytest.mark.parametrize(
        "image",
        [
            "",
            "; rm -rf /",  # Command injection
            "image | cat /etc/passwd",  # Pipe injection
            "image$(whoami)",  # Command substitution
            "image`id`",  # Backtick substitution
            "image&background",  # Background
            "image with spaces",  # Spaces
        ],
    )
    def test_invalid_images(self, image):
        """Invalid or malicious image references should fail."""
        assert validate_container_image(image) is False


class TestIntegerValidation:
    """Test integer range validation."""

    @pytest.mark.parametrize(
        "value",
        [1, 10, 100, 600, "100", "600"],
    )
    def test_valid_positive_int(self, value):
        """Valid positive integers should pass."""
        assert validate_positive_int(value, "test") is True

    @pytest.mark.parametrize(
        "value",
        [0, -1, -100, "0", "-1", "abc", "", None, 2**32],
    )
    def test_invalid_positive_int(self, value):
        """Invalid positive integers should fail."""
        assert validate_positive_int(value, "test") is False

    @pytest.mark.parametrize(
        "value",
        [0, 1, 10, 100, "0", "100"],
    )
    def test_valid_non_negative_int(self, value):
        """Valid non-negative integers should pass."""
        assert validate_non_negative_int(value, "test") is True

    @pytest.mark.parametrize(
        "value",
        [-1, -100, "-1", "abc", "", None],
    )
    def test_invalid_non_negative_int(self, value):
        """Invalid non-negative integers should fail."""
        assert validate_non_negative_int(value, "test") is False


class TestScheduleNameValidation:
    """Test schedule name validation for cron installation."""

    @pytest.mark.parametrize(
        "name",
        [
            "nightly-deep",
            "weekly_balanced",
            "daily",
            "scan1",
            "mySchedule",
            "a" * 64,  # Max length
        ],
    )
    def test_valid_schedule_names(self, name):
        """Valid schedule names should pass."""
        assert validate_schedule_name(name) is True

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "; rm -rf /",  # Command injection
            "name with spaces",
            "123numeric",  # Starts with number
            "-starts-dash",  # Starts with dash
            "a" * 65,  # Too long
            "name\ninjection",  # Newline
        ],
    )
    def test_invalid_schedule_names(self, name):
        """Invalid schedule names should fail."""
        assert validate_schedule_name(name) is False


class TestFuzzingValidation:
    """Fuzzing tests with malicious inputs."""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "; rm -rf /",
            "| cat /etc/passwd",
            "& echo pwned",
            "$(whoami)",
            "`id`",
            "${HOME}",
            "\x00null",
            "\r\ninjection",
        ],
    )
    def test_fuzz_path_validation_rejects_shell_injection(self, malicious_input):
        """Path validation should reject shell injection patterns."""
        assert validate_path_safe(malicious_input, "test") is False

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "../etc/passwd",
            "1.0.0?evil",
            "1.0.0#anchor",
            "1.0.0;rm",
            "1.0.0|cat",
            "1.0.0&bg",
            "1.0.0$var",
            "1.0.0`cmd`",
        ],
    )
    def test_fuzz_version_validation_rejects_injection(self, malicious_input):
        """Version validation should reject injection patterns."""
        assert validate_version(malicious_input, "test") is False

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "; rm -rf /",
            "| cat /etc/passwd",
            "../etc/passwd",
            "$(whoami)",
            "`id`",
        ],
    )
    def test_fuzz_schedule_name_rejects_injection(self, malicious_input):
        """Schedule name validation should reject injection patterns."""
        assert validate_schedule_name(malicious_input) is False

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<script>",
            "ftp://malicious.com",
        ],
    )
    def test_fuzz_url_validation_rejects_bad_protocols(self, malicious_input):
        """URL validation should reject dangerous protocols."""
        assert validate_url(malicious_input) is False

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "; rm -rf /",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "image with spaces",
        ],
    )
    def test_fuzz_container_image_rejects_injection(self, malicious_input):
        """Container image validation should reject injection patterns."""
        assert validate_container_image(malicious_input) is False


class TestSubprocessOutputSanitization:
    """Test subprocess output sanitization for information leakage prevention (Scenario S3)."""

    # =========================================================================
    # Home Directory Path Sanitization
    # =========================================================================

    @pytest.mark.parametrize(
        "input_val,expected",
        [
            # Unix home paths
            ("Error: /home/jimmy/project/file.py not found", "Error: /home/***USER***/project/file.py not found"),
            ("Failed at /home/alice/.config/tool", "Failed at /home/***USER***/.config/tool"),
            # macOS home paths
            ("/Users/developer/workspace/repo", "/Users/***USER***/workspace/repo"),
            ("/Users/john/Documents/secret.txt", "/Users/***USER***/Documents/secret.txt"),
            # Windows paths (backslash)
            (r"C:\Users\Jimmy\Projects\repo", r"C:\Users\***USER***\Projects\repo"),
            (r"Error in C:\Users\Developer\config", r"Error in C:\Users\***USER***\config"),
            # Windows paths (forward slash)
            ("C:/Users/Jimmy/Documents/file.txt", "C:/Users/***USER***/Documents/file.txt"),
        ],
    )
    def test_sanitize_home_paths(self, input_val, expected):
        """Home directory paths should be sanitized to hide usernames."""
        result = sanitize_subprocess_output(input_val, max_length=500)
        assert expected in result

    # =========================================================================
    # Token and Credential Sanitization
    # =========================================================================

    @pytest.mark.parametrize(
        "input_val,should_not_contain",
        [
            # GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
            ("Error: token ghp_abc123def456ghi789jkl012mno345pqr678st", "ghp_abc123"),
            ("Authorization: Bearer ghp_xyzabcdefghijklmnopqrstuvwx123456", "ghp_xyz"),
            # GitLab tokens
            ("clone with glpat-abcd1234efgh5678ijkl9012", "glpat-abcd1234"),
            # AWS keys
            ("Found key: AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
            # Generic tokens
            ("token=secretvalue12345", "secretvalue12345"),
            ("password: mysecretpassword", "mysecretpassword"),
            ("api_key: abcdefghijklmnopqrstuvwxyz123456789012", "abcdefghijklmnopqrstuvwxyz"),
        ],
    )
    def test_sanitize_tokens(self, input_val, should_not_contain):
        """Tokens and credentials should be redacted from output."""
        result = sanitize_subprocess_output(input_val)
        assert should_not_contain not in result
        assert "***" in result  # Should contain redaction marker

    @pytest.mark.parametrize(
        "input_val",
        [
            "token=abc123secret",
            "password: mysecret",
            "secret: confidential",
            "credential: hidden",
            "auth: bearertoken",
        ],
    )
    def test_sanitize_assignment_patterns(self, input_val):
        """Token/password assignment patterns should be sanitized."""
        result = sanitize_subprocess_output(input_val)
        assert "***REDACTED***" in result

    # =========================================================================
    # URL Credential Sanitization
    # =========================================================================

    @pytest.mark.parametrize(
        "input_val,expected",
        [
            # URL with credentials
            ("Failed to connect to https://user:password@api.example.com", "https://***:***@api.example.com"),
            ("git clone https://oauth2:glpat-secret@gitlab.com/repo.git failed", "https://***:***@gitlab.com/repo.git"),
            ("Error: http://admin:pass123@internal.service:8080", "http://***:***@internal.service:8080"),
        ],
    )
    def test_sanitize_url_credentials(self, input_val, expected):
        """URLs with credentials should have them redacted."""
        result = sanitize_subprocess_output(input_val, max_length=500)
        assert expected in result

    # =========================================================================
    # Bearer Token Sanitization
    # =========================================================================

    def test_sanitize_bearer_tokens(self):
        """Bearer authorization headers should be sanitized."""
        input_val = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
        result = sanitize_subprocess_output(input_val)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "Bearer ***REDACTED***" in result

    # =========================================================================
    # Private Key Sanitization
    # =========================================================================

    def test_sanitize_private_key_content(self):
        """SSH/PGP private key content should be fully redacted."""
        input_val = """Error reading key:
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnop
-----END RSA PRIVATE KEY-----
"""
        result = sanitize_subprocess_output(input_val)
        assert "MIIEpAIBAAK" not in result
        assert "***PRIVATE KEY REDACTED***" in result

    # =========================================================================
    # Output Truncation
    # =========================================================================

    def test_truncation(self):
        """Long output should be truncated to max_length."""
        long_output = "x" * 1000
        result = sanitize_subprocess_output(long_output, max_length=100)
        assert len(result) < 150  # Allow for truncation message
        assert "[truncated]" in result

    def test_custom_max_length(self):
        """Custom max_length should be respected."""
        output = "x" * 500
        result = sanitize_subprocess_output(output, max_length=200)
        assert "[truncated]" in result
        result_long = sanitize_subprocess_output(output, max_length=1000)
        assert "[truncated]" not in result_long

    # =========================================================================
    # Empty and Edge Case Handling
    # =========================================================================

    def test_empty_input(self):
        """Empty input should return empty string."""
        assert sanitize_subprocess_output("") == ""
        assert sanitize_subprocess_output(None) == ""  # type: ignore

    def test_safe_content_unchanged(self):
        """Safe content should pass through without modification."""
        safe_inputs = [
            "Command completed successfully",
            "Processing 100 files...",
            "Build finished in 5.2 seconds",
            "Downloaded 50 MB",
        ]
        for input_val in safe_inputs:
            result = sanitize_subprocess_output(input_val)
            assert result == input_val

    # =========================================================================
    # Multiple Patterns in Same Output
    # =========================================================================

    def test_multiple_patterns(self):
        """Multiple sensitive patterns in same output should all be sanitized."""
        input_val = (
            "Error: /home/jimmy/project failed with token=secret123 "
            "connecting to https://user:pass@api.com"
        )
        result = sanitize_subprocess_output(input_val, max_length=500)
        # All patterns should be sanitized
        assert "jimmy" not in result
        assert "secret123" not in result
        assert "user:pass" not in result


class TestSanitizeErrorMessage:
    """Test error message sanitization (shorter max_length)."""

    def test_error_message_shorter_length(self):
        """Error messages should have 200 char limit."""
        long_error = "x" * 300
        result = sanitize_error_message(long_error)
        assert len(result) < 250  # Allow for truncation message
        assert "[truncated]" in result

    def test_error_message_sanitizes_paths(self):
        """Error messages should sanitize home paths."""
        result = sanitize_error_message("pip failed: /home/user/.cache/pip error")
        assert "***USER***" in result


class TestSanitizeUrlForLogging:
    """Test URL sanitization for logging."""

    @pytest.mark.parametrize(
        "input_url,expected",
        [
            # Basic URL with credentials
            ("https://user:password@github.com/repo.git", "https://***:***@github.com/repo.git"),
            ("https://oauth2:glpat-xxx@gitlab.com/repo.git", "https://***:***@gitlab.com/repo.git"),
            ("http://admin:secret@localhost:8080/api", "http://***:***@localhost:8080/api"),
            # URL without credentials (unchanged)
            ("https://github.com/repo.git", "https://github.com/repo.git"),
            ("http://localhost:8080", "http://localhost:8080"),
        ],
    )
    def test_url_credential_sanitization(self, input_url, expected):
        """URLs should have credentials redacted."""
        result = sanitize_url_for_logging(input_url)
        assert result == expected

    def test_url_query_string_tokens(self):
        """Tokens in query strings should be redacted."""
        url = "https://api.example.com/data?token=secret123&other=value"
        result = sanitize_url_for_logging(url)
        assert "secret123" not in result
        assert "***REDACTED***" in result

    def test_empty_url(self):
        """Empty URL should return empty string."""
        assert sanitize_url_for_logging("") == ""


class TestOutputSanitizationPatterns:
    """Test the sanitization pattern definitions."""

    def test_patterns_list_not_empty(self):
        """Patterns list should contain sanitization rules."""
        assert len(OUTPUT_SANITIZATION_PATTERNS) > 0

    def test_patterns_have_correct_structure(self):
        """Each pattern should be a 3-tuple: (regex, replacement, flags)."""
        for pattern, replacement, flags in OUTPUT_SANITIZATION_PATTERNS:
            assert isinstance(pattern, str)
            assert isinstance(replacement, str)
            assert isinstance(flags, int)

    def test_all_patterns_compile(self):
        """All regex patterns should compile without error."""
        import re
        for pattern, replacement, flags in OUTPUT_SANITIZATION_PATTERNS:
            # This will raise if pattern is invalid
            re.compile(pattern, flags)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
