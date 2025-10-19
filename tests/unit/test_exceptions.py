"""
Unit tests for custom JMo Security exception classes.

Tests:
    - Exception hierarchy and inheritance
    - Exception attributes and messages
    - Exception creation and raising
    - Edge cases (long messages, special characters, etc.)

Related:
    - scripts/core/exceptions.py
    - ACTION_PLAN.md Task 3.3: Exception Handling Refactor
"""

import pytest
from pathlib import Path

from scripts.core.exceptions import (
    JmoSecurityException,
    ToolNotFoundException,
    AdapterParseException,
    FingerprintCollisionException,
    ComplianceMappingException,
    ConfigurationException,
    ToolExecutionException,
)


class TestJmoSecurityException:
    """Test the base exception class."""

    def test_is_exception(self):
        """Base exception inherits from Exception."""
        exc = JmoSecurityException("test message")
        assert isinstance(exc, Exception)

    def test_message(self):
        """Base exception stores message correctly."""
        msg = "test error message"
        exc = JmoSecurityException(msg)
        assert str(exc) == msg


class TestToolNotFoundException:
    """Test ToolNotFoundException for missing security tools."""

    def test_creates_with_tool_name(self):
        """Exception stores tool name."""
        exc = ToolNotFoundException("trivy")
        assert exc.tool == "trivy"
        assert "trivy" in str(exc)

    def test_inherits_from_base(self):
        """Exception inherits from JmoSecurityException."""
        exc = ToolNotFoundException("semgrep")
        assert isinstance(exc, JmoSecurityException)
        assert isinstance(exc, Exception)

    def test_message_format(self):
        """Exception message has expected format."""
        exc = ToolNotFoundException("bandit")
        assert str(exc) == "Security tool not found: bandit"

    def test_can_be_caught(self):
        """Exception can be raised and caught."""
        with pytest.raises(ToolNotFoundException) as exc_info:
            raise ToolNotFoundException("checkov")
        assert exc_info.value.tool == "checkov"


class TestAdapterParseException:
    """Test AdapterParseException for tool output parsing failures."""

    def test_creates_with_all_attributes(self):
        """Exception stores tool, path, and reason."""
        path = Path("/tmp/trivy.json")
        exc = AdapterParseException("trivy", path, "Invalid JSON")

        assert exc.tool == "trivy"
        assert exc.path == path
        assert exc.reason == "Invalid JSON"

    def test_message_includes_all_info(self):
        """Exception message includes tool, path, and reason."""
        path = Path("/results/semgrep.json")
        exc = AdapterParseException("semgrep", path, "Missing 'results' field")

        msg = str(exc)
        assert "semgrep" in msg
        assert str(path) in msg
        assert "Missing 'results' field" in msg

    def test_inherits_from_base(self):
        """Exception inherits from JmoSecurityException."""
        exc = AdapterParseException("tool", Path("/tmp/out.json"), "reason")
        assert isinstance(exc, JmoSecurityException)

    def test_can_chain_exceptions(self):
        """Exception can be raised from another exception."""
        try:
            raise ValueError("original error")
        except ValueError as e:
            exc = AdapterParseException("tool", Path("/tmp/test.json"), str(e))
            assert "original error" in exc.reason


class TestFingerprintCollisionException:
    """Test FingerprintCollisionException for duplicate fingerprints."""

    def test_creates_with_findings(self):
        """Exception stores fingerprint and both findings."""
        finding1 = {"ruleId": "G101", "location": {"path": "file1.py"}}
        finding2 = {"ruleId": "G102", "location": {"path": "file2.py"}}
        exc = FingerprintCollisionException("abc123", finding1, finding2)

        assert exc.fingerprint == "abc123"
        assert exc.finding1 == finding1
        assert exc.finding2 == finding2

    def test_message_includes_collision_details(self):
        """Exception message shows both findings and fingerprint."""
        finding1 = {"ruleId": "CWE-79", "location": {"path": "app.py", "startLine": 42}}
        finding2 = {"ruleId": "CWE-89", "location": {"path": "db.py", "startLine": 100}}
        exc = FingerprintCollisionException("collision123", finding1, finding2)

        msg = str(exc)
        assert "collision123" in msg
        assert "CWE-79" in msg
        assert "app.py" in msg
        assert "CWE-89" in msg
        assert "db.py" in msg

    def test_handles_missing_fields(self):
        """Exception handles findings with missing fields gracefully."""
        finding1 = {}  # No fields
        finding2 = {"ruleId": "TEST"}  # Partial fields
        exc = FingerprintCollisionException("fp", finding1, finding2)

        msg = str(exc)
        assert "fp" in msg
        assert "UNKNOWN" in msg  # Default for missing fields

    def test_inherits_from_base(self):
        """Exception inherits from JmoSecurityException."""
        exc = FingerprintCollisionException("fp", {}, {})
        assert isinstance(exc, JmoSecurityException)


class TestComplianceMappingException:
    """Test ComplianceMappingException for compliance framework mapping failures."""

    def test_creates_with_framework_and_cwe(self):
        """Exception stores framework, CWE, and reason."""
        exc = ComplianceMappingException("OWASP Top 10", "CWE-79", "Not in mapping data")

        assert exc.framework == "OWASP Top 10"
        assert exc.cwe == "CWE-79"
        assert exc.reason == "Not in mapping data"

    def test_message_format(self):
        """Exception message has expected format."""
        exc = ComplianceMappingException("CWE Top 25", "CWE-20", "Invalid data structure")

        msg = str(exc)
        assert msg == "Failed to map CWE-20 to CWE Top 25: Invalid data structure"

    def test_inherits_from_base(self):
        """Exception inherits from JmoSecurityException."""
        exc = ComplianceMappingException("PCI DSS", "CWE-89", "reason")
        assert isinstance(exc, JmoSecurityException)


class TestConfigurationException:
    """Test ConfigurationException for jmo.yml validation failures."""

    def test_creates_with_field_and_reason(self):
        """Exception stores field and reason."""
        exc = ConfigurationException("timeout", "must be non-negative")

        assert exc.field == "timeout"
        assert exc.reason == "must be non-negative"
        assert exc.path is None

    def test_creates_with_optional_path(self):
        """Exception stores optional configuration file path."""
        path = Path("/home/user/jmo.yml")
        exc = ConfigurationException("tools", "invalid tool name", path)

        assert exc.path == path
        assert str(path) in str(exc)

    def test_message_without_path(self):
        """Exception message format without path."""
        exc = ConfigurationException("threads", "must be positive integer")
        assert str(exc) == "Invalid configuration 'threads': must be positive integer"

    def test_message_with_path(self):
        """Exception message format includes path when provided."""
        path = Path("jmo.yml")
        exc = ConfigurationException("retries", "invalid value", path)

        msg = str(exc)
        assert "Invalid configuration 'retries'" in msg
        assert "invalid value" in msg
        assert "jmo.yml" in msg

    def test_inherits_from_base(self):
        """Exception inherits from JmoSecurityException."""
        exc = ConfigurationException("field", "reason")
        assert isinstance(exc, JmoSecurityException)


class TestToolExecutionException:
    """Test ToolExecutionException for tool execution failures."""

    def test_creates_with_required_attributes(self):
        """Exception stores tool, command, and return code."""
        cmd = ["trivy", "image", "nginx:latest"]
        exc = ToolExecutionException("trivy", cmd, 1)

        assert exc.tool == "trivy"
        assert exc.command == cmd
        assert exc.return_code == 1
        assert exc.stderr is None

    def test_creates_with_stderr(self):
        """Exception stores optional stderr output."""
        cmd = ["semgrep", "scan"]
        stderr = "Error: invalid config\nStack trace..."
        exc = ToolExecutionException("semgrep", cmd, 2, stderr)

        assert exc.stderr == stderr

    def test_message_without_stderr(self):
        """Exception message format without stderr."""
        exc = ToolExecutionException("bandit", ["bandit", "-r", "src/"], 1)

        msg = str(exc)
        assert "bandit execution failed with exit code 1" in msg
        assert "bandit -r src/" in msg

    def test_message_with_stderr(self):
        """Exception message includes stderr preview."""
        stderr = "Fatal error in tool\nLine 2\nLine 3"
        exc = ToolExecutionException("tool", ["tool", "--arg"], 127, stderr)

        msg = str(exc)
        assert "exit code 127" in msg
        assert "Stderr:" in msg
        assert "Fatal error in tool" in msg

    def test_truncates_long_stderr(self):
        """Exception truncates very long stderr output."""
        long_stderr = "X" * 1000
        exc = ToolExecutionException("tool", ["tool"], 1, long_stderr)

        msg = str(exc)
        assert len(msg) < len(long_stderr)  # Truncated
        assert "..." in msg  # Truncation indicator

    def test_inherits_from_base(self):
        """Exception inherits from JmoSecurityException."""
        exc = ToolExecutionException("tool", ["cmd"], 1)
        assert isinstance(exc, JmoSecurityException)


class TestExceptionHierarchy:
    """Test the overall exception hierarchy."""

    def test_all_inherit_from_base(self):
        """All custom exceptions inherit from JmoSecurityException."""
        exceptions = [
            ToolNotFoundException("tool"),
            AdapterParseException("tool", Path("/tmp/out.json"), "reason"),
            FingerprintCollisionException("fp", {}, {}),
            ComplianceMappingException("framework", "CWE-1", "reason"),
            ConfigurationException("field", "reason"),
            ToolExecutionException("tool", ["cmd"], 1),
        ]

        for exc in exceptions:
            assert isinstance(exc, JmoSecurityException)
            assert isinstance(exc, Exception)

    def test_can_catch_all_with_base(self):
        """JmoSecurityException can catch all custom exceptions."""
        with pytest.raises(JmoSecurityException):
            raise ToolNotFoundException("test")

        with pytest.raises(JmoSecurityException):
            raise AdapterParseException("test", Path("/tmp/test"), "reason")

        with pytest.raises(JmoSecurityException):
            raise ConfigurationException("field", "reason")

    def test_specific_catch_works(self):
        """Can catch specific exception types."""
        with pytest.raises(ToolNotFoundException) as exc_info:
            raise ToolNotFoundException("trivy")

        # Should not catch as different exception type
        with pytest.raises(ToolNotFoundException):
            try:
                raise ConfigurationException("field", "reason")
            except ToolNotFoundException:
                pytest.fail("Should not catch ConfigurationException")
            except ConfigurationException:
                raise ToolNotFoundException("tool")  # Re-raise different type
