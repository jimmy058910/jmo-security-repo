"""
Custom exceptions for JMo Security Suite.

This module defines domain-specific exceptions that improve error handling,
logging, and debugging throughout the codebase.

Usage:
    from scripts.core.exceptions import AdapterParseException

    try:
        data = json.loads(file.read_text())
    except json.JSONDecodeError as e:
        raise AdapterParseException("trivy", file, f"Invalid JSON: {e}") from e

Related:
    - Security Audit MEDIUM-005: Try-except-pass without logging
    - Code Quality HIGH-001: Reduce exception handling breadth
    - ACTION_PLAN.md Task 3.3: Exception Handling Refactor
"""

from pathlib import Path
from typing import Any, Dict, List, Optional


class JmoSecurityException(Exception):
    """Base exception for JMo Security Suite.

    All custom exceptions inherit from this class, making it easy to catch
    all JMo-specific errors while allowing standard library exceptions to
    propagate normally.
    """

    pass


class ToolNotFoundException(JmoSecurityException):
    """Raised when a required security tool is not installed or not found in PATH.

    Attributes:
        tool: Name of the missing tool (e.g., 'trivy', 'semgrep')

    Example:
        >>> if not shutil.which("trivy"):
        ...     raise ToolNotFoundException("trivy")
    """

    def __init__(self, tool: str):
        self.tool = tool
        super().__init__(f"Security tool not found: {tool}")


class AdapterParseException(JmoSecurityException):
    """Raised when a tool adapter fails to parse tool output.

    This exception is used when tool output exists but cannot be parsed due to:
    - Invalid JSON format
    - Missing required fields
    - Unexpected data structure
    - File corruption

    Attributes:
        tool: Name of the tool whose output failed to parse
        path: Path to the output file that failed
        reason: Human-readable explanation of the failure

    Example:
        >>> try:
        ...     data = json.loads(file.read_text())
        >>> except json.JSONDecodeError as e:
        ...     raise AdapterParseException("trivy", file, f"Invalid JSON: {e}") from e
    """

    def __init__(self, tool: str, path: Path, reason: str):
        self.tool = tool
        self.path = path
        self.reason = reason
        super().__init__(f"{tool} adapter failed to parse {path}: {reason}")


class FingerprintCollisionException(JmoSecurityException):
    """Raised when two different findings produce the same fingerprint ID.

    This indicates a critical bug in the fingerprinting algorithm that must
    be investigated immediately. Fingerprint collisions can cause findings
    to be incorrectly deduplicated.

    Attributes:
        fingerprint: The colliding fingerprint ID
        finding1: First finding with this fingerprint
        finding2: Second finding with this fingerprint

    Example:
        >>> if fingerprint in seen_ids:
        ...     raise FingerprintCollisionException(
        ...         fingerprint, seen_ids[fingerprint], current_finding
        ...     )
    """

    def __init__(
        self, fingerprint: str, finding1: Dict[str, Any], finding2: Dict[str, Any]
    ):
        self.fingerprint = fingerprint
        self.finding1 = finding1
        self.finding2 = finding2

        # Extract key info for error message
        rule1 = finding1.get("ruleId", "UNKNOWN")
        path1 = finding1.get("location", {}).get("path", "UNKNOWN")
        rule2 = finding2.get("ruleId", "UNKNOWN")
        path2 = finding2.get("location", {}).get("path", "UNKNOWN")

        super().__init__(
            f"Fingerprint collision detected: {fingerprint}\n"
            f"Finding 1: {rule1} at {path1}\n"
            f"Finding 2: {rule2} at {path2}"
        )


class ComplianceMappingException(JmoSecurityException):
    """Raised when compliance framework mapping fails.

    This exception occurs when:
    - CWE ID cannot be mapped to a compliance framework
    - Compliance data file is missing or corrupt
    - Mapping logic encounters unexpected data

    Attributes:
        framework: Compliance framework name (e.g., 'OWASP Top 10', 'CWE Top 25')
        cwe: CWE identifier that failed to map
        reason: Explanation of the mapping failure

    Example:
        >>> try:
        ...     mapping = compliance_data[cwe]
        ... except KeyError:
        ...     raise ComplianceMappingException("OWASP Top 10", cwe, "CWE not in mapping data")
    """

    def __init__(self, framework: str, cwe: str, reason: str):
        self.framework = framework
        self.cwe = cwe
        self.reason = reason
        super().__init__(f"Failed to map {cwe} to {framework}: {reason}")


class ConfigurationException(JmoSecurityException):
    """Raised when jmo.yml configuration validation fails.

    This exception is raised for:
    - Invalid YAML syntax
    - Missing required configuration fields
    - Invalid configuration values (e.g., negative timeout)
    - Schema validation failures

    Attributes:
        field: Configuration field that failed validation (e.g., 'tools', 'timeout')
        reason: Explanation of why validation failed
        path: Optional path to the configuration file

    Example:
        >>> if timeout < 0:
        ...     raise ConfigurationException("timeout", "must be non-negative")
    """

    def __init__(self, field: str, reason: str, path: Optional[Path] = None):
        self.field = field
        self.reason = reason
        self.path = path

        msg = f"Invalid configuration '{field}': {reason}"
        if path:
            msg += f" in {path}"
        super().__init__(msg)


class ToolExecutionException(JmoSecurityException):
    """Raised when a security tool execution fails unexpectedly.

    This exception is used when:
    - Tool exits with unexpected error code (not 0/1 for findings)
    - Tool times out
    - Tool crashes or is killed
    - Tool output cannot be written

    Attributes:
        tool: Name of the tool that failed
        command: Command that was executed
        return_code: Exit code from the tool
        stderr: Standard error output from the tool

    Example:
        >>> if result.returncode not in ok_rcs:
        ...     raise ToolExecutionException(
        ...         "trivy", cmd, result.returncode, result.stderr
        ...     )
    """

    def __init__(
        self,
        tool: str,
        command: List[str],
        return_code: int,
        stderr: Optional[str] = None,
    ):
        self.tool = tool
        self.command = command
        self.return_code = return_code
        self.stderr = stderr

        msg = f"{tool} execution failed with exit code {return_code}\nCommand: {' '.join(command)}"
        if stderr:
            # Truncate stderr to avoid massive error messages
            stderr_preview = stderr[:500] + "..." if len(stderr) > 500 else stderr
            msg += f"\nStderr: {stderr_preview}"

        super().__init__(msg)


__all__ = [
    "JmoSecurityException",
    "ToolNotFoundException",
    "AdapterParseException",
    "FingerprintCollisionException",
    "ComplianceMappingException",
    "ConfigurationException",
    "ToolExecutionException",
]
