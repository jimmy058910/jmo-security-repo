"""
Centralized input validation module for JMo Security.

This module provides security-focused validation helpers for:
- File paths (path traversal prevention)
- Tool names (valid scanner names only)
- Version strings (URL injection prevention)
- Profile names (valid profile validation)
- CLI arguments (general input sanitization)

Security Philosophy:
- Defense in depth: Multiple validation layers
- Fail-secure: Reject invalid input rather than sanitize
- Allowlist over blocklist: Validate against known-good patterns

Created as part of S2 Input Validation Sweep.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.core.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


# =============================================================================
# Version Validation
# =============================================================================

# Regex for validating version strings (security: prevent URL injection)
# Accepts: 1.0.0, v1.0.0, 1.0.0-rc1, 1.0.0+build123, 1.0.0-alpha.1
# Rejects: ../etc/passwd, 1.0.0?malicious, 1.0.0#anchor
VERSION_PATTERN = re.compile(
    r"^v?[0-9]+(\.[0-9]+)*(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?(\+[a-zA-Z0-9]+)?$"
)

# Characters that could enable URL/path injection in version strings
DANGEROUS_VERSION_CHARS = [
    "../",
    "..\\",
    "?",
    "#",
    "&",
    ";",
    "|",
    "$",
    "`",
    "\n",
    "\r",
    "\x00",
]


def validate_version(version: str, tool_name: str = "unknown") -> bool:
    """
    Validate version string format to prevent URL/path injection.

    Security: Version strings are interpolated into download URLs.
    Malicious versions like "../" could cause path traversal or URL injection.

    Args:
        version: Version string to validate
        tool_name: Tool name for error logging

    Returns:
        True if version is valid, False otherwise

    Examples:
        >>> validate_version("1.0.0", "trivy")
        True
        >>> validate_version("v1.2.3-rc1", "semgrep")
        True
        >>> validate_version("../etc/passwd", "malicious")
        False
        >>> validate_version("1.0.0?evil=true", "malicious")
        False
    """
    if not version:
        logger.error(f"Empty version string for tool {tool_name}")
        return False

    if not VERSION_PATTERN.match(version):
        logger.error(
            f"Invalid version format for {tool_name}: '{version}'. "
            f"Version must be semver-like (e.g., '1.0.0', 'v1.2.3-rc1')"
        )
        return False

    # Additional security checks for dangerous characters
    for char in DANGEROUS_VERSION_CHARS:
        if char in version:
            logger.error(
                f"Dangerous character '{char}' in version for {tool_name}: '{version}'"
            )
            return False

    return True


# =============================================================================
# Path Validation
# =============================================================================

# Characters that should never appear in path components
# Includes shell metacharacters to prevent command injection
DANGEROUS_PATH_CHARS = [
    "<",
    ">",
    "|",
    "?",
    "*",
    '"',  # Windows dangerous chars
    "\x00",
    "\n",
    "\r",  # Control characters
    ";",
    "&",
    "$",
    "`",
    "'",  # Shell metacharacters
    "(",
    ")",
    "{",
    "}",  # Shell grouping
]


def validate_path_safe(path: Path | str, context: str = "path") -> bool:
    """
    Validate that a path doesn't contain traversal sequences or dangerous characters.

    This is a DETECTION function - it returns False for dangerous paths
    rather than attempting to sanitize them.

    Args:
        path: Path to validate (Path or string)
        context: Description of path usage for logging

    Returns:
        True if path is safe, False if potentially dangerous

    Examples:
        >>> validate_path_safe(Path("/valid/path"), "repo")
        True
        >>> validate_path_safe("../../../etc/passwd", "user input")
        False
        >>> validate_path_safe("normal/path", "config")
        True
    """
    path_str = str(path)

    # Check for traversal sequences
    if ".." in path_str:
        logger.warning(f"Path traversal detected in {context}: '{path_str}'")
        return False

    # Check for null bytes (can bypass security checks)
    if "\x00" in path_str:
        logger.warning(f"Null byte in {context}: '{path_str}'")
        return False

    # Check for dangerous characters
    for char in DANGEROUS_PATH_CHARS:
        if char in path_str:
            logger.warning(f"Dangerous character '{char}' in {context}: '{path_str}'")
            return False

    return True


def validate_path_within_base(path: Path, base_dir: Path) -> bool:
    """
    Validate that a path is within the expected base directory.

    Security: Prevents path traversal attacks by ensuring resolved path
    stays within the allowed directory.

    Args:
        path: Path to validate
        base_dir: Base directory that path must be within

    Returns:
        True if path is within base_dir, False otherwise

    Examples:
        >>> validate_path_within_base(Path("/app/results/repo1"), Path("/app/results"))
        True
        >>> validate_path_within_base(Path("/app/results/../etc"), Path("/app/results"))
        False
    """
    try:
        resolved_path = path.resolve()
        resolved_base = base_dir.resolve()

        # Use is_relative_to (Python 3.9+) or try/except for older versions
        try:
            resolved_path.relative_to(resolved_base)
            return True
        except ValueError:
            logger.warning(
                f"Path '{path}' resolves outside base directory '{base_dir}'"
            )
            return False
    except (OSError, ValueError) as e:
        logger.warning(f"Path validation failed: {e}")
        return False


def sanitize_path_component(component: str) -> str:
    """
    Sanitize a single path component (filename or directory name).

    This removes or replaces dangerous characters to create a safe
    filename. Use this when you need to CREATE a path component from
    user input.

    Args:
        component: Raw path component to sanitize

    Returns:
        Sanitized component safe for use in paths

    Examples:
        >>> sanitize_path_component("normal-repo")
        'normal-repo'
        >>> sanitize_path_component("../../../etc/passwd")
        '______etc_passwd'
        >>> sanitize_path_component("nginx:latest")
        'nginx_latest'
    """
    if not component:
        return "unknown"

    result = component

    # Replace path separators
    result = result.replace("/", "_")
    result = result.replace("\\", "_")

    # Replace Windows dangerous characters
    for char in ["<", ">", ":", '"', "|", "?", "*"]:
        result = result.replace(char, "_")

    # Replace control characters
    result = re.sub(r"[\x00-\x1f\x7f]", "_", result)

    # Handle traversal sequences
    while ".." in result:
        result = result.replace("..", "_")

    # Strip leading dots (hidden files)
    while result.startswith("."):
        result = result[1:]

    # Fallback for empty result
    if not result or not result.strip():
        return "unknown"

    return result


# =============================================================================
# Profile Validation
# =============================================================================

# Valid scan profile names
VALID_PROFILES = frozenset(["fast", "slim", "balanced", "deep"])


def validate_profile(profile: str) -> bool:
    """
    Validate that profile name is a known scan profile.

    Args:
        profile: Profile name to validate

    Returns:
        True if profile is valid, False otherwise

    Examples:
        >>> validate_profile("balanced")
        True
        >>> validate_profile("fast")
        True
        >>> validate_profile("evil; rm -rf /")
        False
    """
    if not profile:
        logger.error("Empty profile name")
        return False

    if profile not in VALID_PROFILES:
        logger.error(
            f"Invalid profile: '{profile}'. Valid profiles: {', '.join(sorted(VALID_PROFILES))}"
        )
        return False

    return True


def get_valid_profiles() -> list[str]:
    """
    Get list of valid profile names.

    Returns:
        List of valid profile names
    """
    return sorted(VALID_PROFILES)


# =============================================================================
# Tool Name Validation
# =============================================================================

# Pattern for valid tool names (alphanumeric, hyphens, underscores, plus signs)
TOOL_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_+-]*$")


def validate_tool_name(tool_name: str, registry: ToolRegistry | None = None) -> bool:
    """
    Validate tool name format and optionally check against registry.

    Args:
        tool_name: Tool name to validate
        registry: Optional ToolRegistry to verify tool exists

    Returns:
        True if tool name is valid, False otherwise

    Examples:
        >>> validate_tool_name("trivy")
        True
        >>> validate_tool_name("afl++")
        True
        >>> validate_tool_name("; rm -rf /")
        False
    """
    if not tool_name:
        logger.error("Empty tool name")
        return False

    # Check format
    if not TOOL_NAME_PATTERN.match(tool_name):
        logger.error(
            f"Invalid tool name format: '{tool_name}'. "
            f"Tool names must start with a letter and contain only "
            f"alphanumeric characters, hyphens, underscores, or plus signs."
        )
        return False

    # Length check (reasonable bounds)
    if len(tool_name) > 50:
        logger.error(f"Tool name too long: '{tool_name}' ({len(tool_name)} chars)")
        return False

    # Check against registry if provided
    if registry is not None:
        if registry.get_tool(tool_name) is None:
            logger.warning(f"Unknown tool: '{tool_name}' (not in registry)")
            # This is a warning, not an error - allow unknown tools
            # but log for visibility

    return True


# =============================================================================
# Cron Expression Validation
# =============================================================================

# Pattern for cron schedule expressions
# Format: minute hour day-of-month month day-of-week
# Each field can be: number, *, range (1-5), step (*/5, 1-10/2), list (1,2,3)
# Pattern breakdown:
#   - \*(/[0-9]+)?           : * or */N (every N)
#   - [0-9]+(-[0-9]+)?(/[0-9]+)?  : number, or range, with optional step
CRON_FIELD_PATTERN = r"(\*(/[0-9]+)?|[0-9]+(-[0-9]+)?(/[0-9]+)?)(,(\*(/[0-9]+)?|[0-9]+(-[0-9]+)?(/[0-9]+)?))*"
CRON_SCHEDULE_PATTERN = re.compile(
    rf"^{CRON_FIELD_PATTERN}\s+{CRON_FIELD_PATTERN}\s+{CRON_FIELD_PATTERN}\s+"
    rf"{CRON_FIELD_PATTERN}\s+{CRON_FIELD_PATTERN}$"
)

# Characters that should never appear in cron expressions
DANGEROUS_CRON_CHARS = [";", "|", "&", "$", "`", "(", ")", "{", "}", "<", ">", "'", '"']


def validate_cron_expression(cron_expr: str) -> bool:
    """
    Validate cron schedule expression format.

    Security: Cron expressions are used in command construction.
    Validate format to prevent injection attacks.

    Args:
        cron_expr: Cron expression to validate (5 fields)

    Returns:
        True if expression is valid, False otherwise

    Examples:
        >>> validate_cron_expression("0 2 * * *")
        True
        >>> validate_cron_expression("*/15 * * * *")
        True
        >>> validate_cron_expression("0 2 * * *; rm -rf /")
        False
    """
    if not cron_expr:
        logger.error("Empty cron expression")
        return False

    # Check for dangerous characters
    for char in DANGEROUS_CRON_CHARS:
        if char in cron_expr:
            logger.error(
                f"Dangerous character '{char}' in cron expression: '{cron_expr}'"
            )
            return False

    # Check for command injection patterns
    if "\n" in cron_expr or "\r" in cron_expr:
        logger.error(f"Newline in cron expression: '{cron_expr}'")
        return False

    # Validate cron format
    if not CRON_SCHEDULE_PATTERN.match(cron_expr.strip()):
        logger.error(
            f"Invalid cron format: '{cron_expr}'. "
            f"Expected 5-field cron expression (e.g., '0 2 * * *')"
        )
        return False

    return True


# =============================================================================
# URL Validation
# =============================================================================

# Pattern for valid URLs (http/https only)
URL_PATTERN = re.compile(
    r"^https?://"  # http:// or https://
    r"[a-zA-Z0-9]"  # Domain starts with alphanumeric
    r"[a-zA-Z0-9\-\.]*"  # Domain body
    r"[a-zA-Z0-9]"  # Domain ends with alphanumeric
    r"(:\d{1,5})?"  # Optional port
    r"(/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?$"  # Path and query
)


def validate_url(url: str) -> bool:
    """
    Validate URL format for DAST scanning.

    Security: Only allow http/https URLs to prevent file:// or other
    protocol injection attacks.

    Args:
        url: URL to validate

    Returns:
        True if URL is valid http/https URL, False otherwise

    Examples:
        >>> validate_url("https://example.com")
        True
        >>> validate_url("http://localhost:8080/api")
        True
        >>> validate_url("file:///etc/passwd")
        False
        >>> validate_url("javascript:alert(1)")
        False
    """
    if not url:
        logger.error("Empty URL")
        return False

    # Must start with http:// or https://
    if not url.startswith("http://") and not url.startswith("https://"):
        logger.error(f"Invalid URL protocol: '{url}' (only http/https allowed)")
        return False

    # Check for dangerous injection patterns
    dangerous_patterns = ["javascript:", "data:", "file:", "ftp:", "\\n", "\\r"]
    for pattern in dangerous_patterns:
        if pattern.lower() in url.lower():
            logger.error(f"Dangerous pattern in URL: '{url}'")
            return False

    # Basic URL format validation
    if not URL_PATTERN.match(url):
        logger.error(f"Invalid URL format: '{url}'")
        return False

    return True


# =============================================================================
# Schedule Name Validation
# =============================================================================

# Pattern for valid schedule names
SCHEDULE_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,63}$")


def validate_schedule_name(name: str) -> bool:
    """
    Validate schedule name for cron installation.

    Security: Schedule names are used in cron comments and markers.
    Invalid characters could enable cron injection.

    Args:
        name: Schedule name to validate

    Returns:
        True if name is valid, False otherwise

    Examples:
        >>> validate_schedule_name("nightly-deep")
        True
        >>> validate_schedule_name("weekly_balanced")
        True
        >>> validate_schedule_name("evil; rm -rf /")
        False
    """
    if not name:
        logger.error("Empty schedule name")
        return False

    if not SCHEDULE_NAME_PATTERN.match(name):
        logger.error(
            f"Invalid schedule name: '{name}'. "
            f"Schedule names must start with a letter, be 1-64 characters, "
            f"and contain only alphanumeric characters, hyphens, or underscores."
        )
        return False

    return True


# =============================================================================
# Container Image Validation
# =============================================================================

# Pattern for valid container image references
# Format: [registry/][repository/]name[:tag][@digest]
IMAGE_NAME_PATTERN = re.compile(
    r"^"
    r"([a-zA-Z0-9][a-zA-Z0-9\-_.]*[a-zA-Z0-9]/)*"  # Optional registry/repo
    r"[a-zA-Z0-9][a-zA-Z0-9\-_.]*[a-zA-Z0-9]?"  # Image name
    r"(:[a-zA-Z0-9][a-zA-Z0-9\-_.]{0,127})?"  # Optional tag
    r"(@sha256:[a-fA-F0-9]{64})?$"  # Optional digest
)


def validate_container_image(image: str) -> bool:
    """
    Validate container image reference format.

    Args:
        image: Container image reference to validate

    Returns:
        True if image reference is valid, False otherwise

    Examples:
        >>> validate_container_image("nginx:latest")
        True
        >>> validate_container_image("ghcr.io/owner/repo:v1.2.3")
        True
        >>> validate_container_image("; rm -rf /")
        False
    """
    if not image:
        logger.error("Empty container image reference")
        return False

    # Check for dangerous characters
    dangerous_chars = [
        ";",
        "|",
        "&",
        "$",
        "`",
        "(",
        ")",
        "{",
        "}",
        "<",
        ">",
        "'",
        '"',
        " ",
    ]
    for char in dangerous_chars:
        if char in image:
            logger.error(f"Dangerous character '{char}' in image reference: '{image}'")
            return False

    # Length check
    if len(image) > 255:
        logger.error(f"Image reference too long: '{image}' ({len(image)} chars)")
        return False

    # Basic format validation
    if not IMAGE_NAME_PATTERN.match(image):
        logger.error(f"Invalid container image format: '{image}'")
        return False

    return True


# =============================================================================
# Integer Range Validation
# =============================================================================


def validate_positive_int(
    value: int | str, name: str, max_value: int = 2**31 - 1
) -> bool:
    """
    Validate positive integer value within bounds.

    Args:
        value: Value to validate (int or string representation)
        name: Parameter name for error messages
        max_value: Maximum allowed value (default: INT32_MAX)

    Returns:
        True if value is valid positive integer within bounds

    Examples:
        >>> validate_positive_int(600, "timeout")
        True
        >>> validate_positive_int(-1, "timeout")
        False
        >>> validate_positive_int(999999999999, "timeout")
        False
    """
    try:
        int_value = int(value)
    except (ValueError, TypeError):
        logger.error(f"Invalid integer for {name}: '{value}'")
        return False

    if int_value < 1:
        logger.error(f"{name} must be positive, got {int_value}")
        return False

    if int_value > max_value:
        logger.error(f"{name} too large: {int_value} (max: {max_value})")
        return False

    return True


def validate_non_negative_int(
    value: int | str, name: str, max_value: int = 2**31 - 1
) -> bool:
    """
    Validate non-negative integer value within bounds.

    Args:
        value: Value to validate
        name: Parameter name for error messages
        max_value: Maximum allowed value

    Returns:
        True if value is valid non-negative integer within bounds
    """
    try:
        int_value = int(value)
    except (ValueError, TypeError):
        logger.error(f"Invalid integer for {name}: '{value}'")
        return False

    if int_value < 0:
        logger.error(f"{name} must be non-negative, got {int_value}")
        return False

    if int_value > max_value:
        logger.error(f"{name} too large: {int_value} (max: {max_value})")
        return False

    return True


# =============================================================================
# Output Sanitization (Subprocess Output Security)
# =============================================================================

# Patterns to redact from subprocess output to prevent information leakage
# Each tuple is (regex_pattern, replacement, flags)
# ORDER MATTERS: More specific patterns should come before generic ones
OUTPUT_SANITIZATION_PATTERNS: list[tuple[str, str, int]] = [
    # SSH private key content indicators (RSA, DSA, EC, OPENSSH, etc.)
    # MUST come first - before generic "key:" pattern can break the header
    (
        r"-----BEGIN\s+(?:[A-Z]+\s+)*PRIVATE\s+KEY-----.*?-----END\s+(?:[A-Z]+\s+)*PRIVATE\s+KEY-----",
        "***PRIVATE KEY REDACTED***",
        re.DOTALL,
    ),
    # GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_) - specific patterns first
    (r"gh[pousr]_[a-zA-Z0-9]{36,}", "***GITHUB_TOKEN_REDACTED***", 0),
    # GitLab tokens (glpat-)
    (r"glpat-[a-zA-Z0-9\-_]{20,}", "***GITLAB_TOKEN_REDACTED***", 0),
    # AWS access key IDs
    (r"AKIA[0-9A-Z]{16}", "***AWS_KEY_REDACTED***", 0),
    # Bearer tokens in headers
    (r"Bearer\s+\S+", "Bearer ***REDACTED***", re.IGNORECASE),
    # Basic auth in URLs (user:pass@host)
    (r"(https?://)[^:]+:[^@]+@", r"\1***:***@", re.IGNORECASE),
    # API keys and tokens (common patterns: hex strings of specific lengths)
    (
        r"(['\"]?(?:api[_-]?key|access[_-]?token|secret[_-]?key)['\"]?\s*[:=]\s*['\"]?)[a-zA-Z0-9_\-]{20,}",
        r"\1***REDACTED***",
        re.IGNORECASE,
    ),
    # Tokens, keys, passwords, secrets with assignment (generic - comes after specific)
    # Only match when followed by value characters (not just whitespace/newline)
    (
        r"(token|password|secret|credential|auth)[=:]\s*\S+",
        r"\1=***REDACTED***",
        re.IGNORECASE,
    ),
    # Home directory paths on Unix (Linux/macOS)
    (r"/home/[^/\s:]+", "/home/***USER***", 0),
    (r"/Users/[^/\s:]+", "/Users/***USER***", 0),
    # Home directory paths on Windows
    (r"C:\\Users\\[^\\]+", r"C:\\Users\\***USER***", re.IGNORECASE),
    (r"C:/Users/[^/]+", "C:/Users/***USER***", re.IGNORECASE),
    # Windows user profile via environment variable patterns
    (r"%USERPROFILE%", "***USERPROFILE***", re.IGNORECASE),
    # Generic long hex strings that might be secrets (40+ chars)
    (
        r"(['\"]?(?:secret|token|key|password)['\"]?\s*[:=]\s*['\"]?)[a-fA-F0-9]{40,}",
        r"\1***REDACTED***",
        re.IGNORECASE,
    ),
]


def sanitize_subprocess_output(output: str, max_length: int = 500) -> str:
    """
    Sanitize subprocess output to remove sensitive information.

    This function redacts sensitive data from subprocess output before it's
    logged or included in error messages. It prevents information leakage of:
    - User home directory paths
    - Tokens, passwords, API keys
    - Authentication credentials
    - Private key content

    Security Note:
        This is a defense-in-depth measure. It should not be relied upon as
        the sole protection against credential exposure. Prefer not capturing
        sensitive data in the first place.

    Args:
        output: Raw subprocess output string (stdout or stderr)
        max_length: Maximum length of returned string (default: 500)

    Returns:
        Sanitized output with sensitive information redacted and truncated

    Examples:
        >>> sanitize_subprocess_output("Error: /home/jimmy/project/file.py not found")
        'Error: /home/***USER***/project/file.py not found'

        >>> sanitize_subprocess_output("token=ghp_abc123xyz")
        'token=***REDACTED***'

        >>> sanitize_subprocess_output("Failed to connect to https://user:pass@api.example.com")
        'Failed to connect to https://***:***@api.example.com'
    """
    if not output:
        return ""

    result = output

    # Apply all sanitization patterns
    for pattern, replacement, flags in OUTPUT_SANITIZATION_PATTERNS:
        try:
            result = re.sub(pattern, replacement, result, flags=flags)
        except re.error as e:
            # Log regex errors but continue with other patterns
            logger.debug(f"Regex error in sanitization pattern: {e}")
            continue

    # Truncate to max length
    if len(result) > max_length:
        result = result[:max_length] + "... [truncated]"

    return result


def sanitize_error_message(error_msg: str) -> str:
    """
    Sanitize an error message for safe logging or user display.

    Similar to sanitize_subprocess_output but specifically for error messages.
    Uses a shorter max length (200 chars) suitable for log messages.

    Args:
        error_msg: Error message to sanitize

    Returns:
        Sanitized error message

    Examples:
        >>> sanitize_error_message("pip install failed: /home/jimmy/.cache/pip error")
        'pip install failed: /home/***USER***/.cache/pip error'
    """
    return sanitize_subprocess_output(error_msg, max_length=200)


def sanitize_url_for_logging(url: str) -> str:
    """
    Sanitize a URL for safe logging, removing credentials.

    Specifically handles URL credential patterns more carefully than
    the general sanitization function.

    Args:
        url: URL that may contain credentials

    Returns:
        URL with credentials redacted

    Examples:
        >>> sanitize_url_for_logging("https://oauth2:glpat-xxx@gitlab.com/repo.git")
        'https://***:***@gitlab.com/repo.git'

        >>> sanitize_url_for_logging("https://user:password@github.com/repo.git")
        'https://***:***@github.com/repo.git'

        >>> sanitize_url_for_logging("https://github.com/repo.git")
        'https://github.com/repo.git'
    """
    if not url:
        return ""

    # Pattern for credentials in URL: protocol://user:pass@host
    result = re.sub(
        r"(https?://)[^:/@]+:[^@]+@", r"\1***:***@", url, flags=re.IGNORECASE
    )

    # Also catch token patterns in query strings
    result = re.sub(
        r"([?&](?:token|key|secret|password|auth)[=])[^&]+",
        r"\1***REDACTED***",
        result,
        flags=re.IGNORECASE,
    )

    return result
