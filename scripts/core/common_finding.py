#!/usr/bin/env python3
"""
CommonFinding helpers: severity mapping and fingerprinting.
"""

from __future__ import annotations

import hashlib
from enum import Enum

# Fingerprinting constants
FINGERPRINT_LENGTH = 16  # Hex chars for stable, readable IDs
MESSAGE_SNIPPET_LENGTH = 120  # Chars to include in fingerprint calculation


class Severity(str, Enum):
    """Security finding severity levels (ordered by criticality).

    Inherits from str for JSON serialization compatibility and comparisons.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_string(cls, value: str | None) -> "Severity":
        """Parse severity from string with fallback to INFO.

        Args:
            value: Raw severity string from tool output

        Returns:
            Severity enum member (defaults to INFO if unknown)
        """
        if not value:
            return cls.INFO

        v = str(value).strip().upper()

        # Try direct match
        try:
            return cls(v)
        except ValueError:
            pass

        # Map common variants
        mapping = {
            "ERROR": cls.HIGH,
            "WARN": cls.MEDIUM,
            "WARNING": cls.MEDIUM,
            "CRIT": cls.CRITICAL,
            "MED": cls.MEDIUM,
        }
        return mapping.get(v, cls.INFO)

    def __lt__(self, other: object) -> bool:
        """Enable severity comparisons: CRITICAL > HIGH > MEDIUM > LOW > INFO."""
        if not isinstance(other, Severity):
            return NotImplemented
        order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        return self < other or self == other

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return not self <= other

    def __ge__(self, other: object) -> bool:
        return self > other or self == other


# Backward compatibility: expose severity order as list of strings
SEVERITY_ORDER = [s.value for s in Severity]


def normalize_severity(value: str | None) -> str:
    """Normalize severity string to standard levels.

    Returns string value of Severity enum for backward compatibility with existing code.

    Args:
        value: Raw severity string from tool output

    Returns:
        Normalized severity string: CRITICAL, HIGH, MEDIUM, LOW, or INFO
    """
    return Severity.from_string(value).value


def fingerprint(
    tool: str,
    rule_id: str | None,
    path: str | None,
    start_line: int | None,
    message: str | None,
) -> str:
    """Generate stable fingerprint ID for deduplication.

    Uses SHA256 hash of: tool|ruleId|path|line|message_snippet
    Truncated to FINGERPRINT_LENGTH hex chars for readability.

    Args:
        tool: Tool name (e.g., "gitleaks", "semgrep")
        rule_id: Rule or vulnerability ID
        path: File path where finding occurred
        start_line: Line number (0 if not applicable)
        message: Finding message or description

    Returns:
        Hex string of length FINGERPRINT_LENGTH for stable deduplication
    """
    snippet = (message or "").strip()[:MESSAGE_SNIPPET_LENGTH]
    base = f"{tool}|{rule_id or ''}|{path or ''}|{start_line or 0}|{snippet}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:FINGERPRINT_LENGTH]
