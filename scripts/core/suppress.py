#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass, field
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)

try:
    import yaml
except ImportError as e:
    logger.debug(f"Suppression support unavailable: {e}")
    yaml = None  # type: ignore[assignment]  # Fallback when yaml not installed


@dataclass
class Suppression:
    id: str
    reason: str = ""
    expires: str | None = None  # ISO date or date object (YAML auto-parses dates)

    def is_active(self, now: dt.date | None = None) -> bool:
        """Check if suppression rule is currently active based on expiration date.

        Verifies that current date falls within the suppression's valid_until
        date (if specified). Expired suppressions are ignored.

        Args:
            now (dt.date | None): Current date for testing, or None for today

        Returns:
            bool: True if suppression is active, False if expired

        Example:
            >>> suppression = Suppression(id='fp-123', expires='2025-12-31')
            >>> suppression.is_active()
            True  # (if current date < 2025-12-31)
            >>> suppression.is_active(dt.date(2026, 1, 1))
            False  # (if checking future date > 2025-12-31)

        Note:
            If 'expires' not specified, suppression is always active.
            Date format: YYYY-MM-DD (ISO 8601).
            Invalid dates treated as never expires (returns True).

        """
        if not self.expires:
            return True
        try:
            # Handle both string and date object (YAML auto-parses dates like "2999-01-01")
            if isinstance(self.expires, dt.date):
                exp = self.expires
            elif isinstance(self.expires, str):
                exp = dt.date.fromisoformat(self.expires)
            else:
                # Unexpected type - treat as never expires
                logger.debug(
                    f"Unexpected expiration type '{type(self.expires)}': {self.expires}"
                )
                return True
        except (ValueError, TypeError) as e:
            # Invalid date format - treat as never expires
            logger.debug(f"Invalid expiration date '{self.expires}': {e}")
            return True
        today = now or dt.date.today()
        return today <= exp


@dataclass
class SuppressionSummary:
    """Summary of suppression activity for debt visibility.

    Tracks what was suppressed during filtering to provide insight into
    suppression debt - the accumulation of suppressed findings that may
    need periodic review.

    Attributes:
        total_suppressed: Number of findings that were suppressed
        total_before_suppression: Total findings before suppression applied
        by_severity: Count of suppressed findings by severity level
        by_rule: Count of suppressed findings by suppression rule ID
        suppressed_ids: List of finding IDs that were suppressed
    """

    total_suppressed: int = 0
    total_before_suppression: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_rule: dict[str, int] = field(default_factory=dict)
    suppressed_ids: list[str] = field(default_factory=list)

    @property
    def suppression_percentage(self) -> float:
        """Percentage of findings that were suppressed."""
        if self.total_before_suppression == 0:
            return 0.0
        return (self.total_suppressed / self.total_before_suppression) * 100

    @property
    def debt_label(self) -> str:
        """Human-readable suppression debt summary.

        e.g., 'Suppression debt: 15 findings (3 HIGH, 8 MEDIUM, 4 LOW)'
        """
        if self.total_suppressed == 0:
            return "Suppression debt: 0 findings"
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        severity_parts = [
            f"{count} {sev}"
            for sev, count in sorted(
                self.by_severity.items(),
                key=lambda x: (
                    severity_order.index(x[0]) if x[0] in severity_order else 99
                ),
            )
        ]
        severity_str = f" ({', '.join(severity_parts)})" if severity_parts else ""
        return f"Suppression debt: {self.total_suppressed} findings{severity_str}"

    def to_dict(self) -> dict:
        """Serialize for JSON storage."""
        return {
            "total_suppressed": self.total_suppressed,
            "total_before_suppression": self.total_before_suppression,
            "suppression_percentage": round(self.suppression_percentage, 1),
            "by_severity": self.by_severity,
            "by_rule": self.by_rule,
        }


def load_suppressions(path: str | None) -> dict[str, Suppression]:
    """Load suppressions from YAML file.

    Supports both 'suppressions' (recommended) and 'suppress' (backward compat) keys.

    Args:
        path: Path to suppression YAML file (e.g., jmo.suppress.yml)

    Returns:
        Dict mapping finding IDs to Suppression objects

    """
    if not path:
        return {}
    p = Path(path)
    if not p.exists() or yaml is None:
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    items = {}
    # Support both 'suppressions' (preferred) and 'suppress' (legacy)
    entries = data.get("suppressions", data.get("suppress", []))
    for ent in entries:
        sid = str(ent.get("id") or "").strip()
        if not sid:
            continue
        items[sid] = Suppression(
            id=sid, reason=str(ent.get("reason") or ""), expires=ent.get("expires")
        )
    return items


def filter_suppressed(
    findings: list[dict], suppressions: dict[str, Suppression]
) -> list[dict]:
    """Filter out suppressed findings based on suppression rules.

    Applies suppression rules from jmo.suppress.yml to findings list,
    removing active suppressed findings and returning only active findings.

    Args:
        findings (list[dict]): List of CommonFinding dictionaries
        suppressions (dict[str, Suppression]): Suppression rules keyed by finding ID

    Returns:
        list[dict]: Active (non-suppressed) findings

    Example:
        >>> findings = [{'id': 'fp-123', 'ruleId': 'G101', ...}, {'id': 'real-456', ...}]
        >>> suppressions = {'fp-123': Suppression(id='fp-123', reason='False positive')}
        >>> active = filter_suppressed(findings, suppressions)
        >>> print(len(active))
        1
        >>> print(active[0]['id'])
        real-456

    Note:
        Suppression matching based on exact fingerprint ID match.
        Only active suppressions (not expired) filter findings.
        Findings without IDs are never suppressed (always included).

    """
    out = []
    for f in findings:
        sid = f.get("id")
        if sid and isinstance(sid, str):
            sup = suppressions.get(sid)
            if sup and sup.is_active():
                continue
        out.append(f)
    return out


def filter_suppressed_with_summary(
    findings: list[dict], suppressions: dict[str, Suppression]
) -> tuple[list[dict], SuppressionSummary]:
    """Filter suppressed findings and return summary of what was suppressed.

    Like filter_suppressed() but also tracks suppression statistics for
    debt visibility. The filtering logic is identical - a finding is suppressed
    if its 'id' matches an active suppression rule.

    Args:
        findings (list[dict]): List of CommonFinding dictionaries
        suppressions (dict[str, Suppression]): Suppression rules keyed by finding ID

    Returns:
        tuple[list[dict], SuppressionSummary]: Active (non-suppressed) findings
            and summary of what was suppressed

    Example:
        >>> findings = [{'id': 'fp-123', 'severity': 'HIGH'}, {'id': 'real-456'}]
        >>> suppressions = {'fp-123': Suppression(id='fp-123', reason='False positive')}
        >>> active, summary = filter_suppressed_with_summary(findings, suppressions)
        >>> print(len(active))
        1
        >>> print(summary.total_suppressed)
        1
        >>> print(summary.debt_label)
        Suppression debt: 1 findings (1 HIGH)

    """
    summary = SuppressionSummary(total_before_suppression=len(findings))
    active = []

    for f in findings:
        sid = f.get("id")
        if sid and isinstance(sid, str):
            sup = suppressions.get(sid)
            if sup and sup.is_active():
                summary.total_suppressed += 1
                severity = f.get("severity", "UNKNOWN")
                summary.by_severity[severity] = summary.by_severity.get(severity, 0) + 1
                summary.by_rule[sup.id] = summary.by_rule.get(sup.id, 0) + 1
                if sid:
                    summary.suppressed_ids.append(sid)
                continue
        active.append(f)

    return active, summary
