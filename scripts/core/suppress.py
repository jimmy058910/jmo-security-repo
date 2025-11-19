#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)

try:
    import yaml
except ImportError as e:
    logger.debug(f"Suppression support unavailable: {e}")
    yaml = None  # type: ignore[assignment]


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
