#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

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
    expires: Optional[str] = None  # ISO date or date object (YAML auto-parses dates)

    def is_active(self, now: Optional[dt.date] = None) -> bool:
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


def load_suppressions(path: Optional[str]) -> Dict[str, Suppression]:
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
    findings: List[dict], suppressions: Dict[str, Suppression]
) -> List[dict]:
    out = []
    for f in findings:
        sid = f.get("id")
        if sid and isinstance(sid, str):
            sup = suppressions.get(sid)
            if sup and sup.is_active():
                continue
        out.append(f)
    return out
