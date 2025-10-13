#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


@dataclass
class Suppression:
    id: str
    reason: str = ""
    expires: Optional[str] = None  # ISO date

    def is_active(self, now: Optional[dt.date] = None) -> bool:
        if not self.expires:
            return True
        try:
            exp = dt.date.fromisoformat(self.expires)
        except Exception:
            return True
        today = now or dt.date.today()
        return today <= exp


def load_suppressions(path: Optional[str]) -> Dict[str, Suppression]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists() or yaml is None:
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    items = {}
    for ent in data.get("suppress", []):
        sid = str(ent.get("id") or "").strip()
        if not sid:
            continue
        items[sid] = Suppression(id=sid, reason=str(ent.get("reason") or ""), expires=ent.get("expires"))
    return items


def filter_suppressed(findings: List[dict], suppressions: Dict[str, Suppression]) -> List[dict]:
    out = []
    for f in findings:
        sid = f.get("id")
        sup = suppressions.get(sid)
        if sup and sup.is_active():
            continue
        out.append(f)
    return out
