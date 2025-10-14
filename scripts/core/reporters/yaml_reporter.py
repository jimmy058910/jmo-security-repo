#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml
except Exception:  # optional dependency
    yaml = None  # type: ignore[assignment]


def write_yaml(findings: List[Dict[str, Any]], out_path: str | Path) -> None:
    if yaml is None:
        raise RuntimeError("PyYAML not installed. Install with: pip install pyyaml")
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(findings, sort_keys=False), encoding="utf-8")
