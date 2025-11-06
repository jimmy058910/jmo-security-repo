"""JSON reporter for diff results with v1.0.0 metadata wrapper schema."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from scripts.core.diff_engine import DiffResult


def _get_jmo_version() -> str:
    """Get JMo Security version from pyproject.toml."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    project_root = Path(__file__).parent.parent.parent.parent
    pyproject_path = project_root / "pyproject.toml"

    if pyproject_path.exists():
        with open(pyproject_path, "rb") as f:
            pyproject = tomllib.load(f)
            return pyproject.get("project", {}).get("version", "1.0.0")  # type: ignore[no-any-return]

    return "1.0.0"


def write_json_diff(diff: DiffResult, out_path: Path) -> None:
    """
    Write diff result to JSON file with v1.0.0 metadata wrapper schema.

    Args:
        diff: DiffResult object from DiffEngine
        out_path: Output file path for JSON

    Schema:
        {
          "meta": {
            "diff_version": "1.0.0",
            "jmo_version": "1.0.0",
            "timestamp": "2025-11-05T10:30:00Z",
            "baseline": {...},
            "current": {...}
          },
          "statistics": {...},
          "new_findings": [...],
          "resolved_findings": [...],
          "modified_findings": [...]
        }
    """
    output: Dict[str, Any] = {
        "meta": {
            "diff_version": "1.0.0",
            "jmo_version": _get_jmo_version(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "baseline": {
                "source_type": diff.baseline_source.source_type,
                "path": diff.baseline_source.path,
                "timestamp": diff.baseline_source.timestamp,
                "profile": diff.baseline_source.profile,
                "total_findings": diff.baseline_source.total_findings,
            },
            "current": {
                "source_type": diff.current_source.source_type,
                "path": diff.current_source.path,
                "timestamp": diff.current_source.timestamp,
                "profile": diff.current_source.profile,
                "total_findings": diff.current_source.total_findings,
            },
        },
        "statistics": diff.statistics,
        "new_findings": diff.new,
        "resolved_findings": diff.resolved,
        "modified_findings": [
            {
                "fingerprint": m.fingerprint,
                "changes": m.changes,
                "risk_delta": m.risk_delta,
                "baseline": m.baseline,
                "current": m.current,
            }
            for m in diff.modified
        ],
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n")
