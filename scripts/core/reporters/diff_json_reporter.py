"""JSON Reporter for Security Scan Diff Results.

Generates machine-readable JSON output comparing two security scans,
identifying new, resolved, and modified findings between baseline and current.

Output Format:
    - **DIFF.json**: Structured JSON with comprehensive diff metadata,
      statistics, and categorized findings (new/resolved/modified)

v1.0.0 Metadata Wrapper Schema:
    {
        "meta": {
            "diff_version": "1.0.0",
            "jmo_version": "1.0.0",
            "timestamp": "2025-11-05T10:30:00Z",
            "baseline": {
                "source_type": "directory",
                "path": "results-baseline/",
                "timestamp": "2025-11-01T10:00:00Z",
                "profile": "balanced",
                "total_findings": 42
            },
            "current": {
                "source_type": "directory",
                "path": "results-current/",
                "timestamp": "2025-11-05T10:00:00Z",
                "profile": "balanced",
                "total_findings": 38
            }
        },
        "statistics": {
            "total_new": 5,
            "total_resolved": 9,
            "total_modified": 3,
            "net_change": -4,
            "trend": "improving"
        },
        "new_findings": [...],
        "resolved_findings": [...],
        "modified_findings": [
            {
                "fingerprint": "abc123",
                "changes": {"severity": ["HIGH", "MEDIUM"]},
                "risk_delta": -1,
                "baseline": {...},
                "current": {...}
            }
        ]
    }

Usage:
    >>> from scripts.core.reporters.diff_json_reporter import write_json_diff
    >>> from scripts.core.diff_engine import DiffEngine
    >>>
    >>> # Run diff engine
    >>> engine = DiffEngine()
    >>> diff = engine.compare(baseline_findings, current_findings)
    >>>
    >>> # Generate JSON report
    >>> write_json_diff(diff, Path("results/summaries/DIFF.json"))

Functions:
    write_json_diff: Generate JSON diff report with v1.0.0 metadata wrapper

See Also:
    - scripts/core/diff_engine.py for DiffResult dataclass
    - diff_html_reporter.py for HTML visualization
    - diff_sarif_reporter.py for SARIF format (GitHub/GitLab integration)
"""

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
    out_path.write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
