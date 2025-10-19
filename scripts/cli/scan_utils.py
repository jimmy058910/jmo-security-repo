"""
Utilities for scan jobs.

Centralized utility functions used by scan job modules.
"""

import json
import shutil
from pathlib import Path


def tool_exists(cmd: str) -> bool:
    """Check if a command exists in PATH."""
    return shutil.which(cmd) is not None


def write_stub(tool: str, out_path: Path) -> None:
    """Write empty JSON stub for missing tool."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stubs = {
        "gitleaks": [],
        "trufflehog": [],
        "semgrep": {"results": []},
        "noseyparker": {"matches": []},
        "syft": {"artifacts": []},
        "trivy": {"Results": []},
        "hadolint": [],
        "checkov": {"results": {"failed_checks": []}},
        "tfsec": {"results": []},
        "bandit": {"results": []},
        "osv-scanner": {"results": []},
        "zap": {"site": []},
        "falco": [],
        "afl++": {"crashes": []},
    }
    payload = stubs.get(tool, {})
    out_path.write_text(json.dumps(payload), encoding="utf-8")
