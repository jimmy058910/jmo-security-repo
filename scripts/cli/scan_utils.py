"""
Utilities for scan jobs.

Centralized utility functions used by scan job modules.
"""

import json
import shutil
import logging
from pathlib import Path


def tool_exists(tool_name: str) -> bool:
    """
    Check if a command exists in PATH.

    This function checks whether the given command exist or not. If the command exist it will return true,
    else it will return false.

    Params:
    - tool_name (str): It will contain the tool name as the input.

    Returns:
    - bool: If the tool is present then it will return true, else it will return false.
    """

    logger = logging.getLogger(__name__)

    tool_path = shutil.which(tool_name)

    if tool_path:
        return True

    TOOL_INSTALL_HINTS = {
        "trufflehog": "Install: brew install trufflehog (macOS) or see https://github.com/trufflesecurity/trufflehog#installation",
        "semgrep": "Install: pip install semgrep or see https://semgrep.dev/docs/getting-started/",
        "trivy": "Install: brew install trivy (macOS) or see https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
        "syft": "Install: brew install syft (macOS) or see https://github.com/anchore/syft#installation",
        "checkov": "Install: pip install checkov or see https://www.checkov.io/2.Basics/Installing%20Checkov.html",
        "hadolint": "Install: brew install hadolint (macOS) or see https://github.com/hadolint/hadolint#install",
        "nuclei": "Install: brew install nuclei (macOS) or see https://docs.projectdiscovery.io/tools/nuclei/install",
        "bandit": "Install: pip install bandit",
        "noseyparker": "Install: Docker image ghcr.io/praetorian-inc/noseyparker:latest",
        "zap": "Install: Docker image ghcr.io/zaproxy/zaproxy:stable",
        "falco": "Install: See https://falco.org/docs/install-operate/installation/",
        "afl++": "Install: brew install afl++ (macOS) or see https://aflplus.plus/#building-and-installing-afl",
    }

    hint = TOOL_INSTALL_HINTS.get(tool_name, f"Install {tool_name}")
    logger.error(f"Tool '{tool_name}' not found. {hint}")
    return False


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
        "nuclei": "",  # NDJSON format - empty string for empty file
        "falco": [],
        "afl++": {"crashes": []},
    }
    payload = stubs.get(tool, {})
    if isinstance(payload, str):
        # For NDJSON tools like nuclei, write empty string
        out_path.write_text(payload, encoding="utf-8")
    else:
        # For JSON tools, write JSON-encoded stub
        out_path.write_text(json.dumps(payload), encoding="utf-8")
