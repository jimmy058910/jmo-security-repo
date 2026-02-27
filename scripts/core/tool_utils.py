"""
Core utility functions for finding security tools.

Provides tool discovery across PATH and JMo-specific installation paths.
Extracted from scripts/cli/scan_utils.py to maintain clean dependency layering
(core never imports from cli).
"""

from __future__ import annotations

import importlib.util
import logging
import os
import shutil
from pathlib import Path

# Module-level warning tracker for deduplication (Fix 1.3 - Issue #3)
_warned_tools: set[str] = set()

# Installation hints for supported security tools
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


def clear_tool_warnings() -> None:
    """Clear warning tracker. Call at scan start to reset warning state."""
    global _warned_tools
    _warned_tools = set()


def find_tool(tool_name: str) -> str | None:
    """
    Find a security tool in PATH or JMo special installation paths.

    Checks both standard PATH locations and JMo-specific installation paths
    like ~/.jmo/bin/ for tools installed via 'jmo tools install'.

    Args:
        tool_name: Name of the security tool to find (e.g., 'trivy', 'zap-baseline.py')

    Returns:
        Full path to the tool binary if found, None otherwise
    """
    # First check standard PATH
    path = shutil.which(tool_name)
    if path:
        return path

    # Check JMo special installation paths
    home = Path.home()
    jmo_bin = home / ".jmo" / "bin"

    # Check isolated venv paths first (prowler, checkov, semgrep, bandit, scancode, etc.)
    # These are installed at ~/.jmo/tools/venvs/{tool}/bin/{tool}
    venvs_dir = home / ".jmo" / "tools" / "venvs" / tool_name
    if venvs_dir.exists():
        # Linux/macOS: bin/{tool}
        venv_bin = venvs_dir / "bin" / tool_name
        if venv_bin.exists():
            return str(venv_bin)
        # Windows: Scripts/{tool}.exe
        venv_scripts = venvs_dir / "Scripts" / f"{tool_name}.exe"
        if venv_scripts.exists():
            return str(venv_scripts)

    # ZAP baseline script is inside the extracted ZAP directory
    if tool_name == "zap-baseline.py":
        zap_baseline = jmo_bin / "zap" / "zap-baseline.py"
        if zap_baseline.exists():
            return str(zap_baseline)

    # ZAP main launcher
    if tool_name == "zap.sh":
        zap_sh = jmo_bin / "zap" / "zap.sh"
        if zap_sh.exists():
            return str(zap_sh)

    # dependency-check shell script
    if tool_name in ("dependency-check", "dependency-check.sh"):
        dc_path = jmo_bin / "dependency-check" / "bin" / "dependency-check.sh"
        if dc_path.exists():
            return str(dc_path)

    # Lynis is cloned to ~/.jmo/bin/lynis/
    if tool_name == "lynis":
        lynis_path = jmo_bin / "lynis" / "lynis"
        if lynis_path.exists():
            return str(lynis_path)

    # Yara is a Python module, not a binary - check via importlib
    if tool_name == "yara":
        spec = importlib.util.find_spec("yara")
        if spec is not None:
            # Return a pseudo-path indicating the module is available
            return "python:yara"

    # Generic check for tools in ~/.jmo/bin/{tool}/
    tool_in_subdir = jmo_bin / tool_name / tool_name
    if tool_in_subdir.exists():
        return str(tool_in_subdir)

    # Direct binary in ~/.jmo/bin/
    direct_binary = jmo_bin / tool_name
    if direct_binary.exists() and direct_binary.is_file():
        return str(direct_binary)

    # Windows: Check for .exe extension (tools like hadolint.exe, kubescape.exe)
    if os.name == "nt":
        exe_binary = jmo_bin / f"{tool_name}.exe"
        if exe_binary.exists() and exe_binary.is_file():
            return str(exe_binary)

    return None


def tool_exists(tool_name: str, warn: bool = True) -> bool:
    """
    Check if a security tool exists in PATH or JMo installation paths.

    Logs an error with installation hints if the tool is not found.
    Uses deduplication to avoid duplicate warnings (Fix 1.3 - Issue #3).

    Args:
        tool_name: Name of the security tool to check (e.g., 'trivy', 'semgrep')
        warn: Whether to show warning if not found (default: True)

    Returns:
        True if tool is found, False otherwise
    """
    if find_tool(tool_name):
        return True

    # Tool not found - show warning with deduplication
    if warn:
        global _warned_tools
        if tool_name not in _warned_tools:
            _warned_tools.add(tool_name)
            logger = logging.getLogger(__name__)
            hint = TOOL_INSTALL_HINTS.get(tool_name, f"Install {tool_name}")
            logger.error(f"Tool '{tool_name}' not found. {hint}")

    return False
