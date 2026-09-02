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
import sys
from pathlib import Path

from scripts.core.paths import get_isolated_tool_path

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


def _is_windows() -> bool:
    """Whether to prefer Windows launcher extensions.

    A function rather than `os.name == "nt"` inline so tests can exercise both
    branches on one host. Monkeypatching `os.name` itself is not an option:
    `pathlib` reads it to choose its flavour, so setting it to "posix" on
    Windows makes `Path()` raise
    `NotImplementedError: cannot instantiate 'PosixPath' on your system`.
    """
    return os.name == "nt"


def _platform_launcher(directory: Path, stem: str) -> Path | None:
    """Return the launcher for `stem` that this platform can actually execute.

    The Java-based tools ship a POSIX `.sh` and a Windows `.bat` **side by side
    in the same directory** (`zap.sh`/`zap.bat`,
    `dependency-check.sh`/`dependency-check.bat`). Picking by name alone gets
    the wrong one half the time.

    Handing Windows the `.sh` does not fail as "not found". `subprocess` raises

        [WinError 193] %1 is not a valid Win32 application

    which reads like a corrupt download rather than the wrong file - which is
    why dependency-check's failure was not obvious from its message.

    On Windows a missing `.bat` returns None rather than falling back to the
    `.sh`. `unresolved` is an accounted state the reconciler understands; a
    launcher the platform cannot execute is a run-time failure that, before
    this branch, `--allow-missing-tools` laundered into a recorded success.
    """
    suffixes = (".bat", ".cmd", ".exe") if _is_windows() else (".sh", "")
    for suffix in suffixes:
        candidate = directory / f"{stem}{suffix}"
        if candidate.is_file():
            return candidate
    return None


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
    # JMo-managed isolated venvs win over everything, PATH included (#1101).
    #
    # Delegate rather than reimplement. This function used to carry a narrower
    # private copy that looked only for `bin/{tool}` and `Scripts/{tool}.exe`.
    # checkov ships setuptools-style scripts, so its venv holds `checkov` and
    # `checkov.cmd` but no `checkov.exe`: the copy returned None while
    # `get_isolated_tool_path` -- which also tries `.cmd`, no-extension and
    # alternate name forms -- found it. So `jmo tools check` printed
    # "checkov OK 3.3.8" while the scanner resolved None and dropped checkov
    # from every scan. Measured: 0 IaC findings on a repo with 47 .tf files.
    #
    # And it has to come FIRST. `tool_manager._find_binary` checks the isolated
    # venv before PATH; this resolver checked it third, after `shutil.which`
    # and the interpreter's Scripts/, so with a stale user-site semgrep 1.161.0
    # on PATH `tools check` said OK 1.172.0 (the venv) while the scanner ran
    # 1.161.0. Two resolvers for one question is the same defect as the four
    # private copies of `_can_encode_unicode` (see
    # tests/cross_platform/test_encoding_drift_guard.py). One implementation,
    # one order.
    isolated = get_isolated_tool_path(tool_name)
    if isolated is not None:
        return str(isolated)

    # Then standard PATH
    path = shutil.which(tool_name)
    if path:
        return path

    # Then the interpreter's own script directory.
    #
    # `jmo tools install` runs pip against `sys.executable`, so a pip-backed tool
    # lands next to the running interpreter -- `.venv/Scripts/bandit.exe` when
    # invoked as `.venv/Scripts/python.exe -m scripts.cli.jmo`. That directory is
    # only on PATH if the venv was *activated*, and `jmo` is routinely run by
    # absolute path (make targets, CI, scheduled tasks) where it is not.
    #
    # Measured: `jmo tools install bandit prowler` reported [OK], the executables
    # existed in `.venv/Scripts/`, and `jmo tools check` still said MISSING -- so
    # a tool JMo had just installed itself was invisible to its own scanner.
    scripts_dir = Path(sys.executable).parent
    for candidate in (
        scripts_dir / tool_name,
        scripts_dir / f"{tool_name}.exe",
    ):
        if candidate.is_file():
            return str(candidate)

    # Check JMo special installation paths
    home = Path.home()
    jmo_bin = home / ".jmo" / "bin"

    # ZAP baseline script is inside the extracted ZAP directory
    if tool_name == "zap-baseline.py":
        zap_baseline = jmo_bin / "zap" / "zap-baseline.py"
        if zap_baseline.exists():
            return str(zap_baseline)

    # ZAP main launcher. The name is spelled "zap.sh" at every call site, but
    # that is the POSIX launcher's filename, not the tool's identity - Windows
    # needs zap.bat from the same directory.
    if tool_name in ("zap.sh", "zap.bat"):
        zap_launcher = _platform_launcher(jmo_bin / "zap", "zap")
        if zap_launcher is not None:
            return str(zap_launcher)

    # dependency-check launcher, same shape as zap.
    if tool_name in ("dependency-check", "dependency-check.sh", "dependency-check.bat"):
        dc_launcher = _platform_launcher(
            jmo_bin / "dependency-check" / "bin", "dependency-check"
        )
        if dc_launcher is not None:
            return str(dc_launcher)

    # Lynis is cloned to ~/.jmo/bin/lynis/
    if tool_name == "lynis":
        lynis_path = jmo_bin / "lynis" / "lynis"
        if lynis_path.exists():
            return str(lynis_path)

    # yara ships as libyara bindings (the yara-python wheel), not as a CLI: the
    # installed artifact is a compiled extension exposing compile()/match(),
    # with no main() and no console script. JMo drives it through
    # scripts/core/yara_runner.py, so the executable that runs yara *is* this
    # interpreter - the same shape tool_manager's version probe already uses
    # (`[sys.executable, "-c", "import yara; ..."]`).
    #
    # This used to return the pseudo-path "python:yara", which broke the
    # contract three lines of docstring above ("Full path to the tool binary").
    # Being truthy, it passed pre-flight; landing at command[0], it raised
    # FileNotFoundError; and the scanner then matched the resulting "Tool not
    # found" string and, under --allow-missing-tools, wrote a stub and recorded
    # yara as having run clean. Measured: yara.json existed after a scan with
    # HOME and PATH stripped, where yara could not possibly have run.
    #
    # Falls through rather than returning None, so a genuine native yara binary
    # under ~/.jmo/bin is still found by the generic checks below.
    if tool_name == "yara" and importlib.util.find_spec("yara") is not None:
        return sys.executable

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
