"""
Utilities for scan jobs.

Centralized utility functions used by scan job modules.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess  # nosec B404: imported for controlled, vetted CLI invocations
import time
from pathlib import Path

# Module-level warning tracker for deduplication (Fix 1.3 - Issue #3)
_warned_tools: set[str] = set()


def clear_tool_warnings() -> None:
    """Clear warning tracker. Call at scan start to reset warning state."""
    global _warned_tools
    _warned_tools = set()


def _run_inline_tool_update(drift_list: list[dict]) -> bool:
    """Run tool updates inline during wizard flow.

    Args:
        drift_list: List of drift dicts with 'tool' key for tools to update

    Returns:
        True if updates succeeded, False otherwise
    """
    if not drift_list:
        return True

    try:
        from scripts.cli.tool_installer import ToolInstaller

        installer = ToolInstaller()

        tools_to_update = [d["tool"] for d in drift_list]
        total = len(tools_to_update)
        success_count = 0
        fail_count = 0

        for i, tool_name in enumerate(tools_to_update, 1):
            print(f"  [{i}/{total}] Updating {tool_name}...", end=" ", flush=True)
            result = installer.install_tool(tool_name, force=True)
            if result.success:
                print(f"OK ({result.version_installed or 'installed'})")
                success_count += 1
            else:
                print(f"FAILED ({result.message[:50]})")
                fail_count += 1

        print(f"\nUpdate complete: {success_count} succeeded, {fail_count} failed")
        return fail_count == 0

    except Exception as e:
        logging.getLogger(__name__).error(f"Update failed: {e}")
        return False


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
        import importlib.util

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


def check_version_drift_before_scan(
    profile: str,
    interactive: bool = False,
) -> bool:
    """
    Pre-scan version check with context-aware behavior.

    Checks for version drift between installed tool versions and the pinned
    versions in versions.yaml. Behavior adapts based on context:
    - CLI mode (interactive=False): Log warning, continue
    - Wizard mode (interactive=True): Prompt user before continuing

    Args:
        profile: Scan profile ('fast', 'slim', 'balanced', 'deep')
        interactive: Whether to prompt user for confirmation

    Returns:
        True if scan should proceed, False if user cancelled in interactive mode
    """
    # Import here to avoid circular dependency
    from scripts.cli.tool_manager import ToolManager

    logger = logging.getLogger(__name__)
    manager = ToolManager()
    drift = manager.get_version_drift(profile)

    if not drift:
        return True  # All versions match

    # Categorize drift by direction
    ahead = [d for d in drift if d.get("direction") == "ahead"]
    behind = [d for d in drift if d.get("direction") == "behind"]
    unknown = [d for d in drift if d.get("direction") == "unknown"]

    # Log categorized drift
    if ahead:
        logger.info(
            f"{len(ahead)} tool(s) AHEAD of expected (newer versions installed):"
        )
        for d in ahead:
            logger.info(f"  {d['tool']}: {d['installed']} > {d['expected']}")

    if behind:
        level = logging.WARNING
        critical_behind = [d for d in behind if d["critical"]]
        if critical_behind:
            level = logging.ERROR
        logger.log(
            level, f"{len(behind)} tool(s) BEHIND expected (update recommended):"
        )
        for d in behind:
            marker = " [CRITICAL]" if d["critical"] else ""
            logger.log(
                level, f"  {d['tool']}: {d['installed']} < {d['expected']}{marker}"
            )

    if unknown:
        logger.warning(f"{len(unknown)} tool(s) with unknown version status:")
        for d in unknown:
            marker = " [CRITICAL]" if d["critical"] else ""
            # Clarify what "unknown" means
            if d["installed"] is None:
                status = "version detection failed"
            else:
                status = f"installed={d['installed']}"
            logger.warning(f"  {d['tool']}: {status} expected={d['expected']}{marker}")

    if interactive:
        # Wizard mode - improved display with consolidated info
        print(f"\n{'─' * 50}")
        print(f"Version Status ({len(drift)} tool(s) with differences):")

        if ahead:
            print(f"\n  ✓ {len(ahead)} ahead (newer installed - OK for security):")
            for d in ahead[:3]:
                print(f"    {d['tool']}: {d['installed']} > {d['expected']}")
            if len(ahead) > 3:
                print(f"    ... and {len(ahead) - 3} more")

        if behind:
            print(f"\n  ⚠ {len(behind)} behind (older - update recommended):")
            for d in behind:
                marker = " [CRITICAL]" if d["critical"] else ""
                print(f"    {d['tool']}: {d['installed']} < {d['expected']}{marker}")

        if unknown:
            print(f"\n  ? {len(unknown)} unknown (version detection failed):")
            for d in unknown:
                # Explain what unknown means
                explanation = (
                    "binary found, but --version parsing failed"
                    if d["installed"] is None
                    else f"got {d['installed']}"
                )
                print(f"    {d['tool']}: {explanation}")

        print(f"\n{'─' * 50}")

        # Only prompt if there are concerning issues (behind or critical unknown)
        critical_behind = [d for d in behind if d["critical"]]
        if not behind and not critical_behind:
            # Just ahead or unknown (non-critical) - auto-continue
            print("No critical version issues. Continuing with scan...")
            return True

        print("\nThis may affect scan reproducibility.\n")
        print("Options:")
        print("  [1] Continue anyway (recommended if versions are close)")
        print("  [2] Update outdated tools first")
        print("  [3] Cancel scan")

        try:
            choice = input("\nChoice [1]: ").strip() or "1"
            if choice == "3":
                print("Scan cancelled.")
                return False
            if choice == "2":
                # Run update inline and continue
                print("\nUpdating tools...")
                updated = _run_inline_tool_update(behind + unknown)
                if updated:
                    print("\nTools updated. Continuing with scan...\n")
                    return True
                else:
                    print(
                        "\nUpdate failed or cancelled. Continuing with current versions..."
                    )
                    return True
            # Default: continue
            print("Continuing with current tool versions...")
            return True
        except (KeyboardInterrupt, EOFError):
            print("\nScan cancelled.")
            return False
    else:
        # CLI mode - warn and continue
        if behind:
            logger.warning("Run 'jmo tools update' to synchronize versions")
        return True


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


def run_cmd(
    cmd: list[str],
    timeout: int,
    retries: int = 0,
    capture_stdout: bool = False,
    ok_rcs: tuple[int, ...] | None = None,
) -> tuple[int, str, str, int]:
    """Run a command with timeout and optional retries.

    Args:
        cmd: Command and arguments as list
        timeout: Command timeout in seconds
        retries: Number of retry attempts (default: 0)
        capture_stdout: Whether to capture stdout (default: False)
        ok_rcs: Tuple of acceptable return codes (default: (0,))

    Returns:
        Tuple of (returncode, stdout, stderr, used_attempts)
        - stdout is empty when capture_stdout=False
        - used_attempts is how many tries were made
    """
    logger = logging.getLogger(__name__)
    attempts = max(0, retries) + 1
    used_attempts = 0
    last_exc: Exception | None = None
    rc = 1

    for i in range(attempts):
        used_attempts = i + 1
        try:
            cp = subprocess.run(  # nosec B603: executing fixed CLI tools, no shell, args vetted
                cmd,
                stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            rc = cp.returncode
            success = (rc == 0) if ok_rcs is None else (rc in ok_rcs)
            if success or i == attempts - 1:
                return (
                    rc,
                    (cp.stdout or "") if capture_stdout else "",
                    (cp.stderr or ""),
                    used_attempts,
                )
            time.sleep(min(1.0 * (i + 1), 3.0))
            continue
        except subprocess.TimeoutExpired as e:
            last_exc = e
            rc = 124
        except subprocess.CalledProcessError as e:
            # Command failed with non-zero exit code
            last_exc = e
            rc = e.returncode
            logger.debug(f"Command failed with exit code {e.returncode}: {e}")
        except (OSError, FileNotFoundError, PermissionError) as e:
            # System errors (command not found, permissions, etc.)
            last_exc = e
            rc = 1
            logger.error(f"Command execution error: {e}")
        except Exception as e:
            # Unexpected errors
            last_exc = e
            rc = 1
            logger.error(f"Unexpected command execution error: {e}", exc_info=True)

        if i < attempts - 1:
            time.sleep(min(1.0 * (i + 1), 3.0))
            continue

    return rc, "", str(last_exc or ""), used_attempts or 1
