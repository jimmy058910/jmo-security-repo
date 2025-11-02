"""
Utilities for scan jobs.

Centralized utility functions used by scan job modules.
"""

import json
import logging
import shutil
import subprocess  # nosec B404: imported for controlled, vetted CLI invocations
import time
from pathlib import Path

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


def tool_exists(tool_name: str) -> bool:
    """
    Check if a security tool exists in PATH.

    Logs an error with installation hints if the tool is not found.

    Args:
        tool_name: Name of the security tool to check (e.g., 'trivy', 'semgrep')

    Returns:
        True if tool is found in PATH, False otherwise
    """
    if not shutil.which(tool_name):
        logger = logging.getLogger(__name__)
        hint = TOOL_INSTALL_HINTS.get(tool_name, f"Install {tool_name}")
        logger.error(f"Tool '{tool_name}' not found. {hint}")
        return False
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
