"""
Tool Manager for JMo Security.

Handles tool detection, version checking, and status reporting
across all supported platforms. This is the core logic for the
`jmo tools` command and wizard pre-flight checks.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from scripts.core.tool_registry import (
    PROFILE_TOOLS,
    TOOL_EXECUTION_COMMANDS,
    TOOL_VARIANTS,
    TOOL_VERSION_REQUIREMENTS,
    ToolRegistry,
    detect_platform,
    get_install_hint,
)

logger = logging.getLogger(__name__)

# Version extraction patterns for different tools
VERSION_PATTERNS: dict[str, re.Pattern] = {
    # Standard semver pattern - used as fallback
    "default": re.compile(r"v?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)"),
    # Tool-specific patterns (order matters - more specific patterns first)
    "trivy": re.compile(r"Version:\s*v?(\d+\.\d+\.\d+)"),
    "grype": re.compile(r"Version:\s*v?(\d+\.\d+\.\d+)"),
    "syft": re.compile(r"Version:\s*v?(\d+\.\d+\.\d+)"),
    "nuclei": re.compile(r"Version:\s*v?(\d+\.\d+\.\d+)"),
    "kubescape": re.compile(r"version is:\s*v?(\d+\.\d+\.\d+)", re.IGNORECASE),
    "trufflehog": re.compile(r"trufflehog\s+v?(\d+\.\d+\.\d+)"),
    "bearer": re.compile(r"Version:\s*v?(\d+\.\d+\.\d+)"),
    "horusec": re.compile(r"Version:\s*v?(\d+\.\d+\.\d+)"),
    # shellcheck outputs: "ShellCheck - ...\nversion: 0.10.0\n..."
    # Match "version: X.Y.Z" or just plain "X.Y.Z" on a line
    "shellcheck": re.compile(r"(?:version:?\s*)?(\d+\.\d+\.\d+)", re.IGNORECASE),
    "gosec": re.compile(r"Version:\s*v?(\d+\.\d+\.\d+)"),
    "hadolint": re.compile(r"Haskell Dockerfile Linter\s+v?(\d+\.\d+\.\d+)"),
    # checkov outputs "checkov X.Y.Z" - make pattern more specific to avoid matching warnings
    "checkov": re.compile(r"(?:checkov\s+)?(\d+\.\d+\.\d+)", re.IGNORECASE),
    "prowler": re.compile(r"Prowler\s+(\d+\.\d+\.\d+)"),
    # ZAP -version outputs: "Found Java version 17.0.17\n...\n2.16.1"
    # Must NOT match Java version - use negative lookbehinds:
    # - (?<!version ) - not preceded by "version " (excludes "Java version 17.0.17")
    # - (?<!\d) - not preceded by digit (prevents matching "7.0.17" substring of "17.0.17")
    # Also matches "OWASP ZAP 2.16.1" or standalone "2.16.1" on its own line
    "zap": re.compile(
        r"(?<!version )(?<!\d)(?:(?:OWASP\s+)?(?:ZAP|Zed Attack Proxy)\s+)?v?(\d+\.\d+\.\d+)",
        re.IGNORECASE,
    ),
    # dependency-check outputs: "Dependency-Check Core version X.Y.Z"
    # or "dependency-check version: X.Y.Z" or just "version X.Y.Z"
    "dependency-check": re.compile(
        r"(?:dependency.?check\s+)?(?:core\s+)?version:?\s*(\d+\.\d+\.\d+)",
        re.IGNORECASE,
    ),
    "noseyparker": re.compile(r"noseyparker\s+(\d+\.\d+\.\d+)"),
    "cdxgen": re.compile(r"(\d+\.\d+\.\d+)"),
    # lynis outputs "Lynis X.Y.Z" - make pattern more specific to avoid matching other text
    "lynis": re.compile(r"(?:Lynis\s+)?(\d+\.\d+\.\d+)", re.IGNORECASE),
    # yara-python outputs just the version number (e.g., "4.5.4")
    # Removed ^ anchor which doesn't work with multiline output
    "yara": re.compile(r"v?(\d+\.\d+\.\d+)"),
    "opa": re.compile(r"Version:\s*v?(\d+\.\d+\.\d+)"),
    "falcoctl": re.compile(r"(\d+\.\d+\.\d+)"),
    "osv-scanner": re.compile(r"osv-scanner version:\s*v?(\d+\.\d+\.\d+)"),
}

# Version commands for tools that don't use --version
# Type can be:
#   - list[str]: Universal command (works on all platforms)
#   - dict[str, list[str]]: Platform-specific commands with keys "windows", "linux", "macos", "default"
VERSION_COMMANDS: dict[str, list[str] | dict[str, list[str]]] = {
    # Tools using 'version' subcommand (no dashes)
    "grype": ["grype", "version"],
    "syft": ["syft", "version"],
    "kubescape": ["kubescape", "version"],
    "bearer": ["bearer", "version"],
    "horusec": ["horusec", "version"],
    "opa": ["opa", "version"],
    "falcoctl": ["falcoctl", "version"],
    # Tools using single dash -version
    "nuclei": ["nuclei", "-version"],
    # ZAP: Platform-specific (zap.sh on Unix, zap.bat on Windows)
    "zap": {
        "windows": ["zap.bat", "-version"],
        "default": ["zap.sh", "-version"],
    },
    # Tools using special commands
    # Dependency-check: Platform-specific (.sh on Unix, .bat on Windows)
    "dependency-check": {
        "windows": ["dependency-check.bat", "--version"],
        "default": ["dependency-check.sh", "--version"],
    },
    "lynis": ["lynis", "show", "version"],
    # yara-python is a Python library, not a CLI - check via Python import
    # The native 'yara' CLI is a separate package from yara-python
    "yara": [sys.executable, "-c", "import yara; print(yara.YARA_VERSION)"],
    "cdxgen": ["cdxgen", "--version"],
    "osv-scanner": ["osv-scanner", "--version"],
}

# Tools that need longer timeout for version check (e.g., Java-based tools)
# Default timeout is 10 seconds, these get extended
VERSION_TIMEOUTS: dict[str, int] = {
    "zap": 30,  # ZAP is Java-based, needs JVM startup time
    "dependency-check": 30,  # Java-based
    "mobsf": 30,  # Heavyweight
}

# Remediation commands for tools with issues
# Each entry is a dict with:
#   - "install": command to install the tool
#   - "deps": list of system dependencies and their install commands
#   - "manual": manual instructions if auto-install not possible
REMEDIATION_COMMANDS: dict[str, dict] = {
    "zap": {
        "install": {
            # ZAP is not in Ubuntu repos - use jmo tools install which downloads from GitHub
            "linux": "jmo tools install zap",
            "macos": "brew install --cask owasp-zap",
            "windows": "choco install zap -y",
        },
        "deps": {
            "java": {
                "linux": "sudo apt install openjdk-17-jre -y",
                "macos": "brew install openjdk@17",
                "windows": "choco install openjdk17 -y",
            }
        },
        "jmo_install": "jmo tools install zap",
    },
    "cdxgen": {
        "install": {
            "linux": "sudo npm install -g @cyclonedx/cdxgen",
            "macos": "npm install -g @cyclonedx/cdxgen",
            "windows": "npm install -g @cyclonedx/cdxgen",
        },
        "deps": {
            "node20": {
                "linux": "curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs",
                "macos": "brew install node@20 && brew link --overwrite node@20",
                "windows": "choco install nodejs-lts -y",
                "nvm": "nvm install 20 && nvm use 20 && nvm alias default 20",
            }
        },
        "jmo_install": "jmo tools install cdxgen",
    },
    "dependency-check": {
        "install": {
            "linux": "jmo tools install dependency-check",
            "macos": "jmo tools install dependency-check",
            "windows": "jmo tools install dependency-check",
        },
        "deps": {
            "java": {
                "linux": "sudo apt install openjdk-17-jre -y",
                "macos": "brew install openjdk@17",
                "windows": "choco install openjdk17 -y",
            }
        },
        "jmo_install": "jmo tools install dependency-check",
    },
    "shellcheck": {
        "install": {
            "linux": "sudo apt install shellcheck -y",
            "macos": "brew install shellcheck",
            "windows": "choco install shellcheck -y",
        },
        "jmo_install": "jmo tools install shellcheck",
    },
    "prowler": {
        "install": {
            "linux": "pip install prowler",
            "macos": "pip install prowler",
            "windows": "pip install prowler",
        },
        "jmo_install": "jmo tools install prowler",
    },
    "kubescape": {
        "install": {
            "linux": "curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash",
            "macos": "brew install kubescape",
            "windows": "iwr -useb https://raw.githubusercontent.com/kubescape/kubescape/master/install.ps1 | iex",
        },
        "jmo_install": "jmo tools install kubescape",
    },
    "trivy": {
        "install": {
            "linux": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
            "macos": "brew install trivy",
            "windows": "choco install trivy -y",
        },
        "jmo_install": "jmo tools install trivy",
    },
    "semgrep": {
        "install": {
            "linux": "pip install semgrep",
            "macos": "brew install semgrep",
            "windows": "pip install semgrep",
        },
        "jmo_install": "jmo tools install semgrep",
    },
    "trufflehog": {
        "install": {
            "linux": "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
            "macos": "brew install trufflehog",
            "windows": "choco install trufflehog -y",
        },
        "jmo_install": "jmo tools install trufflehog",
    },
    "grype": {
        "install": {
            "linux": "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
            "macos": "brew install grype",
            "windows": "choco install grype -y",
        },
        "jmo_install": "jmo tools install grype",
    },
    "syft": {
        "install": {
            "linux": "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
            "macos": "brew install syft",
            "windows": "choco install syft -y",
        },
        "jmo_install": "jmo tools install syft",
    },
    "checkov": {
        "install": {
            "linux": "pip install checkov",
            "macos": "pip install checkov",
            "windows": "pip install checkov",
        },
        "jmo_install": "jmo tools install checkov",
    },
    "hadolint": {
        "install": {
            "linux": "wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && chmod +x /usr/local/bin/hadolint",
            "macos": "brew install hadolint",
            "windows": "choco install hadolint -y",
        },
        "jmo_install": "jmo tools install hadolint",
    },
    "nuclei": {
        "install": {
            "linux": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "macos": "brew install nuclei",
            "windows": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        },
        "jmo_install": "jmo tools install nuclei",
    },
    "bearer": {
        "install": {
            "linux": "curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh",
            "macos": "brew install bearer/tap/bearer",
            "windows": "iwr -useb https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.ps1 | iex",
        },
        "jmo_install": "jmo tools install bearer",
    },
    "horusec": {
        "install": {
            "linux": "curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/main/deployments/scripts/install.sh | bash -s latest",
            "macos": "brew install horusec/tap/horusec",
            "windows": "iwr -useb https://raw.githubusercontent.com/ZupIT/horusec/main/deployments/scripts/install.ps1 | iex",
        },
        "jmo_install": "jmo tools install horusec",
    },
    "gosec": {
        "install": {
            "linux": "go install github.com/securego/gosec/v2/cmd/gosec@latest",
            "macos": "brew install gosec",
            "windows": "go install github.com/securego/gosec/v2/cmd/gosec@latest",
        },
        "jmo_install": "jmo tools install gosec",
    },
    "scancode": {
        "install": {
            "linux": "pip install scancode-toolkit",
            "macos": "pip install scancode-toolkit",
            "windows": "pip install scancode-toolkit",
        },
        "deps": {
            "build": {
                "linux": "sudo apt install build-essential pkg-config libicu-dev -y",
                "macos": "xcode-select --install",
                "windows": None,  # Not needed on Windows
            }
        },
        "jmo_install": "jmo tools install scancode",
    },
    "bandit": {
        "install": {
            "linux": "pip install bandit",
            "macos": "pip install bandit",
            "windows": "pip install bandit",
        },
        "jmo_install": "jmo tools install bandit",
    },
    "noseyparker": {
        "install": {
            "linux": "cargo install noseyparker",
            "macos": "brew install noseyparker",
            "windows": "cargo install noseyparker",
        },
        "jmo_install": "jmo tools install noseyparker",
    },
    "yara": {
        "install": {
            "linux": "pip install yara-python",
            "macos": "pip install yara-python",
            "windows": "pip install yara-python",
        },
        "jmo_install": "jmo tools install yara",
    },
    "lynis": {
        "install": {
            "linux": "sudo apt install lynis -y",
            "macos": "brew install lynis",
            "windows": None,  # Not available on Windows
        },
        "jmo_install": "jmo tools install lynis",
    },
}

# Tools that require manual installation on specific platforms
# These tools cannot be auto-installed due to platform limitations or upstream bugs.
# The wizard will skip these tools and display helpful guidance instead of failing.
#
# Key: tool_name
# Value: dict of platform -> (reason, documentation_url)
PLATFORM_MANUAL_TOOLS: dict[str, dict[str, tuple[str, str]]] = {
    "prowler": {
        "windows": (
            "Requires Windows Long Path Support (registry change + reboot)",
            "docs/MANUAL_INSTALLATION.md#prowler-windows",
        ),
    },
    "lynis": {
        "windows": (
            "Shell script requires bash (use WSL or Git Bash)",
            "docs/MANUAL_INSTALLATION.md#lynis-windows",
        ),
    },
    "noseyparker": {
        "windows": (
            "No Windows binaries available (Rust tool, Linux/macOS only)",
            "https://github.com/praetorian-inc/noseyparker",
        ),
    },
    "bearer": {
        "windows": (
            "No Windows binaries available (use Docker or WSL)",
            "https://github.com/Bearer/bearer",
        ),
    },
}


def get_remediation_for_tool(
    tool_name: str,
    platform: str = "linux",
    issue_type: str = "install",
) -> dict:
    """
    Get remediation commands for a tool issue.

    Args:
        tool_name: Name of the tool
        platform: Target platform (linux, macos, windows)
        issue_type: Type of issue (install, deps, version)

    Returns:
        Dict with:
        - 'commands': list of commands to run
        - 'manual': manual instructions (deprecated, use manual_reason)
        - 'jmo_install': jmo tools install command
        - 'is_manual': True if this tool requires manual installation on this platform
        - 'manual_reason': Why manual installation is required
        - 'manual_url': URL/path to documentation for manual installation
    """
    commands: list[str] = []
    manual: str | None = None
    jmo_install: str | None = None

    # Check if this tool requires manual installation on this platform
    # These tools have known platform-specific issues that can't be auto-fixed
    if tool_name in PLATFORM_MANUAL_TOOLS:
        platform_manual = PLATFORM_MANUAL_TOOLS[tool_name].get(platform)
        if platform_manual:
            reason, url = platform_manual
            return {
                "commands": [],
                "manual": reason,  # For backwards compatibility
                "jmo_install": None,
                "is_manual": True,
                "manual_reason": reason,
                "manual_url": url,
            }

    remediation = REMEDIATION_COMMANDS.get(tool_name)
    if not remediation:
        # Fall back to jmo tools install for unknown tools
        commands = [f"jmo tools install {tool_name}"]
        jmo_install = f"jmo tools install {tool_name}"
        return {
            "commands": commands,
            "manual": manual,
            "jmo_install": jmo_install,
            "is_manual": False,
            "manual_reason": None,
            "manual_url": None,
        }

    # Get jmo install command
    jmo_install = remediation.get("jmo_install")

    # Check if dependencies are needed first
    if "deps" in remediation:
        for dep_name, dep_commands in remediation["deps"].items():
            if isinstance(dep_commands, dict):
                cmd = dep_commands.get(platform)
                if cmd:
                    commands.append(cmd)

    # Get install command for platform
    if "install" in remediation:
        install_cmds = remediation["install"]
        if isinstance(install_cmds, dict):
            cmd = install_cmds.get(platform)
            if cmd:
                commands.append(cmd)
        elif isinstance(install_cmds, str):
            commands.append(install_cmds)

    # Add manual instructions if no commands available
    if not commands:
        manual = remediation.get("manual", f"See JMo docs for {tool_name} installation")

    return {
        "commands": commands,
        "manual": manual,
        "jmo_install": jmo_install,
        "is_manual": False,
        "manual_reason": None,
        "manual_url": None,
    }


@dataclass
class ToolStatus:
    """Status of a single tool with execution readiness (Fix 1.4)."""

    name: str
    installed: bool
    installed_version: str | None = None
    expected_version: str | None = None
    is_outdated: bool = False
    is_critical: bool = False
    install_hint: str = ""
    binary_path: str | None = None
    is_variant: bool = False  # True if this is a variant (e.g., semgrep-secrets)
    execution_ready: bool = True  # Tool can actually execute (not just binary exists)
    execution_warning: str | None = None  # Warning if not execution_ready
    missing_deps: list[str] | None = None  # Missing dependencies for execution

    def __post_init__(self) -> None:
        """Initialize mutable defaults."""
        if self.missing_deps is None:
            self.missing_deps = []

    @property
    def status_icon(self) -> str:
        """Get status icon for display."""
        if not self.installed:
            return "X"
        if not self.execution_ready:
            return "!"  # Installed but can't execute
        if self.is_outdated:
            return "!"
        return "OK"

    @property
    def status_text(self) -> str:
        """Get status text for display."""
        if not self.installed:
            return "MISSING"
        if not self.execution_ready:
            return "NOT READY"
        if self.is_outdated:
            return "OUTDATED"
        return "OK"


class ToolManager:
    """Manage security tool installations."""

    def __init__(self, registry: ToolRegistry | None = None):
        """
        Initialize tool manager.

        Args:
            registry: ToolRegistry instance. If None, creates default.
        """
        self._registry = registry
        self.platform = detect_platform()

    @property
    def registry(self) -> ToolRegistry:
        """Lazy-load registry on first access."""
        if self._registry is None:
            self._registry = ToolRegistry()
        return self._registry

    def check_tool(self, tool_name: str) -> ToolStatus:
        """
        Check status of a single tool including execution readiness (Fix 1.4).

        Args:
            tool_name: Name of the tool (e.g., 'trivy', 'semgrep')

        Returns:
            ToolStatus with installation and execution information
        """
        tool_info = self.registry.get_tool(tool_name)

        # Handle variants - they share a binary with base tool
        is_variant = tool_name in TOOL_VARIANTS
        binary_name = tool_info.get_binary_name() if tool_info else tool_name

        # Check if installed
        binary_path = self._find_binary(binary_name)
        installed = binary_path is not None

        # Get installed version if found
        # For variants (e.g., semgrep-secrets), use base tool name for version lookup
        # since VERSION_COMMANDS only has entries for base tools
        installed_version = None
        if binary_path:
            base_tool = TOOL_VARIANTS.get(tool_name, tool_name)
            installed_version = self._get_tool_version(base_tool, binary_path)

        # Determine if outdated
        expected_version = tool_info.version if tool_info else None
        is_outdated = False
        if installed and installed_version and expected_version:
            is_outdated = self._is_version_outdated(installed_version, expected_version)

        # Build install hint
        install_hint = ""
        if tool_info:
            install_hint = get_install_hint(tool_info, self.platform)
        else:
            install_hint = f"See JMo documentation for {tool_name}"

        # Check execution readiness (Fix 1.4 - Issue #4)
        execution_ready = True
        execution_warning = None
        missing_deps: list[str] = []

        if installed:
            execution_ready, execution_warning, missing_deps = self._verify_execution(
                tool_name
            )
        else:
            execution_ready = False
            execution_warning = "Tool binary not found"

        return ToolStatus(
            name=tool_name,
            installed=installed,
            installed_version=installed_version,
            expected_version=expected_version,
            is_outdated=is_outdated,
            is_critical=tool_info.critical if tool_info else False,
            install_hint=install_hint,
            binary_path=binary_path,
            is_variant=is_variant,
            execution_ready=execution_ready,
            execution_warning=execution_warning,
            missing_deps=missing_deps,
        )

    def check_profile(self, profile: str) -> dict[str, ToolStatus]:
        """
        Check all tools for a profile.

        Args:
            profile: Profile name ('fast', 'slim', 'balanced', 'deep')

        Returns:
            Dict mapping tool name to ToolStatus
        """
        tools = PROFILE_TOOLS.get(profile, [])
        return {name: self.check_tool(name) for name in tools}

    def check_all_tools(self) -> dict[str, ToolStatus]:
        """Check status of all registered tools."""
        return {
            tool.name: self.check_tool(tool.name)
            for tool in self.registry.get_all_tools()
        }

    def get_missing_tools(self, profile: str) -> list[ToolStatus]:
        """
        Get list of missing tools for a profile.

        Args:
            profile: Profile name

        Returns:
            List of ToolStatus for missing tools
        """
        statuses = self.check_profile(profile)
        return [s for s in statuses.values() if not s.installed]

    def get_outdated_tools(self, profile: str | None = None) -> list[ToolStatus]:
        """
        Get list of outdated tools.

        Args:
            profile: Optional profile to filter by

        Returns:
            List of ToolStatus for outdated tools
        """
        if profile:
            statuses = self.check_profile(profile)
        else:
            statuses = self.check_all_tools()
        return [s for s in statuses.values() if s.installed and s.is_outdated]

    def get_critical_outdated(self) -> list[ToolStatus]:
        """Get outdated tools marked as critical."""
        outdated = self.get_outdated_tools()
        return [s for s in outdated if s.is_critical]

    def get_profile_summary(self, profile: str) -> dict:
        """
        Get summary statistics for a profile (Fix 1.4).

        Args:
            profile: Profile name

        Returns:
            Dict with total, installed, execution_ready, missing, outdated counts
        """
        statuses = self.check_profile(profile)
        installed = [s for s in statuses.values() if s.installed]
        execution_ready = [s for s in statuses.values() if s.execution_ready]
        missing = [s for s in statuses.values() if not s.installed]
        not_ready = [
            s for s in statuses.values() if s.installed and not s.execution_ready
        ]
        outdated = [s for s in statuses.values() if s.is_outdated]
        critical_outdated = [s for s in outdated if s.is_critical]

        # Collect execution warnings for tools that are installed but not ready
        warnings = [
            f"{s.name}: {s.execution_warning}" for s in not_ready if s.execution_warning
        ]

        return {
            "profile": profile,
            "total": len(statuses),
            "installed": len(installed),
            "execution_ready": len(execution_ready),
            "missing": len(missing),
            "not_ready": len(not_ready),
            "outdated": len(outdated),
            "critical_outdated": len(critical_outdated),
            "ready": len(execution_ready) == len(statuses),  # All tools execution-ready
            "warnings": warnings,
        }

    def get_version_drift(self, profile: str) -> list[dict]:
        """
        Check for version drift between installed and expected versions.

        This is used for pre-scan validation to warn users when their installed
        tool versions don't match the pinned versions in versions.yaml.

        Args:
            profile: Profile name ('fast', 'slim', 'balanced', 'deep')

        Returns:
            List of dicts with tool, installed, expected, critical, and direction fields
            for each tool with version mismatch. Direction is "ahead", "behind", or "unknown".
        """
        drift = []
        statuses = self.check_profile(profile)

        for name, status in statuses.items():
            if status.installed and status.installed_version != status.expected_version:
                # Determine direction: ahead (installed > expected) or behind
                direction = self._compare_version_direction(
                    status.installed_version, status.expected_version
                )
                drift.append(
                    {
                        "tool": name,
                        "installed": status.installed_version,
                        "expected": status.expected_version,
                        "critical": status.is_critical,
                        "direction": direction,
                    }
                )

        return drift

    def _compare_version_direction(
        self, installed: str | None, expected: str | None
    ) -> str:
        """
        Compare versions to determine if installed is ahead or behind expected.

        Args:
            installed: Installed version string
            expected: Expected version string

        Returns:
            "ahead" if installed > expected, "behind" if installed < expected,
            "unknown" if versions can't be compared
        """
        if not installed or not expected:
            return "unknown"

        try:
            installed_parts = self._parse_version_parts(installed)
            expected_parts = self._parse_version_parts(expected)

            # Compare part by part
            for i in range(max(len(installed_parts), len(expected_parts))):
                inst_part = installed_parts[i] if i < len(installed_parts) else 0
                exp_part = expected_parts[i] if i < len(expected_parts) else 0

                if inst_part > exp_part:
                    return "ahead"
                if inst_part < exp_part:
                    return "behind"

            return (
                "unknown"  # Versions are equal (shouldn't happen if called correctly)
            )
        except (ValueError, TypeError):
            return "unknown"

    def _find_binary(self, binary_name: str) -> str | None:
        """
        Find binary in PATH or common locations.

        Args:
            binary_name: Name of the binary to find

        Returns:
            Full path to binary or None if not found
        """
        home = Path.home()

        # Check for tools with special installation paths FIRST
        # (before PATH lookup, to prefer our managed versions)

        # lynis is cloned to ~/.jmo/bin/lynis/ directory
        # The actual script is at ~/.jmo/bin/lynis/lynis
        # Check this BEFORE shutil.which() to prefer our cloned version over apt-installed
        if binary_name == "lynis":
            lynis_clone_path = home / ".jmo" / "bin" / "lynis" / "lynis"
            if lynis_clone_path.exists():
                return str(lynis_clone_path)

        # ZAP is extracted to ~/.jmo/bin/zap/ directory
        # The actual script is at ~/.jmo/bin/zap/zap.sh (Unix) or zap.bat (Windows)
        if binary_name in ("zap.sh", "zap.bat"):
            # Check both zap.sh and zap.bat (cross-platform support)
            for script_name in ("zap.bat", "zap.sh"):
                zap_path = home / ".jmo" / "bin" / "zap" / script_name
                if zap_path.exists():
                    return str(zap_path)

        # dependency-check is extracted to ~/.jmo/bin/dependency-check/
        # The script is at ~/.jmo/bin/dependency-check/bin/dependency-check.sh (Unix)
        # or dependency-check.bat (Windows)
        if binary_name in ("dependency-check.sh", "dependency-check.bat"):
            # Check both .sh and .bat extensions (cross-platform support)
            for script_name in ("dependency-check.bat", "dependency-check.sh"):
                dc_path = (
                    home / ".jmo" / "bin" / "dependency-check" / "bin" / script_name
                )
                if dc_path.exists():
                    return str(dc_path)

        # scancode is extracted to ~/.jmo/bin/scancode/
        # Pre-built releases extract to scancode-toolkit-vX.Y.Z/ nested directory
        if binary_name == "scancode":
            scancode_dir = home / ".jmo" / "bin" / "scancode"
            if scancode_dir.exists():
                # Check root directory first
                for name in ("scancode", "scancode.exe"):
                    scancode_path = scancode_dir / name
                    if scancode_path.exists() and scancode_path.is_file():
                        return str(scancode_path)

                # Check nested directories (scancode-toolkit-vX.Y.Z/)
                # Pre-built releases extract to versioned subdirectory
                for subdir in scancode_dir.iterdir():
                    if subdir.is_dir() and subdir.name.startswith("scancode"):
                        for name in ("scancode", "scancode.exe"):
                            nested_path = subdir / name
                            if nested_path.is_file():
                                return str(nested_path)
                        # Also check bin/ inside nested directory
                        nested_bin = subdir / "bin"
                        if nested_bin.exists():
                            for name in ("scancode", "scancode.exe"):
                                nested_path = nested_bin / name
                                if nested_path.is_file():
                                    return str(nested_path)

                # Also check in bin/ subdirectory (some release formats)
                bin_dir = scancode_dir / "bin"
                if bin_dir.exists():
                    for name in ("scancode", "scancode.exe"):
                        scancode_path = bin_dir / name
                        if scancode_path.exists():
                            return str(scancode_path)

        # yara-python is a Python library, not a CLI binary
        # Check if the module is importable instead of looking for a binary
        if binary_name == "yara":
            try:
                import importlib.util

                spec = importlib.util.find_spec("yara")
                if spec is not None and spec.origin:
                    # Return the module path so we know it's "installed"
                    return spec.origin
            except ImportError:
                pass
            return None

        # Now check PATH for standard tools
        path = shutil.which(binary_name)
        if path:
            return path

        # Check common installation locations
        common_paths = [
            home / ".jmo" / "bin" / binary_name,
            home / ".local" / "bin" / binary_name,
            home / ".kubescape" / "bin" / "kubescape",  # Kubescape's custom location
            Path("/usr/local/bin") / binary_name,
        ]

        for p in common_paths:
            if p.exists() and p.is_file():
                return str(p)

        # Handle special cases for other ZAP locations
        if binary_name in ("zap.sh", "zap.bat"):
            # ZAP can be in various locations
            # Unix locations (.sh), Windows locations (.bat)
            zap_paths = [
                home / "zap" / "zap.sh",
                home / "zap" / "zap.bat",
                Path("/opt/zaproxy/zap.sh"),
                Path("/usr/share/zaproxy/zap.sh"),
            ]
            for p in zap_paths:
                if p.exists():
                    return str(p)

        # Handle special cases for other dependency-check locations
        if binary_name in ("dependency-check.sh", "dependency-check.bat"):
            dc_paths = [
                home / "dependency-check" / "bin" / "dependency-check.sh",
                home / "dependency-check" / "bin" / "dependency-check.bat",
                Path("/opt/dependency-check/bin/dependency-check.sh"),
            ]
            for p in dc_paths:
                if p.exists():
                    return str(p)

        return None

    def _get_tool_version(self, tool_name: str, binary_path: str) -> str | None:
        """
        Get installed version of a tool.

        Args:
            tool_name: Tool name (e.g., 'zap', not 'zap.sh')
            binary_path: Full path to binary

        Returns:
            Version string or None if unable to determine
        """
        # Get version command - use tool_name for lookup (not binary_name)
        # VERSION_COMMANDS uses tool names as keys (e.g., "zap" not "zap.sh")
        if tool_name in VERSION_COMMANDS:
            version_cmd_config = VERSION_COMMANDS[tool_name]

            # Handle platform-specific commands (dict) vs universal commands (list)
            if isinstance(version_cmd_config, dict):
                # Get command for current platform
                cmd_template = version_cmd_config.get(self.platform)
                if not cmd_template:
                    # Fallback to "default" key
                    cmd_template = version_cmd_config.get("default")
                if not cmd_template:
                    cmd_template = [binary_path, "--version"]
                cmd = list(cmd_template)  # Copy to avoid mutation
            else:
                cmd = list(version_cmd_config)  # Copy to avoid mutation

            # Replace first element (the binary) with full path
            cmd[0] = binary_path
        else:
            cmd = [binary_path, "--version"]

        # Use tool-specific timeout (Java tools need longer JVM startup time)
        timeout = VERSION_TIMEOUTS.get(tool_name, 10)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self._get_clean_env(),
            )
            # Combine stdout and stderr - some tools write version to stderr
            output = (result.stdout or "") + (result.stderr or "")

            # Log detailed debug info for troubleshooting
            logger.debug(
                f"Version command for {tool_name}: cmd={cmd}, "
                f"returncode={result.returncode}, "
                f"stdout={result.stdout!r}, stderr={result.stderr!r}"
            )

            # Check for command execution errors
            # Note: Some tools return non-zero even for --version, so we still try parsing
            if not output.strip():
                if result.returncode != 0:
                    logger.debug(
                        f"Version command failed for {tool_name} "
                        f"(exit code {result.returncode}), no output"
                    )
                return None

            # Parse version from output
            version = self._parse_version(tool_name, output)
            if version is None:
                # Log parse failure with sample of output for debugging
                sample = output[:200].replace("\n", "\\n")
                logger.debug(
                    f"Could not parse version for {tool_name} from output: {sample!r}"
                )
            return version
        except subprocess.TimeoutExpired:
            logger.debug(
                f"Timeout ({timeout}s) getting version for {tool_name}. "
                f"Try running '{' '.join(cmd)}' manually."
            )
            return None
        except FileNotFoundError:
            logger.debug(f"Binary not found at {binary_path} for {tool_name}")
            return None
        except PermissionError:
            logger.debug(f"Permission denied executing {binary_path} for {tool_name}")
            return None
        except (OSError, subprocess.SubprocessError) as e:
            logger.debug(
                f"Error getting version for {tool_name}: {type(e).__name__}: {e}"
            )
            return None

    def _parse_version(self, tool_name: str, output: str) -> str | None:
        """
        Parse version string from tool output.

        Args:
            tool_name: Tool name for pattern selection
            output: Command output to parse

        Returns:
            Version string or None
        """
        if not output or not output.strip():
            logger.debug(f"Empty version output for {tool_name}")
            return None

        # Filter deprecation/warning lines that may pollute version output
        # Python tools like semgrep and checkov emit pydantic warnings to stderr
        lines = output.split("\n")
        warning_patterns = [
            "deprecationwarning",
            "pydanticdepr",
            "futurewarning",
            "userwarning",
            "syntaxwarning",
        ]
        filtered = [
            line
            for line in lines
            if not any(w in line.lower() for w in warning_patterns)
        ]
        output = "\n".join(filtered) if filtered else output

        # Get tool-specific pattern or default
        pattern = VERSION_PATTERNS.get(tool_name, VERSION_PATTERNS["default"])

        match = pattern.search(output)
        if match:
            version = match.group(1)
            logger.debug(f"Parsed version for {tool_name}: {version}")
            return version

        # Fallback: try default pattern
        if tool_name in VERSION_PATTERNS:
            match = VERSION_PATTERNS["default"].search(output)
            if match:
                version = match.group(1)
                logger.debug(f"Parsed version for {tool_name} (fallback): {version}")
                return version

        # Log failure for debugging
        output_preview = output[:150].replace("\n", "\\n")
        logger.debug(
            f"Version parse failed for {tool_name}. "
            f"Pattern: {pattern.pattern!r}. Output preview: {output_preview!r}"
        )
        return None

    def _is_version_outdated(self, installed: str, expected: str) -> bool:
        """
        Compare versions to determine if update needed.

        Args:
            installed: Installed version string
            expected: Expected (latest) version string

        Returns:
            True if installed is older than expected
        """
        try:
            installed_parts = self._parse_version_parts(installed)
            expected_parts = self._parse_version_parts(expected)

            # Compare major.minor.patch
            for i in range(min(len(installed_parts), len(expected_parts))):
                if installed_parts[i] < expected_parts[i]:
                    return True
                if installed_parts[i] > expected_parts[i]:
                    return False

            return False
        except (ValueError, TypeError):
            # If parsing fails, do string comparison
            return installed != expected

    def _parse_version_parts(self, version: str) -> list[int]:
        """Parse version string into numeric parts.

        Handles versions like "4.34c" by extracting numeric prefix from each part.
        """
        # Remove 'v' prefix and any suffix after hyphen
        version = version.lstrip("v").split("-")[0]
        parts = version.split(".")
        result = []
        for p in parts:
            # Extract leading digits from each part (handles "34c" -> 34)
            digits = ""
            for char in p:
                if char.isdigit():
                    digits += char
                else:
                    break  # Stop at first non-digit
            if digits:
                result.append(int(digits))
        return result

    def _get_clean_env(self) -> dict:
        """Get a clean environment for subprocess calls."""
        import os

        env = os.environ.copy()
        # Add common tool paths
        home = str(Path.home())
        extra_paths = [
            f"{home}/.jmo/bin",
            f"{home}/.local/bin",
            f"{home}/.kubescape/bin",
        ]
        current_path = env.get("PATH", "")
        env["PATH"] = ":".join(extra_paths) + ":" + current_path
        return env

    def _verify_execution(self, tool_name: str) -> tuple[bool, str | None, list[str]]:
        """
        Verify tool can actually execute, not just that binary exists (Fix 1.4).

        Args:
            tool_name: Name of the tool to verify

        Returns:
            Tuple of (is_ready, warning_message, missing_deps)
        """
        required = TOOL_EXECUTION_COMMANDS.get(tool_name, [tool_name])

        missing = []
        for cmd in required:
            # First try shutil.which for standard PATH lookup
            if shutil.which(cmd):
                continue
            # Then try _find_binary for special paths (zap, dependency-check, etc.)
            if self._find_binary(cmd):
                continue
            missing.append(cmd)

        if missing:
            return False, f"Missing: {', '.join(missing)}", missing

        # Special version checks
        if tool_name == "cdxgen":
            node_version = self._get_node_version()
            if node_version:
                required_version = TOOL_VERSION_REQUIREMENTS.get("cdxgen", {}).get(
                    "node", "20.0.0"
                )
                required_parts = tuple(map(int, required_version.split(".")))
                if node_version < required_parts:
                    ver_str = ".".join(map(str, node_version))
                    return (
                        False,
                        f"Requires Node.js {required_version}+, found {ver_str}",
                        ["node"],
                    )
            else:
                return False, "Node.js not found (required for cdxgen)", ["node"]

        # Lynis requires bash (shell script) - check on Windows
        if tool_name == "lynis" and self.platform == "windows":
            if not shutil.which("bash"):
                return (
                    False,
                    "Requires bash (install WSL, Git Bash, or Cygwin)",
                    ["bash"],
                )

        return True, None, []

    def _get_node_version(self) -> tuple[int, int, int] | None:
        """Get Node.js version as tuple."""
        try:
            result = subprocess.run(
                ["node", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse v20.10.0 -> (20, 10, 0)
                version = result.stdout.strip().lstrip("v")
                parts = version.split(".")[:3]
                return tuple(int(p) for p in parts if p.isdigit())  # type: ignore[return-value]  # Generator returns variable-length tuple, safe for version comparison
        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass
        return None


def print_tool_status_table(
    statuses: dict[str, ToolStatus],
    colorize: Callable[[str, str], str] | None = None,
    show_hints: bool = False,
) -> None:
    """
    Print tool status as formatted table.

    Args:
        statuses: Dict of tool name -> ToolStatus
        colorize: Optional function to colorize output (text, color) -> str
        show_hints: Whether to show installation hints for missing tools
    """
    if colorize is None:
        colorize = lambda text, color: text  # noqa: E731

    # Calculate column widths
    name_width = max(len(name) for name in statuses.keys())
    name_width = max(name_width, 15)

    # Header
    header = (
        f"{'Tool':<{name_width}}  {'Status':<10}  {'Installed':<12}  {'Expected':<12}"
    )
    print(header)
    print("-" * len(header))

    # Sort tools: missing first, then outdated, then OK
    def sort_key(item):
        name, status = item
        if not status.installed:
            return (0, name)
        if status.is_outdated:
            return (1, name)
        return (2, name)

    for name, status in sorted(statuses.items(), key=sort_key):
        # Format status with color
        if not status.installed:
            status_str = colorize("MISSING", "red")
        elif status.is_outdated:
            critical = " [!]" if status.is_critical else ""
            status_str = colorize(f"OUTDATED{critical}", "yellow")
        else:
            status_str = colorize("OK", "green")

        installed_ver = status.installed_version or "-"
        expected_ver = status.expected_version or "-"

        print(
            f"{name:<{name_width}}  {status_str:<10}  {installed_ver:<12}  {expected_ver:<12}"
        )

        if show_hints and not status.installed:
            print(f"  -> {status.install_hint}")


def print_profile_summary(
    manager: ToolManager,
    colorize: Callable[[str, str], str] | None = None,
) -> None:
    """
    Print summary of all profiles.

    Args:
        manager: ToolManager instance
        colorize: Optional colorize function
    """
    if colorize is None:
        colorize = lambda text, color: text  # noqa: E731

    print("\nProfile Summary:")
    print("-" * 50)
    print(f"{'Profile':<12}  {'Required':<10}  {'Installed':<10}  {'Status'}")
    print("-" * 50)

    for profile in ["fast", "slim", "balanced", "deep"]:
        summary = manager.get_profile_summary(profile)
        total = summary["total"]
        installed = summary["installed"]

        if summary["ready"]:
            status = colorize("Ready", "green")
        elif summary["missing"] <= 3:
            status = colorize(f"{summary['missing']} missing", "yellow")
        else:
            status = colorize(f"{summary['missing']} missing", "red")

        print(f"{profile:<12}  {total:<10}  {installed:<10}  {status}")


def get_missing_tools_for_scan(
    tools: list[str],
    manager: ToolManager | None = None,
) -> tuple[list[str], list[ToolStatus]]:
    """
    Check which tools from a list are available for scanning.

    Args:
        tools: List of tool names to check
        manager: Optional ToolManager instance

    Returns:
        Tuple of (available_tools, missing_statuses)
    """
    if manager is None:
        manager = ToolManager()

    available = []
    missing = []

    for tool in tools:
        status = manager.check_tool(tool)
        if status.installed:
            available.append(tool)
        else:
            missing.append(status)

    return available, missing
