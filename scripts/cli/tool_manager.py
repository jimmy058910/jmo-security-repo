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
    TOOL_VARIANTS,
    ToolInfo,
    ToolRegistry,
    detect_platform,
    get_install_hint,
)

logger = logging.getLogger(__name__)

# Version extraction patterns for different tools
VERSION_PATTERNS: dict[str, re.Pattern] = {
    # Standard semver pattern
    "default": re.compile(r"v?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)"),
    # Tool-specific patterns
    "trivy": re.compile(r"Version:\s*(\d+\.\d+\.\d+)"),
    "checkov": re.compile(r"(\d+\.\d+\.\d+)"),
    "prowler": re.compile(r"Prowler\s+(\d+\.\d+\.\d+)"),
    "zap": re.compile(r"ZAP\s+(\d+\.\d+\.\d+)"),
    "dependency-check": re.compile(r"Dependency-Check\s+(\d+\.\d+\.\d+)"),
}

# Version commands for tools that don't use --version
VERSION_COMMANDS: dict[str, list[str]] = {
    "zap": ["zap.sh", "-version"],
    "dependency-check": ["dependency-check.sh", "--version"],
    "lynis": ["lynis", "show", "version"],
    "yara": ["yara", "--version"],
}


@dataclass
class ToolStatus:
    """Status of a single tool."""

    name: str
    installed: bool
    installed_version: str | None = None
    expected_version: str | None = None
    is_outdated: bool = False
    is_critical: bool = False
    install_hint: str = ""
    binary_path: str | None = None
    is_variant: bool = False  # True if this is a variant (e.g., semgrep-secrets)

    @property
    def status_icon(self) -> str:
        """Get status icon for display."""
        if not self.installed:
            return "X"
        if self.is_outdated:
            return "!"
        return "OK"

    @property
    def status_text(self) -> str:
        """Get status text for display."""
        if not self.installed:
            return "MISSING"
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
        Check status of a single tool.

        Args:
            tool_name: Name of the tool (e.g., 'trivy', 'semgrep')

        Returns:
            ToolStatus with installation information
        """
        tool_info = self.registry.get_tool(tool_name)

        # Handle variants - they share a binary with base tool
        is_variant = tool_name in TOOL_VARIANTS
        binary_name = tool_info.get_binary_name() if tool_info else tool_name

        # Check if installed
        binary_path = self._find_binary(binary_name)
        installed = binary_path is not None

        # Get installed version if found
        installed_version = None
        if installed:
            installed_version = self._get_tool_version(binary_name, binary_path)

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
        return {tool.name: self.check_tool(tool.name) for tool in self.registry.get_all_tools()}

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
        Get summary statistics for a profile.

        Args:
            profile: Profile name

        Returns:
            Dict with total, installed, missing, outdated counts
        """
        statuses = self.check_profile(profile)
        installed = [s for s in statuses.values() if s.installed]
        missing = [s for s in statuses.values() if not s.installed]
        outdated = [s for s in statuses.values() if s.is_outdated]
        critical_outdated = [s for s in outdated if s.is_critical]

        return {
            "profile": profile,
            "total": len(statuses),
            "installed": len(installed),
            "missing": len(missing),
            "outdated": len(outdated),
            "critical_outdated": len(critical_outdated),
            "ready": len(missing) == 0,
        }

    def _find_binary(self, binary_name: str) -> str | None:
        """
        Find binary in PATH or common locations.

        Args:
            binary_name: Name of the binary to find

        Returns:
            Full path to binary or None if not found
        """
        # First check PATH
        path = shutil.which(binary_name)
        if path:
            return path

        # Check common installation locations
        home = Path.home()
        common_paths = [
            home / ".jmo" / "bin" / binary_name,
            home / ".local" / "bin" / binary_name,
            home / ".kubescape" / "bin" / "kubescape",  # Kubescape's custom location
            Path("/usr/local/bin") / binary_name,
        ]

        for p in common_paths:
            if p.exists() and p.is_file():
                return str(p)

        # Handle special cases
        if binary_name == "zap.sh":
            # ZAP can be in various locations
            zap_paths = [
                home / "zap" / "zap.sh",
                Path("/opt/zaproxy/zap.sh"),
                Path("/usr/share/zaproxy/zap.sh"),
            ]
            for p in zap_paths:
                if p.exists():
                    return str(p)

        if binary_name == "dependency-check.sh":
            dc_paths = [
                home / "dependency-check" / "bin" / "dependency-check.sh",
                Path("/opt/dependency-check/bin/dependency-check.sh"),
            ]
            for p in dc_paths:
                if p.exists():
                    return str(p)

        return None

    def _get_tool_version(self, binary_name: str, binary_path: str) -> str | None:
        """
        Get installed version of a tool.

        Args:
            binary_name: Tool binary name
            binary_path: Full path to binary

        Returns:
            Version string or None if unable to determine
        """
        # Get version command
        if binary_name in VERSION_COMMANDS:
            cmd = VERSION_COMMANDS[binary_name]
            # Replace binary name with full path
            cmd = [binary_path if c == binary_name else c for c in cmd]
        else:
            cmd = [binary_path, "--version"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                env=self._get_clean_env(),
            )
            output = result.stdout or result.stderr

            # Parse version from output
            return self._parse_version(binary_name, output)
        except subprocess.TimeoutExpired:
            logger.debug(f"Timeout getting version for {binary_name}")
            return None
        except (OSError, subprocess.SubprocessError) as e:
            logger.debug(f"Error getting version for {binary_name}: {e}")
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
        # Get tool-specific pattern or default
        pattern = VERSION_PATTERNS.get(tool_name, VERSION_PATTERNS["default"])

        match = pattern.search(output)
        if match:
            return match.group(1)

        # Fallback: try default pattern
        if tool_name in VERSION_PATTERNS:
            match = VERSION_PATTERNS["default"].search(output)
            if match:
                return match.group(1)

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
        """Parse version string into numeric parts."""
        # Remove 'v' prefix and any suffix after hyphen
        version = version.lstrip("v").split("-")[0]
        parts = version.split(".")
        return [int(p) for p in parts if p.isdigit()]

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
    header = f"{'Tool':<{name_width}}  {'Status':<10}  {'Installed':<12}  {'Expected':<12}"
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

        print(f"{name:<{name_width}}  {status_str:<10}  {installed_ver:<12}  {expected_ver:<12}")

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
