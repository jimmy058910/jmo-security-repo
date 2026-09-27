"""
Tool Registry for JMo Security.

Provides structured access to versions.yaml tool definitions with
version comparison and installation metadata.

This module is the single source of truth for:
- Tool version information
- The scan tool matrix (TOOL_MATRIX) and the policy engine (POLICY_ENGINE)
- Which tools apply to which target type
- Installation hints per platform
- Critical tool identification
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, get_args

import yaml

from scripts.core.tool_descriptors import DESCRIPTORS

logger = logging.getLogger(__name__)

# Type aliases
Platform = Literal["linux", "macos", "windows"]
ToolCategory = Literal["python_tools", "binary_tools", "special_tools"]

#: The scanners `jmo scan` considers when nothing narrows the list. Resolution is
#: `--tools`, then `jmo.yml` `tools:`, then this. Membership makes a tool eligible;
#: the target's type and content decide whether it runs. Declared in
#: `tool_descriptors.DESCRIPTORS`; every table below is derived from it.
TOOL_MATRIX: tuple[str, ...] = tuple(DESCRIPTORS)

#: Evaluates policy-as-code in the report phase. Installed and baked into the image
#: alongside the matrix, but it scans nothing, so it is not in TOOL_MATRIX.
POLICY_ENGINE: str = "opa"

#: Tool name -> executable name, where they differ.
TOOL_BINARY_NAMES: dict[str, str] = {
    name: d.binary for name, d in DESCRIPTORS.items() if d.binary
}

#: Tool name -> the commands that must exist for it to execute (a launcher
#: script and the runtime it starts, for zap).
TOOL_EXECUTION_COMMANDS: dict[str, list[str]] = {
    name: list(d.execution_commands)
    for name, d in DESCRIPTORS.items()
    if d.execution_commands
}

#: Which tools read which target types (docs/TOOLS.md#target-types). Membership
#: means "reads this kind of target", not "runs on every one": content decides
#: that (hadolint needs a Dockerfile). zap and nuclei read only URLs.
TOOL_SCAN_TYPES: dict[str, set[str]] = {
    target_type: {
        name for name, d in DESCRIPTORS.items() if target_type in d.target_types
    }
    for target_type in ("repo", "image", "url", "k8s", "iac", "gitlab")
}
_REPO_TOOLS: frozenset[str] = frozenset(TOOL_SCAN_TYPES["repo"])


def filter_tools_for_scan_type(tools: list[str], scan_type: str) -> list[str]:
    """
    Filter tools list to only include tools applicable to the scan type.

    This enables smarter tool selection - don't run ZAP on repo scans,
    don't run trufflehog on URL scans, etc.

    Args:
        tools: Full list of tools from profile
        scan_type: One of 'repo', 'image', 'url', 'k8s', 'iac', 'gitlab'

    Returns:
        Filtered list containing only applicable tools

    Example:
        >>> filter_tools_for_scan_type(["trufflehog", "nuclei", "trivy"], "image")
        ["trivy"]  # Only trivy applies to image scans
    """
    applicable = TOOL_SCAN_TYPES.get(scan_type, set())
    if not applicable:
        # Unknown scan type - return all tools (fail-safe)
        return tools
    return [t for t in tools if t in applicable]


@dataclass
class ToolInfo:
    """Information about a single security tool."""

    name: str
    version: str
    description: str
    category: ToolCategory

    # Flags
    critical: bool = False
    docker_ready: bool = True

    # Installation metadata
    pypi_package: str | None = None
    github_repo: str | None = None
    apt_package: str | None = None

    # Binary information
    binary_name: str | None = None  # Actual binary name if different from tool name

    # Platform support
    platforms: list[str] = field(default_factory=lambda: ["linux", "macos", "windows"])
    install_notes: str | None = None

    # Update tracking
    update_check: str | None = None

    def get_binary_name(self) -> str:
        """Get the actual binary name to check for in PATH."""
        if self.binary_name:
            return self.binary_name
        return TOOL_BINARY_NAMES.get(self.name, self.name)


class ToolRegistry:
    """Registry of all security tools from versions.yaml."""

    def __init__(self, versions_path: Path | None = None):
        """
        Load tool registry from versions.yaml.

        Args:
            versions_path: Path to versions.yaml. If None, uses default location.
        """
        if versions_path is None:
            # Find versions.yaml relative to this file or repo root
            versions_path = self._find_versions_yaml()

        self._versions_path = versions_path
        self._tools: dict[str, ToolInfo] = {}
        self._load_registry()

    def _find_versions_yaml(self) -> Path:
        """Find versions.yaml in the repository."""
        # Try relative to this file
        script_dir = Path(__file__).resolve().parent
        repo_root = script_dir.parent.parent  # scripts/core -> scripts -> repo_root

        candidates = [
            repo_root / "versions.yaml",
            Path.cwd() / "versions.yaml",
        ]

        for path in candidates:
            if path.exists():
                return path

        raise FileNotFoundError(
            "versions.yaml not found. Searched: "
            + ", ".join(str(p) for p in candidates)
        )

    def _load_registry(self) -> None:
        """Load and parse versions.yaml into ToolInfo objects."""
        try:
            with open(self._versions_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except (
            Exception
        ) as e:  # Acceptable: re-raises after logging — versions.yaml is required
            logger.error(f"Failed to load versions.yaml: {e}")
            raise

        # Parse each category (use get_args to maintain type safety)
        for category in get_args(ToolCategory):
            tools_data = data.get(category, {})
            if not isinstance(tools_data, dict):
                continue

            for name, info in tools_data.items():
                if not isinstance(info, dict):
                    continue

                tool = self._parse_tool(name, info, category)
                if tool:
                    self._tools[name] = tool

        logger.debug(f"Loaded {len(self._tools)} tools from {self._versions_path}")

    def _parse_tool(
        self, name: str, info: dict, category: ToolCategory
    ) -> ToolInfo | None:
        """Parse a single tool entry from versions.yaml."""
        try:
            return ToolInfo(
                name=name,
                version=str(info.get("version", "unknown")),
                description=info.get("description", ""),
                category=category,
                critical=info.get("critical", False),
                docker_ready=info.get("docker_ready", True),
                pypi_package=info.get("pypi_package"),
                github_repo=info.get("github_repo"),
                apt_package=info.get("apt_package"),
                binary_name=info.get("binary_name"),
                install_notes=info.get("notes"),
                update_check=info.get("update_check"),
            )
        except (
            Exception
        ) as e:  # Acceptable: malformed tool entry — skip and continue loading others
            logger.warning(f"Failed to parse tool {name}: {e}")
            return None

    def get_tool(self, name: str) -> ToolInfo | None:
        """
        Get tool info by name.

        Args:
            name: Tool name (e.g., 'trivy', 'semgrep')

        Returns:
            ToolInfo or None if not found
        """
        return self._tools.get(name)

    def get_critical_tools(self) -> list[ToolInfo]:
        """Get tools marked as critical for updates."""
        return [t for t in self._tools.values() if t.critical]

    def get_all_tools(self) -> list[ToolInfo]:
        """Get all registered tools."""
        return list(self._tools.values())


def detect_platform() -> Platform:
    """Detect the current platform."""
    if sys.platform == "darwin":
        return "macos"
    elif sys.platform == "win32":
        return "windows"
    return "linux"


def get_install_hint(tool: ToolInfo, platform: Platform | None = None) -> str:
    """
    Get a platform-appropriate installation hint for a tool.

    `jmo tools install` comes first on every platform: it is the path that
    installs the pinned version. brew and npm are no longer install strategies
    (v2.0.0), so they are not suggested either.

    Args:
        tool: ToolInfo object
        platform: Target platform (auto-detected if None)

    Returns:
        Human-readable installation hint string
    """
    if platform is None:
        platform = detect_platform()

    hints = [f"jmo tools install {tool.name}"]
    if tool.pypi_package:
        hints.append(f"pip install {tool.pypi_package}")
    if platform == "linux" and tool.apt_package:
        hints.append(f"apt install {tool.apt_package}")
    if tool.install_notes:
        hints.append(f"Note: {tool.install_notes}")

    return " | ".join(hints)
