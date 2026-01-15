"""
Tool Registry for JMo Security.

Provides structured access to versions.yaml tool definitions with
profile filtering, version comparison, and installation metadata.

This module is the single source of truth for:
- Tool version information
- Profile-to-tool mappings
- Installation commands per platform
- Critical tool identification
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, get_args

import yaml

logger = logging.getLogger(__name__)

# Type aliases
Platform = Literal["linux", "macos", "windows"]
ToolCategory = Literal["python_tools", "binary_tools", "special_tools"]

# Profile to tool mapping - canonical source from jmo.yml
# These are the actual binary/command names used for detection
PROFILE_TOOLS: dict[str, list[str]] = {
    "fast": [
        "trufflehog",
        "semgrep",
        "syft",
        "trivy",
        "checkov",
        "hadolint",
        "nuclei",
        "shellcheck",
    ],  # 8 tools
    "slim": [
        "trufflehog",
        "semgrep",
        "syft",
        "trivy",
        "checkov",
        "hadolint",
        "nuclei",
        "prowler",
        "kubescape",
        "grype",
        "bearer",
        "horusec",
        "dependency-check",
        "shellcheck",
    ],  # 14 tools
    "balanced": [
        "trufflehog",
        "semgrep",
        "syft",
        "trivy",
        "checkov",
        "hadolint",
        "zap",
        "nuclei",
        "prowler",
        "kubescape",
        "scancode",
        "cdxgen",
        "gosec",
        "grype",
        "bearer",
        "horusec",
        "dependency-check",
        "shellcheck",
    ],  # 18 tools
    "deep": [
        "trufflehog",
        "noseyparker",
        "semgrep",
        "semgrep-secrets",
        "bandit",
        "syft",
        "trivy",
        "trivy-rbac",
        "checkov",
        "checkov-cicd",
        "hadolint",
        "zap",
        "nuclei",
        "prowler",
        "kubescape",
        "akto",
        "scancode",
        "cdxgen",
        "gosec",
        "yara",
        "grype",
        "bearer",
        "horusec",
        "dependency-check",
        "falco",
        "afl++",
        "mobsf",
        "lynis",
    ],  # 28 tools
}

# Tool name normalization - maps jmo.yml names to binary names
TOOL_BINARY_NAMES: dict[str, str] = {
    # Most tools use their name as-is, but some differ
    "dependency-check": "dependency-check.sh",  # Java wrapper script
    "afl++": "afl-fuzz",  # AFL++ binary name
    "semgrep-secrets": "semgrep",  # Same binary, different config
    "trivy-rbac": "trivy",  # Same binary, different config
    "checkov-cicd": "checkov",  # Same binary, different config
    "scancode": "scancode",  # scancode-toolkit installs as 'scancode'
    "zap": "zap.sh",  # ZAP wrapper script (or zap-cli)
}

# Tools that are variants (same binary, different invocation)
TOOL_VARIANTS: dict[str, str] = {
    "semgrep-secrets": "semgrep",
    "trivy-rbac": "trivy",
    "checkov-cicd": "checkov",
}

# Execution requirements - commands/dependencies needed to actually run tools (Fix 1.4)
# Maps tool name to list of commands that must be available for execution
TOOL_EXECUTION_COMMANDS: dict[str, list[str]] = {
    "zap": ["zap.sh"],  # ZAP launcher script (installed via jmo tools install)
    "nuclei": ["nuclei"],  # Standard binary
    "horusec": ["horusec"],  # horusec binary (optionally needs docker)
    "cdxgen": ["cdxgen", "node"],  # Requires Node.js 20+
    "dependency-check": ["dependency-check.sh"],  # Java wrapper script
    "prowler": ["prowler"],
    "kubescape": ["kubescape"],
    "gosec": ["gosec"],
}

# Version requirements for tools with specific dependency versions
TOOL_VERSION_REQUIREMENTS: dict[str, dict[str, str]] = {
    "cdxgen": {"node": "20.0.0"},  # Requires Node.js 20+
}

# Platform compatibility requirements for tools
# Tools not listed here are assumed to work on all platforms
# This is used for proactive filtering in the wizard to skip incompatible tools
TOOL_PLATFORM_REQUIREMENTS: dict[str, dict] = {
    # Linux-only tools (kernel requirements)
    "falco": {
        "platforms": ["linux"],
        "docker_image": "falcosecurity/falco",
        "docker_flags": "--privileged",
        "reason": "Requires Linux kernel module (eBPF or kernel module)",
        "workarounds": ["docker"],
    },
    "afl++": {
        "platforms": ["linux"],
        "docker_image": "aflplusplus/aflplusplus",
        "reason": "Requires Linux kernel features (ptrace, shared memory)",
        "workarounds": ["docker", "wsl2"],
    },
    # Linux/macOS only (no Windows binaries)
    "noseyparker": {
        "platforms": ["linux", "macos"],
        "docker_image": "ghcr.io/praetorian-inc/noseyparker",
        "reason": "Rust binary not available for Windows",
        "workarounds": ["docker", "wsl2"],
    },
    "bearer": {
        "platforms": ["linux", "macos"],
        "docker_image": "bearer/bearer",
        "reason": "Go binary not available for Windows",
        "workarounds": ["docker", "wsl2"],
    },
    # All platforms but with requirements
    "lynis": {
        "platforms": ["linux", "macos", "windows"],
        "windows_requires": ["bash"],
        "docker_image": "cisofy/lynis",
        "reason": "Shell script requires bash interpreter",
        "workarounds": ["git_bash", "wsl", "docker"],
    },
    "prowler": {
        "platforms": ["linux", "macos", "windows"],
        "windows_requires": ["long_path_support"],
        "reason": "Creates deeply nested paths exceeding 260-char limit",
        "workarounds": ["docker", "registry_fix"],
    },
    # Docker-only tools (complex setup not recommended natively)
    "mobsf": {
        "platforms": [],  # No native support recommended
        "docker_image": "opensecurity/mobile-security-framework-mobsf",
        "docker_ports": ["8000:8000"],
        "reason": "Complex setup (Android SDK + Python dependencies)",
        "workarounds": ["docker"],
    },
    "akto": {
        "platforms": [],
        "docker_compose": True,
        "reason": "Microservice architecture requires docker-compose",
        "workarounds": ["docker_compose"],
    },
}


def get_platform_status(tool_name: str, platform: str) -> dict:
    """
    Get platform compatibility status for a tool.

    This function checks whether a tool is supported on the given platform
    and provides detailed information about any compatibility issues.

    Args:
        tool_name: Name of the tool (e.g., 'falco', 'noseyparker')
        platform: Current platform ("windows", "linux", "macos")

    Returns:
        Dictionary with:
        - supported: bool - whether the tool works on this platform
        - reason: str | None - explanation if not supported
        - requirements: list[str] - platform-specific requirements (if supported)
        - workarounds: list[str] - alternative ways to run the tool
        - docker_image: str | None - Docker image for container-based execution
    """
    if tool_name not in TOOL_PLATFORM_REQUIREMENTS:
        # Tool not in requirements dict - assume universal support
        return {
            "supported": True,
            "reason": None,
            "workarounds": [],
            "requirements": [],
        }

    req = TOOL_PLATFORM_REQUIREMENTS[tool_name]

    # Check if platform is in supported list
    platforms = req.get("platforms", ["linux", "macos", "windows"])
    if platform not in platforms:
        return {
            "supported": False,
            "reason": req.get("reason", f"Not available on {platform}"),
            "workarounds": req.get("workarounds", []),
            "docker_image": req.get("docker_image"),
            "requirements": [],
        }

    # Check platform-specific requirements (e.g., windows_requires)
    platform_requires = req.get(f"{platform}_requires", [])
    if platform_requires:
        return {
            "supported": True,  # Supported but with requirements
            "reason": req.get("reason"),
            "requirements": platform_requires,
            "workarounds": req.get("workarounds", []),
            "docker_image": req.get("docker_image"),
        }

    return {
        "supported": True,
        "reason": None,
        "workarounds": [],
        "requirements": [],
    }


def get_tools_for_profile_filtered(
    profile: str, platform: str | None = None
) -> list[str]:
    """
    Get tools for a profile, optionally filtered by platform compatibility.

    This is a module-level function that provides platform-filtered tool lists
    for use in the wizard and other CLI components.

    Args:
        profile: Profile name (fast, slim, balanced, deep)
        platform: Optional platform filter ("windows", "linux", "macos").
                  If None, returns all tools for the profile.

    Returns:
        List of tool names compatible with the platform.

    Example:
        >>> get_tools_for_profile_filtered("deep", "windows")
        ['trufflehog', 'semgrep', ...]  # Excludes falco, afl++, etc.
    """
    all_tools = PROFILE_TOOLS.get(profile, [])

    if platform is None:
        return all_tools

    compatible_tools = []
    for tool in all_tools:
        status = get_platform_status(tool, platform)
        if status["supported"]:
            compatible_tools.append(tool)

    return compatible_tools


def get_skipped_tools_for_profile(profile: str, platform: str) -> list[tuple[str, str]]:
    """
    Get tools that will be skipped on this platform.

    This function identifies tools that are not compatible with the current
    platform and returns them with explanatory reasons. Used by the wizard
    to proactively inform users before tool checking.

    Args:
        profile: Profile name (fast, slim, balanced, deep)
        platform: Current platform ("windows", "linux", "macos")

    Returns:
        List of (tool_name, reason) tuples for incompatible tools.

    Example:
        >>> get_skipped_tools_for_profile("deep", "windows")
        [('falco', 'Requires Linux kernel module (eBPF or kernel module)'),
         ('afl++', 'Requires Linux kernel features (ptrace, shared memory)'),
         ...]
    """
    all_tools = PROFILE_TOOLS.get(profile, [])
    skipped = []

    for tool in all_tools:
        status = get_platform_status(tool, platform)
        if not status["supported"]:
            reason = status.get("reason", "Not available on this platform")
            skipped.append((tool, reason))

    return skipped


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
    brew_package: str | None = None
    apt_package: str | None = None
    npm_package: str | None = None

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

    def is_variant(self) -> bool:
        """Check if this tool is a variant of another (same binary)."""
        return self.name in TOOL_VARIANTS

    def get_base_tool(self) -> str:
        """Get the base tool name for variants."""
        return TOOL_VARIANTS.get(self.name, self.name)


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
        except Exception as e:
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

        # Add virtual tools (variants that share binaries)
        self._add_virtual_tools()

        logger.debug(f"Loaded {len(self._tools)} tools from {self._versions_path}")

    def _parse_tool(
        self, name: str, info: dict, category: ToolCategory
    ) -> ToolInfo | None:
        """Parse a single tool entry from versions.yaml."""
        try:
            # Determine brew package name (often same as tool name)
            brew_pkg = info.get("brew_package")
            if brew_pkg is None and category == "binary_tools":
                # Many binary tools are available via brew with same name
                brew_pkg = name

            # Determine apt package
            apt_pkg = info.get("apt_package")

            # Parse npm package from pypi_package field if it starts with @
            npm_pkg = None
            pypi_pkg = info.get("pypi_package")
            if pypi_pkg and pypi_pkg.startswith("@"):
                npm_pkg = pypi_pkg
                pypi_pkg = None

            return ToolInfo(
                name=name,
                version=str(info.get("version", "unknown")),
                description=info.get("description", ""),
                category=category,
                critical=info.get("critical", False),
                docker_ready=info.get("docker_ready", True),
                pypi_package=pypi_pkg,
                github_repo=info.get("github_repo"),
                brew_package=brew_pkg,
                apt_package=apt_pkg,
                npm_package=npm_pkg,
                binary_name=info.get("binary_name"),
                install_notes=info.get("notes"),
                update_check=info.get("update_check"),
            )
        except Exception as e:
            logger.warning(f"Failed to parse tool {name}: {e}")
            return None

    def _add_virtual_tools(self) -> None:
        """Add virtual tools that are variants of real tools."""
        # These tools use the same binary but with different configurations
        virtual_tools = {
            "semgrep-secrets": ("semgrep", "Semgrep with secrets configuration"),
            "trivy-rbac": ("trivy", "Trivy with RBAC scanning"),
            "checkov-cicd": ("checkov", "Checkov with CI/CD framework"),
        }

        for variant_name, (base_name, description) in virtual_tools.items():
            if variant_name not in self._tools and base_name in self._tools:
                base_tool = self._tools[base_name]
                self._tools[variant_name] = ToolInfo(
                    name=variant_name,
                    version=base_tool.version,
                    description=description,
                    category=base_tool.category,
                    critical=False,
                    docker_ready=base_tool.docker_ready,
                    pypi_package=base_tool.pypi_package,
                    github_repo=base_tool.github_repo,
                    brew_package=None,  # Variants don't have separate packages
                    apt_package=None,
                    binary_name=base_tool.get_binary_name(),
                )

    def get_tool(self, name: str) -> ToolInfo | None:
        """
        Get tool info by name.

        Args:
            name: Tool name (e.g., 'trivy', 'semgrep')

        Returns:
            ToolInfo or None if not found
        """
        return self._tools.get(name)

    def get_tools_for_profile(self, profile: str) -> list[ToolInfo]:
        """
        Get all tools required for a scan profile.

        Args:
            profile: Profile name ('fast', 'slim', 'balanced', 'deep')

        Returns:
            List of ToolInfo objects for the profile
        """
        tool_names = PROFILE_TOOLS.get(profile, [])
        tools = []
        for name in tool_names:
            tool = self.get_tool(name)
            if tool:
                tools.append(tool)
            else:
                # Create a placeholder for unknown tools
                logger.warning(
                    f"Tool {name} in profile {profile} not found in registry"
                )
                tools.append(
                    ToolInfo(
                        name=name,
                        version="unknown",
                        description=f"Unknown tool: {name}",
                        category="binary_tools",
                    )
                )
        return tools

    def get_critical_tools(self) -> list[ToolInfo]:
        """Get tools marked as critical for updates."""
        return [t for t in self._tools.values() if t.critical]

    def get_all_tools(self) -> list[ToolInfo]:
        """Get all registered tools."""
        return list(self._tools.values())

    def get_profile_names(self) -> list[str]:
        """Get list of available profile names."""
        return list(PROFILE_TOOLS.keys())

    def get_profile_tool_count(self, profile: str) -> int:
        """Get count of tools in a profile."""
        return len(PROFILE_TOOLS.get(profile, []))


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

    Args:
        tool: ToolInfo object
        platform: Target platform (auto-detected if None)

    Returns:
        Human-readable installation hint string
    """
    if platform is None:
        platform = detect_platform()

    hints = []

    if platform == "macos":
        if tool.brew_package:
            hints.append(f"brew install {tool.brew_package}")
        if tool.pypi_package:
            hints.append(f"pip install {tool.pypi_package}")
        if tool.npm_package:
            hints.append(f"npm install -g {tool.npm_package}")
    elif platform == "linux":
        if tool.apt_package:
            hints.append(f"apt install {tool.apt_package}")
        if tool.pypi_package:
            hints.append(f"pip install {tool.pypi_package}")
        if tool.npm_package:
            hints.append(f"npm install -g {tool.npm_package}")
        if tool.brew_package:
            hints.append(f"brew install {tool.brew_package}")
    elif platform == "windows":
        if tool.pypi_package:
            hints.append(f"pip install {tool.pypi_package}")
        if tool.npm_package:
            hints.append(f"npm install -g {tool.npm_package}")
        # Windows often needs manual installation
        hints.append("See JMo docs for Windows installation")

    if not hints and tool.github_repo:
        hints.append(f"See: https://github.com/{tool.github_repo}")

    if tool.install_notes:
        hints.append(f"Note: {tool.install_notes}")

    return " | ".join(hints) if hints else "See JMo documentation"
