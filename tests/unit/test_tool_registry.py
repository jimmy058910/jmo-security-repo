#!/usr/bin/env python3
"""Tests for scripts/core/tool_registry.py module.

This test suite validates the ToolRegistry class and related utilities:
1. ToolInfo dataclass behavior
2. ToolRegistry initialization and loading
3. Profile-to-tool mappings
4. Platform detection and install hints
5. Variant handling for tools sharing binaries

Target Coverage: >= 85%
"""

from pathlib import Path
from unittest.mock import patch
import pytest
import sys

# ========== Category 1: Constants and Profile Mappings ==========


def test_profile_tools_contains_expected_profiles():
    """Test PROFILE_TOOLS has all expected profile names."""
    from scripts.core.tool_registry import PROFILE_TOOLS

    expected_profiles = {"fast", "slim", "balanced", "deep"}
    assert set(PROFILE_TOOLS.keys()) == expected_profiles


def test_profile_tools_fast_count():
    """Test fast profile has expected number of tools."""
    from scripts.core.tool_registry import PROFILE_TOOLS

    # Fast profile: 8 core tools + OPA for policy-as-code = 9 tools
    assert len(PROFILE_TOOLS["fast"]) == 9


def test_profile_tools_deep_count():
    """Test deep profile has expected number of tools."""
    from scripts.core.tool_registry import PROFILE_TOOLS

    # Deep profile: 28 security tools + OPA for policy-as-code = 29 tools
    assert len(PROFILE_TOOLS["deep"]) == 29


def test_tool_binary_names_mapping():
    """Test TOOL_BINARY_NAMES contains key mappings."""
    from scripts.core.tool_registry import TOOL_BINARY_NAMES

    # Some tools have different binary names
    assert TOOL_BINARY_NAMES.get("dependency-check") == "dependency-check.sh"
    assert TOOL_BINARY_NAMES.get("afl++") == "afl-fuzz"
    assert TOOL_BINARY_NAMES.get("semgrep-secrets") == "semgrep"


def test_tool_variants_mapping():
    """Test TOOL_VARIANTS identifies variant tools."""
    from scripts.core.tool_registry import TOOL_VARIANTS

    # Variants share the same binary as their base tool
    assert TOOL_VARIANTS["semgrep-secrets"] == "semgrep"
    assert TOOL_VARIANTS["trivy-rbac"] == "trivy"
    assert TOOL_VARIANTS["checkov-cicd"] == "checkov"


def test_tool_execution_commands():
    """Test TOOL_EXECUTION_COMMANDS has execution requirements."""
    from scripts.core.tool_registry import TOOL_EXECUTION_COMMANDS

    assert "zap" in TOOL_EXECUTION_COMMANDS
    assert "zap.sh" in TOOL_EXECUTION_COMMANDS["zap"]
    assert "cdxgen" in TOOL_EXECUTION_COMMANDS
    assert "node" in TOOL_EXECUTION_COMMANDS["cdxgen"]


# ========== Category 2: ToolInfo Dataclass ==========


def test_toolinfo_defaults():
    """Test ToolInfo has correct default values."""
    from scripts.core.tool_registry import ToolInfo

    tool = ToolInfo(
        name="test-tool",
        version="1.0.0",
        description="A test tool",
        category="binary_tools",
    )

    assert tool.name == "test-tool"
    assert tool.version == "1.0.0"
    assert tool.description == "A test tool"
    assert tool.category == "binary_tools"
    assert tool.critical is False
    assert tool.docker_ready is True
    assert tool.pypi_package is None
    assert tool.github_repo is None
    assert tool.platforms == ["linux", "macos", "windows"]


def test_toolinfo_custom_values():
    """Test ToolInfo can be initialized with custom values."""
    from scripts.core.tool_registry import ToolInfo

    tool = ToolInfo(
        name="custom-tool",
        version="2.0.0",
        description="Custom",
        category="python_tools",
        critical=True,
        docker_ready=False,
        pypi_package="custom-package",
        github_repo="org/custom",
        platforms=["linux", "macos"],
    )

    assert tool.critical is True
    assert tool.docker_ready is False
    assert tool.pypi_package == "custom-package"
    assert tool.github_repo == "org/custom"
    assert tool.platforms == ["linux", "macos"]


def test_toolinfo_get_binary_name_default():
    """Test get_binary_name returns tool name when no override."""
    from scripts.core.tool_registry import ToolInfo

    tool = ToolInfo(
        name="trivy",
        version="0.50.0",
        description="Trivy scanner",
        category="binary_tools",
    )

    assert tool.get_binary_name() == "trivy"


def test_toolinfo_get_binary_name_override():
    """Test get_binary_name returns override when set."""
    from scripts.core.tool_registry import ToolInfo

    tool = ToolInfo(
        name="custom-tool",
        version="1.0.0",
        description="Custom",
        category="binary_tools",
        binary_name="custom-bin",
    )

    assert tool.get_binary_name() == "custom-bin"


def test_toolinfo_get_binary_name_from_mapping():
    """Test get_binary_name uses TOOL_BINARY_NAMES mapping."""
    from scripts.core.tool_registry import ToolInfo

    # afl++ has a binary name mapping to afl-fuzz
    tool = ToolInfo(
        name="afl++",
        version="4.0.0",
        description="AFL++ fuzzer",
        category="binary_tools",
    )

    assert tool.get_binary_name() == "afl-fuzz"


def test_toolinfo_is_variant():
    """Test is_variant correctly identifies variant tools."""
    from scripts.core.tool_registry import ToolInfo

    # semgrep-secrets is a variant of semgrep
    variant_tool = ToolInfo(
        name="semgrep-secrets",
        version="1.0.0",
        description="Semgrep secrets",
        category="binary_tools",
    )
    assert variant_tool.is_variant() is True

    # Regular tool is not a variant
    regular_tool = ToolInfo(
        name="trivy",
        version="0.50.0",
        description="Trivy",
        category="binary_tools",
    )
    assert regular_tool.is_variant() is False


def test_toolinfo_get_base_tool():
    """Test get_base_tool returns correct base for variants."""
    from scripts.core.tool_registry import ToolInfo

    variant = ToolInfo(
        name="trivy-rbac",
        version="0.50.0",
        description="Trivy RBAC",
        category="binary_tools",
    )
    assert variant.get_base_tool() == "trivy"

    regular = ToolInfo(
        name="nuclei",
        version="3.0.0",
        description="Nuclei",
        category="binary_tools",
    )
    assert regular.get_base_tool() == "nuclei"


# ========== Category 3: ToolRegistry ==========


def test_toolregistry_init_default():
    """Test ToolRegistry initializes with default versions.yaml."""
    from scripts.core.tool_registry import ToolRegistry

    # This should find versions.yaml in the repo
    registry = ToolRegistry()
    assert len(registry.get_all_tools()) > 0


def test_toolregistry_init_custom_path(tmp_path):
    """Test ToolRegistry can load from custom path."""
    from scripts.core.tool_registry import ToolRegistry

    # Create a minimal versions.yaml
    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text(
        """
python_tools:
  bandit:
    version: "1.7.5"
    description: "Python security linter"
    critical: true
    pypi_package: bandit

binary_tools:
  trivy:
    version: "0.50.0"
    description: "Container scanner"
    github_repo: aquasecurity/trivy
""",
        encoding="utf-8",
    )

    registry = ToolRegistry(versions_path=versions_file)
    tools = registry.get_all_tools()

    # Should have loaded 2 base tools + virtual tools
    tool_names = [t.name for t in tools]
    assert "bandit" in tool_names
    assert "trivy" in tool_names


def test_toolregistry_get_tool():
    """Test ToolRegistry.get_tool returns correct tool."""
    from scripts.core.tool_registry import ToolRegistry

    registry = ToolRegistry()

    # Get a known tool
    trivy = registry.get_tool("trivy")
    assert trivy is not None
    assert trivy.name == "trivy"

    # Non-existent tool returns None
    assert registry.get_tool("nonexistent-tool") is None


def test_toolregistry_get_tools_for_profile():
    """Test ToolRegistry.get_tools_for_profile returns correct tools."""
    from scripts.core.tool_registry import ToolRegistry, PROFILE_TOOLS

    registry = ToolRegistry()

    fast_tools = registry.get_tools_for_profile("fast")
    expected_count = len(PROFILE_TOOLS["fast"])
    assert len(fast_tools) == expected_count

    # Verify all returned tools have valid names
    for tool in fast_tools:
        assert tool.name in PROFILE_TOOLS["fast"]


def test_toolregistry_get_tools_for_invalid_profile():
    """Test ToolRegistry.get_tools_for_profile with invalid profile."""
    from scripts.core.tool_registry import ToolRegistry

    registry = ToolRegistry()

    # Invalid profile returns empty list
    tools = registry.get_tools_for_profile("nonexistent")
    assert tools == []


def test_toolregistry_get_critical_tools():
    """Test ToolRegistry.get_critical_tools returns critical tools."""
    from scripts.core.tool_registry import ToolRegistry

    registry = ToolRegistry()
    critical_tools = registry.get_critical_tools()

    # All returned tools should have critical=True
    for tool in critical_tools:
        assert tool.critical is True


def test_toolregistry_get_all_tools():
    """Test ToolRegistry.get_all_tools returns all registered tools."""
    from scripts.core.tool_registry import ToolRegistry

    registry = ToolRegistry()
    tools = registry.get_all_tools()

    # Should have a reasonable number of tools
    assert len(tools) >= 10  # At least 10 tools in registry


def test_toolregistry_get_profile_names():
    """Test ToolRegistry.get_profile_names returns profile list."""
    from scripts.core.tool_registry import ToolRegistry

    registry = ToolRegistry()
    profiles = registry.get_profile_names()

    assert "fast" in profiles
    assert "slim" in profiles
    assert "balanced" in profiles
    assert "deep" in profiles


def test_toolregistry_get_profile_tool_count():
    """Test ToolRegistry.get_profile_tool_count returns correct counts."""
    from scripts.core.tool_registry import ToolRegistry, PROFILE_TOOLS

    registry = ToolRegistry()

    for profile in PROFILE_TOOLS:
        count = registry.get_profile_tool_count(profile)
        expected = len(PROFILE_TOOLS[profile])
        assert count == expected, f"Profile {profile} count mismatch"


def test_toolregistry_handles_missing_versions_file():
    """Test ToolRegistry raises error for missing versions.yaml."""
    from scripts.core.tool_registry import ToolRegistry

    with pytest.raises(FileNotFoundError):
        ToolRegistry(versions_path=Path("/nonexistent/versions.yaml"))


def test_toolregistry_adds_virtual_tools(tmp_path):
    """Test ToolRegistry adds virtual tools (variants)."""
    from scripts.core.tool_registry import ToolRegistry

    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text(
        """
binary_tools:
  semgrep:
    version: "1.50.0"
    description: "Semgrep static analyzer"
    github_repo: returntocorp/semgrep
""",
        encoding="utf-8",
    )

    registry = ToolRegistry(versions_path=versions_file)

    # Should have base tool and its variant
    assert registry.get_tool("semgrep") is not None
    semgrep_secrets = registry.get_tool("semgrep-secrets")
    assert semgrep_secrets is not None
    assert semgrep_secrets.description == "Semgrep with secrets configuration"


# ========== Category 4: Platform Detection ==========


def test_detect_platform_linux():
    """Test detect_platform returns linux on Linux systems."""
    from scripts.core.tool_registry import detect_platform

    with patch.object(sys, "platform", "linux"):
        assert detect_platform() == "linux"


def test_detect_platform_macos():
    """Test detect_platform returns macos on macOS systems."""
    from scripts.core.tool_registry import detect_platform

    with patch.object(sys, "platform", "darwin"):
        assert detect_platform() == "macos"


def test_detect_platform_windows():
    """Test detect_platform returns windows on Windows systems."""
    from scripts.core.tool_registry import detect_platform

    with patch.object(sys, "platform", "win32"):
        assert detect_platform() == "windows"


# ========== Category 5: Install Hints ==========


def test_get_install_hint_macos_brew():
    """Test get_install_hint returns brew install for macOS."""
    from scripts.core.tool_registry import get_install_hint, ToolInfo

    tool = ToolInfo(
        name="trivy",
        version="0.50.0",
        description="Trivy",
        category="binary_tools",
        brew_package="trivy",
    )

    hint = get_install_hint(tool, platform="macos")
    assert "brew install trivy" in hint


def test_get_install_hint_macos_pip():
    """Test get_install_hint returns pip install for Python tools on macOS."""
    from scripts.core.tool_registry import get_install_hint, ToolInfo

    tool = ToolInfo(
        name="bandit",
        version="1.7.5",
        description="Bandit",
        category="python_tools",
        pypi_package="bandit",
    )

    hint = get_install_hint(tool, platform="macos")
    assert "pip install bandit" in hint


def test_get_install_hint_linux_apt():
    """Test get_install_hint returns apt install for Linux when available."""
    from scripts.core.tool_registry import get_install_hint, ToolInfo

    tool = ToolInfo(
        name="shellcheck",
        version="0.9.0",
        description="ShellCheck",
        category="binary_tools",
        apt_package="shellcheck",
    )

    hint = get_install_hint(tool, platform="linux")
    assert "apt install shellcheck" in hint


def test_get_install_hint_linux_pip():
    """Test get_install_hint returns pip install for Python tools on Linux."""
    from scripts.core.tool_registry import get_install_hint, ToolInfo

    tool = ToolInfo(
        name="checkov",
        version="3.0.0",
        description="Checkov",
        category="python_tools",
        pypi_package="checkov",
    )

    hint = get_install_hint(tool, platform="linux")
    assert "pip install checkov" in hint


def test_get_install_hint_windows():
    """Test get_install_hint returns pip for Windows Python tools."""
    from scripts.core.tool_registry import get_install_hint, ToolInfo

    tool = ToolInfo(
        name="bandit",
        version="1.7.5",
        description="Bandit",
        category="python_tools",
        pypi_package="bandit",
    )

    hint = get_install_hint(tool, platform="windows")
    assert "pip install bandit" in hint


def test_get_install_hint_npm_package():
    """Test get_install_hint returns npm install for npm packages."""
    from scripts.core.tool_registry import get_install_hint, ToolInfo

    tool = ToolInfo(
        name="cdxgen",
        version="10.0.0",
        description="CycloneDX generator",
        category="binary_tools",
        npm_package="@cyclonedx/cdxgen",
    )

    hint = get_install_hint(tool, platform="linux")
    assert "npm install -g @cyclonedx/cdxgen" in hint


def test_get_install_hint_github_repo_fallback():
    """Test get_install_hint falls back to GitHub repo link."""
    from scripts.core.tool_registry import get_install_hint, ToolInfo

    tool = ToolInfo(
        name="custom-tool",
        version="1.0.0",
        description="Custom",
        category="binary_tools",
        github_repo="org/custom-tool",
    )

    hint = get_install_hint(tool, platform="linux")
    assert "https://github.com/org/custom-tool" in hint


def test_get_install_hint_with_notes():
    """Test get_install_hint includes install notes when present."""
    from scripts.core.tool_registry import get_install_hint, ToolInfo

    tool = ToolInfo(
        name="zap",
        version="2.14.0",
        description="OWASP ZAP",
        category="binary_tools",
        install_notes="Requires Java 11+",
    )

    hint = get_install_hint(tool, platform="linux")
    assert "Requires Java 11+" in hint


def test_get_install_hint_auto_detect_platform():
    """Test get_install_hint auto-detects platform when not specified."""
    from scripts.core.tool_registry import get_install_hint, ToolInfo

    tool = ToolInfo(
        name="bandit",
        version="1.7.5",
        description="Bandit",
        category="python_tools",
        pypi_package="bandit",
    )

    # Should not raise, should auto-detect platform
    hint = get_install_hint(tool)
    assert len(hint) > 0


# ========== Category 6: Edge Cases ==========


def test_toolregistry_handles_malformed_yaml(tmp_path):
    """Test ToolRegistry handles malformed YAML gracefully."""
    from scripts.core.tool_registry import ToolRegistry

    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text("invalid: yaml: content:", encoding="utf-8")

    with pytest.raises(Exception):
        ToolRegistry(versions_path=versions_file)


def test_toolregistry_handles_empty_yaml(tmp_path):
    """Test ToolRegistry raises error for empty YAML file."""
    from scripts.core.tool_registry import ToolRegistry

    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text("", encoding="utf-8")

    # Empty YAML file returns None, which is invalid for a versions file
    with pytest.raises((AttributeError, TypeError)):
        ToolRegistry(versions_path=versions_file)


def test_toolregistry_handles_non_dict_category(tmp_path):
    """Test ToolRegistry handles non-dict category gracefully."""
    from scripts.core.tool_registry import ToolRegistry

    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text(
        """
python_tools:
  - not
  - a
  - dict
binary_tools:
  trivy:
    version: "0.50.0"
    description: "Trivy"
""",
        encoding="utf-8",
    )

    # Should skip the malformed category and load the valid one
    registry = ToolRegistry(versions_path=versions_file)
    tools = registry.get_all_tools()
    tool_names = [t.name for t in tools]
    assert "trivy" in tool_names


def test_toolregistry_handles_non_dict_tool_entry(tmp_path):
    """Test ToolRegistry handles non-dict tool entries gracefully."""
    from scripts.core.tool_registry import ToolRegistry

    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text(
        """
binary_tools:
  invalid_tool: "just a string"
  valid_tool:
    version: "1.0.0"
    description: "Valid tool"
""",
        encoding="utf-8",
    )

    registry = ToolRegistry(versions_path=versions_file)
    tools = registry.get_all_tools()
    tool_names = [t.name for t in tools]

    assert "valid_tool" in tool_names
    assert "invalid_tool" not in tool_names


def test_toolregistry_parses_npm_from_pypi_field(tmp_path):
    """Test ToolRegistry parses npm packages from @ prefixed pypi_package."""
    from scripts.core.tool_registry import ToolRegistry

    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text(
        """
binary_tools:
  cdxgen:
    version: "10.0.0"
    description: "CycloneDX generator"
    pypi_package: "@cyclonedx/cdxgen"
""",
        encoding="utf-8",
    )

    registry = ToolRegistry(versions_path=versions_file)
    tool = registry.get_tool("cdxgen")

    assert tool is not None
    assert tool.npm_package == "@cyclonedx/cdxgen"
    assert tool.pypi_package is None
