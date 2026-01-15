"""Tests for scripts/core/tool_registry.py platform filtering functions.

These tests verify the platform compatibility checking added in Chunk 2
of the wizard tool infrastructure improvements.
"""

from scripts.core.tool_registry import (
    PROFILE_TOOLS,
    TOOL_PLATFORM_REQUIREMENTS,
    get_platform_status,
    get_tools_for_profile_filtered,
    get_skipped_tools_for_profile,
)


class TestToolPlatformRequirements:
    """Tests for TOOL_PLATFORM_REQUIREMENTS dict structure."""

    def test_platform_requirements_dict_exists(self):
        """TOOL_PLATFORM_REQUIREMENTS should be a non-empty dict."""
        assert isinstance(TOOL_PLATFORM_REQUIREMENTS, dict)
        assert len(TOOL_PLATFORM_REQUIREMENTS) > 0

    def test_known_linux_only_tools(self):
        """Linux-only tools should be defined."""
        assert "falco" in TOOL_PLATFORM_REQUIREMENTS
        assert "afl++" in TOOL_PLATFORM_REQUIREMENTS
        # Verify they're Linux-only
        assert TOOL_PLATFORM_REQUIREMENTS["falco"]["platforms"] == ["linux"]
        assert TOOL_PLATFORM_REQUIREMENTS["afl++"]["platforms"] == ["linux"]

    def test_known_docker_only_tools(self):
        """Docker-only tools should have empty platforms list."""
        assert "mobsf" in TOOL_PLATFORM_REQUIREMENTS
        assert "akto" in TOOL_PLATFORM_REQUIREMENTS
        assert TOOL_PLATFORM_REQUIREMENTS["mobsf"]["platforms"] == []
        assert TOOL_PLATFORM_REQUIREMENTS["akto"]["platforms"] == []

    def test_tools_with_platform_specific_requirements(self):
        """Tools with platform-specific requirements should be defined."""
        assert "lynis" in TOOL_PLATFORM_REQUIREMENTS
        assert "prowler" in TOOL_PLATFORM_REQUIREMENTS
        # Lynis requires bash on Windows
        assert "windows_requires" in TOOL_PLATFORM_REQUIREMENTS["lynis"]
        assert "bash" in TOOL_PLATFORM_REQUIREMENTS["lynis"]["windows_requires"]


class TestGetPlatformStatus:
    """Tests for get_platform_status() function."""

    def test_unknown_tool_is_supported(self):
        """Tools not in requirements dict should be supported everywhere."""
        status = get_platform_status("trivy", "windows")
        assert status["supported"] is True
        assert status["reason"] is None

    def test_linux_only_tool_on_linux(self):
        """Linux-only tools should be supported on Linux."""
        status = get_platform_status("falco", "linux")
        assert status["supported"] is True

    def test_linux_only_tool_on_windows(self):
        """Linux-only tools should NOT be supported on Windows."""
        status = get_platform_status("falco", "windows")
        assert status["supported"] is False
        assert status["reason"] is not None
        assert len(status["reason"]) > 0
        assert "workarounds" in status

    def test_linux_only_tool_on_macos(self):
        """Linux-only tools should NOT be supported on macOS."""
        status = get_platform_status("falco", "macos")
        assert status["supported"] is False
        assert "docker" in status["workarounds"]

    def test_docker_only_tool_on_any_platform(self):
        """Docker-only tools (empty platforms) should NOT be supported."""
        for platform in ["linux", "macos", "windows"]:
            status = get_platform_status("mobsf", platform)
            assert status["supported"] is False
            assert "docker" in status["workarounds"]

    def test_tool_with_platform_requirements(self):
        """Tools with platform-specific requirements should include them."""
        status = get_platform_status("lynis", "windows")
        assert status["supported"] is True  # Supported but with requirements
        assert "requirements" in status
        assert "bash" in status["requirements"]

    def test_noseyparker_windows_unsupported(self):
        """noseyparker should NOT be supported on Windows."""
        status = get_platform_status("noseyparker", "windows")
        assert status["supported"] is False
        assert "docker" in status["workarounds"]

    def test_noseyparker_linux_supported(self):
        """noseyparker should be supported on Linux."""
        status = get_platform_status("noseyparker", "linux")
        assert status["supported"] is True


class TestGetToolsForProfileFiltered:
    """Tests for get_tools_for_profile_filtered() function."""

    def test_no_platform_filter_returns_all(self):
        """Without platform filter, should return all tools for profile."""
        all_tools = get_tools_for_profile_filtered("deep", None)
        assert all_tools == PROFILE_TOOLS["deep"]

    def test_platform_filter_removes_incompatible(self):
        """Platform filter should remove incompatible tools."""
        windows_tools = get_tools_for_profile_filtered("deep", "windows")
        # Linux-only tools should be removed
        assert "falco" not in windows_tools
        assert "afl++" not in windows_tools
        # Universal tools should remain
        assert "trivy" in windows_tools
        assert "semgrep" in windows_tools

    def test_linux_filter_keeps_linux_tools(self):
        """Linux filter should keep Linux-only tools."""
        linux_tools = get_tools_for_profile_filtered("deep", "linux")
        assert "falco" in linux_tools
        assert "afl++" in linux_tools

    def test_fast_profile_not_affected(self):
        """Fast profile has no platform-specific tools."""
        # Fast profile uses widely available tools
        windows_tools = get_tools_for_profile_filtered("fast", "windows")
        linux_tools = get_tools_for_profile_filtered("fast", "linux")
        # Both should have same tools since fast profile has no platform-specific tools
        assert set(windows_tools) == set(linux_tools)

    def test_invalid_profile_returns_empty(self):
        """Invalid profile should return empty list."""
        tools = get_tools_for_profile_filtered("nonexistent", "linux")
        assert tools == []


class TestGetSkippedToolsForProfile:
    """Tests for get_skipped_tools_for_profile() function."""

    def test_linux_skips_nothing(self):
        """Linux should skip minimal tools (only Docker-only ones)."""
        skipped = get_skipped_tools_for_profile("deep", "linux")
        skipped_names = [t[0] for t in skipped]
        # Docker-only tools should be skipped
        assert "mobsf" in skipped_names
        assert "akto" in skipped_names
        # Linux-only tools should NOT be skipped
        assert "falco" not in skipped_names
        assert "afl++" not in skipped_names

    def test_windows_skips_linux_only(self):
        """Windows should skip Linux-only tools."""
        skipped = get_skipped_tools_for_profile("deep", "windows")
        skipped_names = [t[0] for t in skipped]
        # Linux-only tools should be skipped
        assert "falco" in skipped_names
        assert "afl++" in skipped_names
        # Universal tools should NOT be skipped
        assert "trivy" not in skipped_names

    def test_skipped_includes_reasons(self):
        """Skipped tools should include reasons."""
        skipped = get_skipped_tools_for_profile("deep", "windows")
        for tool_name, reason in skipped:
            assert isinstance(reason, str)
            assert len(reason) > 0

    def test_fast_profile_no_skipped_on_linux(self):
        """Fast profile should have no skipped tools on Linux."""
        skipped = get_skipped_tools_for_profile("fast", "linux")
        assert len(skipped) == 0

    def test_invalid_profile_returns_empty(self):
        """Invalid profile should return empty list."""
        skipped = get_skipped_tools_for_profile("nonexistent", "windows")
        assert skipped == []


class TestIntegration:
    """Integration tests for platform filtering."""

    def test_filtered_plus_skipped_equals_total(self):
        """Filtered tools + skipped tools should equal total profile tools."""
        for profile in ["fast", "slim", "balanced", "deep"]:
            for platform in ["linux", "macos", "windows"]:
                all_tools = set(PROFILE_TOOLS.get(profile, []))
                filtered = set(get_tools_for_profile_filtered(profile, platform))
                skipped = set(
                    t[0] for t in get_skipped_tools_for_profile(profile, platform)
                )

                # Filtered and skipped should be disjoint
                assert filtered.isdisjoint(skipped), f"Overlap in {profile}/{platform}"

                # Union should equal all tools
                assert (
                    filtered | skipped == all_tools
                ), f"Mismatch in {profile}/{platform}"

    def test_windows_deep_profile_count(self):
        """Deep profile on Windows should have fewer tools than Linux."""
        windows_count = len(get_tools_for_profile_filtered("deep", "windows"))
        linux_count = len(get_tools_for_profile_filtered("deep", "linux"))
        # Windows should have fewer (missing falco, afl++, noseyparker, bearer)
        assert windows_count < linux_count
