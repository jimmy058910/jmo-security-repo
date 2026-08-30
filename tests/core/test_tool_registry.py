"""Tests for scripts/core/tool_registry.py platform filtering functions.

These tests verify the platform compatibility checking added in Chunk 2
of the wizard tool infrastructure improvements.
"""

from scripts.core.tool_registry import (
    PROFILE_TOOLS,
    TOOL_PLATFORM_REQUIREMENTS,
    get_platform_status,
    get_skipped_tools_for_profile,
    get_tools_for_profile_filtered,
)


class TestToolPlatformRequirements:
    """Tests for TOOL_PLATFORM_REQUIREMENTS dict structure."""

    # `test_platform_requirements_dict_exists` was deleted here (#979). It
    # asserted `isinstance(dict)` and `len(...) > 0` on a module-level literal,
    # and unlike the parametrized canaries elsewhere in this sweep it was
    # genuinely redundant: `test_known_linux_only_tools` below indexes the dict
    # directly, so an emptied constant reddens it rather than skipping.

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
        # Not merely "a reason exists" -- the reason a user reads must name the
        # actual constraint, and `len(...) > 0` passed for any string at all.
        assert "Linux kernel" in status["reason"]
        assert status["workarounds"] == ["docker"]

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

    def test_fast_profile_filters_platform_specific(self):
        """Fast profile filters platform-specific tools like shellcheck on Windows."""
        # Fast profile includes shellcheck which is linux/macos only
        windows_tools = get_tools_for_profile_filtered("fast", "windows")
        linux_tools = get_tools_for_profile_filtered("fast", "linux")
        # shellcheck is excluded on Windows (linux/macos only)
        assert "shellcheck" not in windows_tools
        assert "shellcheck" in linux_tools
        # Universal tools should be in both
        assert "trivy" in windows_tools
        assert "trivy" in linux_tools
        assert "semgrep" in windows_tools
        assert "semgrep" in linux_tools

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

    def test_skipped_reason_matches_the_platform_status_reason(self):
        """The skip list and the per-tool status must give the same reason.

        These are two producers of one fact: `jmo scan` prints the skip reason,
        `jmo tools check` prints the status reason, and a user comparing them
        should not see two different explanations. The replaced
        `len(reason) > 0` accepted any non-empty string, so the two could drift
        apart -- or one could degrade to a placeholder -- with the loop still
        green for every tool.
        """
        skipped = get_skipped_tools_for_profile("deep", "windows")
        assert skipped, "deep/windows must skip the Linux-only tools"
        for tool_name, reason in skipped:
            assert reason == get_platform_status(tool_name, "windows")["reason"]

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
                skipped = {
                    t[0] for t in get_skipped_tools_for_profile(profile, platform)
                }

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
        # Windows should have fewer (missing falco, afl++, noseyparker)
        assert windows_count < linux_count
