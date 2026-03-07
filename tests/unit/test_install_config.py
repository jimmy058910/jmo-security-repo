"""Tests for scripts.core.install_config module.

Validates that tool URL constants, timeout values, isolated venv configs,
and dependency install commands are well-formed.
"""

from __future__ import annotations

import pytest

from scripts.core.install_config import (
    BINARY_URLS,
    CLEANUP_RETRY_BACKOFF_FACTOR,
    DEPENDENCY_DISPLAY_NAMES,
    DEPENDENCY_INSTALL_COMMANDS,
    DEPENDENCY_MANUAL_COMMANDS,
    DEPENDENCY_VERIFY_COMMANDS,
    DOWNLOAD_CHUNK_SIZE,
    DOWNLOAD_TIMEOUT_SECONDS,
    EXTRACT_APP_URLS,
    INSTALL_PRIORITIES,
    INSTALL_SCRIPTS,
    ISOLATED_TOOLS,
    MAX_CLEANUP_RETRIES,
    MAX_PARALLEL_WORKERS,
    NPM_INSTALL_TIMEOUT_SECONDS,
    PIP_INSTALL_TIMEOUT_SECONDS,
    SPECIAL_INSTALL,
    SUBPROCESS_DEFAULT_TIMEOUT,
)


class TestTimeoutConstants:
    """Verify timeout and limit constants are positive integers."""

    @pytest.mark.parametrize(
        "name,value",
        [
            ("DOWNLOAD_TIMEOUT_SECONDS", DOWNLOAD_TIMEOUT_SECONDS),
            ("PIP_INSTALL_TIMEOUT_SECONDS", PIP_INSTALL_TIMEOUT_SECONDS),
            ("NPM_INSTALL_TIMEOUT_SECONDS", NPM_INSTALL_TIMEOUT_SECONDS),
            ("SUBPROCESS_DEFAULT_TIMEOUT", SUBPROCESS_DEFAULT_TIMEOUT),
            ("DOWNLOAD_CHUNK_SIZE", DOWNLOAD_CHUNK_SIZE),
            ("MAX_PARALLEL_WORKERS", MAX_PARALLEL_WORKERS),
            ("MAX_CLEANUP_RETRIES", MAX_CLEANUP_RETRIES),
        ],
    )
    def test_positive_integers(self, name: str, value: int) -> None:
        assert isinstance(value, int), f"{name} should be int, got {type(value)}"
        assert value > 0, f"{name} should be positive, got {value}"

    def test_backoff_factor_is_positive_float(self) -> None:
        assert isinstance(CLEANUP_RETRY_BACKOFF_FACTOR, (int, float))
        assert CLEANUP_RETRY_BACKOFF_FACTOR > 0


class TestBinaryUrls:
    """Verify BINARY_URLS entries are well-formed."""

    def test_non_empty(self) -> None:
        assert len(BINARY_URLS) > 0

    @pytest.mark.parametrize("tool", list(BINARY_URLS.keys()))
    def test_url_values_are_non_empty_strings(self, tool: str) -> None:
        value = BINARY_URLS[tool]
        if isinstance(value, str):
            assert len(value) > 0, f"{tool} URL is empty"
            assert value.startswith(
                "https://"
            ), f"{tool} URL doesn't start with https://"
        elif isinstance(value, dict):
            assert len(value) > 0, f"{tool} has empty platform dict"
            for platform, url in value.items():
                assert (
                    isinstance(url, str) and len(url) > 0
                ), f"{tool}/{platform} URL is empty"
                assert url.startswith(
                    "https://"
                ), f"{tool}/{platform} URL doesn't start with https://"
        else:
            pytest.fail(f"{tool}: unexpected type {type(value)}")

    @pytest.mark.parametrize("tool", list(BINARY_URLS.keys()))
    def test_urls_contain_version_placeholder(self, tool: str) -> None:
        """All binary URLs should have a {version} placeholder for reproducible installs."""
        value = BINARY_URLS[tool]
        urls = [value] if isinstance(value, str) else list(value.values())
        for url in urls:
            assert "{version}" in url, f"{tool} URL missing {{version}} placeholder"


class TestExtractAppUrls:
    """Verify EXTRACT_APP_URLS entries."""

    def test_non_empty(self) -> None:
        assert len(EXTRACT_APP_URLS) > 0

    @pytest.mark.parametrize("tool", list(EXTRACT_APP_URLS.keys()))
    def test_url_values_well_formed(self, tool: str) -> None:
        value = EXTRACT_APP_URLS[tool]
        if isinstance(value, str):
            assert value.startswith("https://")
        elif isinstance(value, dict):
            for platform, url in value.items():
                assert isinstance(url, str) and url.startswith(
                    "https://"
                ), f"{tool}/{platform} bad URL"

    def test_extract_app_tools_are_in_special_install(self) -> None:
        """Every tool in EXTRACT_APP_URLS should be in SPECIAL_INSTALL with 'extract_app'."""
        for tool in EXTRACT_APP_URLS:
            assert tool in SPECIAL_INSTALL, f"{tool} not in SPECIAL_INSTALL"
            assert (
                SPECIAL_INSTALL[tool] == "extract_app"
            ), f"{tool} should have 'extract_app' method"


class TestInstallScripts:
    """Verify INSTALL_SCRIPTS entries."""

    def test_non_empty(self) -> None:
        assert len(INSTALL_SCRIPTS) > 0

    @pytest.mark.parametrize("tool", list(INSTALL_SCRIPTS.keys()))
    def test_scripts_are_https_urls(self, tool: str) -> None:
        url = INSTALL_SCRIPTS[tool]
        assert isinstance(url, str)
        assert url.startswith("https://"), f"{tool} script URL not HTTPS"


class TestInstallPriorities:
    """Verify INSTALL_PRIORITIES per platform."""

    def test_has_all_platforms(self) -> None:
        for platform in ("linux", "macos", "windows"):
            assert platform in INSTALL_PRIORITIES, f"Missing platform: {platform}"

    @pytest.mark.parametrize("platform", list(INSTALL_PRIORITIES.keys()))
    def test_priorities_are_non_empty_lists(self, platform: str) -> None:
        methods = INSTALL_PRIORITIES[platform]
        assert isinstance(methods, list)
        assert len(methods) > 0
        for method in methods:
            assert isinstance(method, str) and len(method) > 0


class TestIsolatedTools:
    """Verify ISOLATED_TOOLS configuration."""

    def test_non_empty(self) -> None:
        assert len(ISOLATED_TOOLS) > 0

    @pytest.mark.parametrize("tool", list(ISOLATED_TOOLS.keys()))
    def test_required_keys(self, tool: str) -> None:
        config = ISOLATED_TOOLS[tool]
        assert "package" in config, f"{tool} missing 'package' key"
        assert "conflicts_with" in config, f"{tool} missing 'conflicts_with' key"
        assert "reason" in config, f"{tool} missing 'reason' key"

    @pytest.mark.parametrize("tool", list(ISOLATED_TOOLS.keys()))
    def test_package_is_string(self, tool: str) -> None:
        assert isinstance(ISOLATED_TOOLS[tool]["package"], str)
        assert len(ISOLATED_TOOLS[tool]["package"]) > 0

    @pytest.mark.parametrize("tool", list(ISOLATED_TOOLS.keys()))
    def test_conflicts_is_list(self, tool: str) -> None:
        conflicts = ISOLATED_TOOLS[tool]["conflicts_with"]
        assert isinstance(conflicts, list)
        assert len(conflicts) > 0

    def test_conflicts_are_symmetric(self) -> None:
        """If A conflicts with B, B should conflict with A."""
        for tool, config in ISOLATED_TOOLS.items():
            for conflict in config["conflicts_with"]:
                if conflict in ISOLATED_TOOLS:
                    assert (
                        tool in ISOLATED_TOOLS[conflict]["conflicts_with"]
                    ), f"{tool} conflicts with {conflict} but not vice versa"


class TestSpecialInstall:
    """Verify SPECIAL_INSTALL dict."""

    def test_non_empty(self) -> None:
        assert len(SPECIAL_INSTALL) > 0

    @pytest.mark.parametrize("tool", list(SPECIAL_INSTALL.keys()))
    def test_values_are_known_methods(self, tool: str) -> None:
        known_methods = {"extract_app", "manual", "docker", "clone"}
        assert (
            SPECIAL_INSTALL[tool] in known_methods
        ), f"{tool} has unknown install method: {SPECIAL_INSTALL[tool]}"


class TestDependencyConfig:
    """Verify dependency auto-install configuration."""

    def test_install_commands_has_java_and_node(self) -> None:
        assert "java" in DEPENDENCY_INSTALL_COMMANDS
        assert "node" in DEPENDENCY_INSTALL_COMMANDS

    def test_verify_commands_has_java_and_node(self) -> None:
        assert "java" in DEPENDENCY_VERIFY_COMMANDS
        assert "node" in DEPENDENCY_VERIFY_COMMANDS

    def test_display_names_has_java_and_node(self) -> None:
        assert "java" in DEPENDENCY_DISPLAY_NAMES
        assert "node" in DEPENDENCY_DISPLAY_NAMES

    def test_manual_commands_has_java_and_node(self) -> None:
        assert "java" in DEPENDENCY_MANUAL_COMMANDS
        assert "node" in DEPENDENCY_MANUAL_COMMANDS

    @pytest.mark.parametrize("dep", list(DEPENDENCY_VERIFY_COMMANDS.keys()))
    def test_verify_commands_are_lists(self, dep: str) -> None:
        cmd = DEPENDENCY_VERIFY_COMMANDS[dep]
        assert isinstance(cmd, list)
        assert len(cmd) > 0

    @pytest.mark.parametrize("dep", list(DEPENDENCY_INSTALL_COMMANDS.keys()))
    def test_install_commands_cover_platforms(self, dep: str) -> None:
        platforms = DEPENDENCY_INSTALL_COMMANDS[dep]
        assert isinstance(platforms, dict)
        # Should have at least linux and one other platform
        assert "linux" in platforms
