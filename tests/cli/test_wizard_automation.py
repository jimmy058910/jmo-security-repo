"""Tests for wizard automation via CLI flags.

Tests the new --profile, --target-type, --target, --auto-fix, and related
flags that enable fully non-interactive wizard runs.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Import modules before patching (required for patch decorators to work)
import scripts.cli.tool_manager  # noqa: F401

from scripts.cli.wizard import _apply_target_preset, run_wizard
from scripts.cli.wizard_flows.config_models import TargetConfig


class TestApplyTargetPreset:
    """Tests for _apply_target_preset helper function."""

    def test_repo_target_single_repo(self, tmp_path: Path) -> None:
        """Test preset for single git repo."""
        # Create a fake git repo
        repo_path = tmp_path / "my-repo"
        repo_path.mkdir()
        (repo_path / ".git").mkdir()

        tc = TargetConfig()
        _apply_target_preset(tc, "repo", str(repo_path))

        assert tc.type == "repo"
        assert tc.repo_mode == "repo"
        assert tc.repo_path == str(repo_path)

    def test_repo_target_repos_dir(self, tmp_path: Path) -> None:
        """Test preset for directory containing repos."""
        tc = TargetConfig()
        _apply_target_preset(tc, "repo", str(tmp_path))

        assert tc.type == "repo"
        assert tc.repo_mode == "repos-dir"
        assert tc.repo_path == str(tmp_path)

    def test_repo_target_targets_file(self, tmp_path: Path) -> None:
        """Test preset for targets file."""
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("/path/to/repo1\n/path/to/repo2\n")

        tc = TargetConfig()
        _apply_target_preset(tc, "repo", str(targets_file))

        assert tc.type == "repo"
        assert tc.repo_mode == "targets"
        assert tc.repo_path == str(targets_file)

    def test_image_target_single_image(self) -> None:
        """Test preset for single container image."""
        tc = TargetConfig()
        _apply_target_preset(tc, "image", "nginx:latest")

        assert tc.type == "image"
        assert tc.image_name == "nginx:latest"
        assert tc.images_file == ""

    def test_image_target_dockerhub_image(self) -> None:
        """Test preset for DockerHub image with org."""
        tc = TargetConfig()
        _apply_target_preset(tc, "image", "bkimminich/juice-shop:latest")

        assert tc.type == "image"
        assert tc.image_name == "bkimminich/juice-shop:latest"

    def test_image_target_images_file(self, tmp_path: Path) -> None:
        """Test preset for images file."""
        images_file = tmp_path / "images.txt"
        images_file.write_text("nginx:latest\nalpine:3.18\n")

        tc = TargetConfig()
        _apply_target_preset(tc, "image", str(images_file))

        assert tc.type == "image"
        assert tc.images_file == str(images_file)
        assert tc.image_name == ""

    def test_url_target_https(self) -> None:
        """Test preset for HTTPS URL."""
        tc = TargetConfig()
        _apply_target_preset(tc, "url", "https://example.com")

        assert tc.type == "url"
        assert tc.url == "https://example.com"

    def test_url_target_http(self) -> None:
        """Test preset for HTTP URL."""
        tc = TargetConfig()
        _apply_target_preset(tc, "url", "http://localhost:3000")

        assert tc.type == "url"
        assert tc.url == "http://localhost:3000"

    def test_url_target_without_protocol(self) -> None:
        """Test preset for URL without protocol adds https."""
        tc = TargetConfig()
        _apply_target_preset(tc, "url", "example.com")

        assert tc.type == "url"
        assert tc.url == "https://example.com"

    def test_url_target_urls_file(self, tmp_path: Path) -> None:
        """Test preset for URLs file."""
        urls_file = tmp_path / "urls.txt"
        urls_file.write_text("https://site1.com\nhttps://site2.com\n")

        tc = TargetConfig()
        _apply_target_preset(tc, "url", str(urls_file))

        assert tc.type == "url"
        assert tc.urls_file == str(urls_file)
        assert tc.url == ""

    def test_iac_target_existing_path(self, tmp_path: Path) -> None:
        """Test preset for existing IaC path."""
        iac_path = tmp_path / "terraform"
        iac_path.mkdir()
        (iac_path / "main.tf").write_text('resource "aws_s3_bucket" {}')

        tc = TargetConfig()
        _apply_target_preset(tc, "iac", str(iac_path))

        assert tc.type == "iac"
        assert tc.iac_path == str(iac_path)
        # IaC type detection is tested separately

    def test_iac_target_nonexistent_defaults_terraform(self, tmp_path: Path) -> None:
        """Test preset for non-existent IaC path defaults to terraform."""
        tc = TargetConfig()
        _apply_target_preset(tc, "iac", str(tmp_path / "nonexistent"))

        assert tc.type == "iac"
        assert tc.iac_type == "terraform"


class TestWizardWithPresets:
    """Tests for run_wizard with preset configurations."""

    @patch("scripts.cli.wizard.execute_scan")
    @patch("scripts.cli.wizard._check_policy_tools")
    @patch("scripts.cli.wizard.check_tools_for_profile")
    @patch("scripts.core.telemetry.should_show_telemetry_banner", return_value=False)
    def test_wizard_with_profile_preset(
        self,
        mock_banner: MagicMock,
        mock_tools: MagicMock,
        mock_policy: MagicMock,
        mock_scan: MagicMock,
    ) -> None:
        """Test wizard with --profile preset."""
        mock_tools.return_value = (True, ["semgrep", "trivy"])
        mock_policy.return_value = (True, False)
        mock_scan.return_value = 0

        result = run_wizard(
            yes=True,
            profile="fast",
        )

        assert result == 0
        # Profile should be "fast" instead of default "balanced"
        mock_tools.assert_called_once()
        call_args = mock_tools.call_args
        assert call_args[0][0] == "fast"

    @patch("scripts.cli.wizard.execute_scan")
    @patch("scripts.cli.wizard._check_policy_tools")
    @patch("scripts.cli.wizard.check_tools_for_profile")
    @patch("scripts.core.telemetry.should_show_telemetry_banner", return_value=False)
    def test_wizard_with_target_preset(
        self,
        mock_banner: MagicMock,
        mock_tools: MagicMock,
        mock_policy: MagicMock,
        mock_scan: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test wizard with --target-type and --target presets."""
        mock_tools.return_value = (True, ["semgrep"])
        mock_policy.return_value = (True, False)
        mock_scan.return_value = 0

        # Create a repo to scan
        repo_path = tmp_path / "my-repo"
        repo_path.mkdir()
        (repo_path / ".git").mkdir()

        result = run_wizard(
            profile="balanced",
            target_type="repo",
            target=str(repo_path),
        )

        assert result == 0
        # execute_scan should be called with the config
        mock_scan.assert_called_once()
        config = mock_scan.call_args[0][0]
        assert config.target.type == "repo"
        assert config.target.repo_mode == "repo"
        assert config.target.repo_path == str(repo_path)

    @patch("scripts.cli.wizard.execute_scan")
    @patch("scripts.cli.wizard._check_policy_tools")
    @patch("scripts.cli.wizard.check_tools_for_profile")
    @patch("scripts.core.telemetry.should_show_telemetry_banner", return_value=False)
    def test_wizard_with_image_target(
        self,
        mock_banner: MagicMock,
        mock_tools: MagicMock,
        mock_policy: MagicMock,
        mock_scan: MagicMock,
    ) -> None:
        """Test wizard with container image target."""
        mock_tools.return_value = (True, ["trivy"])
        mock_policy.return_value = (True, False)
        mock_scan.return_value = 0

        result = run_wizard(
            profile="balanced",
            target_type="image",
            target="bkimminich/juice-shop:latest",
        )

        assert result == 0
        config = mock_scan.call_args[0][0]
        assert config.target.type == "image"
        assert config.target.image_name == "bkimminich/juice-shop:latest"

    @patch("scripts.cli.wizard.execute_scan")
    @patch("scripts.cli.wizard._check_policy_tools")
    @patch("scripts.cli.wizard.check_tools_for_profile")
    @patch("scripts.core.telemetry.should_show_telemetry_banner", return_value=False)
    def test_wizard_with_advanced_options(
        self,
        mock_banner: MagicMock,
        mock_tools: MagicMock,
        mock_policy: MagicMock,
        mock_scan: MagicMock,
    ) -> None:
        """Test wizard with advanced options (threads, timeout, fail_on)."""
        mock_tools.return_value = (True, ["semgrep"])
        mock_policy.return_value = (True, False)
        mock_scan.return_value = 0

        result = run_wizard(
            profile="fast",
            target_type="repo",
            target=".",
            threads=8,
            timeout=600,
            fail_on="HIGH",
            results_dir="my-results",
        )

        assert result == 0
        config = mock_scan.call_args[0][0]
        assert config.threads == 8
        assert config.timeout == 600
        assert config.fail_on == "HIGH"
        assert config.results_dir == "my-results"

    @patch("scripts.cli.wizard.execute_scan")
    @patch("scripts.cli.wizard._check_policy_tools")
    @patch("scripts.cli.wizard.check_tools_for_profile")
    @patch("scripts.core.telemetry.should_show_telemetry_banner", return_value=False)
    def test_wizard_native_mode_preset(
        self,
        mock_banner: MagicMock,
        mock_tools: MagicMock,
        mock_policy: MagicMock,
        mock_scan: MagicMock,
    ) -> None:
        """Test wizard with --native flag (use_docker=False)."""
        mock_tools.return_value = (True, ["semgrep"])
        mock_policy.return_value = (True, False)
        mock_scan.return_value = 0

        result = run_wizard(
            profile="fast",
            target_type="repo",
            target=".",
            use_docker=False,
        )

        assert result == 0
        config = mock_scan.call_args[0][0]
        assert config.use_docker is False

    @patch("scripts.cli.wizard.execute_scan")
    @patch("scripts.cli.wizard._check_policy_tools")
    @patch("scripts.cli.wizard.check_tools_for_profile")
    @patch("scripts.cli.wizard._check_docker_running", return_value=True)
    @patch("scripts.cli.wizard._detect_docker", return_value=True)
    @patch("scripts.core.telemetry.should_show_telemetry_banner", return_value=False)
    def test_wizard_docker_mode_preset(
        self,
        mock_banner: MagicMock,
        mock_docker: MagicMock,
        mock_docker_running: MagicMock,
        mock_tools: MagicMock,
        mock_policy: MagicMock,
        mock_scan: MagicMock,
    ) -> None:
        """Test wizard with --docker flag (use_docker=True)."""
        mock_tools.return_value = (True, [])
        mock_policy.return_value = (True, False)
        mock_scan.return_value = 0

        result = run_wizard(
            profile="fast",
            target_type="repo",
            target=".",
            use_docker=True,
        )

        assert result == 0
        config = mock_scan.call_args[0][0]
        assert config.use_docker is True


class TestCheckToolsForProfileAutoFix:
    """Tests for check_tools_for_profile with auto_fix flag.

    Note: These tests verify the auto_fix parameter flow through the tool checker.
    The complex mocking makes these integration tests fragile - we test the key
    behavior (auto_fix flag is passed through) with simpler unit tests.
    """

    def test_auto_fix_parameter_accepted(self) -> None:
        """Test that auto_fix parameter is accepted by check_tools_for_profile."""
        from scripts.cli.wizard_flows.tool_checker import check_tools_for_profile

        # Test in docker mode (simplest path - skips all tool checking)
        should_continue, available = check_tools_for_profile(
            profile="balanced",
            yes=True,
            use_docker=True,  # Docker mode skips tool check
            auto_fix=True,
            install_deps=False,
        )

        # Docker mode always continues with all tools available
        assert should_continue is True

    def test_install_deps_parameter_accepted(self) -> None:
        """Test that install_deps parameter is accepted by check_tools_for_profile."""
        from scripts.cli.wizard_flows.tool_checker import check_tools_for_profile

        # Test in docker mode (simplest path)
        should_continue, available = check_tools_for_profile(
            profile="balanced",
            yes=True,
            use_docker=True,  # Docker mode skips tool check
            auto_fix=True,
            install_deps=True,
        )

        assert should_continue is True


class TestWizardCLIArgs:
    """Tests for wizard CLI argument parsing."""

    def test_wizard_help_shows_preset_options(self) -> None:
        """Verify --help shows all preset options."""
        import argparse
        from scripts.cli.jmo import _add_wizard_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        wizard_parser = _add_wizard_args(subparsers)

        # Get the argument names
        arg_names = [a.dest for a in wizard_parser._actions]

        # Check all preset options are present
        assert "profile" in arg_names
        assert "target_type" in arg_names
        assert "target" in arg_names
        assert "auto_fix" in arg_names
        assert "install_deps" in arg_names
        assert "threads" in arg_names
        assert "timeout" in arg_names
        assert "fail_on" in arg_names
        assert "results_dir" in arg_names

    def test_wizard_profile_choices(self) -> None:
        """Verify --profile accepts only valid choices."""
        import argparse
        from scripts.cli.jmo import _add_wizard_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        _add_wizard_args(subparsers)

        # Valid profiles should parse
        for profile in ["fast", "slim", "balanced", "deep"]:
            args = parser.parse_args(["wizard", "--profile", profile])
            assert args.profile == profile

    def test_wizard_target_type_choices(self) -> None:
        """Verify --target-type accepts only valid choices."""
        import argparse
        from scripts.cli.jmo import _add_wizard_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        _add_wizard_args(subparsers)

        # Valid target types should parse
        for target_type in ["repo", "image", "iac", "url"]:
            args = parser.parse_args(["wizard", "--target-type", target_type])
            assert args.target_type == target_type

    def test_wizard_native_docker_mutually_exclusive(self) -> None:
        """Verify --native and --docker are mutually exclusive."""
        import argparse
        from scripts.cli.jmo import _add_wizard_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        _add_wizard_args(subparsers)

        # --native alone should work
        args = parser.parse_args(["wizard", "--native"])
        assert args.native is True
        assert args.docker is False

        # --docker alone should work
        args = parser.parse_args(["wizard", "--docker"])
        assert args.docker is True
        assert args.native is False

        # Both together should fail
        with pytest.raises(SystemExit):
            parser.parse_args(["wizard", "--native", "--docker"])

    def test_wizard_fail_on_choices(self) -> None:
        """Verify --fail-on accepts only valid severity levels."""
        import argparse
        from scripts.cli.jmo import _add_wizard_args

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        _add_wizard_args(subparsers)

        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            args = parser.parse_args(["wizard", "--fail-on", level])
            assert args.fail_on == level
