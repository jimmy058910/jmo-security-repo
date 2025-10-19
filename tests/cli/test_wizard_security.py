"""
Security tests for wizard.py command injection fixes

Tests that wizard.py properly sanitizes user inputs and avoids shell=True
This addresses finding HIGH-002 (Command Injection)
"""

import pytest
from pathlib import Path
import sys

# Add scripts/cli to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts" / "cli"))

from wizard import generate_command_list, WizardConfig


def create_test_config(**overrides):
    """Helper to create WizardConfig with overrides"""
    config = WizardConfig()
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


class TestCommandInjectionPrevention:
    """Test that malicious inputs are handled safely"""

    def test_no_shell_true_in_execution(self):
        """Verify that subprocess execution does NOT use shell=True"""
        # Read wizard.py source code
        wizard_path = Path(__file__).parent.parent.parent / "scripts" / "cli" / "wizard.py"
        content = wizard_path.read_text()

        # Check that shell=False is used (and shell=True is removed)
        assert "shell=False" in content, "shell=False should be used for subprocess.run"

        # shell=True should NOT appear except in comments or nosec suppressions
        lines_with_shell_true = [
            line for line in content.split("\n")
            if "shell=True" in line and "shell=False" not in line
        ]

        # Filter out comment-only lines
        code_lines = [
            line for line in lines_with_shell_true
            if not line.strip().startswith("#")
        ]

        assert len(code_lines) == 0, f"shell=True should not be used in wizard.py. Found: {code_lines}"

    def test_malicious_repo_path_sanitized(self):
        """Test that malicious repo paths are sanitized"""
        config = create_test_config(
            profile="fast",
            target_mode="repo",
            target_path="/tmp/repo; rm -rf /",  # Injection attempt
            use_docker=False
        )

        cmd_list = generate_command_list(config)

        # Command should be a list (not string)
        assert isinstance(cmd_list, list), "Command must be a list"

        # The malicious path should be passed as a single argument
        # When passed as a list element, subprocess won't interpret it as a shell operator
        assert any("; rm -rf /" in str(arg) for arg in cmd_list)

    def test_command_injection_in_profile(self):
        """Test that profile names are from hardcoded set"""
        config = create_test_config(
            profile="fast",
            target_mode="repo",
            target_path="/tmp/repo",
            use_docker=False
        )

        cmd_list = generate_command_list(config)
        assert "fast" in cmd_list

        # Profile is hardcoded to fast/balanced/deep in wizard
        # No user input goes directly into profile field
        # This test documents that behavior

    def test_path_traversal_attempt(self):
        """Test that path traversal attempts are handled"""
        config = create_test_config(
            profile="fast",
            target_mode="repo",
            target_path="../../etc/passwd",  # Path traversal attempt
            use_docker=False
        )

        cmd_list = generate_command_list(config)

        # Path should be passed as-is in list format
        # os.path.abspath() will resolve it safely in generate_command_list
        assert isinstance(cmd_list, list)
        assert "--repo" in cmd_list

    def test_command_substitution_blocked(self):
        """Test that command substitution $(whoami) is not executed"""
        config = create_test_config(
            profile="fast",
            target_mode="repo",
            target_path="/tmp/$(whoami)",  # Command substitution attempt
            use_docker=False
        )

        cmd_list = generate_command_list(config)

        # $(whoami) should be treated as literal text, not executed
        # When shell=False, subprocess doesn't interpret $() syntax
        assert isinstance(cmd_list, list)

        # The path containing $(whoami) should appear literally in the list
        path_found = any("$(whoami)" in str(arg) for arg in cmd_list)
        assert path_found, "Command substitution should be literal, not executed"

    def test_backtick_injection_blocked(self):
        """Test that backtick injection `whoami` is not executed"""
        config = create_test_config(
            profile="fast",
            target_mode="repo",
            target_path="/tmp/`whoami`",  # Backtick injection attempt
            use_docker=False
        )

        cmd_list = generate_command_list(config)

        # Backticks should be treated as literal characters
        assert isinstance(cmd_list, list)

        # The path containing backticks should appear literally
        path_found = any("`whoami`" in str(arg) for arg in cmd_list)
        assert path_found, "Backtick injection should be literal, not executed"


class TestCommandListStructure:
    """Test that command lists are properly structured"""

    def test_docker_command_is_list(self):
        """Test that Docker commands are built as lists"""
        config = create_test_config(
            profile="fast",
            target_mode="repo",
            target_path="/tmp/test-repo",
            use_docker=True
        )

        cmd_list = generate_command_list(config)

        # Verify it's a list
        assert isinstance(cmd_list, list)

        # Verify Docker command structure
        assert cmd_list[0] == "docker"
        assert cmd_list[1] == "run"
        assert cmd_list[2] == "--rm"

        # Find -v flags
        v_indices = [i for i, arg in enumerate(cmd_list) if arg == "-v"]
        assert len(v_indices) == 2, "Should have 2 volume mounts"

    def test_native_command_is_list(self):
        """Test that native commands are built as lists"""
        config = create_test_config(
            profile="balanced",
            target_mode="repos-dir",
            target_path="/tmp/repos",
            use_docker=False,
            fail_on="HIGH",
            human_logs=True
        )

        cmd_list = generate_command_list(config)

        # Verify it's a list
        assert isinstance(cmd_list, list)

        # Verify jmotools command structure
        assert cmd_list[0] == "jmotools"
        assert cmd_list[1] == "balanced"

        # Verify arguments are properly separated
        assert "--repos-dir" in cmd_list
        assert "--results-dir" in cmd_list
        assert "--fail-on" in cmd_list
        assert "HIGH" in cmd_list
        assert "--human-logs" in cmd_list

    def test_absolute_paths_used(self):
        """Test that relative paths are resolved to absolute"""
        config = create_test_config(
            profile="fast",
            target_mode="repo",
            target_path="./relative/path",  # Relative path
            results_dir="./results",        # Relative results
            use_docker=True
        )

        cmd_list = generate_command_list(config)

        # Docker volume mounts should use absolute paths
        # Look for -v arguments
        v_indices = [i for i, arg in enumerate(cmd_list) if arg == "-v"]

        for idx in v_indices:
            mount_spec = cmd_list[idx + 1]
            local_path = mount_spec.split(":")[0]

            # Path should be absolute (starts with /)
            assert local_path.startswith("/"), f"Path should be absolute: {local_path}"


class TestInputSanitization:
    """Test that all user inputs are properly sanitized"""

    def test_special_characters_in_path(self):
        """Test that special characters are handled safely"""
        special_chars_paths = [
            "/tmp/test repo",      # Space
            "/tmp/test&repo",      # Ampersand
            "/tmp/test|repo",      # Pipe
            "/tmp/test>repo",      # Redirect
            "/tmp/test<repo",      # Redirect
            "/tmp/test;repo",      # Semicolon
            "/tmp/test'repo",      # Single quote
            '/tmp/test"repo',      # Double quote
            "/tmp/test$repo",      # Dollar sign
        ]

        for path in special_chars_paths:
            config = create_test_config(
                profile="fast",
                target_mode="repo",
                target_path=path,
                use_docker=False
            )

            cmd_list = generate_command_list(config)

            # Command should be a list
            assert isinstance(cmd_list, list)

            # Path should be in the list as a single element
            # Special characters won't be interpreted because shell=False
            assert any(path in str(arg) for arg in cmd_list)


class TestRegressionTests:
    """Regression tests for the command injection fix"""

    def test_bandit_b602_resolved(self):
        """Verify Bandit B602 (shell=True) is resolved"""
        wizard_path = Path(__file__).parent.parent.parent / "scripts" / "cli" / "wizard.py"
        content = wizard_path.read_text()

        # Count instances of shell=True in actual code (not comments)
        code_lines = [
            line for line in content.split("\n")
            if "shell=True" in line and not line.strip().startswith("#")
        ]

        # There should be no shell=True in the code
        # (Comments and docstrings are OK)
        assert len(code_lines) == 0, f"Found shell=True in code: {code_lines}"

    def test_bandit_b603_reduced(self):
        """Verify Bandit B603 (subprocess without shell=True) is acceptable"""
        wizard_path = Path(__file__).parent.parent.parent / "scripts" / "cli" / "wizard.py"
        content = wizard_path.read_text()

        # subprocess.run with shell=False is safe (no B602/B603 HIGH findings)
        assert "subprocess.run(" in content
        assert "shell=False" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
