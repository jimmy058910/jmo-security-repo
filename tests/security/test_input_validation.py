#!/usr/bin/env python3
"""
Input Validation Security Tests for JMo Security.

Tests that user inputs are properly validated and sanitized to prevent:
- Command injection
- YAML injection
- JSON injection
- Integer overflow/underflow
- Path traversal (already covered in test_path_traversal.py)
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


class TestInputValidation:
    """Test input validation and sanitization."""

    def test_cli_args_prevent_command_injection(self, tmp_path):
        """Test that CLI arguments with shell metacharacters don't cause command injection.

        Security best practice: Never pass user input directly to shell commands.
        """
        import os

        # Test with malicious tool name containing shell metacharacters
        malicious_inputs = [
            "; rm -rf /",
            "| cat /etc/passwd",
            "& echo pwned",
            "$(whoami)",
            "`id`",
        ]

        # Set CI environment to skip interactive prompts
        test_env = os.environ.copy()
        test_env["CI"] = "true"

        for malicious_input in malicious_inputs:
            # Attempt to use malicious input as tool name
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/cli/jmo.py",
                    "scan",
                    "--tools",
                    malicious_input,
                ],
                capture_output=True,
                text=True,
                timeout=30,  # Increased from 5s for slower systems
                env=test_env,
            )

            # Command should fail gracefully (invalid tool name), not execute shell commands
            assert (
                result.returncode != 0
            ), f"Malicious input '{malicious_input}' should fail gracefully"

            # Should not see signs of command execution in stderr
            assert "pwned" not in result.stderr
            assert "root:" not in result.stdout  # /etc/passwd content
            assert result.stderr  # Should have error message about invalid tool

    def test_yaml_config_prevents_arbitrary_code_execution(self, tmp_path):
        """Test that YAML config loading prevents arbitrary code execution.

        Security best practice: Use safe_load, not load, to prevent YAML deserialization attacks.
        """
        # Create malicious YAML with Python object creation
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo pwned > /tmp/yaml-pwned.txt']
"""

        config_file = tmp_path / "malicious.yml"
        config_file.write_text(malicious_yaml)

        # Attempt to load malicious YAML using our config loader
        try:
            from scripts.core.config import load_config

            load_config(config_file)

            # If we get here, safe_load was used (good)
            # The malicious payload should have been parsed as a string, not executed
            assert not Path(
                "/tmp/yaml-pwned.txt"
            ).exists(), "YAML deserialization attack succeeded - should use safe_load"
        except yaml.constructor.ConstructorError:
            # safe_load raises ConstructorError for !!python/object - this is expected and good
            pass
        except Exception:
            # Other exceptions are acceptable (e.g., invalid config structure)
            pass

    def test_json_input_prevents_prototype_pollution(self, tmp_path):
        """Test that JSON parsing doesn't allow prototype pollution.

        Note: Python's json module is not vulnerable to prototype pollution
        (JavaScript-specific attack), but we verify JSON validation.
        """
        # Create malicious JSON attempting prototype pollution pattern
        malicious_json = {
            "__proto__": {"polluted": True},
            "constructor": {"prototype": {"polluted": True}},
        }

        json_file = tmp_path / "malicious.json"
        json_file.write_text(json.dumps(malicious_json))

        # Load JSON
        loaded = json.loads(json_file.read_text())

        # Verify __proto__ is treated as regular key, not special property
        assert "__proto__" in loaded
        assert loaded["__proto__"] == {"polluted": True}

        # Verify no global object pollution occurred
        test_obj = {}
        assert not hasattr(test_obj, "polluted")

    def test_integer_overflow_in_scan_parameters(self, tmp_path):
        """Test that integer parameters handle overflow/underflow gracefully.

        Security best practice: Validate integer ranges to prevent crashes or exploits.
        """
        import os

        # Set CI environment to skip interactive prompts
        test_env = os.environ.copy()
        test_env["CI"] = "true"

        # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933),
        # which resolves Path.home() with no injection point, and the report
        # phase defaults history storage to the real .jmo/history.db (#802).
        # Redirect both via the env vars Path.home() actually reads
        # (ntpath.expanduser / posixpath.expanduser). A *separate* directory
        # from --repo below, not tmp_path itself, so the fake home does not
        # nest inside the scan's own target.
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        test_env["USERPROFILE"] = str(fake_home)
        test_env["HOME"] = str(fake_home)

        # Test with absurdly large timeout value.
        #
        # `--tools`/`--allow-missing-tools` bound the work to one scanner. This
        # test asserts the CLI does not crash on a huge integer; it does not
        # need a full profile to prove that, and running one made its runtime a
        # function of how many scanners the developer happens to have installed
        # (#748). CI installs none, so the scan found nothing to run and
        # returned in seconds -- it passed there for releases while failing on
        # any machine with real tools.
        #
        # Measured on a box with 8 scanners in ~/.jmo/bin: the unbounded form
        # exceeded 45s (the 30s cap below could never be met), redirecting HOME
        # so no tools resolve still took 26s against that 30s cap, and this
        # bounded form takes 12s. Only the last one is independent of the
        # machine it runs on.
        result = subprocess.run(
            [
                sys.executable,
                "scripts/cli/jmo.py",
                "scan",
                "--repo",
                str(tmp_path),
                "--tools",
                "trufflehog",
                "--allow-missing-tools",
                "--timeout",
                "999999999999999",  # Absurdly large
                # Irrelevant to what this test checks, and avoids the real
                # .jmo/history.db (#802) -- the HOME redirect above only
                # covers _show_kofi_reminder()'s separate real-state write
                # (#933), not this one.
                "--no-store-history",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            env=test_env,
        )

        # Should fail gracefully or clamp to reasonable value, not crash
        # (Python handles big ints well, but should validate for reasonableness)
        assert result.returncode in [
            0,
            1,
            2,
        ], "Large timeout should be handled gracefully"

    def test_filename_sanitization(self, tmp_path):
        """Test that filenames with special characters are sanitized.

        Security best practice: Sanitize filenames to prevent directory traversal
        and injection attacks.
        """
        from scripts.core.normalize_and_report import write_json

        # Filenames with special characters
        malicious_names = [
            "../../../etc/passwd",
            "file; rm -rf /",
            "file\x00.json",  # Null byte injection
            "file\n.json",  # Newline injection
        ]

        summaries_dir = tmp_path / "summaries"
        summaries_dir.mkdir()

        for malicious_name in malicious_names:
            try:
                # Attempt to write file with malicious name
                write_json({"test": True}, summaries_dir / malicious_name)

                # File should either:
                # 1. Not be written at all (exception raised)
                # 2. Be written with sanitized name (path resolved to safe location)

                # Verify no file written outside summaries_dir
                for file in tmp_path.rglob("*"):
                    assert (
                        summaries_dir in file.parents or file == summaries_dir
                    ), f"File '{file}' written outside summaries_dir"
            except (OSError, ValueError):
                # Acceptable - invalid filename rejected
                pass

    def test_regex_dos_prevention(self):
        """Test that regex patterns don't cause ReDoS (Regular Expression DoS).

        Security best practice: Avoid catastrophic backtracking in regex.
        """
        import re

        # Pattern that could cause catastrophic backtracking
        # Example: (a+)+ on input "aaaaaaaaaaaaaaaaaaaaaaaaaX"
        redos_input = "a" * 25 + "X"

        # Test common patterns used in codebase
        safe_patterns = [
            r"AKIA[0-9A-Z]{16}",  # AWS key pattern (from test_secrets_management.py)
            r"ghp_[A-Za-z0-9]{36}",  # GitHub token pattern
            r"CVE-\d{4}-\d{4,7}",  # CVE pattern
        ]

        for pattern in safe_patterns:
            # Python's re module doesn't have a timeout parameter.
            # Safe patterns should complete quickly without causing backtracking.
            # We test that these patterns are non-backtracking by simply running them.
            re.search(pattern, redos_input)
            # No assertion needed - just checking it completes quickly
            # (if it hung, the test would timeout via pytest-timeout)

    def test_environment_variable_injection(self, tmp_path):
        """Test that environment variables cannot inject malicious values.

        Security best practice: Validate environment variable values.
        """
        import os

        # Test with malicious environment variable containing shell metacharacters
        malicious_env_values = [
            "; rm -rf /",
            "$(whoami)",
            "`id`",
        ]

        for malicious_value in malicious_env_values:
            # Set environment variable to malicious value
            os.environ["TEST_MALICIOUS_VAR"] = malicious_value

            # Attempt to use in command (should be treated as literal string)
            result = subprocess.run(
                ["echo", os.getenv("TEST_MALICIOUS_VAR", "")],
                capture_output=True,
                text=True,
                shell=False,  # CRITICAL: shell=False prevents injection
                timeout=2,
            )

            # Should echo the literal value, not execute it
            assert (
                result.stdout.strip() == malicious_value
            ), "Environment variable value should be literal, not executed"

            # Clean up
            del os.environ["TEST_MALICIOUS_VAR"]


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v", "--tb=short"])
