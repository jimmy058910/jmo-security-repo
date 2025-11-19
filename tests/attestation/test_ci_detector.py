"""
Tests for CI/CD environment detection.

Tests the three-tier priority system for auto-attestation:
1. CLI flag (highest priority)
2. Environment variable (JMO_ATTEST_ENABLED)
3. Config file (lowest priority)

Also tests CI provider detection (GitHub Actions, GitLab CI, generic, local).
"""

import pytest
from unittest.mock import patch
from scripts.core.attestation.ci_detector import CIDetector


class TestCIDetection:
    """Tests for CI environment detection."""

    @patch.dict("os.environ", {"CI": "true"})
    def test_is_ci_true(self):
        """Test CI detection when CI=true."""
        detector = CIDetector()
        assert detector.is_ci() is True

    @patch.dict("os.environ", {}, clear=True)
    def test_is_ci_false(self):
        """Test CI detection when not in CI."""
        detector = CIDetector()
        assert detector.is_ci() is False

    @patch.dict("os.environ", {"CI": "false"})
    def test_is_ci_false_explicit(self):
        """Test CI detection when CI=false."""
        detector = CIDetector()
        assert detector.is_ci() is False


class TestCIProviderDetection:
    """Tests for specific CI provider detection."""

    @patch.dict("os.environ", {"GITHUB_ACTIONS": "true"})
    def test_github_actions_detection(self):
        """Test GitHub Actions detection."""
        detector = CIDetector()
        assert detector.get_ci_provider() == "github"

    @patch.dict("os.environ", {"GITLAB_CI": "true"})
    def test_gitlab_ci_detection(self):
        """Test GitLab CI detection."""
        detector = CIDetector()
        assert detector.get_ci_provider() == "gitlab"

    @patch.dict("os.environ", {"CI": "true"}, clear=True)
    def test_generic_ci_detection(self):
        """Test generic CI detection (CI=true but no specific provider)."""
        detector = CIDetector()
        assert detector.get_ci_provider() == "generic"

    @patch.dict("os.environ", {}, clear=True)
    def test_local_detection(self):
        """Test local (non-CI) detection."""
        detector = CIDetector()
        assert detector.get_ci_provider() == "local"

    @patch.dict(
        "os.environ",
        {
            "GITHUB_ACTIONS": "true",
            "GITLAB_CI": "true",
        },
    )
    def test_github_takes_precedence_over_gitlab(self):
        """Test GitHub Actions takes precedence over GitLab CI."""
        detector = CIDetector()
        assert detector.get_ci_provider() == "github"


class TestAutoAttestationPriority:
    """Tests for three-tier auto-attestation priority system."""

    # Priority 1: CLI flag (highest)

    @patch.dict("os.environ", {"CI": "true"})
    def test_cli_flag_true_overrides_all(self):
        """Test CLI flag=True overrides environment variable and config."""
        config = {"attestation": {"auto_attest": False}}  # Config says no
        detector = CIDetector(config=config)

        # Environment variable says no (would be checked next)
        with patch.dict("os.environ", {"JMO_ATTEST_ENABLED": "false", "CI": "true"}):
            # CLI flag says yes (highest priority)
            assert detector.should_auto_attest(cli_flag=True) is True

    @patch.dict("os.environ", {"CI": "true"})
    def test_cli_flag_false_overrides_all(self):
        """Test CLI flag=False overrides environment variable and config."""
        config = {"attestation": {"auto_attest": True}}  # Config says yes
        detector = CIDetector(config=config)

        # Environment variable says yes (would be checked next)
        with patch.dict("os.environ", {"JMO_ATTEST_ENABLED": "true", "CI": "true"}):
            # CLI flag says no (highest priority)
            assert detector.should_auto_attest(cli_flag=False) is False

    # Priority 2: Environment variable

    @patch.dict(
        "os.environ",
        {
            "JMO_ATTEST_ENABLED": "true",
            "CI": "true",
        },
    )
    def test_env_var_true_in_ci(self):
        """Test JMO_ATTEST_ENABLED=true enables attestation in CI."""
        detector = CIDetector()
        assert detector.should_auto_attest() is True

    @patch.dict(
        "os.environ",
        {
            "JMO_ATTEST_ENABLED": "true",
        },
        clear=True,
    )
    def test_env_var_true_local(self):
        """Test JMO_ATTEST_ENABLED=true in local environment (not CI)."""
        # Environment variable is true BUT not in CI
        detector = CIDetector()
        assert detector.should_auto_attest() is False

    @patch.dict(
        "os.environ",
        {
            "JMO_ATTEST_ENABLED": "false",
            "CI": "true",
        },
    )
    def test_env_var_false_overrides_config(self):
        """Test JMO_ATTEST_ENABLED=false overrides config."""
        config = {"attestation": {"auto_attest": True}}  # Config says yes
        detector = CIDetector(config=config)

        # Environment variable says no (priority 2)
        assert detector.should_auto_attest() is False

    @patch.dict(
        "os.environ",
        {
            "JMO_ATTEST_ENABLED": "1",
            "CI": "true",
        },
    )
    def test_env_var_1_treated_as_true(self):
        """Test JMO_ATTEST_ENABLED=1 is treated as true."""
        detector = CIDetector()
        assert detector.should_auto_attest() is True

    @patch.dict(
        "os.environ",
        {
            "JMO_ATTEST_ENABLED": "0",
            "CI": "true",
        },
    )
    def test_env_var_0_treated_as_false(self):
        """Test JMO_ATTEST_ENABLED=0 is treated as false."""
        detector = CIDetector()
        assert detector.should_auto_attest() is False

    @patch.dict(
        "os.environ",
        {
            "JMO_ATTEST_ENABLED": "yes",
            "CI": "true",
        },
    )
    def test_env_var_yes_treated_as_true(self):
        """Test JMO_ATTEST_ENABLED=yes is treated as true."""
        detector = CIDetector()
        assert detector.should_auto_attest() is True

    @patch.dict(
        "os.environ",
        {
            "JMO_ATTEST_ENABLED": "no",
            "CI": "true",
        },
    )
    def test_env_var_no_treated_as_false(self):
        """Test JMO_ATTEST_ENABLED=no is treated as false."""
        detector = CIDetector()
        assert detector.should_auto_attest() is False

    @patch.dict(
        "os.environ",
        {
            "JMO_ATTEST_ENABLED": "YES",
            "CI": "true",
        },
    )
    def test_env_var_case_insensitive(self):
        """Test environment variable parsing is case-insensitive."""
        detector = CIDetector()
        assert detector.should_auto_attest() is True

    @patch.dict(
        "os.environ",
        {
            "JMO_ATTEST_ENABLED": "invalid_value",
            "CI": "true",
        },
    )
    def test_env_var_invalid_falls_through_to_config(self):
        """Test invalid environment variable falls through to config."""
        config = {"attestation": {"auto_attest": True}}  # Config says yes
        detector = CIDetector(config=config)

        # Invalid env var falls through to config (priority 3)
        assert detector.should_auto_attest() is True

    # Priority 3: Config file

    @patch.dict("os.environ", {"CI": "true"}, clear=True)
    def test_config_true_in_ci(self):
        """Test config auto_attest=True enables attestation in CI."""
        config = {"attestation": {"auto_attest": True}}
        detector = CIDetector(config=config)
        assert detector.should_auto_attest() is True

    @patch.dict("os.environ", {}, clear=True)
    def test_config_true_local(self):
        """Test config auto_attest=True in local environment (not CI)."""
        config = {"attestation": {"auto_attest": True}}
        detector = CIDetector(config=config)

        # Config is true BUT not in CI
        assert detector.should_auto_attest() is False

    @patch.dict("os.environ", {"CI": "true"}, clear=True)
    def test_config_false_disables(self):
        """Test config auto_attest=False disables attestation."""
        config = {"attestation": {"auto_attest": False}}
        detector = CIDetector(config=config)
        assert detector.should_auto_attest() is False

    @patch.dict("os.environ", {"CI": "true"}, clear=True)
    def test_config_missing_defaults_to_false(self):
        """Test missing config defaults to disabled (conservative)."""
        detector = CIDetector(config={})
        assert detector.should_auto_attest() is False

    @patch.dict("os.environ", {"CI": "true"}, clear=True)
    def test_config_none_defaults_to_false(self):
        """Test None config defaults to disabled."""
        detector = CIDetector()  # No config provided
        assert detector.should_auto_attest() is False


class TestParseBoolEnv:
    """Tests for _parse_bool_env helper method."""

    def test_parse_true_lowercase(self):
        """Test parsing 'true' (lowercase)."""
        detector = CIDetector()
        assert detector._parse_bool_env("true") is True

    def test_parse_true_uppercase(self):
        """Test parsing 'TRUE' (uppercase)."""
        detector = CIDetector()
        assert detector._parse_bool_env("TRUE") is True

    def test_parse_false_lowercase(self):
        """Test parsing 'false' (lowercase)."""
        detector = CIDetector()
        assert detector._parse_bool_env("false") is False

    def test_parse_false_uppercase(self):
        """Test parsing 'FALSE' (uppercase)."""
        detector = CIDetector()
        assert detector._parse_bool_env("FALSE") is False

    def test_parse_1(self):
        """Test parsing '1' as true."""
        detector = CIDetector()
        assert detector._parse_bool_env("1") is True

    def test_parse_0(self):
        """Test parsing '0' as false."""
        detector = CIDetector()
        assert detector._parse_bool_env("0") is False

    def test_parse_yes(self):
        """Test parsing 'yes' as true."""
        detector = CIDetector()
        assert detector._parse_bool_env("yes") is True

    def test_parse_no(self):
        """Test parsing 'no' as false."""
        detector = CIDetector()
        assert detector._parse_bool_env("no") is False

    def test_parse_invalid_value(self):
        """Test parsing invalid value returns None."""
        detector = CIDetector()
        assert detector._parse_bool_env("invalid") is None

    def test_parse_empty_string(self):
        """Test parsing empty string returns None."""
        detector = CIDetector()
        assert detector._parse_bool_env("") is None

    def test_parse_whitespace(self):
        """Test parsing handles whitespace."""
        detector = CIDetector()
        assert detector._parse_bool_env("  true  ") is True
        assert detector._parse_bool_env("  false  ") is False
