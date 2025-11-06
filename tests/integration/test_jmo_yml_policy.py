#!/usr/bin/env python3
"""
Integration test for jmo.yml policy configuration.

This test verifies that:
1. The policy section loads correctly from jmo.yml
2. Profile-specific policy overrides work as expected
3. All three profiles (fast/balanced/deep) have correct policy defaults
4. Environment variables correctly override jmo.yml settings

Target Coverage: ≥90%
"""

import os
from pathlib import Path
import pytest


@pytest.fixture
def jmo_yml_path():
    """Return path to the actual jmo.yml in the repository root."""
    repo_root = Path(__file__).parent.parent.parent
    return repo_root / "jmo.yml"


def test_jmo_yml_exists(jmo_yml_path):
    """Test that jmo.yml exists in repository root."""
    assert jmo_yml_path.exists(), f"jmo.yml not found at {jmo_yml_path}"


def test_jmo_yml_policy_section_exists(jmo_yml_path):
    """Test that jmo.yml contains policy section."""
    from scripts.core.config import load_config

    config = load_config(str(jmo_yml_path))

    # Policy section should exist
    assert hasattr(config, "policy"), "Config missing policy attribute"
    assert config.policy is not None


def test_jmo_yml_global_policy_defaults(jmo_yml_path):
    """Test that global policy defaults are correct."""
    from scripts.core.config import load_config

    config = load_config(str(jmo_yml_path))

    # Global defaults from jmo.yml
    assert config.policy.enabled is True
    assert config.policy.auto_evaluate is True
    assert config.policy.fail_on_violation is False
    assert config.policy.opa["binary"] == "opa"
    assert config.policy.opa["version"] == ">=0.70.0"
    assert config.policy.opa["timeout"] == 30


def test_jmo_yml_default_profile_policy(jmo_yml_path):
    """Test that default profile (balanced) policy is applied."""
    from scripts.core.config import load_config

    config = load_config(str(jmo_yml_path))

    # Default profile is balanced, should use balanced policies
    assert "owasp-top-10" in config.policy.default_policies
    assert "zero-secrets" in config.policy.default_policies
    assert len(config.policy.default_policies) == 2


def test_jmo_yml_fast_profile_policy(jmo_yml_path, tmp_path):
    """Test that fast profile has correct policy defaults."""
    from scripts.core.config import load_config

    # Create modified jmo.yml with fast profile as default
    jmo_content = jmo_yml_path.read_text(encoding="utf-8")
    jmo_content = jmo_content.replace("default_profile: balanced", "default_profile: fast")

    modified_yml = tmp_path / "jmo_fast.yml"
    modified_yml.write_text(jmo_content, encoding="utf-8")

    config = load_config(str(modified_yml))

    # Fast profile should use minimal policies
    assert config.policy.default_policies == ["zero-secrets"]
    assert config.policy.fail_on_violation is False


def test_jmo_yml_deep_profile_policy(jmo_yml_path, tmp_path):
    """Test that deep profile has correct policy defaults."""
    from scripts.core.config import load_config

    # Create modified jmo.yml with deep profile as default
    jmo_content = jmo_yml_path.read_text(encoding="utf-8")
    jmo_content = jmo_content.replace("default_profile: balanced", "default_profile: deep")

    modified_yml = tmp_path / "jmo_deep.yml"
    modified_yml.write_text(jmo_content, encoding="utf-8")

    config = load_config(str(modified_yml))

    # Deep profile should use all 5 policies
    assert len(config.policy.default_policies) == 5
    assert "owasp-top-10" in config.policy.default_policies
    assert "zero-secrets" in config.policy.default_policies
    assert "pci-dss" in config.policy.default_policies
    assert "production-hardening" in config.policy.default_policies
    assert "hipaa-compliance" in config.policy.default_policies
    assert config.policy.fail_on_violation is True


def test_jmo_yml_environment_variable_override(jmo_yml_path, monkeypatch):
    """Test that environment variables override jmo.yml settings."""
    from scripts.core.config import load_config_with_env_overrides

    # Override with environment variables
    monkeypatch.setenv("JMO_POLICY_ENABLED", "false")
    monkeypatch.setenv("JMO_POLICY_DEFAULT_POLICIES", "pci-dss")
    monkeypatch.setenv("JMO_POLICY_FAIL_ON_VIOLATION", "true")

    config = load_config_with_env_overrides(str(jmo_yml_path))

    # Environment variables should take precedence
    assert config.policy.enabled is False
    assert config.policy.default_policies == ["pci-dss"]
    assert config.policy.fail_on_violation is True


def test_jmo_yml_profile_precedence_over_global(jmo_yml_path):
    """Test that profile defaults override global policy defaults."""
    from scripts.core.config import load_config
    import yaml

    # Read jmo.yml to check profile override structure
    jmo_data = yaml.safe_load(jmo_yml_path.read_text(encoding="utf-8"))

    # Verify profile structure
    assert "profiles" in jmo_data
    assert "fast" in jmo_data["profiles"]
    assert "balanced" in jmo_data["profiles"]
    assert "deep" in jmo_data["profiles"]

    # Verify each profile has policy section
    assert "policy" in jmo_data["profiles"]["fast"]
    assert "policy" in jmo_data["profiles"]["balanced"]
    assert "policy" in jmo_data["profiles"]["deep"]

    # Load config and verify profile overrides global
    config = load_config(str(jmo_yml_path))

    # Default profile (balanced) should override global defaults
    # Global has [owasp-top-10, zero-secrets], balanced should use its own
    assert config.policy.default_policies == ["owasp-top-10", "zero-secrets"]


def test_jmo_yml_opa_configuration(jmo_yml_path):
    """Test that OPA configuration is loaded correctly."""
    from scripts.core.config import load_config

    config = load_config(str(jmo_yml_path))

    # OPA config should have all required fields
    assert "binary" in config.policy.opa
    assert "version" in config.policy.opa
    assert "timeout" in config.policy.opa

    # Values should match jmo.yml
    assert config.policy.opa["binary"] == "opa"
    assert config.policy.opa["version"] == ">=0.70.0"
    assert config.policy.opa["timeout"] == 30


def test_jmo_yml_all_profiles_have_policy(jmo_yml_path):
    """Test that all three profiles have policy configuration."""
    import yaml

    jmo_data = yaml.safe_load(jmo_yml_path.read_text(encoding="utf-8"))

    profiles = ["fast", "balanced", "deep"]
    for profile in profiles:
        assert profile in jmo_data["profiles"], f"Profile {profile} missing"
        assert "policy" in jmo_data["profiles"][profile], f"Policy missing in {profile} profile"
        assert "default_policies" in jmo_data["profiles"][profile]["policy"], \
            f"default_policies missing in {profile} profile"


# ========== COVERAGE TARGET: ≥90% ====================
# Run: pytest tests/integration/test_jmo_yml_policy.py -v
