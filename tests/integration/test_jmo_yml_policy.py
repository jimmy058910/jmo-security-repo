#!/usr/bin/env python3
"""
Integration test for jmo.yml policy configuration.

This test verifies that:
1. The policy section loads correctly from jmo.yml
2. The shipped jmo.yml's top-level policy is the one applied (v2.0.0 removed
   the per-profile overrides with the profiles)
3. Environment variables correctly override jmo.yml settings

Target Coverage: ≥90%
"""

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


def test_jmo_yml_default_policies(jmo_yml_path):
    """Test that the shipped top-level policy set is what loads.

    It is the set the former default profile (balanced) applied, now the only
    one: there is no profile left to override it.
    """
    from scripts.core.config import load_config

    config = load_config(str(jmo_yml_path))

    assert config.policy.default_policies == ["owasp-top-10", "zero-secrets"]


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


def test_the_shipped_jmo_yml_has_no_unrecognised_keys(jmo_yml_path, caplog):
    """Every key the shipped config carries must configure something.

    A `profiles:` or `default_profile:` block left in the file after v2.0.0
    would load, warn, and do nothing -- the default config telling every user
    that its own settings are ignored.
    """
    import logging

    from scripts.core.config import load_config

    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        load_config(str(jmo_yml_path))

    unrecognised = [
        r.getMessage() for r in caplog.records if "unrecognised" in r.getMessage()
    ]
    assert not unrecognised, unrecognised


# ========== COVERAGE TARGET: ≥90% ====================
# Run: pytest tests/integration/test_jmo_yml_policy.py -v
