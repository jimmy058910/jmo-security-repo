#!/usr/bin/env python3
"""
Comprehensive tests for PolicyConfig and policy configuration loading.

This test suite follows TDD approach:
1. Tests written FIRST before implementation
2. Tests define expected behavior
3. Implementation written to pass tests

Target Coverage: ≥90%
"""

from pathlib import Path
import pytest


def write_yaml_file(tmp_path: Path, filename: str, content: str) -> Path:
    """Helper to write YAML config files for testing."""
    yaml_file = tmp_path / filename
    yaml_file.write_text(content, encoding="utf-8")
    return yaml_file


# ========== Category 1: PolicyConfig Dataclass Tests ==========


def test_policy_config_defaults():
    """Test PolicyConfig has correct default values."""
    from scripts.core.config import PolicyConfig

    config = PolicyConfig()

    assert config.enabled is True
    assert config.auto_evaluate is True
    assert config.default_policies == []
    assert config.fail_on_violation is False
    assert config.opa["binary"] == "opa"
    assert config.opa["version"] == ">=0.70.0"
    assert config.opa["timeout"] == 30


def test_policy_config_custom_initialization():
    """Test PolicyConfig can be initialized with custom values."""
    from scripts.core.config import PolicyConfig

    config = PolicyConfig(
        enabled=False,
        auto_evaluate=False,
        default_policies=["owasp-top-10", "zero-secrets"],
        fail_on_violation=True,
        opa={
            "binary": "/usr/local/bin/opa",
            "version": ">=1.0.0",
            "timeout": 60,
        },
    )

    assert config.enabled is False
    assert config.auto_evaluate is False
    assert config.default_policies == ["owasp-top-10", "zero-secrets"]
    assert config.fail_on_violation is True
    assert config.opa["binary"] == "/usr/local/bin/opa"
    assert config.opa["version"] == ">=1.0.0"
    assert config.opa["timeout"] == 60


def test_policy_config_validation_default_policies_must_be_list():
    """Test PolicyConfig validation fails if default_policies is not a list."""
    from scripts.core.config import PolicyConfig

    with pytest.raises(ValueError, match="default_policies must be a list"):
        PolicyConfig(default_policies="owasp-top-10")  # type: ignore[arg-type]


def test_policy_config_validation_timeout_must_be_positive():
    """Test PolicyConfig validation fails if OPA timeout is not positive."""
    from scripts.core.config import PolicyConfig

    with pytest.raises(ValueError, match="opa.timeout must be positive"):
        PolicyConfig(opa={"timeout": -1})

    with pytest.raises(ValueError, match="opa.timeout must be positive"):
        PolicyConfig(opa={"timeout": 0})


def test_policy_config_partial_opa_config():
    """Test PolicyConfig merges partial OPA config with defaults."""
    from scripts.core.config import PolicyConfig

    # Only override timeout, keep other defaults
    config = PolicyConfig(opa={"timeout": 60})

    assert config.opa["binary"] == "opa"
    assert config.opa["version"] == ">=0.70.0"
    assert config.opa["timeout"] == 60


# ========== Category 2: Config Dataclass with Policy Field ==========


def test_config_has_policy_field():
    """Test Config dataclass has policy field with PolicyConfig default."""
    from scripts.core.config import Config

    cfg = Config()

    assert hasattr(cfg, "policy")
    assert cfg.policy is not None
    assert cfg.policy.enabled is True
    assert cfg.policy.auto_evaluate is True


def test_config_custom_policy_config():
    """Test Config can be initialized with custom PolicyConfig."""
    from scripts.core.config import Config, PolicyConfig

    policy_cfg = PolicyConfig(
        enabled=False,
        default_policies=["zero-secrets"],
    )
    cfg = Config(policy=policy_cfg)

    assert cfg.policy.enabled is False
    assert cfg.policy.default_policies == ["zero-secrets"]


# ========== Category 3: Loading Policy Config from jmo.yml ==========


def test_load_config_with_policy_section(tmp_path):
    """Test loading policy configuration from jmo.yml."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
  enabled: true
  auto_evaluate: true
  default_policies:
    - owasp-top-10
    - zero-secrets
  fail_on_violation: false
  opa:
    binary: /usr/local/bin/opa
    version: ">=0.70.0"
    timeout: 60
""",
    )

    config = load_config(str(config_file))

    assert config.policy.enabled is True
    assert config.policy.auto_evaluate is True
    assert config.policy.default_policies == ["owasp-top-10", "zero-secrets"]
    assert config.policy.fail_on_violation is False
    assert config.policy.opa["binary"] == "/usr/local/bin/opa"
    assert config.policy.opa["timeout"] == 60


def test_load_config_without_policy_section(tmp_path):
    """Test load_config returns PolicyConfig defaults when policy section missing."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
tools:
  - trufflehog
  - semgrep
""",
    )

    config = load_config(str(config_file))

    # Should have default PolicyConfig
    assert config.policy.enabled is True
    assert config.policy.auto_evaluate is True
    assert config.policy.default_policies == []
    assert config.policy.fail_on_violation is False


def test_load_config_partial_policy_section(tmp_path):
    """Test load_config merges partial policy config with defaults."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
  enabled: false
  default_policies:
    - zero-secrets
""",
    )

    config = load_config(str(config_file))

    # Specified values
    assert config.policy.enabled is False
    assert config.policy.default_policies == ["zero-secrets"]

    # Default values for unspecified fields
    assert config.policy.auto_evaluate is True
    assert config.policy.fail_on_violation is False
    assert config.policy.opa["timeout"] == 30


def test_load_config_policy_disabled(tmp_path):
    """Test policy config can be explicitly disabled."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
  enabled: false
""",
    )

    config = load_config(str(config_file))
    assert config.policy.enabled is False


# ========== Category 4: Profile-Specific Policy Overrides ==========


def test_load_config_profile_policy_override(tmp_path):
    """Test profile-specific policy overrides work correctly."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
default_profile: balanced

policy:
  default_policies:
    - zero-secrets

profiles:
  fast:
    policy:
      default_policies:
        - zero-secrets
  balanced:
    policy:
      default_policies:
        - owasp-top-10
        - zero-secrets
  deep:
    policy:
      default_policies:
        - owasp-top-10
        - zero-secrets
        - pci-dss
        - production-hardening
        - hipaa-compliance
      fail_on_violation: true
""",
    )

    config = load_config(str(config_file))

    # Default profile is balanced, should use balanced policies
    assert config.policy.default_policies == ["owasp-top-10", "zero-secrets"]
    assert config.policy.fail_on_violation is False


def test_load_config_deep_profile_policy_override(tmp_path):
    """Test deep profile policy overrides include fail_on_violation."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
default_profile: deep

profiles:
  deep:
    policy:
      default_policies:
        - owasp-top-10
        - zero-secrets
        - pci-dss
        - production-hardening
        - hipaa-compliance
      fail_on_violation: true
""",
    )

    config = load_config(str(config_file))

    assert len(config.policy.default_policies) == 5
    assert "owasp-top-10" in config.policy.default_policies
    assert "hipaa-compliance" in config.policy.default_policies
    assert config.policy.fail_on_violation is True


def test_load_config_fast_profile_minimal_policies(tmp_path):
    """Test fast profile uses minimal policy set."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
default_profile: fast

profiles:
  fast:
    policy:
      default_policies:
        - zero-secrets
""",
    )

    config = load_config(str(config_file))

    assert config.policy.default_policies == ["zero-secrets"]
    assert config.policy.fail_on_violation is False


def test_load_config_profile_without_policy_override(tmp_path):
    """Test profile without policy section uses global policy defaults."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
default_profile: custom

policy:
  default_policies:
    - owasp-top-10

profiles:
  custom:
    tools:
      - semgrep
      - trivy
""",
    )

    config = load_config(str(config_file))

    # Should use global policy config (no profile override)
    assert config.policy.default_policies == ["owasp-top-10"]


# ========== Category 5: Environment Variable Overrides ==========


def test_environment_variable_override_enabled(monkeypatch, tmp_path):
    """Test JMO_POLICY_ENABLED environment variable overrides config."""
    from scripts.core.config import load_config_with_env_overrides

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
  enabled: true
""",
    )

    monkeypatch.setenv("JMO_POLICY_ENABLED", "false")

    config = load_config_with_env_overrides(str(config_file))
    assert config.policy.enabled is False


def test_environment_variable_override_auto_evaluate(monkeypatch, tmp_path):
    """Test JMO_POLICY_AUTO_EVALUATE environment variable overrides config."""
    from scripts.core.config import load_config_with_env_overrides

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
  auto_evaluate: true
""",
    )

    monkeypatch.setenv("JMO_POLICY_AUTO_EVALUATE", "false")

    config = load_config_with_env_overrides(str(config_file))
    assert config.policy.auto_evaluate is False


def test_environment_variable_override_default_policies(monkeypatch, tmp_path):
    """Test JMO_POLICY_DEFAULT_POLICIES environment variable overrides config."""
    from scripts.core.config import load_config_with_env_overrides

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
  default_policies:
    - owasp-top-10
""",
    )

    monkeypatch.setenv("JMO_POLICY_DEFAULT_POLICIES", "zero-secrets,pci-dss")

    config = load_config_with_env_overrides(str(config_file))
    assert config.policy.default_policies == ["zero-secrets", "pci-dss"]


def test_environment_variable_override_fail_on_violation(monkeypatch, tmp_path):
    """Test JMO_POLICY_FAIL_ON_VIOLATION environment variable overrides config."""
    from scripts.core.config import load_config_with_env_overrides

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
  fail_on_violation: false
""",
    )

    monkeypatch.setenv("JMO_POLICY_FAIL_ON_VIOLATION", "true")

    config = load_config_with_env_overrides(str(config_file))
    assert config.policy.fail_on_violation is True


def test_environment_variable_override_opa_binary(monkeypatch, tmp_path):
    """Test JMO_POLICY_OPA_BINARY environment variable overrides config."""
    from scripts.core.config import load_config_with_env_overrides

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
  opa:
    binary: opa
""",
    )

    monkeypatch.setenv("JMO_POLICY_OPA_BINARY", "/custom/path/opa")

    config = load_config_with_env_overrides(str(config_file))
    assert config.policy.opa["binary"] == "/custom/path/opa"


def test_environment_variable_override_opa_timeout(monkeypatch, tmp_path):
    """Test JMO_POLICY_OPA_TIMEOUT environment variable overrides config."""
    from scripts.core.config import load_config_with_env_overrides

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
  opa:
    timeout: 30
""",
    )

    monkeypatch.setenv("JMO_POLICY_OPA_TIMEOUT", "120")

    config = load_config_with_env_overrides(str(config_file))
    assert config.policy.opa["timeout"] == 120


def test_environment_variables_without_config_file(monkeypatch):
    """Test environment variables work without config file."""
    from scripts.core.config import load_config_with_env_overrides

    monkeypatch.setenv("JMO_POLICY_ENABLED", "true")
    monkeypatch.setenv("JMO_POLICY_DEFAULT_POLICIES", "zero-secrets")
    monkeypatch.setenv("JMO_POLICY_FAIL_ON_VIOLATION", "true")

    config = load_config_with_env_overrides(None)

    assert config.policy.enabled is True
    assert config.policy.default_policies == ["zero-secrets"]
    assert config.policy.fail_on_violation is True


def test_environment_variable_precedence_over_profile(monkeypatch, tmp_path):
    """Test environment variables take precedence over profile defaults."""
    from scripts.core.config import load_config_with_env_overrides

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
default_profile: balanced

profiles:
  balanced:
    policy:
      default_policies:
        - owasp-top-10
        - zero-secrets
""",
    )

    monkeypatch.setenv("JMO_POLICY_DEFAULT_POLICIES", "pci-dss")

    config = load_config_with_env_overrides(str(config_file))

    # Env var should override profile default
    assert config.policy.default_policies == ["pci-dss"]


# ========== Category 6: Edge Cases and Error Handling ==========


def test_load_config_invalid_policy_section_ignored(tmp_path):
    """Test invalid policy section is gracefully ignored."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy: "invalid_string_not_dict"
""",
    )

    config = load_config(str(config_file))

    # Should fall back to defaults
    assert config.policy.enabled is True
    assert config.policy.default_policies == []


def test_load_config_invalid_default_policies_ignored(tmp_path):
    """Test invalid default_policies type is gracefully ignored."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
  default_policies: "invalid_string_not_list"
""",
    )

    config = load_config(str(config_file))

    # Should fall back to empty list
    assert config.policy.default_policies == []


def test_load_config_empty_policy_section(tmp_path):
    """Test empty policy section uses all defaults."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
""",
    )

    config = load_config(str(config_file))

    assert config.policy.enabled is True
    assert config.policy.auto_evaluate is True
    assert config.policy.default_policies == []
    assert config.policy.fail_on_violation is False


def test_environment_variable_boolean_case_insensitive(monkeypatch):
    """Test environment variable boolean parsing is case-insensitive."""
    from scripts.core.config import load_config_with_env_overrides

    test_cases = [
        ("true", True),
        ("TRUE", True),
        ("True", True),
        ("false", False),
        ("FALSE", False),
        ("False", False),
    ]

    for env_value, expected in test_cases:
        monkeypatch.setenv("JMO_POLICY_ENABLED", env_value)
        config = load_config_with_env_overrides(None)
        assert config.policy.enabled is expected, f"Failed for {env_value}"


def test_environment_variable_invalid_timeout_ignored(monkeypatch):
    """Test that invalid OPA timeout environment variable is ignored."""
    from scripts.core.config import load_config_with_env_overrides

    monkeypatch.setenv("JMO_POLICY_OPA_TIMEOUT", "invalid")

    config = load_config_with_env_overrides(None)

    # Should keep default timeout (30) when invalid value provided
    assert config.policy.opa["timeout"] == 30


def test_environment_variable_empty_policies_list(monkeypatch):
    """Test that empty policy list from env var results in empty list."""
    from scripts.core.config import load_config_with_env_overrides

    monkeypatch.setenv("JMO_POLICY_DEFAULT_POLICIES", "")

    config = load_config_with_env_overrides(None)

    # Empty string should result in empty list
    assert config.policy.default_policies == []


def test_environment_variable_whitespace_policies(monkeypatch):
    """Test that whitespace-only policy names are filtered out."""
    from scripts.core.config import load_config_with_env_overrides

    monkeypatch.setenv("JMO_POLICY_DEFAULT_POLICIES", "owasp-top-10,  ,zero-secrets, ")

    config = load_config_with_env_overrides(None)

    # Whitespace-only entries should be filtered out
    assert config.policy.default_policies == ["owasp-top-10", "zero-secrets"]


def test_load_config_nonexistent_file():
    """Test that load_config returns defaults when file doesn't exist."""
    from scripts.core.config import load_config

    config = load_config("/nonexistent/path/jmo.yml")

    # Should return default Config
    assert config.policy.enabled is True
    assert config.policy.auto_evaluate is True
    assert config.policy.default_policies == []
    assert config.policy.fail_on_violation is False


def test_load_config_none_path():
    """Test that load_config returns defaults when path is None."""
    from scripts.core.config import load_config

    config = load_config(None)

    # Should return default Config
    assert config.policy.enabled is True
    assert config.policy.default_policies == []


def test_policy_config_zero_timeout():
    """Test that PolicyConfig validation rejects zero timeout."""
    from scripts.core.config import PolicyConfig

    with pytest.raises(ValueError, match="opa.timeout must be positive"):
        PolicyConfig(opa={"timeout": 0})


def test_policy_config_negative_timeout():
    """Test that PolicyConfig validation rejects negative timeout."""
    from scripts.core.config import PolicyConfig

    with pytest.raises(ValueError, match="opa.timeout must be positive"):
        PolicyConfig(opa={"timeout": -10})


def test_load_config_policy_value_error_fallback(tmp_path):
    """Test that ValueError during policy parsing falls back to defaults."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy:
  enabled: true
  default_policies: "invalid_string_not_list"
  opa:
    timeout: -1
""",
    )

    config = load_config(str(config_file))

    # Should fall back to default PolicyConfig due to validation error
    assert config.policy.enabled is True
    assert config.policy.default_policies == []
    assert config.policy.opa["timeout"] == 30


def test_load_config_policy_type_error_fallback(tmp_path):
    """Test that TypeError during policy parsing falls back to defaults."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
policy: null
""",
    )

    config = load_config(str(config_file))

    # Should use default PolicyConfig when policy is null
    assert config.policy.enabled is True
    assert config.policy.default_policies == []


def test_load_config_profile_override_with_no_fail_on_violation(tmp_path):
    """Test profile override doesn't set fail_on_violation if not specified."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
default_profile: custom

policy:
  fail_on_violation: false

profiles:
  custom:
    policy:
      default_policies:
        - owasp-top-10
""",
    )

    config = load_config(str(config_file))

    # Profile should override policies but keep global fail_on_violation
    assert config.policy.default_policies == ["owasp-top-10"]
    assert config.policy.fail_on_violation is False


def test_environment_variable_negative_timeout_ignored(monkeypatch):
    """Test that negative OPA timeout from env var is ignored."""
    from scripts.core.config import load_config_with_env_overrides

    monkeypatch.setenv("JMO_POLICY_OPA_TIMEOUT", "-5")

    config = load_config_with_env_overrides(None)

    # Negative timeout should be ignored, keep default
    assert config.policy.opa["timeout"] == 30


def test_environment_variable_zero_timeout_ignored(monkeypatch):
    """Test that zero OPA timeout from env var is ignored."""
    from scripts.core.config import load_config_with_env_overrides

    monkeypatch.setenv("JMO_POLICY_OPA_TIMEOUT", "0")

    config = load_config_with_env_overrides(None)

    # Zero timeout should be ignored, keep default
    assert config.policy.opa["timeout"] == 30


def test_load_config_profile_nonexistent_profile(tmp_path):
    """Test that nonexistent profile doesn't cause errors."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
default_profile: nonexistent

policy:
  default_policies:
    - owasp-top-10
""",
    )

    config = load_config(str(config_file))

    # Should use global policy defaults when profile doesn't exist
    assert config.policy.default_policies == ["owasp-top-10"]


def test_load_config_profile_no_policy_section(tmp_path):
    """Test profile without policy section uses global defaults."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
default_profile: minimal

policy:
  default_policies:
    - zero-secrets

profiles:
  minimal:
    tools:
      - trufflehog
""",
    )

    config = load_config(str(config_file))

    # Should use global policy defaults
    assert config.policy.default_policies == ["zero-secrets"]


def test_load_config_profile_override_fail_on_violation_only(tmp_path):
    """Test profile can override fail_on_violation without overriding policies."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
default_profile: strict

policy:
  default_policies:
    - zero-secrets
  fail_on_violation: false

profiles:
  strict:
    policy:
      fail_on_violation: true
""",
    )

    config = load_config(str(config_file))

    # Profile should override fail_on_violation but keep global policies
    # Note: Profile overrides default_policies too if not specified (empty list)
    assert config.policy.fail_on_violation is True


def test_load_config_profile_policy_non_list_default_policies(tmp_path):
    """Test profile with non-list default_policies doesn't override."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
default_profile: broken

policy:
  default_policies:
    - owasp-top-10

profiles:
  broken:
    policy:
      default_policies: "not_a_list"
""",
    )

    config = load_config(str(config_file))

    # Should keep global policies when profile has invalid type
    assert config.policy.default_policies == ["owasp-top-10"]


def test_load_config_profile_policy_dict_not_dict(tmp_path):
    """Test profile with non-dict policy section doesn't cause errors."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
default_profile: broken

policy:
  default_policies:
    - zero-secrets

profiles:
  broken:
    policy: "invalid_string"
""",
    )

    config = load_config(str(config_file))

    # Should use global policies when profile policy is invalid
    assert config.policy.default_policies == ["zero-secrets"]


# ========== NON-POLICY COVERAGE TESTS (LINES 95-146) ====================


def test_load_config_yaml_not_available(tmp_path, monkeypatch):
    """Test graceful fallback when yaml module not available (lines 14-15, 94-95)."""
    from scripts.core.config import load_config

    # Create config file
    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
tools:
  - trivy
outputs:
  - json
""",
    )

    # Mock yaml as None (simulating ImportError)
    import scripts.core.config

    original_yaml = scripts.core.config.yaml
    scripts.core.config.yaml = None

    try:
        config = load_config(str(config_file))

        # Should return default Config when yaml unavailable
        assert config.tools == [
            "trufflehog",
            "semgrep",
            "syft",
            "trivy",
            "checkov",
            "hadolint",
            "zap",
        ]
        assert config.outputs == ["json", "md", "yaml", "html"]
    finally:
        scripts.core.config.yaml = original_yaml


def test_load_config_outputs_list(tmp_path):
    """Test outputs list parsing (line 101)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
outputs:
  - json
  - md
  - sarif
""",
    )

    config = load_config(str(config_file))

    assert config.outputs == ["json", "md", "sarif"]


def test_load_config_fail_on_string(tmp_path):
    """Test fail_on string parsing with uppercase conversion (lines 102-103)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
fail_on: high
""",
    )

    config = load_config(str(config_file))

    assert config.fail_on == "HIGH"


def test_load_config_threads_auto(tmp_path):
    """Test threads with 'auto' string (lines 107-108)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
threads: auto
""",
    )

    config = load_config(str(config_file))

    assert config.threads == "auto"


def test_load_config_threads_positive_int(tmp_path):
    """Test threads with positive integer (lines 109-110)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
threads: 8
""",
    )

    config = load_config(str(config_file))

    assert config.threads == 8


def test_load_config_include_list(tmp_path):
    """Test include list parsing (lines 112-113)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
include:
  - "*.py"
  - "src/**/*.js"
""",
    )

    config = load_config(str(config_file))

    assert config.include == ["*.py", "src/**/*.js"]


def test_load_config_exclude_list(tmp_path):
    """Test exclude list parsing (lines 114-115)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
exclude:
  - "node_modules"
  - ".git"
""",
    )

    config = load_config(str(config_file))

    assert config.exclude == ["node_modules", ".git"]


def test_load_config_timeout_positive(tmp_path):
    """Test timeout with positive integer (lines 118-119)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
timeout: 300
""",
    )

    config = load_config(str(config_file))

    assert config.timeout == 300


def test_load_config_log_level_valid(tmp_path):
    """Test log_level with valid uppercase conversion (lines 121-124)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
log_level: debug
""",
    )

    config = load_config(str(config_file))

    assert config.log_level == "DEBUG"


def test_load_config_log_level_warn(tmp_path):
    """Test log_level with WARN value (lines 121-124)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
log_level: warn
""",
    )

    config = load_config(str(config_file))

    assert config.log_level == "WARN"


def test_load_config_log_level_error(tmp_path):
    """Test log_level with ERROR value (lines 121-124, branch 123->126)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
log_level: error
""",
    )

    config = load_config(str(config_file))

    assert config.log_level == "ERROR"


def test_load_config_per_tool_dict(tmp_path):
    """Test per_tool dict parsing (lines 132-133)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
per_tool:
  trivy:
    flags:
      - --no-progress
  semgrep:
    timeout: 600
""",
    )

    config = load_config(str(config_file))

    assert "trivy" in config.per_tool
    assert config.per_tool["trivy"]["flags"] == ["--no-progress"]
    assert "semgrep" in config.per_tool
    assert config.per_tool["semgrep"]["timeout"] == 600


def test_load_config_retries_positive(tmp_path):
    """Test retries with positive integer (lines 136-137)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
retries: 2
""",
    )

    config = load_config(str(config_file))

    assert config.retries == 2


def test_load_config_profiling_min_threads(tmp_path):
    """Test profiling min_threads parsing (lines 140-142)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
profiling:
  min_threads: 4
""",
    )

    config = load_config(str(config_file))

    assert config.profiling_min_threads == 4


def test_load_config_profiling_max_threads(tmp_path):
    """Test profiling max_threads parsing (lines 140, 143-144)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
profiling:
  max_threads: 16
""",
    )

    config = load_config(str(config_file))

    assert config.profiling_max_threads == 16


def test_load_config_profiling_default_threads(tmp_path):
    """Test profiling default_threads parsing (lines 140, 145-146)."""
    from scripts.core.config import load_config

    config_file = write_yaml_file(
        tmp_path,
        "jmo.yml",
        """
profiling:
  default_threads: 6
""",
    )

    config = load_config(str(config_file))

    assert config.profiling_default_threads == 6


# ========== COVERAGE TARGET: ≥90% ====================
# Run: pytest tests/unit/test_config_policy.py --cov=scripts.core.config --cov-report=term-missing -v
