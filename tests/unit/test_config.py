#!/usr/bin/env python3
"""Comprehensive tests for config.py module.

This test suite provides ≥85% coverage for scripts/core/config.py, testing:
1. Config dataclass defaults and initialization
2. load_config() function with various file states
3. Profile loading (fast/balanced/deep)
4. Per-tool overrides
5. PolicyConfig and policy loading
6. Environment variable overrides (load_config_with_env_overrides)
7. Edge cases and error handling

Target Coverage: ≥85%
"""

from pathlib import Path
import pytest


def write_yaml_file(tmp_path: Path, filename: str, content: str) -> Path:
    """Helper to write YAML config files for testing."""
    yaml_file = tmp_path / filename
    yaml_file.write_text(content, encoding="utf-8")
    return yaml_file


# ========== Category 1: Config Dataclass Defaults ==========


def test_config_default_values():
    """Test Config dataclass has correct default values."""
    from scripts.core.config import Config

    cfg = Config()

    # Verify default tools list
    assert isinstance(cfg.tools, list)
    assert len(cfg.tools) == 7
    expected_tools = [
        "trufflehog",
        "semgrep",
        "syft",
        "trivy",
        "checkov",
        "hadolint",
        "zap",
    ]
    assert cfg.tools == expected_tools

    # Verify default outputs
    assert isinstance(cfg.outputs, list)
    assert cfg.outputs == ["json", "md", "yaml", "html"]

    # Verify other defaults
    assert cfg.fail_on == ""
    assert cfg.threads is None
    assert cfg.include == []
    assert cfg.exclude == []
    assert cfg.timeout is None
    assert cfg.log_level == "INFO"
    assert cfg.default_profile is None
    assert cfg.profiles == {}
    assert cfg.per_tool == {}
    assert cfg.retries == 0
    assert cfg.profiling_min_threads == 2
    assert cfg.profiling_max_threads == 8
    assert cfg.profiling_default_threads == 4


def test_config_custom_initialization():
    """Test Config can be initialized with custom values."""
    from scripts.core.config import Config

    cfg = Config(
        tools=["tool1", "tool2"],
        outputs=["json"],
        fail_on="HIGH",
        threads=4,
        include=["src/"],
        exclude=["tests/"],
        timeout=600,
        log_level="DEBUG",
        retries=2,
    )

    assert cfg.tools == ["tool1", "tool2"]
    assert cfg.outputs == ["json"]
    assert cfg.fail_on == "HIGH"
    assert cfg.threads == 4
    assert cfg.include == ["src/"]
    assert cfg.exclude == ["tests/"]
    assert cfg.timeout == 600
    assert cfg.log_level == "DEBUG"
    assert cfg.retries == 2


# ========== Category 2: Basic Config Loading ==========


def test_load_config_none_path():
    """Test load_config returns defaults when path is None."""
    from scripts.core.config import load_config

    cfg = load_config(None)

    assert isinstance(cfg.tools, list)
    assert len(cfg.tools) == 7
    assert cfg.log_level == "INFO"


def test_load_config_nonexistent_file(tmp_path: Path):
    """Test load_config returns defaults when file doesn't exist."""
    from scripts.core.config import load_config

    cfg = load_config(str(tmp_path / "nonexistent.yml"))

    assert isinstance(cfg.tools, list)
    assert len(cfg.tools) == 7


def test_load_config_empty_file(tmp_path: Path):
    """Test load_config handles empty YAML file."""
    from scripts.core.config import load_config

    yaml_file = write_yaml_file(tmp_path, "empty.yml", "")
    cfg = load_config(str(yaml_file))

    # Should return defaults
    assert len(cfg.tools) == 7
    assert cfg.outputs == ["json", "md", "yaml", "html"]


def test_load_config_minimal_valid(tmp_path: Path):
    """Test load_config with minimal valid configuration."""
    from scripts.core.config import load_config

    yaml_content = """
tools:
  - trufflehog
  - semgrep
outputs:
  - json
  - md
"""
    yaml_file = write_yaml_file(tmp_path, "minimal.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.tools == ["trufflehog", "semgrep"]
    assert cfg.outputs == ["json", "md"]


# ========== Category 3: Tools and Outputs Configuration ==========


def test_load_config_tools_list(tmp_path: Path):
    """Test loading tools as list."""
    from scripts.core.config import load_config

    yaml_content = """
tools:
  - tool1
  - tool2
  - tool3
"""
    yaml_file = write_yaml_file(tmp_path, "tools.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.tools == ["tool1", "tool2", "tool3"]


def test_load_config_tools_not_list(tmp_path: Path):
    """Test tools field ignored if not a list."""
    from scripts.core.config import load_config

    yaml_content = """
tools: "not-a-list"
"""
    yaml_file = write_yaml_file(tmp_path, "tools_invalid.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    # Should use defaults
    assert len(cfg.tools) == 7


def test_load_config_outputs_list(tmp_path: Path):
    """Test loading outputs as list."""
    from scripts.core.config import load_config

    yaml_content = """
outputs:
  - json
  - sarif
"""
    yaml_file = write_yaml_file(tmp_path, "outputs.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.outputs == ["json", "sarif"]


def test_load_config_outputs_not_list(tmp_path: Path):
    """Test outputs field ignored if not a list."""
    from scripts.core.config import load_config

    yaml_content = """
outputs: json
"""
    yaml_file = write_yaml_file(tmp_path, "outputs_invalid.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    # Should use defaults
    assert cfg.outputs == ["json", "md", "yaml", "html"]


# ========== Category 4: Fail-On Configuration ==========


def test_load_config_fail_on_valid(tmp_path: Path):
    """Test fail_on setting with valid severity."""
    from scripts.core.config import load_config

    yaml_content = """
fail_on: high
"""
    yaml_file = write_yaml_file(tmp_path, "fail_on.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.fail_on == "HIGH"  # Should be uppercased


def test_load_config_fail_on_case_insensitive(tmp_path: Path):
    """Test fail_on is uppercased."""
    from scripts.core.config import load_config

    test_cases = ["critical", "High", "MEDIUM", "low"]

    for severity in test_cases:
        yaml_content = f"fail_on: {severity}"
        yaml_file = write_yaml_file(tmp_path, f"fail_{severity}.yml", yaml_content)
        cfg = load_config(str(yaml_file))
        assert cfg.fail_on == severity.upper()


def test_load_config_fail_on_not_string(tmp_path: Path):
    """Test fail_on ignored if not a string."""
    from scripts.core.config import load_config

    yaml_content = """
fail_on: 123
"""
    yaml_file = write_yaml_file(tmp_path, "fail_on_invalid.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.fail_on == ""  # Should use default


# ========== Category 5: Threads Configuration ==========


def test_load_config_threads_positive_int(tmp_path: Path):
    """Test threads setting with positive integer."""
    from scripts.core.config import load_config

    yaml_content = """
threads: 8
"""
    yaml_file = write_yaml_file(tmp_path, "threads.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.threads == 8


def test_load_config_threads_auto(tmp_path: Path):
    """Test threads with 'auto' string."""
    from scripts.core.config import load_config

    yaml_content = """
threads: auto
"""
    yaml_file = write_yaml_file(tmp_path, "threads_auto.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.threads == "auto"


def test_load_config_threads_zero(tmp_path: Path):
    """Test threads=0 is treated as None (auto)."""
    from scripts.core.config import load_config

    yaml_content = """
threads: 0
"""
    yaml_file = write_yaml_file(tmp_path, "threads_zero.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.threads is None


def test_load_config_threads_negative(tmp_path: Path):
    """Test negative threads is treated as None (auto)."""
    from scripts.core.config import load_config

    yaml_content = """
threads: -1
"""
    yaml_file = write_yaml_file(tmp_path, "threads_negative.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.threads is None


# ========== Category 6: Include/Exclude Configuration ==========


def test_load_config_include_list(tmp_path: Path):
    """Test include patterns as list."""
    from scripts.core.config import load_config

    yaml_content = """
include:
  - "src/**/*.py"
  - "lib/**/*.js"
"""
    yaml_file = write_yaml_file(tmp_path, "include.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.include == ["src/**/*.py", "lib/**/*.js"]


def test_load_config_exclude_list(tmp_path: Path):
    """Test exclude patterns as list."""
    from scripts.core.config import load_config

    yaml_content = """
exclude:
  - "tests/"
  - "*.test.js"
"""
    yaml_file = write_yaml_file(tmp_path, "exclude.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.exclude == ["tests/", "*.test.js"]


def test_load_config_include_not_list(tmp_path: Path):
    """Test include ignored if not a list."""
    from scripts.core.config import load_config

    yaml_content = """
include: "src/"
"""
    yaml_file = write_yaml_file(tmp_path, "include_invalid.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.include == []


def test_load_config_exclude_not_list(tmp_path: Path):
    """Test exclude ignored if not a list."""
    from scripts.core.config import load_config

    yaml_content = """
exclude: "tests/"
"""
    yaml_file = write_yaml_file(tmp_path, "exclude_invalid.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.exclude == []


# ========== Category 7: Timeout Configuration ==========


def test_load_config_timeout_positive_int(tmp_path: Path):
    """Test timeout with positive integer."""
    from scripts.core.config import load_config

    yaml_content = """
timeout: 600
"""
    yaml_file = write_yaml_file(tmp_path, "timeout.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.timeout == 600


def test_load_config_timeout_zero(tmp_path: Path):
    """Test timeout=0 is treated as None."""
    from scripts.core.config import load_config

    yaml_content = """
timeout: 0
"""
    yaml_file = write_yaml_file(tmp_path, "timeout_zero.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.timeout is None


def test_load_config_timeout_negative(tmp_path: Path):
    """Test negative timeout is treated as None."""
    from scripts.core.config import load_config

    yaml_content = """
timeout: -100
"""
    yaml_file = write_yaml_file(tmp_path, "timeout_negative.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.timeout is None


# ========== Category 8: Log Level Configuration ==========


def test_load_config_log_level_valid(tmp_path: Path):
    """Test log_level with valid levels."""
    from scripts.core.config import load_config

    valid_levels = ["DEBUG", "INFO", "WARN", "ERROR"]

    for level in valid_levels:
        yaml_content = f"log_level: {level}"
        yaml_file = write_yaml_file(tmp_path, f"log_{level}.yml", yaml_content)
        cfg = load_config(str(yaml_file))
        assert cfg.log_level == level


def test_load_config_log_level_case_insensitive(tmp_path: Path):
    """Test log_level is uppercased."""
    from scripts.core.config import load_config

    yaml_content = """
log_level: debug
"""
    yaml_file = write_yaml_file(tmp_path, "log_lower.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.log_level == "DEBUG"


def test_load_config_log_level_invalid(tmp_path: Path):
    """Test invalid log_level is ignored."""
    from scripts.core.config import load_config

    yaml_content = """
log_level: INVALID
"""
    yaml_file = write_yaml_file(tmp_path, "log_invalid.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.log_level == "INFO"  # Should use default


# ========== Category 9: Default Profile Configuration ==========


def test_load_config_default_profile(tmp_path: Path):
    """Test default_profile setting."""
    from scripts.core.config import load_config

    yaml_content = """
default_profile: fast
"""
    yaml_file = write_yaml_file(tmp_path, "profile.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.default_profile == "fast"


def test_load_config_default_profile_strips_whitespace(tmp_path: Path):
    """Test default_profile strips whitespace."""
    from scripts.core.config import load_config

    yaml_content = """
default_profile: "  balanced  "
"""
    yaml_file = write_yaml_file(tmp_path, "profile_spaces.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.default_profile == "balanced"


def test_load_config_default_profile_empty_string(tmp_path: Path):
    """Test empty default_profile becomes None."""
    from scripts.core.config import load_config

    yaml_content = """
default_profile: ""
"""
    yaml_file = write_yaml_file(tmp_path, "profile_empty.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.default_profile is None


# ========== Category 10: Profiles Configuration ==========


def test_load_config_profiles_dict(tmp_path: Path):
    """Test profiles as dictionary."""
    from scripts.core.config import load_config

    yaml_content = """
profiles:
  fast:
    tools: [trufflehog, semgrep]
    timeout: 300
  balanced:
    tools: [trufflehog, semgrep, trivy]
    timeout: 600
  deep:
    tools: [trufflehog, semgrep, bandit, trivy]
    timeout: 900
"""
    yaml_file = write_yaml_file(tmp_path, "profiles.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert isinstance(cfg.profiles, dict)
    assert "fast" in cfg.profiles
    assert "balanced" in cfg.profiles
    assert "deep" in cfg.profiles
    assert cfg.profiles["fast"]["timeout"] == 300
    assert cfg.profiles["balanced"]["timeout"] == 600
    assert cfg.profiles["deep"]["timeout"] == 900


def test_load_config_profiles_empty(tmp_path: Path):
    """Test empty profiles dict."""
    from scripts.core.config import load_config

    yaml_content = """
profiles: {}
"""
    yaml_file = write_yaml_file(tmp_path, "profiles_empty.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.profiles == {}


def test_load_config_profiles_not_dict(tmp_path: Path):
    """Test profiles ignored if not a dict."""
    from scripts.core.config import load_config

    yaml_content = """
profiles: "invalid"
"""
    yaml_file = write_yaml_file(tmp_path, "profiles_invalid.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.profiles == {}


# ========== Category 11: Per-Tool Configuration ==========


def test_load_config_per_tool_dict(tmp_path: Path):
    """Test per_tool overrides as dictionary."""
    from scripts.core.config import load_config

    yaml_content = """
per_tool:
  semgrep:
    flags: ["--exclude", "node_modules"]
    timeout: 1200
  trivy:
    flags: ["--no-progress"]
  trufflehog:
    timeout: 900
"""
    yaml_file = write_yaml_file(tmp_path, "per_tool.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert isinstance(cfg.per_tool, dict)
    assert "semgrep" in cfg.per_tool
    assert "trivy" in cfg.per_tool
    assert "trufflehog" in cfg.per_tool
    assert cfg.per_tool["semgrep"]["timeout"] == 1200
    assert cfg.per_tool["trivy"]["flags"] == ["--no-progress"]
    assert cfg.per_tool["trufflehog"]["timeout"] == 900


def test_load_config_per_tool_empty(tmp_path: Path):
    """Test empty per_tool dict."""
    from scripts.core.config import load_config

    yaml_content = """
per_tool: {}
"""
    yaml_file = write_yaml_file(tmp_path, "per_tool_empty.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.per_tool == {}


def test_load_config_per_tool_not_dict(tmp_path: Path):
    """Test per_tool ignored if not a dict."""
    from scripts.core.config import load_config

    yaml_content = """
per_tool: "invalid"
"""
    yaml_file = write_yaml_file(tmp_path, "per_tool_invalid.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.per_tool == {}


# ========== Category 12: Retries Configuration ==========


def test_load_config_retries_positive(tmp_path: Path):
    """Test retries with positive integer."""
    from scripts.core.config import load_config

    yaml_content = """
retries: 2
"""
    yaml_file = write_yaml_file(tmp_path, "retries.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.retries == 2


def test_load_config_retries_zero(tmp_path: Path):
    """Test retries=0 is accepted."""
    from scripts.core.config import load_config

    yaml_content = """
retries: 0
"""
    yaml_file = write_yaml_file(tmp_path, "retries_zero.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.retries == 0


def test_load_config_retries_negative(tmp_path: Path):
    """Test negative retries is ignored."""
    from scripts.core.config import load_config

    yaml_content = """
retries: -1
"""
    yaml_file = write_yaml_file(tmp_path, "retries_negative.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.retries == 0  # Should use default


# ========== Category 13: Profiling Configuration ==========


def test_load_config_profiling_settings(tmp_path: Path):
    """Test profiling thread recommendations."""
    from scripts.core.config import load_config

    yaml_content = """
profiling:
  min_threads: 1
  max_threads: 16
  default_threads: 6
"""
    yaml_file = write_yaml_file(tmp_path, "profiling.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.profiling_min_threads == 1
    assert cfg.profiling_max_threads == 16
    assert cfg.profiling_default_threads == 6


def test_load_config_profiling_partial(tmp_path: Path):
    """Test profiling with only some fields set."""
    from scripts.core.config import load_config

    yaml_content = """
profiling:
  max_threads: 12
"""
    yaml_file = write_yaml_file(tmp_path, "profiling_partial.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.profiling_min_threads == 2  # Default
    assert cfg.profiling_max_threads == 12
    assert cfg.profiling_default_threads == 4  # Default


def test_load_config_profiling_zero_values(tmp_path: Path):
    """Test profiling with zero values are ignored."""
    from scripts.core.config import load_config

    yaml_content = """
profiling:
  min_threads: 0
  max_threads: 0
  default_threads: 0
"""
    yaml_file = write_yaml_file(tmp_path, "profiling_zero.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    # Should use defaults (zeros are ignored)
    assert cfg.profiling_min_threads == 2
    assert cfg.profiling_max_threads == 8
    assert cfg.profiling_default_threads == 4


# ========== Category 14: PolicyConfig Tests ==========


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


# ========== Category 15: Policy Configuration Loading ==========


def test_load_config_with_policy_section(tmp_path: Path):
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


def test_load_config_without_policy_section(tmp_path: Path):
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


def test_load_config_policy_profile_override(tmp_path: Path):
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
  balanced:
    policy:
      default_policies:
        - owasp-top-10
        - zero-secrets
      fail_on_violation: false
""",
    )

    config = load_config(str(config_file))

    # Default profile is balanced, should use balanced policies
    assert config.policy.default_policies == ["owasp-top-10", "zero-secrets"]
    assert config.policy.fail_on_violation is False


# ========== Category 16: Environment Variable Overrides ==========


def test_environment_variable_override_enabled(monkeypatch, tmp_path: Path):
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


def test_environment_variable_override_default_policies(monkeypatch, tmp_path: Path):
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


def test_environment_variable_override_opa_timeout(monkeypatch, tmp_path: Path):
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


# ========== Category 17: Complete Configuration ==========


def test_load_config_complete(tmp_path: Path):
    """Test loading complete configuration with all fields."""
    from scripts.core.config import load_config

    yaml_content = """
tools:
  - trufflehog
  - semgrep
  - trivy
outputs:
  - json
  - sarif
fail_on: HIGH
threads: 4
include:
  - "src/**"
exclude:
  - "tests/**"
timeout: 600
log_level: DEBUG
default_profile: balanced
profiles:
  fast:
    tools: [trufflehog, semgrep]
    timeout: 300
  balanced:
    tools: [trufflehog, semgrep, trivy]
    timeout: 600
  deep:
    tools: [trufflehog, semgrep, bandit, trivy]
    timeout: 900
per_tool:
  semgrep:
    timeout: 1200
  trivy:
    flags: ["--no-progress"]
retries: 1
profiling:
  min_threads: 1
  max_threads: 16
  default_threads: 6
policy:
  enabled: true
  default_policies:
    - owasp-top-10
    - zero-secrets
"""
    yaml_file = write_yaml_file(tmp_path, "complete.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    # Verify all fields loaded correctly
    assert cfg.tools == ["trufflehog", "semgrep", "trivy"]
    assert cfg.outputs == ["json", "sarif"]
    assert cfg.fail_on == "HIGH"
    assert cfg.threads == 4
    assert cfg.include == ["src/**"]
    assert cfg.exclude == ["tests/**"]
    assert cfg.timeout == 600
    assert cfg.log_level == "DEBUG"
    assert cfg.default_profile == "balanced"
    assert "fast" in cfg.profiles
    assert "balanced" in cfg.profiles
    assert "deep" in cfg.profiles
    assert "semgrep" in cfg.per_tool
    assert "trivy" in cfg.per_tool
    assert cfg.retries == 1
    assert cfg.profiling_min_threads == 1
    assert cfg.profiling_max_threads == 16
    assert cfg.profiling_default_threads == 6
    assert cfg.policy.enabled is True
    assert cfg.policy.default_policies == ["owasp-top-10", "zero-secrets"]


# ========== Category 18: Edge Cases ==========


def test_load_config_yaml_with_comments(tmp_path: Path):
    """Test loading YAML with comments."""
    from scripts.core.config import load_config

    yaml_content = """
# Main configuration
tools:
  - trufflehog  # Secret scanning
  - semgrep     # SAST
# Output formats
outputs:
  - json
"""
    yaml_file = write_yaml_file(tmp_path, "with_comments.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    assert cfg.tools == ["trufflehog", "semgrep"]
    assert cfg.outputs == ["json"]


def test_load_config_null_values(tmp_path: Path):
    """Test loading YAML with null values."""
    from scripts.core.config import load_config

    yaml_content = """
threads: null
timeout: null
default_profile: null
"""
    yaml_file = write_yaml_file(tmp_path, "nulls.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    # Nulls should be treated as missing (use defaults)
    assert cfg.threads is None
    assert cfg.timeout is None
    assert cfg.default_profile is None


def test_load_config_mixed_types_in_lists(tmp_path: Path):
    """Test loading lists with mixed types (converted to strings)."""
    from scripts.core.config import load_config

    yaml_content = """
tools:
  - trufflehog
  - 123
  - true
"""
    yaml_file = write_yaml_file(tmp_path, "mixed_types.yml", yaml_content)
    cfg = load_config(str(yaml_file))

    # All should be converted to strings
    assert cfg.tools == ["trufflehog", "123", "True"]


def test_load_config_invalid_policy_section_ignored(tmp_path: Path):
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


def test_environment_variable_invalid_timeout_ignored(monkeypatch):
    """Test that invalid OPA timeout environment variable is ignored."""
    from scripts.core.config import load_config_with_env_overrides

    monkeypatch.setenv("JMO_POLICY_OPA_TIMEOUT", "invalid")

    config = load_config_with_env_overrides(None)

    # Should keep default timeout (30) when invalid value provided
    assert config.policy.opa["timeout"] == 30


def test_environment_variable_whitespace_policies(monkeypatch):
    """Test that whitespace-only policy names are filtered out."""
    from scripts.core.config import load_config_with_env_overrides

    monkeypatch.setenv("JMO_POLICY_DEFAULT_POLICIES", "owasp-top-10,  ,zero-secrets, ")

    config = load_config_with_env_overrides(None)

    # Whitespace-only entries should be filtered out
    assert config.policy.default_policies == ["owasp-top-10", "zero-secrets"]
