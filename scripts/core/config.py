#!/usr/bin/env python3
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING, Any as AnyType

if TYPE_CHECKING:
    import yaml as YamlModule
else:
    try:
        import yaml as YamlModule  # type: ignore[assignment]
    except ImportError:
        YamlModule = None  # type: ignore[assignment]

yaml: AnyType | None = YamlModule


@dataclass
class PolicyConfig:
    """Policy-as-Code configuration (Feature #5, v1.0.0)."""

    enabled: bool = True
    auto_evaluate: bool = True  # Auto-evaluate policies after scans
    default_policies: list[str] = field(default_factory=list)
    fail_on_violation: bool = False
    opa: dict[str, Any] = field(
        default_factory=lambda: {
            "binary": "opa",
            "version": ">=0.70.0",
            "timeout": 30,
        }
    )

    def __post_init__(self) -> None:
        """Validate policy configuration."""
        if not isinstance(self.default_policies, list):
            raise ValueError("default_policies must be a list")

        if self.opa.get("timeout", 30) <= 0:
            raise ValueError("opa.timeout must be positive")

        # Merge partial OPA config with defaults
        default_opa = {
            "binary": "opa",
            "version": ">=0.70.0",
            "timeout": 30,
        }
        for key, default_value in default_opa.items():
            if key not in self.opa:
                self.opa[key] = default_value


@dataclass
class Config:
    tools: list[str] = field(
        default_factory=lambda: [
            "trufflehog",
            "semgrep",
            "syft",
            "trivy",
            "checkov",
            "hadolint",
            "zap",
        ]
    )
    outputs: list[str] = field(default_factory=lambda: ["json", "md", "yaml", "html"])
    fail_on: str = ""
    threads: int | str | None = None  # int for explicit count, 'auto' for detection
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    timeout: int | None = None
    log_level: str = "INFO"
    # Advanced
    default_profile: str | None = None
    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)
    per_tool: dict[str, dict[str, Any]] = field(default_factory=dict)
    retries: int = 0
    # Profiling thread recommendations (used when --profile flag set)
    profiling_min_threads: int = 2
    profiling_max_threads: int = 8
    profiling_default_threads: int = 4
    # Policy-as-Code configuration (Feature #5, v1.0.0)
    policy: PolicyConfig = field(default_factory=PolicyConfig)


def load_config(path: str | None) -> Config:
    """Load and parse JMo Security configuration from YAML file.

    Reads jmo.yml configuration file and returns parsed Config dataclass with
    tool selection, profiles, output formats, and per-tool overrides.

    Args:
        path (str | None): Path to jmo.yml configuration file, or None for defaults

    Returns:
        Config: Parsed configuration dataclass with keys:
            - tools (list): Enabled security tools
            - profiles (dict): Named profile configurations
            - outputs (list): Output format selection
            - per_tool (dict): Per-tool overrides
            - email (dict): Email notification settings
            - schedule (dict): Scheduled scan settings

    Raises:
        None: Returns default Config() if path is None, file missing, or YAML error

    Example:
        >>> config = load_config('jmo.yml')
        >>> print(config.default_profile)
        balanced
        >>> config = load_config(None)  # Returns defaults
        >>> print(config.tools)
        []

    Note:
        If jmo.yml not found or YAML library missing, returns default Config with empty values.
        All configuration fields are optional and have sensible defaults.

    """
    if not path:
        return Config()
    p = Path(path)
    if not p.exists():
        return Config()
    if yaml is None:
        return Config()
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    cfg = Config()
    if isinstance(data.get("tools"), list):
        cfg.tools = [str(x) for x in data["tools"]]
    if isinstance(data.get("outputs"), list):
        cfg.outputs = [str(x) for x in data["outputs"]]
    if isinstance(data.get("fail_on"), str):
        cfg.fail_on = data["fail_on"].upper()
    # threads: optional positive int, 'auto' string, or None
    # <=0 or missing -> None (auto-detect)
    tval = data.get("threads")
    if isinstance(tval, str) and tval.lower() == "auto":
        cfg.threads = "auto"
    elif isinstance(tval, int) and tval > 0:
        cfg.threads = tval
    # include/exclude
    if isinstance(data.get("include"), list):
        cfg.include = [str(x) for x in data["include"]]
    if isinstance(data.get("exclude"), list):
        cfg.exclude = [str(x) for x in data["exclude"]]
    # timeout
    tv = data.get("timeout")
    if isinstance(tv, int) and tv > 0:
        cfg.timeout = tv
    # log_level
    if isinstance(data.get("log_level"), str):
        lvl = str(data["log_level"]).upper()
        if lvl in ("DEBUG", "INFO", "WARN", "ERROR"):
            cfg.log_level = lvl
    # default_profile
    if isinstance(data.get("default_profile"), str):
        cfg.default_profile = str(data["default_profile"]).strip() or None
    # profiles (free-form dict)
    if isinstance(data.get("profiles"), dict):
        cfg.profiles = data["profiles"]
    # per_tool overrides
    if isinstance(data.get("per_tool"), dict):
        cfg.per_tool = data["per_tool"]
    # retries
    rv = data.get("retries")
    if isinstance(rv, int) and rv >= 0:
        cfg.retries = rv
    # profiling thread recommendations
    if "profiling" in data and isinstance(data["profiling"], dict):
        prof = data["profiling"]
        if isinstance(prof.get("min_threads"), int) and prof["min_threads"] > 0:
            cfg.profiling_min_threads = prof["min_threads"]
        if isinstance(prof.get("max_threads"), int) and prof["max_threads"] > 0:
            cfg.profiling_max_threads = prof["max_threads"]
        if isinstance(prof.get("default_threads"), int) and prof["default_threads"] > 0:
            cfg.profiling_default_threads = prof["default_threads"]

    # Policy configuration (Feature #5, v1.0.0)
    policy_section = data.get("policy", {})
    if isinstance(policy_section, dict):
        try:
            # Build OPA config with defaults
            opa_config = {
                "binary": "opa",
                "version": ">=0.70.0",
                "timeout": 30,
            }
            if isinstance(policy_section.get("opa"), dict):
                opa_config.update(policy_section["opa"])

            # Create PolicyConfig
            policy_config = PolicyConfig(
                enabled=policy_section.get("enabled", True),
                auto_evaluate=policy_section.get("auto_evaluate", True),
                default_policies=(
                    policy_section.get("default_policies", [])
                    if isinstance(policy_section.get("default_policies"), list)
                    else []
                ),
                fail_on_violation=policy_section.get("fail_on_violation", False),
                opa=opa_config,
            )

            # Apply profile-specific policy overrides
            profile_name = cfg.default_profile or data.get("default_profile")
            if profile_name and isinstance(cfg.profiles.get(profile_name), dict):
                profile_data = cfg.profiles[profile_name]
                if isinstance(profile_data.get("policy"), dict):
                    profile_policy = profile_data["policy"]
                    # Override with profile-specific settings
                    if isinstance(profile_policy.get("default_policies"), list):
                        policy_config.default_policies = profile_policy[
                            "default_policies"
                        ]
                    if "fail_on_violation" in profile_policy:
                        policy_config.fail_on_violation = profile_policy[
                            "fail_on_violation"
                        ]

            cfg.policy = policy_config
        except (ValueError, TypeError):
            # If policy config is invalid, use defaults
            cfg.policy = PolicyConfig()

    return cfg


def load_config_with_env_overrides(path: str | None) -> Config:
    """Load configuration with environment variable overrides.

    Environment variables take highest precedence:
    1. CLI arguments (handled by caller)
    2. Environment variables (this function)
    3. jmo.yml config file
    4. Profile defaults
    """
    config = load_config(path)

    # Override policy settings from environment
    if os.getenv("JMO_POLICY_ENABLED"):
        config.policy.enabled = os.getenv("JMO_POLICY_ENABLED", "").lower() == "true"

    if os.getenv("JMO_POLICY_AUTO_EVALUATE"):
        config.policy.auto_evaluate = (
            os.getenv("JMO_POLICY_AUTO_EVALUATE", "").lower() == "true"
        )

    if os.getenv("JMO_POLICY_DEFAULT_POLICIES"):
        policies_str = os.getenv("JMO_POLICY_DEFAULT_POLICIES", "")
        config.policy.default_policies = [
            p.strip() for p in policies_str.split(",") if p.strip()
        ]

    if os.getenv("JMO_POLICY_FAIL_ON_VIOLATION"):
        config.policy.fail_on_violation = (
            os.getenv("JMO_POLICY_FAIL_ON_VIOLATION", "").lower() == "true"
        )

    if os.getenv("JMO_POLICY_OPA_BINARY"):
        config.policy.opa["binary"] = os.getenv("JMO_POLICY_OPA_BINARY", "opa")

    if os.getenv("JMO_POLICY_OPA_TIMEOUT"):
        try:
            timeout = int(os.getenv("JMO_POLICY_OPA_TIMEOUT", "30"))
            if timeout > 0:
                config.policy.opa["timeout"] = timeout
        except ValueError:
            pass  # Keep existing timeout if invalid

    return config
