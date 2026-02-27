#!/usr/bin/env python3
from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING, Any as AnyType

if TYPE_CHECKING:
    import yaml as YamlModule
else:
    try:
        import yaml as YamlModule  # type: ignore[assignment]  # PyYAML vs ruamel.yaml type mismatch
    except ImportError:
        YamlModule = None  # type: ignore[assignment]  # Fallback when yaml not installed

yaml: AnyType | None = YamlModule


@dataclass
class DeduplicationConfig:
    """Deduplication configuration for cross-tool finding clustering.

    Controls the similarity threshold used by FindingClusterer to identify
    and merge duplicate findings from different security tools.
    """

    similarity_threshold: float = 0.65  # Default threshold (0.5-1.0)

    def __post_init__(self) -> None:
        """Validate deduplication configuration."""
        if not isinstance(self.similarity_threshold, (int, float)):
            raise ValueError("similarity_threshold must be a number")
        if not 0.5 <= self.similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be between 0.5 and 1.0")


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
class RetryConfig:
    """Typed retry configuration with per-failure-type retry budgets.

    Different failure types get different retry strategies:
    - timeout: max_attempts + timeout_retries (transient, worth retrying)
    - crash: max_attempts (may be transient)
    - missing_tool: 1 (never retry, tool won't appear)
    - system_error: max_attempts (permissions, OS errors)
    """

    max_attempts: int = 2  # Total base attempts (1 = no retry)
    timeout_retries: int = 1  # Extra retries specifically for timeouts
    backoff_base: float = 1.0  # Base backoff in seconds
    backoff_max: float = 5.0  # Max backoff cap
    retry_on_timeout: bool = True
    retry_on_crash: bool = True
    retry_on_parse_error: bool = False  # Reserved for future

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError(f"max_attempts must be >= 1, got {self.max_attempts}")
        if self.timeout_retries < 0:
            raise ValueError(
                f"timeout_retries must be >= 0, got {self.timeout_retries}"
            )
        if self.backoff_base < 0:
            raise ValueError(f"backoff_base must be >= 0, got {self.backoff_base}")
        if self.backoff_max < 0:
            raise ValueError(f"backoff_max must be >= 0, got {self.backoff_max}")

    def attempts_for_failure(self, failure_type: str) -> int:
        """Return total attempts allowed for a failure type."""
        if failure_type == "timeout":
            if not self.retry_on_timeout:
                return 1
            return self.max_attempts + self.timeout_retries
        if failure_type == "missing_tool":
            return 1  # Never retry
        if failure_type == "crash":
            if not self.retry_on_crash:
                return 1
            return self.max_attempts
        # system_error, unknown
        return self.max_attempts

    def backoff_delay(self, attempt: int) -> float:
        """Exponential backoff capped at backoff_max.

        attempt is 1-based (attempt 1 = first try, attempt 2 = first retry).
        """
        if attempt <= 1:
            return 0.0
        delay = self.backoff_base * math.pow(2, attempt - 2)
        return min(delay, self.backoff_max)

    @classmethod
    def from_flat_retries(cls, retries: int) -> RetryConfig:
        """Backward compat: convert flat int retries to RetryConfig.

        retries=0 -> max_attempts=1, timeout_retries=0 (no retries)
        retries=1 -> max_attempts=2, timeout_retries=0
        retries=2 -> max_attempts=3, timeout_retries=0
        """
        return cls(max_attempts=retries + 1, timeout_retries=0)


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
    retries: int | RetryConfig = 0
    # Profiling thread recommendations (used when --profile flag set)
    profiling_min_threads: int = 2
    profiling_max_threads: int = 8
    profiling_default_threads: int = 4
    # Deduplication configuration (configurable threshold)
    deduplication: DeduplicationConfig = field(default_factory=DeduplicationConfig)
    # Policy-as-Code configuration (Feature #5, v1.0.0)
    policy: PolicyConfig = field(default_factory=PolicyConfig)

    @property
    def retry_config(self) -> RetryConfig:
        """Get retries as a RetryConfig, converting flat int if needed."""
        if isinstance(self.retries, RetryConfig):
            return self.retries
        return RetryConfig.from_flat_retries(self.retries)


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
    # retries (int for backward compat, or dict for typed config)
    rv = data.get("retries")
    if isinstance(rv, int) and rv >= 0:
        cfg.retries = rv
    elif isinstance(rv, dict):
        cfg.retries = RetryConfig(
            max_attempts=rv.get("max_attempts", 2),
            timeout_retries=rv.get("timeout_retries", 1),
            backoff_base=float(rv.get("backoff_base", 1.0)),
            backoff_max=float(rv.get("backoff_max", 5.0)),
            retry_on_timeout=rv.get("retry_on_timeout", True),
            retry_on_crash=rv.get("retry_on_crash", True),
            retry_on_parse_error=rv.get("retry_on_parse_error", False),
        )
    # profiling thread recommendations
    if "profiling" in data and isinstance(data["profiling"], dict):
        prof = data["profiling"]
        if isinstance(prof.get("min_threads"), int) and prof["min_threads"] > 0:
            cfg.profiling_min_threads = prof["min_threads"]
        if isinstance(prof.get("max_threads"), int) and prof["max_threads"] > 0:
            cfg.profiling_max_threads = prof["max_threads"]
        if isinstance(prof.get("default_threads"), int) and prof["default_threads"] > 0:
            cfg.profiling_default_threads = prof["default_threads"]

    # Deduplication configuration
    dedup_section = data.get("deduplication", {})
    if isinstance(dedup_section, dict):
        try:
            threshold = dedup_section.get("similarity_threshold", 0.65)
            if isinstance(threshold, (int, float)) and 0.5 <= threshold <= 1.0:
                cfg.deduplication = DeduplicationConfig(
                    similarity_threshold=float(threshold)
                )
        except (ValueError, TypeError):
            # If dedup config is invalid, use defaults
            cfg.deduplication = DeduplicationConfig()

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

    # Override deduplication settings from environment
    if os.getenv("JMO_DEDUP_THRESHOLD"):
        try:
            threshold = float(os.getenv("JMO_DEDUP_THRESHOLD", "0.65"))
            if 0.5 <= threshold <= 1.0:
                config.deduplication.similarity_threshold = threshold
        except ValueError:
            pass  # Keep existing threshold if invalid

    return config
