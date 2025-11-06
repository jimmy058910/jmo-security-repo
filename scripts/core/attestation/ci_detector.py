"""
CI/CD Environment Detection for Auto-Attestation.

This module detects CI/CD environments and determines whether auto-attestation
should be enabled based on a three-tier priority system:
1. CLI flag (highest priority)
2. Environment variable (JMO_ATTEST_ENABLED)
3. Config file (lowest priority)

Supported CI environments:
- GitHub Actions
- GitLab CI
- Generic CI (CI=true)
- Local (non-CI)
"""

import os
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class CIDetector:
    """
    Detect CI/CD environments and auto-attestation requirements.

    Three-tier priority system for auto-attestation:
    1. CLI flag (--attest / --no-attest) - highest priority
    2. Environment variable (JMO_ATTEST_ENABLED=true/false)
    3. Config file (jmo.yml: attestation.auto_attest)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize CI detector.

        Args:
            config: Optional configuration dict with attestation settings
        """
        self.config = config or {}

    def is_ci(self) -> bool:
        """
        Check if running in CI/CD environment.

        Returns:
            True if in CI, False if local
        """
        return os.getenv("CI") == "true"

    def get_ci_provider(self) -> str:
        """
        Detect specific CI provider.

        Returns:
            CI provider name: "github", "gitlab", "generic", or "local"
        """
        if os.getenv("GITHUB_ACTIONS") == "true":
            return "github"
        elif os.getenv("GITLAB_CI") == "true":
            return "gitlab"
        elif os.getenv("CI") == "true":
            return "generic"
        else:
            return "local"

    def should_auto_attest(self, cli_flag: Optional[bool] = None) -> bool:
        """
        Determine if auto-attestation should be enabled.

        Three-tier priority system:
        1. CLI flag (--attest / --no-attest) - highest priority
        2. Environment variable (JMO_ATTEST_ENABLED=true/false)
        3. Config file (jmo.yml: attestation.auto_attest)

        Args:
            cli_flag: CLI flag value (True/False/None)
                     None = not specified, check lower priorities

        Returns:
            True if auto-attestation should be enabled, False otherwise
        """
        # Priority 1: CLI flag (highest)
        if cli_flag is not None:
            logger.debug(f"Auto-attestation determined by CLI flag: {cli_flag}")
            return cli_flag

        # Priority 2: Environment variable
        env_var = os.getenv("JMO_ATTEST_ENABLED")
        if env_var is not None:
            # Parse env var (handle true/false/1/0)
            env_value = self._parse_bool_env(env_var)
            if env_value is not None:
                logger.debug(f"Auto-attestation determined by env var: {env_value}")
                return env_value and self.is_ci()  # Only in CI environment

        # Priority 3: Config file (lowest)
        config_value = self.config.get("attestation", {}).get("auto_attest")
        if config_value is True:
            logger.debug("Auto-attestation determined by config file: True")
            return self.is_ci()  # Only in CI environment

        # Default: do not auto-attest (conservative)
        logger.debug("Auto-attestation disabled (default)")
        return False

    def _parse_bool_env(self, value: str) -> Optional[bool]:
        """
        Parse boolean environment variable.

        Accepts: true/false/1/0/yes/no (case-insensitive)

        Args:
            value: Environment variable string

        Returns:
            True/False if valid, None if invalid
        """
        value_lower = value.lower().strip()
        if value_lower in ("true", "1", "yes"):
            return True
        elif value_lower in ("false", "0", "no"):
            return False
        else:
            logger.warning(f"Invalid JMO_ATTEST_ENABLED value: {value}, treating as not set")
            return None
