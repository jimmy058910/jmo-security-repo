"""Plugin API for tool adapters (INTERNAL USE ONLY).

This module provides the base classes and interfaces for JMo Security's
internal tool adapter architecture. The plugin system enables:

1. Faster tool integration (4 hours → 1 hour, 75% reduction)
2. Independent adapter updates (ship without core releases)
3. Hot-reload during development (no reinstall needed)
4. Low-risk experimentation (test new tools without committing)

IMPORTANT: This is for JMo Security's internal tool management,
NOT for community plugin development.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.core.common_finding import fingerprint


@dataclass
class Finding:
    """CommonFinding schema v1.2.0.

    Unified data structure for security findings from all tools.
    All tool outputs are normalized to this schema for consistent
    reporting, deduplication, and compliance mapping.
    """

    schemaVersion: str = "1.2.0"
    id: str = ""  # Fingerprint for deduplication
    ruleId: str = ""
    severity: str = ""  # CRITICAL|HIGH|MEDIUM|LOW|INFO
    tool: dict[str, str] = field(default_factory=dict)  # {name, version}
    location: dict[str, Any] = field(default_factory=dict)  # {path, startLine, endLine}
    message: str = ""
    title: str | None = None
    description: str | None = None
    remediation: str | dict[str, Any] | None = None  # v1.1.0: Can be dict with autofix
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cvss: dict[str, Any] | None = None
    risk: dict[str, Any] | None = None
    compliance: dict[str, Any] | None = None
    context: dict[str, Any] | None = None
    raw: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert Finding to dictionary, excluding None values.

        Returns:
            Dict: Finding data with None values filtered out
        """
        result = {}
        for key, value in self.__dict__.items():
            if value is not None:
                result[key] = value
        return result


@dataclass
class PluginMetadata:
    """Plugin metadata for internal tracking.

    Metadata provides information about the adapter plugin for
    registration, discovery, and validation purposes.
    """

    name: str
    version: str
    author: str = "JMo Security"
    description: str = ""
    tool_name: str = ""  # Name of security tool this adapter wraps
    tool_version: str | None = None
    schema_version: str = "1.2.0"  # CommonFinding schema version
    output_format: str = "json"  # json|ndjson|yaml|xml
    exit_codes: dict[int, str] = field(
        default_factory=dict
    )  # {0: 'clean', 1: 'findings'}


class AdapterPlugin(ABC):
    """Abstract base class for tool adapters.

    INTERNAL USE: This is for JMo Security's internal tool management,
    not for community plugin development.

    All tool adapters should inherit from this class and implement:
    - metadata property: Return plugin metadata
    - parse() method: Parse tool output and return normalized findings

    Optional overrides:
    - validate(): Custom validation logic
    - get_fingerprint(): Custom fingerprinting logic
    """

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata.

        Returns:
            PluginMetadata: Plugin metadata including name, version, etc.
        """

    @abstractmethod
    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to tool output file (JSON/NDJSON/etc)

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0

        Raises:
            FileNotFoundError: If output file doesn't exist
            ValueError: If output cannot be parsed
        """

    def validate(self, output_path: Path) -> bool:
        """Validate that output file exists and is parseable.

        Args:
            output_path: Path to tool output file

        Returns:
            True if valid, False otherwise
        """
        if not output_path.exists():
            return False
        try:
            self.parse(output_path)
            return True
        except (
            Exception
        ):  # Acceptable: validation probe — any parse failure means invalid
            return False

    def get_fingerprint(self, finding: Finding) -> str:
        """Generate stable fingerprint for deduplication.

        Delegates to :func:`scripts.core.common_finding.fingerprint`, the one
        formula (#1010). This method used to carry a second copy that rendered
        a missing line as ``""`` where the canonical one uses ``0`` and did not
        strip the message; trivy, trufflehog and semgrep ids built from a
        finding with no line or a padded message differ from before.
        Override for tool-specific fingerprinting logic.

        Args:
            finding: Finding object to fingerprint

        Returns:
            16-character hex fingerprint
        """
        return fingerprint(
            finding.tool.get("name", ""),
            finding.ruleId,
            finding.location.get("path", ""),
            finding.location.get("startLine"),
            finding.message,
        )


def adapter_plugin(metadata: PluginMetadata) -> Callable[[type], type]:
    """Decorator to register an adapter plugin.

    Usage:
        @adapter_plugin(PluginMetadata(
            name="trivy",
            version="1.0.0",
            tool_name="trivy"
        ))
        class TrivyAdapter(AdapterPlugin):
            ...

    Args:
        metadata: Plugin metadata

    Returns:
        Decorator function that attaches metadata to class
    """

    def decorator(cls: type) -> type:
        cls._plugin_metadata = metadata  # type: ignore[attr-defined]  # Dynamically attached by decorator to avoid base class attr
        return cls

    return decorator
