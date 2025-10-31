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

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional
import hashlib


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
    tool: Dict[str, str] = field(default_factory=dict)  # {name, version}
    location: Dict[str, Any] = field(default_factory=dict)  # {path, startLine, endLine}
    message: str = ""
    title: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    cvss: Optional[Dict[str, Any]] = None
    risk: Optional[Dict[str, Any]] = None
    compliance: Optional[Dict[str, Any]] = None
    context: Optional[Dict[str, Any]] = None
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
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
    tool_version: Optional[str] = None
    schema_version: str = "1.2.0"  # CommonFinding schema version
    output_format: str = "json"  # json|ndjson|yaml|xml
    exit_codes: Dict[int, str] = field(
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
        pass

    @abstractmethod
    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to tool output file (JSON/NDJSON/etc)

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0

        Raises:
            FileNotFoundError: If output file doesn't exist
            ValueError: If output cannot be parsed
        """
        pass

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
        except Exception:
            return False

    def get_fingerprint(self, finding: Finding) -> str:
        """Generate stable fingerprint for deduplication.

        Default implementation uses: tool | ruleId | path | line | message[:120]
        Override for tool-specific fingerprinting logic.

        Args:
            finding: Finding object to fingerprint

        Returns:
            16-character hex fingerprint
        """
        parts = [
            finding.tool.get("name", ""),
            finding.ruleId,
            finding.location.get("path", ""),
            str(finding.location.get("startLine", "")),
            finding.message[:120],
        ]
        fingerprint_input = "|".join(parts)
        return hashlib.sha256(fingerprint_input.encode()).hexdigest()[:16]


def adapter_plugin(metadata: PluginMetadata):
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

    def decorator(cls):
        cls._plugin_metadata = metadata
        return cls

    return decorator
