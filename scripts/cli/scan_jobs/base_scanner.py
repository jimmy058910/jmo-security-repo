"""Base scanner class for all target types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List
import re


@dataclass
class ScanResult:
    """Result from scanning a single target."""

    target_id: str  # Path, URL, image name, etc.
    target_type: str  # 'repo', 'image', 'iac', 'url', 'gitlab', 'k8s'
    tool_statuses: Dict[str, bool]  # {'trivy': True, 'syft': False}
    output_files: Dict[str, Path]  # {'trivy': Path('trivy.json')}
    errors: List[str]  # Error messages
    duration: float  # Seconds
    metadata: Dict[str, Any]  # Target-specific metadata


class BaseScanner(ABC):
    """Abstract base class for target scanners."""

    def __init__(self, config: "ScanConfig"):
        """Initialize scanner with configuration.

        Args:
            config: ScanConfig object with tools, timeout, retries, etc.
        """
        self.config = config

    @abstractmethod
    def scan(
        self, target: Any, results_dir: Path, tools: List[str], args: Any
    ) -> ScanResult:
        """Execute scan on target.

        Args:
            target: Target-specific data (Path for repo, str for image, etc.)
            results_dir: Base results directory
            tools: List of tool names to run
            args: CLI arguments (for logging, flags, etc.)

        Returns:
            ScanResult with execution summary
        """
        pass

    @abstractmethod
    def get_applicable_tools(self, tools: List[str]) -> List[str]:
        """Filter tools list to those applicable for this target type.

        Args:
            tools: Full list of tools from config

        Returns:
            Filtered list of applicable tools
        """
        pass

    def _create_output_dir(
        self, base_dir: Path, target_type: str, safe_name: str
    ) -> Path:
        """Create target-specific output directory.

        Args:
            base_dir: Base results directory
            target_type: Type of target ('repo', 'image', 'iac', etc.)
            safe_name: Sanitized name for directory

        Returns:
            Path to created output directory
        """
        output_dir = base_dir / f"individual-{target_type}s" / safe_name
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def _sanitize_name(self, name: str) -> str:
        """Sanitize target identifier for filesystem.

        Args:
            name: Original target name

        Returns:
            Filesystem-safe name
        """
        return re.sub(r"[^a-zA-Z0-9._-]", "_", str(name))
