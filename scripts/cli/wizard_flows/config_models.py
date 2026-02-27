"""
Configuration models for the wizard.

Contains dataclasses for:
- TargetConfig: Target-specific configuration for a single scan target
- WizardConfig: Full configuration collected by the wizard

These models are pure data containers with no dependencies on UI or scan logic,
making them safe to import anywhere without circular dependency risks.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class TargetConfig:
    """Target-specific configuration for a single scan target."""

    def __init__(self) -> None:
        self.type: str = "repo"  # repo, image, iac, url, gitlab, k8s

        # Repository targets (existing)
        self.repo_mode: str = ""  # repo, repos-dir, targets, tsv
        self.repo_path: str = ""
        self.tsv_path: str = ""
        self.tsv_dest: str = "repos-tsv"

        # Container image targets (v0.6.0+)
        self.image_name: str = ""
        self.images_file: str = ""

        # IaC targets (v0.6.0+)
        self.iac_type: str = ""  # terraform, cloudformation, k8s-manifest
        self.iac_path: str = ""

        # Web URL targets (v0.6.0+)
        self.url: str = ""
        self.urls_file: str = ""
        self.api_spec: str = ""

        # GitLab targets (v0.6.0+)
        self.gitlab_url: str = "https://gitlab.com"
        self.gitlab_token: str = ""  # Prefer GITLAB_TOKEN env var
        self.gitlab_repo: str = ""  # group/repo format
        self.gitlab_group: str = ""

        # Kubernetes targets (v0.6.0+)
        self.k8s_context: str = ""
        self.k8s_namespace: str = ""
        self.k8s_all_namespaces: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "repo_mode": self.repo_mode,
            "repo_path": self.repo_path,
            "tsv_path": self.tsv_path,
            "tsv_dest": self.tsv_dest,
            "image_name": self.image_name,
            "images_file": self.images_file,
            "iac_type": self.iac_type,
            "iac_path": self.iac_path,
            "url": self.url,
            "urls_file": self.urls_file,
            "api_spec": self.api_spec,
            "gitlab_url": self.gitlab_url,
            "gitlab_token": "***" if self.gitlab_token else "",  # Redact token
            "gitlab_repo": self.gitlab_repo,
            "gitlab_group": self.gitlab_group,
            "k8s_context": self.k8s_context,
            "k8s_namespace": self.k8s_namespace,
            "k8s_all_namespaces": self.k8s_all_namespaces,
        }


class WizardConfig:
    """Configuration collected by the wizard.

    Attributes:
        profile: Scanning profile (fast/slim/balanced/deep)
        use_docker: Whether to use Docker execution mode
        target: Target-specific configuration
        results_dir: Directory for scan results
        threads: Number of parallel threads (None = use profile default)
        timeout: Per-tool timeout in seconds (None = use profile default)
        fail_on: Severity threshold for CI failures (empty = don't fail)
        allow_missing_tools: Whether to continue if some tools are missing
        human_logs: Whether to use human-readable log format
        analyze_trends: Enable trend analysis (v1.0.0+)
        export_trends_html: Export trends as HTML dashboard
        export_trends_json: Export trends as JSON
        policies_enabled: Whether OPA policy evaluation is enabled
        _custom_db_path: Custom database path (internal, set via set_db_path)
    """

    # Class-level custom db_path (replaces module-level global)
    _custom_db_path: str | None = None

    def __init__(self) -> None:
        self.profile: str = "balanced"
        self.use_docker: bool = False
        self.target: TargetConfig = TargetConfig()
        self.results_dir: str = "results"
        self.threads: int | None = None
        self.timeout: int | None = None
        self.fail_on: str = ""
        self.allow_missing_tools: bool = True
        self.human_logs: bool = True
        # Trend analysis flags (v1.0.0+)
        self.analyze_trends: bool = False
        self.export_trends_html: bool = False
        self.export_trends_json: bool = False
        # Policy evaluation flag (set by OPA pre-flight check)
        self.policies_enabled: bool = False

    @classmethod
    def set_db_path(cls, path: str | None) -> None:
        """Set custom database path.

        Args:
            path: Custom path to history database, or None to use default
        """
        cls._custom_db_path = path

    @classmethod
    def get_db_path(cls) -> Path:
        """Get the history database path, respecting custom --db flag.

        Returns:
            Path to SQLite history database
        """
        if cls._custom_db_path:
            return Path(cls._custom_db_path).expanduser().resolve()
        return Path.home() / ".jmo" / "history.db"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "profile": self.profile,
            "use_docker": self.use_docker,
            "target": self.target.to_dict(),
            "results_dir": self.results_dir,
            "threads": self.threads,
            "timeout": self.timeout,
            "fail_on": self.fail_on,
            "allow_missing_tools": self.allow_missing_tools,
            "human_logs": self.human_logs,
            "analyze_trends": self.analyze_trends,
            "export_trends_html": self.export_trends_html,
            "export_trends_json": self.export_trends_json,
            "policies_enabled": self.policies_enabled,
        }
