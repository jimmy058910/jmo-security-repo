"""
JMo Security - Scan Jobs Module

This module contains extracted scan job functions for different target types.
Each scanner is responsible for executing security tools against a specific target type.

Scanners:
- repository_scanner: Local Git repositories (trufflehog, semgrep, trivy, syft, etc.)
- image_scanner: Container images (trivy, syft)
- iac_scanner: IaC files (checkov, trivy)
- url_scanner: Web URLs (zap)
- gitlab_scanner: GitLab repositories (trufflehog)
- k8s_scanner: Kubernetes resources (trivy)

These scanners integrate with:
- ToolRunner (scripts/core/tool_runner.py) for tool execution
- ScanOrchestrator (scripts/cli/scan_orchestrator.py) for target discovery
"""

from .repository_scanner import scan_repository
from .image_scanner import scan_image
from .iac_scanner import scan_iac_file
from .url_scanner import scan_url
from .gitlab_scanner import scan_gitlab_repo
from .k8s_scanner import scan_k8s_resource

__all__ = [
    "scan_repository",
    "scan_image",
    "scan_iac_file",
    "scan_url",
    "scan_gitlab_repo",
    "scan_k8s_resource",
]
