"""
Scan orchestration for JMo Security.

This module provides the ScanOrchestrator class for discovering scan targets,
filtering repositories, and coordinating multi-target scans.

Created as part of PHASE 1 refactoring to extract orchestration logic from cmd_scan().
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
import fnmatch


@dataclass
class ScanTargets:
    """
    Container for all discovered scan targets across 6 target types.

    Attributes:
        repos: List of repository paths (local Git repos)
        images: List of container image names (Docker/OCI)
        iac_files: List of (type, path) tuples for IaC files
        urls: List of web URLs for DAST scanning
        gitlab_repos: List of GitLab repository info dicts
        k8s_resources: List of Kubernetes resource info dicts
    """

    repos: List[Path] = field(default_factory=list)
    images: List[str] = field(default_factory=list)
    iac_files: List[Tuple[str, Path]] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    gitlab_repos: List[Dict[str, str]] = field(default_factory=list)
    k8s_resources: List[Dict[str, str]] = field(default_factory=list)

    def total_count(self) -> int:
        """Return total number of scan targets across all types."""
        return (
            len(self.repos)
            + len(self.images)
            + len(self.iac_files)
            + len(self.urls)
            + len(self.gitlab_repos)
            + len(self.k8s_resources)
        )

    def is_empty(self) -> bool:
        """Check if no targets were discovered."""
        return self.total_count() == 0

    def summary(self) -> str:
        """Generate human-readable summary of targets."""
        return (
            f"{len(self.repos)} repos, "
            f"{len(self.images)} images, "
            f"{len(self.iac_files)} IaC files, "
            f"{len(self.urls)} URLs, "
            f"{len(self.gitlab_repos)} GitLab repos, "
            f"{len(self.k8s_resources)} K8s resources"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "repos": [str(r) for r in self.repos],
            "images": self.images,
            "iac_files": [(t, str(p)) for t, p in self.iac_files],
            "urls": self.urls,
            "gitlab_repos": self.gitlab_repos,
            "k8s_resources": self.k8s_resources,
            "total_count": self.total_count(),
        }


@dataclass
class ScanConfig:
    """
    Scan configuration extracted from CLI arguments and config file.

    Attributes:
        tools: List of tool names to run
        results_dir: Base directory for scan results
        timeout: Tool timeout in seconds
        retries: Number of retry attempts
        max_workers: Maximum parallel workers (None = auto)
        include_patterns: Repository name patterns to include
        exclude_patterns: Repository name patterns to exclude
        allow_missing_tools: Allow scan to continue if tools missing
    """

    tools: List[str]
    results_dir: Path
    timeout: int = 600
    retries: int = 0
    max_workers: Optional[int] = None
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    allow_missing_tools: bool = False

    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.tools:
            raise ValueError("At least one tool must be specified")
        if self.timeout <= 0:
            raise ValueError(f"Timeout must be positive, got {self.timeout}")
        if self.retries < 0:
            raise ValueError(f"Retries must be non-negative, got {self.retries}")
        if self.max_workers is not None and self.max_workers < 1:
            raise ValueError(f"max_workers must be >= 1, got {self.max_workers}")


class ScanOrchestrator:
    """
    Orchestrate multi-target security scans.

    This class handles:
    1. Target discovery (repos, images, IaC, URLs, GitLab, K8s)
    2. Repository filtering (include/exclude patterns)
    3. Results directory setup
    4. Target validation

    Example:
        >>> orchestrator = ScanOrchestrator(config)
        >>> targets = orchestrator.discover_targets(args)
        >>> print(targets.summary())
        "5 repos, 2 images, 1 IaC files, 0 URLs, 0 GitLab repos, 0 K8s resources"
        >>> orchestrator.setup_results_directories(targets)
    """

    def __init__(self, config: ScanConfig):
        """
        Initialize ScanOrchestrator.

        Args:
            config: Scan configuration
        """
        self.config = config

    def discover_targets(self, args) -> ScanTargets:
        """
        Discover all scan targets from CLI arguments.

        Args:
            args: Parsed CLI arguments (from argparse)

        Returns:
            ScanTargets with all discovered targets
        """
        targets = ScanTargets()

        # Discover repositories
        targets.repos = self._discover_repos(args)

        # Discover container images
        targets.images = self._discover_images(args)

        # Discover IaC files
        targets.iac_files = self._discover_iac_files(args)

        # Discover URLs
        targets.urls = self._discover_urls(args)

        # Discover GitLab repositories
        targets.gitlab_repos = self._discover_gitlab_repos(args)

        # Discover Kubernetes resources
        targets.k8s_resources = self._discover_k8s_resources(args)

        # Apply repository filters (include/exclude patterns)
        targets.repos = self._filter_repos(targets.repos)

        return targets

    def _discover_repos(self, args) -> List[Path]:
        """
        Discover local Git repositories from CLI arguments.

        Supports three input modes:
        - --repo: Single repository path
        - --repos-dir: Directory containing multiple repos
        - --targets: File with list of repository paths
        """
        repos: List[Path] = []

        # Single repository
        if getattr(args, "repo", None):
            p = Path(args.repo)
            if p.exists():
                repos.append(p)

        # Directory of repositories
        elif getattr(args, "repos_dir", None):
            base = Path(args.repos_dir)
            if base.exists() and base.is_dir():
                # Find all subdirectories (assumed to be repos)
                repos.extend([p for p in base.iterdir() if p.is_dir()])

        # Targets file (list of repository paths)
        elif getattr(args, "targets", None):
            targets_file = Path(args.targets)
            if targets_file.exists():
                for line in targets_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    p = Path(line)
                    if p.exists():
                        repos.append(p)

        return repos

    def _discover_images(self, args) -> List[str]:
        """
        Discover container images from CLI arguments.

        Supports two input modes:
        - --image: Single container image
        - --images-file: File with list of image names
        """
        images: List[str] = []

        # Single image
        if getattr(args, "image", None):
            images.append(args.image)

        # Images file
        if getattr(args, "images_file", None):
            images_file = Path(args.images_file)
            if images_file.exists():
                for line in images_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    images.append(line)

        return images

    def _discover_iac_files(self, args) -> List[Tuple[str, Path]]:
        """
        Discover IaC files from CLI arguments.

        Returns list of (type, path) tuples where type is:
        - "terraform": Terraform state files
        - "cloudformation": CloudFormation templates
        - "k8s": Kubernetes manifests
        """
        iac_files: List[Tuple[str, Path]] = []

        # Terraform state files
        if getattr(args, "terraform_state", None):
            p = Path(args.terraform_state)
            if p.exists():
                iac_files.append(("terraform", p))

        # CloudFormation templates
        if getattr(args, "cloudformation", None):
            p = Path(args.cloudformation)
            if p.exists():
                iac_files.append(("cloudformation", p))

        # Kubernetes manifests
        if getattr(args, "k8s_manifest", None):
            p = Path(args.k8s_manifest)
            if p.exists():
                iac_files.append(("k8s", p))

        return iac_files

    def _discover_urls(self, args) -> List[str]:
        """
        Discover web URLs from CLI arguments.

        Supports two input modes:
        - --url: Single URL
        - --urls-file: File with list of URLs
        """
        urls: List[str] = []

        # Single URL
        if getattr(args, "url", None):
            urls.append(args.url)

        # URLs file
        if getattr(args, "urls_file", None):
            urls_file = Path(args.urls_file)
            if urls_file.exists():
                for line in urls_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    urls.append(line)

        return urls

    def _discover_gitlab_repos(self, args) -> List[Dict[str, str]]:
        """
        Discover GitLab repositories from CLI arguments.

        Supports:
        - --gitlab-repo: Single repository (format: group/project)
        - --gitlab-group: All repos in a group

        Returns:
            List of dicts with keys: full_path, url, token, repo, group, name
        """
        gitlab_repos: List[Dict[str, str]] = []

        # Single GitLab repository
        if getattr(args, "gitlab_repo", None):
            full_path = args.gitlab_repo
            parts = full_path.split("/")
            group = parts[0] if len(parts) > 1 else ""
            repo = parts[1] if len(parts) > 1 else full_path

            gitlab_repos.append(
                {
                    "full_path": full_path,
                    "url": getattr(args, "gitlab_url", "https://gitlab.com"),
                    "token": getattr(args, "gitlab_token", ""),
                    "repo": repo,
                    "group": group,
                    "name": full_path.replace("/", "_"),
                }
            )

        # GitLab group (would need API call to enumerate)
        if getattr(args, "gitlab_group", None):
            # Note: Actual implementation would query GitLab API
            # For now, create a placeholder entry
            group = args.gitlab_group
            gitlab_repos.append(
                {
                    "full_path": f"group:{group}",
                    "url": getattr(args, "gitlab_url", "https://gitlab.com"),
                    "token": getattr(args, "gitlab_token", ""),
                    "repo": "",
                    "group": group,
                    "name": f"group_{group}",
                }
            )

        return gitlab_repos

    def _discover_k8s_resources(self, args) -> List[Dict[str, str]]:
        """
        Discover Kubernetes resources from CLI arguments.

        Supports:
        - --k8s-context: Kubernetes context name
        - --k8s-namespace: Specific namespace
        - --k8s-all-namespaces: All namespaces flag

        Returns:
            List of dicts with keys: context, namespace, name
        """
        k8s_resources: List[Dict[str, str]] = []

        if getattr(args, "k8s_context", None):
            context = args.k8s_context
            namespace = getattr(args, "k8s_namespace", None)
            all_namespaces = getattr(args, "k8s_all_namespaces", False)

            if all_namespaces:
                k8s_resources.append(
                    {
                        "context": context,
                        "namespace": "*",
                        "name": f"{context}_all-namespaces",
                    }
                )
            elif namespace:
                k8s_resources.append(
                    {
                        "context": context,
                        "namespace": namespace,
                        "name": f"{context}_{namespace}",
                    }
                )
            else:
                k8s_resources.append(
                    {
                        "context": context,
                        "namespace": "default",
                        "name": f"{context}_default",
                    }
                )

        return k8s_resources

    def _filter_repos(self, repos: List[Path]) -> List[Path]:
        """
        Apply include/exclude patterns to repository list.

        Args:
            repos: List of repository paths

        Returns:
            Filtered list of repositories
        """
        # Apply include patterns
        if self.config.include_patterns:
            repos = [
                r
                for r in repos
                if any(
                    fnmatch.fnmatch(r.name, pat) for pat in self.config.include_patterns
                )
            ]

        # Apply exclude patterns
        if self.config.exclude_patterns:
            repos = [
                r
                for r in repos
                if not any(
                    fnmatch.fnmatch(r.name, pat) for pat in self.config.exclude_patterns
                )
            ]

        return repos

    def setup_results_directories(self, targets: ScanTargets) -> None:
        """
        Create results directory structure for all target types.

        Creates:
        - results/individual-repos/ (always)
        - results/individual-images/ (if images present)
        - results/individual-iac/ (if IaC files present)
        - results/individual-web/ (if URLs present)
        - results/individual-gitlab/ (if GitLab repos present)
        - results/individual-k8s/ (if K8s resources present)

        Args:
            targets: Discovered scan targets
        """
        base = self.config.results_dir

        # Always create repos directory (legacy compatibility)
        (base / "individual-repos").mkdir(parents=True, exist_ok=True)

        # Create directories for other target types (only if targets present)
        if targets.images:
            (base / "individual-images").mkdir(parents=True, exist_ok=True)

        if targets.iac_files:
            (base / "individual-iac").mkdir(parents=True, exist_ok=True)

        if targets.urls:
            (base / "individual-web").mkdir(parents=True, exist_ok=True)

        if targets.gitlab_repos:
            (base / "individual-gitlab").mkdir(parents=True, exist_ok=True)

        if targets.k8s_resources:
            (base / "individual-k8s").mkdir(parents=True, exist_ok=True)

    def validate_targets(self, targets: ScanTargets) -> bool:
        """
        Validate that at least one scan target was discovered.

        Args:
            targets: Discovered scan targets

        Returns:
            True if targets exist, False if no targets found
        """
        return not targets.is_empty()

    def get_effective_max_workers(self) -> int:
        """
        Calculate effective max_workers value.

        Priority:
        1. ScanConfig.max_workers (if set)
        2. JMO_THREADS environment variable
        3. Default: 4

        Returns:
            Number of parallel workers to use
        """
        import os

        if self.config.max_workers is not None:
            return self.config.max_workers

        if os.getenv("JMO_THREADS"):
            try:
                return max(1, int(os.getenv("JMO_THREADS", "4")))
            except ValueError:
                pass

        return 4  # Default

    def get_summary(self, targets: ScanTargets) -> Dict[str, Any]:
        """
        Generate summary of orchestration configuration.

        Args:
            targets: Discovered scan targets

        Returns:
            Dictionary with summary information
        """
        return {
            "config": {
                "tools": self.config.tools,
                "results_dir": str(self.config.results_dir),
                "timeout": self.config.timeout,
                "retries": self.config.retries,
                "max_workers": self.get_effective_max_workers(),
                "include_patterns": self.config.include_patterns,
                "exclude_patterns": self.config.exclude_patterns,
            },
            "targets": targets.to_dict(),
            "validation": {
                "has_targets": not targets.is_empty(),
                "total_count": targets.total_count(),
            },
        }
