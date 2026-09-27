"""
Scan Metadata Capture for Attestations.

This module captures metadata about scans for inclusion in attestations:
- Scan parameters (tools, targets, threads, timeout)
- Git context (commit, branch, tag)
- CI-specific metadata (GitHub Actions, GitLab CI)

Used by ProvenanceGenerator to populate buildDefinition.externalParameters
and runDetails metadata fields.
"""

import logging
import os
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


class MetadataCapture:
    """Capture scan metadata for attestations."""

    def __init__(self):
        """Initialize metadata capture."""

    def from_scan_args(
        self,
        tools: list[str] | None = None,
        repos: list[str] | None = None,
        images: list[str] | None = None,
        urls: list[str] | None = None,
        threads: int | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """
        Capture scan parameters from command-line arguments.

        Args:
            tools: List of tools used
            repos: List of repositories scanned
            images: List of container images scanned
            urls: List of URLs scanned
            threads: Thread count
            timeout: Timeout in seconds

        Returns:
            Dict of scan metadata

        There is deliberately no ``**kwargs``. It used to copy every keyword
        into the metadata, so a password or token passed beside the scan
        arguments would have reached the attestation, and a typo vanished into
        it. An unknown keyword is now a ``TypeError``. Nothing in the product
        calls this yet (#1277).
        """
        metadata: dict[str, Any] = {}

        if tools is not None:
            metadata["tools"] = tools

        if repos is not None:
            metadata["repos"] = repos

        if images is not None:
            metadata["images"] = images

        if urls is not None:
            metadata["urls"] = urls

        if threads is not None:
            metadata["threads"] = threads

        if timeout is not None:
            metadata["timeout"] = timeout

        return metadata

    def capture_git_context(self, repo_path: str) -> dict[str, Any]:
        """
        Capture Git context from repository.

        Args:
            repo_path: Path to Git repository

        Returns:
            Dict with commit, branch, tag (if available)
        """
        git_context: dict[str, Any] = {}

        try:
            # Get commit SHA
            result = subprocess.run(
                ["git", "-C", repo_path, "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                git_context["commit"] = result.stdout.strip()

            # Get branch name
            result = subprocess.run(
                ["git", "-C", repo_path, "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                git_context["branch"] = result.stdout.strip()

            # Get tag (if any)
            result = subprocess.run(
                ["git", "-C", repo_path, "describe", "--tags", "--exact-match"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                git_context["tag"] = result.stdout.strip()

        except subprocess.TimeoutExpired:
            logger.warning(f"Git context capture timed out for {repo_path}")
        except Exception as e:  # Acceptable: git context capture is optional metadata — safe default on failure
            logger.warning(f"Could not capture Git context for {repo_path}: {e}")

        return git_context

    def capture_ci_metadata(self) -> dict[str, Any]:
        """
        Capture CI-specific metadata.

        Supports:
        - GitHub Actions (GITHUB_*)
        - GitLab CI (GITLAB_CI, CI_*)

        Returns:
            Dict with CI provider and metadata
        """
        ci_metadata: dict[str, Any] = {}

        # Detect CI provider
        if os.getenv("GITHUB_ACTIONS") == "true":
            ci_metadata["ci_provider"] = "github"
            ci_metadata["repository"] = os.getenv("GITHUB_REPOSITORY")
            ci_metadata["commit"] = os.getenv("GITHUB_SHA")
            ci_metadata["ref"] = os.getenv("GITHUB_REF")
            ci_metadata["workflow"] = os.getenv("GITHUB_WORKFLOW")
            ci_metadata["run_id"] = os.getenv("GITHUB_RUN_ID")
            ci_metadata["run_number"] = os.getenv("GITHUB_RUN_NUMBER")

        elif os.getenv("GITLAB_CI") == "true":
            ci_metadata["ci_provider"] = "gitlab"
            ci_metadata["repository"] = os.getenv("CI_PROJECT_PATH")
            ci_metadata["commit"] = os.getenv("CI_COMMIT_SHA")
            ci_metadata["ref"] = os.getenv("CI_COMMIT_REF_NAME")
            ci_metadata["pipeline_id"] = os.getenv("CI_PIPELINE_ID")
            ci_metadata["pipeline_url"] = os.getenv("CI_PIPELINE_URL")
            ci_metadata["job_id"] = os.getenv("CI_JOB_ID")
            ci_metadata["job_name"] = os.getenv("CI_JOB_NAME")

        elif os.getenv("CI") == "true":
            ci_metadata["ci_provider"] = "generic"

        # Remove None values
        ci_metadata = {k: v for k, v in ci_metadata.items() if v is not None}

        return ci_metadata
