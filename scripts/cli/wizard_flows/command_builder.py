"""Command building utilities for wizard workflows."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.cli.wizard import TargetConfig, WizardConfig


def build_repo_args(target: TargetConfig, use_docker: bool = False) -> list[str]:
    """Build command arguments for repository targets."""
    args = []

    if use_docker:
        # Docker mode: mount volumes
        if target.repo_path:
            repo_abs = str(Path(target.repo_path).resolve())
            return ["-v", f"{repo_abs}:/scan", "--repos-dir", "/scan"]
    else:
        # Native mode: use paths directly
        if target.repo_mode == "repo":
            args.extend(["--repo", target.repo_path])
        elif target.repo_mode == "repos-dir":
            args.extend(["--repos-dir", target.repo_path])
        elif target.repo_mode == "targets":
            args.extend(["--targets", target.repo_path])
        elif target.repo_mode == "tsv":
            args.extend(["--tsv", target.tsv_path])
            if hasattr(target, "tsv_dest") and target.tsv_dest:
                args.extend(["--dest", target.tsv_dest])

    return args


def build_image_args(target: TargetConfig, use_docker: bool = False) -> list[str]:
    """Build command arguments for container image targets."""
    args = []

    if target.image_name:
        args.extend(["--image", target.image_name])
    elif target.images_file:
        if use_docker:
            # Mount images file for Docker
            file_abs = str(Path(target.images_file).resolve())
            args.extend(
                ["-v", f"{file_abs}:/images.txt", "--images-file", "/images.txt"]
            )
        else:
            args.extend(["--images-file", target.images_file])

    return args


def build_iac_args(target: TargetConfig, use_docker: bool = False) -> list[str]:
    """Build command arguments for IaC targets."""
    args = []

    if use_docker:
        # Mount IaC file for Docker
        if target.iac_path:
            iac_abs = str(Path(target.iac_path).resolve())
            args.extend(["-v", f"{iac_abs}:/scan/iac-file"])
            args.append(f"--{target.iac_type.replace('-', '-')}")
            args.append("/scan/iac-file")
    else:
        args.append(f"--{target.iac_type}")
        args.append(target.iac_path)

    return args


def build_url_args(target: TargetConfig, use_docker: bool = False) -> list[str]:
    """Build command arguments for web URL targets."""
    args = []

    if target.url:
        args.extend(["--url", target.url])
    elif target.urls_file:
        if use_docker:
            file_abs = str(Path(target.urls_file).resolve())
            args.extend(["-v", f"{file_abs}:/urls.txt", "--urls-file", "/urls.txt"])
        else:
            args.extend(["--urls-file", target.urls_file])
    elif target.api_spec:
        args.extend(["--api-spec", target.api_spec])

    return args


def build_gitlab_args(target: TargetConfig, use_docker: bool = False) -> list[str]:
    """Build command arguments for GitLab targets."""
    args = []

    if target.gitlab_url:
        args.extend(["--gitlab-url", target.gitlab_url])
    if target.gitlab_token:
        args.extend(["--gitlab-token", target.gitlab_token])
    if target.gitlab_repo:
        args.extend(["--gitlab-repo", target.gitlab_repo])
    elif target.gitlab_group:
        args.extend(["--gitlab-group", target.gitlab_group])

    return args


def build_k8s_args(target: TargetConfig, use_docker: bool = False) -> list[str]:
    """Build command arguments for Kubernetes targets."""
    args = []

    if target.k8s_context:
        args.extend(["--k8s-context", target.k8s_context])
    if target.k8s_all_namespaces:
        args.append("--k8s-all-namespaces")
    elif target.k8s_namespace:
        args.extend(["--k8s-namespace", target.k8s_namespace])

    return args


def build_command_parts(config: WizardConfig) -> list[str]:
    """
    Build complete command parts from wizard configuration.

    Args:
        config: Wizard configuration

    Returns:
        List of command components for execution
    """
    if config.use_docker:
        # Docker command base
        cmd_parts = ["docker", "run", "--rm"]

        # Add volume mounts (collected from target-specific builders)
        target_args = _get_target_args_with_volumes(config.target, use_docker=True)
        volume_mounts = [
            arg
            for i, arg in enumerate(target_args)
            if arg == "-v" or (i > 0 and target_args[i - 1] == "-v")
        ]
        cmd_parts.extend(volume_mounts)

        # Results mount (convert to absolute path)
        results_abs = str(Path(config.results_dir).resolve())
        cmd_parts.extend(["-v", f"{results_abs}:/results"])

        # Image and base command
        cmd_parts.append("ghcr.io/jimmy058910/jmo-security:latest")
        cmd_parts.append("scan")

        # Add target flags (non-volume args)
        target_flags = [
            arg for arg in target_args if arg not in volume_mounts and arg != "-v"
        ]
        cmd_parts.extend(target_flags)

        cmd_parts.extend(["--results", "/results"])
        cmd_parts.extend(["--profile", config.profile])

    else:
        # Native command
        cmd_parts = ["jmo", "scan"]

        # Add target-specific flags
        cmd_parts.extend(_get_target_args_with_volumes(config.target, use_docker=False))

        # Results directory and profile
        if config.results_dir:
            cmd_parts.extend(["--results-dir", config.results_dir])
        cmd_parts.extend(["--profile-name", config.profile])

        # Advanced options
        if config.threads is not None:
            cmd_parts.extend(["--threads", str(config.threads)])
        if config.timeout is not None:
            cmd_parts.extend(["--timeout", str(config.timeout)])
        if config.fail_on:
            cmd_parts.extend(["--fail-on", config.fail_on.upper()])
        if config.allow_missing_tools:
            cmd_parts.append("--allow-missing-tools")
        if config.human_logs:
            cmd_parts.append("--human-logs")

    return cmd_parts


def _get_target_args_with_volumes(target: TargetConfig, use_docker: bool) -> list[str]:
    """Get target-specific arguments including volume mounts for Docker."""
    if target.type == "repo":
        return build_repo_args(target, use_docker)
    elif target.type == "image":
        return build_image_args(target, use_docker)
    elif target.type == "iac":
        return build_iac_args(target, use_docker)
    elif target.type == "url":
        return build_url_args(target, use_docker)
    elif target.type == "gitlab":
        return build_gitlab_args(target, use_docker)
    elif target.type == "k8s":
        return build_k8s_args(target, use_docker)
    return []
