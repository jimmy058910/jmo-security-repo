"""Target configuration helpers for wizard workflows."""

from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING, Any
from collections.abc import Callable

if TYPE_CHECKING:
    pass

from scripts.cli.wizard_flows.base_flow import PromptHelper, TargetDetector
from scripts.cli.wizard_flows.validators import (
    detect_iac_type,
    validate_k8s_context,
    validate_path,
    validate_url,
)

# Shared prompter instance
_prompter = PromptHelper()
_detector = TargetDetector()


def _prompt_text(question: str, default: str = "") -> str:
    """Prompt user for text input."""
    prompt = f"{question} [{default}]: " if default else f"{question}: "
    value = input(prompt).strip()
    return value if value else default


def configure_repo_target(target_config_class: Any, print_step_fn: Callable) -> Any:
    """Configure repository scanning target."""
    print_step_fn(4, 7, "Configure Repository Target")

    config = target_config_class()
    config.type = "repo"

    # Select mode
    print("\nRepository modes:")
    modes = [
        ("repo", "Single repository"),
        ("repos-dir", "Directory with multiple repos (most common)"),
        ("targets", "File listing repo paths"),
        ("tsv", "Clone from TSV file"),
    ]
    for key, desc in modes:
        print(f"  [{key:10}] {desc}")

    mode = _prompter.prompt_choice(
        "\nSelect mode:", [k for k, _ in modes], default="repos-dir"
    )
    config.repo_mode = mode

    if mode == "tsv":
        config.tsv_path = _prompt_text("Path to TSV file", default="./repos.tsv")
        config.tsv_dest = _prompt_text("Clone destination", default="repos-tsv")
        return config

    # Path prompting
    prompts = {
        "repo": "Path to repository",
        "repos-dir": "Path to repos directory",
        "targets": "Path to targets file",
    }

    while True:
        path = _prompt_text(prompts[mode], default="." if mode == "repos-dir" else "")
        if not path:
            print(_prompter.colorize("Path cannot be empty", "red"))
            continue

        validated = validate_path(path, must_exist=True)
        if validated:
            if mode == "repos-dir":
                repos = _detector.detect_repos(validated)
                if repos:
                    print(
                        _prompter.colorize(f"Found {len(repos)} repositories:", "green")
                    )
                    for repo in repos[:5]:
                        print(f"  - {repo.name}")
                    if len(repos) > 5:
                        print(f"  ... and {len(repos) - 5} more")
                else:
                    print(
                        _prompter.colorize(
                            "Warning: No git repositories detected", "yellow"
                        )
                    )
                    if not _prompter.prompt_yes_no("Continue anyway?", default=False):
                        continue

            config.repo_path = str(validated)
            return config

        print(_prompter.colorize(f"Path not found: {path}", "red"))


def configure_image_target(target_config_class: Any, print_step_fn: Callable) -> Any:
    """Configure container image scanning target."""
    print_step_fn(4, 7, "Configure Container Image Target")

    config = target_config_class()
    config.type = "image"

    # Select mode
    print("\nContainer image modes:")
    modes = [("single", "Scan a single image"), ("batch", "Scan images from file")]
    for key, desc in modes:
        print(f"  [{key:10}] {desc}")

    mode = _prompter.prompt_choice(
        "\nSelect mode:", [k for k, _ in modes], default="single"
    )

    if mode == "single":
        config.image_name = _prompt_text(
            "Container image (e.g., nginx:latest, myregistry.io/app:v1.0)",
            default="nginx:latest",
        )
        print(_prompter.colorize(f"Will scan: {config.image_name}", "green"))
    else:
        while True:
            path = _prompt_text("Path to images file", default="./images.txt")
            validated = validate_path(path, must_exist=True)
            if validated:
                config.images_file = str(validated)
                lines = validated.read_text(encoding="utf-8").splitlines()
                images = [
                    line.strip()
                    for line in lines
                    if line.strip() and not line.startswith("#")
                ]
                print(_prompter.colorize(f"Found {len(images)} images:", "green"))
                for img in images[:5]:
                    print(f"  - {img}")
                if len(images) > 5:
                    print(f"  ... and {len(images) - 5} more")
                break
            print(_prompter.colorize(f"File not found: {path}", "red"))

    return config


def configure_iac_target(target_config_class: Any, print_step_fn: Callable) -> Any:
    """Configure IaC file scanning target."""
    print_step_fn(4, 7, "Configure Infrastructure as Code Target")

    config = target_config_class()
    config.type = "iac"

    while True:
        path = _prompt_text(
            "Path to IaC file (.tfstate, .yaml, .json)",
            default="./infrastructure.tfstate",
        )
        validated = validate_path(path, must_exist=True)
        if validated:
            config.iac_path = str(validated)

            detected_type = detect_iac_type(validated)
            print(_prompter.colorize(f"Detected type: {detected_type}", "green"))

            # Confirm or override
            print("\nIaC file types:")
            types = [
                ("terraform", "Terraform state file (.tfstate)"),
                ("cloudformation", "CloudFormation template (.yaml/.json)"),
                ("k8s-manifest", "Kubernetes manifest (.yaml)"),
            ]
            for key, desc in types:
                print(f"  [{key:15}] {desc}")

            iac_type = _prompter.prompt_choice(
                "\nSelect type:", [k for k, _ in types], default=detected_type
            )
            config.iac_type = iac_type
            return config

        print(_prompter.colorize(f"File not found: {path}", "red"))


def configure_url_target(target_config_class: Any, print_step_fn: Callable) -> Any:
    """Configure web URL scanning target."""
    print_step_fn(4, 7, "Configure Web Application/API Target")

    config = target_config_class()
    config.type = "url"

    # Select mode
    print("\nWeb application modes:")
    modes = [
        ("single", "Scan a single URL"),
        ("batch", "Scan URLs from file"),
        ("api", "Scan API from OpenAPI spec"),
    ]
    for key, desc in modes:
        print(f"  [{key:10}] {desc}")

    mode = _prompter.prompt_choice(
        "\nSelect mode:", [k for k, _ in modes], default="single"
    )

    if mode == "single":
        while True:
            url = _prompt_text("Web application URL", default="https://example.com")
            print(_prompter.colorize("Validating URL...", "blue"))
            if validate_url(url):
                print(_prompter.colorize(f"URL is reachable: {url}", "green"))
                config.url = url
                break
            else:
                print(
                    _prompter.colorize(f"Warning: URL not reachable: {url}", "yellow")
                )
                if _prompter.prompt_yes_no("Use this URL anyway?", default=False):
                    config.url = url
                    break

    elif mode == "batch":
        while True:
            path = _prompt_text("Path to URLs file", default="./urls.txt")
            validated = validate_path(path, must_exist=True)
            if validated:
                config.urls_file = str(validated)
                lines = validated.read_text(encoding="utf-8").splitlines()
                urls = [
                    line.strip()
                    for line in lines
                    if line.strip() and not line.startswith("#")
                ]
                print(_prompter.colorize(f"Found {len(urls)} URLs:", "green"))
                for url in urls[:5]:
                    print(f"  - {url}")
                if len(urls) > 5:
                    print(f"  ... and {len(urls) - 5} more")
                break
            print(_prompter.colorize(f"File not found: {path}", "red"))

    else:  # api
        config.api_spec = _prompt_text(
            "OpenAPI spec URL or file path", default="./openapi.yaml"
        )
        print(_prompter.colorize(f"Will scan API spec: {config.api_spec}", "green"))

    return config


def configure_gitlab_target(target_config_class: Any, print_step_fn: Callable) -> Any:
    """Configure GitLab scanning target."""
    print_step_fn(4, 7, "Configure GitLab Target")

    config = target_config_class()
    config.type = "gitlab"

    config.gitlab_url = _prompt_text("GitLab URL", default="https://gitlab.com")

    # Check for token in environment
    env_token = os.getenv("GITLAB_TOKEN")
    if env_token:
        print(_prompter.colorize("GitLab token found in GITLAB_TOKEN env var", "green"))
        config.gitlab_token = env_token
    else:
        print(_prompter.colorize("\nWarning: GITLAB_TOKEN env var not set", "yellow"))
        print("For security, it's recommended to set GITLAB_TOKEN env var")
        token = _prompt_text("GitLab access token (or press Enter to skip)")
        if token:
            config.gitlab_token = token
        else:
            print(
                _prompter.colorize(
                    "Note: Scan will fail without token. Set GITLAB_TOKEN before running.",
                    "yellow",
                )
            )

    # Repo or group
    print("\nGitLab scope:")
    modes = [
        ("repo", "Single repository (group/repo)"),
        ("group", "Entire group (all repos)"),
    ]
    for key, desc in modes:
        print(f"  [{key:10}] {desc}")

    mode = _prompter.prompt_choice(
        "\nSelect scope:", [k for k, _ in modes], default="repo"
    )

    if mode == "repo":
        config.gitlab_repo = _prompt_text(
            "Repository (format: group/repo)", default="mygroup/myrepo"
        )
        print(
            _prompter.colorize(
                f"Will scan GitLab repo: {config.gitlab_url}/{config.gitlab_repo}",
                "green",
            )
        )
    else:
        config.gitlab_group = _prompt_text("Group name", default="mygroup")
        print(
            _prompter.colorize(
                f"Will scan all repos in group: {config.gitlab_url}/{config.gitlab_group}",
                "green",
            )
        )

    return config


def configure_k8s_target(target_config_class: Any, print_step_fn: Callable) -> Any:
    """Configure Kubernetes scanning target."""
    print_step_fn(4, 7, "Configure Kubernetes Target")

    config = target_config_class()
    config.type = "k8s"

    if not shutil.which("kubectl"):
        print(
            _prompter.colorize(
                "Warning: kubectl not found. Install kubectl to scan K8s clusters.",
                "yellow",
            )
        )
        config.k8s_context = "current"
        config.k8s_namespace = "default"
        return config

    # Context validation
    while True:
        context = _prompt_text(
            "Kubernetes context (or 'current' for default)", default="current"
        )
        if validate_k8s_context(context):
            print(_prompter.colorize(f"Context validated: {context}", "green"))
            config.k8s_context = context
            break
        else:
            print(
                _prompter.colorize(f"Warning: Context not found: {context}", "yellow")
            )
            if _prompter.prompt_yes_no("Use this context anyway?", default=False):
                config.k8s_context = context
                break

    # Namespace scope
    print("\nNamespace scope:")
    modes = [("single", "Single namespace"), ("all", "All namespaces")]
    for key, desc in modes:
        print(f"  [{key:10}] {desc}")

    mode = _prompter.prompt_choice(
        "\nSelect scope:", [k for k, _ in modes], default="single"
    )

    if mode == "single":
        config.k8s_namespace = _prompt_text("Namespace name", default="default")
        print(
            _prompter.colorize(
                f"Will scan namespace: {config.k8s_context}/{config.k8s_namespace}",
                "green",
            )
        )
    else:
        config.k8s_all_namespaces = True
        print(
            _prompter.colorize(
                f"Will scan all namespaces in context: {config.k8s_context}", "green"
            )
        )

    return config
