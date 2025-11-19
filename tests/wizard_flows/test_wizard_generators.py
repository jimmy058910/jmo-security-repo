"""
Tests for wizard_generators.py - Artifact generation functions.

Coverage targets:
- generate_makefile_target with all workflow types (repo, stack, cicd, deployment, dependency)
- generate_shell_script basic generation
- generate_github_actions with Docker and native modes
- generate_github_actions with all target types (repo, image, url, iac, gitlab, k8s)
- generate_gitlab_ci with all workflow types
- generate_docker_compose with all workflow types
- Proper escaping and formatting in generated files
- Environment variable handling
- Secrets detection and setup steps
"""

from dataclasses import dataclass, field
from typing import Any

import pytest

from scripts.cli.wizard_generators import (
    generate_docker_compose,
    generate_github_actions,
    generate_gitlab_ci,
    generate_makefile_target,
    generate_shell_script,
)


# Mock config classes
@dataclass
class MockTarget:
    """Mock target configuration."""

    type: str = "repo"
    repo_mode: str = "repo"
    image_name: str | None = None
    url: str | None = None
    iac_type: str | None = None
    gitlab_repo: str | None = None
    k8s_context: str | None = None


@dataclass
class MockConfig:
    """Mock wizard configuration."""

    profile: str = "balanced"
    threads: int | None = None
    timeout: int | None = None
    fail_on: str | None = None
    use_docker: bool = False
    target: MockTarget = field(default_factory=MockTarget)


# Fixtures
@pytest.fixture
def mock_config():
    """Create mock wizard configuration."""
    return MockConfig()


@pytest.fixture
def mock_profiles():
    """Create mock PROFILES dictionary."""
    return {
        "fast": {"threads": 8, "timeout": 300, "tools": ["trufflehog", "semgrep"]},
        "balanced": {
            "threads": 4,
            "timeout": 600,
            "tools": ["trufflehog", "semgrep", "trivy"],
        },
        "deep": {
            "threads": 2,
            "timeout": 900,
            "tools": ["trufflehog", "semgrep", "trivy", "bandit"],
        },
    }


# generate_makefile_target tests
def test_generate_makefile_target_repo_workflow(mock_config):
    """Test Makefile generation for repo workflow."""
    result = generate_makefile_target(mock_config, "jmo scan --repo .", "repo")

    assert ".PHONY: security-scan" in result
    assert ".PHONY: security-report" in result
    assert ".PHONY: security-clean" in result
    assert "jmo scan --repo ." in result
    assert "jmo report ./results --profile" in result
    assert "rm -rf results/" in result


def test_generate_makefile_target_dependency_workflow(mock_config):
    """Test Makefile generation for dependency workflow (same as repo)."""
    result = generate_makefile_target(mock_config, "jmo scan --repo .", "dependency")

    # Should use basic template like repo
    assert ".PHONY: security-scan" in result
    assert ".PHONY: security-report" in result
    assert ".PHONY: security-clean" in result


def test_generate_makefile_target_stack_workflow(mock_config):
    """Test Makefile generation for stack workflow (enhanced)."""
    result = generate_makefile_target(mock_config, "jmo scan --repos-dir .", "stack")

    # Should have multiple scan targets
    assert ".PHONY: security-scan-all" in result
    assert ".PHONY: security-scan-repos" in result
    assert ".PHONY: security-scan-images" in result
    assert ".PHONY: security-scan-iac" in result
    assert ".PHONY: security-scan-fast" in result
    assert ".PHONY: security-scan-deep" in result
    assert ".PHONY: help" in result

    # Should have help target
    assert "@echo" in result
    assert "Available Targets:" in result


def test_generate_makefile_target_cicd_workflow(mock_config):
    """Test Makefile generation for CI/CD workflow."""
    result = generate_makefile_target(mock_config, "jmo ci --repos-dir .", "cicd")

    assert ".PHONY: security-audit-ci" in result
    assert ".PHONY: security-audit-fast" in result
    assert ".PHONY: security-check-pipelines" in result
    assert ".PHONY: security-check-images" in result
    assert "jmo ci --repos-dir ." in result
    assert ".PHONY: help" in result


def test_generate_makefile_target_deployment_workflow(mock_config):
    """Test Makefile generation for deployment workflow."""
    result = generate_makefile_target(
        mock_config, "jmo ci --image myapp:latest", "deployment"
    )

    assert ".PHONY: security-check-staging" in result
    assert ".PHONY: security-check-production" in result
    assert ".PHONY: security-sbom" in result
    assert ".PHONY: security-full-check" in result
    assert "jmo ci --image myapp:latest" in result
    assert ".PHONY: help" in result


def test_generate_makefile_target_unknown_workflow(mock_config):
    """Test Makefile generation with unknown workflow (fallback)."""
    result = generate_makefile_target(mock_config, "jmo scan --repo .", "unknown_type")

    # Should use default template
    assert ".PHONY: security-scan" in result
    assert "jmo scan --repo ." in result


# generate_shell_script tests
def test_generate_shell_script_basic(mock_config):
    """Test basic shell script generation."""
    result = generate_shell_script(mock_config, "jmo scan --repo .")

    assert "#!/usr/bin/env bash" in result
    assert "set -euo pipefail" in result
    assert "jmo scan --repo ." in result


def test_generate_shell_script_multiline_command(mock_config):
    """Test shell script with multiline command."""
    command = "jmo scan --repo . \\\n  --profile balanced \\\n  --threads 4"
    result = generate_shell_script(mock_config, command)

    assert "#!/usr/bin/env bash" in result
    assert command in result


# generate_github_actions tests
def test_generate_github_actions_docker_mode(mock_config, mock_profiles):
    """Test GitHub Actions generation with Docker mode."""
    mock_config.use_docker = True
    mock_config.profile = "balanced"
    mock_config.threads = 4
    mock_config.timeout = 600

    result = generate_github_actions(mock_config, mock_profiles)

    assert "name: Security Scan" in result
    assert "runs-on: ubuntu-latest" in result
    assert "container:" in result
    assert "image: ghcr.io/jimmy058910/jmo-security:latest" in result
    assert "jmo scan --results results --profile balanced" in result
    assert "--threads 4" in result
    assert "--timeout 600" in result
    assert "upload-artifact@v4" in result
    assert "upload-sarif@v3" in result


def test_generate_github_actions_docker_mode_with_image(mock_config, mock_profiles):
    """Test GitHub Actions Docker mode with image target."""
    mock_config.use_docker = True
    mock_config.target.type = "image"
    mock_config.target.image_name = "nginx:latest"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--image nginx:latest" in result


def test_generate_github_actions_docker_mode_with_url(mock_config, mock_profiles):
    """Test GitHub Actions Docker mode with URL target."""
    mock_config.use_docker = True
    mock_config.target.type = "url"
    mock_config.target.url = "https://example.com"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--url https://example.com" in result


def test_generate_github_actions_docker_mode_with_fail_on(mock_config, mock_profiles):
    """Test GitHub Actions Docker mode with fail_on threshold."""
    mock_config.use_docker = True
    mock_config.fail_on = "HIGH"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--fail-on HIGH" in result


def test_generate_github_actions_native_mode_repo(mock_config, mock_profiles):
    """Test GitHub Actions generation with native mode (repo)."""
    mock_config.use_docker = False
    mock_config.profile = "balanced"
    mock_config.target.type = "repo"
    mock_config.target.repo_mode = "repos-dir"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "name: Security Scan" in result
    assert "runs-on: ubuntu-latest" in result
    assert "container:" not in result  # No container in native mode
    assert "setup-python@v5" in result
    assert "python-version: '3.11'" in result
    assert "pip install jmo-security" in result
    assert "Install Security Tools" in result
    assert "jmo scan" in result
    assert "--repos-dir ." in result
    assert "--profile-name balanced" in result
    assert "trufflehog, semgrep, trivy" in result  # Tools comment


def test_generate_github_actions_native_mode_single_repo(mock_config, mock_profiles):
    """Test GitHub Actions native mode with single repo."""
    mock_config.use_docker = False
    mock_config.target.type = "repo"
    mock_config.target.repo_mode = "repo"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--repo ." in result


def test_generate_github_actions_native_mode_image(mock_config, mock_profiles):
    """Test GitHub Actions native mode with image target."""
    mock_config.use_docker = False
    mock_config.target.type = "image"
    mock_config.target.image_name = "myapp:latest"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--image myapp:latest" in result


def test_generate_github_actions_native_mode_url(mock_config, mock_profiles):
    """Test GitHub Actions native mode with URL target."""
    mock_config.use_docker = False
    mock_config.target.type = "url"
    mock_config.target.url = "https://api.example.com"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--url https://api.example.com" in result


def test_generate_github_actions_native_mode_iac_terraform(mock_config, mock_profiles):
    """Test GitHub Actions native mode with IaC (Terraform) target."""
    mock_config.use_docker = False
    mock_config.target.type = "iac"
    mock_config.target.iac_type = "terraform"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--terraform-state infrastructure" in result


def test_generate_github_actions_native_mode_iac_cloudformation(
    mock_config, mock_profiles
):
    """Test GitHub Actions native mode with IaC (CloudFormation) target."""
    mock_config.use_docker = False
    mock_config.target.type = "iac"
    mock_config.target.iac_type = "cloudformation"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--cloudformation infrastructure" in result


def test_generate_github_actions_native_mode_iac_k8s_manifest(
    mock_config, mock_profiles
):
    """Test GitHub Actions native mode with IaC (K8s manifest) target."""
    mock_config.use_docker = False
    mock_config.target.type = "iac"
    mock_config.target.iac_type = "k8s-manifest"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--k8s-manifest infrastructure" in result


def test_generate_github_actions_native_mode_gitlab(mock_config, mock_profiles):
    """Test GitHub Actions native mode with GitLab target."""
    mock_config.use_docker = False
    mock_config.target.type = "gitlab"
    mock_config.target.gitlab_repo = "myorg/myrepo"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--gitlab-repo myorg/myrepo" in result
    assert "Configure GitLab Access" in result
    assert "GITLAB_TOKEN: ${{ secrets.GITLAB_TOKEN }}" in result
    assert "NOTE: Add GITLAB_TOKEN secret" in result


def test_generate_github_actions_native_mode_k8s(mock_config, mock_profiles):
    """Test GitHub Actions native mode with Kubernetes target."""
    mock_config.use_docker = False
    mock_config.target.type = "k8s"
    mock_config.target.k8s_context = "production"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--k8s-context production" in result
    assert "Configure kubectl" in result
    assert "KUBECONFIG" in result
    assert "NOTE: Add KUBECONFIG secret" in result


def test_generate_github_actions_native_mode_with_fail_on(mock_config, mock_profiles):
    """Test GitHub Actions native mode with fail_on threshold."""
    mock_config.use_docker = False
    mock_config.fail_on = "CRITICAL"

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--fail-on CRITICAL" in result


def test_generate_github_actions_native_mode_with_custom_threads(
    mock_config, mock_profiles
):
    """Test GitHub Actions native mode with custom threads."""
    mock_config.use_docker = False
    mock_config.threads = 8

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--threads 8" in result


def test_generate_github_actions_native_mode_with_custom_timeout(
    mock_config, mock_profiles
):
    """Test GitHub Actions native mode with custom timeout."""
    mock_config.use_docker = False
    mock_config.timeout = 1200

    result = generate_github_actions(mock_config, mock_profiles)

    assert "--timeout 1200" in result


def test_generate_github_actions_native_mode_uses_profile_defaults(
    mock_config, mock_profiles
):
    """Test GitHub Actions native mode uses profile defaults when no overrides."""
    mock_config.use_docker = False
    mock_config.profile = "fast"
    mock_config.threads = None  # Use profile default
    mock_config.timeout = None  # Use profile default

    result = generate_github_actions(mock_config, mock_profiles)

    # Should use fast profile defaults (threads=8, timeout=300)
    assert "--threads 8" in result
    assert "--timeout 300" in result


# generate_gitlab_ci tests
def test_generate_gitlab_ci_default_workflow():
    """Test GitLab CI generation with default workflow."""
    result = generate_gitlab_ci("repo", "balanced")

    assert "stages:" in result
    assert "- security-scan" in result
    assert "security-scan:" in result
    assert "image: ghcr.io/jimmy058910/jmo-security:latest" in result
    assert "jmo scan --repo . --profile balanced" in result
    assert "artifacts:" in result
    assert "sast: results/summaries/findings.sarif" in result


def test_generate_gitlab_ci_stack_workflow():
    """Test GitLab CI generation with stack workflow."""
    result = generate_gitlab_ci("stack", "deep")

    assert "- security-scan" in result
    assert "- report" in result
    assert "security-scan-all:" in result
    assert "security-report:" in result
    assert "jmo scan --repos-dir . --profile deep" in result
    assert "jmo report ./results --profile" in result
    assert "dependencies:" in result


def test_generate_gitlab_ci_cicd_workflow():
    """Test GitLab CI generation with CI/CD workflow."""
    result = generate_gitlab_ci("cicd", "fast")

    assert "- security-audit" in result
    assert "ci-security-audit:" in result
    assert "jmo ci --repos-dir . --profile fast --fail-on HIGH" in result


def test_generate_gitlab_ci_deployment_workflow():
    """Test GitLab CI generation with deployment workflow."""
    result = generate_gitlab_ci("deployment", "balanced")

    assert "- pre-deployment" in result
    assert "deployment-security-check:" in result
    assert "jmo ci --profile balanced --fail-on CRITICAL" in result
    assert "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA" in result
    assert "when: manual" in result


def test_generate_gitlab_ci_dependency_workflow():
    """Test GitLab CI generation with dependency workflow (uses default)."""
    result = generate_gitlab_ci("dependency", "balanced")

    # Should use default template
    assert "security-scan:" in result
    assert "jmo scan --repo . --profile balanced" in result


# generate_docker_compose tests
def test_generate_docker_compose_default_workflow():
    """Test docker-compose generation with default workflow."""
    result = generate_docker_compose("repo", "balanced")

    assert "version: '3.8'" in result
    assert "services:" in result
    assert "jmo-security:" in result
    assert "image: ghcr.io/jimmy058910/jmo-security:latest" in result
    assert "volumes:" in result
    assert ".:/scan:ro" in result
    assert "./results:/scan/results" in result
    assert "scan" in result
    assert "--repo /scan" in result
    assert "--profile balanced" in result
    assert "JMO_THREADS=auto" in result
    assert "JMO_TELEMETRY_DISABLE=1" in result


def test_generate_docker_compose_stack_workflow():
    """Test docker-compose generation with stack workflow."""
    result = generate_docker_compose("stack", "deep")

    assert "jmo-security:" in result
    assert "jmo-report:" in result
    assert "depends_on:" in result
    assert "- jmo-security" in result
    assert "scan" in result
    assert "--repos-dir /scan" in result
    assert "--profile deep" in result
    assert "report /scan/results --profile" in result


def test_generate_docker_compose_cicd_workflow():
    """Test docker-compose generation with CI/CD workflow."""
    result = generate_docker_compose("cicd", "fast")

    assert "jmo-security:" in result
    assert "ci" in result
    assert "--repos-dir /scan" in result
    assert "--profile fast" in result
    assert "--fail-on HIGH" in result


def test_generate_docker_compose_deployment_workflow():
    """Test docker-compose generation with deployment workflow."""
    result = generate_docker_compose("deployment", "balanced")

    assert "jmo-security:" in result
    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in result
    assert "ci" in result
    assert "--image myapp:latest" in result
    assert "--fail-on CRITICAL" in result


def test_generate_docker_compose_dependency_workflow():
    """Test docker-compose generation with dependency workflow (uses default)."""
    result = generate_docker_compose("dependency", "balanced")

    # Should use default template
    assert "jmo-security:" in result
    assert "scan" in result
    assert "--repo /scan" in result
