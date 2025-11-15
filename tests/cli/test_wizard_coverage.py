#!/usr/bin/env python3
"""
Comprehensive coverage tests for wizard.py and wizard_generators.py.

This test file specifically targets uncovered code paths to meet the 85% coverage threshold.
Tests focus on:
- GitLab target type workflows
- K8s target type workflows
- IaC target type workflows
- Image target type workflows
- URL target type workflows
- Alternative repo modes (repos-dir vs repo)
- Edge cases in generator functions
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock


from scripts.cli.wizard import PROFILES
from scripts.cli.wizard_generators import (
    generate_github_actions,
    generate_makefile_target,
    generate_shell_script,
)


def create_wizard_config(**kwargs: Any) -> MagicMock:
    """Create mock wizard configuration with explicit attributes."""
    config = MagicMock(spec=[])

    # Define all expected attributes with defaults
    default_attrs = {
        "profile": "balanced",
        "use_docker": False,
        "threads": None,
        "timeout": None,
        "fail_on": "",
        "target": MagicMock(spec=[]),
    }

    # Update with provided values
    default_attrs.update(kwargs)

    # Set attributes explicitly
    for key, value in default_attrs.items():
        setattr(config, key, value)

    # Ensure target has necessary attributes
    if not hasattr(config.target, "type"):
        config.target.type = "repo"
    if not hasattr(config.target, "repo_mode"):
        config.target.repo_mode = "repo"

    return config


# ========== Test Category 1: GitLab Target Type ==========


def test_github_actions_gitlab_docker():
    """Test GitHub Actions generation for GitLab target with Docker."""
    config = create_wizard_config(
        profile="fast",
        use_docker=True,
        fail_on="HIGH",
    )
    config.target.type = "gitlab"
    config.target.gitlab_repo = "myorg/myproject"

    result = generate_github_actions(config, PROFILES)

    # Verify GitLab-specific setup steps
    assert "Configure GitLab Access" in result
    assert "GITLAB_TOKEN" in result
    assert "secrets.GITLAB_TOKEN" in result

    # Verify Docker container usage
    assert "container:" in result
    assert "ghcr.io/jimmy058910/jmo-security:latest" in result


def test_github_actions_gitlab_native():
    """Test GitHub Actions generation for GitLab target with native mode."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
        threads=4,
        timeout=600,
    )
    config.target.type = "gitlab"
    config.target.gitlab_repo = "group/repo"

    result = generate_github_actions(config, PROFILES)

    # Verify GitLab repo flag
    assert "--gitlab-repo group/repo" in result

    # Verify native Python setup
    assert "Set up Python" in result
    assert "Install JMo Security" in result

    # Verify secrets note
    assert "NOTE: Add GITLAB_TOKEN secret to repository settings" in result


# ========== Test Category 2: K8s Target Type ==========


def test_github_actions_k8s_docker():
    """Test GitHub Actions generation for K8s target with Docker."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=True,
    )
    config.target.type = "k8s"
    config.target.k8s_context = "prod-cluster"

    result = generate_github_actions(config, PROFILES)

    # Verify K8s-specific setup steps
    assert "Configure kubectl" in result
    assert "secrets.KUBECONFIG" in result
    assert "kubectl config view" in result


def test_github_actions_k8s_native():
    """Test GitHub Actions generation for K8s target with native mode."""
    config = create_wizard_config(
        profile="fast",
        use_docker=False,
    )
    config.target.type = "k8s"
    config.target.k8s_context = "staging"

    result = generate_github_actions(config, PROFILES)

    # Verify K8s context flag
    assert "--k8s-context staging" in result

    # Verify secrets note
    assert "NOTE: Add KUBECONFIG secret to repository settings" in result


# ========== Test Category 3: Image Target Type ==========


def test_github_actions_image_docker():
    """Test GitHub Actions generation for container image with Docker."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=True,
        fail_on="MEDIUM",
    )
    config.target.type = "image"
    config.target.image_name = "nginx:latest"

    result = generate_github_actions(config, PROFILES)

    # Verify image flag
    assert "--image nginx:latest" in result

    # Verify fail-on threshold
    assert "--fail-on MEDIUM" in result


def test_github_actions_image_native():
    """Test GitHub Actions generation for container image with native mode."""
    config = create_wizard_config(
        profile="fast",
        use_docker=False,
        threads=8,
    )
    config.target.type = "image"
    config.target.image_name = "python:3.11"

    result = generate_github_actions(config, PROFILES)

    # Verify image flag
    assert "--image python:3.11" in result

    # Verify threads override
    assert "--threads 8" in result


def test_github_actions_image_native_no_name():
    """Test GitHub Actions generation for image without image_name (edge case)."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
    )
    config.target.type = "image"
    config.target.image_name = None

    result = generate_github_actions(config, PROFILES)

    # Should generate valid workflow even without image name
    assert "security-scan:" in result
    assert "jmo scan" in result
    assert "--profile-name balanced" in result


# ========== Test Category 4: URL Target Type ==========


def test_github_actions_url_docker():
    """Test GitHub Actions generation for URL target with Docker."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=True,
    )
    config.target.type = "url"
    config.target.url = "https://api.example.com"

    result = generate_github_actions(config, PROFILES)

    # Verify URL flag
    assert "--url https://api.example.com" in result


def test_github_actions_url_native():
    """Test GitHub Actions generation for URL target with native mode."""
    config = create_wizard_config(
        profile="fast",
        use_docker=False,
    )
    config.target.type = "url"
    config.target.url = "https://example.com"

    result = generate_github_actions(config, PROFILES)

    # Verify URL flag
    assert "--url https://example.com" in result


def test_github_actions_url_native_no_url():
    """Test GitHub Actions generation for URL without url value (edge case)."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
    )
    config.target.type = "url"
    config.target.url = None

    result = generate_github_actions(config, PROFILES)

    # Should generate valid workflow even without URL
    assert "jmo scan" in result
    assert "--profile-name balanced" in result


# ========== Test Category 5: IaC Target Type ==========


def test_github_actions_iac_terraform():
    """Test GitHub Actions generation for Terraform IaC."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
    )
    config.target.type = "iac"
    config.target.iac_type = "terraform"

    result = generate_github_actions(config, PROFILES)

    # Verify Terraform flag
    assert "--terraform-state infrastructure" in result


def test_github_actions_iac_cloudformation():
    """Test GitHub Actions generation for CloudFormation IaC."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
    )
    config.target.type = "iac"
    config.target.iac_type = "cloudformation"

    result = generate_github_actions(config, PROFILES)

    # Verify CloudFormation flag
    assert "--cloudformation infrastructure" in result


def test_github_actions_iac_k8s_manifest():
    """Test GitHub Actions generation for K8s manifest IaC."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
    )
    config.target.type = "iac"
    config.target.iac_type = "k8s-manifest"

    result = generate_github_actions(config, PROFILES)

    # Verify K8s manifest flag
    assert "--k8s-manifest infrastructure" in result


# ========== Test Category 6: Repo Mode Variations ==========


def test_github_actions_repos_dir_mode():
    """Test GitHub Actions generation with repos-dir mode."""
    config = create_wizard_config(
        profile="fast",
        use_docker=False,
    )
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"

    result = generate_github_actions(config, PROFILES)

    # Verify repos-dir flag
    assert "--repos-dir ." in result


def test_github_actions_repo_mode():
    """Test GitHub Actions generation with single repo mode."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
    )
    config.target.type = "repo"
    config.target.repo_mode = "repo"

    result = generate_github_actions(config, PROFILES)

    # Verify repo flag
    assert "--repo ." in result


# ========== Test Category 7: Thread and Timeout Overrides ==========


def test_github_actions_thread_override():
    """Test GitHub Actions with explicit thread override."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
        threads=16,
        timeout=1200,
    )
    config.target.type = "repo"
    config.target.repo_mode = "repo"

    result = generate_github_actions(config, PROFILES)

    # Verify thread override (not profile default of 4)
    assert "--threads 16" in result
    assert "--timeout 1200" in result


def test_github_actions_use_profile_defaults():
    """Test GitHub Actions uses profile defaults when overrides not specified."""
    config = create_wizard_config(
        profile="fast",
        use_docker=False,
        threads=None,
        timeout=None,
    )
    config.target.type = "repo"
    config.target.repo_mode = "repo"

    result = generate_github_actions(config, PROFILES)

    # Should use fast profile defaults: threads=8, timeout=300
    assert "--threads 8" in result
    assert "--timeout 300" in result


# ========== Test Category 8: Fail-On Threshold Variations ==========


def test_github_actions_fail_on_critical():
    """Test GitHub Actions with CRITICAL fail-on threshold."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=True,
        fail_on="CRITICAL",
    )
    config.target.type = "repo"

    result = generate_github_actions(config, PROFILES)

    assert "--fail-on CRITICAL" in result


def test_github_actions_fail_on_low():
    """Test GitHub Actions with LOW fail-on threshold."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
        fail_on="LOW",
    )
    config.target.type = "repo"
    config.target.repo_mode = "repo"

    result = generate_github_actions(config, PROFILES)

    assert "--fail-on LOW" in result


def test_github_actions_no_fail_on():
    """Test GitHub Actions without fail-on threshold."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
        fail_on="",
    )
    config.target.type = "repo"
    config.target.repo_mode = "repo"

    result = generate_github_actions(config, PROFILES)

    # Should not include --fail-on when empty
    assert "--fail-on" not in result


# ========== Test Category 9: Profile Coverage ==========


def test_github_actions_deep_profile():
    """Test GitHub Actions generation with deep profile."""
    config = create_wizard_config(
        profile="deep",
        use_docker=False,
    )
    config.target.type = "repo"
    config.target.repo_mode = "repo"

    result = generate_github_actions(config, PROFILES)

    # Verify deep profile defaults: threads=2, timeout=900
    assert "--threads 2" in result
    assert "--timeout 900" in result
    assert "jmo scan" in result
    assert "--profile-name deep" in result


# ========== Test Category 10: Environment Variables ==========


def test_github_actions_gitlab_env_vars():
    """Test that GitLab target includes environment variables in scan step."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=True,
    )
    config.target.type = "gitlab"

    result = generate_github_actions(config, PROFILES)

    # Verify env section exists in scan step
    assert "Run Security Scan" in result
    # The env section should be present with GITLAB_TOKEN
    assert "env:" in result
    assert "GITLAB_TOKEN: ${{ secrets.GITLAB_TOKEN }}" in result


def test_github_actions_no_env_vars_for_repo():
    """Test that repo target doesn't include env section."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=True,
    )
    config.target.type = "repo"

    result = generate_github_actions(config, PROFILES)

    # Verify no env section in scan step (only in setup if needed)
    lines = result.split("\n")
    scan_step_found = False
    env_after_scan = False
    for i, line in enumerate(lines):
        if "Run Security Scan" in line:
            scan_step_found = True
            # Check next 5 lines for env:
            for j in range(i + 1, min(i + 6, len(lines))):
                if "env:" in lines[j] and "run:" not in lines[j]:
                    env_after_scan = True

    # Repo targets should not have env vars in scan step
    assert scan_step_found
    assert not env_after_scan


# ========== Test Category 11: Makefile and Shell Script Coverage ==========


def test_makefile_generation_with_config():
    """Test Makefile target generation with config object."""
    config = create_wizard_config(profile="balanced")
    command = "jmotools balanced --repo . --results-dir results"

    result = generate_makefile_target(config, command)

    assert ".PHONY: security-scan" in result
    assert "security-scan:" in result
    assert command in result
    assert "JMo Security Scan Target" in result


def test_shell_script_generation_with_config():
    """Test shell script generation with config object."""
    config = create_wizard_config(profile="fast")
    command = "jmotools fast --repos-dir . --results-dir results"

    result = generate_shell_script(config, command)

    assert "#!/usr/bin/env bash" in result
    assert "set -euo pipefail" in result
    assert command in result
    assert "JMo Security Scan Script" in result


def test_shell_script_multiline_command():
    """Test shell script generation with multiline command."""
    config = create_wizard_config(profile="balanced")
    command = """jmotools balanced \\
  --repo . \\
  --threads 4 \\
  --timeout 600 \\
  --results-dir results"""

    result = generate_shell_script(config, command)

    assert "#!/usr/bin/env bash" in result
    assert "set -euo pipefail" in result
    assert "--threads 4" in result
    assert "--timeout 600" in result


# ========== Test Category 12: Edge Cases and Error Handling ==========


def test_github_actions_unknown_target_type():
    """Test GitHub Actions generation gracefully handles unknown target type."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
    )
    config.target.type = "unknown_type"

    # Should not crash, should generate valid workflow
    result = generate_github_actions(config, PROFILES)

    assert "security-scan:" in result
    assert "jmo scan" in result
    assert "--profile-name balanced" in result


def test_github_actions_gitlab_without_repo():
    """Test GitLab target without gitlab_repo attribute."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
    )
    config.target.type = "gitlab"
    config.target.gitlab_repo = None

    result = generate_github_actions(config, PROFILES)

    # Should generate valid workflow even without gitlab_repo
    assert "jmo scan" in result
    assert "--profile-name balanced" in result


def test_github_actions_k8s_without_context():
    """Test K8s target without k8s_context attribute."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
    )
    config.target.type = "k8s"
    config.target.k8s_context = None

    result = generate_github_actions(config, PROFILES)

    # Should generate valid workflow even without k8s_context
    assert "jmo scan" in result
    assert "--profile-name balanced" in result


# ========== Test Category 13: YAML Structure Verification ==========


def test_github_actions_valid_yaml_structure_docker():
    """Test that generated Docker workflow has valid YAML structure."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=True,
    )
    config.target.type = "repo"

    result = generate_github_actions(config, PROFILES)

    # Verify key YAML sections
    assert "name: Security Scan" in result
    assert "on:" in result
    assert "push:" in result
    assert "pull_request:" in result
    assert "schedule:" in result
    assert "jobs:" in result
    assert "security-scan:" in result
    assert "runs-on: ubuntu-latest" in result
    assert "container:" in result
    assert "steps:" in result
    assert "uses: actions/checkout@v4" in result


def test_github_actions_valid_yaml_structure_native():
    """Test that generated native workflow has valid YAML structure."""
    config = create_wizard_config(
        profile="fast",
        use_docker=False,
    )
    config.target.type = "repo"
    config.target.repo_mode = "repo"

    result = generate_github_actions(config, PROFILES)

    # Verify key YAML sections
    assert "name: Security Scan" in result
    assert "jobs:" in result
    assert "security-scan:" in result
    assert "steps:" in result
    assert "Set up Python" in result
    assert "Install JMo Security" in result
    assert "Install Security Tools" in result
    assert "Run Security Scan" in result
    assert "Upload Results" in result
    assert "Upload SARIF" in result


# ========== Test Category 14: Comments and Metadata ==========


def test_github_actions_includes_tool_comments():
    """Test that native workflow includes tool installation comments."""
    config = create_wizard_config(
        profile="balanced",
        use_docker=False,
    )
    config.target.type = "repo"
    config.target.repo_mode = "repo"

    result = generate_github_actions(config, PROFILES)

    # Verify tool comments
    assert "# Install based on profile: balanced" in result
    # Should list balanced profile tools
    assert "trufflehog" in result
    assert "semgrep" in result
