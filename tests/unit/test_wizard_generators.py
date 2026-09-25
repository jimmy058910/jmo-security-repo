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

There are no scan profiles (v2.0.0): nothing here selects one, and threads /
timeout defaults come from jmo.yml's top level (or 4 / 600), not a profile.
"""

from dataclasses import dataclass, field
from unittest.mock import patch

import pytest

from scripts.cli.wizard_generators import (
    JMO_DOCKER_IMAGE_FULL,
    generate_docker_compose,
    generate_github_actions,
    generate_gitlab_ci,
    generate_makefile_target,
    generate_shell_script,
)
from scripts.core.tool_registry import TOOL_MATRIX

WORKFLOW_TYPES = ("repo", "stack", "cicd", "deployment", "dependency")


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


# generate_makefile_target tests
def test_generate_makefile_target_repo_workflow(mock_config):
    """Test Makefile generation for repo workflow."""
    result = generate_makefile_target(mock_config, "jmo scan --repo .", "repo")

    assert ".PHONY: security-scan" in result
    assert ".PHONY: security-report" in result
    assert ".PHONY: security-clean" in result
    assert "jmo scan --repo ." in result
    assert "jmo report ./results" in result
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

    # Should have one scan target per target type
    assert ".PHONY: security-scan-all" in result
    assert ".PHONY: security-scan-repos" in result
    assert ".PHONY: security-scan-images" in result
    assert ".PHONY: security-scan-iac" in result
    assert "\tjmo scan --repos-dir .\n" in result
    assert "\tjmo scan --images-file detected-images.txt\n" in result
    assert "\tjmo scan --terraform-state terraform/*.tfstate\n" in result
    assert ".PHONY: help" in result

    # The fast/deep variants were profile selections; one scan job replaces them
    assert "security-scan-fast" not in result
    assert "security-scan-deep" not in result

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


def test_generate_makefile_target_cicd_quick_job_narrows_with_tools(mock_config):
    """The quick PR target narrows the tool list; it no longer picks a profile."""
    result = generate_makefile_target(mock_config, "jmo ci --repos-dir .", "cicd")

    assert (
        "security-audit-fast:\n"
        "\tjmo ci --repos-dir . --tools trufflehog semgrep --fail-on HIGH\n"
    ) in result


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

    # Staging and production differ by threshold only
    assert "\tjmo ci --fail-on HIGH --image myapp:staging\n" in result
    assert "\tjmo ci --fail-on CRITICAL --image myapp:production\n" in result
    assert "\tjmo scan --tools syft --image myapp:latest\n" in result


def test_generate_makefile_target_unknown_workflow(mock_config):
    """Test Makefile generation with unknown workflow (fallback)."""
    result = generate_makefile_target(mock_config, "jmo scan --repo .", "unknown_type")

    # Should use default template
    assert ".PHONY: security-scan" in result
    assert "jmo scan --repo ." in result


@pytest.mark.parametrize("workflow", WORKFLOW_TYPES)
def test_generate_makefile_target_selects_no_profile(mock_config, workflow):
    """No Makefile template names a profile, in a command or in its help text."""
    result = generate_makefile_target(mock_config, "jmo scan --repo .", workflow)

    assert "--profile" not in result
    assert "profile" not in result.lower()


# generate_shell_script tests
def test_generate_shell_script_basic(mock_config):
    """Test basic shell script generation."""
    result = generate_shell_script(mock_config, "jmo scan --repo .")

    assert "#!/usr/bin/env bash" in result
    assert "set -euo pipefail" in result
    assert "jmo scan --repo ." in result


def test_generate_shell_script_multiline_command(mock_config):
    """Test shell script with multiline command."""
    command = "jmo scan --repo . \\\n  --threads 4 \\\n  --timeout 600"
    result = generate_shell_script(mock_config, command)

    assert "#!/usr/bin/env bash" in result
    assert command in result


# generate_github_actions tests
def test_generate_github_actions_docker_mode(mock_config):
    """Test GitHub Actions generation with Docker mode."""
    mock_config.use_docker = True
    mock_config.threads = 4
    mock_config.timeout = 600

    result = generate_github_actions(mock_config)

    assert "name: Security Scan" in result
    assert "runs-on: ubuntu-latest" in result
    assert "container:" in result
    assert f"image: {JMO_DOCKER_IMAGE_FULL}" in result
    assert "jmo scan --results-dir results" in result
    assert "--profile-name" not in result
    assert "--threads 4" in result
    assert "--timeout 600" in result
    assert "upload-artifact@v4" in result
    assert "upload-sarif@v3" in result


def test_generate_github_actions_docker_mode_with_image(mock_config):
    """Test GitHub Actions Docker mode with image target."""
    mock_config.use_docker = True
    mock_config.target.type = "image"
    mock_config.target.image_name = "nginx:latest"

    result = generate_github_actions(mock_config)

    assert "--image nginx:latest" in result


def test_generate_github_actions_docker_mode_with_url(mock_config):
    """Test GitHub Actions Docker mode with URL target."""
    mock_config.use_docker = True
    mock_config.target.type = "url"
    mock_config.target.url = "https://example.com"

    result = generate_github_actions(mock_config)

    assert "--url https://example.com" in result


def test_generate_github_actions_docker_mode_with_fail_on(mock_config):
    """A threshold makes the Docker workflow run `jmo ci`, which defines --fail-on.

    `jmo scan` does not: `--fail-on HIGH` there resolves as a prefix of
    `--fail-on-store-error` and leaves HIGH unrecognised, so the job exits 2.
    """
    mock_config.use_docker = True
    mock_config.fail_on = "HIGH"

    result = generate_github_actions(mock_config)

    assert "jmo ci --results-dir results" in result
    assert "jmo scan" not in result
    assert "--fail-on HIGH" in result


def test_generate_github_actions_native_mode_repo(mock_config):
    """Test GitHub Actions generation with native mode (repo)."""
    mock_config.use_docker = False
    mock_config.target.type = "repo"
    mock_config.target.repo_mode = "repos-dir"

    result = generate_github_actions(mock_config)

    assert "name: Security Scan" in result
    assert "runs-on: ubuntu-latest" in result
    assert "container:" not in result  # No container in native mode
    assert "setup-python@v5" in result  # its version: the test below
    assert "pip install jmo-security" in result
    assert "Install Security Tools" in result
    assert "jmo scan" in result
    # The checkout itself: `--repos-dir .` scanned each subdirectory of it as a
    # repository and never the root's files.
    assert "--repo ." in result
    assert "--repos-dir" not in result
    assert "--profile-name" not in result
    # Tools comment lists the whole matrix, derived rather than typed
    assert f"# Tools: {', '.join(TOOL_MATRIX)}" in result


def test_the_native_workflow_installs_the_scanners(mock_config):
    """Its "Install Security Tools" step held only comments.

    So the scan step found no scanner and stopped ("None of the requested
    tools are installed"), or scanned with whatever the runner happened to have.
    """
    import shlex

    import yaml

    from scripts.cli.jmo import build_parser

    mock_config.use_docker = False
    mock_config.target.type = "repo"

    steps = yaml.safe_load(generate_github_actions(mock_config))["jobs"][
        "security-scan"
    ]["steps"]
    run = next(s["run"] for s in steps if s.get("name") == "Install Security Tools")
    commands = [
        ln.strip()
        for ln in run.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]

    assert commands, "the install step runs nothing"
    for command in commands:
        argv = shlex.split(command)
        assert argv[0] == "jmo", command
        parsed = build_parser().parse_args(argv[1:])
        assert (parsed.cmd, parsed.tools_command) == ("tools", "install")
        assert parsed.yes is True, "a CI job cannot answer a prompt"


def test_the_native_workflow_installs_a_python_the_package_supports(mock_config):
    """It set up Python 3.11 for a package that requires 3.12, so its
    `pip install jmo-security` could never succeed. The floor is read from
    pyproject.toml, so the next bump cannot leave the template behind.
    """
    import re
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).parents[2] / "pyproject.toml"
    requires = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"][
        "requires-python"
    ]
    floor = tuple(int(n) for n in re.fullmatch(r">=(\d+)\.(\d+)", requires).groups())
    mock_config.use_docker = False
    mock_config.target.type = "repo"

    result = generate_github_actions(mock_config)

    pinned = re.search(r"python-version: '(\d+)\.(\d+)'", result)
    assert pinned, "no python-version in the native workflow"
    assert tuple(int(n) for n in pinned.groups()) >= floor, (
        f"workflow sets up Python {'.'.join(pinned.groups())}, "
        f"package requires {requires}"
    )


def test_generate_github_actions_native_mode_single_repo(mock_config):
    """Test GitHub Actions native mode with single repo."""
    mock_config.use_docker = False
    mock_config.target.type = "repo"
    mock_config.target.repo_mode = "repo"

    result = generate_github_actions(mock_config)

    assert "--repo ." in result


def test_generate_github_actions_native_mode_image(mock_config):
    """Test GitHub Actions native mode with image target."""
    mock_config.use_docker = False
    mock_config.target.type = "image"
    mock_config.target.image_name = "myapp:latest"

    result = generate_github_actions(mock_config)

    assert "--image myapp:latest" in result


def test_generate_github_actions_native_mode_url(mock_config):
    """Test GitHub Actions native mode with URL target."""
    mock_config.use_docker = False
    mock_config.target.type = "url"
    mock_config.target.url = "https://api.example.com"

    result = generate_github_actions(mock_config)

    assert "--url https://api.example.com" in result


def test_generate_github_actions_native_mode_iac_terraform(mock_config):
    """Test GitHub Actions native mode with IaC (Terraform) target."""
    mock_config.use_docker = False
    mock_config.target.type = "iac"
    mock_config.target.iac_type = "terraform"

    result = generate_github_actions(mock_config)

    assert "--terraform-state infrastructure" in result


def test_generate_github_actions_native_mode_iac_cloudformation(mock_config):
    """Test GitHub Actions native mode with IaC (CloudFormation) target."""
    mock_config.use_docker = False
    mock_config.target.type = "iac"
    mock_config.target.iac_type = "cloudformation"

    result = generate_github_actions(mock_config)

    assert "--cloudformation infrastructure" in result


def test_generate_github_actions_native_mode_iac_k8s_manifest(mock_config):
    """Test GitHub Actions native mode with IaC (K8s manifest) target."""
    mock_config.use_docker = False
    mock_config.target.type = "iac"
    mock_config.target.iac_type = "k8s-manifest"

    result = generate_github_actions(mock_config)

    assert "--k8s-manifest infrastructure" in result


def test_generate_github_actions_native_mode_gitlab(mock_config):
    """Test GitHub Actions native mode with GitLab target."""
    mock_config.use_docker = False
    mock_config.target.type = "gitlab"
    mock_config.target.gitlab_repo = "myorg/myrepo"

    result = generate_github_actions(mock_config)

    assert "--gitlab-repo myorg/myrepo" in result
    assert "Configure GitLab Access" in result
    assert "GITLAB_TOKEN: ${{ secrets.GITLAB_TOKEN }}" in result
    assert "NOTE: Add GITLAB_TOKEN secret" in result


def test_generate_github_actions_native_mode_k8s(mock_config):
    """Test GitHub Actions native mode with Kubernetes target."""
    mock_config.use_docker = False
    mock_config.target.type = "k8s"
    mock_config.target.k8s_context = "production"

    result = generate_github_actions(mock_config)

    assert "--k8s-context production" in result
    assert "Configure kubectl" in result
    assert "KUBECONFIG" in result
    assert "NOTE: Add KUBECONFIG secret" in result


def test_generate_github_actions_native_mode_with_fail_on(mock_config):
    """A threshold makes the native workflow run `jmo ci` (see the Docker test)."""
    mock_config.use_docker = False
    mock_config.fail_on = "CRITICAL"

    result = generate_github_actions(mock_config)

    assert "jmo ci" in result
    assert "jmo scan" not in result
    assert "--fail-on CRITICAL" in result


def test_generate_github_actions_native_mode_with_custom_threads(mock_config):
    """Test GitHub Actions native mode with custom threads."""
    mock_config.use_docker = False
    mock_config.threads = 8

    result = generate_github_actions(mock_config)

    assert "--threads 8" in result


def test_generate_github_actions_native_mode_with_custom_timeout(mock_config):
    """Test GitHub Actions native mode with custom timeout."""
    mock_config.use_docker = False
    mock_config.timeout = 1200

    result = generate_github_actions(mock_config)

    assert "--timeout 1200" in result


def test_generate_github_actions_uses_scan_defaults_when_unset(mock_config):
    """With no threads/timeout from the wizard, the values come from scan_defaults().

    That is the one source (jmo.yml top level, else 4 / 600); a sentinel pair
    proves the generator reads it rather than carrying its own numbers.
    """
    mock_config.use_docker = False
    mock_config.threads = None
    mock_config.timeout = None

    with patch(
        "scripts.cli.wizard_flows.config_models.scan_defaults",
        return_value=(7, 777),
    ):
        result = generate_github_actions(mock_config)

    assert "--threads 7" in result
    assert "--timeout 777" in result


def test_generate_github_actions_wizard_values_beat_scan_defaults(mock_config):
    """An explicit wizard setting wins over the jmo.yml / built-in default."""
    mock_config.threads = 2
    mock_config.timeout = 120

    with patch(
        "scripts.cli.wizard_flows.config_models.scan_defaults",
        return_value=(7, 777),
    ):
        result = generate_github_actions(mock_config)

    assert "--threads 2" in result
    assert "--timeout 120" in result
    assert "--threads 7" not in result


def test_generate_github_actions_defaults_read_jmo_yml(
    mock_config, tmp_path, monkeypatch
):
    """End to end: the top-level threads/timeout of the jmo.yml in the cwd."""
    (tmp_path / "jmo.yml").write_bytes(b"threads: 6\ntimeout: 900\n")
    monkeypatch.chdir(tmp_path)

    result = generate_github_actions(mock_config)

    assert "--threads 6" in result
    assert "--timeout 900" in result


def test_generate_github_actions_defaults_without_jmo_yml(
    mock_config, tmp_path, monkeypatch
):
    """No jmo.yml: the built-in 4 threads / 600 s, the shipped jmo.yml's values."""
    monkeypatch.chdir(tmp_path)

    result = generate_github_actions(mock_config)

    assert "--threads 4" in result
    assert "--timeout 600" in result


# generate_gitlab_ci tests
def test_generate_gitlab_ci_default_workflow():
    """Test GitLab CI generation with default workflow."""
    result = generate_gitlab_ci("repo")

    assert "stages:" in result
    assert "- security-scan" in result
    assert "security-scan:" in result
    assert f"image: {JMO_DOCKER_IMAGE_FULL}" in result
    assert "    - jmo scan --repo .\n" in result
    assert "artifacts:" in result
    assert "sast: results/summaries/findings.sarif" in result


def test_generate_gitlab_ci_stack_workflow():
    """Test GitLab CI generation with stack workflow."""
    result = generate_gitlab_ci("stack")

    assert "- security-scan" in result
    assert "- report" in result
    assert "security-scan-all:" in result
    assert "security-report:" in result
    assert "    - jmo scan --repos-dir .\n" in result
    assert "jmo report ./results" in result
    assert "dependencies:" in result


def test_generate_gitlab_ci_cicd_workflow():
    """Test GitLab CI generation with CI/CD workflow."""
    result = generate_gitlab_ci("cicd")

    assert "- security-audit" in result
    assert "ci-security-audit:" in result
    assert "    - jmo ci --repos-dir . --fail-on HIGH\n" in result


def test_generate_gitlab_ci_deployment_workflow():
    """Test GitLab CI generation with deployment workflow."""
    result = generate_gitlab_ci("deployment")

    assert "- pre-deployment" in result
    assert "deployment-security-check:" in result
    assert "jmo ci --fail-on CRITICAL --image" in result
    assert "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA" in result
    assert "when: manual" in result


def test_generate_gitlab_ci_dependency_workflow():
    """Test GitLab CI generation with dependency workflow (uses default)."""
    result = generate_gitlab_ci("dependency")

    # Should use default template
    assert "security-scan:" in result
    assert "    - jmo scan --repo .\n" in result


@pytest.mark.parametrize("workflow", WORKFLOW_TYPES)
def test_generate_gitlab_ci_selects_no_profile(workflow):
    """No GitLab CI template names a profile."""
    assert "profile" not in generate_gitlab_ci(workflow).lower()


# generate_docker_compose tests
def test_generate_docker_compose_default_workflow():
    """Test docker-compose generation with default workflow."""
    result = generate_docker_compose("repo")

    assert "version: '3.8'" in result
    assert "services:" in result
    assert "jmo-security:" in result
    assert f"image: {JMO_DOCKER_IMAGE_FULL}" in result
    assert "volumes:" in result
    assert ".:/scan:ro" in result
    assert "./results:/scan/results" in result
    assert "scan" in result
    assert "--repo /scan" in result
    assert "JMO_THREADS=auto" in result


def test_generate_docker_compose_stack_workflow():
    """Test docker-compose generation with stack workflow."""
    result = generate_docker_compose("stack")

    assert "jmo-security:" in result
    assert "jmo-report:" in result
    assert "depends_on:" in result
    assert "- jmo-security" in result
    assert "scan" in result
    assert "--repos-dir /scan" in result
    # `jmo report` has no profile-selection flag at all. This used to assert
    # `--profile {profile}`, which made the generated command exit 2.
    assert "report /scan/results" in result


def test_generate_docker_compose_cicd_workflow():
    """Test docker-compose generation with CI/CD workflow."""
    result = generate_docker_compose("cicd")

    assert "jmo-security:" in result
    assert "ci" in result
    assert "--repos-dir /scan" in result
    assert "--fail-on HIGH" in result


def test_generate_docker_compose_deployment_workflow():
    """Test docker-compose generation with deployment workflow."""
    result = generate_docker_compose("deployment")

    assert "jmo-security:" in result
    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in result
    assert "ci" in result
    assert "--image myapp:latest" in result
    assert "--fail-on CRITICAL" in result


def test_generate_docker_compose_dependency_workflow():
    """Test docker-compose generation with dependency workflow (uses default)."""
    result = generate_docker_compose("dependency")

    # Should use default template
    assert "jmo-security:" in result
    assert "scan" in result
    assert "--repo /scan" in result


@pytest.mark.parametrize("workflow", WORKFLOW_TYPES)
def test_generate_docker_compose_selects_no_profile(workflow):
    """No docker-compose template names a profile."""
    assert "profile" not in generate_docker_compose(workflow).lower()
