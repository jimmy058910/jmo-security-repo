"""Unit tests for wizard command building utilities.

Tests cover:
- Repository arguments (repo, repos-dir, targets, tsv modes)
- Container image arguments (single, batch)
- IaC arguments (terraform, cloudformation, k8s-manifest)
- URL arguments (single, batch, api)
- GitLab arguments (repo, group)
- Kubernetes arguments (single namespace, all namespaces)
- Complete command building for native and Docker modes

Architecture Note:
- Uses MagicMock for TargetConfig and WizardConfig objects
- Tests both native and Docker execution modes
- Verifies volume mounting for Docker mode
"""

from unittest.mock import MagicMock


from scripts.cli.wizard_flows.command_builder import (
    build_command_parts,
    build_gitlab_args,
    build_iac_args,
    build_image_args,
    build_k8s_args,
    build_repo_args,
    build_url_args,
)


# ========== Category 1: Repository Arguments ==========


def test_build_repo_args_repo_mode_native():
    """Test build_repo_args with --repo in native mode."""
    target = MagicMock()
    target.repo_mode = "repo"
    target.repo_path = "/path/to/repo"

    args = build_repo_args(target, use_docker=False)

    assert args == ["--repo", "/path/to/repo"]


def test_build_repo_args_repos_dir_mode_native():
    """Test build_repo_args with --repos-dir in native mode."""
    target = MagicMock()
    target.repo_mode = "repos-dir"
    target.repo_path = "/path/to/repos"

    args = build_repo_args(target, use_docker=False)

    assert args == ["--repos-dir", "/path/to/repos"]


def test_build_repo_args_targets_mode_native():
    """Test build_repo_args with --targets in native mode."""
    target = MagicMock()
    target.repo_mode = "targets"
    target.repo_path = "/path/to/targets.txt"

    args = build_repo_args(target, use_docker=False)

    assert args == ["--targets", "/path/to/targets.txt"]


def test_build_repo_args_tsv_mode_native():
    """Test build_repo_args with TSV mode in native."""
    target = MagicMock()
    target.repo_mode = "tsv"
    target.tsv_path = "./repos.tsv"
    target.tsv_dest = "repos-tsv"

    args = build_repo_args(target, use_docker=False)

    assert "--tsv" in args
    assert "./repos.tsv" in args
    assert "--dest" in args
    assert "repos-tsv" in args


def test_build_repo_args_tsv_mode_no_dest():
    """Test build_repo_args with TSV mode without dest."""
    target = MagicMock()
    target.repo_mode = "tsv"
    target.tsv_path = "./repos.tsv"
    target.tsv_dest = None

    args = build_repo_args(target, use_docker=False)

    assert "--tsv" in args
    assert "./repos.tsv" in args
    assert "--dest" not in args


def test_build_repo_args_docker_mode(tmp_path):
    """Test build_repo_args with Docker volume mounting."""
    target = MagicMock()
    target.repo_path = str(tmp_path / "repos")

    args = build_repo_args(target, use_docker=True)

    assert "-v" in args
    assert any("/scan" in arg for arg in args)
    assert "--repos-dir" in args


# ========== Category 2: Image Arguments ==========


def test_build_image_args_single_image():
    """Test build_image_args with single image."""
    target = MagicMock()
    target.image_name = "nginx:latest"
    target.images_file = None

    args = build_image_args(target, use_docker=False)

    assert args == ["--image", "nginx:latest"]


def test_build_image_args_batch_native():
    """Test build_image_args with images file in native mode."""
    target = MagicMock()
    target.image_name = None
    target.images_file = "./images.txt"

    args = build_image_args(target, use_docker=False)

    assert args == ["--images-file", "./images.txt"]


def test_build_image_args_batch_docker(tmp_path):
    """Test build_image_args with images file in Docker mode."""
    target = MagicMock()
    target.image_name = None
    target.images_file = str(tmp_path / "images.txt")

    args = build_image_args(target, use_docker=True)

    assert "-v" in args
    assert "--images-file" in args
    assert "/images.txt" in args


# ========== Category 3: IaC Arguments ==========


def test_build_iac_args_terraform_native():
    """Test build_iac_args with Terraform in native mode."""
    target = MagicMock()
    target.iac_type = "terraform"
    target.iac_path = "./infrastructure.tfstate"

    args = build_iac_args(target, use_docker=False)

    assert "--terraform" in args
    assert "./infrastructure.tfstate" in args


def test_build_iac_args_cloudformation_native():
    """Test build_iac_args with CloudFormation in native mode."""
    target = MagicMock()
    target.iac_type = "cloudformation"
    target.iac_path = "./template.yaml"

    args = build_iac_args(target, use_docker=False)

    assert "--cloudformation" in args
    assert "./template.yaml" in args


def test_build_iac_args_k8s_manifest_native():
    """Test build_iac_args with Kubernetes manifest in native mode."""
    target = MagicMock()
    target.iac_type = "k8s-manifest"
    target.iac_path = "./deployment.yaml"

    args = build_iac_args(target, use_docker=False)

    assert "--k8s-manifest" in args
    assert "./deployment.yaml" in args


def test_build_iac_args_docker_mode(tmp_path):
    """Test build_iac_args with Docker volume mounting."""
    target = MagicMock()
    target.iac_type = "terraform"
    target.iac_path = str(tmp_path / "infrastructure.tfstate")

    args = build_iac_args(target, use_docker=True)

    assert "-v" in args
    assert any("/scan/iac-file" in arg for arg in args)
    assert "--terraform" in args


# ========== Category 4: URL Arguments ==========


def test_build_url_args_single_url():
    """Test build_url_args with single URL."""
    target = MagicMock()
    target.url = "https://example.com"
    target.urls_file = None
    target.api_spec = None

    args = build_url_args(target, use_docker=False)

    assert args == ["--url", "https://example.com"]


def test_build_url_args_batch_native():
    """Test build_url_args with URLs file in native mode."""
    target = MagicMock()
    target.url = None
    target.urls_file = "./urls.txt"
    target.api_spec = None

    args = build_url_args(target, use_docker=False)

    assert args == ["--urls-file", "./urls.txt"]


def test_build_url_args_batch_docker(tmp_path):
    """Test build_url_args with URLs file in Docker mode."""
    target = MagicMock()
    target.url = None
    target.urls_file = str(tmp_path / "urls.txt")
    target.api_spec = None

    args = build_url_args(target, use_docker=True)

    assert "-v" in args
    assert "--urls-file" in args
    assert "/urls.txt" in args


def test_build_url_args_api_spec():
    """Test build_url_args with OpenAPI spec."""
    target = MagicMock()
    target.url = None
    target.urls_file = None
    target.api_spec = "./openapi.yaml"

    args = build_url_args(target, use_docker=False)

    assert args == ["--api-spec", "./openapi.yaml"]


# ========== Category 5: GitLab Arguments ==========


def test_build_gitlab_args_repo_mode():
    """Test build_gitlab_args with repository mode."""
    target = MagicMock()
    target.gitlab_url = "https://gitlab.com"
    target.gitlab_token = "token123"
    target.gitlab_repo = "mygroup/myrepo"
    target.gitlab_group = None

    args = build_gitlab_args(target, use_docker=False)

    assert "--gitlab-url" in args
    assert "https://gitlab.com" in args
    assert "--gitlab-token" in args
    assert "token123" in args
    assert "--gitlab-repo" in args
    assert "mygroup/myrepo" in args


def test_build_gitlab_args_group_mode():
    """Test build_gitlab_args with group mode."""
    target = MagicMock()
    target.gitlab_url = "https://gitlab.com"
    target.gitlab_token = "token123"
    target.gitlab_repo = None
    target.gitlab_group = "mygroup"

    args = build_gitlab_args(target, use_docker=False)

    assert "--gitlab-url" in args
    assert "--gitlab-token" in args
    assert "--gitlab-group" in args
    assert "mygroup" in args
    assert "--gitlab-repo" not in args


def test_build_gitlab_args_minimal():
    """Test build_gitlab_args with minimal config (no token)."""
    target = MagicMock()
    target.gitlab_url = "https://gitlab.com"
    target.gitlab_token = None
    target.gitlab_repo = "mygroup/myrepo"
    target.gitlab_group = None

    args = build_gitlab_args(target, use_docker=False)

    assert "--gitlab-url" in args
    assert "--gitlab-token" not in args
    assert "--gitlab-repo" in args


# ========== Category 6: Kubernetes Arguments ==========


def test_build_k8s_args_single_namespace():
    """Test build_k8s_args with single namespace."""
    target = MagicMock()
    target.k8s_context = "minikube"
    target.k8s_namespace = "default"
    target.k8s_all_namespaces = False

    args = build_k8s_args(target, use_docker=False)

    assert "--k8s-context" in args
    assert "minikube" in args
    assert "--k8s-namespace" in args
    assert "default" in args
    assert "--k8s-all-namespaces" not in args


def test_build_k8s_args_all_namespaces():
    """Test build_k8s_args with all namespaces flag."""
    target = MagicMock()
    target.k8s_context = "prod-cluster"
    target.k8s_namespace = None
    target.k8s_all_namespaces = True

    args = build_k8s_args(target, use_docker=False)

    assert "--k8s-context" in args
    assert "prod-cluster" in args
    assert "--k8s-all-namespaces" in args
    assert "--k8s-namespace" not in args


def test_build_k8s_args_minimal():
    """Test build_k8s_args with minimal config (context only)."""
    target = MagicMock()
    target.k8s_context = "minikube"
    target.k8s_namespace = None
    target.k8s_all_namespaces = False

    args = build_k8s_args(target, use_docker=False)

    assert "--k8s-context" in args
    assert "minikube" in args


# ========== Category 7: Complete Command Building ==========


def test_build_command_parts_native_repo(tmp_path):
    """Test build_command_parts for native repo scan."""
    config = MagicMock()
    config.use_docker = False
    config.profile = "balanced"
    config.results_dir = str(tmp_path / "results")
    config.threads = 4
    config.timeout = 600
    config.fail_on = "high"
    config.allow_missing_tools = True
    config.human_logs = True

    target = MagicMock()
    target.type = "repo"
    target.repo_mode = "repos-dir"
    target.repo_path = str(tmp_path)
    config.target = target

    cmd = build_command_parts(config)

    assert cmd[0] == "jmo"
    assert cmd[1] == "scan"
    assert "--repos-dir" in cmd
    assert "--results-dir" in cmd
    assert "--threads" in cmd
    assert "--timeout" in cmd
    assert "--fail-on" in cmd
    assert "--allow-missing-tools" in cmd
    assert "--human-logs" in cmd


def test_build_command_parts_docker_repo(tmp_path):
    """Test build_command_parts for Docker repo scan."""
    config = MagicMock()
    config.use_docker = True
    config.profile = "fast"
    config.results_dir = str(tmp_path / "results")

    target = MagicMock()
    target.type = "repo"
    target.repo_path = str(tmp_path / "myrepo")
    config.target = target

    cmd = build_command_parts(config)

    assert cmd[0] == "docker"
    assert "run" in cmd
    assert "--rm" in cmd
    assert "ghcr.io/jimmy058910/jmo-security:latest" in cmd
    assert "scan" in cmd
    assert "--profile" in cmd
    assert "fast" in cmd


def test_build_command_parts_native_image():
    """Test build_command_parts for native image scan."""
    config = MagicMock()
    config.use_docker = False
    config.profile = "balanced"
    config.results_dir = "./results"
    config.threads = None
    config.timeout = None
    config.fail_on = None
    config.allow_missing_tools = False
    config.human_logs = False

    target = MagicMock()
    target.type = "image"
    target.image_name = "nginx:latest"
    target.images_file = None
    config.target = target

    cmd = build_command_parts(config)

    assert "jmotools" in cmd
    assert "balanced" in cmd
    assert "--image" in cmd
    assert "nginx:latest" in cmd


def test_build_command_parts_docker_volumes(tmp_path):
    """Test build_command_parts includes correct volume mounts for Docker."""
    config = MagicMock()
    config.use_docker = True
    config.profile = "balanced"
    config.results_dir = str(tmp_path / "results")

    target = MagicMock()
    target.type = "repo"
    target.repo_path = str(tmp_path / "myrepo")
    config.target = target

    cmd = build_command_parts(config)

    # Should have volume mounts (-v flags)
    assert "-v" in cmd
    # Should have results mount
    assert any("/results" in arg for arg in cmd)
