"""Tests for command building utilities."""

from __future__ import annotations


from scripts.cli.wizard_flows.command_builder import (
    build_command_parts,
    build_gitlab_args,
    build_iac_args,
    build_image_args,
    build_k8s_args,
    build_repo_args,
    build_url_args,
)


class MockTargetConfig:
    """Mock TargetConfig for testing."""

    def __init__(self):
        self.type = "repo"
        self.repo_mode = ""
        self.repo_path = ""
        self.tsv_path = ""
        self.tsv_dest = "repos-tsv"
        self.image_name = ""
        self.images_file = ""
        self.iac_type = ""
        self.iac_path = ""
        self.url = ""
        self.urls_file = ""
        self.api_spec = ""
        self.gitlab_url = "https://gitlab.com"
        self.gitlab_token = ""
        self.gitlab_repo = ""
        self.gitlab_group = ""
        self.k8s_context = ""
        self.k8s_all_namespaces = False
        self.k8s_namespace = ""


class MockWizardConfig:
    """Mock WizardConfig for testing."""

    def __init__(self):
        self.use_docker = False
        self.profile = "balanced"
        self.results_dir = "results"
        self.threads = None
        self.timeout = None
        self.fail_on = ""
        self.allow_missing_tools = False
        self.human_logs = False
        self.target = MockTargetConfig()


class TestBuildRepoArgs:
    """Tests for build_repo_args function."""

    def test_build_repo_args_native_repo_mode(self):
        """Test building repo arguments in native repo mode."""
        target = MockTargetConfig()
        target.repo_mode = "repo"
        target.repo_path = "/path/to/repo"

        args = build_repo_args(target, use_docker=False)

        assert args == ["--repo", "/path/to/repo"]

    def test_build_repo_args_native_repos_dir_mode(self):
        """Test building repo arguments in native repos-dir mode."""
        target = MockTargetConfig()
        target.repo_mode = "repos-dir"
        target.repo_path = "/path/to/repos"

        args = build_repo_args(target, use_docker=False)

        assert args == ["--repos-dir", "/path/to/repos"]

    def test_build_repo_args_native_targets_mode(self):
        """Test building repo arguments in native targets mode."""
        target = MockTargetConfig()
        target.repo_mode = "targets"
        target.repo_path = "/path/to/targets.txt"

        args = build_repo_args(target, use_docker=False)

        assert args == ["--targets", "/path/to/targets.txt"]

    def test_build_repo_args_native_tsv_mode(self):
        """Test building repo arguments in native TSV mode."""
        target = MockTargetConfig()
        target.repo_mode = "tsv"
        target.tsv_path = "/path/to/repos.tsv"
        target.tsv_dest = "repos-output"

        args = build_repo_args(target, use_docker=False)

        assert args == ["--tsv", "/path/to/repos.tsv", "--dest", "repos-output"]

    def test_build_repo_args_native_tsv_mode_no_dest(self):
        """Test building repo arguments in native TSV mode without dest."""
        target = MockTargetConfig()
        target.repo_mode = "tsv"
        target.tsv_path = "/path/to/repos.tsv"
        delattr(target, "tsv_dest")  # Remove tsv_dest attribute

        args = build_repo_args(target, use_docker=False)

        assert args == ["--tsv", "/path/to/repos.tsv"]

    def test_build_repo_args_docker_mode(self, tmp_path):
        """Test building repo arguments in Docker mode."""
        target = MockTargetConfig()
        target.repo_path = str(tmp_path)

        args = build_repo_args(target, use_docker=True)

        assert "-v" in args
        assert "--repos-dir" in args
        assert "/scan" in args
        # Should contain absolute path
        assert str(tmp_path.resolve()) in " ".join(args)

    def test_build_repo_args_docker_no_path(self):
        """Test building repo arguments in Docker mode without path."""
        target = MockTargetConfig()
        target.repo_path = ""

        args = build_repo_args(target, use_docker=True)

        assert args == []


class TestBuildImageArgs:
    """Tests for build_image_args function."""

    def test_build_image_args_single_image(self):
        """Test building arguments for single image."""
        target = MockTargetConfig()
        target.image_name = "nginx:latest"

        args = build_image_args(target, use_docker=False)

        assert args == ["--image", "nginx:latest"]

    def test_build_image_args_images_file_native(self):
        """Test building arguments for images file in native mode."""
        target = MockTargetConfig()
        target.images_file = "/path/to/images.txt"

        args = build_image_args(target, use_docker=False)

        assert args == ["--images-file", "/path/to/images.txt"]

    def test_build_image_args_images_file_docker(self, tmp_path):
        """Test building arguments for images file in Docker mode."""
        images_file = tmp_path / "images.txt"
        images_file.touch()

        target = MockTargetConfig()
        target.images_file = str(images_file)

        args = build_image_args(target, use_docker=True)

        assert "-v" in args
        assert "--images-file" in args
        assert "/images.txt" in args

    def test_build_image_args_no_image(self):
        """Test building arguments with no image specified."""
        target = MockTargetConfig()

        args = build_image_args(target, use_docker=False)

        assert args == []


class TestBuildIacArgs:
    """Tests for build_iac_args function."""

    def test_build_iac_args_terraform_native(self):
        """Test building arguments for Terraform in native mode."""
        target = MockTargetConfig()
        target.iac_type = "terraform"
        target.iac_path = "/path/to/main.tf"

        args = build_iac_args(target, use_docker=False)

        assert args == ["--terraform", "/path/to/main.tf"]

    def test_build_iac_args_cloudformation_native(self):
        """Test building arguments for CloudFormation in native mode."""
        target = MockTargetConfig()
        target.iac_type = "cloudformation"
        target.iac_path = "/path/to/template.yaml"

        args = build_iac_args(target, use_docker=False)

        assert args == ["--cloudformation", "/path/to/template.yaml"]

    def test_build_iac_args_k8s_manifest_native(self):
        """Test building arguments for K8s manifest in native mode."""
        target = MockTargetConfig()
        target.iac_type = "k8s-manifest"
        target.iac_path = "/path/to/deployment.yaml"

        args = build_iac_args(target, use_docker=False)

        assert args == ["--k8s-manifest", "/path/to/deployment.yaml"]

    def test_build_iac_args_docker_mode(self, tmp_path):
        """Test building arguments for IaC in Docker mode."""
        iac_file = tmp_path / "main.tf"
        iac_file.touch()

        target = MockTargetConfig()
        target.iac_type = "terraform"
        target.iac_path = str(iac_file)

        args = build_iac_args(target, use_docker=True)

        assert "-v" in args
        assert "--terraform" in args
        assert "/scan/iac-file" in args


class TestBuildUrlArgs:
    """Tests for build_url_args function."""

    def test_build_url_args_single_url(self):
        """Test building arguments for single URL."""
        target = MockTargetConfig()
        target.url = "https://example.com"

        args = build_url_args(target, use_docker=False)

        assert args == ["--url", "https://example.com"]

    def test_build_url_args_urls_file_native(self):
        """Test building arguments for URLs file in native mode."""
        target = MockTargetConfig()
        target.urls_file = "/path/to/urls.txt"

        args = build_url_args(target, use_docker=False)

        assert args == ["--urls-file", "/path/to/urls.txt"]

    def test_build_url_args_urls_file_docker(self, tmp_path):
        """Test building arguments for URLs file in Docker mode."""
        urls_file = tmp_path / "urls.txt"
        urls_file.touch()

        target = MockTargetConfig()
        target.urls_file = str(urls_file)

        args = build_url_args(target, use_docker=True)

        assert "-v" in args
        assert "--urls-file" in args
        assert "/urls.txt" in args

    def test_build_url_args_api_spec(self):
        """Test building arguments for API spec."""
        target = MockTargetConfig()
        target.api_spec = "/path/to/openapi.json"

        args = build_url_args(target, use_docker=False)

        assert args == ["--api-spec", "/path/to/openapi.json"]

    def test_build_url_args_no_url(self):
        """Test building arguments with no URL specified."""
        target = MockTargetConfig()

        args = build_url_args(target, use_docker=False)

        assert args == []


class TestBuildGitlabArgs:
    """Tests for build_gitlab_args function."""

    def test_build_gitlab_args_repo(self):
        """Test building arguments for GitLab repo."""
        target = MockTargetConfig()
        target.gitlab_url = "https://gitlab.example.com"
        target.gitlab_token = "glpat-abc123"
        target.gitlab_repo = "mygroup/myrepo"

        args = build_gitlab_args(target, use_docker=False)

        assert "--gitlab-url" in args
        assert "https://gitlab.example.com" in args
        assert "--gitlab-token" in args
        assert "glpat-abc123" in args
        assert "--gitlab-repo" in args
        assert "mygroup/myrepo" in args

    def test_build_gitlab_args_group(self):
        """Test building arguments for GitLab group."""
        target = MockTargetConfig()
        target.gitlab_url = "https://gitlab.com"
        target.gitlab_token = "glpat-xyz789"
        target.gitlab_group = "mygroup"

        args = build_gitlab_args(target, use_docker=False)

        assert "--gitlab-url" in args
        assert "--gitlab-token" in args
        assert "--gitlab-group" in args
        assert "mygroup" in args

    def test_build_gitlab_args_minimal(self):
        """Test building arguments with minimal GitLab config."""
        target = MockTargetConfig()

        args = build_gitlab_args(target, use_docker=False)

        # Should have gitlab-url even if using default
        assert "--gitlab-url" in args
        assert "https://gitlab.com" in args


class TestBuildK8sArgs:
    """Tests for build_k8s_args function."""

    def test_build_k8s_args_context_and_namespace(self):
        """Test building arguments for K8s context and namespace."""
        target = MockTargetConfig()
        target.k8s_context = "minikube"
        target.k8s_namespace = "production"

        args = build_k8s_args(target, use_docker=False)

        assert "--k8s-context" in args
        assert "minikube" in args
        assert "--k8s-namespace" in args
        assert "production" in args

    def test_build_k8s_args_all_namespaces(self):
        """Test building arguments for all K8s namespaces."""
        target = MockTargetConfig()
        target.k8s_context = "minikube"
        target.k8s_all_namespaces = True

        args = build_k8s_args(target, use_docker=False)

        assert "--k8s-context" in args
        assert "minikube" in args
        assert "--k8s-all-namespaces" in args
        assert "--k8s-namespace" not in args

    def test_build_k8s_args_minimal(self):
        """Test building arguments with minimal K8s config."""
        target = MockTargetConfig()

        args = build_k8s_args(target, use_docker=False)

        assert args == []


class TestBuildCommandParts:
    """Tests for build_command_parts function."""

    def test_build_command_parts_native_basic(self):
        """Test building command parts in native mode (basic)."""
        config = MockWizardConfig()
        config.use_docker = False
        config.profile = "fast"
        config.results_dir = "results"
        config.target.type = "repo"
        config.target.repo_mode = "repo"
        config.target.repo_path = "/path/to/repo"

        parts = build_command_parts(config)

        assert "jmo" in parts
        assert "scan" in parts
        assert "--repo" in parts
        assert "/path/to/repo" in parts
        assert "--results-dir" in parts
        assert "results" in parts
        assert "--profile-name" in parts
        assert "fast" in parts

    def test_build_command_parts_native_with_options(self):
        """Test building command parts with advanced options."""
        config = MockWizardConfig()
        config.use_docker = False
        config.profile = "balanced"
        config.results_dir = "results"
        config.threads = 8
        config.timeout = 600
        config.fail_on = "high"
        config.allow_missing_tools = True
        config.human_logs = True
        config.target.type = "repo"
        config.target.repo_mode = "repos-dir"
        config.target.repo_path = "/repos"

        parts = build_command_parts(config)

        assert "--threads" in parts
        assert "8" in parts
        assert "--timeout" in parts
        assert "600" in parts
        assert "--fail-on" in parts
        assert "HIGH" in parts
        assert "--allow-missing-tools" in parts
        assert "--human-logs" in parts

    def test_build_command_parts_docker_basic(self, tmp_path):
        """Test building command parts in Docker mode (basic)."""
        config = MockWizardConfig()
        config.use_docker = True
        config.profile = "deep"
        config.results_dir = str(tmp_path / "results")
        config.target.type = "repo"
        config.target.repo_path = str(tmp_path)

        parts = build_command_parts(config)

        assert "docker" in parts
        assert "run" in parts
        assert "--rm" in parts
        assert "ghcr.io/jimmy058910/jmo-security:latest" in parts
        assert "scan" in parts
        assert "--profile" in parts
        assert "deep" in parts
        assert "-v" in parts
        assert "/results" in parts

    def test_build_command_parts_image_target(self):
        """Test building command parts for image target."""
        config = MockWizardConfig()
        config.use_docker = False
        config.profile = "balanced"
        config.target.type = "image"
        config.target.image_name = "nginx:latest"

        parts = build_command_parts(config)

        assert "--image" in parts
        assert "nginx:latest" in parts

    def test_build_command_parts_iac_target(self):
        """Test building command parts for IaC target."""
        config = MockWizardConfig()
        config.use_docker = False
        config.profile = "balanced"
        config.target.type = "iac"
        config.target.iac_type = "terraform"
        config.target.iac_path = "/path/to/main.tf"

        parts = build_command_parts(config)

        assert "--terraform" in parts
        assert "/path/to/main.tf" in parts

    def test_build_command_parts_url_target(self):
        """Test building command parts for URL target."""
        config = MockWizardConfig()
        config.use_docker = False
        config.profile = "balanced"
        config.target.type = "url"
        config.target.url = "https://example.com"

        parts = build_command_parts(config)

        assert "--url" in parts
        assert "https://example.com" in parts

    def test_build_command_parts_gitlab_target(self):
        """Test building command parts for GitLab target."""
        config = MockWizardConfig()
        config.use_docker = False
        config.profile = "balanced"
        config.target.type = "gitlab"
        config.target.gitlab_repo = "mygroup/myrepo"
        config.target.gitlab_token = "glpat-123"

        parts = build_command_parts(config)

        assert "--gitlab-repo" in parts
        assert "mygroup/myrepo" in parts
        assert "--gitlab-token" in parts

    def test_build_command_parts_k8s_target(self):
        """Test building command parts for K8s target."""
        config = MockWizardConfig()
        config.use_docker = False
        config.profile = "balanced"
        config.target.type = "k8s"
        config.target.k8s_context = "minikube"
        config.target.k8s_namespace = "default"

        parts = build_command_parts(config)

        assert "--k8s-context" in parts
        assert "minikube" in parts
        assert "--k8s-namespace" in parts
        assert "default" in parts
