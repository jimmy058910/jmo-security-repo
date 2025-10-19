"""
Unit tests for scripts/cli/scan_orchestrator.py

Tests the ScanOrchestrator class extracted from cmd_scan() as part of PHASE 1 refactoring.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock
from scripts.cli.scan_orchestrator import (
    ScanTargets,
    ScanConfig,
    ScanOrchestrator,
)


class TestScanTargets:
    """Test ScanTargets dataclass"""

    def test_empty_targets(self):
        """Test creating empty ScanTargets"""
        targets = ScanTargets()

        assert len(targets.repos) == 0
        assert len(targets.images) == 0
        assert len(targets.iac_files) == 0
        assert len(targets.urls) == 0
        assert len(targets.gitlab_repos) == 0
        assert len(targets.k8s_resources) == 0
        assert targets.total_count() == 0
        assert targets.is_empty() is True

    def test_targets_with_repos(self):
        """Test ScanTargets with repositories"""
        targets = ScanTargets(repos=[Path("/repo1"), Path("/repo2"), Path("/repo3")])

        assert len(targets.repos) == 3
        assert targets.total_count() == 3
        assert targets.is_empty() is False

    def test_targets_with_multiple_types(self):
        """Test ScanTargets with multiple target types"""
        targets = ScanTargets(
            repos=[Path("/repo1")],
            images=["nginx:latest", "redis:alpine"],
            iac_files=[("terraform", Path("main.tf"))],
            urls=["https://example.com"],
            gitlab_repos=["group/project"],
            k8s_resources=["prod:default"],
        )

        assert targets.total_count() == 7
        assert targets.is_empty() is False

    def test_summary_string(self):
        """Test human-readable summary generation"""
        targets = ScanTargets(
            repos=[Path("/repo1"), Path("/repo2")],
            images=["nginx:latest"],
            urls=["https://example.com", "https://test.com"],
        )

        summary = targets.summary()

        assert "2 repos" in summary
        assert "1 images" in summary
        assert "2 URLs" in summary

    def test_to_dict_conversion(self):
        """Test converting targets to dictionary"""
        targets = ScanTargets(
            repos=[Path("/repo1")],
            images=["nginx:latest"],
            iac_files=[("terraform", Path("main.tf"))],
        )

        data = targets.to_dict()

        assert data["repos"] == ["/repo1"]
        assert data["images"] == ["nginx:latest"]
        assert data["iac_files"] == [("terraform", "main.tf")]
        assert data["total_count"] == 3


class TestScanConfig:
    """Test ScanConfig dataclass"""

    def test_valid_config(self):
        """Test creating a valid ScanConfig"""
        config = ScanConfig(
            tools=["trufflehog", "semgrep", "trivy"],
            results_dir=Path("/tmp/results"),
            timeout=600,
            retries=1,
            max_workers=4,
        )

        assert config.tools == ["trufflehog", "semgrep", "trivy"]
        assert config.results_dir == Path("/tmp/results")
        assert config.timeout == 600
        assert config.retries == 1
        assert config.max_workers == 4

    def test_default_values(self):
        """Test default configuration values"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
        )

        assert config.timeout == 600  # Default
        assert config.retries == 0  # Default
        assert config.max_workers is None  # Default (auto)
        assert config.include_patterns == []  # Default
        assert config.exclude_patterns == []  # Default
        assert config.allow_missing_tools is False  # Default

    def test_empty_tools_raises_error(self):
        """Test that empty tools list raises ValueError"""
        with pytest.raises(ValueError, match="At least one tool must be specified"):
            ScanConfig(
                tools=[],
                results_dir=Path("/tmp/results"),
            )

    def test_negative_timeout_raises_error(self):
        """Test that negative timeout raises ValueError"""
        with pytest.raises(ValueError, match="Timeout must be positive"):
            ScanConfig(
                tools=["trufflehog"],
                results_dir=Path("/tmp/results"),
                timeout=-1,
            )

    def test_negative_retries_raises_error(self):
        """Test that negative retries raises ValueError"""
        with pytest.raises(ValueError, match="Retries must be non-negative"):
            ScanConfig(
                tools=["trufflehog"],
                results_dir=Path("/tmp/results"),
                retries=-1,
            )

    def test_invalid_max_workers_raises_error(self):
        """Test that max_workers < 1 raises ValueError"""
        with pytest.raises(ValueError, match="max_workers must be >= 1"):
            ScanConfig(
                tools=["trufflehog"],
                results_dir=Path("/tmp/results"),
                max_workers=0,
            )


class TestScanOrchestrator:
    """Test ScanOrchestrator class"""

    def test_orchestrator_initialization(self):
        """Test creating a ScanOrchestrator"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
        )

        orchestrator = ScanOrchestrator(config)

        assert orchestrator.config == config

    def test_discover_repos_single_repo(self):
        """Test discovering a single repository"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
        )
        orchestrator = ScanOrchestrator(config)

        # Mock args with single repo
        args = MagicMock()
        args.repo = "/tmp/test-repo"
        args.repos_dir = None
        args.targets = None

        # Create the test repo directory
        test_repo = Path("/tmp/test-repo")
        test_repo.mkdir(exist_ok=True)

        try:
            repos = orchestrator._discover_repos(args)
            assert len(repos) == 1
            assert repos[0] == test_repo
        finally:
            if test_repo.exists():
                test_repo.rmdir()

    def test_discover_repos_directory(self, tmp_path):
        """Test discovering repos from a directory"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
        )
        orchestrator = ScanOrchestrator(config)

        # Create test repositories
        (tmp_path / "repo1").mkdir()
        (tmp_path / "repo2").mkdir()
        (tmp_path / "repo3").mkdir()

        # Mock args with repos-dir
        args = MagicMock()
        args.repo = None
        args.repos_dir = str(tmp_path)
        args.targets = None

        repos = orchestrator._discover_repos(args)

        assert len(repos) == 3
        repo_names = {r.name for r in repos}
        assert repo_names == {"repo1", "repo2", "repo3"}

    def test_discover_repos_from_targets_file(self, tmp_path):
        """Test discovering repos from a targets file"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
        )
        orchestrator = ScanOrchestrator(config)

        # Create test repos
        repo1 = tmp_path / "repo1"
        repo2 = tmp_path / "repo2"
        repo1.mkdir()
        repo2.mkdir()

        # Create targets file
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text(
            f"{repo1}\n"
            f"# Comment line\n"
            f"{repo2}\n"
            f"\n"  # Empty line
        )

        # Mock args with targets file
        args = MagicMock()
        args.repo = None
        args.repos_dir = None
        args.targets = str(targets_file)

        repos = orchestrator._discover_repos(args)

        assert len(repos) == 2
        assert repo1 in repos
        assert repo2 in repos

    def test_discover_images_single(self):
        """Test discovering a single container image"""
        config = ScanConfig(
            tools=["trivy"],
            results_dir=Path("/tmp/results"),
        )
        orchestrator = ScanOrchestrator(config)

        args = MagicMock()
        args.image = "nginx:latest"
        args.images_file = None

        images = orchestrator._discover_images(args)

        assert len(images) == 1
        assert images[0] == "nginx:latest"

    def test_discover_images_from_file(self, tmp_path):
        """Test discovering images from a file"""
        config = ScanConfig(
            tools=["trivy"],
            results_dir=Path("/tmp/results"),
        )
        orchestrator = ScanOrchestrator(config)

        # Create images file
        images_file = tmp_path / "images.txt"
        images_file.write_text(
            "nginx:latest\n" "# Comment\n" "redis:alpine\n" "postgres:14\n"
        )

        args = MagicMock()
        args.image = None
        args.images_file = str(images_file)

        images = orchestrator._discover_images(args)

        assert len(images) == 3
        assert "nginx:latest" in images
        assert "redis:alpine" in images
        assert "postgres:14" in images

    def test_discover_iac_files(self, tmp_path):
        """Test discovering IaC files"""
        config = ScanConfig(
            tools=["checkov"],
            results_dir=Path("/tmp/results"),
        )
        orchestrator = ScanOrchestrator(config)

        # Create IaC files
        tf_file = tmp_path / "main.tf"
        cf_file = tmp_path / "stack.yaml"
        k8s_file = tmp_path / "deployment.yaml"
        tf_file.touch()
        cf_file.touch()
        k8s_file.touch()

        args = MagicMock()
        args.terraform_state = str(tf_file)
        args.cloudformation = str(cf_file)
        args.k8s_manifest = str(k8s_file)

        iac_files = orchestrator._discover_iac_files(args)

        assert len(iac_files) == 3
        types = [t for t, _ in iac_files]
        assert "terraform" in types
        assert "cloudformation" in types
        assert "k8s" in types

    def test_discover_urls_single(self):
        """Test discovering a single URL"""
        config = ScanConfig(
            tools=["zap"],
            results_dir=Path("/tmp/results"),
        )
        orchestrator = ScanOrchestrator(config)

        args = MagicMock()
        args.url = "https://example.com"
        args.urls_file = None

        urls = orchestrator._discover_urls(args)

        assert len(urls) == 1
        assert urls[0] == "https://example.com"

    def test_discover_gitlab_repos(self):
        """Test discovering GitLab repositories"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
        )
        orchestrator = ScanOrchestrator(config)

        args = MagicMock()
        args.gitlab_repo = "mygroup/myproject"
        args.gitlab_url = "https://gitlab.com"
        args.gitlab_token = ""
        args.gitlab_group = None

        gitlab_repos = orchestrator._discover_gitlab_repos(args)

        assert len(gitlab_repos) == 1
        assert isinstance(gitlab_repos[0], dict)
        assert gitlab_repos[0]["full_path"] == "mygroup/myproject"
        assert gitlab_repos[0]["group"] == "mygroup"
        assert gitlab_repos[0]["repo"] == "myproject"
        assert gitlab_repos[0]["name"] == "mygroup_myproject"
        assert gitlab_repos[0]["url"] == "https://gitlab.com"

    def test_discover_k8s_resources(self):
        """Test discovering Kubernetes resources"""
        config = ScanConfig(
            tools=["trivy"],
            results_dir=Path("/tmp/results"),
        )
        orchestrator = ScanOrchestrator(config)

        args = MagicMock()
        args.k8s_context = "prod"
        args.k8s_namespace = "default"
        args.k8s_all_namespaces = False

        k8s_resources = orchestrator._discover_k8s_resources(args)

        assert len(k8s_resources) == 1
        assert isinstance(k8s_resources[0], dict)
        assert k8s_resources[0]["context"] == "prod"
        assert k8s_resources[0]["namespace"] == "default"
        assert k8s_resources[0]["name"] == "prod_default"

    def test_filter_repos_include_patterns(self, tmp_path):
        """Test filtering repos with include patterns"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
            include_patterns=["test-*", "demo-*"],
        )
        orchestrator = ScanOrchestrator(config)

        repos = [
            tmp_path / "test-repo1",
            tmp_path / "demo-repo2",
            tmp_path / "prod-repo3",
        ]

        filtered = orchestrator._filter_repos(repos)

        assert len(filtered) == 2
        names = {r.name for r in filtered}
        assert names == {"test-repo1", "demo-repo2"}

    def test_filter_repos_exclude_patterns(self, tmp_path):
        """Test filtering repos with exclude patterns"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
            exclude_patterns=["test-*"],
        )
        orchestrator = ScanOrchestrator(config)

        repos = [
            tmp_path / "test-repo1",
            tmp_path / "prod-repo2",
            tmp_path / "demo-repo3",
        ]

        filtered = orchestrator._filter_repos(repos)

        assert len(filtered) == 2
        names = {r.name for r in filtered}
        assert names == {"prod-repo2", "demo-repo3"}

    def test_setup_results_directories(self, tmp_path):
        """Test creating results directory structure"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=tmp_path,
        )
        orchestrator = ScanOrchestrator(config)

        targets = ScanTargets(
            repos=[Path("/repo1")],
            images=["nginx:latest"],
            iac_files=[("terraform", Path("main.tf"))],
        )

        orchestrator.setup_results_directories(targets)

        # Check that directories were created
        assert (tmp_path / "individual-repos").exists()
        assert (tmp_path / "individual-images").exists()
        assert (tmp_path / "individual-iac").exists()

        # These should NOT be created (no targets)
        assert not (tmp_path / "individual-web").exists()
        assert not (tmp_path / "individual-gitlab").exists()
        assert not (tmp_path / "individual-k8s").exists()

    def test_validate_targets_with_targets(self):
        """Test validating targets when targets exist"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
        )
        orchestrator = ScanOrchestrator(config)

        targets = ScanTargets(repos=[Path("/repo1")])

        assert orchestrator.validate_targets(targets) is True

    def test_validate_targets_empty(self):
        """Test validating targets when no targets exist"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
        )
        orchestrator = ScanOrchestrator(config)

        targets = ScanTargets()

        assert orchestrator.validate_targets(targets) is False

    def test_get_effective_max_workers_from_config(self):
        """Test getting max_workers from config"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
            max_workers=8,
        )
        orchestrator = ScanOrchestrator(config)

        assert orchestrator.get_effective_max_workers() == 8

    def test_get_effective_max_workers_default(self):
        """Test getting default max_workers"""
        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=Path("/tmp/results"),
            max_workers=None,
        )
        orchestrator = ScanOrchestrator(config)

        workers = orchestrator.get_effective_max_workers()

        assert workers >= 1  # Should use default (4) or env var

    def test_get_summary(self, tmp_path):
        """Test generating orchestration summary"""
        config = ScanConfig(
            tools=["trufflehog", "semgrep"],
            results_dir=tmp_path,
            timeout=300,
            max_workers=4,
        )
        orchestrator = ScanOrchestrator(config)

        targets = ScanTargets(
            repos=[Path("/repo1"), Path("/repo2")],
            images=["nginx:latest"],
        )

        summary = orchestrator.get_summary(targets)

        assert summary["config"]["tools"] == ["trufflehog", "semgrep"]
        assert summary["config"]["timeout"] == 300
        assert summary["config"]["max_workers"] == 4
        assert summary["targets"]["total_count"] == 3
        assert summary["validation"]["has_targets"] is True

    def test_discover_targets_integration(self, tmp_path):
        """Test full target discovery integration"""
        config = ScanConfig(
            tools=["trufflehog", "semgrep"],
            results_dir=tmp_path,
        )
        orchestrator = ScanOrchestrator(config)

        # Create test repos
        (tmp_path / "repos" / "repo1").mkdir(parents=True)
        (tmp_path / "repos" / "repo2").mkdir(parents=True)

        # Mock args with multiple target types
        args = MagicMock()
        args.repo = None
        args.repos_dir = str(tmp_path / "repos")
        args.targets = None
        args.image = "nginx:latest"
        args.images_file = None
        args.terraform_state = None
        args.cloudformation = None
        args.k8s_manifest = None
        args.url = "https://example.com"
        args.urls_file = None
        args.gitlab_repo = None
        args.gitlab_group = None
        args.k8s_context = None

        targets = orchestrator.discover_targets(args)

        assert len(targets.repos) == 2
        assert len(targets.images) == 1
        assert len(targets.urls) == 1
        assert targets.total_count() == 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
