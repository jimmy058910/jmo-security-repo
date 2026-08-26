"""
Unit tests for scripts/cli/scan_orchestrator.py

Tests the ScanOrchestrator class extracted from cmd_scan() as part of PHASE 1 refactoring.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.scan_orchestrator import (
    ScanConfig,
    ScanOrchestrator,
    ScanTargets,
    _detect_msys_path_mangling,
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

    def test_to_dict_conversion(self, tmp_path):
        """Test converting targets to dictionary"""
        repo1 = tmp_path / "repo1"
        iac_file = tmp_path / "main.tf"

        targets = ScanTargets(
            repos=[repo1],
            images=["nginx:latest"],
            iac_files=[("terraform", iac_file)],
        )

        data = targets.to_dict()

        assert data["repos"] == [str(repo1)]
        assert data["images"] == ["nginx:latest"]
        assert data["iac_files"] == [("terraform", str(iac_file))]
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

    def test_discover_repos_single_repo(self, tmp_path):
        """Test discovering a single repository"""
        test_repo = tmp_path / "test-repo"
        test_repo.mkdir()

        config = ScanConfig(
            tools=["trufflehog"],
            results_dir=tmp_path / "results",
        )
        orchestrator = ScanOrchestrator(config)

        # Mock args with single repo
        args = MagicMock()
        args.repo = str(test_repo)
        args.repos_dir = None
        args.targets = None

        repos = orchestrator._discover_repos(args)
        # Single repo should be the configured repo
        assert len(repos) == 1
        assert repos[0] == test_repo

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
        args.api_spec = None

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
        args.api_spec = None
        args.gitlab_repo = None
        args.gitlab_group = None
        args.k8s_context = None

        targets = orchestrator.discover_targets(args)

        assert len(targets.repos) == 2
        assert len(targets.images) == 1
        assert len(targets.urls) == 1
        assert targets.total_count() == 4


class TestMsysPathDetection:
    """Test MSYS path mangling detection for Docker on Windows Git Bash."""

    def test_detects_program_files_git_path(self):
        """Should detect paths containing 'Program Files/Git' (MSYS telltale sign)."""
        # Standard Git for Windows installation path
        assert (
            _detect_msys_path_mangling("C:/Program Files/Git/scan/juice-shop") is True
        )
        assert (
            _detect_msys_path_mangling("C:\\Program Files\\Git\\scan\\juice-shop")
            is True
        )
        # Different drive letter
        assert _detect_msys_path_mangling("D:/Program Files/Git/usr/bin") is True

    def test_detects_windows_path_in_docker(self, monkeypatch):
        """Should detect Windows drive paths when DOCKER_CONTAINER=1."""
        monkeypatch.setenv("DOCKER_CONTAINER", "1")

        # Any Windows path inside Docker container is likely MSYS-mangled
        assert _detect_msys_path_mangling("C:/Users/test/project") is True
        assert _detect_msys_path_mangling("D:\\Projects\\myrepo") is True

    def test_ignores_windows_path_outside_docker(self, monkeypatch):
        """Should NOT flag Windows paths when NOT in Docker (native Windows use)."""
        monkeypatch.delenv("DOCKER_CONTAINER", raising=False)

        # Normal Windows paths outside Docker are valid
        assert _detect_msys_path_mangling("C:/Users/test/project") is False
        assert _detect_msys_path_mangling("D:\\Projects\\myrepo") is False

    def test_ignores_normal_unix_paths(self):
        """Should NOT flag normal Unix paths."""
        assert _detect_msys_path_mangling("/scan/juice-shop") is False
        assert _detect_msys_path_mangling("/home/user/project") is False
        assert _detect_msys_path_mangling("./relative/path") is False

    def test_handles_empty_and_none(self):
        """Should handle empty and None paths gracefully."""
        assert _detect_msys_path_mangling("") is False
        assert _detect_msys_path_mangling(None) is False


class TestWarnMsysPathMangling:
    """Test MSYS path mangling warning output."""

    def test_warn_msys_path_mangling_output(self, capsys):
        """Test that warning function outputs correct message."""
        from scripts.cli.scan_orchestrator import _warn_msys_path_mangling

        _warn_msys_path_mangling("C:/Program Files/Git/scan/myrepo")

        captured = capsys.readouterr()
        # Warning goes to stderr
        assert "MSYS PATH CONVERSION DETECTED" in captured.err
        assert "MSYS_NO_PATHCONV=1" in captured.err
        assert "Git Bash" in captured.err

    def test_warn_truncates_long_paths(self, capsys):
        """Test that very long paths are truncated in warning."""
        from scripts.cli.scan_orchestrator import _warn_msys_path_mangling

        long_path = "C:/Program Files/Git/" + "a" * 100
        _warn_msys_path_mangling(long_path)

        captured = capsys.readouterr()
        # Path should be truncated to 50 chars
        assert "..." in captured.err


class TestDiscoverUrlsFromFile:
    """Test URL discovery from file."""

    def test_urls_from_file(self, tmp_path):
        """Test reading URLs from a file."""
        urls_file_path = tmp_path / "urls.txt"
        urls_file_path.write_text("https://example.com\nhttps://test.com\n")

        config = ScanConfig(results_dir=tmp_path, tools=["trivy"])
        orchestrator = ScanOrchestrator(config)

        args = MagicMock()
        args.url = None
        args.urls_file = str(urls_file_path)
        args.api_spec = None

        urls = orchestrator._discover_urls(args)
        assert len(urls) == 2
        assert "https://example.com" in urls
        assert "https://test.com" in urls

    def test_urls_file_with_comments(self, tmp_path):
        """Test that comment lines are skipped."""
        urls_file_path = tmp_path / "urls.txt"
        urls_file_path.write_text(
            "# This is a comment\nhttps://example.com\n# Another comment\n"
        )

        config = ScanConfig(results_dir=tmp_path, tools=["trivy"])
        orchestrator = ScanOrchestrator(config)

        args = MagicMock()
        args.url = None
        args.urls_file = str(urls_file_path)
        args.api_spec = None

        urls = orchestrator._discover_urls(args)
        assert len(urls) == 1
        assert "https://example.com" in urls

    def test_urls_file_with_empty_lines(self, tmp_path):
        """Test that empty lines are skipped."""
        urls_file_path = tmp_path / "urls.txt"
        urls_file_path.write_text("\n\nhttps://example.com\n\n")

        config = ScanConfig(results_dir=tmp_path, tools=["trivy"])
        orchestrator = ScanOrchestrator(config)

        args = MagicMock()
        args.url = None
        args.urls_file = str(urls_file_path)
        args.api_spec = None

        urls = orchestrator._discover_urls(args)
        assert len(urls) == 1

    def test_urls_file_with_invalid_urls(self, tmp_path, caplog):
        """Test that invalid URLs are skipped with warning."""
        import logging

        urls_file_path = tmp_path / "urls.txt"
        urls_file_path.write_text("https://example.com\nnot-a-valid-url\n")

        config = ScanConfig(results_dir=tmp_path, tools=["trivy"])
        orchestrator = ScanOrchestrator(config)

        args = MagicMock()
        args.url = None
        args.urls_file = str(urls_file_path)
        args.api_spec = None

        with caplog.at_level(logging.WARNING):
            urls = orchestrator._discover_urls(args)

        # Only valid URL should be returned
        assert len(urls) == 1
        assert "https://example.com" in urls


class TestGetEffectiveMaxWorkers:
    """Test max workers calculation."""

    def test_config_max_workers_takes_precedence(self, tmp_path):
        """Test that config max_workers is used when set."""
        config = ScanConfig(results_dir=tmp_path, tools=["trivy"], max_workers=8)
        orchestrator = ScanOrchestrator(config)

        assert orchestrator.get_effective_max_workers() == 8

    def test_env_var_used_when_no_config(self, tmp_path, monkeypatch):
        """Test JMO_THREADS environment variable."""
        monkeypatch.setenv("JMO_THREADS", "6")

        config = ScanConfig(results_dir=tmp_path, tools=["trivy"], max_workers=None)
        orchestrator = ScanOrchestrator(config)

        assert orchestrator.get_effective_max_workers() == 6

    def test_env_var_invalid_uses_default(self, tmp_path, monkeypatch):
        """Test invalid JMO_THREADS falls back to default."""
        monkeypatch.setenv("JMO_THREADS", "invalid")

        config = ScanConfig(results_dir=tmp_path, tools=["trivy"], max_workers=None)
        orchestrator = ScanOrchestrator(config)

        # Should fall back to default 4
        assert orchestrator.get_effective_max_workers() == 4

    def test_env_var_zero_becomes_one(self, tmp_path, monkeypatch):
        """Test that JMO_THREADS=0 becomes 1 (min)."""
        monkeypatch.setenv("JMO_THREADS", "0")

        config = ScanConfig(results_dir=tmp_path, tools=["trivy"], max_workers=None)
        orchestrator = ScanOrchestrator(config)

        # Should be at least 1
        assert orchestrator.get_effective_max_workers() >= 1

    def test_default_when_no_config_or_env(self, tmp_path, monkeypatch):
        """Test default value when nothing is set."""
        monkeypatch.delenv("JMO_THREADS", raising=False)

        config = ScanConfig(results_dir=tmp_path, tools=["trivy"], max_workers=None)
        orchestrator = ScanOrchestrator(config)

        # Default is 4
        assert orchestrator.get_effective_max_workers() == 4


class TestScanAll:
    """Test scan_all method for parallel scanning of multiple targets."""

    def test_scan_repos_parallel(self, tmp_path):
        """Test scanning multiple repos in parallel."""
        config = ScanConfig(results_dir=tmp_path, tools=["trivy"])
        orchestrator = ScanOrchestrator(config)

        repo1 = tmp_path / "repo1"
        repo1.mkdir()
        repo2 = tmp_path / "repo2"
        repo2.mkdir()

        targets = ScanTargets(repos=[repo1, repo2])

        # Mock the scan_repository function from scan_jobs module
        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("repo1", {"trivy": {"status": "success"}})

            results = orchestrator.scan_all(targets, {})

        assert len(results) == 2

    def test_scan_images_parallel(self, tmp_path):
        """Test scanning multiple images in parallel."""
        config = ScanConfig(results_dir=tmp_path, tools=["trivy"])
        orchestrator = ScanOrchestrator(config)

        targets = ScanTargets(images=["nginx:latest", "redis:alpine"])

        with patch("scripts.cli.scan_jobs.scan_image") as mock_scan:
            mock_scan.return_value = ("nginx:latest", {"trivy": {"status": "success"}})

            results = orchestrator.scan_all(targets, {})

        assert len(results) == 2

    def test_scan_iac_parallel(self, tmp_path):
        """Test scanning IaC files in parallel."""
        config = ScanConfig(results_dir=tmp_path, tools=["checkov"])
        orchestrator = ScanOrchestrator(config)

        iac_file = tmp_path / "main.tf"
        iac_file.write_text("# terraform")

        targets = ScanTargets(iac_files=[("terraform", iac_file)])

        with patch("scripts.cli.scan_jobs.scan_iac_file") as mock_scan:
            mock_scan.return_value = ("main.tf", {"checkov": {"status": "success"}})

            results = orchestrator.scan_all(targets, {})

        assert len(results) == 1

    def test_scan_urls_parallel(self, tmp_path):
        """Test scanning URLs in parallel."""
        config = ScanConfig(results_dir=tmp_path, tools=["nikto"])
        orchestrator = ScanOrchestrator(config)

        targets = ScanTargets(urls=["https://example.com", "https://test.com"])

        with patch("scripts.cli.scan_jobs.scan_url") as mock_scan:
            mock_scan.return_value = ("example.com", {"nikto": {"status": "success"}})

            results = orchestrator.scan_all(targets, {})

        assert len(results) == 2

    def test_scan_gitlab_repos_parallel(self, tmp_path):
        """Test scanning GitLab repos in parallel."""
        config = ScanConfig(results_dir=tmp_path, tools=["gitleaks"])
        orchestrator = ScanOrchestrator(config)

        targets = ScanTargets(gitlab_repos=[{"group": "org", "name": "repo1"}])

        with patch("scripts.cli.scan_jobs.scan_gitlab_repo") as mock_scan:
            mock_scan.return_value = ("org_repo1", {"gitleaks": {"status": "success"}})

            results = orchestrator.scan_all(targets, {})

        assert len(results) == 1

    def test_scan_k8s_resources_parallel(self, tmp_path):
        """Test scanning K8s resources in parallel."""
        config = ScanConfig(results_dir=tmp_path, tools=["kubescape"])
        orchestrator = ScanOrchestrator(config)

        targets = ScanTargets(
            k8s_resources=[{"context": "prod", "namespace": "default"}]
        )

        with patch("scripts.cli.scan_jobs.scan_k8s_resource") as mock_scan:
            mock_scan.return_value = (
                "prod_default",
                {"kubescape": {"status": "success"}},
            )

            results = orchestrator.scan_all(targets, {})

        assert len(results) == 1

    def test_scan_handles_exception(self, tmp_path):
        """Test that exceptions from one target don't stop others."""
        config = ScanConfig(results_dir=tmp_path, tools=["trivy"])
        orchestrator = ScanOrchestrator(config)

        targets = ScanTargets(images=["nginx:latest", "redis:alpine"])

        with patch("scripts.cli.scan_jobs.scan_image") as mock_scan:
            # First call succeeds, second throws exception
            mock_scan.side_effect = [
                ("nginx:latest", {"trivy": {"status": "success"}}),
                Exception("Scan failed"),
            ]

            results = orchestrator.scan_all(targets, {})

        # Both should have results (second will be partial)
        assert len(results) == 2

    def test_scan_with_progress_callback(self, tmp_path):
        """Test progress callback is called."""
        config = ScanConfig(results_dir=tmp_path, tools=["trivy"])
        orchestrator = ScanOrchestrator(config)

        repo = tmp_path / "repo"
        repo.mkdir()
        targets = ScanTargets(repos=[repo])

        progress_calls = []

        def progress_callback(target_type, target_id, statuses, elapsed=0.0):
            progress_calls.append((target_type, target_id, statuses, elapsed))

        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("repo", {"trivy": True})

            orchestrator.scan_all(targets, {}, progress_callback=progress_callback)

        assert len(progress_calls) == 1
        assert progress_calls[0][0] == "repo"
        # The status map has to arrive, because it is the only thing that can
        # distinguish a target that produced findings from one that produced
        # nothing. The callback was already being handed it and the two
        # implementations both declared the parameter `elapsed: float` (#809).
        assert progress_calls[0][2] == {"trivy": True}
        # And the duration has to be measured, not invented.
        assert isinstance(progress_calls[0][3], float)
        assert progress_calls[0][3] >= 0.0


class TestInvalidUrlWarning:
    """Test warning for invalid URLs in direct url argument."""

    def test_invalid_url_logs_warning(self, tmp_path, caplog):
        """Test that invalid URL argument logs warning."""
        import logging

        config = ScanConfig(results_dir=tmp_path, tools=["trivy"])
        orchestrator = ScanOrchestrator(config)

        class Args:
            url = "not-a-valid-url"  # Single invalid URL
            urls_file = None
            api_spec = None

        with caplog.at_level(logging.WARNING):
            urls = orchestrator._discover_urls(Args())

        # No URLs should be returned
        assert len(urls) == 0
        # Warning should be logged
        assert "invalid url" in caplog.text.lower()

    def test_valid_url_no_warning(self, tmp_path, caplog):
        """Test that valid URL doesn't log warning."""
        import logging

        config = ScanConfig(results_dir=tmp_path, tools=["trivy"])
        orchestrator = ScanOrchestrator(config)

        class Args:
            url = "https://example.com"  # Valid URL
            urls_file = None
            api_spec = None

        with caplog.at_level(logging.WARNING):
            urls = orchestrator._discover_urls(Args())

        # URL should be returned
        assert len(urls) == 1
        assert "https://example.com" in urls


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestUnroutedToolsAreReported:
    """A requested tool that matches no target type in this scan must say so.

    `filter_tools_for_scan_type` is a bare list comprehension: it drops tools
    and returns, telling nobody. On a `deep` scan of a repository that silently
    removed `nuclei` (URL-only) and `lynis` (absent from TOOL_SCAN_TYPES["repo"]
    despite having a repository implementation), and neither appeared in any
    stream or artifact for the whole run - not in the scanner's `unresolved`,
    `not_implemented` or `idle` diagnostics, not in the progress display, and
    not in `.scan_metadata.json`.

    Being filtered is usually correct - nuclei genuinely cannot scan a
    repository - but "correctly skipped" and "silently vanished" have to look
    different to whoever reads the output, or every skip reads as a scan.
    """

    def _orchestrator(self, tmp_path, tools):
        cfg = ScanConfig(
            tools=tools,
            results_dir=tmp_path / "results",
            timeout=60,
            retries=0,
        )
        return ScanOrchestrator(cfg)

    def test_url_only_tool_on_a_repo_scan_is_reported(self, tmp_path, caplog):
        import logging

        repo = tmp_path / "proj"
        repo.mkdir()

        targets = ScanTargets()
        targets.repos = [repo]

        orch = self._orchestrator(tmp_path, ["trufflehog", "nuclei", "lynis"])

        with (
            patch("scripts.cli.scan_jobs.scan_repository", return_value=("proj", {})),
            caplog.at_level(logging.DEBUG),
        ):
            orch.scan_all(targets, per_tool_config={})

        assert (
            "nuclei" in caplog.text
        ), f"nuclei was dropped from a repo scan without a word:\n{caplog.text}"
        assert (
            "lynis" in caplog.text
        ), f"lynis was dropped from a repo scan without a word:\n{caplog.text}"

    def test_routed_tool_is_not_reported_as_unrouted(self, tmp_path, caplog):
        """trufflehog does apply to repositories; it must not be named."""
        import logging

        repo = tmp_path / "proj"
        repo.mkdir()

        targets = ScanTargets()
        targets.repos = [repo]

        orch = self._orchestrator(tmp_path, ["trufflehog"])

        with (
            patch("scripts.cli.scan_jobs.scan_repository", return_value=("proj", {})),
            caplog.at_level(logging.DEBUG),
        ):
            orch.scan_all(targets, per_tool_config={})

        assert "no target type in this scan" not in caplog.text


class TestRejectedTargetsAreNamed:
    """Discovery must say which target it refused, and why.

    Eight degenerate inputs used to produce one identical message - "No scan
    targets provided" - at exit code 0, so a typo'd path, a missing targets
    file and an empty directory were indistinguishable from asking for nothing
    (#805, #806). `--image` and `--url` already warned; the six path-based
    flags dropped silently.
    """

    @staticmethod
    def _args(**kw):
        from types import SimpleNamespace

        base = {
            "repo": None,
            "repos_dir": None,
            "targets": None,
            "image": None,
            "images_file": None,
            "terraform_state": None,
            "cloudformation": None,
            "k8s_manifest": None,
            "url": None,
            "urls_file": None,
            "api_spec": None,
            "gitlab_url": None,
            "gitlab_repo": None,
            "gitlab_group": None,
            "k8s_context": None,
            "k8s_namespace": None,
            "k8s_all_namespaces": False,
        }
        base.update(kw)
        return SimpleNamespace(**base)

    @staticmethod
    def _orchestrator(tmp_path):
        return ScanOrchestrator(
            ScanConfig(tools=["trufflehog"], results_dir=tmp_path / "results")
        )

    @pytest.mark.parametrize(
        "flag,value_factory,fragment",
        [
            ("repo", lambda t: str(t / "nope"), "--repo"),
            ("repos_dir", lambda t: str(t / "nope_dir"), "--repos-dir"),
            ("targets", lambda t: str(t / "nope.txt"), "--targets"),
            ("terraform_state", lambda t: str(t / "nope.tfstate"), "--terraform-state"),
            ("cloudformation", lambda t: str(t / "nope.yaml"), "--cloudformation"),
            ("k8s_manifest", lambda t: str(t / "nope.yaml"), "--k8s-manifest"),
        ],
    )
    def test_missing_path_is_named_not_dropped(
        self, tmp_path, flag, value_factory, fragment
    ):
        orch = self._orchestrator(tmp_path)
        targets = orch.discover_targets(self._args(**{flag: value_factory(tmp_path)}))

        assert targets.is_empty()
        assert targets.rejected, f"{fragment} was dropped without a reason"
        assert any(fragment in r for r in targets.rejected)

    def test_empty_repos_dir_is_distinguished_from_a_missing_one(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()

        orch = self._orchestrator(tmp_path)
        targets = orch.discover_targets(self._args(repos_dir=str(empty)))

        assert targets.is_empty()
        assert any("no subdirectories" in r for r in targets.rejected)

    def test_targets_file_names_each_missing_line(self, tmp_path):
        listing = tmp_path / "targets.txt"
        listing.write_text("# a comment\n/definitely/not/here\n\n", encoding="utf-8")

        orch = self._orchestrator(tmp_path)
        targets = orch.discover_targets(self._args(targets=str(listing)))

        assert targets.is_empty()
        assert any("/definitely/not/here" in r for r in targets.rejected)

    def test_invalid_image_and_url_also_count_as_rejections(self, tmp_path):
        """These already logged a warning but nothing acted on it."""
        orch = self._orchestrator(tmp_path)

        image_targets = orch.discover_targets(self._args(image="not a valid image!!"))
        assert image_targets.rejected

        url_targets = orch.discover_targets(self._args(url="ftp://evil.example"))
        assert url_targets.rejected

    def test_no_target_flag_at_all_records_no_rejection(self, tmp_path):
        """Asking for nothing is a different mistake from asking for something
        that does not exist, and must stay distinguishable."""
        orch = self._orchestrator(tmp_path)
        targets = orch.discover_targets(self._args())

        assert targets.is_empty()
        assert targets.rejected == []

    def test_rejections_do_not_leak_between_calls(self, tmp_path):
        orch = self._orchestrator(tmp_path)
        orch.discover_targets(self._args(repo=str(tmp_path / "nope")))
        second = orch.discover_targets(self._args())

        assert second.rejected == []


class TestApiSpecIsDiscovered:
    """`--api-spec` is advertised in `jmo scan --help` and was a no-op (#807).

    The only code that handled it was jmo.py's _iter_urls, which nothing has
    called since discovery moved to ScanOrchestrator.
    """

    @staticmethod
    def _args(**kw):
        return TestRejectedTargetsAreNamed._args(**kw)

    @staticmethod
    def _orchestrator(tmp_path):
        return ScanOrchestrator(
            ScanConfig(tools=["zap"], results_dir=tmp_path / "results")
        )

    def test_remote_spec_becomes_a_url_target(self, tmp_path):
        orch = self._orchestrator(tmp_path)
        targets = orch.discover_targets(
            self._args(api_spec="https://example.com/openapi.json")
        )

        assert targets.urls == ["https://example.com/openapi.json"]
        assert not targets.is_empty()

    def test_local_spec_becomes_a_file_url(self, tmp_path):
        spec = tmp_path / "openapi.json"
        spec.write_text('{"openapi": "3.0.0"}', encoding="utf-8")

        orch = self._orchestrator(tmp_path)
        targets = orch.discover_targets(self._args(api_spec=str(spec)))

        assert len(targets.urls) == 1
        assert targets.urls[0].startswith("file://")

    def test_missing_local_spec_is_rejected_rather_than_ignored(self, tmp_path):
        orch = self._orchestrator(tmp_path)
        targets = orch.discover_targets(
            self._args(api_spec=str(tmp_path / "gone.json"))
        )

        assert targets.is_empty()
        assert any("--api-spec" in r for r in targets.rejected)
