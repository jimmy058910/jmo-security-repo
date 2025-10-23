"""
Tests for GitLab Scanner

Tests the gitlab_scanner module with various scenarios.
Updated to mock scan_repository() and subprocess.run() instead of ToolRunner.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.gitlab_scanner import scan_gitlab_repo


class TestGitlabScanner:
    """Test GitLab scanner functionality"""

    def test_scan_gitlab_basic(self, tmp_path):
        """Test basic GitLab repo scanning with trufflehog"""
        # Mock subprocess.run for git clone
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            # Mock scan_repository function
            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo:
                # Mock successful clone
                mock_subprocess.return_value = MagicMock(returncode=0)

                # Mock scan_repository return value: (repo_name, statuses_dict)
                mock_scan_repo.return_value = ("myrepo", {"trufflehog": True})

                gitlab_info = {
                    "full_path": "mygroup/myrepo",
                    "url": "https://gitlab.com",
                    "token": "glpat-abc123",
                    "repo": "myrepo",
                    "group": "mygroup",
                }

                full_path, statuses = scan_gitlab_repo(
                    gitlab_info=gitlab_info,
                    results_dir=tmp_path,
                    tools=["trufflehog"],
                    timeout=600,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=False,
                )

                assert full_path == "mygroup/myrepo"
                assert statuses["trufflehog"] is True

                # Verify scan_repository was called
                assert mock_scan_repo.called

    def test_scan_gitlab_group_scan(self, tmp_path):
        """Test GitLab group scan (wildcard repo)"""
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo:
                mock_subprocess.return_value = MagicMock(returncode=0)
                mock_scan_repo.return_value = ("repo", {"trufflehog": True})

                gitlab_info = {
                    "full_path": "engineering/*",
                    "url": "https://gitlab.com",
                    "token": "glpat-xyz789",
                    "repo": "*",
                    "group": "engineering",
                }

                full_path, statuses = scan_gitlab_repo(
                    gitlab_info=gitlab_info,
                    results_dir=tmp_path,
                    tools=["trufflehog"],
                    timeout=600,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=False,
                )

                assert "engineering" in full_path
                assert statuses["trufflehog"] is True

    def test_scan_gitlab_sanitizes_path(self, tmp_path):
        """Test that GitLab paths are sanitized for directory names"""
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo:
                mock_subprocess.return_value = MagicMock(returncode=0)
                mock_scan_repo.return_value = ("project", {"trufflehog": True})

                gitlab_info = {
                    "full_path": "my-group/sub-group/project",
                    "url": "https://gitlab.example.com",
                    "token": "glpat-test",
                    "repo": "project",
                    "group": "my-group/sub-group",
                }

                full_path, statuses = scan_gitlab_repo(
                    gitlab_info=gitlab_info,
                    results_dir=tmp_path,
                    tools=["trufflehog"],
                    timeout=600,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=False,
                )

                assert full_path == "my-group/sub-group/project"
                assert statuses["trufflehog"] is True

    def test_scan_gitlab_with_timeout_override(self, tmp_path):
        """Test per-tool timeout overrides"""
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo:
                mock_subprocess.return_value = MagicMock(returncode=0)
                mock_scan_repo.return_value = ("repo", {"trufflehog": True})

                per_tool_config = {
                    "trufflehog": {"timeout": 900, "flags": ["--concurrency", "4"]}
                }

                gitlab_info = {
                    "full_path": "org/repo",
                    "url": "https://gitlab.com",
                    "token": "glpat-123",
                    "repo": "repo",
                    "group": "org",
                }

                full_path, statuses = scan_gitlab_repo(
                    gitlab_info=gitlab_info,
                    results_dir=tmp_path,
                    tools=["trufflehog"],
                    timeout=600,
                    retries=0,
                    per_tool_config=per_tool_config,
                    allow_missing_tools=False,
                )

                assert full_path == "org/repo"
                assert statuses["trufflehog"] is True

                # Verify scan_repository was called with per_tool_config
                mock_scan_repo.assert_called_once()
                call_kwargs = mock_scan_repo.call_args.kwargs
                assert call_kwargs["per_tool_config"] == per_tool_config

    def test_scan_gitlab_tool_failure(self, tmp_path):
        """Test handling of tool failures"""
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo:
                mock_subprocess.return_value = MagicMock(returncode=0)
                # Mock tool failure
                mock_scan_repo.return_value = ("test", {"trufflehog": False})

                gitlab_info = {
                    "full_path": "fail/test",
                    "url": "https://gitlab.com",
                    "token": "glpat-fail",
                    "repo": "test",
                    "group": "fail",
                }

                full_path, statuses = scan_gitlab_repo(
                    gitlab_info=gitlab_info,
                    results_dir=tmp_path,
                    tools=["trufflehog"],
                    timeout=600,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=False,
                )

                assert statuses["trufflehog"] is False

    def test_scan_gitlab_with_retries(self, tmp_path):
        """Test GitLab scanning with retries"""
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo:
                mock_subprocess.return_value = MagicMock(returncode=0)
                # Mock retry scenario (tool succeeded on retry)
                mock_scan_repo.return_value = (
                    "test",
                    {"trufflehog": True, "__attempts__": {"trufflehog": 3}},
                )

                gitlab_info = {
                    "full_path": "retry/test",
                    "url": "https://gitlab.com",
                    "token": "glpat-retry",
                    "repo": "test",
                    "group": "retry",
                }

                full_path, statuses = scan_gitlab_repo(
                    gitlab_info=gitlab_info,
                    results_dir=tmp_path,
                    tools=["trufflehog"],
                    timeout=600,
                    retries=2,
                    per_tool_config={},
                    allow_missing_tools=False,
                )

                assert statuses["trufflehog"] is True
                assert "__attempts__" in statuses
                assert statuses["__attempts__"]["trufflehog"] == 3

                # Verify retries parameter was passed
                call_kwargs = mock_scan_repo.call_args.kwargs
                assert call_kwargs["retries"] == 2

    def test_scan_gitlab_creates_output_directory(self, tmp_path):
        """Test that output directories are created"""
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo:
                mock_subprocess.return_value = MagicMock(returncode=0)
                mock_scan_repo.return_value = ("scanner", {"trufflehog": True})

                gitlab_info = {
                    "full_path": "security/scanner",
                    "url": "https://gitlab.com",
                    "token": "glpat-test",
                    "repo": "scanner",
                    "group": "security",
                }

                full_path, statuses = scan_gitlab_repo(
                    gitlab_info=gitlab_info,
                    results_dir=tmp_path,
                    tools=["trufflehog"],
                    timeout=600,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=False,
                )

                assert full_path == "security/scanner"
                assert statuses["trufflehog"] is True

                # Verify scan_repository was called (directory creation happens inside)
                assert mock_scan_repo.called

    def test_scan_gitlab_clone_failure(self, tmp_path):
        """Test GitLab scan when git clone fails"""
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            # Mock failed clone
            mock_subprocess.return_value = MagicMock(returncode=1)

            gitlab_info = {
                "full_path": "fail/clone",
                "url": "https://gitlab.com",
                "token": "glpat-fail",
                "repo": "clone",
                "group": "fail",
            }

            full_path, statuses = scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog", "semgrep"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Should return failure for all tools
            assert full_path == "fail/clone"
            assert statuses["trufflehog"] is False
            assert statuses["semgrep"] is False

    def test_scan_gitlab_no_token(self, tmp_path):
        """Test GitLab scan when token is missing"""
        gitlab_info = {
            "full_path": "notoken/repo",
            "url": "https://gitlab.com",
            # No token provided
            "repo": "repo",
            "group": "notoken",
        }

        full_path, statuses = scan_gitlab_repo(
            gitlab_info=gitlab_info,
            results_dir=tmp_path,
            tools=["trufflehog"],
            timeout=600,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
        )

        # Should return failure for all tools
        assert full_path == "notoken/repo"
        assert statuses["trufflehog"] is False

    def test_discover_container_images_dockerfile(self, tmp_path):
        """Test discovering images from Dockerfiles"""
        from scripts.cli.scan_jobs.gitlab_scanner import _discover_container_images

        repo = tmp_path / "repo"
        repo.mkdir()

        # Create Dockerfile with FROM line
        dockerfile = repo / "Dockerfile"
        dockerfile.write_text(
            """
FROM nginx:latest
RUN apt-get update
FROM python:3.11-slim AS builder
COPY . /app
FROM postgres:14
FROM scratch
        """,
            encoding="utf-8",
        )

        images = _discover_container_images(repo)

        # Should find nginx:latest and postgres:14, but NOT scratch or "AS builder" stage
        assert "nginx:latest" in images
        assert "postgres:14" in images
        assert "scratch" not in images  # Excluded
        # python:3.11-slim NOT included because it has "AS builder"
        assert len(images) == 2

    def test_discover_container_images_docker_compose(self, tmp_path):
        """Test discovering images from docker-compose.yml"""
        from scripts.cli.scan_jobs.gitlab_scanner import _discover_container_images

        repo = tmp_path / "repo"
        repo.mkdir()

        # Create docker-compose.yml
        compose_file = repo / "docker-compose.yml"
        compose_file.write_text(
            """
version: '3.8'
services:
  web:
    image: nginx:alpine
  db:
    image: postgres:14
  app:
    build: .
        """,
            encoding="utf-8",
        )

        images = _discover_container_images(repo)

        assert "nginx:alpine" in images
        assert "postgres:14" in images
        assert len(images) == 2

    def test_discover_container_images_k8s_manifest(self, tmp_path):
        """Test discovering images from Kubernetes manifests"""
        from scripts.cli.scan_jobs.gitlab_scanner import _discover_container_images

        repo = tmp_path / "repo"
        repo.mkdir()

        # Create K8s deployment manifest
        k8s_manifest = repo / "deployment.k8s.yaml"
        k8s_manifest.write_text(
            """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  containers:
  - name: app
    image: myapp:v1.0
  - name: sidecar
    image: nginx:1.21
        """,
            encoding="utf-8",
        )

        images = _discover_container_images(repo)

        assert "myapp:v1.0" in images
        assert "nginx:1.21" in images
        assert len(images) == 2

    def test_discover_container_images_malformed_files(self, tmp_path):
        """Test that malformed files are skipped gracefully"""
        from scripts.cli.scan_jobs.gitlab_scanner import _discover_container_images

        repo = tmp_path / "repo"
        repo.mkdir()

        # Create malformed docker-compose.yml
        bad_compose = repo / "docker-compose.yml"
        bad_compose.write_text("{invalid yaml content", encoding="utf-8")

        # Create malformed K8s manifest
        bad_k8s = repo / "deploy.k8s.yaml"
        bad_k8s.write_text("not: [valid]: yaml:", encoding="utf-8")

        # Should return empty set without crashing
        images = _discover_container_images(repo)
        assert len(images) == 0

    def test_scan_gitlab_timeout_expired(self, tmp_path):
        """Test GitLab scan when git clone times out"""
        import subprocess

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            # Mock timeout exception
            mock_subprocess.side_effect = subprocess.TimeoutExpired("git", 600)

            gitlab_info = {
                "full_path": "timeout/repo",
                "url": "https://gitlab.com",
                "token": "glpat-timeout",
                "repo": "repo",
                "group": "timeout",
            }

            full_path, statuses = scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog", "semgrep"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Should return failure for all tools
            assert full_path == "timeout/repo"
            assert statuses["trufflehog"] is False
            assert statuses["semgrep"] is False

    def test_scan_gitlab_generic_exception(self, tmp_path):
        """Test GitLab scan when unexpected exception occurs"""
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            # Mock unexpected exception
            mock_subprocess.side_effect = RuntimeError("Unexpected error")

            gitlab_info = {
                "full_path": "error/repo",
                "url": "https://gitlab.com",
                "token": "glpat-error",
                "repo": "repo",
                "group": "error",
            }

            full_path, statuses = scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Should return failure for all tools
            assert full_path == "error/repo"
            assert statuses["trufflehog"] is False

    def test_scan_gitlab_with_image_discovery(self, tmp_path):
        """Test GitLab scan with container image discovery and scanning"""
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo:
                with patch(
                    "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
                ) as mock_discover:
                    with patch(
                        "scripts.cli.scan_jobs.gitlab_scanner.scan_image"
                    ) as mock_scan_image:
                        mock_subprocess.return_value = MagicMock(returncode=0)
                        mock_scan_repo.return_value = (
                            "repo",
                            {"trivy": True, "syft": True},
                        )
                        mock_discover.return_value = {"nginx:latest", "python:3.11"}
                        mock_scan_image.return_value = (
                            "nginx:latest",
                            {"trivy": True, "syft": True},
                        )

                        gitlab_info = {
                            "full_path": "devops/app",
                            "url": "https://gitlab.com",
                            "token": "glpat-test",
                            "repo": "app",
                            "group": "devops",
                        }

                        full_path, statuses = scan_gitlab_repo(
                            gitlab_info=gitlab_info,
                            results_dir=tmp_path,
                            tools=["trivy", "syft"],
                            timeout=600,
                            retries=0,
                            per_tool_config={},
                            allow_missing_tools=False,
                        )

                        assert full_path == "devops/app"
                        assert statuses["trivy"] is True
                        assert statuses["syft"] is True

                        # Verify image discovery was called
                        assert mock_discover.called

                        # Verify scan_image was called for discovered images
                        assert mock_scan_image.call_count == 2  # Two images discovered

    def test_scan_gitlab_url_formats(self, tmp_path):
        """Test handling of different GitLab URL formats"""
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo:
                mock_subprocess.return_value = MagicMock(returncode=0)
                mock_scan_repo.return_value = ("repo", {"trufflehog": True})

                # Test http:// URL
                gitlab_info = {
                    "full_path": "test/repo",
                    "url": "http://gitlab.internal",
                    "token": "glpat-test",
                    "repo": "repo",
                    "group": "test",
                }

                full_path, statuses = scan_gitlab_repo(
                    gitlab_info=gitlab_info,
                    results_dir=tmp_path,
                    tools=["trufflehog"],
                    timeout=600,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=False,
                )

                assert full_path == "test/repo"
                assert statuses["trufflehog"] is True

                # Verify clone URL was constructed correctly (check call args)
                clone_call = mock_subprocess.call_args[0][0]
                assert any("http://oauth2:glpat-test@" in arg for arg in clone_call)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
