"""
Tests for GitLab Scanner

Tests the gitlab_scanner module with various scenarios.
Updated to mock scan_repository() and subprocess.run() instead of ToolRunner.
"""

import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.gitlab_scanner import DiscoveredImages, scan_gitlab_repo
from scripts.core.scan_timings import Reason, State, ToolRun


def _rows(**ran: bool) -> dict[str, ToolRun]:
    """What `scan_repository` returns: one row per tool. These tests mock it, and
    the GitLab job passes its rows through; they used to mock v1's booleans."""
    return {
        tool: ToolRun(tool, State.RAN)
        if ok
        else ToolRun(tool, State.FAILED, Reason.EXIT_CODE)
        for tool, ok in ran.items()
    }


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
                mock_scan_repo.return_value = ("myrepo", _rows(trufflehog=True))

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
                assert statuses["trufflehog"].state is State.RAN

                # Verify scan_repository was called
                assert mock_scan_repo.called

    def test_scan_gitlab_group_scan(self, tmp_path):
        """Test GitLab group scan (wildcard repo)"""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
        ):
            mock_subprocess.return_value = MagicMock(returncode=0)
            mock_scan_repo.return_value = ("repo", _rows(trufflehog=True))

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
            assert statuses["trufflehog"].state is State.RAN

    def test_scan_gitlab_sanitizes_path(self, tmp_path):
        """Test that GitLab paths are sanitized for directory names"""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
        ):
            mock_subprocess.return_value = MagicMock(returncode=0)
            mock_scan_repo.return_value = ("project", _rows(trufflehog=True))

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
            assert statuses["trufflehog"].state is State.RAN

    def test_scan_gitlab_with_timeout_override(self, tmp_path):
        """Test per-tool timeout overrides"""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
        ):
            mock_subprocess.return_value = MagicMock(returncode=0)
            mock_scan_repo.return_value = ("repo", _rows(trufflehog=True))

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
            assert statuses["trufflehog"].state is State.RAN

            # Verify scan_repository was called with per_tool_config
            mock_scan_repo.assert_called_once()
            call_kwargs = mock_scan_repo.call_args.kwargs
            assert call_kwargs["per_tool_config"] == per_tool_config

    def test_scan_gitlab_tool_failure(self, tmp_path):
        """Test handling of tool failures"""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
        ):
            mock_subprocess.return_value = MagicMock(returncode=0)
            # Mock tool failure
            mock_scan_repo.return_value = ("test", _rows(trufflehog=False))

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

            assert statuses["trufflehog"].state is State.FAILED

    def test_scan_gitlab_with_retries(self, tmp_path):
        """Test GitLab scanning with retries"""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
        ):
            mock_subprocess.return_value = MagicMock(returncode=0)
            # Mock retry scenario (tool succeeded on retry)
            mock_scan_repo.return_value = (
                "test",
                {
                    "trufflehog": ToolRun(
                        "trufflehog", State.RAN, attempts=3, invocations=1
                    )
                },
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

            assert statuses["trufflehog"].state is State.RAN
            assert statuses["trufflehog"].attempts == 3

            # Verify retries parameter was passed
            call_kwargs = mock_scan_repo.call_args.kwargs
            assert call_kwargs["retries"] == 2

    def test_scan_gitlab_creates_output_directory(self, tmp_path):
        """Test that output directories are created"""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
        ):
            mock_subprocess.return_value = MagicMock(returncode=0)
            mock_scan_repo.return_value = ("scanner", _rows(trufflehog=True))

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
            assert statuses["trufflehog"].state is State.RAN

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
            assert statuses["trufflehog"].label == "failed:target not scanned"
            assert statuses["semgrep"].label == "failed:target not scanned"

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
        assert statuses["trufflehog"].label == "failed:target not scanned"
        assert statuses["trufflehog"].detail == "no GitLab token"

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
            assert statuses["trufflehog"].label == "failed:target not scanned"
            assert statuses["semgrep"].label == "failed:target not scanned"

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
            assert statuses["trufflehog"].label == "failed:target not scanned"

    def test_scan_gitlab_with_image_discovery(self, tmp_path):
        """Test GitLab scan with container image discovery and scanning"""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover,
            patch("scripts.cli.scan_jobs.gitlab_scanner.scan_image") as mock_scan_image,
        ):
            mock_subprocess.return_value = MagicMock(returncode=0)
            mock_scan_repo.return_value = (
                "repo",
                _rows(trivy=True, syft=True),
            )
            mock_discover.return_value = {"nginx:latest", "python:3.11"}
            mock_scan_image.return_value = (
                "nginx:latest",
                _rows(trivy=True, syft=True),
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
                images=DiscoveredImages(tmp_path / "individual-images"),
            )

            assert full_path == "devops/app"
            assert statuses["trivy"].state is State.RAN
            assert statuses["syft"].state is State.RAN

            # Verify image discovery was called
            assert mock_discover.called

            # Each discovered image is scanned, into the directory the scan
            # names for images, not one inferred from `results_dir`.
            assert mock_scan_image.call_count == 2  # Two images discovered
            assert {
                c.kwargs["results_dir"] for c in mock_scan_image.call_args_list
            } == {tmp_path / "individual-images"}

    def test_without_the_scans_images_the_repository_alone_is_scanned(self, tmp_path):
        """Discovery belongs to the scan, which says where images go: a caller
        that hands the job none scans the repository and names no image."""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
                return_value=MagicMock(returncode=0),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository",
                return_value=("app", _rows(trivy=True)),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images",
                return_value={"alpine:3.19"},
            ) as mock_discover,
            patch("scripts.cli.scan_jobs.gitlab_scanner.scan_image") as mock_scan_image,
        ):
            _full_path, statuses = scan_gitlab_repo(
                gitlab_info={"full_path": "group/app", "url": "", "token": "t"},
                results_dir=tmp_path / "individual-gitlab",
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

        assert statuses == _rows(trivy=True)
        assert not mock_discover.called
        assert not mock_scan_image.called
        assert not (tmp_path / "individual-images").exists()

    def test_scan_gitlab_url_formats(self, tmp_path):
        """Test handling of different GitLab URL formats with secure credential passing"""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
        ):
            mock_subprocess.return_value = MagicMock(returncode=0)
            mock_scan_repo.return_value = ("repo", _rows(trufflehog=True))

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
            assert statuses["trufflehog"].state is State.RAN

            # Verify clone URL was constructed correctly without embedded token
            # (secure: uses GIT_ASKPASS for credentials instead)
            clone_call = mock_subprocess.call_args[0][0]
            # URL should NOT contain token (that's the old insecure pattern)
            assert not any("glpat-test" in str(arg) for arg in clone_call)
            # URL should use the base http URL format
            assert any(
                "http://gitlab.internal/test/repo.git" in arg for arg in clone_call
            )
            # GIT_ASKPASS_TOKEN should be passed via environment, not URL
            call_kwargs = mock_subprocess.call_args[1]
            assert "env" in call_kwargs
            assert call_kwargs["env"].get("GIT_ASKPASS_TOKEN") == "glpat-test"

    def test_scan_gitlab_cleanup_exception(self, tmp_path):
        """Test temp directory cleanup handles exceptions gracefully"""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover,
        ):
            with patch("shutil.rmtree") as mock_rmtree:
                mock_subprocess.return_value = MagicMock(returncode=0)
                mock_scan_repo.return_value = (
                    "myrepo",
                    _rows(trufflehog=True),
                )
                mock_discover.return_value = set()
                mock_rmtree.side_effect = OSError("Permission denied")

                gitlab_info = {
                    "full_path": "mygroup/myrepo",
                    "url": "https://gitlab.com",
                    "token": "glpat-test",
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
                assert statuses["trufflehog"].state is State.RAN

    def test_scan_gitlab_custom_find_tool_func(self, tmp_path):
        """The resolver reaches the repository scan, as it reaches each image's"""

        def mock_find_tool(tool: str) -> str | None:
            return "/usr/bin/trufflehog" if tool == "trufflehog" else None

        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover,
        ):
            mock_subprocess.return_value = MagicMock(returncode=0)
            mock_scan_repo.return_value = (
                "myrepo",
                _rows(trufflehog=True, semgrep=True),
            )
            mock_discover.return_value = set()

            gitlab_info = {
                "full_path": "mygroup/myrepo",
                "url": "https://gitlab.com",
                "token": "glpat-test",
                "repo": "myrepo",
                "group": "mygroup",
            }
            full_path, statuses = scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog", "semgrep"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                find_tool_func=mock_find_tool,
            )

            assert mock_scan_repo.call_args.kwargs["find_tool_func"] is mock_find_tool

    def test_scan_gitlab_http_url(self, tmp_path):
        """Test GitLab clone URL construction with HTTP (not HTTPS)"""
        gitlab_info = {
            "full_path": "mygroup/myrepo",
            "url": "http://gitlab.internal.com",
            "token": "glpat-test",
            "repo": "myrepo",
            "group": "mygroup",
        }

        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover,
        ):
            mock_subprocess.return_value = MagicMock(returncode=0)
            mock_scan_repo.return_value = ("myrepo", _rows(trufflehog=True))
            mock_discover.return_value = set()

            scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            clone_call = mock_subprocess.call_args[0][0]
            assert not any("glpat-test" in str(arg) for arg in clone_call)
            assert any(
                "http://gitlab.internal.com/mygroup/myrepo.git" in arg
                for arg in clone_call
            )
            call_kwargs = mock_subprocess.call_args[1]
            assert "env" in call_kwargs
            assert call_kwargs["env"].get("GIT_ASKPASS_TOKEN") == "glpat-test"

    def test_scan_gitlab_image_scan_exception(self, tmp_path):
        """Test handling of image scan exceptions"""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
            ) as mock_subprocess,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
            ) as mock_scan_repo,
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover,
            patch("scripts.cli.scan_jobs.gitlab_scanner.scan_image") as mock_scan_image,
        ):
            mock_subprocess.return_value = MagicMock(returncode=0)
            mock_scan_repo.return_value = (
                "myrepo",
                _rows(trufflehog=True),
            )
            mock_discover.return_value = {
                "nginx:latest",
                "postgres:14",
            }
            mock_scan_image.side_effect = [
                ("nginx:latest", _rows(trivy=True, syft=True)),
                RuntimeError("Image scan failed"),
            ]

            gitlab_info = {
                "full_path": "mygroup/myrepo",
                "url": "https://gitlab.com",
                "token": "glpat-test",
                "repo": "myrepo",
                "group": "mygroup",
            }
            images = DiscoveredImages(tmp_path / "individual-images")
            full_path, statuses = scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog", "trivy", "syft"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                images=images,
            )

            # The repository's rows are its own; each image has rows of its
            # own, and the one whose scan raised is failed on every tool that
            # reads an image, with the reason, rather than dropped.
            assert statuses == _rows(trufflehog=True)
            assert mock_scan_image.call_count == 2
            found = dict(images.found_in("mygroup/myrepo"))
            assert found["nginx:latest"] == _rows(trivy=True, syft=True)
            failed = found["postgres:14"]
            assert failed["trivy"].label == "failed:scanner error"
            assert failed["syft"].label == "failed:scanner error"
            assert "Image scan failed" in (failed["trivy"].detail or "")
            assert failed["trufflehog"].state is State.SKIPPED

    def test_the_images_folder_exists_before_an_image_is_scanned(self, tmp_path):
        """`individual-images` beside `individual-gitlab`, created before
        scan_image resolves it: the orchestrator creates it up front only for
        `--image` targets, and on Windows a directory another job creates
        during `resolve()` failed scan_image's traversal check."""
        seen: list[tuple[Path, bool]] = []

        def scan_image(**kwargs):
            seen.append((kwargs["results_dir"], kwargs["results_dir"].is_dir()))
            return kwargs["image"], _rows(trivy=True)

        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
                return_value=MagicMock(returncode=0),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository",
                return_value=("app", _rows(trivy=True)),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images",
                return_value={"alpine:3.19"},
            ),
            patch("scripts.cli.scan_jobs.gitlab_scanner.scan_image", scan_image),
        ):
            scan_gitlab_repo(
                gitlab_info={
                    "full_path": "group/app",
                    "url": "https://gitlab.com",
                    "token": "t",
                },
                results_dir=tmp_path / "individual-gitlab",
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                images=DiscoveredImages(tmp_path / "individual-images"),
            )

        assert seen == [(tmp_path / "individual-images", True)]

    def test_a_claimed_image_whose_folder_cannot_be_made_still_has_rows(self, tmp_path):
        """A claim keeps every other target from scanning the image, so the
        claimer must record rows whatever fails: here a file stands where the
        images folder goes. The repository's own rows are untouched."""
        (tmp_path / "individual-images").write_bytes(b"not a directory")
        images = DiscoveredImages(tmp_path / "individual-images")

        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
                return_value=MagicMock(returncode=0),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository",
                return_value=("app", _rows(trivy=True)),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images",
                return_value={"alpine:3.19"},
            ),
        ):
            _full_path, statuses = scan_gitlab_repo(
                gitlab_info={
                    "full_path": "group/app",
                    "url": "https://gitlab.com",
                    "token": "t",
                },
                results_dir=tmp_path / "individual-gitlab",
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                images=images,
            )

        assert statuses == _rows(trivy=True)
        ((image, rows),) = images.found_in("group/app")
        assert image == "alpine:3.19"
        assert rows["trivy"].label == "failed:scanner error"


class TestAFailurePastTheRepositoryScanIsTheImagesOwn:
    """Once the repository is scanned, its outputs are where the report reads
    them. A failure in discovery or the image loop used to relabel that
    completed scan `failed-before-tools`, over a folder whose outputs the
    report still read, and could leave a claimed image with no rows."""

    GITLAB_INFO = {"full_path": "group/app", "url": "https://gitlab.com", "token": "t"}

    def _scan(self, tmp_path, discover=None, unique_names=None):
        from scripts.cli.scan_jobs import gitlab_scanner

        images = DiscoveredImages(tmp_path / "individual-images")
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
                return_value=MagicMock(returncode=0),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository",
                return_value=("group_app", _rows(trivy=True)),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images",
                **(discover or {"return_value": {"alpine:3.19"}}),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_image",
                side_effect=lambda **kw: (kw["image"], _rows(trivy=True)),
            ) as mock_scan_image,
            patch.object(
                gitlab_scanner,
                "unique_names",
                unique_names or gitlab_scanner.unique_names,
            ),
        ):
            _full_path, statuses = scan_gitlab_repo(
                gitlab_info=dict(self.GITLAB_INFO),
                results_dir=tmp_path / "individual-gitlab",
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                images=images,
            )
        return statuses, images, mock_scan_image

    def test_a_discovery_failure_keeps_the_repositorys_rows(self, tmp_path):
        statuses, images, mock_scan_image = self._scan(
            tmp_path, discover={"side_effect": OSError("walk failed")}
        )

        assert statuses == _rows(trivy=True)
        assert images.found_in("group/app") == []
        assert not mock_scan_image.called
        timings = tmp_path / "individual-gitlab" / "group_app" / "scan-timings.json"
        assert not timings.exists(), "the completed scan was relabelled abandoned"

    def test_a_failure_after_the_claim_gives_the_image_failed_rows(self, tmp_path):
        """Claimed, so no other target will scan it: it must have rows."""

        def boom(*args, **kwargs):
            raise RuntimeError("folders failed")

        statuses, images, mock_scan_image = self._scan(tmp_path, unique_names=boom)

        assert statuses == _rows(trivy=True)
        ((image, rows),) = images.found_in("group/app")
        assert image == "alpine:3.19"
        assert rows["trivy"].label == "failed:scanner error"
        assert "folders failed" in (rows["trivy"].detail or "")
        assert not mock_scan_image.called


class TestAReferenceNoToolIsGivenIsAFailedImageRow:
    """A reference the validator refuses never reaches a tool's command line:
    `--file=<path>` is a syft flag, and `registry.corp:5000/...` is a private
    registry the validator has no port for. Either is still an image the
    repository names, so it is a failed image target, not a silent skip."""

    @pytest.mark.parametrize(
        ("image", "folder"),
        [
            (
                "registry.corp:5000/team/app:1",
                "group_app__registry.corp_5000_team_app_1",
            ),
            ("--file=/tmp/owned.json", "group_app__--file=_tmp_owned.json"),
        ],
    )
    def test_it_is_failed_and_recorded_where_the_report_reads(
        self, tmp_path, image, folder
    ):
        images = DiscoveredImages(tmp_path / "individual-images")
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
                return_value=MagicMock(returncode=0),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository",
                return_value=("group_app", _rows(trivy=True)),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images",
                return_value={image},
            ),
            patch("scripts.cli.scan_jobs.gitlab_scanner.scan_image") as mock_scan_image,
        ):
            scan_gitlab_repo(
                gitlab_info={"full_path": "group/app", "url": "", "token": "t"},
                results_dir=tmp_path / "individual-gitlab",
                tools=["trivy", "hadolint"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                images=images,
            )

        assert not mock_scan_image.called, "the refused reference reached a tool"
        ((named, rows),) = images.found_in("group/app")
        assert named == image
        assert rows["trivy"].label == "failed:target not scanned"
        assert image in (rows["trivy"].detail or "")
        assert rows["hadolint"].state is State.SKIPPED
        doc = json.loads(
            (tmp_path / "individual-images" / folder / "scan-timings.json").read_bytes()
        )
        assert (doc["target_type"], doc["target"]) == ("image", image)
        assert doc["outcome"] == "failed-before-tools"


class TestAbandonedGitlabTargetsStillGetTimings:
    """#824: gitlab was the only target type that never wrote scan-timings.json.

    Five of the six scanners call `write_scan_timings`; `gitlab_scanner` had no
    import and no call. On the success path that was masked -- it delegates to
    `scan_repository`, which writes the artifact into a temp dir, and the copy
    loop globs `*.json` and carries it across. On the four failure paths it was
    not masked at all, and those are the ones where the row matters: an absent
    file is indistinguishable from a target nobody requested, so the scan-phase
    instrumentation added in #722 had a hole invisible from the artifact.

    #809 was filed on the premise that "the accounting layer is fine --
    `scan-timings.json` records the truth". True for five target types, false
    for the sixth, and the sixth's gap is exactly the failure case.
    """

    GITLAB_INFO = {
        "full_path": "group/project",
        "url": "https://gitlab.com",
        "repo": "project",
        "group": "group",
    }

    def _timings(self, results_dir: Path) -> dict:
        path = results_dir / "group_project" / "scan-timings.json"
        assert path.exists(), (
            f"no scan-timings.json written for the abandoned target: "
            f"{sorted(p.name for p in results_dir.rglob('*'))}"
        )
        return json.loads(path.read_bytes().decode("utf-8"))

    def test_a_missing_token_still_records_a_row(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)

        _full_path, statuses = scan_gitlab_repo(
            gitlab_info=dict(self.GITLAB_INFO),
            results_dir=tmp_path,
            tools=["trufflehog", "semgrep"],
            timeout=600,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
        )

        assert {t: r.label for t, r in statuses.items()} == {
            "trufflehog": "failed:target not scanned",
            "semgrep": "failed:target not scanned",
        }
        doc = self._timings(tmp_path)
        assert doc["target"] == "group/project"
        assert doc["target_type"] == "gitlab"
        # A row per requested tool, none of which ran, so none has a time.
        assert [(r["tool"], r["state"]) for r in doc["tools"]] == [
            ("trufflehog", "failed"),
            ("semgrep", "failed"),
        ]
        assert all(r["seconds"] == 0 for r in doc["tools"])
        assert doc["outcome"] == "failed-before-tools"
        assert "token" in doc["error"].lower(), doc["error"]

    def test_the_token_falls_back_to_the_environment(self, tmp_path, monkeypatch):
        """`--gitlab-token` is optional because GITLAB_TOKEN is read instead.

        It never was: `jmo scan` always builds the dict with a `"token"` key
        (None when the flag is absent), and `dict.get`'s default applies only
        to a missing key. The tests above omit the key, which is how they
        passed. This is the shape `scan_orchestrator` really builds.
        """
        monkeypatch.setenv("GITLAB_TOKEN", "glpat-from-env")
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            mock_subprocess.return_value = MagicMock(
                returncode=128, stderr=b"fatal: repository not found"
            )
            scan_gitlab_repo(
                gitlab_info={**self.GITLAB_INFO, "token": None},
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

        assert mock_subprocess.called, "never cloned: the env token was not read"
        doc = self._timings(tmp_path)
        assert "token" not in doc["error"].lower(), doc["error"]

    def test_a_failed_clone_still_records_a_row(self, tmp_path):
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run"
        ) as mock_subprocess:
            mock_subprocess.return_value = MagicMock(
                returncode=128, stderr=b"fatal: repository not found"
            )
            _full_path, statuses = scan_gitlab_repo(
                gitlab_info={**self.GITLAB_INFO, "token": "glpat-x"},
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

        assert statuses["trufflehog"].label == "failed:target not scanned"
        doc = self._timings(tmp_path)
        assert doc["outcome"] == "failed-before-tools"
        assert "128" in doc["error"], doc["error"]

    def test_a_clone_timeout_still_records_a_row(self, tmp_path):
        import subprocess as _sp

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
            side_effect=_sp.TimeoutExpired(cmd="git clone", timeout=600),
        ):
            _full_path, statuses = scan_gitlab_repo(
                gitlab_info={**self.GITLAB_INFO, "token": "glpat-x"},
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

        assert statuses["trufflehog"].label == "failed:target not scanned"
        doc = self._timings(tmp_path)
        assert doc["outcome"] == "failed-before-tools"
        assert "timeout" in doc["error"].lower(), doc["error"]

    def test_an_unexpected_error_still_records_a_row(self, tmp_path):
        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
            side_effect=RuntimeError("disk on fire"),
        ):
            _full_path, statuses = scan_gitlab_repo(
                gitlab_info={**self.GITLAB_INFO, "token": "glpat-x"},
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

        assert statuses["trufflehog"].label == "failed:target not scanned"
        assert "disk on fire" in statuses["trufflehog"].detail
        doc = self._timings(tmp_path)
        assert doc["outcome"] == "failed-before-tools"
        assert "disk on fire" in doc["error"], doc["error"]

    def test_a_successful_scan_is_not_labelled_as_abandoned(self, tmp_path):
        """Negative control.

        Without it, labelling every gitlab target `failed-before-tools` passes
        all four tests above -- and would make the field useless, which is the
        whole reason the schema version was bumped.
        """
        from scripts.core.scan_timings import (
            OUTCOME_FAILED_BEFORE_TOOLS,
            write_scan_timings,
        )

        out = tmp_path / "ok"
        out.mkdir()
        write_scan_timings(
            out, {}, target="group/project", target_type="gitlab", wall_seconds=1.0
        )
        doc = json.loads((out / "scan-timings.json").read_bytes().decode("utf-8"))
        assert doc["outcome"] != OUTCOME_FAILED_BEFORE_TOOLS
        assert doc["outcome"] == "completed"
        assert doc["error"] is None


class TestDiscoveryNamesOnlyImagesJmoCanPull:
    """#1311: a discovered reference is handed to trivy and syft, first on
    their command line. What reaches them must be an image reference taken
    from the repository's content, never a flag, a build argument or a stage."""

    @staticmethod
    def _discover(tmp_path: Path, files: dict[str, str]) -> set[str]:
        from scripts.cli.scan_jobs.gitlab_scanner import _discover_container_images

        for name, body in files.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body.encode("utf-8"))
        return _discover_container_images(tmp_path)

    def test_a_platform_flag_is_not_the_image(self, tmp_path):
        """`FROM --platform=...` is the common multi-architecture form. The
        flag was taken as the image and would reach the tools as a flag."""
        images = self._discover(
            tmp_path, {"Dockerfile": "FROM --platform=linux/amd64 alpine:3.19\n"}
        )
        assert images == {"alpine:3.19"}

    def test_a_build_argument_is_skipped_and_the_file_named(self, tmp_path, caplog):
        """`FROM $BASE` names no image until the build supplies BASE."""
        dockerfile = "ARG BASE=alpine\nFROM $BASE\nFROM ${BASE}:3.19\nFROM nginx:1.27\n"
        with caplog.at_level(
            logging.INFO, logger="scripts.cli.scan_jobs.gitlab_scanner"
        ):
            images = self._discover(tmp_path, {"build/Dockerfile": dockerfile})

        assert images == {"nginx:1.27"}
        said = [
            r.getMessage()
            for r in caplog.records
            if r.levelno == logging.INFO and "build/Dockerfile" in r.getMessage()
        ]
        assert len(said) == 2, [r.getMessage() for r in caplog.records]
        assert "$BASE" in said[0] or "$BASE" in said[1], said

    def test_a_value_that_is_not_an_image_reference_is_named_for_the_job_to_refuse(
        self, tmp_path
    ):
        """Discovery reports what the repository names. The job refuses what
        is not an image reference (it never reaches a tool) and records it as
        a failed image target, so it is never silently dropped."""
        compose = "services:\n  web:\n    image: --file=/tmp/owned.json\n"
        images = self._discover(tmp_path, {"docker-compose.yml": compose})
        assert images == {"--file=/tmp/owned.json"}

    def test_only_a_dockerfile_is_read_for_its_from_lines(self, tmp_path):
        """One definition of a Dockerfile, hadolint's row's: Docker's names,
        with their case, outside vendored trees, and not a document about
        one. `*Dockerfile*` read a Python module and a README (measured:
        `os` and `the`, each then pulled from Docker Hub, failing the scan)."""
        images = self._discover(
            tmp_path,
            {
                "Dockerfile": "FROM alpine:3.19\n",
                "api.Dockerfile": "FROM python:3.12\n",
                "Dockerfile.dev": "FROM golang:1.22\n",
                "Dockerfile.md": "From the root of the repo, run make.\n",
                "pkg/dockerfile_utils.py": "from os import path\n",
                "sub/dockerfile": "FROM busybox:1\n",
                "node_modules/dep/Dockerfile": "FROM node:20\n",
            },
        )
        assert images == {"alpine:3.19", "python:3.12", "golang:1.22"}

    @pytest.mark.parametrize(
        "files",
        [
            {"pkg/dockerfile_utils.py": "from os import path\n"},
            {"Dockerfile.md": "From the root of the repo, run make.\n"},
        ],
        ids=["python-module", "markdown"],
    )
    def test_a_file_that_only_mentions_dockerfile_discovers_nothing(
        self, tmp_path, files
    ):
        assert self._discover(tmp_path, files) == set()

    def test_a_later_stage_named_by_an_earlier_one_is_not_an_image(self, tmp_path):
        """`FROM build` after `FROM node:20 AS build` names the stage, which
        no registry holds."""
        dockerfile = "FROM node:20 AS build\nRUN make\nFROM build\n"
        assert self._discover(tmp_path, {"Dockerfile": dockerfile}) == set()

    def test_a_builder_stage_and_scratch_discover_nothing(self, tmp_path):
        """The gate's negative project, and today's two skips kept."""
        dockerfile = "FROM golang:alpine AS builder\nRUN go build\nFROM scratch\n"
        assert self._discover(tmp_path, {"Dockerfile": dockerfile}) == set()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
