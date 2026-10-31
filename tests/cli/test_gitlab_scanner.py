"""
Tests for GitLab Scanner

Tests the gitlab_scanner module with various scenarios.
Updated to mock scan_repository() and subprocess.run() instead of ToolRunner.
"""

import json
import logging
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.gitlab_scanner import DiscoveredImages, scan_gitlab_repo
from scripts.core.scan_timings import Reason, State, ToolRun
from scripts.core.secure_temp import secure_temp_dir


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
                tools=["trufflehog", "opengrep"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Should return failure for all tools
            assert full_path == "fail/clone"
            assert statuses["trufflehog"].label == "failed:target not scanned"
            assert statuses["opengrep"].label == "failed:target not scanned"

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
                tools=["trufflehog", "opengrep"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Should return failure for all tools
            assert full_path == "timeout/repo"
            assert statuses["trufflehog"].label == "failed:target not scanned"
            assert statuses["opengrep"].label == "failed:target not scanned"

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
                _rows(trufflehog=True, opengrep=True),
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
                tools=["trufflehog", "opengrep"],
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

    def test_a_raise_out_of_the_image_step_keeps_the_repositorys_rows(
        self, tmp_path, caplog
    ):
        """`_scan_named_images` contains its own failures, but a fault in its
        handlers can still escape it, and by then the repository's rows and
        outputs are final: `_record_abandoned_target` says a failure past the
        scan does not come to it. The repository's rows come back as they
        were, no abandoned-target timings are written over them, and the
        WARNING names the target and the error."""
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
                "scripts.cli.scan_jobs.gitlab_scanner._scan_named_images",
                side_effect=RuntimeError("images exploded"),
            ),
            caplog.at_level(
                logging.WARNING, logger="scripts.cli.scan_jobs.gitlab_scanner"
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
                images=DiscoveredImages(tmp_path / "individual-images"),
            )

        assert statuses == _rows(trivy=True)
        timings = tmp_path / "individual-gitlab" / "group_app" / "scan-timings.json"
        assert not timings.exists(), "the completed scan was relabelled abandoned"
        logged = [
            r.getMessage() for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert any(
            "group/app" in m and "RuntimeError: images exploded" in m for m in logged
        ), logged


class TestAReferenceNoToolIsGivenIsAFailedImageRow:
    """A reference the validator refuses never reaches a tool's command line:
    `--file=<path>` is a syft flag. Discovery keeps only what Docker's grammar
    accepts and the validator accepts the same grammar, so a file can name one
    only by length: the validator also refuses a reference over 255
    characters, which discovery does not check. The job's refusal is otherwise
    a guard, and these tests reach it through a patched discovery. It is still
    an image the repository names, so it is a failed image target, not a
    silent skip."""

    def test_it_is_failed_and_recorded_where_the_report_reads(self, tmp_path):
        image = "--file=/tmp/owned.json"
        folder = "group_app__--file=_tmp_owned.json"
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


class TestAnImageOnARegistryWithAPortIsScanned:
    """#1405: `registry.corp:5000/team/app:1` is a normal Docker reference. The
    validator refused it, so the job recorded a failed image target for an
    image no pull was ever attempted for."""

    @pytest.mark.parametrize(
        "image",
        [
            "registry.corp:5000/team/app:1",
            "localhost:5000/app",
            "registry.corp:5000/team/app@sha256:" + "a" * 64,
        ],
    )
    def test_it_reaches_scan_image_and_is_no_failed_row(self, tmp_path, image):
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
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_image",
                side_effect=lambda **kw: (kw["image"], _rows(trivy=True)),
            ) as mock_scan_image,
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

        (call,) = mock_scan_image.call_args_list
        assert call.kwargs["image"] == image
        ((named, rows),) = images.found_in("group/app")
        assert named == image
        assert "failed:target not scanned" not in {row.label for row in rows.values()}
        assert rows["trivy"].state is State.RAN


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
            tools=["trufflehog", "opengrep"],
            timeout=600,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
        )

        assert {t: r.label for t, r in statuses.items()} == {
            "trufflehog": "failed:target not scanned",
            "opengrep": "failed:target not scanned",
        }
        doc = self._timings(tmp_path)
        assert doc["target"] == "group/project"
        assert doc["target_type"] == "gitlab"
        # A row per requested tool, none of which ran, so none has a time.
        assert [(r["tool"], r["state"]) for r in doc["tools"]] == [
            ("trufflehog", "failed"),
            ("opengrep", "failed"),
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

    def test_a_repository_scan_that_raises_still_records_a_row(self, tmp_path):
        """The other side of the line the image step's own `except` draws: until
        `scan_repository` has returned there are no results to keep, so a raise
        out of it still abandons the target, with images to scan or not."""
        with (
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
                return_value=MagicMock(returncode=0),
            ),
            patch(
                "scripts.cli.scan_jobs.gitlab_scanner.scan_repository",
                side_effect=RuntimeError("scanner exploded"),
            ),
        ):
            _full_path, statuses = scan_gitlab_repo(
                gitlab_info={**self.GITLAB_INFO, "token": "glpat-x"},
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                images=DiscoveredImages(tmp_path / "individual-images"),
            )

        assert statuses["trufflehog"].label == "failed:target not scanned"
        assert statuses["trufflehog"].detail == "RuntimeError: scanner exploded"
        doc = self._timings(tmp_path)
        assert doc["outcome"] == "failed-before-tools"
        assert doc["error"] == "RuntimeError: scanner exploded"

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

    def test_a_value_that_is_not_an_image_reference_is_named_and_dropped(
        self, tmp_path, caplog
    ):
        """It never reaches a tool's command line (`--file=` is a syft flag),
        and it is not silently dropped: a WARNING names the file and line. As
        an image target it failed and made a clean scan exit 1."""
        compose = "services:\n  web:\n    image: --file=/tmp/owned.json\n"
        with caplog.at_level(
            logging.WARNING, logger="scripts.cli.scan_jobs.gitlab_scanner"
        ):
            images = self._discover(tmp_path, {"docker-compose.yml": compose})

        assert images == set()
        assert caplog.messages == [
            "docker-compose.yml:3 names '--file=/tmp/owned.json', which is not "
            "an image reference: not scanned"
        ]

    def test_a_registry_with_a_port_is_an_image_reference(self, tmp_path):
        """Docker pulls it, so discovery keeps it, and the job scans it (#1405)."""
        images = self._discover(
            tmp_path, {"Dockerfile": "FROM registry.corp:5000/team/app:1\n"}
        )
        assert images == {"registry.corp:5000/team/app:1"}

    @pytest.mark.parametrize("image", ["Org/app", "registry.corp/App:1"])
    def test_an_upper_case_repository_is_no_image_reference(
        self, tmp_path, caplog, image
    ):
        """A repository path is lower case, and a first component is a
        registry only when it holds `.` or `:` or is `localhost` (#1405): so
        `Org/app` is named and dropped, not a target that fails."""
        with caplog.at_level(
            logging.WARNING, logger="scripts.cli.scan_jobs.gitlab_scanner"
        ):
            images = self._discover(tmp_path, {"Dockerfile": f"FROM {image}\n"})

        assert images == set()
        assert caplog.messages == [
            f"Dockerfile:1 names {image!r}, which is not an image reference: "
            "not scanned"
        ]

    @pytest.mark.parametrize(
        ("dockerfile", "images"),
        [
            pytest.param(
                "# escape=`\nFROM `\n    alpine:3.19\nCOPY C:\\app\\ C:\\dest\\\n",
                {"alpine:3.19"},
                id="escape-directive",
            ),
            pytest.param(
                "FROM alpine:3.19 \\\n  # a comment inside\n\n  AS base\nFROM base\n",
                set(),
                id="comment-and-blank-inside-a-continuation",
            ),
            pytest.param(
                "FROM alpine:3.19\nRUN <<-EOT bash\n\tfrom x import y\n\tEOT\n"
                "FROM nginx:1.27\n",
                {"alpine:3.19", "nginx:1.27"},
                id="tab-stripped-heredoc",
            ),
            pytest.param(
                "FROM alpine:3.19\nCOPY <<'A' <<\"B\" /dest/\nfrom a import b\nA\n"
                "from c import d\nB\nFROM nginx:1.27\n",
                {"alpine:3.19", "nginx:1.27"},
                id="two-quoted-heredocs",
            ),
            pytest.param(
                "FROM alpine:3.19\nRUN cat <<<from\nFROM nginx:1.27\n",
                {"alpine:3.19", "nginx:1.27"},
                id="here-string-is-no-heredoc",
            ),
            pytest.param(
                "# syntax=docker/dockerfile:1\nfrom alpine:3.19 as build\n"
                "FROM python:3.12\n",
                {"python:3.12"},
                id="syntax-directive-and-lower-case",
            ),
            # A guard: the word read past ONBUILD is not a heredoc instruction.
            pytest.param(
                "FROM alpine:3.19\nONBUILD ENV X=1\nFROM nginx:1.27\n",
                {"alpine:3.19", "nginx:1.27"},
                id="guard-onbuild-with-a-non-heredoc-instruction",
            ),
        ],
    )
    def test_instructions_are_read_as_docker_reads_them(
        self, tmp_path, dockerfile, images
    ):
        assert self._discover(tmp_path, {"Dockerfile": dockerfile}) == images

    @pytest.mark.parametrize(
        "dockerfile",
        [
            pytest.param(
                "FROM python:3.12\nONBUILD RUN <<EOF\npython -c 'import os'\n"
                "from os import path\nEOF\n",
                id="onbuild-run",
            ),
            pytest.param(
                "FROM python:3.12\nonbuild copy <<EOF /app/main.py\n"
                "from flask import Flask\nEOF\n",
                id="lower-case-onbuild-copy",
            ),
        ],
    )
    def test_an_onbuild_heredoc_body_is_not_read_as_instructions(
        self, tmp_path, dockerfile
    ):
        """#1415: `ONBUILD RUN <<EOF` starts with ONBUILD, so its body was read
        as Dockerfile lines and `from os import path` named the image `os`,
        which failed as an image target and made the scan exit 1."""
        assert self._discover(tmp_path, {"Dockerfile": dockerfile}) == {"python:3.12"}

    @pytest.mark.parametrize(
        "line",
        [
            pytest.param('RUN echo "usage: cat <<EOF here"', id="double-quoted"),
            pytest.param("RUN echo 'a <<EOF b'", id="single-quoted"),
            # An escaped quote does not end a double-quoted span (this failed).
            pytest.param(r'RUN echo "a \" <<EOF b"', id="escaped-quote-inside-double"),
            # The last two already passed: the regex wants whitespace before
            # `<<`, and a quote is not whitespace. They guard the fix, which
            # must not make a quote after the word read differently.
            pytest.param('RUN echo "<<EOF"', id="guard-no-space-before-marker"),
            pytest.param('RUN echo " <<EOF"', id="guard-quote-right-after-the-word"),
        ],
    )
    def test_a_marker_inside_quotes_does_not_open_a_heredoc(self, tmp_path, line):
        """#1416: `<<EOF` in a quoted string was taken as a heredoc, and the
        body that never ended swallowed every later FROM, silently."""
        dockerfile = f"FROM alpine:3.19\n{line}\nFROM nginx:1.27\n"
        assert self._discover(tmp_path, {"Dockerfile": dockerfile}) == {
            "alpine:3.19",
            "nginx:1.27",
        }

    @pytest.mark.parametrize(
        "line",
        [
            # The first three failed: in shell an escaped quote opens no
            # quoted span, but the scan took it for one, and the span
            # swallowed the real marker after it.
            pytest.param(
                r"RUN echo don\'t && cat <<'EOF' > /x", id="escaped-apostrophe-1"
            ),
            pytest.param(
                r"RUN echo can\'t; cat <<EOF > 'out file'", id="escaped-apostrophe-2"
            ),
            pytest.param(
                r'RUN printf \"x && cat <<EOF > "/y"', id="escaped-double-quote"
            ),
            # An escaped space is no quote: `<<` is an operator, so the marker
            # after `a\ ` still opens a heredoc. This one passed before the
            # fix and failed after its first version (a fix to it, not a guard).
            pytest.param(r"RUN echo a\ <<EOF", id="escaped-space-before-the-marker"),
            # The rest passed before the fix (found by probe). They guard it:
            # a quote that closes and one that never does read as shell reads them.
            pytest.param(
                'RUN echo "x y" && cat <<EOF > /x', id="guard-closed-quoted-span"
            ),
            pytest.param("RUN echo it's <<EOF", id="guard-unbalanced-apostrophe"),
        ],
    )
    def test_an_escaped_quote_does_not_hide_a_heredoc_marker(self, tmp_path, line):
        """#1415 again, by another road: a quote after a backslash opens no
        quoted span in shell, so `don\\'t && cat <<'EOF'` still opens a heredoc.
        The scan took `'t && cat <<'` for a span, never saw the marker, and read
        the heredoc body as Dockerfile lines: `from os import path` named the
        image `os`, which failed as an image target and made the scan exit 1."""
        dockerfile = (
            f"FROM alpine:3.19\n{line}\nfrom os import path\nEOF\nFROM nginx:1.27\n"
        )
        assert self._discover(tmp_path, {"Dockerfile": dockerfile}) == {
            "alpine:3.19",
            "nginx:1.27",
        }

    @pytest.mark.parametrize(
        ("line", "marker", "indent"),
        [
            # Whitespace between `<<` and the word: BuildKit folds it into the
            # word, so each of these opens a heredoc (all failed).
            pytest.param("RUN cat << EOF > /x", "EOF", "", id="space"),
            pytest.param("RUN cat <<  EOF > /x", "EOF", "", id="two-spaces"),
            pytest.param("RUN cat <<\tEOF > /x", "EOF", "", id="tab"),
            pytest.param('RUN cat << "EOF" > /x', "EOF", "", id="space-then-quoted"),
            pytest.param("COPY << EOF /x", "EOF", "", id="copy"),
            pytest.param("RUN cat <<- EOF > /x", "EOF", "\t", id="chomp-then-space"),
            # The dash after the whitespace is part of the word, not chomp.
            pytest.param("RUN cat << -EOF", "-EOF", "", id="space-then-dash-word"),
            # A marker with quotes or backslashes is named without them (all
            # failed): `\EOF` was the marker `\EOF`, and nothing closed it.
            pytest.param(r"RUN cat <<\EOF > /x", "EOF", "", id="backslash-first"),
            pytest.param(r"RUN cat <<-\EOF > /x", "EOF", "\t", id="chomp-backslash"),
            pytest.param(r"RUN cat <<E\OF > /x", "EOF", "", id="backslash-inside"),
            pytest.param('RUN cat <<EO"F" > /x', "EOF", "", id="quoted-part"),
            pytest.param("RUN cat <<'one two' > /x", "one two", "", id="quoted-spaced"),
            pytest.param(
                r'RUN cat <<"E\"F" > /x', 'E"F', "", id="escaped-quote-in-quotes"
            ),
            # Inside double quotes a backslash escapes only `"`, `$` and `\`
            # (this passed before the change, as did the control below it).
            pytest.param(
                r'RUN cat <<"E\xF" > /x', r"E\xF", "", id="guard-other-escape-kept"
            ),
            pytest.param("RUN cat <<EOF > /x", "EOF", "", id="guard-no-whitespace"),
        ],
    )
    def test_a_heredoc_word_is_read_as_buildkit_reads_it(
        self, tmp_path, line, marker, indent
    ):
        """A heredoc not recognised leaves its body to be read as Dockerfile
        lines: `from os import path` named the image `os`, which failed as an
        image target and made the scan exit 1. An opening word that is read
        wrongly (`<<- EOF` gave the marker `-`) swallows every later FROM."""
        dockerfile = (
            f"FROM alpine:3.19\n{line}\n{indent}from os import path\n"
            f"{indent}{marker}\nFROM nginx:1.27\n"
        )
        assert self._discover(tmp_path, {"Dockerfile": dockerfile}) == {
            "alpine:3.19",
            "nginx:1.27",
        }

    @pytest.mark.parametrize(
        "line",
        [
            # A word that is only `<<` or `<<-` names no marker (`<<-` was
            # read as the marker `-`, which no line closed). The `guard-` ones
            # passed before the change and must keep passing.
            pytest.param("RUN cat <<", id="guard-lone-operator"),
            pytest.param("RUN cat <<-", id="lone-chomp-operator"),
            pytest.param('RUN cat <<""', id="guard-empty-quoted-word"),
            pytest.param("RUN cat <<<word", id="guard-here-string"),
            pytest.param("RUN cat <<< word", id="guard-here-string-with-a-space"),
            pytest.param('RUN "<<EOF"', id="guard-whole-word-quoted"),
        ],
    )
    def test_a_word_that_names_no_marker_opens_no_heredoc(self, tmp_path, caplog, line):
        """BuildKit reads no heredoc here, so what follows is read, and no
        WARNING says the rest of the file is a body."""
        dockerfile = f"FROM alpine:3.19\n{line}\nFROM nginx:1.27\n"
        with caplog.at_level(
            logging.WARNING, logger="scripts.cli.scan_jobs.gitlab_scanner"
        ):
            images = self._discover(tmp_path, {"Dockerfile": dockerfile})

        assert images == {"alpine:3.19", "nginx:1.27"}
        assert caplog.messages == []

    @pytest.mark.parametrize(
        ("dockerfile", "images", "messages"),
        [
            pytest.param(
                "FROM alpine:3.19\nRUN <<\\EOF\nfrom os import path\nFROM nginx:1.27\n",
                {"alpine:3.19"},
                [
                    "build/Dockerfile:2 opens the heredoc 'EOF', which is never "
                    "closed: the rest of the file is its body, so no later FROM "
                    "is read"
                ],
                id="escaped-marker-is-named-without-the-backslash",
            ),
            pytest.param(
                "FROM alpine:3.19\nCOPY << 'A B' /dest/\nbody\nFROM nginx:1.27\n",
                {"alpine:3.19"},
                [
                    "build/Dockerfile:2 opens the heredoc 'A B', which is never "
                    "closed: the rest of the file is its body, so no later FROM "
                    "is read"
                ],
                id="spaced-quoted-marker-is-named-without-the-quotes",
            ),
            pytest.param(
                "FROM alpine:3.19\nRUN <<EOF\nfrom os import path\nFROM nginx:1.27\n"
                "FROM busybox:1\n",
                {"alpine:3.19"},
                [
                    "build/Dockerfile:2 opens the heredoc 'EOF', which is never "
                    "closed: the rest of the file is its body, so no later FROM "
                    "is read"
                ],
                id="body-runs-to-the-end-of-the-file",
            ),
            pytest.param(
                "FROM alpine:3.19\nCOPY <<A <<B /dest/\nbody\nA\nbody\n",
                {"alpine:3.19"},
                [
                    "build/Dockerfile:2 opens the heredoc 'B', which is never "
                    "closed: the rest of the file is its body, so no later FROM "
                    "is read"
                ],
                id="second-of-two-heredocs",
            ),
            pytest.param(
                "FROM alpine:3.19\nRUN <<EOF\nFROM nginx:1.27\nEOF\nFROM busybox:1\n",
                {"alpine:3.19", "busybox:1"},
                [],
                id="closed-heredoc-says-nothing",
            ),
        ],
    )
    def test_a_heredoc_left_open_at_the_end_of_the_file_is_named(
        self, tmp_path, caplog, dockerfile, images, messages
    ):
        """#1416: BuildKit reads the rest of the file as the body, so what
        follows is not read. That was silent: now one WARNING names the file,
        the line and the marker."""
        with caplog.at_level(
            logging.WARNING, logger="scripts.cli.scan_jobs.gitlab_scanner"
        ):
            found = self._discover(tmp_path, {"build/Dockerfile": dockerfile})

        assert found == images
        assert caplog.messages == messages

    def test_a_compose_service_that_builds_its_image_names_none_to_pull(self, tmp_path):
        """With `build:`, `image:` is the tag compose gives its own build."""
        compose = (
            "services:\n"
            "  web:\n    build: .\n    image: example-local/web:dev\n"
            "  db:\n    image: postgres:16\n"
        )
        images = self._discover(tmp_path, {"docker-compose.yml": compose})
        assert images == {"postgres:16"}

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

    # --- #1410: compose.yaml and workload manifests -------------------------

    @pytest.mark.parametrize(
        "name",
        ["compose.yaml", "compose.yml", "compose.override.yaml", "deploy/compose.yaml"],
    )
    def test_the_compose_specifications_own_file_names_are_read(self, tmp_path, name):
        """`compose.yaml` and `compose.yml` are the names the Compose
        specification gives a project, and only `docker-compose*` was read:
        a project on the current names had no image scanned (measured)."""
        compose = (
            "services:\n"
            "  web:\n    image: nginx:1.27\n"
            "  app:\n    build: .\n    image: example-local/app:dev\n"
        )
        assert self._discover(tmp_path, {name: compose}) == {"nginx:1.27"}

    def test_a_compose_file_in_a_vendored_tree_is_not_read(self, tmp_path):
        """The one walk skips `node_modules`, `vendor`, `.venv`, `venv` and
        `.git` for compose files as it does for Dockerfiles: a dependency's
        example compose file names images the repository does not use."""
        images = self._discover(
            tmp_path,
            {
                "docker-compose.yml": "services:\n  web:\n    image: nginx:1.27\n",
                "node_modules/dep/docker-compose.yml": (
                    "services:\n  web:\n    image: alpine:3.14\n"
                ),
            },
        )
        assert images == {"nginx:1.27"}

    @pytest.mark.parametrize("name", ["compose-prod.yaml", "docker-compose.prod.yml"])
    def test_a_manifest_in_a_compose_named_file_is_read(self, tmp_path, name):
        """A file is a manifest by its content, not its name: the name only
        says which reader a file goes to first. A Deployment kept in
        `compose-prod.yaml` named no image, though a manifest is read
        "whatever the file is called"."""
        deployment = (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\nspec:\n"
            "  template:\n    spec:\n      containers:\n"
            "      - name: web\n        image: nginx:1.27\n"
        )
        assert self._discover(tmp_path, {name: deployment}) == {"nginx:1.27"}

    def test_a_pods_init_containers_are_images_to_scan(self, tmp_path):
        """An init container's image runs in the cluster as the app's does."""
        pod = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n"
            "  initContainers:\n  - name: wait\n    image: busybox:1.36\n"
            "  containers:\n  - name: app\n    image: nginx:1.27\n"
        )
        assert self._discover(tmp_path, {"pod.k8s.yaml": pod}) == {
            "busybox:1.36",
            "nginx:1.27",
        }

    @pytest.mark.parametrize(
        ("api_version", "kind"),
        [
            ("apps/v1", "Deployment"),
            ("apps/v1", "StatefulSet"),
            ("apps/v1", "DaemonSet"),
            ("batch/v1", "Job"),
        ],
    )
    def test_a_workloads_pod_template_is_read(self, tmp_path, api_version, kind):
        """A Deployment names its images under `spec.template.spec`, not
        `spec`: only a bare Pod's `spec.containers` was read, so the usual
        workload kinds named no image at all."""
        workload = (
            f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: w\n"
            "spec:\n  template:\n    spec:\n"
            "      initContainers:\n      - name: wait\n        image: busybox:1.36\n"
            "      containers:\n      - name: app\n        image: nginx:1.27\n"
        )
        assert self._discover(tmp_path, {"k8s/workload.yaml": workload}) == {
            "busybox:1.36",
            "nginx:1.27",
        }

    def test_a_cron_jobs_job_template_is_read(self, tmp_path):
        """A CronJob's pod template is one level deeper:
        `spec.jobTemplate.spec.template.spec`."""
        cron = (
            "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: nightly\n"
            "spec:\n  schedule: '0 * * * *'\n  jobTemplate:\n    spec:\n"
            "      template:\n        spec:\n"
            "          initContainers:\n          - name: wait\n"
            "            image: busybox:1.36\n"
            "          containers:\n          - name: job\n"
            "            image: nginx:1.27\n"
        )
        assert self._discover(tmp_path, {"k8s/cron.yaml": cron}) == {
            "busybox:1.36",
            "nginx:1.27",
        }

    @pytest.mark.parametrize("name", ["deploy/app.yaml", "deploy/app.yml"])
    def test_a_manifest_is_found_by_its_content_not_a_k8s_file_name(
        self, tmp_path, name
    ):
        """Almost no repository names a manifest `*.k8s.yaml`: it has an
        `apiVersion` and a `kind`, and that is what makes it one."""
        pod = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n"
            "  containers:\n  - name: app\n    image: nginx:1.27\n"
        )
        assert self._discover(tmp_path, {name: pod}) == {"nginx:1.27"}

    def test_every_document_of_a_multi_document_file_is_read(self, tmp_path):
        """One file holds a ConfigMap, a Pod, an empty document and a
        Deployment: the ConfigMap names nothing, the others each name images."""
        manifests = (
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n"
            "data:\n  image: not-an-image-here\n"
            "---\n"
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n"
            "  initContainers:\n  - name: wait\n    image: busybox:1.36\n"
            "  containers:\n  - name: app\n    image: redis:7\n"
            "---\n"
            "---\n"
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\nspec:\n"
            "  template:\n    spec:\n      containers:\n"
            "      - name: web\n        image: nginx:1.27\n"
        )
        assert self._discover(tmp_path, {"deploy/all.yaml": manifests}) == {
            "busybox:1.36",
            "redis:7",
            "nginx:1.27",
        }

    @pytest.mark.parametrize(
        ("name", "body"),
        [
            pytest.param(
                ".gitlab-ci.yml",
                "image: alpine:3.15\nstages:\n  - build\nbuild:\n"
                "  image: python:3.12\n  script:\n    - make\n",
                id="gitlab-ci",
            ),
            pytest.param(
                "deploy/app.yaml",
                "kind: Pod\nspec:\n  containers:\n  - name: app\n"
                "    image: nginx:1.27\n",
                id="kind-without-apiversion",
            ),
            pytest.param(
                "deploy/app.yaml",
                "apiVersion: 1\nkind: Pod\nspec:\n  containers:\n  - name: app\n"
                "    image: nginx:1.27\n",
                id="apiversion-not-a-string",
            ),
        ],
    )
    def test_a_yaml_file_that_is_not_a_manifest_names_no_image(
        self, tmp_path, name, body
    ):
        """Only a document with a string `apiVersion` and `kind` is a
        manifest. A CI file's `image:` is the job's runner image, not one the
        repository ships, and the pipeline file is no Kubernetes object."""
        assert self._discover(tmp_path, {name: body}) == set()

    def test_a_yaml_file_naming_neither_apiversion_nor_kind_is_not_parsed(
        self, tmp_path, monkeypatch
    ):
        """Lockfiles and CI files are YAML, and the pure-Python loader takes
        seconds on a large one (0.37 s on a real 430 KB `pnpm-lock.yaml`), so
        a file is parsed for manifests only when its text holds both words."""
        from scripts.cli.scan_jobs import gitlab_scanner

        parsed: list[object] = []
        real_load_all = gitlab_scanner.yaml.load_all

        def spy(stream, Loader):
            parsed.append(stream)
            return real_load_all(stream, Loader=Loader)

        monkeypatch.setattr(gitlab_scanner.yaml, "load_all", spy)
        pod = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n"
            "  containers:\n  - name: app\n    image: nginx:1.27\n"
        )
        images = self._discover(
            tmp_path,
            {
                "pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  a@1: {}\n",
                ".gitlab-ci.yml": "image: alpine:3.15\nscript:\n  - make\n",
                "deploy/app.yaml": pod,
            },
        )
        assert images == {"nginx:1.27"}
        assert len(parsed) == 1

    def test_a_manifest_that_does_not_parse_is_skipped_and_the_walk_goes_on(
        self, tmp_path
    ):
        """Parsing is per file: one broken manifest must not stop the others
        being read. (The pre-existing malformed-file test names no `kind`, so
        it no longer reaches the parser; this one does.)"""
        images = self._discover(
            tmp_path,
            {
                "a-broken.yaml": "apiVersion: v1\nkind: Pod\nspec: [unclosed\n",
                "b-good.yaml": (
                    "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n"
                    "  - name: app\n    image: nginx:1.27\n"
                ),
            },
        )
        assert images == {"nginx:1.27"}

    @pytest.mark.parametrize(
        ("name", "body", "images"),
        [
            pytest.param(
                "list.k8s.yaml",
                "apiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n"
                "  kind: Pod\n  spec:\n    containers:\n    - name: app\n"
                "      image: nginx:1.27\n",
                set(),
                id="kind-list",
            ),
            pytest.param(
                "pod.k8s.yaml",
                "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n"
                "  - name: app\n    image: nginx:1.27\n"
                "  ephemeralContainers:\n  - name: debugger\n"
                "    image: busybox:1.36\n",
                {"nginx:1.27"},
                id="ephemeral-containers",
            ),
        ],
    )
    def test_what_a_cluster_adds_or_wraps_is_not_read(
        self, tmp_path, name, body, images
    ):
        """Guards for the limits of the reading, which the manifest rule does
        not widen: an ephemeral container is added to a running Pod by a
        debugger, and a `List` only wraps objects that are files of their own
        elsewhere. Neither is an image the repository names to run."""
        assert self._discover(tmp_path, {name: body}) == images

    @pytest.mark.parametrize(
        ("filler", "body", "last", "last_body"),
        [
            pytest.param(
                "a/f{:03d}.yaml",
                "x: 1\n",
                "z/compose.yaml",
                "services:\n  web:\n    image: nginx:1.27\n",
                id="yaml",
            ),
            pytest.param(
                "a{:03d}/Dockerfile",
                "FROM scratch\n",
                "z/Dockerfile",
                "FROM nginx:1.27\n",
                id="dockerfile",
            ),
        ],
    )
    def test_discovery_reads_every_file_not_the_first_300(
        self, tmp_path, caplog, filler, body, last, last_body
    ):
        """The walk's 300-file cut is for a tool's command line, and discovery
        puts nothing on one: past it, a repository with many YAML files or
        Dockerfiles lost the files that sort last, under a WARNING that blamed
        a command-line limit (measured: 350 YAML files and a `z/compose.yaml`
        gave 300, without the compose file)."""
        from scripts.cli.scan_jobs.tool_loop import MAX_FILE_ARGS

        files = {filler.format(i): body for i in range(MAX_FILE_ARGS + 1)}
        files[last] = last_body
        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_jobs.tool_loop"):
            images = self._discover(tmp_path, files)

        assert images == {"nginx:1.27"}
        assert "command-line length limit" not in caplog.text, caplog.text


class TestAGitlabUrlIsClonedFromTheHostItNames:
    """`--gitlab-url gitlab.example.com` (no scheme) used to be replaced by
    `https://gitlab.com`: the project was requested from gitlab.com, which
    answers 401 for a path it does not serve publicly, and git then offered
    the self-hosted instance's token to it. A value is a host, an http(s) URL,
    or refused; it is never another host than the one the user typed.

    No test touches the network: `subprocess.run` is patched and the clone
    argument is read from the command it was given."""

    SCANNER = "scripts.cli.scan_jobs.gitlab_scanner"
    TOKEN = "glpat-self-hosted-secret"

    def _scan(self, tmp_path, url):
        """Scan `group/app` at `url`. Returns (rows, the patched `git` run,
        the patched repository scan, whether each temporary directory held
        the askpass helper when it was removed)."""
        askpass_written: list[bool] = []

        @contextmanager
        def watched_temp_dir(*args, **kwargs):
            with secure_temp_dir(*args, **kwargs) as temp_dir:
                try:
                    yield temp_dir
                finally:
                    askpass_written.append((temp_dir / "git-askpass.py").exists())

        with (
            patch(
                f"{self.SCANNER}.subprocess.run",
                return_value=MagicMock(returncode=0),
            ) as run,
            patch(
                f"{self.SCANNER}.scan_repository",
                return_value=("group_app", _rows(trufflehog=True)),
            ) as scan_repo,
            patch(f"{self.SCANNER}.secure_temp_dir", watched_temp_dir),
        ):
            _full_path, rows = scan_gitlab_repo(
                gitlab_info={"full_path": "group/app", "url": url, "token": self.TOKEN},
                results_dir=tmp_path / "individual-gitlab",
                tools=["trufflehog", "opengrep"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )
        return rows, run, scan_repo, askpass_written

    @pytest.mark.parametrize(
        ("url", "cloned"),
        [
            ("gitlab.example.com", "https://gitlab.example.com/group/app.git"),
            ("gitlab.example.com/", "https://gitlab.example.com/group/app.git"),
            ("  gitlab.example.com/  ", "https://gitlab.example.com/group/app.git"),
            (
                "gitlab.example.com:8443",
                "https://gitlab.example.com:8443/group/app.git",
            ),
            (
                "gitlab.example.com/gitlab",
                "https://gitlab.example.com/gitlab/group/app.git",
            ),
            # `startswith("http")` read this as a URL and cloned a path with no host.
            ("httpfoo.example.com", "https://httpfoo.example.com/group/app.git"),
            ("https://gitlab.example.com", "https://gitlab.example.com/group/app.git"),
            ("https://gitlab.example.com/", "https://gitlab.example.com/group/app.git"),
            ("http://gitlab.internal", "http://gitlab.internal/group/app.git"),
            # git looks its remote helper up by the scheme as written, case-sensitively.
            ("HTTPS://gitlab.example.com", "https://gitlab.example.com/group/app.git"),
            ("HTTPS://Gitlab.Example.com", "https://Gitlab.Example.com/group/app.git"),
            (
                "https://gitlab.example.com:8443/sub/",
                "https://gitlab.example.com:8443/sub/group/app.git",
            ),
            ("[::1]:8443", "https://[::1]:8443/group/app.git"),
            # A bare value is checked as the URL it becomes, so it takes every host
            # the explicit form takes (docker network names, IDN, a rooted name).
            ("gitlab_web", "https://gitlab_web/group/app.git"),
            ("gitlab_web:8080", "https://gitlab_web:8080/group/app.git"),
            ("https://gitlab_web:8080", "https://gitlab_web:8080/group/app.git"),
            (
                "gitlab.ex\u00e4mple.com",
                "https://gitlab.ex\u00e4mple.com/group/app.git",
            ),
            ("gitlab.example.com.", "https://gitlab.example.com./group/app.git"),
            # Only the authority is screened for `%`: a sub-path may carry one.
            (
                "https://gitlab.example.com/gl%2Fprefix",
                "https://gitlab.example.com/gl%2Fprefix/group/app.git",
            ),
            ("", "https://gitlab.com/group/app.git"),
            ("   ", "https://gitlab.com/group/app.git"),
            (None, "https://gitlab.com/group/app.git"),
        ],
        ids=[
            "bare-host",
            "bare-host-trailing-slash",
            "bare-host-with-whitespace",
            "bare-host-with-port",
            "bare-host-with-subpath",
            "host-starting-with-http",
            "https",
            "https-trailing-slash",
            "http",
            "uppercase-scheme-lowercased",
            "uppercase-scheme-keeps-the-host-case",
            "https-with-port-and-subpath",
            "bare-ipv6-with-port",
            "bare-underscore-host",
            "bare-underscore-host-with-port",
            "https-underscore-host-with-port",
            "bare-idn-host",
            "bare-host-with-trailing-dot",
            "percent-escape-in-the-path-is-kept",
            "empty-is-the-default",
            "blank-is-the-default",
            "none-is-the-default",
        ],
    )
    def test_the_repository_is_cloned_from_the_host_the_url_names(
        self, tmp_path, url, cloned
    ):
        rows, run, _scan_repo, askpass_written = self._scan(tmp_path, url)

        clone_cmd = run.call_args.args[0]
        assert clone_cmd[-2] == cloned
        assert not any(self.TOKEN in str(arg) for arg in clone_cmd)
        assert run.call_args.kwargs["env"]["GIT_ASKPASS_TOKEN"] == self.TOKEN
        assert rows["trufflehog"].state is State.RAN
        # The spy sees the helper being written, so the abandoned cases below
        # asserting that it was not written can fail.
        assert askpass_written == [True]

    # (value, text its reason carries). What the reason never carries is the value.
    ABANDONED = [
        # A transport this scan does not clone over.
        pytest.param("ssh://git@gitlab.example.com", "ssh://", id="ssh"),
        pytest.param(
            "ssh://git@gitlab.example.com/", "ssh://", id="ssh-trailing-slash"
        ),
        pytest.param("git://gitlab.example.com", "git://", id="git"),
        pytest.param("ftp://gitlab.example.com", "ftp://", id="ftp"),
        pytest.param("file:///srv/git", "file://", id="file"),
        pytest.param("SSH://gitlab.example.com", "ssh://", id="uppercase-ssh"),
        pytest.param("git@gitlab.example.com:group/app", "user@host:", id="scp-style"),
        # No host: curl skips an empty authority and takes the first path segment,
        # `group` here, as the host.
        pytest.param("https://", "names no host", id="https-and-nothing"),
        pytest.param("http:///", "names no host", id="http-and-slash"),
        pytest.param("https:///sub", "names no host", id="https-empty-authority"),
        pytest.param("HTTPS:///sub", "names no host", id="uppercase-empty-authority"),
        pytest.param("/", "does not start with a host", id="slash"),
        pytest.param("//", "does not start with a host", id="two-slashes"),
        pytest.param("///", "does not start with a host", id="three-slashes"),
        pytest.param(" / ", "does not start with a host", id="slash-with-whitespace"),
        pytest.param("/sub", "does not start with a host", id="path-only"),
        pytest.param("host:/x", "no port", id="colon-slash"),
        pytest.param("https://gitlab.example.com:/x", "no port", id="empty-port"),
        # A mistyped scheme is read as a host called `https` or `http`: git took
        # it for the host and CONNECTed to it.
        pytest.param("https:/gitlab.example.com", "scheme word", id="https-one-slash"),
        pytest.param("http:/gitlab.example.com", "scheme word", id="http-one-slash"),
        pytest.param("https//gitlab.example.com", "scheme word", id="https-no-colon"),
        pytest.param("http//gitlab.example.com", "scheme word", id="http-no-colon"),
        pytest.param("https/gitlab.example.com", "scheme word", id="https-slash-only"),
        pytest.param(
            "https://https://evil.com", "scheme word", id="https-twice-with-slashes"
        ),
        pytest.param(
            "https://https:/evil.com", "scheme word", id="https-twice-one-slash"
        ),
        pytest.param("HTTP://http/x", "scheme word", id="uppercase-http-host"),
        # A DNS name ends in a root dot as well, so `https.` is the host `https`.
        pytest.param(
            "https.//gitlab.example.com", "scheme word", id="https-dot-slashes"
        ),
        pytest.param("https./gitlab.example.com", "scheme word", id="https-dot-slash"),
        pytest.param("http.//gitlab.example.com", "scheme word", id="http-dot-slashes"),
        pytest.param("https://https.//evil.com", "scheme word", id="https-twice-dot"),
        pytest.param("HTTPS://HTTP../x", "scheme word", id="uppercase-two-dots"),
        # No GitLab host is written with a percent escape, and a client may decode
        # one to a host this check never saw: `%68ttps` is `https`.
        pytest.param("%68ttps//gitlab.example.com", "% escape", id="percent-https"),
        pytest.param(
            "https://%67itlab.example.com", "% escape", id="percent-in-host-letter"
        ),
        pytest.param(
            "https://gitlab.example.com%2eevil.com", "% escape", id="percent-dot"
        ),
        pytest.param("https://[fe80::1%25eth0]:8443", "% escape", id="percent-zone"),
        # git resolves a host written before an `@` to the part after it.
        pytest.param(
            "https://gitlab.example.com@evil.com/", "--gitlab-token", id="host-at-host"
        ),
        pytest.param(
            "gitlab.example.com@evil.com", "--gitlab-token", id="bare-host-at-host"
        ),
        # A value with no scheme is screened for `@` anywhere, before it is a URL.
        pytest.param(
            "gitlab.example.com/a@b", "--gitlab-token", id="bare-at-sign-in-path"
        ),
        pytest.param(
            "https://user:pw@gitlab.example.com", "--gitlab-token", id="userinfo"
        ),
        pytest.param("https://host\\@evil.com", "backslash", id="backslash-at-host"),
        pytest.param(
            "https://gitlab.example.com\\evil.com", "backslash", id="backslash"
        ),
        pytest.param("gitlab .example.com", "whitespace", id="inner-whitespace"),
        pytest.param(
            "https://gitlab.example.com/a b", "whitespace", id="whitespace-in-path"
        ),
        pytest.param("https://gitlab.example.com?@evil.com", "?", id="query"),
        pytest.param("https://gitlab.example.com#x", "#", id="fragment"),
        pytest.param(
            "https://gitlab.example.com:99999", "not a valid URL", id="port-range"
        ),
        pytest.param("https://[::1", "not a valid URL", id="unclosed-ipv6"),
    ]

    @pytest.mark.parametrize(("url", "named"), ABANDONED)
    def test_a_url_git_would_not_clone_from_the_host_it_names_is_abandoned_before_git_runs(
        self, tmp_path, caplog, url, named
    ):
        with caplog.at_level(logging.DEBUG):
            rows, run, scan_repo, askpass_written = self._scan(tmp_path, url)

        assert not run.called, "git was started for a URL this scan refuses"
        assert not scan_repo.called
        # The token reaches git through the helper and the environment of the
        # clone, both built only for a URL that will be cloned.
        assert askpass_written == [], "a credential helper was set up"
        for tool in ("trufflehog", "opengrep"):
            assert rows[tool].label == "failed:target not scanned"
            assert named in (rows[tool].detail or "")
            assert self.TOKEN not in (rows[tool].detail or "")
            assert url.strip() not in (rows[tool].detail or "")
        assert self.TOKEN not in caplog.text

    @pytest.mark.parametrize(
        ("url", "named"),
        [
            pytest.param(
                "ssh://deploy:hunter2@gitlab.example.com/", "ssh://", id="ssh-userinfo"
            ),
            pytest.param(
                "https://deploy:hunter2@gitlab.example.com/",
                "--gitlab-token",
                id="https-userinfo",
            ),
        ],
    )
    def test_a_reason_does_not_repeat_credentials_typed_into_the_url(
        self, tmp_path, caplog, url, named
    ):
        with caplog.at_level(logging.DEBUG):
            rows, run, _scan_repo, _askpass = self._scan(tmp_path, url)

        assert not run.called
        assert named in (rows["trufflehog"].detail or "")
        assert "hunter2" not in (rows["trufflehog"].detail or "")
        assert "hunter2" not in caplog.text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
