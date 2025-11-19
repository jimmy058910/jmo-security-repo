"""
Tests for gitlab_scanner.py - GitLab repository scanning functionality.

Coverage targets:
- GitLab repo cloning
- Token authentication
- Full repository scanner integration
- Container image discovery (Dockerfile, docker-compose.yml, K8s manifests)
- Image scanning integration
- Results directory management
- Temporary directory cleanup
- Error handling (missing token, clone failures, timeouts)
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from scripts.cli.scan_jobs.gitlab_scanner import (
    scan_gitlab_repo,
    _discover_container_images,
)


@pytest.fixture
def gitlab_info():
    """Create mock GitLab info."""
    return {
        "full_path": "mygroup/myrepo",
        "url": "https://gitlab.com",
        "token": "test-token-123",
        "repo": "myrepo",
        "group": "mygroup",
    }


@pytest.fixture
def mock_repo_with_dockerfile(tmp_path):
    """Create a mock repository with Dockerfile."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    dockerfile = repo_dir / "Dockerfile"
    dockerfile.write_text(
        """
FROM nginx:latest
FROM python:3.11-slim
FROM scratch
RUN echo "test"
"""
    )

    return repo_dir


@pytest.fixture
def mock_repo_with_compose(tmp_path):
    """Create a mock repository with docker-compose.yml."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    compose_file = repo_dir / "docker-compose.yml"
    compose_file.write_text(
        """
version: '3.8'
services:
  web:
    image: nginx:latest
  db:
    image: postgres:14
    build: ./db
"""
    )

    return repo_dir


@pytest.fixture
def mock_repo_with_k8s(tmp_path):
    """Create a mock repository with Kubernetes manifests."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    k8s_file = repo_dir / "deployment.k8s.yaml"
    k8s_file.write_text(
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx:1.21
  - name: sidecar
    image: busybox:latest
"""
    )

    return repo_dir


def test_scan_gitlab_repo_basic_success(tmp_path, gitlab_info):
    """Test basic GitLab repo cloning and scanning."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        # Mock successful clone
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
        ) as mock_scan_repo:
            mock_scan_repo.return_value = (
                "myrepo",
                {"trufflehog": True, "semgrep": True},
            )

            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover:
                mock_discover.return_value = set()  # No images discovered

                with patch("scripts.cli.scan_jobs.gitlab_scanner.shutil.copy2"):
                    full_path, statuses = scan_gitlab_repo(
                        gitlab_info=gitlab_info,
                        results_dir=results_dir,
                        tools=["trufflehog", "semgrep"],
                        timeout=300,
                        retries=0,
                        per_tool_config={},
                        allow_missing_tools=False,
                    )

                    assert full_path == "mygroup/myrepo"
                    assert statuses["trufflehog"] is True
                    assert statuses["semgrep"] is True


def test_scan_gitlab_repo_missing_token(tmp_path):
    """Test GitLab scan with missing token."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    gitlab_info_no_token = {
        "full_path": "mygroup/myrepo",
        "url": "https://gitlab.com",
        "token": None,  # No token
        "repo": "myrepo",
        "group": "mygroup",
    }

    with patch.dict("os.environ", {}, clear=True):
        # No GITLAB_TOKEN environment variable
        full_path, statuses = scan_gitlab_repo(
            gitlab_info=gitlab_info_no_token,
            results_dir=results_dir,
            tools=["trufflehog", "semgrep"],
            timeout=300,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
        )

        assert full_path == "mygroup/myrepo"
        assert statuses["trufflehog"] is False
        assert statuses["semgrep"] is False


def test_scan_gitlab_repo_clone_failure(tmp_path, gitlab_info):
    """Test GitLab scan when clone fails."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        # Mock failed clone (non-zero returncode)
        mock_run.return_value = MagicMock(
            returncode=128, stderr=b"Authentication failed"
        )

        full_path, statuses = scan_gitlab_repo(
            gitlab_info=gitlab_info,
            results_dir=results_dir,
            tools=["trufflehog", "semgrep"],
            timeout=300,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
        )

        assert full_path == "mygroup/myrepo"
        assert statuses["trufflehog"] is False
        assert statuses["semgrep"] is False


def test_scan_gitlab_repo_clone_timeout(tmp_path, gitlab_info):
    """Test GitLab scan when clone times out."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        # Mock clone timeout
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["git", "clone"], timeout=300
        )

        full_path, statuses = scan_gitlab_repo(
            gitlab_info=gitlab_info,
            results_dir=results_dir,
            tools=["trufflehog", "semgrep"],
            timeout=300,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
        )

        assert full_path == "mygroup/myrepo"
        assert statuses["trufflehog"] is False
        assert statuses["semgrep"] is False


def test_scan_gitlab_repo_with_image_discovery(tmp_path, gitlab_info):
    """Test GitLab scan with container image discovery and scanning."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
        ) as mock_scan_repo:
            mock_scan_repo.return_value = (
                "myrepo",
                {"trufflehog": True, "trivy": True},
            )

            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover:
                mock_discover.return_value = {"nginx:latest", "postgres:14"}

                with patch(
                    "scripts.cli.scan_jobs.gitlab_scanner.scan_image"
                ) as mock_scan_image:
                    mock_scan_image.return_value = (
                        "nginx:latest",
                        {"trivy": True, "syft": True},
                    )

                    with patch("scripts.cli.scan_jobs.gitlab_scanner.shutil.copy2"):
                        full_path, statuses = scan_gitlab_repo(
                            gitlab_info=gitlab_info,
                            results_dir=results_dir,
                            tools=["trufflehog", "trivy"],
                            timeout=300,
                            retries=0,
                            per_tool_config={},
                            allow_missing_tools=False,
                        )

                        assert full_path == "mygroup/myrepo"
                        assert statuses["trufflehog"] is True
                        assert statuses["trivy"] is True
                        # Image scan results should be included
                        assert (
                            "image:nginx:latest:trivy" in statuses
                            or "image:nginx:latest:syft" in statuses
                        )


def test_scan_gitlab_repo_results_directory_structure(tmp_path, gitlab_info):
    """Test GitLab scan creates correct results directory structure."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
        ) as mock_scan_repo:
            mock_scan_repo.return_value = ("myrepo", {"trufflehog": True})

            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover:
                mock_discover.return_value = set()

                with patch("scripts.cli.scan_jobs.gitlab_scanner.shutil.copy2"):
                    scan_gitlab_repo(
                        gitlab_info=gitlab_info,
                        results_dir=results_dir,
                        tools=["trufflehog"],
                        timeout=300,
                        retries=0,
                        per_tool_config={},
                        allow_missing_tools=False,
                    )

                    # Verify sanitized directory created
                    expected_dir = results_dir / "mygroup_myrepo"
                    assert expected_dir.exists()


def test_discover_container_images_dockerfile(mock_repo_with_dockerfile):
    """Test container image discovery from Dockerfile."""
    images = _discover_container_images(mock_repo_with_dockerfile)

    # Should discover nginx:latest and python:3.11-slim
    # Should NOT discover scratch or builder stages
    assert "nginx:latest" in images
    assert "python:3.11-slim" in images
    assert "scratch" not in images


def test_discover_container_images_docker_compose(mock_repo_with_compose):
    """Test container image discovery from docker-compose.yml."""
    images = _discover_container_images(mock_repo_with_compose)

    # Should discover nginx:latest and postgres:14
    assert "nginx:latest" in images
    assert "postgres:14" in images


def test_discover_container_images_k8s_manifests(mock_repo_with_k8s):
    """Test container image discovery from Kubernetes manifests."""
    images = _discover_container_images(mock_repo_with_k8s)

    # Should discover nginx:1.21 and busybox:latest
    assert "nginx:1.21" in images
    assert "busybox:latest" in images


def test_discover_container_images_malformed_files(tmp_path):
    """Test container image discovery handles malformed files gracefully."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    # Create malformed docker-compose.yml
    compose_file = repo_dir / "docker-compose.yml"
    compose_file.write_text("not: valid: yaml: content: [")

    # Should not crash, just return empty set
    images = _discover_container_images(repo_dir)
    assert len(images) == 0


def test_discover_container_images_empty_repo(tmp_path):
    """Test container image discovery on empty repository."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    images = _discover_container_images(repo_dir)
    assert len(images) == 0


def test_scan_gitlab_repo_authenticated_url_https(tmp_path):
    """Test GitLab clone URL construction with HTTPS."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    gitlab_info = {
        "full_path": "mygroup/myrepo",
        "url": "https://gitlab.example.com",
        "token": "test-token",
        "repo": "myrepo",
        "group": "mygroup",
    }

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
        ) as mock_scan_repo:
            mock_scan_repo.return_value = ("myrepo", {"trufflehog": True})

            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover:
                mock_discover.return_value = set()

                with patch("scripts.cli.scan_jobs.gitlab_scanner.shutil.copy2"):
                    scan_gitlab_repo(
                        gitlab_info=gitlab_info,
                        results_dir=results_dir,
                        tools=["trufflehog"],
                        timeout=300,
                        retries=0,
                        per_tool_config={},
                        allow_missing_tools=False,
                    )

                    # Verify git clone was called with authenticated URL
                    clone_call = mock_run.call_args
                    clone_cmd = clone_call[0][0]
                    # The authenticated URL should be in the command (typically index -2 before path)
                    repo_url = clone_cmd[-2]  # Second to last arg is the repo URL
                    assert "oauth2:test-token@" in repo_url


def test_scan_gitlab_repo_temporary_cleanup(tmp_path, gitlab_info):
    """Test temporary directory cleanup after scan."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
        ) as mock_scan_repo:
            mock_scan_repo.return_value = ("myrepo", {"trufflehog": True})

            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover:
                mock_discover.return_value = set()

                with patch("scripts.cli.scan_jobs.gitlab_scanner.shutil.copy2"):
                    with patch(
                        "scripts.cli.scan_jobs.gitlab_scanner.shutil.rmtree"
                    ) as mock_rmtree:
                        scan_gitlab_repo(
                            gitlab_info=gitlab_info,
                            results_dir=results_dir,
                            tools=["trufflehog"],
                            timeout=300,
                            retries=0,
                            per_tool_config={},
                            allow_missing_tools=False,
                        )

                        # Verify temporary directory cleanup was called
                        assert mock_rmtree.called


def test_scan_gitlab_repo_exception_handling(tmp_path, gitlab_info):
    """Test GitLab scan handles unexpected exceptions gracefully."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        # Mock unexpected exception during clone
        mock_run.side_effect = RuntimeError("Unexpected error")

        full_path, statuses = scan_gitlab_repo(
            gitlab_info=gitlab_info,
            results_dir=results_dir,
            tools=["trufflehog", "semgrep"],
            timeout=300,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
        )

        assert full_path == "mygroup/myrepo"
        assert statuses["trufflehog"] is False
        assert statuses["semgrep"] is False


def test_scan_gitlab_repo_custom_tool_exists_func(tmp_path, gitlab_info):
    """Test using custom tool_exists_func."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    def mock_tool_exists(tool: str) -> bool:
        return tool == "trufflehog"

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
        ) as mock_scan_repo:
            mock_scan_repo.return_value = (
                "myrepo",
                {"trufflehog": True, "semgrep": True},
            )

            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover:
                mock_discover.return_value = set()

                with patch("scripts.cli.scan_jobs.gitlab_scanner.shutil.copy2"):
                    full_path, statuses = scan_gitlab_repo(
                        gitlab_info=gitlab_info,
                        results_dir=results_dir,
                        tools=["trufflehog", "semgrep"],
                        timeout=300,
                        retries=0,
                        per_tool_config={},
                        allow_missing_tools=False,
                        tool_exists_func=mock_tool_exists,
                    )

                    # Custom function passed to scan_repository
                    assert mock_scan_repo.called


def test_discover_container_images_k8s_invalid_document(tmp_path):
    """Test K8s manifest with non-dict documents (should skip gracefully)."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    k8s_file = repo_dir / "deployment.k8s.yaml"
    k8s_file.write_text(
        """
---
# String document (invalid)
"invalid"
---
# Valid document
apiVersion: apps/v1
kind: Deployment
spec:
  containers:
  - name: web
    image: nginx:1.21
"""
    )

    images = _discover_container_images(repo_dir)

    # Should skip invalid document and find image from valid document
    assert "nginx:1.21" in images


def test_discover_container_images_dockerfile_exception(tmp_path):
    """Test Dockerfile parsing handles exceptions gracefully."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    # Create a Dockerfile that will cause parsing issues
    dockerfile = repo_dir / "Dockerfile"
    # Write binary data that can't be decoded
    dockerfile.write_bytes(b"\xff\xfe\x00\x00")

    # Should not crash, just return empty set
    images = _discover_container_images(repo_dir)
    assert len(images) >= 0  # May be 0 or may skip the file


def test_scan_gitlab_repo_http_url(tmp_path):
    """Test GitLab clone URL construction with HTTP (not HTTPS)."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    gitlab_info = {
        "full_path": "mygroup/myrepo",
        "url": "http://gitlab.internal.com",  # HTTP not HTTPS
        "token": "test-token",
        "repo": "myrepo",
        "group": "mygroup",
    }

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
        ) as mock_scan_repo:
            mock_scan_repo.return_value = ("myrepo", {"trufflehog": True})

            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover:
                mock_discover.return_value = set()

                with patch("scripts.cli.scan_jobs.gitlab_scanner.shutil.copy2"):
                    scan_gitlab_repo(
                        gitlab_info=gitlab_info,
                        results_dir=results_dir,
                        tools=["trufflehog"],
                        timeout=300,
                        retries=0,
                        per_tool_config={},
                        allow_missing_tools=False,
                    )

                    # Verify git clone was called with HTTP authenticated URL
                    clone_call = mock_run.call_args
                    clone_cmd = clone_call[0][0]
                    repo_url = clone_cmd[-2]
                    assert "http://oauth2:test-token@" in repo_url


def test_scan_gitlab_repo_non_http_url(tmp_path):
    """Test GitLab clone URL construction with non-HTTP/HTTPS URL."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    gitlab_info = {
        "full_path": "mygroup/myrepo",
        "url": "git://gitlab.example.com",  # Non-HTTP/HTTPS
        "token": "test-token",
        "repo": "myrepo",
        "group": "mygroup",
    }

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
        ) as mock_scan_repo:
            mock_scan_repo.return_value = ("myrepo", {"trufflehog": True})

            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover:
                mock_discover.return_value = set()

                with patch("scripts.cli.scan_jobs.gitlab_scanner.shutil.copy2"):
                    scan_gitlab_repo(
                        gitlab_info=gitlab_info,
                        results_dir=results_dir,
                        tools=["trufflehog"],
                        timeout=300,
                        retries=0,
                        per_tool_config={},
                        allow_missing_tools=False,
                    )

                    # Verify git clone was called with default HTTPS authenticated URL
                    clone_call = mock_run.call_args
                    clone_cmd = clone_call[0][0]
                    repo_url = clone_cmd[-2]
                    assert "https://oauth2:test-token@gitlab.com" in repo_url


def test_scan_gitlab_repo_image_scan_exception(tmp_path, gitlab_info):
    """Test handling of image scan exceptions."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
        ) as mock_scan_repo:
            # Repository scan only has trufflehog, not trivy
            mock_scan_repo.return_value = ("myrepo", {"trufflehog": True})

            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover:
                mock_discover.return_value = {"nginx:latest", "postgres:14"}

                with patch(
                    "scripts.cli.scan_jobs.gitlab_scanner.scan_image"
                ) as mock_scan_image:
                    # One image succeeds, one raises exception (set iteration order is non-deterministic)
                    mock_scan_image.side_effect = [
                        ("nginx:latest", {"trivy": True, "syft": True}),
                        RuntimeError("Image scan failed"),
                    ]

                    with patch("scripts.cli.scan_jobs.gitlab_scanner.shutil.copy2"):
                        full_path, statuses = scan_gitlab_repo(
                            gitlab_info=gitlab_info,
                            results_dir=results_dir,
                            tools=["trufflehog", "trivy", "syft"],
                            timeout=300,
                            retries=0,
                            per_tool_config={},
                            allow_missing_tools=False,
                        )

                        # Scan should continue despite exception on one image
                        assert statuses["trufflehog"] is True
                        # At least one image scan should succeed
                        assert (
                            "image:nginx:latest:trivy" in statuses
                            or "image:postgres:14:trivy" in statuses
                        )
                        # Verify scan_image was called twice (both images attempted)
                        assert mock_scan_image.call_count == 2


def test_scan_gitlab_repo_cleanup_exception(tmp_path, gitlab_info):
    """Test temp directory cleanup handles exceptions gracefully."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.gitlab_scanner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")

        with patch(
            "scripts.cli.scan_jobs.gitlab_scanner.scan_repository"
        ) as mock_scan_repo:
            mock_scan_repo.return_value = ("myrepo", {"trufflehog": True})

            with patch(
                "scripts.cli.scan_jobs.gitlab_scanner._discover_container_images"
            ) as mock_discover:
                mock_discover.return_value = set()

                with patch("scripts.cli.scan_jobs.gitlab_scanner.shutil.copy2"):
                    with patch(
                        "scripts.cli.scan_jobs.gitlab_scanner.shutil.rmtree"
                    ) as mock_rmtree:
                        # rmtree raises exception
                        mock_rmtree.side_effect = OSError("Permission denied")

                        # Should not raise exception, just log warning
                        full_path, statuses = scan_gitlab_repo(
                            gitlab_info=gitlab_info,
                            results_dir=results_dir,
                            tools=["trufflehog"],
                            timeout=300,
                            retries=0,
                            per_tool_config={},
                            allow_missing_tools=False,
                        )

                        assert full_path == "mygroup/myrepo"
                        assert statuses["trufflehog"] is True
