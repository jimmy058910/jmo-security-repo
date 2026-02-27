"""Tests for BaseScanner."""

from pathlib import Path
from scripts.cli.scan_jobs.base_scanner import BaseScanner, ScanResult
from scripts.cli.scan_orchestrator import ScanConfig


class MockScanner(BaseScanner):
    """Mock implementation of BaseScanner for testing."""

    def scan(self, target, results_dir, tools, args):
        """Minimal scan implementation for testing."""
        return ScanResult(
            target_id=str(target),
            target_type="test",
            tool_statuses={},
            output_files={},
            errors=[],
            duration=0.0,
            metadata={},
        )

    def get_applicable_tools(self, tools):
        """Return all tools for testing."""
        return tools


def test_create_output_dir(tmp_path):
    """Test output directory creation."""
    config = ScanConfig(tools=["trivy"], results_dir=tmp_path)
    scanner = MockScanner(config)

    output_dir = scanner._create_output_dir(tmp_path, "repo", "test-repo")

    assert output_dir.exists()
    assert output_dir == tmp_path / "individual-repos" / "test-repo"


def test_create_output_dir_with_nested_path(tmp_path):
    """Test output directory creation with nested paths."""
    config = ScanConfig(tools=["trivy"], results_dir=tmp_path)
    scanner = MockScanner(config)

    output_dir = scanner._create_output_dir(tmp_path, "image", "registry_image_tag")

    assert output_dir.exists()
    assert output_dir == tmp_path / "individual-images" / "registry_image_tag"


def test_sanitize_name_simple():
    """Test name sanitization for simple names."""
    config = ScanConfig(tools=["trivy"], results_dir=Path("/tmp"))
    scanner = MockScanner(config)

    assert scanner._sanitize_name("my-repo") == "my-repo"
    assert scanner._sanitize_name("my_repo") == "my_repo"
    assert scanner._sanitize_name("my.repo") == "my.repo"


def test_sanitize_name_with_special_chars():
    """Test name sanitization with special characters."""
    config = ScanConfig(tools=["trivy"], results_dir=Path("/tmp"))
    scanner = MockScanner(config)

    assert scanner._sanitize_name("my/repo:tag") == "my_repo_tag"
    assert (
        scanner._sanitize_name("registry/image@sha256:abc")
        == "registry_image_sha256_abc"
    )
    assert scanner._sanitize_name("my repo") == "my_repo"
    assert scanner._sanitize_name("my?repo") == "my_repo"


def test_sanitize_name_preserves_valid_chars():
    """Test that sanitization preserves valid characters."""
    config = ScanConfig(tools=["trivy"], results_dir=Path("/tmp"))
    scanner = MockScanner(config)

    valid_name = "my-valid.repo_123"
    assert scanner._sanitize_name(valid_name) == valid_name


def test_scan_result_dataclass():
    """Test ScanResult dataclass creation."""
    result = ScanResult(
        target_id="/path/to/repo",
        target_type="repo",
        tool_statuses={"trivy": True, "syft": False},
        output_files={"trivy": Path("/tmp/trivy.json")},
        errors=["Error 1", "Error 2"],
        duration=10.5,
        metadata={"repo_name": "test-repo"},
    )

    assert result.target_id == "/path/to/repo"
    assert result.target_type == "repo"
    assert result.tool_statuses == {"trivy": True, "syft": False}
    assert result.output_files == {"trivy": Path("/tmp/trivy.json")}
    assert result.errors == ["Error 1", "Error 2"]
    assert result.duration == 10.5
    assert result.metadata == {"repo_name": "test-repo"}


def test_scanner_has_config():
    """Test that scanner stores config."""
    config = ScanConfig(tools=["trivy", "syft"], results_dir=Path("/tmp"))
    scanner = MockScanner(config)

    assert scanner.config == config
    assert scanner.config.tools == ["trivy", "syft"]
