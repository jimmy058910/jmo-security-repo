"""
Tests for base_scanner.py - Abstract scanner base class.

Coverage targets:
- BaseScanner abstract methods (scan, get_applicable_tools)
- ScanResult dataclass
- Helper methods (_create_output_dir, _sanitize_name)
- Configuration handling
"""

import pytest
from pathlib import Path
from dataclasses import asdict

from scripts.cli.scan_jobs.base_scanner import BaseScanner, ScanResult


class ConcreteScanner(BaseScanner):
    """Concrete implementation for testing abstract base class."""

    def scan(self, target, results_dir, tools, args):
        """Minimal scan implementation."""
        return ScanResult(
            target_id=str(target),
            target_type="test",
            tool_statuses={"tool1": True, "tool2": False},
            output_files={"tool1": Path("/tmp/tool1.json")},
            errors=["tool2 failed"],
            duration=10.5,
            metadata={"test_key": "test_value"},
        )

    def get_applicable_tools(self, tools):
        """Return filtered tools list."""
        # Only return tools that start with 'test_'
        return [t for t in tools if t.startswith("test_")]


def test_base_scanner_is_abstract():
    """Test that BaseScanner cannot be instantiated directly."""
    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        BaseScanner(config=None)  # type: ignore


def test_base_scanner_requires_scan_implementation():
    """Test that scan() must be implemented."""

    class IncompleteScannerA(BaseScanner):
        def get_applicable_tools(self, tools):
            return tools

    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        IncompleteScannerA(config=None)  # type: ignore


def test_base_scanner_requires_get_applicable_tools_implementation():
    """Test that get_applicable_tools() must be implemented."""

    class IncompleteScannerB(BaseScanner):
        def scan(self, target, results_dir, tools, args):
            pass

    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        IncompleteScannerB(config=None)  # type: ignore


def test_concrete_scanner_initialization():
    """Test concrete scanner can be initialized with config."""

    class MockConfig:
        tools = ["test_tool1", "test_tool2"]
        timeout = 300

    scanner = ConcreteScanner(config=MockConfig())
    assert scanner.config is not None
    assert scanner.config.tools == ["test_tool1", "test_tool2"]
    assert scanner.config.timeout == 300


def test_concrete_scanner_scan_returns_scan_result():
    """Test that scan() returns ScanResult object."""

    class MockConfig:
        pass

    scanner = ConcreteScanner(config=MockConfig())
    result = scanner.scan(
        target="/tmp/repo",
        results_dir=Path("/tmp/results"),
        tools=["tool1", "tool2"],
        args=None,
    )

    assert isinstance(result, ScanResult)
    assert result.target_id == "/tmp/repo"
    assert result.target_type == "test"
    assert result.tool_statuses == {"tool1": True, "tool2": False}
    assert result.output_files == {"tool1": Path("/tmp/tool1.json")}
    assert result.errors == ["tool2 failed"]
    assert result.duration == 10.5
    assert result.metadata == {"test_key": "test_value"}


def test_get_applicable_tools_filters_correctly():
    """Test get_applicable_tools() filters tools list."""

    class MockConfig:
        pass

    scanner = ConcreteScanner(config=MockConfig())
    all_tools = ["test_trivy", "semgrep", "test_bandit", "checkov", "test_gosec"]
    filtered = scanner.get_applicable_tools(all_tools)

    assert filtered == ["test_trivy", "test_bandit", "test_gosec"]


def test_create_output_dir(tmp_path):
    """Test _create_output_dir() creates target-specific directory."""

    class MockConfig:
        pass

    scanner = ConcreteScanner(config=MockConfig())

    # Test repository target type
    output_dir = scanner._create_output_dir(
        base_dir=tmp_path, target_type="repo", safe_name="myrepo"
    )

    assert output_dir.exists()
    assert output_dir.is_dir()
    assert output_dir == tmp_path / "individual-repos" / "myrepo"


def test_create_output_dir_multiple_target_types(tmp_path):
    """Test _create_output_dir() works for all target types."""

    class MockConfig:
        pass

    scanner = ConcreteScanner(config=MockConfig())

    target_types = ["repo", "image", "iac", "url", "gitlab", "k8s"]
    for target_type in target_types:
        output_dir = scanner._create_output_dir(
            base_dir=tmp_path, target_type=target_type, safe_name="test-target"
        )

        assert output_dir.exists()
        assert output_dir == tmp_path / f"individual-{target_type}s" / "test-target"


def test_create_output_dir_idempotent(tmp_path):
    """Test _create_output_dir() can be called multiple times."""

    class MockConfig:
        pass

    scanner = ConcreteScanner(config=MockConfig())

    # Call twice with same parameters
    output_dir1 = scanner._create_output_dir(
        base_dir=tmp_path, target_type="repo", safe_name="myrepo"
    )
    output_dir2 = scanner._create_output_dir(
        base_dir=tmp_path, target_type="repo", safe_name="myrepo"
    )

    assert output_dir1 == output_dir2
    assert output_dir1.exists()


def test_sanitize_name_basic():
    """Test _sanitize_name() replaces unsafe characters."""

    class MockConfig:
        pass

    scanner = ConcreteScanner(config=MockConfig())

    # Test basic sanitization
    assert scanner._sanitize_name("my-repo") == "my-repo"
    assert scanner._sanitize_name("my_repo") == "my_repo"
    assert scanner._sanitize_name("my.repo") == "my.repo"


def test_sanitize_name_special_characters():
    """Test _sanitize_name() handles special characters."""

    class MockConfig:
        pass

    scanner = ConcreteScanner(config=MockConfig())

    # Test special characters replaced with underscores
    assert scanner._sanitize_name("nginx:latest") == "nginx_latest"
    assert scanner._sanitize_name("my/repo") == "my_repo"
    assert scanner._sanitize_name("my repo") == "my_repo"
    assert scanner._sanitize_name("my@repo") == "my_repo"
    assert scanner._sanitize_name("my#repo") == "my_repo"


def test_sanitize_name_multiple_replacements():
    """Test _sanitize_name() handles multiple special characters."""

    class MockConfig:
        pass

    scanner = ConcreteScanner(config=MockConfig())

    # Test complex sanitization
    assert (
        scanner._sanitize_name("gcr.io/myproject/myimage:v1.2.3")
        == "gcr.io_myproject_myimage_v1.2.3"
    )
    assert (
        scanner._sanitize_name("https://example.com/path") == "https___example.com_path"
    )


def test_sanitize_name_preserves_allowed_chars():
    """Test _sanitize_name() preserves allowed characters."""

    class MockConfig:
        pass

    scanner = ConcreteScanner(config=MockConfig())

    # Test allowed characters preserved
    allowed = "abc123XYZ.-_"
    assert scanner._sanitize_name(allowed) == allowed


def test_scan_result_dataclass():
    """Test ScanResult dataclass can be created and accessed."""
    result = ScanResult(
        target_id="test-target",
        target_type="repo",
        tool_statuses={"trivy": True},
        output_files={"trivy": Path("/tmp/trivy.json")},
        errors=[],
        duration=5.0,
        metadata={"commit": "abc123"},
    )

    assert result.target_id == "test-target"
    assert result.target_type == "repo"
    assert result.tool_statuses == {"trivy": True}
    assert result.output_files == {"trivy": Path("/tmp/trivy.json")}
    assert result.errors == []
    assert result.duration == 5.0
    assert result.metadata == {"commit": "abc123"}


def test_scan_result_with_errors():
    """Test ScanResult can store multiple errors."""
    result = ScanResult(
        target_id="test-target",
        target_type="repo",
        tool_statuses={"tool1": False, "tool2": False},
        output_files={},
        errors=["tool1 timeout", "tool2 missing"],
        duration=10.0,
        metadata={},
    )

    assert len(result.errors) == 2
    assert "tool1 timeout" in result.errors
    assert "tool2 missing" in result.errors


def test_scan_result_empty_metadata():
    """Test ScanResult with empty metadata."""
    result = ScanResult(
        target_id="test-target",
        target_type="repo",
        tool_statuses={},
        output_files={},
        errors=[],
        duration=0.0,
        metadata={},
    )

    assert result.metadata == {}
    assert len(result.errors) == 0


def test_scan_result_dataclass_asdict():
    """Test ScanResult can be converted to dict."""
    result = ScanResult(
        target_id="test-target",
        target_type="repo",
        tool_statuses={"trivy": True},
        output_files={"trivy": Path("/tmp/trivy.json")},
        errors=[],
        duration=5.0,
        metadata={"key": "value"},
    )

    result_dict = asdict(result)
    assert result_dict["target_id"] == "test-target"
    assert result_dict["target_type"] == "repo"
    assert result_dict["tool_statuses"] == {"trivy": True}
    assert result_dict["duration"] == 5.0
