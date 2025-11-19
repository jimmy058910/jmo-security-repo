"""
Tests for repository_scanner.py - Repository scanning functionality.

Coverage targets:
- Tool invocation (trufflehog, semgrep, trivy, syft, checkov, hadolint, bandit)
- ToolRunner integration
- Error handling (missing tools, timeouts)
- Per-tool configuration (flags, timeouts)
- Allow-missing-tools flag handling
- Result aggregation
"""

import pytest
from pathlib import Path
from unittest.mock import patch

from scripts.cli.scan_jobs.repository_scanner import scan_repository
from scripts.core.tool_runner import ToolResult


@pytest.fixture
def mock_repo(tmp_path):
    """Create a mock repository with various file types."""
    repo = tmp_path / "test-repo"
    repo.mkdir()

    # Add a Python file
    (repo / "app.py").write_text("print('hello')")

    # Add a Dockerfile
    (repo / "Dockerfile").write_text("FROM python:3.11\nRUN pip install flask")

    # Add a .github/workflows directory
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: CI\non: [push]")

    return repo


def test_scan_repository_basic_success(tmp_path, mock_repo):
    """Test basic repository scan with mock tools."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    # Mock tool_exists and ToolRunner
    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=True
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            # Mock successful tool results
            mock_results = [
                ToolResult(
                    tool="trufflehog",
                    status="success",
                    stdout='{"key": "value"}',
                    stderr="",
                    returncode=0,
                    duration=1.0,
                    attempts=1,
                    output_file=results_dir / "test-repo" / "trufflehog.json",
                    capture_stdout=True,
                    error_message="",
                ),
                ToolResult(
                    tool="semgrep",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=2.0,
                    attempts=1,
                    output_file=results_dir / "test-repo" / "semgrep.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            name, statuses = scan_repository(
                repo=mock_repo,
                results_dir=results_dir,
                tools=["trufflehog", "semgrep"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert name == "test-repo"
            assert statuses["trufflehog"] is True
            assert statuses["semgrep"] is True


def test_scan_repository_missing_tools_no_allow(tmp_path, mock_repo):
    """Test scan fails when tools missing and allow_missing_tools=False."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=False
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            # Return empty results (no tools run)
            MockRunner.return_value.run_all_parallel.return_value = []

            name, statuses = scan_repository(
                repo=mock_repo,
                results_dir=results_dir,
                tools=["trufflehog", "semgrep"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert name == "test-repo"
            # Tools not in statuses dict when missing and not allowed
            assert "trufflehog" not in statuses
            assert "semgrep" not in statuses


def test_scan_repository_missing_tools_with_allow(tmp_path, mock_repo):
    """Test scan writes stubs when tools missing and allow_missing_tools=True."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=False
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.write_stub") as mock_stub:
            with patch(
                "scripts.cli.scan_jobs.repository_scanner.ToolRunner"
            ) as MockRunner:
                MockRunner.return_value.run_all_parallel.return_value = []

                name, statuses = scan_repository(
                    repo=mock_repo,
                    results_dir=results_dir,
                    tools=["trufflehog", "semgrep"],
                    timeout=300,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=True,
                )

                assert name == "test-repo"
                # Stubs written for missing tools
                assert statuses["trufflehog"] is True
                assert statuses["semgrep"] is True
                assert mock_stub.call_count == 2


def test_scan_repository_per_tool_timeout(tmp_path, mock_repo):
    """Test per-tool timeout configuration."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    per_tool_config = {
        "trivy": {"timeout": 1200},  # Custom timeout for trivy
        "semgrep": {"timeout": 600},  # Custom timeout for semgrep
    }

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=True
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=10.0,
                    attempts=1,
                    output_file=results_dir / "test-repo" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_repository(
                repo=mock_repo,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,  # Default timeout
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
            )

            # Verify ToolRunner called with tools
            MockRunner.assert_called_once()
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]

            # Find trivy tool definition
            trivy_def = next(t for t in tools_passed if t.name == "trivy")
            assert trivy_def.timeout == 1200  # Custom timeout used


def test_scan_repository_per_tool_flags(tmp_path, mock_repo):
    """Test per-tool flags configuration."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    per_tool_config = {
        "semgrep": {"flags": ["--exclude", "node_modules", "--exclude", ".git"]},
    }

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=True
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="semgrep",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=results_dir / "test-repo" / "semgrep.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_repository(
                repo=mock_repo,
                results_dir=results_dir,
                tools=["semgrep"],
                timeout=300,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
            )

            # Verify flags passed to semgrep
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            semgrep_def = next(t for t in tools_passed if t.name == "semgrep")

            assert "--exclude" in semgrep_def.command
            assert "node_modules" in semgrep_def.command


def test_scan_repository_tool_failure(tmp_path, mock_repo):
    """Test handling of tool execution failures."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=True
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            # Mock tool failure
            mock_results = [
                ToolResult(
                    tool="semgrep",
                    status="error",
                    stdout="",
                    stderr="timeout",
                    returncode=124,
                    duration=300.0,
                    attempts=1,
                    output_file=results_dir / "test-repo" / "semgrep.json",
                    capture_stdout=False,
                    error_message="Timeout after 300s",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            name, statuses = scan_repository(
                repo=mock_repo,
                results_dir=results_dir,
                tools=["semgrep"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["semgrep"] is False


def test_scan_repository_retry_tracking(tmp_path, mock_repo):
    """Test retry tracking in __attempts__ metadata."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=True
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            # Mock tool that succeeded after retries
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=10.0,
                    attempts=3,  # Required 3 attempts
                    output_file=results_dir / "test-repo" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            name, statuses = scan_repository(
                repo=mock_repo,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=2,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["trivy"] is True
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["trivy"] == 3


def test_scan_repository_hadolint_dockerfile_detection(tmp_path, mock_repo):
    """Test hadolint only runs when Dockerfile present."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=True
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="hadolint",
                    status="success",
                    stdout='[{"level":"warning"}]',
                    stderr="",
                    returncode=0,
                    duration=1.0,
                    attempts=1,
                    output_file=results_dir / "test-repo" / "hadolint.json",
                    capture_stdout=True,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_repository(
                repo=mock_repo,
                results_dir=results_dir,
                tools=["hadolint"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Verify hadolint was invoked (Dockerfile exists in mock_repo)
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            hadolint_def = next((t for t in tools_passed if t.name == "hadolint"), None)

            assert hadolint_def is not None
            assert "hadolint" in hadolint_def.command


def test_scan_repository_hadolint_no_dockerfile(tmp_path):
    """Test hadolint behavior when no Dockerfile present."""
    repo = tmp_path / "no-docker-repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')")

    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=True
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            # hadolint should not be in tool definitions
            MockRunner.return_value.run_all_parallel.return_value = []

            name, statuses = scan_repository(
                repo=repo,
                results_dir=results_dir,
                tools=["hadolint"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
            )

            # Should write stub when no Dockerfile found (allow_missing_tools=True)
            # or not include hadolint if tool doesn't exist
            # In this case, no Dockerfile means hadolint won't run


def test_scan_repository_noseyparker_multi_phase(tmp_path, mock_repo):
    """Test noseyparker multi-phase execution (init, scan, report)."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=True
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            # Mock all three noseyparker phases
            mock_results = [
                ToolResult(
                    tool="noseyparker-init",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=0.5,
                    attempts=1,
                    output_file=None,
                    capture_stdout=False,
                    error_message="",
                ),
                ToolResult(
                    tool="noseyparker-scan",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=None,
                    capture_stdout=False,
                    error_message="",
                ),
                ToolResult(
                    tool="noseyparker-report",
                    status="success",
                    stdout='{"findings": []}',
                    stderr="",
                    returncode=0,
                    duration=1.0,
                    attempts=1,
                    output_file=results_dir / "test-repo" / "noseyparker.json",
                    capture_stdout=True,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            name, statuses = scan_repository(
                repo=mock_repo,
                results_dir=results_dir,
                tools=["noseyparker"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # All three phases succeeded -> noseyparker successful
            assert statuses["noseyparker"] is True


def test_scan_repository_noseyparker_partial_failure(tmp_path, mock_repo):
    """Test noseyparker failure when one phase fails."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=True
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.write_stub") as mock_stub:
            with patch(
                "scripts.cli.scan_jobs.repository_scanner.ToolRunner"
            ) as MockRunner:
                # Mock init success, scan failure
                mock_results = [
                    ToolResult(
                        tool="noseyparker-init",
                        status="success",
                        stdout="",
                        stderr="",
                        returncode=0,
                        duration=0.5,
                        attempts=1,
                        output_file=None,
                        capture_stdout=False,
                        error_message="",
                    ),
                    ToolResult(
                        tool="noseyparker-scan",
                        status="error",
                        stdout="",
                        stderr="timeout",
                        returncode=124,
                        duration=300.0,
                        attempts=1,
                        output_file=None,
                        capture_stdout=False,
                        error_message="Timeout after 300s",
                    ),
                ]
                MockRunner.return_value.run_all_parallel.return_value = mock_results

                name, statuses = scan_repository(
                    repo=mock_repo,
                    results_dir=results_dir,
                    tools=["noseyparker"],
                    timeout=300,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=True,
                )

                # Partial failure -> write stub with allow_missing_tools
                assert statuses["noseyparker"] is True
                mock_stub.assert_called()


def test_scan_repository_checkov_cicd_directory_handling(tmp_path, mock_repo):
    """Test checkov-cicd special directory handling."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=True
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            # Mock checkov-cicd creating temp directory structure
            mock_results = [
                ToolResult(
                    tool="checkov-cicd",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=results_dir
                    / "test-repo"
                    / "checkov-cicd-temp"
                    / "results_json.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            # Create the temp file that checkov would create
            temp_dir = results_dir / "test-repo" / "checkov-cicd-temp"
            temp_dir.mkdir(parents=True)
            temp_file = temp_dir / "results_json.json"
            temp_file.write_text("{}")

            name, statuses = scan_repository(
                repo=mock_repo,
                results_dir=results_dir,
                tools=["checkov-cicd"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["checkov-cicd"] is True
            # Verify final checkov-cicd.json exists after file move
            final_file = results_dir / "test-repo" / "checkov-cicd.json"
            assert final_file.exists()


def test_scan_repository_output_dir_creation(tmp_path, mock_repo):
    """Test output directory created correctly."""
    results_dir = tmp_path / "results"
    # Don't create results_dir - scan_repository should create it

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=False
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            scan_repository(
                repo=mock_repo,
                results_dir=results_dir,
                tools=[],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
            )

            # Verify output directory created
            output_dir = results_dir / "test-repo"
            assert output_dir.exists()
            assert output_dir.is_dir()


def test_scan_repository_custom_tool_exists_func(tmp_path, mock_repo):
    """Test using custom tool_exists_func for testing."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    def mock_tool_exists(tool: str) -> bool:
        """Custom tool existence checker."""
        return tool == "trivy"  # Only trivy exists

    with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
        mock_results = [
            ToolResult(
                tool="trivy",
                status="success",
                stdout="",
                stderr="",
                returncode=0,
                duration=5.0,
                attempts=1,
                output_file=results_dir / "test-repo" / "trivy.json",
                capture_stdout=False,
                error_message="",
            ),
        ]
        MockRunner.return_value.run_all_parallel.return_value = mock_results

        name, statuses = scan_repository(
            repo=mock_repo,
            results_dir=results_dir,
            tools=["trivy", "semgrep"],
            timeout=300,
            retries=0,
            per_tool_config={},
            allow_missing_tools=True,
            tool_exists_func=mock_tool_exists,
        )

        # Only trivy should run
        assert "trivy" in statuses
        # semgrep should have stub written
        assert "semgrep" in statuses


def test_scan_repository_custom_write_stub_func(tmp_path, mock_repo):
    """Test using custom write_stub_func for testing."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    stub_calls = []

    def mock_write_stub(tool: str, path: Path) -> None:
        """Custom stub writer that tracks calls."""
        stub_calls.append((tool, path))

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.tool_exists", return_value=False
    ):
        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            scan_repository(
                repo=mock_repo,
                results_dir=results_dir,
                tools=["trivy", "semgrep"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                write_stub_func=mock_write_stub,
            )

            # Verify stub writer called
            assert len(stub_calls) == 2
            assert ("trivy", results_dir / "test-repo" / "trivy.json") in stub_calls
            assert ("semgrep", results_dir / "test-repo" / "semgrep.json") in stub_calls
