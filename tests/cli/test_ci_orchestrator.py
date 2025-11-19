"""
Tests for ci_orchestrator.py - CI command orchestration.

Coverage targets:
- cmd_ci orchestrates scan + report
- ScanArgs adapter with all attributes
- ReportArgs adapter with all attributes
- Return exit code from report command
- Default values for missing attributes
- Path conversion for results_dir
- All target types (repo, image, IaC, web, GitLab, K8s)
- History database flags
- Policy flags
- Output format flags
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.ci_orchestrator import cmd_ci


@pytest.fixture
def minimal_args():
    """Create minimal CI arguments."""

    class Args:
        repo = "/path/to/repo"
        results_dir = "results"
        config = "jmo.yml"

    return Args()


@pytest.fixture
def complete_args():
    """Create complete CI arguments with all possible fields."""

    class Args:
        # Repository scanning
        repo = "/path/to/repo"
        repos_dir = "/path/to/repos"
        targets = "/path/to/targets.txt"
        # Container image scanning
        image = "nginx:latest"
        images_file = "/path/to/images.txt"
        # IaC scanning
        terraform_state = "/path/to/terraform.tfstate"
        cloudformation = "/path/to/cloudformation.yaml"
        k8s_manifest = "/path/to/k8s.yaml"
        # Web app/API scanning
        url = "https://example.com"
        urls_file = "/path/to/urls.txt"
        api_spec = "/path/to/api.yaml"
        # GitLab integration
        gitlab_url = "https://gitlab.com"
        gitlab_token = "glpat-token"
        gitlab_group = "mygroup"
        gitlab_repo = "myrepo"
        # Kubernetes cluster scanning
        k8s_context = "minikube"
        k8s_namespace = "default"
        k8s_all_namespaces = True
        # Other options
        results_dir = "results-custom"
        config = "custom-jmo.yml"
        tools = ["trivy", "semgrep"]
        timeout = 900
        threads = 8
        allow_missing_tools = True
        profile_name = "balanced"
        log_level = "DEBUG"
        human_logs = True
        # History database flags
        store_history = True
        history_db = "/path/to/history.db"
        # Report options
        fail_on = "HIGH"
        profile = True
        json = True
        md = True
        html = True
        sarif = True
        yaml = True
        # Policy flags
        policies = ["no_high_severity", "require_cwe"]
        fail_on_policy_violation = True

    return Args()


def test_cmd_ci_minimal_args(minimal_args):
    """Test cmd_ci with minimal arguments."""
    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        rc = cmd_ci(minimal_args, mock_scan, mock_report)

    # Verify scan was called
    assert mock_scan.called
    scan_args = mock_scan.call_args[0][0]
    assert scan_args.repo == "/path/to/repo"
    assert scan_args.results_dir == "results"
    assert scan_args.config == "jmo.yml"

    # Verify report was called
    assert mock_report.called
    report_args = mock_report.call_args[0][0]
    assert report_args.results_dir == "results"
    assert report_args.config == "jmo.yml"

    # Verify return code from report
    assert rc == 0


def test_cmd_ci_complete_args(complete_args):
    """Test cmd_ci with all possible arguments."""
    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=2)

    with patch("scripts.cli.jmo._log"):
        rc = cmd_ci(complete_args, mock_scan, mock_report)

    # Verify scan was called with all arguments
    scan_args = mock_scan.call_args[0][0]
    assert scan_args.repo == "/path/to/repo"
    assert scan_args.repos_dir == "/path/to/repos"
    assert scan_args.targets == "/path/to/targets.txt"
    assert scan_args.image == "nginx:latest"
    assert scan_args.images_file == "/path/to/images.txt"
    assert scan_args.terraform_state == "/path/to/terraform.tfstate"
    assert scan_args.cloudformation == "/path/to/cloudformation.yaml"
    assert scan_args.k8s_manifest == "/path/to/k8s.yaml"
    assert scan_args.url == "https://example.com"
    assert scan_args.urls_file == "/path/to/urls.txt"
    assert scan_args.api_spec == "/path/to/api.yaml"
    assert scan_args.gitlab_url == "https://gitlab.com"
    assert scan_args.gitlab_token == "glpat-token"
    assert scan_args.gitlab_group == "mygroup"
    assert scan_args.gitlab_repo == "myrepo"
    assert scan_args.k8s_context == "minikube"
    assert scan_args.k8s_namespace == "default"
    assert scan_args.k8s_all_namespaces is True
    assert scan_args.results_dir == "results-custom"
    assert scan_args.config == "custom-jmo.yml"
    assert scan_args.tools == ["trivy", "semgrep"]
    assert scan_args.timeout == 900
    assert scan_args.threads == 8
    assert scan_args.allow_missing_tools is True
    assert scan_args.profile_name == "balanced"
    assert scan_args.log_level == "DEBUG"
    assert scan_args.human_logs is True
    assert scan_args.store_history is True
    assert scan_args.history_db == "/path/to/history.db"

    # Verify report was called with all arguments
    report_args = mock_report.call_args[0][0]
    assert report_args.results_dir == "results-custom"
    assert report_args.results_dir_pos == "results-custom"
    assert report_args.results_dir_opt == "results-custom"
    assert report_args.out is None
    assert report_args.config == "custom-jmo.yml"
    assert report_args.fail_on == "HIGH"
    assert report_args.profile is True
    assert report_args.threads == 8
    assert report_args.log_level == "DEBUG"
    assert report_args.human_logs is True
    assert report_args.json is True
    assert report_args.md is True
    assert report_args.html is True
    assert report_args.sarif is True
    assert report_args.yaml is True
    assert report_args.store_history is True
    assert report_args.history_db == "/path/to/history.db"
    assert report_args.profile_name == "balanced"
    assert report_args.policies == ["no_high_severity", "require_cwe"]
    assert report_args.fail_on_policy_violation is True

    # Verify return code from report (not scan)
    assert rc == 2


def test_cmd_ci_return_codes():
    """Test cmd_ci returns exit code from report command."""

    class Args:
        repo = "/repo"
        results_dir = "results"
        config = "jmo.yml"

    for expected_rc in [0, 1, 2]:
        mock_scan = MagicMock(return_value=0)
        mock_report = MagicMock(return_value=expected_rc)

        with patch("scripts.cli.jmo._log"):
            rc = cmd_ci(Args(), mock_scan, mock_report)

        assert rc == expected_rc


def test_cmd_ci_scan_args_defaults():
    """Test ScanArgs uses correct defaults when attributes missing."""

    class Args:
        repo = "/repo"

    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    scan_args = mock_scan.call_args[0][0]
    # Verify defaults
    assert scan_args.repos_dir is None
    assert scan_args.targets is None
    assert scan_args.image is None
    assert scan_args.images_file is None
    assert scan_args.terraform_state is None
    assert scan_args.cloudformation is None
    assert scan_args.k8s_manifest is None
    assert scan_args.url is None
    assert scan_args.urls_file is None
    assert scan_args.api_spec is None
    assert scan_args.gitlab_url is None
    assert scan_args.gitlab_token is None
    assert scan_args.gitlab_group is None
    assert scan_args.gitlab_repo is None
    assert scan_args.k8s_context is None
    assert scan_args.k8s_namespace is None
    assert scan_args.k8s_all_namespaces is False
    assert scan_args.results_dir == "results"
    assert scan_args.config == "jmo.yml"
    assert scan_args.tools is None
    assert scan_args.timeout == 600
    assert scan_args.threads is None
    assert scan_args.allow_missing_tools is False
    assert scan_args.profile_name is None
    assert scan_args.log_level is None
    assert scan_args.human_logs is False
    assert scan_args.store_history is False
    assert scan_args.history_db is None


def test_cmd_ci_report_args_defaults():
    """Test ReportArgs uses correct defaults when attributes missing."""

    class Args:
        results_dir = "results"

    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    report_args = mock_report.call_args[0][0]
    # Verify defaults
    assert report_args.results_dir == "results"
    assert report_args.results_dir_pos == "results"
    assert report_args.results_dir_opt == "results"
    assert report_args.out is None
    assert report_args.config == "jmo.yml"
    assert report_args.fail_on is None
    assert report_args.profile is False
    assert report_args.threads is None
    assert report_args.log_level is None
    assert report_args.human_logs is False
    assert report_args.json is False
    assert report_args.md is False
    assert report_args.html is False
    assert report_args.sarif is False
    assert report_args.yaml is False
    assert report_args.store_history is False
    assert report_args.history_db is None
    assert report_args.profile_name is None
    assert report_args.policies is None
    assert report_args.fail_on_policy_violation is False


def test_cmd_ci_results_dir_path_conversion():
    """Test ReportArgs converts results_dir to string."""

    class Args:
        results_dir = Path("/path/to/results")

    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    report_args = mock_report.call_args[0][0]
    # Path should be converted to string
    assert report_args.results_dir == "/path/to/results"
    assert isinstance(report_args.results_dir, str)
    assert report_args.results_dir_pos == "/path/to/results"
    assert report_args.results_dir_opt == "/path/to/results"


def test_cmd_ci_calls_scan_then_report():
    """Test cmd_ci calls scan before report."""
    call_order = []

    def mock_scan(args):
        call_order.append("scan")
        return 0

    def mock_report(args, log_fn):
        call_order.append("report")
        return 0

    class Args:
        repo = "/repo"
        results_dir = "results"

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    assert call_order == ["scan", "report"]


def test_cmd_ci_report_receives_log_function():
    """Test cmd_ci passes _log function to cmd_report."""
    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    class Args:
        repo = "/repo"
        results_dir = "results"

    with patch("scripts.cli.jmo._log") as mock_log:
        cmd_ci(Args(), mock_scan, mock_report)

    # Verify report was called with 2 arguments (args, log_fn)
    assert mock_report.call_count == 1
    assert len(mock_report.call_args[0]) == 2
    # Second argument should be _log function
    assert mock_report.call_args[0][1] == mock_log


def test_cmd_ci_container_image_args():
    """Test cmd_ci with container image scanning arguments."""

    class Args:
        image = "nginx:latest"
        images_file = "/path/to/images.txt"
        results_dir = "results"

    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    scan_args = mock_scan.call_args[0][0]
    assert scan_args.image == "nginx:latest"
    assert scan_args.images_file == "/path/to/images.txt"


def test_cmd_ci_iac_args():
    """Test cmd_ci with IaC scanning arguments."""

    class Args:
        terraform_state = "/path/to/terraform.tfstate"
        cloudformation = "/path/to/cloudformation.yaml"
        k8s_manifest = "/path/to/k8s.yaml"
        results_dir = "results"

    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    scan_args = mock_scan.call_args[0][0]
    assert scan_args.terraform_state == "/path/to/terraform.tfstate"
    assert scan_args.cloudformation == "/path/to/cloudformation.yaml"
    assert scan_args.k8s_manifest == "/path/to/k8s.yaml"


def test_cmd_ci_web_scanning_args():
    """Test cmd_ci with web app/API scanning arguments."""

    class Args:
        url = "https://example.com"
        urls_file = "/path/to/urls.txt"
        api_spec = "/path/to/api.yaml"
        results_dir = "results"

    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    scan_args = mock_scan.call_args[0][0]
    assert scan_args.url == "https://example.com"
    assert scan_args.urls_file == "/path/to/urls.txt"
    assert scan_args.api_spec == "/path/to/api.yaml"


def test_cmd_ci_gitlab_args():
    """Test cmd_ci with GitLab integration arguments."""

    class Args:
        gitlab_url = "https://gitlab.com"
        gitlab_token = "glpat-token"
        gitlab_group = "mygroup"
        gitlab_repo = "myrepo"
        results_dir = "results"

    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    scan_args = mock_scan.call_args[0][0]
    assert scan_args.gitlab_url == "https://gitlab.com"
    assert scan_args.gitlab_token == "glpat-token"
    assert scan_args.gitlab_group == "mygroup"
    assert scan_args.gitlab_repo == "myrepo"


def test_cmd_ci_k8s_args():
    """Test cmd_ci with Kubernetes cluster scanning arguments."""

    class Args:
        k8s_context = "minikube"
        k8s_namespace = "default"
        k8s_all_namespaces = True
        results_dir = "results"

    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    scan_args = mock_scan.call_args[0][0]
    assert scan_args.k8s_context == "minikube"
    assert scan_args.k8s_namespace == "default"
    assert scan_args.k8s_all_namespaces is True


def test_cmd_ci_history_database_args():
    """Test cmd_ci with history database arguments."""

    class Args:
        store_history = True
        history_db = "/path/to/history.db"
        results_dir = "results"
        repo = "/repo"

    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    scan_args = mock_scan.call_args[0][0]
    assert scan_args.store_history is True
    assert scan_args.history_db == "/path/to/history.db"

    report_args = mock_report.call_args[0][0]
    assert report_args.store_history is True
    assert report_args.history_db == "/path/to/history.db"


def test_cmd_ci_policy_args():
    """Test cmd_ci with policy arguments."""

    class Args:
        policies = ["no_high_severity", "require_cwe"]
        fail_on_policy_violation = True
        results_dir = "results"
        repo = "/repo"

    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    report_args = mock_report.call_args[0][0]
    assert report_args.policies == ["no_high_severity", "require_cwe"]
    assert report_args.fail_on_policy_violation is True


def test_cmd_ci_output_format_args():
    """Test cmd_ci with output format arguments."""

    class Args:
        json = True
        md = True
        html = True
        sarif = True
        yaml = True
        results_dir = "results"
        repo = "/repo"

    mock_scan = MagicMock(return_value=0)
    mock_report = MagicMock(return_value=0)

    with patch("scripts.cli.jmo._log"):
        cmd_ci(Args(), mock_scan, mock_report)

    report_args = mock_report.call_args[0][0]
    assert report_args.json is True
    assert report_args.md is True
    assert report_args.html is True
    assert report_args.sarif is True
    assert report_args.yaml is True
