"""
Tests for scripts/cli/jmo.py - Main CLI entry point.

Coverage:
- CLI argument parsing for all subcommands
- Subcommand dispatch logic
- Error handling for invalid arguments
- Helper functions (_iter_repos, _iter_images, etc.)
- Command routing

Test approach:
- Mock external dependencies (subprocess, file I/O, orchestrators)
- Use tmp_path for file-based operations
- Test argument parsing in isolation
- Verify dispatch logic routes to correct handlers
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.jmo import (
    _iter_repos,
    _iter_images,
    _iter_iac_files,
    _iter_urls,
    _merge_dict,
    parse_args,
    main,
)


# ========== Category 1: Argument Parsing Tests ==========


def test_parse_args_scan_basic(tmp_path: Path):
    """Test basic scan argument parsing."""
    with patch("sys.argv", ["jmo", "scan", "--repo", str(tmp_path)]):
        args = parse_args()
        assert args.cmd == "scan"
        assert args.repo == str(tmp_path)


def test_parse_args_scan_with_profile(tmp_path: Path):
    """Test scan with profile argument."""
    with patch(
        "sys.argv", ["jmo", "scan", "--repo", str(tmp_path), "--profile-name", "fast"]
    ):
        args = parse_args()
        assert args.cmd == "scan"
        assert args.profile_name == "fast"
        assert args.repo == str(tmp_path)


def test_parse_args_scan_with_tools(tmp_path: Path):
    """Test scan with explicit tools list."""
    with patch(
        "sys.argv",
        ["jmo", "scan", "--repo", str(tmp_path), "--tools", "trivy", "semgrep"],
    ):
        args = parse_args()
        assert args.cmd == "scan"
        assert args.tools == ["trivy", "semgrep"]


def test_parse_args_scan_with_threads_timeout(tmp_path: Path):
    """Test scan with threads and timeout overrides."""
    with patch(
        "sys.argv",
        ["jmo", "scan", "--repo", str(tmp_path), "--threads", "4", "--timeout", "600"],
    ):
        args = parse_args()
        assert args.cmd == "scan"
        assert args.threads == 4
        assert args.timeout == 600


def test_parse_args_scan_with_allow_missing_tools(tmp_path: Path):
    """Test scan with --allow-missing-tools flag."""
    with patch(
        "sys.argv", ["jmo", "scan", "--repo", str(tmp_path), "--allow-missing-tools"]
    ):
        args = parse_args()
        assert args.cmd == "scan"
        assert args.allow_missing_tools is True


def test_parse_args_report_positional(tmp_path: Path):
    """Test report with positional results directory."""
    with patch("sys.argv", ["jmo", "report", str(tmp_path)]):
        args = parse_args()
        assert args.cmd == "report"
        assert args.results_dir_pos == str(tmp_path)


def test_parse_args_report_optional(tmp_path: Path):
    """Test report with optional --results-dir."""
    with patch("sys.argv", ["jmo", "report", "--results-dir", str(tmp_path)]):
        args = parse_args()
        assert args.cmd == "report"
        assert args.results_dir_opt == str(tmp_path)


def test_parse_args_report_with_fail_on():
    """Test report with --fail-on threshold."""
    with patch("sys.argv", ["jmo", "report", "results", "--fail-on", "HIGH"]):
        args = parse_args()
        assert args.cmd == "report"
        assert args.fail_on == "HIGH"


def test_parse_args_ci_basic(tmp_path: Path):
    """Test CI mode argument parsing."""
    with patch(
        "sys.argv", ["jmo", "ci", "--repo", str(tmp_path), "--fail-on", "CRITICAL"]
    ):
        args = parse_args()
        assert args.cmd == "ci"
        assert args.repo == str(tmp_path)
        assert args.fail_on == "CRITICAL"


def test_parse_args_diff_directories(tmp_path: Path):
    """Test diff with two directories."""
    baseline = tmp_path / "baseline"
    current = tmp_path / "current"
    baseline.mkdir()
    current.mkdir()

    with patch("sys.argv", ["jmo", "diff", str(baseline), str(current)]):
        args = parse_args()
        assert args.cmd == "diff"
        assert args.directories == [str(baseline), str(current)]


def test_parse_args_diff_auto_mode():
    """Test diff with --auto flag."""
    with patch("sys.argv", ["jmo", "diff", "--auto"]):
        args = parse_args()
        assert args.cmd == "diff"
        assert args.auto is True


def test_parse_args_diff_scan_ids():
    """Test diff with --scan flags."""
    with patch("sys.argv", ["jmo", "diff", "--scan", "abc123", "--scan", "def456"]):
        args = parse_args()
        assert args.cmd == "diff"
        assert args.scan_ids == ["abc123", "def456"]


def test_parse_args_history_list():
    """Test history list command."""
    with patch("sys.argv", ["jmo", "history", "list"]):
        args = parse_args()
        assert args.cmd == "history"
        assert args.history_command == "list"


def test_parse_args_history_show():
    """Test history show command."""
    with patch("sys.argv", ["jmo", "history", "show", "abc123"]):
        args = parse_args()
        assert args.cmd == "history"
        assert args.history_command == "show"
        assert args.scan_id == "abc123"


def test_parse_args_trends_analyze():
    """Test trends analyze command."""
    with patch("sys.argv", ["jmo", "trends", "analyze", "--days", "30"]):
        args = parse_args()
        assert args.cmd == "trends"
        assert args.trends_command == "analyze"
        assert args.days == 30


def test_parse_args_wizard_basic():
    """Test wizard command."""
    with patch("sys.argv", ["jmo", "wizard"]):
        args = parse_args()
        assert args.cmd == "wizard"


def test_parse_args_wizard_yes():
    """Test wizard with --yes flag."""
    with patch("sys.argv", ["jmo", "wizard", "--yes"]):
        args = parse_args()
        assert args.cmd == "wizard"
        assert args.yes is True


def test_parse_args_setup():
    """Test setup command."""
    with patch("sys.argv", ["jmo", "setup"]):
        args = parse_args()
        assert args.cmd == "setup"


def test_parse_args_adapters_list():
    """Test adapters list command."""
    with patch("sys.argv", ["jmo", "adapters", "list"]):
        args = parse_args()
        assert args.cmd == "adapters"
        assert args.adapters_command == "list"


def test_parse_args_fast_profile(tmp_path: Path):
    """Test fast profile command."""
    with patch("sys.argv", ["jmo", "fast", "--repo", str(tmp_path)]):
        args = parse_args()
        assert args.cmd == "fast"


def test_parse_args_balanced_profile(tmp_path: Path):
    """Test balanced profile command."""
    with patch("sys.argv", ["jmo", "balanced", "--repo", str(tmp_path)]):
        args = parse_args()
        assert args.cmd == "balanced"


def test_parse_args_full_profile(tmp_path: Path):
    """Test full profile command."""
    with patch("sys.argv", ["jmo", "full", "--repo", str(tmp_path)]):
        args = parse_args()
        assert args.cmd == "full"


def test_parse_args_multi_target_scanning(tmp_path: Path):
    """Test multi-target scanning arguments."""
    with patch(
        "sys.argv",
        [
            "jmo",
            "scan",
            "--repo",
            str(tmp_path),
            "--image",
            "nginx:latest",
            "--url",
            "https://example.com",
        ],
    ):
        args = parse_args()
        assert args.cmd == "scan"
        assert args.repo == str(tmp_path)
        assert args.image == "nginx:latest"
        assert args.url == "https://example.com"


# ========== Category 2: Error Handling Tests ==========


def test_parse_args_invalid_command(capsys):
    """Test error on invalid command."""
    with patch("sys.argv", ["jmo", "invalid-command"]):
        with patch(
            "os.getenv", return_value=None
        ):  # Disable pytest detection in parse_args
            with pytest.raises(SystemExit) as exc_info:
                parse_args()
            assert exc_info.value.code != 0
            captured = capsys.readouterr()
            assert "invalid choice" in captured.err


def test_parse_args_missing_required_subcommand(capsys):
    """Test error when no subcommand provided."""
    with patch("sys.argv", ["jmo"]):
        with patch(
            "os.getenv", return_value=None
        ):  # Disable pytest detection in parse_args
            with pytest.raises(SystemExit) as exc_info:
                parse_args()
            assert exc_info.value.code != 0


def test_parse_args_scan_missing_target():
    """Test scan without any target argument (should succeed, validation happens later)."""
    with patch("sys.argv", ["jmo", "scan"]):
        args = parse_args()
        assert args.cmd == "scan"
        # Validation happens in cmd_scan, not arg parsing


def test_parse_args_help_flag(capsys):
    """Test --help flag (should exit with code 0)."""
    with patch("sys.argv", ["jmo", "--help"]):
        with patch(
            "os.getenv", return_value=None
        ):  # Disable pytest detection in parse_args
            with pytest.raises(SystemExit) as exc_info:
                parse_args()
            assert exc_info.value.code == 0
            captured = capsys.readouterr()
            assert "usage:" in captured.out or "usage:" in captured.err


def test_parse_args_invalid_threads_value(capsys):
    """Test invalid --threads value."""
    with patch("sys.argv", ["jmo", "scan", "--repo", ".", "--threads", "invalid"]):
        with patch(
            "os.getenv", return_value=None
        ):  # Disable pytest detection in parse_args
            with pytest.raises(SystemExit) as exc_info:
                parse_args()
            assert exc_info.value.code != 0
            captured = capsys.readouterr()
            assert "invalid int value" in captured.err


def test_parse_args_invalid_timeout_value(capsys):
    """Test invalid --timeout value."""
    with patch("sys.argv", ["jmo", "scan", "--repo", ".", "--timeout", "invalid"]):
        with patch(
            "os.getenv", return_value=None
        ):  # Disable pytest detection in parse_args
            with pytest.raises(SystemExit) as exc_info:
                parse_args()
            assert exc_info.value.code != 0
            captured = capsys.readouterr()
            assert "invalid int value" in captured.err


# ========== Category 3: Helper Function Tests ==========


def test_iter_repos_single_repo(tmp_path: Path):
    """Test _iter_repos with --repo argument."""
    repo = tmp_path / "test-repo"
    repo.mkdir()

    args = MagicMock()
    args.repo = str(repo)
    args.repos_dir = None
    args.targets = None

    repos = _iter_repos(args)
    assert len(repos) == 1
    assert repos[0] == repo


def test_iter_repos_repos_dir(tmp_path: Path):
    """Test _iter_repos with --repos-dir argument."""
    repos_dir = tmp_path / "repos"
    repos_dir.mkdir()
    (repos_dir / "repo1").mkdir()
    (repos_dir / "repo2").mkdir()
    (repos_dir / "file.txt").write_text("not a dir")  # Should be skipped

    args = MagicMock()
    args.repo = None
    args.repos_dir = str(repos_dir)
    args.targets = None

    repos = _iter_repos(args)
    assert len(repos) == 2
    assert all(r.is_dir() for r in repos)


def test_iter_repos_targets_file(tmp_path: Path):
    """Test _iter_repos with --targets file."""
    repo1 = tmp_path / "repo1"
    repo2 = tmp_path / "repo2"
    repo1.mkdir()
    repo2.mkdir()

    targets_file = tmp_path / "targets.txt"
    targets_file.write_text(f"{repo1}\n{repo2}\n# comment\n\n")

    args = MagicMock()
    args.repo = None
    args.repos_dir = None
    args.targets = str(targets_file)

    repos = _iter_repos(args)
    assert len(repos) == 2
    assert repo1 in repos
    assert repo2 in repos


def test_iter_repos_empty():
    """Test _iter_repos with no arguments."""
    args = MagicMock()
    args.repo = None
    args.repos_dir = None
    args.targets = None

    repos = _iter_repos(args)
    assert len(repos) == 0


def test_iter_images_single_image():
    """Test _iter_images with --image argument."""
    args = MagicMock()
    args.image = "nginx:latest"
    args.images_file = None

    images = _iter_images(args)
    assert len(images) == 1
    assert images[0] == "nginx:latest"


def test_iter_images_file(tmp_path: Path):
    """Test _iter_images with --images-file."""
    images_file = tmp_path / "images.txt"
    images_file.write_text("nginx:latest\nalpine:3.14\n# comment\n\n")

    args = MagicMock()
    args.image = None
    args.images_file = str(images_file)

    images = _iter_images(args)
    assert len(images) == 2
    assert "nginx:latest" in images
    assert "alpine:3.14" in images


def test_iter_iac_files_terraform(tmp_path: Path):
    """Test _iter_iac_files with terraform state."""
    tf_state = tmp_path / "terraform.tfstate"
    tf_state.write_text("{}")

    args = MagicMock()
    args.terraform_state = str(tf_state)
    args.cloudformation = None
    args.k8s_manifest = None

    iac_files = _iter_iac_files(args)
    assert len(iac_files) == 1
    assert iac_files[0] == ("terraform", tf_state)


def test_iter_iac_files_multiple_types(tmp_path: Path):
    """Test _iter_iac_files with multiple IaC types."""
    tf_state = tmp_path / "terraform.tfstate"
    cf_template = tmp_path / "cloudformation.yaml"
    k8s_manifest = tmp_path / "deployment.yaml"

    tf_state.write_text("{}")
    cf_template.write_text("AWSTemplateFormatVersion: '2010-09-09'")
    k8s_manifest.write_text("apiVersion: v1\nkind: Pod")

    args = MagicMock()
    args.terraform_state = str(tf_state)
    args.cloudformation = str(cf_template)
    args.k8s_manifest = str(k8s_manifest)

    iac_files = _iter_iac_files(args)
    assert len(iac_files) == 3
    types = [t for t, _ in iac_files]
    assert "terraform" in types
    assert "cloudformation" in types
    assert "k8s-manifest" in types


def test_iter_urls_single_url():
    """Test _iter_urls with --url argument."""
    args = MagicMock()
    args.url = "https://example.com"
    args.urls_file = None
    args.api_spec = None

    urls = _iter_urls(args)
    assert len(urls) == 1
    assert urls[0] == "https://example.com"


def test_iter_urls_file(tmp_path: Path):
    """Test _iter_urls with --urls-file."""
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("https://example.com\nhttps://test.com\n# comment\n\n")

    args = MagicMock()
    args.url = None
    args.urls_file = str(urls_file)
    args.api_spec = None

    urls = _iter_urls(args)
    assert len(urls) == 2
    assert "https://example.com" in urls
    assert "https://test.com" in urls


def test_merge_dict_basic():
    """Test _merge_dict with basic dictionaries."""
    a = {"key1": "value1", "key2": "value2"}
    b = {"key2": "new_value2", "key3": "value3"}

    result = _merge_dict(a, b)
    assert result["key1"] == "value1"
    assert result["key2"] == "new_value2"  # b overrides a
    assert result["key3"] == "value3"


def test_merge_dict_none_inputs():
    """Test _merge_dict with None inputs."""
    a = {"key1": "value1"}

    result1 = _merge_dict(a, None)
    assert result1 == a

    result2 = _merge_dict(None, a)
    assert result2 == a

    result3 = _merge_dict(None, None)
    assert result3 == {}


# ========== Category 4: Main Dispatch Tests ==========


@patch("scripts.cli.jmo.cmd_scan")
def test_main_dispatch_scan(mock_cmd_scan):
    """Test main dispatches to cmd_scan."""
    mock_cmd_scan.return_value = 0

    with patch("sys.argv", ["jmo", "scan", "--repo", "."]):
        exit_code = main()

    mock_cmd_scan.assert_called_once()
    assert exit_code == 0


@patch("scripts.cli.jmo.cmd_report")
def test_main_dispatch_report(mock_cmd_report):
    """Test main dispatches to cmd_report."""
    mock_cmd_report.return_value = 0

    with patch("sys.argv", ["jmo", "report", "results"]):
        exit_code = main()

    mock_cmd_report.assert_called_once()
    assert exit_code == 0


@patch("scripts.cli.jmo.cmd_ci")
def test_main_dispatch_ci(mock_cmd_ci):
    """Test main dispatches to cmd_ci."""
    mock_cmd_ci.return_value = 0

    with patch("sys.argv", ["jmo", "ci", "--repo", "."]):
        exit_code = main()

    mock_cmd_ci.assert_called_once()
    assert exit_code == 0


@patch("scripts.cli.jmo.cmd_wizard")
def test_main_dispatch_wizard(mock_cmd_wizard):
    """Test main dispatches to cmd_wizard."""
    mock_cmd_wizard.return_value = 0

    with patch("sys.argv", ["jmo", "wizard"]):
        exit_code = main()

    mock_cmd_wizard.assert_called_once()
    assert exit_code == 0


@patch("scripts.cli.jmo.cmd_adapters")
def test_main_dispatch_adapters(mock_cmd_adapters):
    """Test main dispatches to cmd_adapters."""
    mock_cmd_adapters.return_value = 0

    with patch("sys.argv", ["jmo", "adapters", "list"]):
        exit_code = main()

    mock_cmd_adapters.assert_called_once()
    assert exit_code == 0


@patch("scripts.cli.jmo.cmd_history")
def test_main_dispatch_history(mock_cmd_history):
    """Test main dispatches to cmd_history."""
    mock_cmd_history.return_value = 0

    with patch("sys.argv", ["jmo", "history", "list"]):
        exit_code = main()

    mock_cmd_history.assert_called_once()
    assert exit_code == 0


@patch("scripts.cli.jmo.cmd_trends")
def test_main_dispatch_trends(mock_cmd_trends):
    """Test main dispatches to cmd_trends."""
    mock_cmd_trends.return_value = 0

    with patch("sys.argv", ["jmo", "trends", "analyze"]):
        exit_code = main()

    mock_cmd_trends.assert_called_once()
    assert exit_code == 0


@patch("scripts.cli.jmo.cmd_diff")
def test_main_dispatch_diff(mock_cmd_diff):
    """Test main dispatches to cmd_diff."""
    mock_cmd_diff.return_value = 0

    with patch("sys.argv", ["jmo", "diff", "results-a", "results-b"]):
        exit_code = main()

    mock_cmd_diff.assert_called_once()
    assert exit_code == 0


def test_main_unknown_command(capsys):
    """Test main with unknown command."""
    with patch("sys.argv", ["jmo", "unknown-cmd"]):
        with patch(
            "os.getenv", return_value=None
        ):  # Disable pytest detection in parse_args
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code != 0
            captured = capsys.readouterr()
            assert "invalid choice" in captured.err


def test_main_empty_namespace():
    """Test main with empty namespace (e.g., --help during pytest)."""
    args = argparse.Namespace()
    with patch("scripts.cli.jmo.parse_args", return_value=args):
        exit_code = main()
        assert exit_code == 0


# ========== Category 5: Policy and Schedule Commands ==========


def test_parse_args_policy_list():
    """Test policy list command."""
    with patch("sys.argv", ["jmo", "policy", "list"]):
        args = parse_args()
        assert args.cmd == "policy"
        assert args.policy_command == "list"


def test_parse_args_policy_validate():
    """Test policy validate command."""
    with patch("sys.argv", ["jmo", "policy", "validate", "zero-secrets"]):
        args = parse_args()
        assert args.cmd == "policy"
        assert args.policy_command == "validate"
        assert args.policy == "zero-secrets"


def test_parse_args_schedule_create():
    """Test schedule create command."""
    with patch(
        "sys.argv",
        [
            "jmo",
            "schedule",
            "create",
            "--name",
            "nightly-scan",
            "--cron",
            "0 2 * * *",
            "--profile",
            "balanced",
        ],
    ):
        args = parse_args()
        assert args.cmd == "schedule"
        assert args.schedule_action == "create"
        assert args.name == "nightly-scan"
        assert args.cron == "0 2 * * *"
        assert args.profile == "balanced"


def test_parse_args_schedule_list():
    """Test schedule list command."""
    with patch("sys.argv", ["jmo", "schedule", "list"]):
        args = parse_args()
        assert args.cmd == "schedule"
        assert args.schedule_action == "list"


# ========== Category 6: Attestation Commands ==========


def test_parse_args_attest_basic():
    """Test attest command."""
    with patch("sys.argv", ["jmo", "attest", "findings.json"]):
        args = parse_args()
        assert args.cmd == "attest"
        assert args.subject == "findings.json"


def test_parse_args_attest_with_sign():
    """Test attest with --sign flag."""
    with patch("sys.argv", ["jmo", "attest", "findings.json", "--sign"]):
        args = parse_args()
        assert args.cmd == "attest"
        assert args.sign is True


def test_parse_args_verify_basic():
    """Test verify command."""
    with patch("sys.argv", ["jmo", "verify", "findings.json"]):
        args = parse_args()
        assert args.cmd == "verify"
        assert args.subject == "findings.json"


# ========== Category 7: MCP Server Command ==========


def test_parse_args_mcp_server():
    """Test mcp-server command."""
    with patch("sys.argv", ["jmo", "mcp-server"]):
        args = parse_args()
        assert args.cmd == "mcp-server"


def test_parse_args_mcp_server_with_options():
    """Test mcp-server with custom options."""
    with patch(
        "sys.argv",
        [
            "jmo",
            "mcp-server",
            "--results-dir",
            "./results",
            "--repo-root",
            "/tmp/repo",
            "--api-key",
            "test-key",
        ],
    ):
        args = parse_args()
        assert args.cmd == "mcp-server"
        assert args.results_dir == "./results"
        assert args.repo_root == "/tmp/repo"
        assert args.api_key == "test-key"


# ========== Category 8: Logging Arguments ==========


def test_parse_args_logging_human_logs():
    """Test --human-logs flag."""
    with patch("sys.argv", ["jmo", "scan", "--repo", ".", "--human-logs"]):
        args = parse_args()
        assert args.cmd == "scan"
        assert args.human_logs is True


def test_parse_args_logging_log_level():
    """Test --log-level argument."""
    with patch("sys.argv", ["jmo", "scan", "--repo", ".", "--log-level", "DEBUG"]):
        args = parse_args()
        assert args.cmd == "scan"
        assert args.log_level == "DEBUG"


# ========== Category 9: History Database Arguments ==========


def test_parse_args_no_store_history():
    """Test --no-store-history flag."""
    with patch("sys.argv", ["jmo", "scan", "--repo", ".", "--no-store-history"]):
        args = parse_args()
        assert args.cmd == "scan"
        assert args.store_history is False


def test_parse_args_encrypt_findings():
    """Test --encrypt-findings flag."""
    with patch("sys.argv", ["jmo", "scan", "--repo", ".", "--encrypt-findings"]):
        args = parse_args()
        assert args.cmd == "scan"
        assert args.encrypt_findings is True


def test_parse_args_no_store_raw_findings():
    """Test --no-store-raw-findings flag."""
    with patch("sys.argv", ["jmo", "scan", "--repo", ".", "--no-store-raw-findings"]):
        args = parse_args()
        assert args.cmd == "scan"
        assert args.no_store_raw_findings is True
