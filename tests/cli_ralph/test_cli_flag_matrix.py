#!/usr/bin/env python3
"""
CLI Flag Matrix Tests for JMo Security CLI.

Tests flag combinations across commands using parametrized tests.
Verifies that CLI arguments are parsed correctly and commands handle
various flag combinations gracefully.

Usage:
    pytest tests/cli_ralph/test_cli_flag_matrix.py -v
    pytest tests/cli_ralph/test_cli_flag_matrix.py -v -k "profile"
"""

from __future__ import annotations

import pytest





# ============================================================================
# Profile/Threads Matrix Tests
# ============================================================================


class TestScanProfileThreadsMatrix:
    """Test profile and threads flag combinations."""

    @pytest.mark.parametrize("profile", ["fast", "balanced", "deep"])
    def test_scan_profile_help_shows_valid_profile(self, jmo_runner, profile):
        """Verify each profile is recognized in scan command."""
        result = jmo_runner(
            ["scan", "--profile-name", profile, "--help"],
            timeout=30,
        )
        # Help should work regardless of profile
        assert result.returncode == 0 or "usage" in result.stdout.lower()

    @pytest.mark.parametrize("threads", [1, 2, 4, 8])
    def test_scan_threads_argument_accepted(self, jmo_runner, tmp_path, threads):
        """Verify --threads flag is accepted for various values."""
        # Create minimal scan target
        (tmp_path / "test.py").write_text("print('hello')", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--threads",
                str(threads),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        # Should accept the threads argument without error
        combined = result.stdout.lower() + result.stderr.lower()
        assert "invalid" not in combined or "threads" not in combined
        # May fail for other reasons but threads should be accepted
        assert "unrecognized arguments" not in combined

    @pytest.mark.parametrize(
        "profile,threads",
        [
            ("fast", 1),
            ("fast", 4),
            ("balanced", 2),
            ("deep", 8),
        ],
    )
    def test_profile_command_with_threads(
        self, jmo_runner, tmp_path, profile, threads
    ):
        """Verify profile commands accept --threads flag."""
        (tmp_path / "test.py").write_text("print('hello')", encoding="utf-8")

        result = jmo_runner(
            [
                profile,
                "--repo",
                str(tmp_path),
                "--threads",
                str(threads),
                "--results-dir",
                str(tmp_path / "results"),
                "--no-open",
            ],
            timeout=60,
        )
        # Should accept arguments even if tools are missing
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


# ============================================================================
# Batch Target Flags Tests
# ============================================================================


class TestBatchTargetFlags:
    """Test batch target flags: --repos-dir, --targets, --images-file, --urls-file."""

    def test_scan_repos_dir_flag_accepted(self, jmo_runner, tmp_path):
        """Verify --repos-dir flag is accepted."""
        # Create repos directory structure
        repos_dir = tmp_path / "repos"
        repos_dir.mkdir()
        (repos_dir / "repo1").mkdir()
        (repos_dir / "repo1" / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repos-dir",
                str(repos_dir),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        # Flag should be recognized
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_targets_file_flag(self, jmo_runner, tmp_path):
        """Verify --targets flag accepts a file with repo paths."""
        # Create targets file
        targets_file = tmp_path / "targets.txt"
        repo1 = tmp_path / "repo1"
        repo1.mkdir()
        (repo1 / "test.py").write_text("x = 1", encoding="utf-8")

        targets_file.write_text(str(repo1), encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--targets",
                str(targets_file),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_images_file_flag(self, jmo_runner, tmp_path):
        """Verify --images-file flag is accepted."""
        images_file = tmp_path / "images.txt"
        images_file.write_text("alpine:latest\nnginx:latest", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--images-file",
                str(images_file),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_urls_file_flag(self, jmo_runner, tmp_path):
        """Verify --urls-file flag is accepted."""
        urls_file = tmp_path / "urls.txt"
        urls_file.write_text(
            "https://example.com\nhttps://test.example.com", encoding="utf-8"
        )

        result = jmo_runner(
            [
                "scan",
                "--urls-file",
                str(urls_file),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_repo_repos_dir_mutually_exclusive(self, jmo_runner, tmp_path):
        """Verify --repo and --repos-dir are mutually exclusive."""
        repo = tmp_path / "repo"
        repo.mkdir()
        repos_dir = tmp_path / "repos"
        repos_dir.mkdir()

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--repos-dir",
                str(repos_dir),
            ],
            timeout=30,
        )
        # Should show error about mutually exclusive
        combined = result.stdout.lower() + result.stderr.lower()
        assert result.returncode != 0 or "mutually exclusive" in combined or "not allowed" in combined


# ============================================================================
# GitLab Integration Flags Tests
# ============================================================================


class TestGitLabFlags:
    """Test GitLab integration flags."""

    def test_scan_gitlab_url_flag(self, jmo_runner, tmp_path):
        """Verify --gitlab-url flag is accepted."""
        result = jmo_runner(
            [
                "scan",
                "--gitlab-url",
                "https://gitlab.example.com",
                "--gitlab-token",
                "fake-token",
                "--gitlab-group",
                "test-group",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_gitlab_repo_flag(self, jmo_runner, tmp_path):
        """Verify --gitlab-repo flag is accepted."""
        result = jmo_runner(
            [
                "scan",
                "--gitlab-url",
                "https://gitlab.example.com",
                "--gitlab-token",
                "fake-token",
                "--gitlab-repo",
                "group/repo",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


# ============================================================================
# Kubernetes Flags Tests
# ============================================================================


class TestKubernetesFlags:
    """Test Kubernetes integration flags."""

    def test_scan_k8s_context_flag(self, jmo_runner, tmp_path):
        """Verify --k8s-context flag is accepted."""
        result = jmo_runner(
            [
                "scan",
                "--k8s-context",
                "minikube",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_k8s_namespace_flag(self, jmo_runner, tmp_path):
        """Verify --k8s-namespace flag is accepted."""
        result = jmo_runner(
            [
                "scan",
                "--k8s-context",
                "minikube",
                "--k8s-namespace",
                "default",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_k8s_all_namespaces_flag(self, jmo_runner, tmp_path):
        """Verify --k8s-all-namespaces flag is accepted."""
        result = jmo_runner(
            [
                "scan",
                "--k8s-context",
                "minikube",
                "--k8s-all-namespaces",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_k8s_manifest_flag(self, jmo_runner, tmp_path):
        """Verify --k8s-manifest flag is accepted."""
        manifest = tmp_path / "deployment.yaml"
        manifest.write_text(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test",
            encoding="utf-8",
        )

        result = jmo_runner(
            [
                "scan",
                "--k8s-manifest",
                str(manifest),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


# ============================================================================
# IaC/Cloud Flags Tests
# ============================================================================


class TestIaCFlags:
    """Test Infrastructure-as-Code scanning flags."""

    def test_scan_terraform_state_flag(self, jmo_runner, tmp_path):
        """Verify --terraform-state flag is accepted."""
        tf_state = tmp_path / "terraform.tfstate"
        tf_state.write_text('{"version": 4}', encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--terraform-state",
                str(tf_state),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_cloudformation_flag(self, jmo_runner, tmp_path):
        """Verify --cloudformation flag is accepted."""
        cfn_template = tmp_path / "template.yaml"
        cfn_template.write_text(
            "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}",
            encoding="utf-8",
        )

        result = jmo_runner(
            [
                "scan",
                "--cloudformation",
                str(cfn_template),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_api_spec_flag(self, jmo_runner, tmp_path):
        """Verify --api-spec flag is accepted."""
        api_spec = tmp_path / "openapi.yaml"
        api_spec.write_text(
            "openapi: 3.0.0\ninfo:\n  title: Test\n  version: 1.0.0\npaths: {}",
            encoding="utf-8",
        )

        result = jmo_runner(
            [
                "scan",
                "--api-spec",
                str(api_spec),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


# ============================================================================
# Security/Privacy Flags Tests
# ============================================================================


class TestSecurityFlags:
    """Test security and privacy-related flags."""

    def test_scan_no_store_raw_findings_flag(self, jmo_runner, tmp_path):
        """Verify --no-store-raw-findings flag is accepted."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--no-store-raw-findings",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_no_store_history_flag(self, jmo_runner, tmp_path):
        """Verify --no-store-history flag is accepted."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--no-store-history",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


# ============================================================================
# Logging Flags Tests
# ============================================================================


class TestLoggingFlags:
    """Test logging configuration flags."""

    @pytest.mark.parametrize("log_level", ["DEBUG", "INFO", "WARNING", "ERROR"])
    def test_scan_log_level_flag(self, jmo_runner, tmp_path, log_level):
        """Verify --log-level flag accepts various levels."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--log-level",
                log_level,
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_human_logs_flag(self, jmo_runner, tmp_path):
        """Verify --human-logs flag is accepted."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--human-logs",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


# ============================================================================
# CI Command Flags Tests
# ============================================================================


class TestCICommandFlags:
    """Test CI command flag combinations."""

    @pytest.mark.parametrize(
        "fail_on", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )
    def test_ci_fail_on_levels(self, jmo_runner, tmp_path, fail_on):
        """Verify --fail-on accepts all severity levels."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "ci",
                "--repo",
                str(tmp_path),
                "--fail-on",
                fail_on,
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_ci_profile_flag(self, jmo_runner, tmp_path):
        """Verify CI command accepts --profile-name flag."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "ci",
                "--repo",
                str(tmp_path),
                "--profile-name",
                "fast",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_ci_policy_flag(self, jmo_runner, tmp_path):
        """Verify CI command accepts --policy flag."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "ci",
                "--repo",
                str(tmp_path),
                "--policy",
                "zero-critical",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


# ============================================================================
# Report Command Flags Tests
# ============================================================================


class TestReportCommandFlags:
    """Test report command flag combinations."""

    @pytest.mark.parametrize("fail_on", ["CRITICAL", "HIGH", "MEDIUM"])
    def test_report_fail_on_levels(
        self, jmo_runner, baseline_results, tmp_path, fail_on
    ):
        """Verify report --fail-on accepts severity levels."""
        result = jmo_runner(
            [
                "report",
                str(baseline_results),
                "--fail-on",
                fail_on,
                "--out",
                str(tmp_path / "out"),
            ],
            timeout=60,
        )
        # May fail based on findings but flag should be accepted
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_report_profile_flag(self, jmo_runner, baseline_results, tmp_path):
        """Verify report --profile flag for timing collection."""
        result = jmo_runner(
            [
                "report",
                str(baseline_results),
                "--profile",
                "--out",
                str(tmp_path / "out"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


# ============================================================================
# Config File Flag Tests
# ============================================================================


class TestConfigFileFlag:
    """Test --config flag across commands."""

    def test_scan_config_flag(self, jmo_runner, tmp_path):
        """Verify scan accepts custom config file."""
        config_file = tmp_path / "custom-jmo.yml"
        config_file.write_text(
            "default_profile: fast\nfail_on: HIGH", encoding="utf-8"
        )
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--config",
                str(config_file),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_profile_config_flag(self, jmo_runner, tmp_path):
        """Verify profile commands accept custom config file."""
        config_file = tmp_path / "custom-jmo.yml"
        config_file.write_text(
            "default_profile: fast\nfail_on: HIGH", encoding="utf-8"
        )
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "fast",
                "--repo",
                str(tmp_path),
                "--config",
                str(config_file),
                "--results-dir",
                str(tmp_path / "results"),
                "--no-open",
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


# ============================================================================
# History Database Flag Tests
# ============================================================================


class TestHistoryDatabaseFlag:
    """Test --history-db and --db flags."""

    def test_scan_history_db_flag(self, jmo_runner, tmp_path):
        """Verify scan accepts custom history database path."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")
        db_path = tmp_path / "custom-history.db"

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--history-db",
                str(db_path),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_history_db_flag(self, jmo_runner, test_history_db):
        """Verify history command accepts --db flag."""
        result = jmo_runner(
            ["history", "list", "--db", str(test_history_db)],
            timeout=30,
        )
        assert result.returncode == 0


# ============================================================================
# Timeout Flag Tests
# ============================================================================


class TestTimeoutFlag:
    """Test --timeout flag."""

    @pytest.mark.parametrize("timeout", [60, 120, 300, 600])
    def test_scan_timeout_values(self, jmo_runner, tmp_path, timeout):
        """Verify scan accepts various timeout values."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--timeout",
                str(timeout),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


# ============================================================================
# Tools Override Flag Tests
# ============================================================================


class TestToolsOverrideFlag:
    """Test --tools flag for overriding tool list."""

    def test_scan_tools_override(self, jmo_runner, tmp_path):
        """Verify scan accepts --tools flag to override tool list."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--tools",
                "trivy,bandit",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_scan_tools_single_tool(self, jmo_runner, tmp_path):
        """Verify scan accepts --tools with single tool."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--tools",
                "trivy",
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================


class TestFlagEdgeCases:
    """Test edge cases for flag handling."""

    def test_invalid_profile_rejected(self, jmo_runner, tmp_path):
        """Invalid profile name should be rejected."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--profile-name",
                "nonexistent_profile_xyz",
            ],
            timeout=30,
        )
        # Should fail or warn about invalid profile
        combined = result.stdout.lower() + result.stderr.lower()
        assert result.returncode != 0 or "invalid" in combined or "unknown" in combined

    def test_invalid_log_level_rejected(self, jmo_runner, tmp_path):
        """Invalid log level should be rejected."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--log-level",
                "INVALID_LEVEL",
            ],
            timeout=30,
        )
        # Should fail with error
        combined = result.stdout.lower() + result.stderr.lower()
        assert result.returncode != 0 or "invalid" in combined

    def test_negative_threads_rejected(self, jmo_runner, tmp_path):
        """Negative thread count should be rejected."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--threads",
                "-1",
            ],
            timeout=30,
        )
        # Should fail or treat as invalid
        combined = result.stdout.lower() + result.stderr.lower()
        assert result.returncode != 0 or "invalid" in combined or "error" in combined

    def test_nonexistent_config_file(self, jmo_runner, tmp_path):
        """Nonexistent config file should be handled gracefully."""
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path),
                "--config",
                str(tmp_path / "nonexistent.yml"),
                "--allow-missing-tools",
            ],
            timeout=30,
        )
        # May warn or fail, but shouldn't crash
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined or "handled" in combined
