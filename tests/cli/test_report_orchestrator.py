"""
Tests for report_orchestrator.py - Report command orchestration.

Coverage targets:
- fail_code() with different severity thresholds
- cmd_report() results_dir normalization
- Output directory creation
- Profiling environment setup
- Findings gathering and suppressions
- Metadata generation
- Report generation (JSON, MD, YAML, HTML, SARIF, CSV)
- Compliance reports
- Policy evaluation
- Profiling data
- Environment restoration
- Severity counting and exit codes
- History database storage
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.report_orchestrator import cmd_report, fail_code

# =============================================================================
# fail_code() tests
# =============================================================================


def test_fail_code_no_threshold():
    """Test fail_code returns 0 when no threshold provided."""
    counts = {"HIGH": 5, "MEDIUM": 10}
    assert fail_code(None, counts) == 0


def test_fail_code_invalid_threshold():
    """Test fail_code returns 0 for invalid threshold."""
    counts = {"HIGH": 5}
    assert fail_code("INVALID", counts) == 0


def test_fail_code_critical_threshold():
    """Test fail_code with CRITICAL threshold."""
    # No CRITICAL findings -> 0
    counts = {"HIGH": 5, "MEDIUM": 10}
    assert fail_code("CRITICAL", counts) == 0

    # Has CRITICAL findings -> 1
    counts = {"CRITICAL": 1, "HIGH": 5}
    assert fail_code("CRITICAL", counts) == 1


def test_fail_code_high_threshold():
    """Test fail_code with HIGH threshold."""
    # No HIGH or CRITICAL -> 0
    counts = {"MEDIUM": 10, "LOW": 5}
    assert fail_code("HIGH", counts) == 0

    # Has HIGH -> 1
    counts = {"HIGH": 1, "MEDIUM": 5}
    assert fail_code("HIGH", counts) == 1

    # Has CRITICAL -> 1
    counts = {"CRITICAL": 1, "MEDIUM": 5}
    assert fail_code("HIGH", counts) == 1


def test_fail_code_medium_threshold():
    """Test fail_code with MEDIUM threshold."""
    counts = {"LOW": 10}
    assert fail_code("MEDIUM", counts) == 0

    counts = {"MEDIUM": 1}
    assert fail_code("MEDIUM", counts) == 1

    counts = {"HIGH": 1}
    assert fail_code("MEDIUM", counts) == 1


def test_fail_code_low_threshold():
    """Test fail_code with LOW threshold."""
    counts = {"INFO": 10}
    assert fail_code("LOW", counts) == 0

    counts = {"LOW": 1}
    assert fail_code("LOW", counts) == 1


def test_fail_code_info_threshold():
    """Test fail_code with INFO threshold."""
    counts = {}
    assert fail_code("INFO", counts) == 0

    counts = {"INFO": 1}
    assert fail_code("INFO", counts) == 1


def test_fail_code_case_insensitive():
    """Test fail_code handles lowercase threshold."""
    counts = {"HIGH": 1}
    assert fail_code("high", counts) == 1


# =============================================================================
# cmd_report() tests
# =============================================================================


@pytest.fixture
def mock_config():
    """Create mock configuration."""
    cfg = MagicMock()
    cfg.outputs = ["json", "md"]
    cfg.fail_on = None
    cfg.threads = None
    cfg.profiling_default_threads = 4
    cfg.profiling_min_threads = 1
    cfg.profiling_max_threads = 16
    cfg.default_profile = "balanced"
    cfg.tools = ["trivy", "semgrep"]
    # Policy configuration
    cfg.policy = MagicMock()
    cfg.policy.enabled = False
    cfg.policy.auto_evaluate = False
    cfg.policy.default_policies = []
    cfg.policy.fail_on_violation = False
    # CSV configuration
    cfg.csv = None
    return cfg


@pytest.fixture
def minimal_args():
    """Create minimal arguments."""

    class Args:
        results_dir = None
        results_dir_pos = "results"
        results_dir_opt = None
        out = None
        config = "jmo.yml"
        fail_on = None
        profile = False
        threads = None
        log_level = None
        human_logs = False
        json = False
        md = False
        html = False
        simple_html = False
        sarif = False
        yaml = False
        store_history = False
        history_db = None
        profile_name = None
        policies = None
        fail_on_policy_violation = False

    return Args()


def test_cmd_report_no_results_dir(tmp_path, mock_config):
    """Test cmd_report returns error when no results_dir provided."""

    class Args:
        results_dir = None
        results_dir_pos = None
        results_dir_opt = None
        config = "jmo.yml"

    mock_log = MagicMock()

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        rc = cmd_report(Args(), mock_log)

    assert rc == 2
    # Verify error logged
    mock_log.assert_called_once()
    assert mock_log.call_args[0][1] == "ERROR"


def test_cmd_report_results_dir_normalization(tmp_path, mock_config, minimal_args):
    """Test cmd_report normalizes results_dir from different sources."""
    # Test results_dir_opt has priority over results_dir_pos
    results_dir_opt = tmp_path / "results-opt"
    results_dir_opt.mkdir()

    results_dir_pos = tmp_path / "results-pos"
    results_dir_pos.mkdir()

    minimal_args.results_dir_opt = str(results_dir_opt)
    minimal_args.results_dir_pos = str(results_dir_pos)
    minimal_args.results_dir = None

    mock_log = MagicMock()

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch("scripts.cli.report_orchestrator.write_json"),
    ):
        with patch("scripts.cli.report_orchestrator.write_markdown"):
            rc = cmd_report(minimal_args, mock_log)

    # Should use results_dir_opt (highest priority)
    # Verify output directory created under results_dir_opt
    assert (results_dir_opt / "summaries").exists()
    assert rc == 0


def test_cmd_report_creates_output_directory(tmp_path, mock_config, minimal_args):
    """Test cmd_report creates output directory."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    minimal_args.results_dir_pos = str(results_dir)
    minimal_args.out = str(tmp_path / "custom-out")

    mock_log = MagicMock()

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch("scripts.cli.report_orchestrator.write_json"),
    ):
        with patch("scripts.cli.report_orchestrator.write_markdown"):
            cmd_report(minimal_args, mock_log)

    # Verify custom output directory created
    assert (tmp_path / "custom-out").exists()


def test_cmd_report_profiling_environment_setup(tmp_path, mock_config, minimal_args):
    """Test cmd_report sets profiling environment variables."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)
    minimal_args.profile = True
    minimal_args.threads = 8

    mock_log = MagicMock()

    # Store original environment
    orig_profile = os.getenv("JMO_PROFILE")
    orig_threads = os.getenv("JMO_THREADS")

    try:
        with (
            patch(
                "scripts.cli.report_orchestrator.load_config_with_env_overrides",
                return_value=mock_config,
            ),
            patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
            patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
            patch("scripts.cli.report_orchestrator.write_json"),
        ):
            with patch("scripts.cli.report_orchestrator.write_markdown"):
                # Verify environment set during execution
                def check_env(*args, **kwargs):
                    assert os.getenv("JMO_PROFILE") == "1"
                    assert os.getenv("JMO_THREADS") == "8"
                    return []

                    with patch(
                        "scripts.cli.report_orchestrator.gather_results",
                        side_effect=check_env,
                    ):
                        cmd_report(minimal_args, mock_log)

        # Verify environment restored after execution
        assert os.getenv("JMO_PROFILE") == orig_profile
        assert os.getenv("JMO_THREADS") == orig_threads

    finally:
        # Cleanup
        if orig_profile is not None:
            os.environ["JMO_PROFILE"] = orig_profile
        elif "JMO_PROFILE" in os.environ:
            del os.environ["JMO_PROFILE"]

        if orig_threads is not None:
            os.environ["JMO_THREADS"] = orig_threads
        elif "JMO_THREADS" in os.environ:
            del os.environ["JMO_THREADS"]


def test_cmd_report_gathers_findings_and_applies_suppressions(
    tmp_path, mock_config, minimal_args
):
    """Test cmd_report gathers findings and applies suppressions."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

    # Create suppression file
    sup_file = results_dir / "jmo.suppress.yml"
    sup_file.write_text("suppressions: []", encoding="utf-8")

    sample_findings = [
        {"id": "f1", "severity": "HIGH"},
        {"id": "f2", "severity": "MEDIUM"},
    ]

    sample_suppressions = {"f1": MagicMock(id="f1")}

    mock_log = MagicMock()

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch(
            "scripts.cli.report_orchestrator.gather_results",
            return_value=sample_findings,
        ),
        patch(
            "scripts.cli.report_orchestrator.load_suppressions",
            return_value=sample_suppressions,
        ),
        patch(
            "scripts.cli.report_orchestrator.filter_suppressed_with_summary",
            return_value=(
                [{"id": "f2", "severity": "MEDIUM"}],
                MagicMock(
                    suppressed_ids=["f1"],
                    total_suppressed=1,
                    debt_label="Suppression debt: 1 findings (1 HIGH)",
                ),
            ),
        ),
        patch("scripts.cli.report_orchestrator.write_json"),
    ):
        with patch("scripts.cli.report_orchestrator.write_markdown"):
            with patch(
                "scripts.cli.report_orchestrator.write_suppression_report"
            ) as mock_sup_report:
                cmd_report(minimal_args, mock_log)

    # Verify suppression report written
    assert mock_sup_report.called


def test_cmd_report_writes_all_output_formats(tmp_path, mock_config, minimal_args):
    """Test cmd_report writes all configured output formats."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

    # Enable all output formats
    mock_config.outputs = ["json", "md", "yaml", "html", "simple-html", "sarif", "csv"]
    mock_config.csv = {"columns": ["id", "severity"]}

    mock_log = MagicMock()

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch("scripts.cli.report_orchestrator.write_json") as mock_json,
        patch("scripts.cli.report_orchestrator.write_markdown") as mock_md,
        patch("scripts.cli.report_orchestrator.write_yaml") as mock_yaml,
        patch("scripts.cli.report_orchestrator.write_html") as mock_html,
        patch("scripts.cli.report_orchestrator.write_simple_html") as mock_simple_html,
        patch("scripts.cli.report_orchestrator.write_sarif") as mock_sarif,
        patch("scripts.cli.report_orchestrator.write_csv") as mock_csv,
    ):
        cmd_report(minimal_args, mock_log)

    # Verify all output formats written
    assert mock_json.called
    assert mock_md.called
    assert mock_yaml.called
    assert mock_html.called
    assert mock_simple_html.called
    assert mock_sarif.called
    assert mock_csv.called
    # Verify CSV called with columns
    assert mock_csv.call_args[1]["columns"] == ["id", "severity"]


def test_cmd_report_yaml_runtime_error_handling(tmp_path, mock_config, minimal_args):
    """Test cmd_report handles YAML RuntimeError gracefully."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)
    mock_config.outputs = ["yaml"]

    mock_log = MagicMock()

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch(
            "scripts.cli.report_orchestrator.write_yaml",
            side_effect=RuntimeError("PyYAML not installed"),
        ),
    ):
        cmd_report(minimal_args, mock_log)

    # The config asked for findings.yaml and it will not exist, so this must be
    # visible in a normal run -- it was DEBUG, i.e. invisible. Assert the level
    # rather than the wording.
    warned = [
        c.args[2]
        for c in mock_log.call_args_list
        if len(c.args) >= 3 and str(c.args[1]).upper() in ("WARN", "ERROR")
    ]
    assert any("yaml" in str(m).lower() for m in warned), mock_log.call_args_list


def test_cmd_report_writes_compliance_reports(tmp_path, mock_config, minimal_args):
    """Test cmd_report writes compliance framework reports."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

    mock_log = MagicMock()

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch(
            "scripts.cli.report_orchestrator.write_compliance_summary"
        ) as mock_compliance,
        patch("scripts.cli.report_orchestrator.write_pci_dss_report") as mock_pci,
        patch(
            "scripts.cli.report_orchestrator.write_attack_navigator_json"
        ) as mock_attack,
    ):
        cmd_report(minimal_args, mock_log)

    assert mock_compliance.called
    assert mock_pci.called
    assert mock_attack.called


def test_cmd_report_compliance_report_error_handling(
    tmp_path, mock_config, minimal_args
):
    """Test cmd_report handles compliance report errors gracefully."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

    mock_log = MagicMock()

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch(
            "scripts.cli.report_orchestrator.write_compliance_summary",
            side_effect=OSError("Disk full"),
        ),
    ):
        cmd_report(minimal_args, mock_log)

    # Should not crash, just log DEBUG
    assert any(
        "Failed to write compliance reports" in str(c) for c in mock_log.call_args_list
    )


def test_cmd_report_policy_evaluation_cli_args(tmp_path, mock_config, minimal_args):
    """Test cmd_report evaluates policies from CLI arguments."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)
    minimal_args.policies = ["no_high_severity", "require_cwe"]

    mock_policy_result = MagicMock()
    mock_policy_result.passed = True

    mock_log = MagicMock()

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch("scripts.cli.report_orchestrator.gather_results", return_value=[]):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch(
                    "scripts.core.reporters.policy_reporter.evaluate_policies",
                    return_value={"no_high_severity": mock_policy_result},
                ):
                    with patch(
                        "scripts.core.reporters.policy_reporter.write_policy_report"
                    ) as mock_policy_report:
                        with patch(
                            "scripts.core.reporters.policy_reporter.write_policy_json"
                        ):
                            with patch(
                                "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                            ):
                                cmd_report(minimal_args, mock_log)

    assert mock_policy_report.called


def test_cmd_report_policy_evaluation_config(tmp_path, mock_config, minimal_args):
    """Test cmd_report evaluates policies from config."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

    # Enable policies in config
    mock_config.policy.enabled = True
    mock_config.policy.auto_evaluate = True
    mock_config.policy.default_policies = ["policy1", "policy2"]

    mock_policy_result = MagicMock()
    mock_policy_result.passed = True

    mock_log = MagicMock()

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch("scripts.cli.report_orchestrator.gather_results", return_value=[]):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch(
                    "scripts.core.reporters.policy_reporter.evaluate_policies",
                    return_value={"policy1": mock_policy_result},
                ):
                    with patch(
                        "scripts.core.reporters.policy_reporter.write_policy_report"
                    ):
                        with patch(
                            "scripts.core.reporters.policy_reporter.write_policy_json"
                        ):
                            with patch(
                                "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                            ):
                                cmd_report(minimal_args, mock_log)

    assert any("Using policies from config" in str(c) for c in mock_log.call_args_list)


def test_cmd_report_policy_fail_on_violation(tmp_path, mock_config, minimal_args):
    """Test cmd_report returns 1 when policies fail and fail_on_violation=True."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)
    minimal_args.policies = ["policy1"]
    minimal_args.fail_on_policy_violation = True

    mock_policy_result_passed = MagicMock()
    mock_policy_result_passed.passed = True

    mock_policy_result_failed = MagicMock()
    mock_policy_result_failed.passed = False

    mock_log = MagicMock()

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch("scripts.cli.report_orchestrator.gather_results", return_value=[]):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch(
                    "scripts.core.reporters.policy_reporter.evaluate_policies",
                    return_value={
                        "policy1": mock_policy_result_failed,
                        "policy2": mock_policy_result_passed,
                    },
                ):
                    with patch(
                        "scripts.core.reporters.policy_reporter.write_policy_report"
                    ):
                        with patch(
                            "scripts.core.reporters.policy_reporter.write_policy_json"
                        ):
                            with patch(
                                "scripts.core.reporters.policy_reporter.write_policy_summary_md"
                            ):
                                rc = cmd_report(minimal_args, mock_log)

    assert rc == 1


def test_cmd_report_severity_threshold_exit_code(tmp_path, mock_config, minimal_args):
    """Test cmd_report returns 1 when severity threshold exceeded."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)
    minimal_args.fail_on = "HIGH"

    findings_with_high = [
        {"id": "f1", "severity": "HIGH", "tool": {"name": "trivy"}},
    ]

    mock_log = MagicMock()

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch(
            "scripts.cli.report_orchestrator.gather_results",
            return_value=findings_with_high,
        ),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch("scripts.cli.report_orchestrator.write_json"),
    ):
        with patch("scripts.cli.report_orchestrator.write_markdown"):
            rc = cmd_report(minimal_args, mock_log)

    assert rc == 1


def test_cmd_report_history_database_storage(tmp_path, mock_config, minimal_args):
    """Test cmd_report stores scan in history database when requested."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)
    minimal_args.store_history = True
    minimal_args.history_db = str(tmp_path / "history.db")

    mock_log = MagicMock()

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch("scripts.cli.report_orchestrator.write_json"),
    ):
        with patch("scripts.cli.report_orchestrator.write_markdown"):
            with patch(
                "scripts.core.history_db.store_scan",
                return_value="scan-id-123",
            ) as mock_store:
                cmd_report(minimal_args, mock_log)

    assert mock_store.called
    assert any("Stored scan in history" in str(c) for c in mock_log.call_args_list)


def test_cmd_report_profiling_data_written(tmp_path, mock_config, minimal_args):
    """Test cmd_report writes profiling data when profile=True."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)
    minimal_args.profile = True

    mock_log = MagicMock()

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch("scripts.cli.report_orchestrator.write_json"),
    ):
        with patch("scripts.cli.report_orchestrator.write_markdown"):
            cmd_report(minimal_args, mock_log)

    # Verify timings.json created
    timings_file = results_dir / "summaries" / "timings.json"
    assert timings_file.exists()
    timings_data = json.loads(timings_file.read_text())
    assert "aggregate_seconds" in timings_data
    assert "recommended_threads" in timings_data


# =============================================================================
# Bug #3 + #5: Scan metadata tests
# =============================================================================


def test_cmd_report_reads_profile_from_scan_metadata(
    tmp_path, mock_config, minimal_args
):
    """Test cmd_report reads profile from .scan_metadata.json.

    Bug #3 fix: Profile name should be read from scan metadata file
    instead of falling back to config's default_profile.
    """
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

    # Create scan metadata file with "deep" profile
    scan_metadata = {
        "profile": "deep",
        "tools": ["trivy", "semgrep", "bandit", "hadolint"],
        "timestamp": "2025-01-15T10:00:00+00:00",
        "target_count": 1,
    }
    scan_metadata_path = results_dir / ".scan_metadata.json"
    scan_metadata_path.write_text(json.dumps(scan_metadata), encoding="utf-8")

    # Config has different default profile
    mock_config.default_profile = "balanced"

    mock_log = MagicMock()
    captured_metadata = {}

    def capture_metadata(findings, path, metadata=None):
        """Capture metadata passed to write_json."""
        if metadata:
            captured_metadata.update(metadata)

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch(
            "scripts.cli.report_orchestrator.write_json",
            side_effect=capture_metadata,
        ),
        patch("scripts.cli.report_orchestrator.write_markdown"),
    ):
        cmd_report(minimal_args, mock_log)

    # Verify profile is "deep" from scan metadata, not "balanced" from config
    assert captured_metadata.get("profile") == "deep"


def test_cmd_report_reads_tools_from_scan_metadata(tmp_path, mock_config, minimal_args):
    """Test cmd_report reads tools list from .scan_metadata.json.

    Bug #5 fix: meta.tools should include all tools from scan,
    not just tools that produced findings.
    """
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

    # Create scan metadata with 4 tools
    scan_metadata = {
        "profile": "deep",
        "tools": ["trivy", "semgrep", "bandit", "hadolint"],
        "timestamp": "2025-01-15T10:00:00+00:00",
        "target_count": 1,
    }
    scan_metadata_path = results_dir / ".scan_metadata.json"
    scan_metadata_path.write_text(json.dumps(scan_metadata), encoding="utf-8")

    # Only trivy has findings
    findings_with_single_tool = [
        {"id": "f1", "severity": "HIGH", "tool": {"name": "trivy"}},
    ]

    mock_log = MagicMock()
    captured_metadata = {}

    def capture_metadata(findings, path, metadata=None):
        if metadata:
            captured_metadata.update(metadata)

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch(
            "scripts.cli.report_orchestrator.gather_results",
            return_value=findings_with_single_tool,
        ),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch(
            "scripts.cli.report_orchestrator.write_json",
            side_effect=capture_metadata,
        ),
        patch("scripts.cli.report_orchestrator.write_markdown"),
    ):
        cmd_report(minimal_args, mock_log)

    # Verify all 4 tools from scan metadata are included, not just trivy
    assert set(captured_metadata.get("tools", [])) == {
        "trivy",
        "semgrep",
        "bandit",
        "hadolint",
    }


def test_cmd_report_falls_back_to_config_profile(tmp_path, mock_config, minimal_args):
    """Test cmd_report falls back to config profile when no scan metadata."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

    # No .scan_metadata.json file
    mock_config.default_profile = "balanced"

    mock_log = MagicMock()
    captured_metadata = {}

    def capture_metadata(findings, path, metadata=None):
        if metadata:
            captured_metadata.update(metadata)

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch(
            "scripts.cli.report_orchestrator.write_json",
            side_effect=capture_metadata,
        ),
        patch("scripts.cli.report_orchestrator.write_markdown"),
    ):
        cmd_report(minimal_args, mock_log)

    # Should fall back to config default_profile
    assert captured_metadata.get("profile") == "balanced"


def test_cmd_report_handles_corrupt_scan_metadata(tmp_path, mock_config, minimal_args):
    """Test cmd_report handles corrupt .scan_metadata.json gracefully."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

    # Create corrupt scan metadata file
    scan_metadata_path = results_dir / ".scan_metadata.json"
    scan_metadata_path.write_text("{ invalid json", encoding="utf-8")

    mock_config.default_profile = "balanced"

    mock_log = MagicMock()
    captured_metadata = {}

    def capture_metadata(findings, path, metadata=None):
        if metadata:
            captured_metadata.update(metadata)

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch(
            "scripts.cli.report_orchestrator.write_json",
            side_effect=capture_metadata,
        ),
        patch("scripts.cli.report_orchestrator.write_markdown"),
    ):
        cmd_report(minimal_args, mock_log)

    # Should gracefully fall back to config default_profile
    assert captured_metadata.get("profile") == "balanced"


def test_cmd_report_infers_tools_from_findings_without_metadata(
    tmp_path, mock_config, minimal_args
):
    """Test cmd_report infers tools from findings when no scan metadata exists."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

    # No .scan_metadata.json file
    findings = [
        {"id": "f1", "severity": "HIGH", "tool": {"name": "trivy"}},
        {"id": "f2", "severity": "MEDIUM", "tool": {"name": "semgrep"}},
    ]

    mock_log = MagicMock()
    captured_metadata = {}

    def capture_metadata(findings, path, metadata=None):
        if metadata:
            captured_metadata.update(metadata)

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=findings),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch(
            "scripts.cli.report_orchestrator.write_json",
            side_effect=capture_metadata,
        ),
        patch("scripts.cli.report_orchestrator.write_markdown"),
    ):
        cmd_report(minimal_args, mock_log)

    # Should infer tools from findings
    assert set(captured_metadata.get("tools", [])) == {"semgrep", "trivy"}


def test_cmd_report_threads_auto_does_not_crash(
    tmp_path, mock_config, minimal_args, monkeypatch
):
    """`threads: auto` in jmo.yml must not crash cmd_report.

    `Config.threads` is typed `int | str | None` and is set to the literal
    string "auto" when jmo.yml says `threads: auto` (config.py). Passing that
    to int() raises ValueError, which would abort `jmo report` for any user
    who configured auto-detection. "auto" means auto-detect, so the correct
    behavior is to leave JMO_THREADS unset and let the consumer default.
    """
    monkeypatch.delenv("JMO_THREADS", raising=False)
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    minimal_args.results_dir_pos = str(results_dir)
    mock_config.threads = "auto"

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
    ):
        # Must not raise ValueError: invalid literal for int() ... 'auto'
        cmd_report(minimal_args, MagicMock())

    # "auto" => leave it to the consumer's own auto-detection
    assert "JMO_THREADS" not in os.environ


def test_cmd_report_threads_int_sets_env(
    tmp_path, mock_config, minimal_args, monkeypatch
):
    """An explicit integer `threads` is still exported to JMO_THREADS."""
    monkeypatch.delenv("JMO_THREADS", raising=False)
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    minimal_args.results_dir_pos = str(results_dir)
    mock_config.threads = 8

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
    ):
        cmd_report(minimal_args, MagicMock())

    assert os.environ.get("JMO_THREADS") == "8"


# =============================================================================
# #903: a failed history write must be visible, and only fail the run on request
# =============================================================================


def _report_with_store(
    tmp_path, mock_config, minimal_args, mock_log, *, store_raises=None, **arg_overrides
):
    """Run cmd_report with the auto-storage hook enabled.

    `store_raises` is the exception `store_scan` should raise, or None for a
    successful store. Returns cmd_report's exit code.
    """
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)
    minimal_args.store_history = True
    minimal_args.history_db = str(tmp_path / "history.db")
    for key, value in arg_overrides.items():
        setattr(minimal_args, key, value)

    if store_raises is None:
        store = MagicMock(return_value="scan-uuid")
    else:
        store = MagicMock(side_effect=store_raises)

    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch("scripts.cli.report_orchestrator.write_json"),
        patch("scripts.cli.report_orchestrator.write_markdown"),
        patch("scripts.core.history_db.store_scan", store),
    ):
        return cmd_report(minimal_args, mock_log)


def _levels(mock_log):
    """Levels passed to the log function, in order."""
    return [call.args[1] for call in mock_log.call_args_list if len(call.args) > 1]


def _messages(mock_log, level):
    return [
        call.args[2]
        for call in mock_log.call_args_list
        if len(call.args) > 2 and call.args[1] == level
    ]


def test_successful_store_logs_no_error(tmp_path, mock_config, minimal_args):
    mock_log = MagicMock()
    rc = _report_with_store(tmp_path, mock_config, minimal_args, mock_log)
    assert rc == 0
    assert "ERROR" not in _levels(mock_log)


def test_failed_store_does_not_change_the_exit_code_by_default(
    tmp_path, mock_config, minimal_args
):
    """Storage is on unless --no-store-history, so failing by default would
    redden scans for users who never asked for history."""
    mock_log = MagicMock()
    rc = _report_with_store(
        tmp_path,
        mock_config,
        minimal_args,
        mock_log,
        store_raises=RuntimeError("disk on fire"),
    )
    assert rc == 0


def test_failed_store_is_reported_at_error_naming_the_consequence(
    tmp_path, mock_config, minimal_args
):
    mock_log = MagicMock()
    _report_with_store(
        tmp_path,
        mock_config,
        minimal_args,
        mock_log,
        store_raises=RuntimeError("disk on fire"),
    )
    errors = _messages(mock_log, "ERROR")
    assert errors, "a failed history write must be reported at ERROR"
    joined = " ".join(errors)
    # The consequence, not just the exception -- a WARN saying "failed to store"
    # scrolled past and read as cosmetic (#903).
    assert "NOT recorded" in joined
    assert "disk on fire" in joined
    assert "jmo history store" in joined, "must say how to re-record the scan"
    assert "--fail-on-store-error" in joined, "must name the opt-in flag"


def test_failed_store_traceback_is_debug_not_user_facing(
    tmp_path, mock_config, minimal_args, capsys
):
    """A recoverable condition must not print a stack trace into scan output."""
    mock_log = MagicMock()
    _report_with_store(
        tmp_path,
        mock_config,
        minimal_args,
        mock_log,
        store_raises=RuntimeError("disk on fire"),
    )
    captured = capsys.readouterr()
    assert "Traceback (most recent call last)" not in captured.out
    assert "Traceback (most recent call last)" not in captured.err
    # It is still recoverable at DEBUG for whoever needs it.
    assert any("traceback" in m.lower() for m in _messages(mock_log, "DEBUG"))


def test_fail_on_store_error_makes_a_failed_store_non_zero(
    tmp_path, mock_config, minimal_args
):
    mock_log = MagicMock()
    rc = _report_with_store(
        tmp_path,
        mock_config,
        minimal_args,
        mock_log,
        store_raises=RuntimeError("disk on fire"),
        fail_on_store_error=True,
    )
    assert rc == 1


def test_fail_on_store_error_does_not_fail_a_successful_store(
    tmp_path, mock_config, minimal_args
):
    """The flag must not turn every run non-zero -- the negative control."""
    mock_log = MagicMock()
    rc = _report_with_store(
        tmp_path, mock_config, minimal_args, mock_log, fail_on_store_error=True
    )
    assert rc == 0


def test_storage_disabled_is_unaffected(tmp_path, mock_config, minimal_args):
    """The store_error / history_db_path bindings must exist even when no store
    is attempted, or the exit-code check below them raises NameError."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)
    minimal_args.store_history = False
    minimal_args.fail_on_store_error = True

    mock_log = MagicMock()
    with (
        patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ),
        patch("scripts.cli.report_orchestrator.gather_results", return_value=[]),
        patch("scripts.cli.report_orchestrator.load_suppressions", return_value={}),
        patch("scripts.cli.report_orchestrator.write_json"),
        patch("scripts.cli.report_orchestrator.write_markdown"),
    ):
        assert cmd_report(minimal_args, mock_log) == 0
    assert "ERROR" not in _levels(mock_log)


def test_real_parser_defines_fail_on_store_error_off_by_default(monkeypatch):
    """Uses the real parser, not a stand-in: a mirror cannot notice a flag the
    parser never defined (the chunk 11 lesson)."""
    import sys

    from scripts.cli.jmo import parse_args

    monkeypatch.setattr(sys, "argv", ["jmo", "scan", "--repo", "."])
    assert parse_args().fail_on_store_error is False

    monkeypatch.setattr(
        sys, "argv", ["jmo", "scan", "--repo", ".", "--fail-on-store-error"]
    )
    assert parse_args().fail_on_store_error is True


def test_ci_forwards_fail_on_store_error_to_the_report_phase(monkeypatch):
    """`jmo ci` must not drop the flag -- #876's class of defect."""
    import sys

    from scripts.cli.ci_orchestrator import _REPORT_REQUIRED, _phase_args
    from scripts.cli.jmo import parse_args

    monkeypatch.setattr(
        sys, "argv", ["jmo", "ci", "--repo", ".", "--fail-on-store-error"]
    )
    args = parse_args()
    forwarded = _phase_args(args, _REPORT_REQUIRED)
    assert forwarded.fail_on_store_error is True
