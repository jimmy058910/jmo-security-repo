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
- Telemetry events
- History database storage
"""

import json
import logging
import os
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from scripts.cli.report_orchestrator import fail_code, cmd_report, SEV_ORDER


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

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch("scripts.cli.report_orchestrator.gather_results", return_value=[]):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch("scripts.cli.report_orchestrator.write_json"):
                    with patch("scripts.cli.report_orchestrator.write_markdown"):
                        with patch("scripts.cli.report_orchestrator.send_event"):
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

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch("scripts.cli.report_orchestrator.gather_results", return_value=[]):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch("scripts.cli.report_orchestrator.write_json"):
                    with patch("scripts.cli.report_orchestrator.write_markdown"):
                        with patch("scripts.cli.report_orchestrator.send_event"):
                            rc = cmd_report(minimal_args, mock_log)

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
        with patch(
            "scripts.cli.report_orchestrator.load_config_with_env_overrides",
            return_value=mock_config,
        ):
            with patch(
                "scripts.cli.report_orchestrator.gather_results", return_value=[]
            ):
                with patch(
                    "scripts.cli.report_orchestrator.load_suppressions", return_value={}
                ):
                    with patch("scripts.cli.report_orchestrator.write_json"):
                        with patch("scripts.cli.report_orchestrator.write_markdown"):
                            with patch("scripts.cli.report_orchestrator.send_event"):
                                # Verify environment set during execution
                                def check_env(*args, **kwargs):
                                    assert os.getenv("JMO_PROFILE") == "1"
                                    assert os.getenv("JMO_THREADS") == "8"
                                    return []

                                with patch(
                                    "scripts.cli.report_orchestrator.gather_results",
                                    side_effect=check_env,
                                ):
                                    rc = cmd_report(minimal_args, mock_log)

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

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch(
            "scripts.cli.report_orchestrator.gather_results",
            return_value=sample_findings,
        ):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions",
                return_value=sample_suppressions,
            ):
                with patch(
                    "scripts.cli.report_orchestrator.filter_suppressed",
                    return_value=[{"id": "f2", "severity": "MEDIUM"}],
                ):
                    with patch("scripts.cli.report_orchestrator.write_json"):
                        with patch("scripts.cli.report_orchestrator.write_markdown"):
                            with patch(
                                "scripts.cli.report_orchestrator.write_suppression_report"
                            ) as mock_sup_report:
                                with patch(
                                    "scripts.cli.report_orchestrator.send_event"
                                ):
                                    rc = cmd_report(minimal_args, mock_log)

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

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch("scripts.cli.report_orchestrator.gather_results", return_value=[]):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch("scripts.cli.report_orchestrator.write_json") as mock_json:
                    with patch(
                        "scripts.cli.report_orchestrator.write_markdown"
                    ) as mock_md:
                        with patch(
                            "scripts.cli.report_orchestrator.write_yaml"
                        ) as mock_yaml:
                            with patch(
                                "scripts.cli.report_orchestrator.write_html"
                            ) as mock_html:
                                with patch(
                                    "scripts.cli.report_orchestrator.write_simple_html"
                                ) as mock_simple_html:
                                    with patch(
                                        "scripts.cli.report_orchestrator.write_sarif"
                                    ) as mock_sarif:
                                        with patch(
                                            "scripts.cli.report_orchestrator.write_csv"
                                        ) as mock_csv:
                                            with patch(
                                                "scripts.cli.report_orchestrator.send_event"
                                            ):
                                                rc = cmd_report(minimal_args, mock_log)

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

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch("scripts.cli.report_orchestrator.gather_results", return_value=[]):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch(
                    "scripts.cli.report_orchestrator.write_yaml",
                    side_effect=RuntimeError("PyYAML not installed"),
                ):
                    with patch("scripts.cli.report_orchestrator.send_event"):
                        rc = cmd_report(minimal_args, mock_log)

    # Verify DEBUG log for YAML unavailable
    assert any("YAML reporter unavailable" in str(c) for c in mock_log.call_args_list)


def test_cmd_report_writes_compliance_reports(tmp_path, mock_config, minimal_args):
    """Test cmd_report writes compliance framework reports."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

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
                    "scripts.cli.report_orchestrator.write_compliance_summary"
                ) as mock_compliance:
                    with patch(
                        "scripts.cli.report_orchestrator.write_pci_dss_report"
                    ) as mock_pci:
                        with patch(
                            "scripts.cli.report_orchestrator.write_attack_navigator_json"
                        ) as mock_attack:
                            with patch("scripts.cli.report_orchestrator.send_event"):
                                rc = cmd_report(minimal_args, mock_log)

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

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch("scripts.cli.report_orchestrator.gather_results", return_value=[]):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch(
                    "scripts.cli.report_orchestrator.write_compliance_summary",
                    side_effect=OSError("Disk full"),
                ):
                    with patch("scripts.cli.report_orchestrator.send_event"):
                        rc = cmd_report(minimal_args, mock_log)

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
                                with patch(
                                    "scripts.cli.report_orchestrator.send_policy_evaluation_event"
                                ):
                                    with patch(
                                        "scripts.cli.report_orchestrator.send_event"
                                    ):
                                        rc = cmd_report(minimal_args, mock_log)

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
                                with patch(
                                    "scripts.cli.report_orchestrator.send_policy_evaluation_event"
                                ):
                                    with patch(
                                        "scripts.cli.report_orchestrator.send_event"
                                    ):
                                        rc = cmd_report(minimal_args, mock_log)

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
                                with patch(
                                    "scripts.cli.report_orchestrator.send_policy_evaluation_event"
                                ):
                                    with patch(
                                        "scripts.cli.report_orchestrator.send_event"
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

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch(
            "scripts.cli.report_orchestrator.gather_results",
            return_value=findings_with_high,
        ):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch("scripts.cli.report_orchestrator.write_json"):
                    with patch("scripts.cli.report_orchestrator.write_markdown"):
                        with patch("scripts.cli.report_orchestrator.send_event"):
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

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch("scripts.cli.report_orchestrator.gather_results", return_value=[]):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch("scripts.cli.report_orchestrator.write_json"):
                    with patch("scripts.cli.report_orchestrator.write_markdown"):
                        with patch(
                            "scripts.core.history_db.store_scan",
                            return_value="scan-id-123",
                        ) as mock_store:
                            with patch("scripts.cli.report_orchestrator.send_event"):
                                rc = cmd_report(minimal_args, mock_log)

    assert mock_store.called
    assert any("Stored scan in history" in str(c) for c in mock_log.call_args_list)


def test_cmd_report_telemetry_event(tmp_path, mock_config, minimal_args):
    """Test cmd_report sends telemetry event."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)

    mock_log = MagicMock()

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch("scripts.cli.report_orchestrator.gather_results", return_value=[]):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch("scripts.cli.report_orchestrator.write_json"):
                    with patch("scripts.cli.report_orchestrator.write_markdown"):
                        with patch(
                            "scripts.cli.report_orchestrator.send_event"
                        ) as mock_send:
                            rc = cmd_report(minimal_args, mock_log)

    assert mock_send.called
    # Verify event name
    assert mock_send.call_args[0][0] == "report.generated"


def test_cmd_report_profiling_data_written(tmp_path, mock_config, minimal_args):
    """Test cmd_report writes profiling data when profile=True."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    minimal_args.results_dir_pos = str(results_dir)
    minimal_args.profile = True

    mock_log = MagicMock()

    with patch(
        "scripts.cli.report_orchestrator.load_config_with_env_overrides",
        return_value=mock_config,
    ):
        with patch("scripts.cli.report_orchestrator.gather_results", return_value=[]):
            with patch(
                "scripts.cli.report_orchestrator.load_suppressions", return_value={}
            ):
                with patch("scripts.cli.report_orchestrator.write_json"):
                    with patch("scripts.cli.report_orchestrator.write_markdown"):
                        with patch("scripts.cli.report_orchestrator.send_event"):
                            rc = cmd_report(minimal_args, mock_log)

    # Verify timings.json created
    timings_file = results_dir / "summaries" / "timings.json"
    assert timings_file.exists()
    timings_data = json.loads(timings_file.read_text())
    assert "aggregate_seconds" in timings_data
    assert "recommended_threads" in timings_data
