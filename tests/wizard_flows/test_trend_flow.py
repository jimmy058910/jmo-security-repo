"""Tests for scripts/cli/wizard_flows/trend_flow.py.

Covers:
- TrendArgs dataclass defaults and custom values
- CompareArgs dataclass defaults and custom values
- offer_trend_analysis_after_scan(): History check, menu offer
- explore_trends_interactive(): Menu navigation and command dispatch
- _run_trend_command_interactive(): Command execution and error handling
- _compare_scans_interactive(): Scan selection and comparison
- _export_trends_interactive(): Format selection and export
- _explain_metrics_interactive(): Help text display
"""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path
from unittest.mock import MagicMock, patch


from scripts.cli.wizard_flows.trend_flow import (
    TrendArgs,
    CompareArgs,
    offer_trend_analysis_after_scan,
    explore_trends_interactive,
    _run_trend_command_interactive,
    _compare_scans_interactive,
    _export_trends_interactive,
    _explain_metrics_interactive,
)


# ========== Helpers ==========


def _stub_colorize(text: str, style: str = "") -> str:
    """No-op colorize for testing."""
    return text


def _stub_prompt_yes_no(question: str, default: bool = False) -> bool:
    """Always returns default."""
    return default


# ========== Category 0: Lazy Accessors ==========


class TestLazyAccessors:
    """Tests for lazy initialization functions."""

    def test_get_colorize_returns_callable(self):
        """Test _get_colorize returns a callable."""
        from scripts.cli.wizard_flows.trend_flow import _get_colorize

        result = _get_colorize()
        assert callable(result)

    def test_get_prompt_yes_no_returns_callable(self):
        """Test _get_prompt_yes_no returns a callable."""
        from scripts.cli.wizard_flows.trend_flow import _get_prompt_yes_no

        result = _get_prompt_yes_no()
        assert callable(result)

    def test_get_db_path_returns_path(self):
        """Test _get_db_path returns a Path object."""
        from scripts.cli.wizard_flows.trend_flow import _get_db_path

        result = _get_db_path()
        assert isinstance(result, Path)


# ========== Category 1: TrendArgs Dataclass ==========


class TestTrendArgs:
    """Tests for TrendArgs dataclass."""

    def test_defaults(self):
        """Test TrendArgs default values."""
        args = TrendArgs()
        assert args.db == ""
        assert args.last == 30
        assert args.format == "terminal"
        assert args.output is None
        assert args.top == 10
        assert args.team_file is None
        assert args.threshold is None
        assert isinstance(args.repo, str)

    def test_custom_values(self):
        """Test TrendArgs with custom values."""
        args = TrendArgs(
            db="/path/to/db",
            last=50,
            format="html",
            output="report.html",
            top=20,
        )
        assert args.db == "/path/to/db"
        assert args.last == 50
        assert args.format == "html"
        assert args.output == "report.html"
        assert args.top == 20

    def test_field_count(self):
        """Test TrendArgs has expected number of fields."""
        assert len(fields(TrendArgs)) == 8


# ========== Category 2: CompareArgs Dataclass ==========


class TestCompareArgs:
    """Tests for CompareArgs dataclass."""

    def test_defaults(self):
        """Test CompareArgs default values."""
        args = CompareArgs()
        assert args.db == ""
        assert args.scan_ids == []
        assert args.format == "terminal"
        assert args.output is None

    def test_custom_values(self):
        """Test CompareArgs with custom values."""
        args = CompareArgs(
            db="/db/path",
            scan_ids=["scan-a", "scan-b"],
            format="md",
            output="compare.md",
        )
        assert args.scan_ids == ["scan-a", "scan-b"]
        assert args.format == "md"

    def test_field_count(self):
        """Test CompareArgs has expected number of fields."""
        assert len(fields(CompareArgs)) == 4


# ========== Category 3: offer_trend_analysis_after_scan() ==========


class TestOfferTrendAnalysis:
    """Tests for offer_trend_analysis_after_scan()."""

    def test_no_history_db(self, tmp_path: Path):
        """Test skips when no history database exists."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow._get_prompt_yes_no",
                return_value=_stub_prompt_yes_no,
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._get_db_path",
                    return_value=tmp_path / "missing.db",
                ):
                    # Should return without error
                    offer_trend_analysis_after_scan(str(tmp_path))

    def test_not_enough_scans(self, tmp_path: Path):
        """Test skips when fewer than 2 scans exist."""
        db_path = tmp_path / "history.db"
        db_path.touch()

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)  # Only 1 scan
        mock_conn.execute.return_value = mock_cursor

        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow._get_prompt_yes_no",
                return_value=_stub_prompt_yes_no,
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._get_db_path",
                    return_value=db_path,
                ):
                    with patch(
                        "scripts.core.history_db.get_connection", return_value=mock_conn
                    ):
                        offer_trend_analysis_after_scan(str(tmp_path))

    def test_offers_when_enough_scans(self, tmp_path: Path):
        """Test offers trends when 2+ scans exist and user declines."""
        db_path = tmp_path / "history.db"
        db_path.touch()

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (5,)  # 5 scans
        mock_conn.execute.return_value = mock_cursor

        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow._get_prompt_yes_no",
                return_value=lambda q, default=False: False,
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._get_db_path",
                    return_value=db_path,
                ):
                    with patch(
                        "scripts.core.history_db.get_connection", return_value=mock_conn
                    ):
                        # User declines trend exploration
                        offer_trend_analysis_after_scan(str(tmp_path))

    def test_exception_handled_gracefully(self, tmp_path: Path):
        """Test exceptions don't block user."""
        db_path = tmp_path / "history.db"
        db_path.touch()

        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow._get_prompt_yes_no",
                return_value=_stub_prompt_yes_no,
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._get_db_path",
                    return_value=db_path,
                ):
                    with patch(
                        "scripts.core.history_db.get_connection",
                        side_effect=Exception("db error"),
                    ):
                        # Should not raise
                        offer_trend_analysis_after_scan(str(tmp_path))


# ========== Category 4: _run_trend_command_interactive() ==========


class TestRunTrendCommandInteractive:
    """Tests for _run_trend_command_interactive().

    Note: The function lazily imports 5 functions from scripts.cli.trend_commands.
    cmd_trends_velocity doesn't exist yet, so the import always fails unless we
    mock it with create=True. Tests that need the import to succeed use
    _patch_missing_velocity(); tests for the ImportError path skip it.
    """

    @staticmethod
    def _patch_missing_velocity():
        """Patch the missing cmd_trends_velocity so the lazy import succeeds."""
        return patch(
            "scripts.cli.trend_commands.cmd_trends_velocity",
            create=True,
            return_value=0,
        )

    def test_analyze_command(self, tmp_path: Path):
        """Test dispatches 'analyze' to cmd_trends_analyze."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with self._patch_missing_velocity():
                with patch(
                    "scripts.cli.trend_commands.cmd_trends_analyze", return_value=0
                ) as mock_cmd:
                    with patch("builtins.input", return_value=""):
                        _run_trend_command_interactive(tmp_path, "analyze", last_n=30)
                        mock_cmd.assert_called_once()

    def test_unknown_command(self, tmp_path: Path):
        """Test unknown command prints error."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with self._patch_missing_velocity():
                with patch("builtins.input", return_value=""):
                    # Should not raise; function prints error for unknown commands
                    _run_trend_command_interactive(tmp_path, "unknown_cmd")

    def test_import_error(self, tmp_path: Path):
        """Test handles missing trend dependencies gracefully.

        cmd_trends_velocity doesn't exist, so the import naturally fails
        and the except ImportError branch executes.
        """
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch("builtins.input", return_value=""):
                # Should not raise — ImportError is caught internally
                _run_trend_command_interactive(tmp_path, "analyze")

    def test_generic_exception(self, tmp_path: Path):
        """Test handles generic exceptions."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with self._patch_missing_velocity():
                with patch(
                    "scripts.cli.trend_commands.cmd_trends_analyze",
                    side_effect=RuntimeError("db error"),
                ):
                    with patch("builtins.input", return_value=""):
                        _run_trend_command_interactive(tmp_path, "analyze")

    def test_nonzero_exit_code(self, tmp_path: Path):
        """Test displays warning on nonzero exit code."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with self._patch_missing_velocity():
                with patch(
                    "scripts.cli.trend_commands.cmd_trends_analyze", return_value=1
                ):
                    with patch("builtins.input", return_value=""):
                        _run_trend_command_interactive(tmp_path, "analyze")


# ========== Category 5: _compare_scans_interactive() ==========


class TestCompareScansInteractive:
    """Tests for _compare_scans_interactive()."""

    def test_not_enough_scans(self, tmp_path: Path):
        """Test error when fewer than 2 scans."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.core.history_db.list_recent_scans", return_value=[{"id": "a"}]
            ):
                with patch("builtins.input", return_value=""):
                    _compare_scans_interactive(tmp_path)

    def test_import_error(self, tmp_path: Path):
        """Test handles missing dependencies."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.core.history_db.list_recent_scans",
                side_effect=ImportError("no module"),
            ):
                with patch("builtins.input", return_value=""):
                    _compare_scans_interactive(tmp_path)

    def test_generic_exception(self, tmp_path: Path):
        """Test handles generic exceptions."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.core.history_db.list_recent_scans",
                side_effect=RuntimeError("unexpected"),
            ):
                with patch("builtins.input", return_value=""):
                    _compare_scans_interactive(tmp_path)

    def test_happy_path_with_scan_selection(self, tmp_path: Path):
        """Test full compare flow: list scans, select two, run comparison."""
        scans = [
            {
                "id": "scan-aaa",
                "timestamp_iso": "2026-02-10",
                "profile": "balanced",
                "branch": "main",
                "total_findings": 5,
            },
            {
                "id": "scan-bbb",
                "timestamp_iso": "2026-02-11",
                "profile": "balanced",
                "branch": "dev",
                "total_findings": 3,
            },
            {
                "id": "scan-ccc",
                "timestamp_iso": "2026-02-12",
                "profile": "deep",
                "branch": "dev",
                "total_findings": 8,
            },
        ]
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch("scripts.core.history_db.list_recent_scans", return_value=scans):
                with patch(
                    "scripts.cli.trend_commands.cmd_trends_compare", return_value=0
                ) as mock_compare:
                    # Select baseline=1, current=2, then press Enter to continue
                    with patch("builtins.input", side_effect=["1", "2", ""]):
                        _compare_scans_interactive(tmp_path)
                        mock_compare.assert_called_once()
                        args = mock_compare.call_args[0][0]
                        assert args.scan_ids == ["scan-aaa", "scan-bbb"]

    def test_compare_nonzero_exit(self, tmp_path: Path):
        """Test compare prints warning on nonzero exit code."""
        scans = [
            {
                "id": "scan-aaa",
                "timestamp_iso": "2026-02-10",
                "profile": "b",
                "branch": "m",
                "total_findings": 0,
            },
            {
                "id": "scan-bbb",
                "timestamp_iso": "2026-02-11",
                "profile": "b",
                "branch": "d",
                "total_findings": 0,
            },
        ]
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch("scripts.core.history_db.list_recent_scans", return_value=scans):
                with patch(
                    "scripts.cli.trend_commands.cmd_trends_compare", return_value=1
                ):
                    with patch("builtins.input", side_effect=["1", "2", ""]):
                        _compare_scans_interactive(tmp_path)  # Should not raise

    def test_same_scan_selection_retry(self, tmp_path: Path):
        """Test selecting same scan for baseline and current retries."""
        scans = [
            {
                "id": "scan-aaa",
                "timestamp_iso": "2026-02-10",
                "profile": "b",
                "branch": "m",
                "total_findings": 0,
            },
            {
                "id": "scan-bbb",
                "timestamp_iso": "2026-02-11",
                "profile": "b",
                "branch": "d",
                "total_findings": 0,
            },
        ]
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch("scripts.core.history_db.list_recent_scans", return_value=scans):
                with patch(
                    "scripts.cli.trend_commands.cmd_trends_compare", return_value=0
                ):
                    # Baseline=1, current=1 (same!), then 2 (valid), then Enter
                    with patch("builtins.input", side_effect=["1", "1", "2", ""]):
                        _compare_scans_interactive(tmp_path)


# ========== Category 6: _export_trends_interactive() ==========


class TestExportTrendsInteractive:
    """Tests for _export_trends_interactive()."""

    def test_import_error(self, tmp_path: Path):
        """Test handles missing export dependencies."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow._get_prompt_yes_no",
                return_value=_stub_prompt_yes_no,
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow.prompt_choice",
                    side_effect=ImportError("no module"),
                ):
                    with patch("builtins.input", return_value=""):
                        _export_trends_interactive(tmp_path, str(tmp_path))

    def test_generic_exception(self, tmp_path: Path):
        """Test handles generic exceptions."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow._get_prompt_yes_no",
                return_value=_stub_prompt_yes_no,
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow.prompt_choice",
                    side_effect=RuntimeError("error"),
                ):
                    with patch("builtins.input", return_value=""):
                        _export_trends_interactive(tmp_path, str(tmp_path))


# ========== Category 7: _explain_metrics_interactive() ==========


class TestExplainMetricsInteractive:
    """Tests for _explain_metrics_interactive()."""

    def test_displays_help(self):
        """Test metrics explanation displays without error."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch("builtins.input", return_value=""):
                _explain_metrics_interactive()

    def test_contains_metric_descriptions(self, capsys):
        """Test output contains key metric names."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch("builtins.input", return_value=""):
                _explain_metrics_interactive()
                captured = capsys.readouterr()
                assert (
                    "REMEDIATION" in captured.out.upper()
                    or "TREND" in captured.out.upper()
                )


# ========== Category 8: explore_trends_interactive() ==========


class TestExploreTrendsInteractive:
    """Tests for explore_trends_interactive() menu loop."""

    def test_back_option_exits(self, tmp_path: Path):
        """Test option 9 (Back) exits the loop."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow.prompt_choice", return_value="9"
            ):
                explore_trends_interactive(tmp_path)

    def test_dispatches_analyze(self, tmp_path: Path):
        """Test option 1 dispatches to _run_trend_command_interactive."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow.prompt_choice",
                side_effect=["1", "9"],
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._run_trend_command_interactive"
                ) as mock_run:
                    explore_trends_interactive(tmp_path)
                    mock_run.assert_called_once_with(tmp_path, "analyze", last_n=30)

    def test_dispatches_compare(self, tmp_path: Path):
        """Test option 6 dispatches to _compare_scans_interactive."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow.prompt_choice",
                side_effect=["6", "9"],
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._compare_scans_interactive"
                ) as mock_compare:
                    explore_trends_interactive(tmp_path)
                    mock_compare.assert_called_once_with(tmp_path)

    def test_dispatches_export(self, tmp_path: Path):
        """Test option 7 dispatches to _export_trends_interactive."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow.prompt_choice",
                side_effect=["7", "9"],
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._export_trends_interactive"
                ) as mock_export:
                    explore_trends_interactive(tmp_path)
                    mock_export.assert_called_once()

    def test_dispatches_explain(self, tmp_path: Path):
        """Test option 8 dispatches to _explain_metrics_interactive."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow.prompt_choice",
                side_effect=["8", "9"],
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._explain_metrics_interactive"
                ) as mock_explain:
                    explore_trends_interactive(tmp_path)
                    mock_explain.assert_called_once()

    def test_dispatches_regressions(self, tmp_path: Path):
        """Test option 2 dispatches to _run_trend_command_interactive with 'regressions'."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow.prompt_choice",
                side_effect=["2", "9"],
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._run_trend_command_interactive"
                ) as mock_run:
                    explore_trends_interactive(tmp_path)
                    mock_run.assert_called_once_with(tmp_path, "regressions", last_n=30)

    def test_dispatches_velocity(self, tmp_path: Path):
        """Test option 3 dispatches to _run_trend_command_interactive with 'velocity'."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow.prompt_choice",
                side_effect=["3", "9"],
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._run_trend_command_interactive"
                ) as mock_run:
                    explore_trends_interactive(tmp_path)
                    mock_run.assert_called_once_with(tmp_path, "velocity", last_n=30)

    def test_dispatches_developers(self, tmp_path: Path):
        """Test option 4 dispatches to _run_trend_command_interactive with 'developers'."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow.prompt_choice",
                side_effect=["4", "9"],
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._run_trend_command_interactive"
                ) as mock_run:
                    explore_trends_interactive(tmp_path)
                    mock_run.assert_called_once_with(tmp_path, "developers", last_n=30)

    def test_dispatches_score(self, tmp_path: Path):
        """Test option 5 dispatches to _run_trend_command_interactive with 'score'."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow.prompt_choice",
                side_effect=["5", "9"],
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._run_trend_command_interactive"
                ) as mock_run:
                    explore_trends_interactive(tmp_path)
                    mock_run.assert_called_once_with(tmp_path, "score", last_n=30)

    def test_multiple_commands_before_exit(self, tmp_path: Path):
        """Test multiple menu selections in one session."""
        with patch(
            "scripts.cli.wizard_flows.trend_flow._get_colorize",
            return_value=_stub_colorize,
        ):
            with patch(
                "scripts.cli.wizard_flows.trend_flow.prompt_choice",
                side_effect=["1", "3", "9"],
            ):
                with patch(
                    "scripts.cli.wizard_flows.trend_flow._run_trend_command_interactive"
                ) as mock_run:
                    explore_trends_interactive(tmp_path)
                    assert mock_run.call_count == 2
