"""Tests for scripts/cli/wizard_flows/diff_flow.py.

Covers:
- DiffArgs dataclass defaults and field values
- _get_db_path() delegation
- run_diff_wizard_impl(): non-interactive (--yes) mode
- run_diff_wizard_impl(): interactive mode flow
- Error handling: missing dirs, no history, keyboard interrupt
"""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path
from unittest.mock import patch


from scripts.cli.wizard_flows.diff_flow import (
    DiffArgs,
    _get_db_path,
    run_diff_wizard_impl,
)

# ========== Helpers ==========


def _stub_colorize(text: str, style: str = "") -> str:
    """No-op colorize for testing."""
    return text


def _patch_diff_flow_ui():
    """Patch all UI functions in diff_flow module."""
    return [
        patch(
            "scripts.cli.wizard_flows.diff_flow._colorize", side_effect=_stub_colorize
        ),
        patch("scripts.cli.wizard_flows.diff_flow._print_step"),
        patch("scripts.cli.wizard_flows.diff_flow._prompt_yes_no", return_value=True),
    ]


# ========== Category 1: DiffArgs Dataclass ==========


class TestDiffArgs:
    """Tests for DiffArgs dataclass."""

    def test_defaults(self):
        """Test DiffArgs default values."""
        args = DiffArgs()
        assert args.directories is None
        assert args.scan_ids is None
        assert args.db == ""
        assert args.severity is None
        assert args.tool is None
        assert args.only is None
        assert args.no_modifications is False
        assert args.format == "html"
        assert args.output == "diff-report.html"

    def test_custom_values(self):
        """Test DiffArgs with custom values."""
        args = DiffArgs(
            directories=["baseline/", "current/"],
            severity="CRITICAL,HIGH",
            only="new",
            format="json",
            output="diff.json",
        )
        assert args.directories == ["baseline/", "current/"]
        assert args.severity == "CRITICAL,HIGH"
        assert args.only == "new"
        assert args.format == "json"

    def test_field_count(self):
        """Test DiffArgs has expected number of fields."""
        assert len(fields(DiffArgs)) == 9


# ========== Category 2: _get_db_path() ==========


class TestGetDbPath:
    """Tests for _get_db_path() delegation."""

    def test_delegates_to_wizard_config(self):
        """Test _get_db_path delegates to WizardConfig.get_db_path()."""
        mock_path = Path("/mock/.jmo/history.db")
        with patch("scripts.cli.wizard_flows.config_models.WizardConfig") as MockConfig:
            MockConfig.get_db_path.return_value = mock_path
            result = _get_db_path()
            assert result == mock_path
            MockConfig.get_db_path.assert_called_once()


# ========== Category 3: Non-Interactive Mode (--yes) ==========


class TestRunDiffWizardNonInteractive:
    """Tests for run_diff_wizard_impl() with yes=True."""

    def test_yes_without_baseline_current(self):
        """Test --yes without --baseline/--current returns error."""
        for ctx in _patch_diff_flow_ui():
            ctx.__enter__()
        try:
            result = run_diff_wizard_impl(yes=True, baseline=None, current=None)
            assert result == 1
        finally:
            for ctx in _patch_diff_flow_ui():
                try:
                    ctx.__exit__(None, None, None)
                except Exception:
                    pass

    def test_yes_missing_baseline_dir(self, tmp_path: Path):
        """Test --yes with nonexistent baseline directory."""
        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            result = run_diff_wizard_impl(
                yes=True,
                baseline=str(tmp_path / "nonexistent"),
                current=str(tmp_path),
            )
            assert result == 1
        finally:
            for p in patches:
                p.stop()

    def test_yes_missing_current_dir(self, tmp_path: Path):
        """Test --yes with nonexistent current directory."""
        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            result = run_diff_wizard_impl(
                yes=True,
                baseline=str(tmp_path),
                current=str(tmp_path / "nonexistent"),
            )
            assert result == 1
        finally:
            for p in patches:
                p.stop()

    def test_yes_successful_diff(self, tmp_path: Path):
        """Test --yes mode with valid dirs runs cmd_diff."""
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()

        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow._get_db_path",
                return_value=tmp_path / "history.db",
            ):
                with patch(
                    "scripts.cli.diff_commands.cmd_diff", return_value=0
                ) as mock_diff:
                    result = run_diff_wizard_impl(
                        yes=True,
                        baseline=str(baseline),
                        current=str(current),
                    )
                    assert result == 0
                    mock_diff.assert_called_once()
                    # Verify DiffArgs passed to cmd_diff
                    diff_args = mock_diff.call_args[0][0]
                    assert diff_args.directories == [str(baseline), str(current)]
                    assert (
                        diff_args.format == "json"
                    )  # Non-interactive defaults to json
        finally:
            for p in patches:
                p.stop()

    def test_yes_diff_failure(self, tmp_path: Path):
        """Test --yes mode returns cmd_diff exit code on failure."""
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()

        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow._get_db_path",
                return_value=tmp_path / "history.db",
            ):
                with patch("scripts.cli.diff_commands.cmd_diff", return_value=1):
                    result = run_diff_wizard_impl(
                        yes=True,
                        baseline=str(baseline),
                        current=str(current),
                    )
                    assert result == 1
        finally:
            for p in patches:
                p.stop()


# ========== Category 4: Interactive Mode ==========


class TestRunDiffWizardInteractive:
    """Tests for run_diff_wizard_impl() interactive mode."""

    def test_keyboard_interrupt(self):
        """Test KeyboardInterrupt returns 130."""
        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.select_mode",
                side_effect=KeyboardInterrupt,
            ):
                result = run_diff_wizard_impl(yes=False)
                assert result == 130
        finally:
            for p in patches:
                p.stop()

    def test_generic_exception(self):
        """Test generic exception returns 1."""
        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.select_mode",
                side_effect=RuntimeError("unexpected"),
            ):
                result = run_diff_wizard_impl(yes=False)
                assert result == 1
        finally:
            for p in patches:
                p.stop()

    def test_history_mode_no_db(self, tmp_path: Path):
        """Test history mode with missing database."""
        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.select_mode", return_value="history"
            ):
                with patch(
                    "scripts.cli.wizard_flows.diff_flow._get_db_path",
                    return_value=tmp_path / "missing.db",
                ):
                    result = run_diff_wizard_impl(yes=False)
                    assert result == 1
        finally:
            for p in patches:
                p.stop()

    def test_history_mode_not_enough_scans(self, tmp_path: Path):
        """Test history mode with less than 2 scans."""
        db_path = tmp_path / "history.db"
        db_path.touch()

        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.select_mode", return_value="history"
            ):
                with patch(
                    "scripts.cli.wizard_flows.diff_flow._get_db_path",
                    return_value=db_path,
                ):
                    with patch(
                        "scripts.core.history_db.list_recent_scans",
                        return_value=[{"id": "1"}],
                    ):
                        result = run_diff_wizard_impl(yes=False)
                        assert result == 1
        finally:
            for p in patches:
                p.stop()

    def test_directory_mode_missing_baseline(self, tmp_path: Path):
        """Test directory mode with nonexistent baseline."""
        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.select_mode",
                return_value="directory",
            ):
                with patch("builtins.input", return_value=str(tmp_path / "missing")):
                    result = run_diff_wizard_impl(yes=False)
                    assert result == 1
        finally:
            for p in patches:
                p.stop()

    def test_directory_mode_missing_current(self, tmp_path: Path):
        """Test directory mode with valid baseline but nonexistent current."""
        baseline = tmp_path / "baseline"
        baseline.mkdir()

        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.select_mode",
                return_value="directory",
            ):
                # First input: valid baseline, second: nonexistent current
                with patch(
                    "builtins.input",
                    side_effect=[str(baseline), str(tmp_path / "missing")],
                ):
                    result = run_diff_wizard_impl(yes=False)
                    assert result == 1
        finally:
            for p in patches:
                p.stop()

    def test_directory_mode_full_flow(self, tmp_path: Path):
        """Test directory mode through full interactive flow."""
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()

        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.select_mode",
                return_value="directory",
            ):
                with patch(
                    "scripts.cli.wizard_flows.diff_flow.prompt_choice",
                    side_effect=["1", "1"],
                ):
                    # Inputs: baseline dir, current dir, output file (empty = default)
                    with patch(
                        "builtins.input", side_effect=[str(baseline), str(current), ""]
                    ):
                        with patch(
                            "scripts.cli.wizard_flows.diff_flow._get_db_path",
                            return_value=tmp_path / "h.db",
                        ):
                            with patch(
                                "scripts.cli.diff_commands.cmd_diff", return_value=0
                            ) as mock_diff:
                                result = run_diff_wizard_impl(yes=False)
                                assert result == 0
                                mock_diff.assert_called_once()
                                args = mock_diff.call_args[0][0]
                                assert args.directories == [str(baseline), str(current)]
        finally:
            for p in patches:
                p.stop()

    def test_directory_mode_user_cancels(self, tmp_path: Path):
        """Test directory mode where user cancels at confirmation."""
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()

        # Override _prompt_yes_no to return False for cancellation
        ui_patches = [
            patch(
                "scripts.cli.wizard_flows.diff_flow._colorize",
                side_effect=_stub_colorize,
            ),
            patch("scripts.cli.wizard_flows.diff_flow._print_step"),
            patch(
                "scripts.cli.wizard_flows.diff_flow._prompt_yes_no", return_value=False
            ),
        ]
        for p in ui_patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.select_mode",
                return_value="directory",
            ):
                with patch(
                    "scripts.cli.wizard_flows.diff_flow.prompt_choice",
                    side_effect=["1", "1"],
                ):
                    with patch(
                        "builtins.input", side_effect=[str(baseline), str(current), ""]
                    ):
                        result = run_diff_wizard_impl(yes=False)
                        assert result == 0  # Cancelled returns 0
        finally:
            for p in ui_patches:
                p.stop()

    def test_history_mode_full_flow(self, tmp_path: Path):
        """Test history mode through full interactive flow with scan selection."""
        db_path = tmp_path / "history.db"
        db_path.touch()

        scans = [
            {
                "id": "scan-aaa111",
                "timestamp_iso": "2026-02-10T10:00:00",
                "profile": "balanced",
                "branch": "main",
                "total_findings": 5,
            },
            {
                "id": "scan-bbb222",
                "timestamp_iso": "2026-02-11T11:00:00",
                "profile": "balanced",
                "branch": "dev",
                "total_findings": 3,
            },
            {
                "id": "scan-ccc333",
                "timestamp_iso": "2026-02-12T12:00:00",
                "profile": "deep",
                "branch": "dev",
                "total_findings": 8,
            },
        ]

        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.select_mode", return_value="history"
            ):
                with patch(
                    "scripts.cli.wizard_flows.diff_flow._get_db_path",
                    return_value=db_path,
                ):
                    with patch(
                        "scripts.core.history_db.list_recent_scans", return_value=scans
                    ):
                        with patch(
                            "scripts.cli.wizard_flows.diff_flow.prompt_choice",
                            side_effect=["1", "1"],
                        ):
                            # Inputs: baseline scan "1", current scan "2", output file ""
                            with patch("builtins.input", side_effect=["1", "2", ""]):
                                with patch(
                                    "scripts.cli.diff_commands.cmd_diff", return_value=0
                                ) as mock_diff:
                                    result = run_diff_wizard_impl(yes=False)
                                    assert result == 0
                                    mock_diff.assert_called_once()
                                    args = mock_diff.call_args[0][0]
                                    assert args.scan_ids == [
                                        "scan-aaa111",
                                        "scan-bbb222",
                                    ]
        finally:
            for p in patches:
                p.stop()

    def test_history_mode_scan_selection_error(self, tmp_path: Path):
        """Test history mode handles exception during scan listing."""
        db_path = tmp_path / "history.db"
        db_path.touch()

        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.select_mode", return_value="history"
            ):
                with patch(
                    "scripts.cli.wizard_flows.diff_flow._get_db_path",
                    return_value=db_path,
                ):
                    with patch(
                        "scripts.core.history_db.list_recent_scans",
                        side_effect=RuntimeError("db error"),
                    ):
                        result = run_diff_wizard_impl(yes=False)
                        assert result == 1
        finally:
            for p in patches:
                p.stop()

    def test_directory_mode_diff_failure_and_html_open(self, tmp_path: Path):
        """Test directory mode with diff success and HTML auto-open."""
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()
        # Create a fake output file for the HTML open path
        (tmp_path / "diff-report.html").write_text("<html></html>")

        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.select_mode",
                return_value="directory",
            ):
                # Select severity=All, category=All, format=html
                with patch(
                    "scripts.cli.wizard_flows.diff_flow.prompt_choice",
                    side_effect=["1", "1"],
                ):
                    with patch(
                        "builtins.input",
                        side_effect=[
                            str(baseline),
                            str(current),
                            str(tmp_path / "diff-report.html"),
                        ],
                    ):
                        with patch(
                            "scripts.cli.wizard_flows.diff_flow._get_db_path",
                            return_value=tmp_path / "h.db",
                        ):
                            with patch(
                                "scripts.cli.diff_commands.cmd_diff", return_value=1
                            ):
                                result = run_diff_wizard_impl(yes=False)
                                assert result == 1  # cmd_diff failed
        finally:
            for p in patches:
                p.stop()

    def test_baseline_current_args_skip_mode_selection(self, tmp_path: Path):
        """Test providing baseline/current without --yes uses directory mode."""
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()

        patches = _patch_diff_flow_ui()
        for p in patches:
            p.start()
        try:
            with patch(
                "scripts.cli.wizard_flows.diff_flow.prompt_choice",
                side_effect=["1", "1"],
            ):
                with patch("builtins.input", return_value=""):
                    with patch(
                        "scripts.cli.wizard_flows.diff_flow._get_db_path",
                        return_value=tmp_path / "h.db",
                    ):
                        with patch(
                            "scripts.cli.diff_commands.cmd_diff", return_value=0
                        ) as mock_diff:
                            result = run_diff_wizard_impl(
                                yes=False,
                                baseline=str(baseline),
                                current=str(current),
                            )
                            assert result == 0
                            args = mock_diff.call_args[0][0]
                            assert args.directories == [str(baseline), str(current)]
        finally:
            for p in patches:
                p.stop()
