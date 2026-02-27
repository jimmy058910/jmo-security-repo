"""Tests for jmo validate CLI dispatcher and scorecard renderer."""

import argparse
import json
from unittest.mock import patch

import pytest

from scripts.cli.validate_commands import cmd_validate, render_scorecard
from scripts.core.validators import CategoryResult, CheckResult, CheckStatus


class TestRenderScorecard:
    def test_all_pass(self, capsys):
        results = [
            CategoryResult(
                name="CLI Completeness",
                checks=[
                    CheckResult(name="help works", status=CheckStatus.PASS),
                    CheckResult(name="version", status=CheckStatus.PASS),
                ],
            ),
        ]
        exit_code = render_scorecard(results, verbose=False)
        captured = capsys.readouterr()
        assert "CLI Completeness" in captured.out
        assert "2/2 PASS" in captured.out
        assert "GO" in captured.out
        assert exit_code == 0

    def test_with_failures(self, capsys):
        results = [
            CategoryResult(
                name="Release Artifacts",
                checks=[
                    CheckResult(name="version", status=CheckStatus.PASS),
                    CheckResult(
                        name="changelog",
                        status=CheckStatus.FAIL,
                        message="Missing entry",
                    ),
                ],
            ),
        ]
        exit_code = render_scorecard(results, verbose=False)
        captured = capsys.readouterr()
        assert "1 FAIL" in captured.out
        assert "NO-GO" in captured.out
        assert exit_code == 1

    def test_warnings_non_blocking(self, capsys):
        results = [
            CategoryResult(
                name="Cross-Platform",
                checks=[
                    CheckResult(name="paths", status=CheckStatus.PASS),
                    CheckResult(
                        name="docker",
                        status=CheckStatus.WARN,
                        message="Docker not running",
                    ),
                ],
            ),
        ]
        exit_code = render_scorecard(results, verbose=False)
        captured = capsys.readouterr()
        assert "GO" in captured.out
        assert exit_code == 0

    def test_verbose_shows_check_names(self, capsys):
        results = [
            CategoryResult(
                name="CLI Completeness",
                checks=[
                    CheckResult(
                        name="help works",
                        status=CheckStatus.PASS,
                        message="13 subcommands verified",
                    ),
                ],
            ),
        ]
        render_scorecard(results, verbose=True)
        captured = capsys.readouterr()
        assert "help works" in captured.out

    def test_verbose_shows_failure_messages(self, capsys):
        results = [
            CategoryResult(
                name="Release",
                checks=[
                    CheckResult(
                        name="changelog",
                        status=CheckStatus.FAIL,
                        message="Missing v1.0.0 entry",
                    ),
                ],
            ),
        ]
        render_scorecard(results, verbose=True)
        captured = capsys.readouterr()
        assert "Missing v1.0.0 entry" in captured.out

    def test_json_output_structure(self, capsys):
        results = [
            CategoryResult(
                name="CLI",
                checks=[CheckResult(name="test", status=CheckStatus.PASS)],
            ),
        ]
        exit_code = render_scorecard(results, verbose=False, json_output=True)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["verdict"] == "GO"
        assert data["categories"][0]["name"] == "CLI"
        assert data["summary"]["total"] == 1
        assert data["summary"]["passed"] == 1
        assert exit_code == 0

    def test_json_output_with_failures(self, capsys):
        results = [
            CategoryResult(
                name="CLI",
                checks=[CheckResult(name="test", status=CheckStatus.FAIL)],
            ),
        ]
        exit_code = render_scorecard(results, verbose=False, json_output=True)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["verdict"] == "NO-GO"
        assert exit_code == 1

    def test_empty_results(self, capsys):
        exit_code = render_scorecard([], verbose=False)
        captured = capsys.readouterr()
        assert "0/0" in captured.out
        assert exit_code == 0

    def test_errors_count_as_failure(self, capsys):
        results = [
            CategoryResult(
                name="Test",
                checks=[
                    CheckResult(
                        name="broken", status=CheckStatus.ERROR, message="crash"
                    ),
                ],
            ),
        ]
        exit_code = render_scorecard(results, verbose=False)
        assert exit_code == 1

    def test_multiple_categories(self, capsys):
        results = [
            CategoryResult(
                name="CLI Completeness",
                checks=[CheckResult(name="a", status=CheckStatus.PASS)],
            ),
            CategoryResult(
                name="Scan Correctness",
                checks=[CheckResult(name="b", status=CheckStatus.PASS)],
            ),
        ]
        exit_code = render_scorecard(results, verbose=False)
        captured = capsys.readouterr()
        assert "CLI Completeness" in captured.out
        assert "Scan Correctness" in captured.out
        assert "2/2 PASS" in captured.out
        assert exit_code == 0


class TestCmdValidate:
    def test_quick_tier_default(self):
        args = argparse.Namespace(
            tier="quick",
            category=None,
            verbose=False,
            fail_fast=False,
            json=False,
        )
        with patch("scripts.cli.validate_commands._get_validators") as mock_get:
            mock_get.return_value = []
            result = cmd_validate(args)
            assert result == 0

    def test_full_tier(self):
        args = argparse.Namespace(
            tier="full",
            category=None,
            verbose=False,
            fail_fast=False,
            json=False,
        )
        with patch("scripts.cli.validate_commands._get_validators") as mock_get:
            mock_get.return_value = []
            result = cmd_validate(args)
            assert result == 0

    def test_category_filter_parsed(self):
        args = argparse.Namespace(
            tier="quick",
            category="cli,scans",
            verbose=False,
            fail_fast=False,
            json=False,
        )
        with patch("scripts.cli.validate_commands._get_validators") as mock_get:
            mock_get.return_value = []
            with patch("scripts.cli.validate_commands.run_validators") as mock_run:
                mock_run.return_value = []
                cmd_validate(args)
                _, kwargs = mock_run.call_args
                assert kwargs["categories"] == ["cli", "scans"]

    def test_fail_fast_passed_through(self):
        args = argparse.Namespace(
            tier="quick",
            category=None,
            verbose=False,
            fail_fast=True,
            json=False,
        )
        with patch("scripts.cli.validate_commands._get_validators") as mock_get:
            mock_get.return_value = []
            with patch("scripts.cli.validate_commands.run_validators") as mock_run:
                mock_run.return_value = []
                cmd_validate(args)
                _, kwargs = mock_run.call_args
                assert kwargs["fail_fast"] is True


class TestJmoValidateArgs:
    """Test that jmo validate is wired into the CLI."""

    def test_validate_in_parse_args(self):
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate", "--help"]):
            # parse_args() suppresses SystemExit(0) during pytest
            result = parse_args()
            assert isinstance(result, argparse.Namespace)

    def test_validate_default_tier(self):
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate"]):
            args = parse_args()
            assert args.cmd == "validate"
            assert args.tier == "quick"

    def test_validate_full_tier(self):
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate", "--tier", "full"]):
            args = parse_args()
            assert args.tier == "full"

    def test_validate_category_flag(self):
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate", "--category", "cli,scans"]):
            args = parse_args()
            assert args.category == "cli,scans"

    def test_validate_verbose_flag(self):
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate", "-v"]):
            args = parse_args()
            assert args.verbose is True

    def test_validate_fail_fast_flag(self):
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate", "--fail-fast"]):
            args = parse_args()
            assert args.fail_fast is True

    def test_validate_json_flag(self):
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate", "--json"]):
            args = parse_args()
            assert getattr(args, "json") is True

    def test_validate_invalid_tier_rejected(self):
        from scripts.cli.jmo import parse_args

        with patch("sys.argv", ["jmo", "validate", "--tier", "invalid"]):
            with pytest.raises(SystemExit) as exc_info:
                parse_args()
            assert exc_info.value.code == 2
