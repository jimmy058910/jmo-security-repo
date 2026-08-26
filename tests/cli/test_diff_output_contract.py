"""What `jmo diff` promises about its own output.

These guard contracts a unit test on a reporter cannot see, because they are
properties of the command: which stream a thing lands on, which database is
read when no flag says, and whether a filter that selects nothing says so.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import scripts.cli.diff_commands as diff_commands
from scripts.cli.diff_commands import (
    VALID_SEVERITIES,
    _recalculate_statistics,
    _write_document_to_stdout,
    cmd_diff,
)
from scripts.cli.jmo import parse_args
from scripts.core.history_db import DEFAULT_DB_PATH


@pytest.fixture
def results_pair(tmp_path):
    """Two results directories with a known delta: 1 resolved, 1 unchanged."""

    def finding(fid, severity, tool="bandit"):
        return {
            "id": fid,
            "severity": severity,
            "ruleId": "B602",
            "message": "subprocess call with shell=True",
            "tool": {"name": tool},
            "location": {"path": "app.py", "startLine": 40},
        }

    def write(name, findings):
        d = tmp_path / name
        (d / "summaries").mkdir(parents=True)
        (d / "summaries" / "findings.json").write_text(
            json.dumps({"meta": {"profile": "fast"}, "findings": findings}),
            encoding="utf-8",
        )
        return d

    baseline = write("base", [finding("keep", "HIGH"), finding("gone", "LOW")])
    current = write("cur", [finding("keep", "HIGH")])
    return baseline, current


def diff_args(baseline, current, **overrides):
    """Build args through the REAL parser, so parser defaults are exercised."""
    argv = ["jmo", "diff", str(baseline), str(current)]
    for key, value in overrides.items():
        flag = "--" + key.replace("_", "-")
        if value is True:
            argv.append(flag)
        elif value is not None:
            argv.extend([flag, str(value)])
    saved, sys.argv = sys.argv, argv
    try:
        return parse_args()
    finally:
        sys.argv = saved


class TestSqliteModeDefault:
    def test_default_database_is_the_one_the_product_writes(
        self, tmp_path, monkeypatch, capsys
    ):
        """`--db` unset must mean `.jmo/history.db`, not `~/.jmo/scans.db`.

        Nothing in JMo has ever written a file called `scans.db`, so SQLite
        mode could not run without `--db` -- including the
        `jmo diff --scan abc123 --scan def456` printed in the command's own
        help text.

        Asserting the import alone is not enough: a mutation moving the *use
        site* back to `Path.home() / ".jmo" / "scans.db"` survived that. Run
        the command and read which path it names.
        """
        assert DEFAULT_DB_PATH.name == "history.db"

        missing = tmp_path / "history.db"
        monkeypatch.setattr(diff_commands, "DEFAULT_DB_PATH", missing)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        saved, sys.argv = sys.argv, ["jmo", "diff", "--scan", "a", "--scan", "b"]
        try:
            args = parse_args()
        finally:
            sys.argv = saved

        assert cmd_diff(args) == 1
        err = capsys.readouterr().err
        assert str(missing) in err
        assert "scans.db" not in err


class TestStdoutIsMachineReadable:
    def test_rich_summary_never_writes_to_stdout(self, results_pair, capsys):
        """`--format json` on stdout must be exactly one JSON document.

        The Rich summary is gated on `sys.stderr.isatty()` but `Console()`
        writes to stdout, so the panel could be appended to the JSON. Forcing
        the guard on is the only way to test it: on Windows a plain `2>NUL`
        does exactly that, because the CRT reports a character device as a tty.
        """
        baseline, current = results_pair
        args = diff_args(baseline, current, format="json")

        real_isatty = sys.stderr.isatty
        try:
            sys.stderr.isatty = lambda: True  # type: ignore[method-assign]
            assert cmd_diff(args) == 0
        finally:
            sys.stderr.isatty = real_isatty  # type: ignore[method-assign]

        out = capsys.readouterr().out
        parsed = json.loads(out)  # raises if anything followed the document
        assert parsed["statistics"]["total_resolved"] == 1

    def test_json_version_matches_the_file_written_by_output(
        self, results_pair, tmp_path, capsys
    ):
        """Same command, same data -- the two paths must agree.

        The stdout path hardcoded "1.0.0" while `--output` resolved the real
        version.
        """
        baseline, current = results_pair
        assert cmd_diff(diff_args(baseline, current, format="json")) == 0
        from_stdout = json.loads(capsys.readouterr().out)

        out_file = tmp_path / "d.json"
        assert (
            cmd_diff(diff_args(baseline, current, format="json", output=out_file)) == 0
        )
        from_file = json.loads(out_file.read_text(encoding="utf-8"))

        assert from_stdout["meta"]["jmo_version"] == from_file["meta"]["jmo_version"]
        assert from_stdout["meta"]["jmo_version"] != "1.0.0" or (
            from_file["meta"]["jmo_version"] == "1.0.0"
        )


class TestMarkdownToStdoutKeepsItsCharacters:
    """#784 -- the captured document must not carry console substitutions."""

    def test_non_terminal_stdout_gets_utf8_bytes(self, monkeypatch):
        written: list[bytes] = []

        class FakeBuffer:
            def write(self, data):
                written.append(data)

            def flush(self):
                pass

        class FakeStdout:
            encoding = "cp1252"
            buffer = FakeBuffer()

            def isatty(self):
                return False

            def flush(self):
                pass

        monkeypatch.setattr(sys, "stdout", FakeStdout())
        _write_document_to_stdout("# \U0001f50d Security Diff Report\n")

        assert (
            b"".join(written).decode("utf-8") == "# \U0001f50d Security Diff Report\n"
        )

    def test_a_real_terminal_still_gets_the_ascii_fallback(self, monkeypatch, capsys):
        """Negative control: a cp437 console genuinely cannot render this.

        Writing raw UTF-8 there would be mojibake, which is worse than a
        legible substitution -- so the terminal path must keep using it.
        """
        calls: list[str] = []
        monkeypatch.setattr(
            diff_commands, "safe_print", lambda text: calls.append(text)
        )

        class FakeStdout:
            encoding = "cp437"
            buffer = None

            def isatty(self):
                return True

            def flush(self):
                pass

        monkeypatch.setattr(sys, "stdout", FakeStdout())
        _write_document_to_stdout("# \U0001f50d Security Diff Report\n")
        assert calls == ["# \U0001f50d Security Diff Report\n"]


class TestBrowserHint:
    def test_html_path_is_offered_as_a_valid_file_uri(
        self, results_pair, tmp_path, capsys
    ):
        """`file://C:\\Users\\...` is not a URI a browser can open.

        `C:` parses as the authority and backslashes are not separators. The
        correct form has three slashes and forward separators.
        """
        baseline, current = results_pair
        out = tmp_path / "d.html"
        assert cmd_diff(diff_args(baseline, current, format="html", output=out)) == 0
        printed = capsys.readouterr().out
        hint = next(line for line in printed.splitlines() if "Open in browser" in line)
        assert out.absolute().as_uri() in hint
        assert "file:///" in hint
        assert "\\" not in hint.split("file://", 1)[1]


class TestFilterValidation:
    def test_unrecognised_severity_is_reported(self, results_pair, tmp_path, capsys):
        """An empty result and a clean scan must not look identical.

        `--severity NOPE` selected nothing, exited 0 and said nothing -- the
        same shape as `--fail-on HIGHH` in chunk 11.
        """
        baseline, current = results_pair
        out = tmp_path / "d.json"
        assert (
            cmd_diff(
                diff_args(baseline, current, format="json", output=out, severity="NOPE")
            )
            == 0
        )
        assert "unrecognised severity" in capsys.readouterr().err.lower()

    def test_severity_matching_is_case_and_space_insensitive(
        self, results_pair, tmp_path
    ):
        """`--severity "HIGH, LOW"` silently dropped LOW over one space."""
        baseline, current = results_pair
        out = tmp_path / "d.json"
        assert (
            cmd_diff(
                diff_args(
                    baseline, current, format="json", output=out, severity="high, low"
                )
            )
            == 0
        )
        stats = json.loads(out.read_text(encoding="utf-8"))["statistics"]
        assert stats["total_resolved"] == 1
        assert stats["total_unchanged"] == 1

    def test_a_valid_severity_is_not_reported(self, results_pair, tmp_path, capsys):
        """Negative control -- the warning must not fire on every run."""
        baseline, current = results_pair
        out = tmp_path / "d.json"
        cmd_diff(
            diff_args(baseline, current, format="json", output=out, severity="HIGH")
        )
        assert "unrecognised" not in capsys.readouterr().err.lower()

    def test_unknown_tool_is_reported(self, results_pair, tmp_path, capsys):
        baseline, current = results_pair
        out = tmp_path / "d.json"
        cmd_diff(
            diff_args(baseline, current, format="json", output=out, tool="nosuchtool")
        )
        err = capsys.readouterr().err
        assert "no findings from nosuchtool" in err
        assert "bandit" in err, "the message should name what IS present"

    def test_a_present_tool_is_not_reported(self, results_pair, tmp_path, capsys):
        """Negative control for the tool warning."""
        baseline, current = results_pair
        out = tmp_path / "d.json"
        cmd_diff(diff_args(baseline, current, format="json", output=out, tool="bandit"))
        assert "no findings from" not in capsys.readouterr().err


class TestStatisticsShapeIsStable:
    def test_filtered_statistics_keep_every_severity_level(self):
        """The unfiltered path zero-fills all five levels; filters did not.

        Three near-identical copies of the recalculation each omitted it, so
        the same artifact had two shapes depending on whether a filter ran.
        """
        stats = _recalculate_statistics(
            new=[{"severity": "HIGH"}], resolved=[], unchanged=[], modified=[]
        )
        assert set(stats["new_by_severity"]) == set(VALID_SEVERITIES)
        assert set(stats["resolved_by_severity"]) == set(VALID_SEVERITIES)
        assert stats["new_by_severity"]["HIGH"] == 1
        assert stats["new_by_severity"]["CRITICAL"] == 0

    def test_trend_uses_the_vocabulary_the_engine_emits(self):
        """ "worsening", not "degrading" -- the Rich colour map had the latter."""
        assert (
            _recalculate_statistics([{"severity": "HIGH"}], [], [], [])["trend"]
            == "worsening"
        )
        assert (
            _recalculate_statistics([], [{"severity": "HIGH"}], [], [])["trend"]
            == "improving"
        )
        assert _recalculate_statistics([], [], [], [])["trend"] == "stable"


class TestAutoModeFormatSuggestion:
    def test_format_has_no_parser_default_so_auto_can_suggest(self):
        """`--auto` advertises a format suggestion that could never run.

        `--format` defaulted to "md", so `args.format` was always truthy and
        `suggest_output_format()` was unreachable from the CLI.
        """
        saved, sys.argv = sys.argv, ["jmo", "diff", "--auto"]
        try:
            args = parse_args()
        finally:
            sys.argv = saved
        assert args.format is None

    def test_explicit_format_is_preserved(self):
        saved, sys.argv = sys.argv, ["jmo", "diff", "--auto", "--format", "sarif"]
        try:
            args = parse_args()
        finally:
            sys.argv = saved
        assert args.format == "sarif"

    def test_unset_format_still_resolves_to_markdown(self, results_pair, capsys):
        """Removing the parser default must not change the documented default."""
        baseline, current = results_pair
        assert cmd_diff(diff_args(baseline, current)) == 0
        assert "Security Diff Report" in capsys.readouterr().out
