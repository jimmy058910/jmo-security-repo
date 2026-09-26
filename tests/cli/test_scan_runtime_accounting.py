#!/usr/bin/env python3
"""Guards for the scan phase's partial-failure accounting (chunk 4, #809/#811).

The failure this file exists to prevent: **the scan layer knew a target had
produced nothing and said it succeeded anyway.** A GitLab target with no token
printed ``[1/1] OK`` and exited 0, and its ``zero-secrets`` policy passed on a
scan where no secret scanner ran.

Since v2.0.0 Phase 3 a target's account is its rows, one per requested tool:
``ran``, ``skipped:<reason>`` or ``failed:<reason>``.

Each test below asserts more than one condition, because on chunk 3 two tests
asserting only ``rc != 0`` passed on CI for the wrong reason: the shards install
no scanners, so ``cmd_scan`` bailed at the tool pre-flight before reaching the
code under test, and that bail also returns non-zero.
"""

from __future__ import annotations

import itertools
import json
import logging
import sqlite3
import time
import types
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.cli.scan_orchestrator import (
    TARGET_FAILED,
    TARGET_NOT_ATTEMPTED,
    TARGET_OK,
    TARGET_PARTIAL,
    _run_timed,
    classify_target_outcome,
    summarize_target,
)
from scripts.core.scan_timings import Reason, State, ToolRun


def row(tool: str, label: str) -> ToolRun:
    """`ran`, or `<state>:<reason value>`."""
    if label == "ran":
        return ToolRun(tool, State.RAN)
    state, _, reason = label.partition(":")
    return ToolRun(tool, State(state), Reason(reason))


def rows(**labels: str) -> dict[str, ToolRun]:
    return {tool: row(tool, label) for tool, label in labels.items()}


class TestClassifyTargetOutcome:
    """The one place that decides whether a target produced anything."""

    @pytest.mark.parametrize(
        ("labels", "expected"),
        [
            ({"trivy": "ran", "trufflehog": "ran"}, TARGET_OK),
            ({"trivy": "ran", "trufflehog": "failed:timed out"}, TARGET_PARTIAL),
            (
                {"trivy": "failed:no output", "trufflehog": "failed:timed out"},
                TARGET_FAILED,
            ),
            ({"trivy": "ran"}, TARGET_OK),
            ({"trivy": "failed:unaccepted exit code"}, TARGET_FAILED),
        ],
    )
    def test_outcome_follows_the_rows(self, labels, expected):
        assert classify_target_outcome(rows(**labels)) == expected

    def test_no_rows_is_failure_not_vacuous_success(self):
        """``all([])`` is True. That reading is the bug, not the fix."""
        assert classify_target_outcome({}) == TARGET_FAILED
        assert classify_target_outcome(None) == TARGET_FAILED

    def test_only_off_target_rows_is_failure(self):
        """No requested tool reads this kind of target: it contributed nothing
        (`--tools nuclei` against a repository)."""
        assert (
            classify_target_outcome(rows(nuclei="skipped:needs --url")) == TARGET_FAILED
        )
        assert (
            classify_target_outcome(rows(semgrep="skipped:not for this target type"))
            == TARGET_FAILED
        )


class TestSkippedToolIsNotASuccess:
    """#825: `--allow-missing-tools` recorded a tool that never ran as a
    success, so an empty stub from a secret scanner that never ran satisfied a
    zero-secrets policy. A skipped tool gets no vote, in either direction:
    counting it as a failure would make a target where one tool ran cleanly and
    two were not installed a partial failure."""

    @pytest.mark.parametrize(
        ("labels", "expected", "why"),
        [
            pytest.param(
                {"trivy": "skipped:not installed"},
                TARGET_NOT_ATTEMPTED,
                "the only tool was stubbed",
                id="all-stubbed",
            ),
            pytest.param(
                {"trivy": "ran", "semgrep": "skipped:not installed"},
                TARGET_OK,
                "what ran, worked",
                id="one-ran-one-stubbed",
            ),
            pytest.param(
                {"trivy": "failed:timed out", "semgrep": "skipped:not installed"},
                TARGET_FAILED,
                "the tool that ran failed; the stub does not soften that",
                id="one-failed-one-stubbed",
            ),
            pytest.param(
                {"hadolint": "skipped:no Dockerfiles", "zap": "skipped:needs --url"},
                TARGET_NOT_ATTEMPTED,
                "every tool that reads it had nothing: not a failure",
                id="content-skips-only",
            ),
        ],
    )
    def test_a_skip_does_not_vote(self, labels, expected, why):
        assert classify_target_outcome(rows(**labels)) == expected, why

    def test_a_row_cannot_be_ran_with_a_reason(self):
        """The drift this file once guarded with an AST scan of 38 stub sites
        (`write_stub` followed by `statuses[tool] = True`) cannot be written
        now: a row that ran has no reason, and one that did not has one."""
        with pytest.raises(ValueError):
            ToolRun("trivy", State.RAN, Reason.NOT_INSTALLED)
        with pytest.raises(ValueError):
            ToolRun("trivy", State.SKIPPED)
        with pytest.raises(ValueError):
            ToolRun("trivy", State.SKIPPED, Reason.TIMED_OUT)
        with pytest.raises(ValueError):
            ToolRun("trivy", State.FAILED)
        with pytest.raises(ValueError):
            ToolRun("trivy", State.FAILED, Reason.NO_IAC)

    def _stubbed_scan(self, scan_env, monkeypatch):
        """A scan where no tool resolves, so every one is stubbed."""
        scan_env.allow_missing_tools = True
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.tool_loop.find_tool", lambda *a, **k: None
        )
        return jmo.cmd_scan(scan_env)

    def test_a_fully_stubbed_target_still_exits_zero(
        self, scan_env, monkeypatch, capsys
    ):
        """`--allow-missing-tools` is what makes this reachable; making it
        non-zero would invert what the flag is for."""
        assert self._stubbed_scan(scan_env, monkeypatch) == 0

    @staticmethod
    def _lines(err: str, needle: str) -> list[str]:
        return [ln for ln in err.splitlines() if needle in ln]

    def test_the_per_target_line_says_no_tool_ran(self, scan_env, monkeypatch, capsys):
        """The progress line for this target, specifically: both it and the
        end-of-scan summary name the tool, so a test reading the whole stream
        passes with either one deleted."""
        self._stubbed_scan(scan_env, monkeypatch)
        err = capsys.readouterr().err

        progress = self._lines(err, "[1/1]")
        assert len(progress) == 1, f"expected one progress line: {progress}"
        line = progress[0]
        assert '"level": "WARN"' in line, "the progress line was logged at INFO"
        assert "NO tool ran against this target" in line
        assert "trufflehog (not installed)" in line, line
        # `_log` emits JSON; json.dumps renders U+25CB as `○`.
        assert "\\u25cb" in line, "the progress line still shows a pass/fail glyph"
        assert "\\u2713" not in line, "a fully stubbed target rendered as a success"

    def test_the_end_of_scan_summary_names_the_stubbed_tools(
        self, scan_env, monkeypatch, capsys
    ):
        self._stubbed_scan(scan_env, monkeypatch)
        err = capsys.readouterr().err

        summary = self._lines(err, "were STUBBED, not executed")
        assert len(summary) == 1, f"expected one end-of-scan summary: {summary}"
        assert '"level": "WARN"' in summary[0]
        assert "proj: trufflehog" in summary[0], (
            "the summary does not attribute per target"
        )
        assert "not the same as finding nothing" in summary[0]

    def test_the_scan_metadata_carries_every_row(self, scan_env, monkeypatch, capsys):
        """The report phase cannot tell a stub from a clean run on its own; the
        scan->report handoff carries the row, which history then stores."""
        self._stubbed_scan(scan_env, monkeypatch)
        capsys.readouterr()

        meta = json.loads(
            (Path(scan_env.results_dir) / ".scan_metadata.json").read_bytes()
        )
        assert [
            (r["target"], r["target_type"], r["tool"], r["state"], r["reason"])
            for r in meta["tool_runs"]
        ] == [("proj", "repo", "trufflehog", "skipped", "not installed")]
        assert "stubbed_tools" not in meta, "the rows replace it"

    def test_a_real_scan_reports_no_stubs(self, scan_env, capsys):
        """Negative control: reporting every target as stubbed would satisfy
        every test above."""
        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("proj", rows(trufflehog="ran"))
            assert jmo.cmd_scan(scan_env) == 0

        err = capsys.readouterr().err
        assert "STUBBED" not in err
        assert "\\u2713" in err, "a clean target should still carry the tick"


class TestRunTimed:
    """The per-target duration must be measured, not asserted."""

    def test_returns_result_and_a_real_duration(self):
        def job(a, b, *, c):
            return f"{a}{b}{c}", rows(trivy="ran")

        name, result, elapsed = _run_timed(job, "x", "y", c="z")
        assert name == "xyz"
        assert result == rows(trivy="ran")
        assert isinstance(elapsed, float)
        assert elapsed >= 0.0

    def test_exceptions_propagate_to_the_future(self):
        def job():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            _run_timed(job)


def _scan_args(
    tmp_path: Path, cfg_path: Path, repos_dir: Path
) -> types.SimpleNamespace:
    """The minimum namespace ``cmd_scan`` needs, mirroring test_cli_per_tool_config."""
    return types.SimpleNamespace(
        cmd="scan",
        repo=None,
        repos_dir=str(repos_dir),
        targets=None,
        results_dir=str(tmp_path / "results"),
        config=str(cfg_path),
        tools=None,
        timeout=None,
        threads=None,
        allow_missing_tools=False,
        log_level="INFO",
        human_logs=False,
        no_store_history=True,
        no_resume=True,
    )


@pytest.fixture
def scan_env(tmp_path: Path, monkeypatch):
    """A one-repo scan whose tool pre-flight is pinned.

    Pinning ``_check_scan_tools`` is the point: without it a runner with no
    scanners installed bails before the code under test and returns non-zero
    for an unrelated reason.

    ``cmd_scan`` unconditionally calls ``_show_kofi_reminder()`` (#933), which
    resolves ``Path.home()``; redirected here. ``_warn_critical_updates``
    version-checks every requested tool through ``ToolManager._find_binary`` on
    the real PATH, so that resolves nothing (#1237).

    The repository holds a file: an empty tree fails every tool before any
    runs (G2), which is not what these tests are about.
    """
    repos_dir = tmp_path / "repos"
    (repos_dir / "proj").mkdir(parents=True)
    (repos_dir / "proj" / "README.md").write_bytes(b"# proj\n")
    cfg_path = tmp_path / "jmo.yml"
    cfg_path.write_text(
        yaml.safe_dump({"tools": ["trufflehog"], "outputs": ["json"]}), encoding="utf-8"
    )
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    monkeypatch.setattr(
        "scripts.cli.tool_manager.ToolManager._find_binary", lambda *a, **k: None
    )
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    return _scan_args(tmp_path, cfg_path, repos_dir)


class TestScanStoresHistory:
    """#870: `--store-history` has to exist on the parser AND work, and #722:
    the per-tool rows reach `scan_tool_runs` with the scan."""

    @staticmethod
    def _args(scan_env, tmp_path, db, *extra):
        import sys

        from scripts.cli.jmo import parse_args

        argv = [
            "jmo",
            "scan",
            "--repos-dir",
            scan_env.repos_dir,
            "--results-dir",
            str(tmp_path / "results"),
            "--config",
            scan_env.config,
            "--history-db",
            str(db),
            "--tools",
            "trufflehog",
            *extra,
        ]
        with patch.object(sys, "argv", argv):
            return parse_args()

    @staticmethod
    def _scan(args, result=None) -> int:
        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("proj", result or rows(trufflehog="ran"))
            return jmo.cmd_scan(args)

    def test_jmo_scan_records_the_scan_in_history(self, scan_env, tmp_path):
        db = tmp_path / "history.db"
        args = self._args(scan_env, tmp_path, db)

        assert args.store_history is True, "jmo scan no longer stores by default"
        assert self._scan(args) == 0

        assert db.exists(), "jmo scan created no history database at all"
        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        try:
            (stored,) = con.execute("SELECT COUNT(*) FROM scans").fetchone()
        finally:
            con.close()
        assert stored == 1, f"expected exactly one stored scan, got {stored}"

    def test_every_row_reaches_scan_tool_runs(self, scan_env, tmp_path):
        """#722: "why is my scan slow" needs per-tool seconds in history, and a
        tool that did not run needs its row too."""
        db = tmp_path / "history.db"
        args = self._args(scan_env, tmp_path, db)
        result = {
            "trufflehog": ToolRun(
                "trufflehog",
                State.RAN,
                seconds=12.5,
                exit_code=0,
                attempts=1,
                invocations=1,
            ),
        }

        assert self._scan(args, result) == 0

        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        try:
            stored = con.execute(
                "SELECT target, target_type, tool, state, reason, seconds, exit_code, "
                "attempts FROM scan_tool_runs"
            ).fetchall()
        finally:
            con.close()
        assert stored == [("proj", "repo", "trufflehog", "ran", None, 12.5, 0, 1)]

    def test_history_names_only_the_tools_that_ran(self, scan_env, tmp_path):
        """#787: `scans.tools` and findings.json's `meta.tools` are what the scan
        did, not what was asked for. Pre-flight used to drop a missing tool
        before the list was recorded; it keeps it now (its row says `failed:not
        installed`), so the list has to come from the rows."""
        db = tmp_path / "history.db"
        args = self._args(scan_env, tmp_path, db, "--tools", "trufflehog,trivy")
        result = {
            "trufflehog": ToolRun("trufflehog", State.RAN, attempts=1, invocations=1),
            "trivy": ToolRun("trivy", State.FAILED, Reason.NOT_INSTALLED),
        }

        self._scan(args, result)

        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        try:
            (stored,) = con.execute("SELECT tools FROM scans").fetchone()
        finally:
            con.close()
        assert json.loads(stored) == ["trufflehog"]
        findings = json.loads(
            (tmp_path / "results" / "summaries" / "findings.json").read_bytes()
        )
        assert findings["meta"]["tools"] == ["trufflehog"]

    def test_a_scan_in_which_no_tool_ran_is_not_stored(
        self, scan_env, tmp_path, caplog
    ):
        """With pre-flight keeping missing tools, a host with none installed now
        scans (every row `failed:not installed`) instead of exiting before the
        report. Stored, that run is a scan with 0 findings, which `jmo trends`
        and `jmo diff` read as every earlier finding resolved."""
        db = tmp_path / "history.db"
        args = self._args(scan_env, tmp_path, db)
        result = {
            "trufflehog": ToolRun("trufflehog", State.FAILED, Reason.NOT_INSTALLED)
        }

        rc = self._scan(args, result)

        assert rc != 0
        if db.exists():
            con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
            try:
                (stored,) = con.execute("SELECT COUNT(*) FROM scans").fetchone()
            finally:
                con.close()
            assert stored == 0, "a scan in which nothing ran reached history"

    def test_each_row_keeps_its_targets_type(self, scan_env, tmp_path):
        """The key is (target_type, target, tool): a repository and an image
        in one scan are told apart by the type each row carries."""
        db = tmp_path / "history.db"
        args = self._args(
            scan_env,
            tmp_path,
            db,
            "--image",
            "alpine:3.19",
            "--tools",
            "trufflehog,trivy",
        )
        trivy = ToolRun(
            "trivy", State.RAN, seconds=3.0, exit_code=0, attempts=1, invocations=1
        )

        with (
            patch("scripts.cli.scan_jobs.scan_repository") as repo_scan,
            patch("scripts.cli.scan_jobs.scan_image") as image_scan,
        ):
            repo_scan.return_value = ("proj", rows(trufflehog="ran", trivy="ran"))
            image_scan.return_value = ("alpine:3.19", {"trivy": trivy})
            assert jmo.cmd_scan(args) == 0

        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        try:
            stored = con.execute(
                "SELECT target_type, target, tool FROM scan_tool_runs ORDER BY 1, 2, 3"
            ).fetchall()
        finally:
            con.close()
        assert stored == [
            ("image", "alpine:3.19", "trivy"),
            ("repo", "proj", "trivy"),
            ("repo", "proj", "trufflehog"),
        ]

    def test_no_store_history_turns_it_off(self, scan_env, tmp_path):
        db = tmp_path / "history.db"
        args = self._args(scan_env, tmp_path, db, "--no-store-history")

        assert args.store_history is False
        assert self._scan(args) == 0
        assert not db.exists(), "--no-store-history still wrote a database"


class TestScanRecordsItsOwnDuration:
    """#981: `scans.duration_seconds` was NULL on 2472 of 2472 rows. The scan
    phase records its own wall clock and hands it over in `.scan_metadata.json`;
    the report phase's `elapsed` times aggregation, not scanning."""

    def test_a_scan_stores_a_duration_a_user_can_read(
        self, scan_env, tmp_path, monkeypatch
    ):
        db = tmp_path / "history.db"
        scan_env.store_history = True
        scan_env.history_db = str(db)
        scan_env.tools = ["trufflehog"]

        # A clock that advances 1000s per read from a large base, so a recorded
        # value is a delta between two reads and cannot be a raw reading.
        clock_base = 500_000.0
        ticks = itertools.count(clock_base, 1000.0)
        monkeypatch.setattr(time, "perf_counter", lambda: next(ticks))

        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("proj", rows(trufflehog="ran"))
            assert jmo.cmd_scan(scan_env) == 0

        meta = json.loads((tmp_path / "results" / ".scan_metadata.json").read_bytes())
        assert meta["duration_seconds"] >= 1000.0, meta["duration_seconds"]
        assert meta["duration_seconds"] < clock_base, meta["duration_seconds"]

        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        try:
            stored = con.execute("SELECT duration_seconds FROM scans").fetchone()[0]
        finally:
            con.close()
        assert stored == meta["duration_seconds"]


class TestScanExitCodeReflectsTargetOutcome:
    """#809: a target that produced nothing must not exit 0."""

    def test_target_where_every_tool_failed_exits_non_zero(self, scan_env, capsys):
        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("proj", rows(trufflehog="failed:timed out"))
            rc = jmo.cmd_scan(scan_env)

        err = capsys.readouterr().err
        assert rc != 0, "a target that produced nothing must not exit 0"
        assert "produced no findings" in err
        assert "proj" in err
        assert "\\u2717" in err, "the progress line should carry the failure glyph"
        assert '"level": "ERROR"' in err

    def test_successful_target_still_exits_zero(self, scan_env, capsys):
        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("proj", rows(trufflehog="ran"))
            rc = jmo.cmd_scan(scan_env)

        err = capsys.readouterr().err
        assert rc == 0
        assert "produced no findings" not in err
        assert "\\u2713" in err, "a clean target should carry the success glyph"

    def test_partial_target_exits_zero_but_says_so(self, scan_env, capsys):
        """Only a target that produced *nothing* fails the run."""
        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = (
                "proj",
                rows(trufflehog="ran", trivy="failed:unaccepted exit code"),
            )
            rc = jmo.cmd_scan(scan_env)

        err = capsys.readouterr().err
        assert rc == 0
        assert "MISSING" in err
        assert "trivy" in err


class TestPreflightNoLongerDropsTools:
    """Phase 3: a missing tool reaches the scan and gets a row. It used to be
    removed before any target, so on a host it had no row anywhere."""

    def test_nothing_installed_with_the_flag_still_says_so(
        self, scan_env, capsys, monkeypatch
    ):
        """#811: with every tool missing, `--allow-missing-tools` has nothing to
        scan with, and says so rather than exiting 1 in silence."""
        monkeypatch.setattr(
            jmo, "_check_scan_tools", lambda args, tools: (tools, list(tools))
        )
        scan_env.allow_missing_tools = True

        rc = jmo.cmd_scan(scan_env)
        captured = capsys.readouterr()

        assert rc == 1
        combined = captured.out + captured.err
        assert "--allow-missing-tools" in combined
        assert "trufflehog" in combined

    def test_nothing_installed_without_the_flag_scans_and_records_each(
        self, scan_env, capsys, monkeypatch
    ):
        """B8's stripped-PATH case: today's pre-flight exited 1 before any
        target; now every row says `failed:not installed`, and the target
        produced nothing, so the run still exits 1."""
        monkeypatch.setattr(
            jmo, "_check_scan_tools", lambda args, tools: (tools, list(tools))
        )
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.tool_loop.find_tool", lambda *a, **k: None
        )

        rc = jmo.cmd_scan(scan_env)
        err = capsys.readouterr().err

        assert rc == 1
        meta = json.loads(
            (Path(scan_env.results_dir) / ".scan_metadata.json").read_bytes()
        )
        assert [(r["tool"], r["state"], r["reason"]) for r in meta["tool_runs"]] == [
            ("trufflehog", "failed", "not installed")
        ]
        assert "not installed and will not run: trufflehog" in err

    def test_a_cancel_at_the_prompt_still_stops(self, scan_env, monkeypatch):
        monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: ([], []))

        assert jmo.cmd_scan(scan_env) == 1
        assert not (Path(scan_env.results_dir) / ".scan_metadata.json").exists()


class TestReportDoesNotWarnAboutItsOwnArtifact:
    """#784(3): a warning that fires every run trains the reader to ignore it."""

    def test_scan_timings_is_not_treated_as_a_tool_output(self, tmp_path, caplog):
        from scripts.core.normalize_and_report import gather_results
        from scripts.core.scan_timings import SCAN_TIMINGS_FILENAME

        target = tmp_path / "individual-repos" / "proj"
        target.mkdir(parents=True)
        (target / SCAN_TIMINGS_FILENAME).write_text(
            json.dumps({"schema_version": 3, "tools": []}), encoding="utf-8"
        )

        with caplog.at_level(
            logging.WARNING, logger="scripts.core.normalize_and_report"
        ):
            gather_results(tmp_path)

        assert not [
            r for r in caplog.records if "No adapter plugin found" in r.getMessage()
        ], "the report phase warned about JMo's own instrumentation file"

    def test_a_genuinely_unknown_tool_output_still_warns(self, tmp_path, caplog):
        """The control: suppression must be scoped to the one filename."""
        target = tmp_path / "individual-repos" / "proj"
        target.mkdir(parents=True)
        (target / "not-a-real-tool.json").write_text("{}", encoding="utf-8")

        from scripts.core.normalize_and_report import gather_results

        with caplog.at_level(
            logging.WARNING, logger="scripts.core.normalize_and_report"
        ):
            gather_results(tmp_path)

        assert [
            r for r in caplog.records if "No adapter plugin found" in r.getMessage()
        ], "a real missing adapter must still be reported"


class TestResumeSkipIsVisibleAtDefaultVerbosity:
    """A resumed scan covers fewer targets. The reader has to be told."""

    def test_skip_notice_survives_the_default_log_level(self, tmp_path, caplog):
        """`configure_scan_logging` floors the `scripts` logger at WARNING, so an
        INFO notice here was configured away by the scan itself."""
        from scripts.cli.scan_orchestrator import ScanOrchestrator, ScanTargets
        from scripts.cli.scan_session import ScanSession

        config = jmo.ScanConfig(results_dir=tmp_path, tools=["trufflehog"])
        orchestrator = ScanOrchestrator(config)

        for name in ("alpha", "beta"):
            (tmp_path / name).mkdir()
        targets = ScanTargets(repos=[tmp_path / "alpha", tmp_path / "beta"])

        session = ScanSession(session_id="s", config_hash="h", started_at=0.0, pid=1)
        session.register_target("repo", "alpha", ["trufflehog"])
        session.register_target("repo", "beta", ["trufflehog"])
        session.mark_target_complete("alpha", rows(trufflehog="ran"))

        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("beta", rows(trufflehog="ran"))
            with caplog.at_level(
                logging.WARNING, logger="scripts.cli.scan_orchestrator"
            ):
                results = orchestrator.scan_all(
                    targets, {}, session=session, session_path=tmp_path / "s.json"
                )

        # alpha is not scanned again; its rows come back from the session.
        assert [c.kwargs["result_name"] for c in mock_scan.call_args_list] == ["beta"]
        assert sorted(name for _type, name, _rows in results) == ["alpha", "beta"]
        visible = [
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        ]
        assert any("skipped 1 previously completed" in m for m in visible), visible


class TestCrashedTargetIsStillAccounted:
    """A scanner that raises is the loudest outcome, and it was the quietest."""

    def _raise(self, tmp_path, callback):
        from scripts.cli.scan_orchestrator import ScanOrchestrator, ScanTargets

        config = jmo.ScanConfig(results_dir=tmp_path, tools=["trufflehog", "zap"])
        orchestrator = ScanOrchestrator(config)
        (tmp_path / "proj").mkdir()
        targets = ScanTargets(repos=[tmp_path / "proj"])

        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.side_effect = RuntimeError("scanner exploded")
            return orchestrator.scan_all(targets, {}, progress_callback=callback)

    def test_raising_scanner_still_reaches_the_progress_display(self, tmp_path):
        """The callback used to be skipped on the exception path, and the run
        ended showing fewer targets than it had."""
        calls: list[tuple] = []

        results = self._raise(
            tmp_path, lambda t, i, r, elapsed=0.0: calls.append((t, i, r))
        )

        assert len(calls) == 1, "the crashed target never reached the progress display"
        assert calls[0][1] == "proj"
        (target_type, name, failed) = results[0]
        assert (target_type, name) == ("repo", "proj")
        # A row per tool, with the reason, so it reaches history too.
        assert failed["trufflehog"].label == "failed:scanner error"
        assert "scanner exploded" in (failed["trufflehog"].detail or "")
        assert failed["zap"].label == "skipped:needs --url"
        assert classify_target_outcome(failed) == TARGET_FAILED
        assert calls[0][2] == failed

    def test_a_broken_progress_callback_cannot_kill_the_scan(self, tmp_path):
        def exploding_callback(*args, **kwargs):
            raise ValueError("display is broken")

        results = self._raise(tmp_path, exploding_callback)

        assert results[0][2]["trufflehog"].label == "failed:scanner error"


class TestToolApplicableToNoTargetType:
    """#1279 item 1: only a tool someone named earns the "applicable to no
    target type" line. The matrix default put zap and nuclei in every
    repository scan, where it fired although nothing was requested."""

    def _scan(self, tmp_path, caplog, explicit):
        from scripts.cli.scan_orchestrator import ScanOrchestrator, ScanTargets

        config = jmo.ScanConfig(
            results_dir=tmp_path, tools=["nuclei"], explicit_tools=explicit
        )
        (tmp_path / "proj").mkdir()
        (tmp_path / "proj" / "a.py").write_bytes(b"x = 1\n")
        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_orchestrator"):
            results = ScanOrchestrator(config).scan_all(
                ScanTargets(repos=[tmp_path / "proj"]), {}
            )
        visible = [
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        ]
        return results, visible

    def test_a_named_tool_that_reads_no_target_here_is_warned_about(
        self, tmp_path, caplog
    ):
        results, visible = self._scan(tmp_path, caplog, explicit=True)

        (_type, _name, target_rows) = results[0]
        assert target_rows == rows(nuclei="skipped:needs --url")
        # The target contributed nothing, and the warning agrees.
        assert classify_target_outcome(target_rows) == TARGET_FAILED
        assert any("applicable to no target type" in m for m in visible), visible

    def test_a_defaulted_tool_gets_its_row_and_no_warning(self, tmp_path, caplog):
        results, visible = self._scan(tmp_path, caplog, explicit=False)

        assert results[0][2] == rows(nuclei="skipped:needs --url")
        assert not any("applicable to no target type" in m for m in visible), visible


class TestTheSkipReasonsReadDifferently:
    """#1081: `not installed` is a gap the user can close; `no Go sources` is a
    correct decision about this target. The end-of-scan WARN is for the first
    only, and must keep firing for it."""

    def test_the_summary_separates_them(self):
        summary = summarize_target(
            rows(
                semgrep="ran",
                trivy="skipped:not installed",
                gosec="skipped:no Go sources",
                zap="skipped:needs --url",
                grype="failed:timed out",
            )
        )

        assert summary.not_installed == ["trivy"]
        assert summary.failed == ["grype"]
        # In-scope skips only: a tool that reads no target of this kind is not
        # news on a line about why this target produced nothing.
        assert summary.skipped == ["gosec (no Go sources)", "trivy (not installed)"]
        assert summary.outcome == TARGET_PARTIAL

    @staticmethod
    def _scan_with(scan_env, tmp_path, monkeypatch, capsys, tool, resolves):
        """Run a one-repo scan for `tool` against a repository with no Go."""
        cfg = tmp_path / "jmo.yml"
        cfg.write_text(
            yaml.safe_dump({"tools": [tool], "outputs": ["json"]}), encoding="utf-8"
        )
        scan_env.config = str(cfg)
        scan_env.tools = [tool]
        scan_env.allow_missing_tools = True
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.tool_loop.find_tool",
            (lambda *a, **k: "/usr/bin/" + tool)
            if resolves
            else (lambda *a, **k: None),
        )
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.repository_scanner.ToolRunner",
            lambda **kw: types.SimpleNamespace(run_all_parallel=list),
        )
        jmo.cmd_scan(scan_env)
        return capsys.readouterr().err

    def test_nothing_to_scan_is_not_reported_as_a_stub(
        self, scan_env, tmp_path, monkeypatch, capsys
    ):
        err = self._scan_with(
            scan_env, tmp_path, monkeypatch, capsys, "gosec", resolves=True
        )

        assert "were STUBBED, not executed" not in err, err
        skipped = [
            ln for ln in err.splitlines() if "SKIPPED with nothing to scan" in ln
        ]
        assert len(skipped) == 1, f"expected one skipped line: {err}"
        assert "gosec (no Go sources)" in skipped[0]
        assert '"level": "INFO"' in skipped[0], "a benign outcome was raised to WARN"

    def test_a_missing_binary_is_still_reported_as_a_stub(
        self, scan_env, tmp_path, monkeypatch, capsys
    ):
        """The other half: a fix that simply stopped warning would pass above."""
        err = self._scan_with(
            scan_env, tmp_path, monkeypatch, capsys, "gosec", resolves=False
        )

        stubbed = [ln for ln in err.splitlines() if "were STUBBED, not executed" in ln]
        assert len(stubbed) == 1, f"the true warning was lost with the false one: {err}"
        assert "gosec" in stubbed[0]
        assert '"level": "WARN"' in stubbed[0]
        assert "SKIPPED with nothing to scan" not in err


class TestThePerTargetLineOnlyWarnsAboutRealGaps:
    """The per-target progress line warns "stubbed and did NOT run" only for a
    tool that is not installed; a content skip is said once, at INFO, at the
    end of the run."""

    @staticmethod
    def _scan(scan_env, tmp_path, monkeypatch, capsys, *, gosec_resolves):
        from scripts.core.tool_runner import ToolResult

        cfg = tmp_path / "jmo.yml"
        cfg.write_text(
            yaml.safe_dump({"tools": ["trufflehog", "gosec"], "outputs": ["json"]}),
            encoding="utf-8",
        )
        scan_env.config = str(cfg)
        scan_env.tools = ["trufflehog", "gosec"]
        scan_env.allow_missing_tools = True

        resolvable = {"trufflehog", "gosec"} if gosec_resolves else {"trufflehog"}
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.tool_loop.find_tool",
            lambda name, *a, **k: ("/usr/bin/" + name) if name in resolvable else None,
        )
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.repository_scanner.ToolRunner",
            lambda **kw: types.SimpleNamespace(
                run_all_parallel=lambda: [
                    ToolResult(tool="trufflehog", status="success", attempts=1)
                ]
            ),
        )
        jmo.cmd_scan(scan_env)
        return capsys.readouterr().err

    @staticmethod
    def _progress_line(err: str) -> str:
        lines = [ln for ln in err.splitlines() if "[1/1]" in ln]
        assert len(lines) == 1, f"expected one progress line: {lines}"
        return lines[0]

    def test_a_tool_with_nothing_to_scan_does_not_warn_on_the_target_line(
        self, scan_env, tmp_path, monkeypatch, capsys
    ):
        err = self._scan(scan_env, tmp_path, monkeypatch, capsys, gosec_resolves=True)
        line = self._progress_line(err)

        assert "were stubbed and did NOT run" not in line, line
        assert '"level": "INFO"' in line, "a clean target was raised to WARN: " + line
        assert "SKIPPED with nothing to scan" in err
        assert "gosec" in err

    def test_a_missing_tool_still_warns_on_the_target_line(
        self, scan_env, tmp_path, monkeypatch, capsys
    ):
        err = self._scan(scan_env, tmp_path, monkeypatch, capsys, gosec_resolves=False)
        line = self._progress_line(err)

        assert "1 tool(s) were stubbed and did NOT run" in line, line
        assert "gosec" in line
        assert '"level": "WARN"' in line


class TestResumedTargetsKeepTheirRows:
    """`--resume` skips the targets its session completed. Their rows must still
    reach `tool_runs`, or history loses them and the reconciler sees more
    timing documents than targets (review of PR B, Important #2)."""

    def test_a_completed_target_is_not_rescanned_and_keeps_its_rows(self, tmp_path):
        from scripts.cli.scan_orchestrator import (
            ScanConfig,
            ScanOrchestrator,
            ScanTargets,
        )
        from scripts.cli.scan_session import ScanSession, load_session, save_session

        alpha, beta = tmp_path / "alpha", tmp_path / "beta"
        for repo in (alpha, beta):
            repo.mkdir()
        session = ScanSession(session_id="s", config_hash="h", started_at=0.0, pid=1)
        for name in ("alpha", "beta"):
            session.register_target("repo", name, ["trufflehog"])
        done = ToolRun(
            "trufflehog", State.RAN, seconds=4.5, exit_code=0, attempts=1, invocations=1
        )
        session.mark_target_complete("alpha", {"trufflehog": done})
        path = tmp_path / "session.json"
        save_session(session, path)
        resumed = load_session(path)  # the rows must survive the file itself
        orch = ScanOrchestrator(
            ScanConfig(results_dir=tmp_path / "results", tools=["trufflehog"])
        )

        with patch("scripts.cli.scan_jobs.scan_repository") as scan:
            scan.side_effect = lambda repo, *a, result_name, **k: (
                result_name,
                rows(trufflehog="ran"),
            )
            results = orch.scan_all(
                ScanTargets(repos=[alpha, beta]), {}, session=resumed, session_path=path
            )

        assert [c.kwargs["result_name"] for c in scan.call_args_list] == ["beta"]
        by_name = {name: target_rows for _, name, target_rows in results}
        assert sorted(by_name) == ["alpha", "beta"]
        assert by_name["alpha"] == {"trufflehog": done}
