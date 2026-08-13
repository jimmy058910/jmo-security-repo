#!/usr/bin/env python3
"""Guards for the scan phase's partial-failure accounting (chunk 4, #809/#811).

The failure this file exists to prevent: **the scan layer knew a target had
produced nothing and said it succeeded anyway.** Every scanner in
``scan_jobs/`` reports ``dict.fromkeys(tools, False)`` on its failure paths, and
that map reached neither the progress line nor the exit code -- so
``jmo scan --gitlab-repo <x>`` with no token printed ``[1/1] OK`` and exited 0,
and its ``zero-secrets`` policy passed on a scan where no secret scanner ran.

Each test below asserts more than one condition, because on chunk 3 two tests
asserting only ``rc != 0`` passed on CI for the wrong reason: the shards install
no scanners, so ``cmd_scan`` bailed at the tool pre-flight before reaching the
code under test, and that bail also returns non-zero.
"""

from __future__ import annotations

import json
import logging
import types
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.cli.scan_orchestrator import (
    TARGET_FAILED,
    TARGET_OK,
    TARGET_PARTIAL,
    _run_timed,
    classify_target_outcome,
)


class TestClassifyTargetOutcome:
    """The one place that decides whether a target produced anything."""

    @pytest.mark.parametrize(
        ("statuses", "expected"),
        [
            ({"trivy": True, "trufflehog": True}, TARGET_OK),
            ({"trivy": True, "trufflehog": False}, TARGET_PARTIAL),
            ({"trivy": False, "trufflehog": False}, TARGET_FAILED),
            ({"trivy": True}, TARGET_OK),
            ({"trivy": False}, TARGET_FAILED),
        ],
    )
    def test_outcome_follows_the_booleans(self, statuses, expected):
        assert classify_target_outcome(statuses) == expected

    def test_empty_map_is_failure_not_vacuous_success(self):
        """``all([])`` is True. That reading is the bug, not the fix.

        ``scan_all`` appends ``(target_id, {})`` when a scan job raises, and a
        scanner handed no applicable tools returns an empty map too. Both mean
        the target contributed nothing.
        """
        assert classify_target_outcome({}) == TARGET_FAILED
        assert classify_target_outcome(None) == TARGET_FAILED

    def test_metadata_keys_are_not_tools(self):
        """``__attempts__`` rides in the same dict and must not vote."""
        assert classify_target_outcome({"__attempts__": {"trivy": 3}}) == TARGET_FAILED
        assert (
            classify_target_outcome({"trivy": True, "__attempts__": {"trivy": 3}})
            == TARGET_OK
        )
        assert (
            classify_target_outcome({"trivy": False, "__attempts__": {"trivy": 3}})
            == TARGET_FAILED
        )


class TestRunTimed:
    """The per-target duration must be measured, not asserted."""

    def test_returns_result_and_a_real_duration(self):
        def job(a, b, *, c):
            return f"{a}{b}{c}", {"trivy": True}

        name, statuses, elapsed = _run_timed(job, "x", "y", c="z")
        assert name == "xyz"
        assert statuses == {"trivy": True}
        assert isinstance(elapsed, float)
        assert elapsed >= 0.0

    def test_exceptions_propagate_to_the_future(self):
        """A raising job must still reach scan_all's except branch."""

        def job():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            _run_timed(job)


def _scan_args(
    tmp_path: Path, cfg_path: Path, repos_dir: Path
) -> types.SimpleNamespace:
    """The minimum namespace ``cmd_scan`` needs, mirroring test_cli_profiles."""
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
        profile_name=None,
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
    for an unrelated reason, which is exactly how two chunk-3 guards passed
    while never executing what they claimed to cover.
    """
    repos_dir = tmp_path / "repos"
    (repos_dir / "proj").mkdir(parents=True)
    cfg_path = tmp_path / "jmo.yml"
    cfg_path.write_text(
        yaml.safe_dump({"tools": ["trufflehog"], "outputs": ["json"]}), encoding="utf-8"
    )
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    monkeypatch.setenv("CI", "true")
    return _scan_args(tmp_path, cfg_path, repos_dir)


class TestScanExitCodeReflectsTargetOutcome:
    """#809: a target that produced nothing must not exit 0."""

    def test_target_where_every_tool_failed_exits_non_zero(self, scan_env, capsys):
        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("proj", {"trufflehog": False})
            rc = jmo.cmd_scan(scan_env)

        err = capsys.readouterr().err
        # Four independent conditions. The exit code alone cannot tell this
        # apart from a pre-flight bail, and the glyph alone is not durable.
        #
        # The glyph is matched in its escaped form: `_log` emits JSON via
        # json.dumps, whose ensure_ascii default renders U+2717 as the six
        # literal characters `✗`. Asserting the raw character here would
        # fail against output that is entirely correct.
        assert rc != 0, "a target that produced nothing must not exit 0"
        assert "produced no findings" in err
        assert "proj" in err
        assert "\\u2717" in err, "the progress line should carry the failure glyph"
        # The level carries the outcome for anyone consuming the JSON stream
        # rather than the glyph.
        assert '"level": "ERROR"' in err

    def test_successful_target_still_exits_zero(self, scan_env, capsys):
        """The control. Without it the test above passes for any always-fail bug."""
        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("proj", {"trufflehog": True})
            rc = jmo.cmd_scan(scan_env)

        err = capsys.readouterr().err
        assert rc == 0
        assert "produced no findings" not in err
        assert "\\u2713" in err, "a clean target should carry the success glyph"

    def test_partial_target_exits_zero_but_says_so(self, scan_env, capsys):
        """Deliberately scoped: only a target that produced *nothing* fails the run.

        Individual tool failures are already reported per tool, and a deep
        profile legitimately runs tools that do not apply everywhere. Making
        any single tool failure non-zero would redden ordinary scans.
        """
        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("proj", {"trufflehog": True, "trivy": False})
            rc = jmo.cmd_scan(scan_env)

        err = capsys.readouterr().err
        assert rc == 0
        assert "MISSING" in err
        assert "trivy" in err


class TestAllowMissingToolsSaysWhatHappened:
    """#811: the flag that exists to let a scan proceed failed silently."""

    def test_nothing_left_to_run_is_explained(self, scan_env, capsys, monkeypatch):
        monkeypatch.setattr(
            jmo, "_check_scan_tools", lambda args, tools: ([], ["nuclei"])
        )
        scan_env.allow_missing_tools = True

        rc = jmo.cmd_scan(scan_env)
        captured = capsys.readouterr()

        assert rc == 1
        # The original defect was silence on *both* streams, so assert on both.
        combined = captured.out + captured.err
        assert combined.strip(), "the branch returned 1 with no output on any stream"
        assert "--allow-missing-tools" in combined
        assert "nuclei" in combined


class TestReportDoesNotWarnAboutItsOwnArtifact:
    """#784(3): a warning that fires every run trains the reader to ignore it."""

    def test_scan_timings_is_not_treated_as_a_tool_output(self, tmp_path, caplog):
        from scripts.core.normalize_and_report import gather_results
        from scripts.core.scan_timings import SCAN_TIMINGS_FILENAME

        target = tmp_path / "individual-repos" / "proj"
        target.mkdir(parents=True)
        (target / SCAN_TIMINGS_FILENAME).write_text(
            json.dumps({"schema_version": 1, "tools": []}), encoding="utf-8"
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
        """Asserted as "at least WARNING", which is the property that matters.

        `configure_scan_logging` sets the `scripts` logger to WARNING by
        default, so this notice was emitted at a level the scan itself
        configures away -- measured: present under `--log-level INFO`, absent
        under `--log-level WARN`, which is the default. Meanwhile jmo.py's own
        `_log` prints INFO, so the two logging systems have different effective
        floors and the only line reporting reduced coverage was on the quiet
        one. The progress display also ends part-way (`Progress: 50%`) with no
        other explanation.
        """
        from scripts.cli.scan_orchestrator import ScanOrchestrator, ScanTargets
        from scripts.cli.scan_session import ScanSession

        config = jmo.ScanConfig(results_dir=tmp_path, tools=["trufflehog"])
        orchestrator = ScanOrchestrator(config)

        for name in ("alpha", "beta"):
            (tmp_path / name).mkdir()
        targets = ScanTargets(repos=[tmp_path / "alpha", tmp_path / "beta"])

        session = ScanSession(
            session_id="s", profile="p", config_hash="h", started_at=0.0, pid=1
        )
        session.register_target("repo", "alpha", ["trufflehog"])
        session.register_target("repo", "beta", ["trufflehog"])
        session.mark_target_complete("alpha", {"trufflehog": True})

        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("beta", {"trufflehog": True})
            with caplog.at_level(
                logging.WARNING, logger="scripts.cli.scan_orchestrator"
            ):
                results = orchestrator.scan_all(
                    targets, {}, session=session, session_path=tmp_path / "s.json"
                )

        # Only the un-completed target ran -- the resume itself works.
        assert [name for name, _ in results] == ["beta"]

        visible = [
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        ]
        assert any("skipped 1 previously completed" in m for m in visible), (
            "the only notice that this run covered fewer targets than requested "
            "was emitted below the default log level, so nobody saw it. Records "
            f"at >=WARNING were: {visible}"
        )


class TestCrashedTargetIsStillAccounted:
    """A scanner that raises is the loudest outcome, and it was the quietest."""

    def test_raising_scanner_still_reaches_the_progress_display(self, tmp_path):
        """The callback used to be skipped entirely on the exception path.

        The run then ended showing fewer completed targets than it had, with no
        line naming the one that vanished.
        """
        from scripts.cli.scan_orchestrator import ScanOrchestrator, ScanTargets

        config = jmo.ScanConfig(results_dir=tmp_path, tools=["trufflehog"])
        orchestrator = ScanOrchestrator(config)
        (tmp_path / "proj").mkdir()
        targets = ScanTargets(repos=[tmp_path / "proj"])

        calls: list[tuple] = []

        def progress_callback(target_type, target_id, statuses, elapsed=0.0):
            calls.append((target_type, target_id, statuses, elapsed))

        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.side_effect = RuntimeError("scanner exploded")
            results = orchestrator.scan_all(
                targets, {}, progress_callback=progress_callback
            )

        assert len(calls) == 1, "the crashed target never reached the progress display"
        assert calls[0][1] == "proj"
        # Empty status map -> classify_target_outcome says TARGET_FAILED, which
        # is what drives the cross and the non-zero exit.
        assert calls[0][2] == {}
        assert results == [("proj", {})]

    def test_a_broken_progress_callback_cannot_kill_the_scan(self, tmp_path):
        """The new call sits inside an except block; anything it raises escapes.

        Guarded the way ToolRunner guards its callbacks. Without it a display
        bug turns one target's failure into the death of the whole run.
        """
        from scripts.cli.scan_orchestrator import ScanOrchestrator, ScanTargets

        config = jmo.ScanConfig(results_dir=tmp_path, tools=["trufflehog"])
        orchestrator = ScanOrchestrator(config)
        (tmp_path / "proj").mkdir()
        targets = ScanTargets(repos=[tmp_path / "proj"])

        def exploding_callback(*args, **kwargs):
            raise ValueError("display is broken")

        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.side_effect = RuntimeError("scanner exploded")
            results = orchestrator.scan_all(
                targets, {}, progress_callback=exploding_callback
            )

        assert results == [("proj", {})]


class TestToolApplicableToNoTargetType:
    """A requested tool that applies nowhere leaves the target with no tools."""

    def test_target_with_no_applicable_tool_produced_nothing(self, tmp_path, caplog):
        """`nuclei` is URL-only, so a repo target is handed an empty tool list.

        `filter_tools_for_scan_type(["nuclei"], "repo")` is `[]`, so the repo
        scanner builds no ToolDefinitions and returns an empty status map --
        which `classify_target_outcome` reads as TARGET_FAILED, because the
        target genuinely contributed nothing. `scan_all` was already warning
        about exactly this ("Requested but applicable to no target type in this
        scan"); the outcome now agrees with the warning.

        This is what `tests/unit/test_signal_handling.py` had been doing by
        accident for years with `gitleaks` -- removed in v0.5.0 and implemented
        nowhere -- while asserting the run exited 0. Measured across all four
        profiles, **every** profile/target-type pair has at least one applicable
        tool, so no profile-driven scan reaches this state; it takes an explicit
        `--tools` naming something inapplicable.
        """
        from scripts.cli.scan_orchestrator import ScanOrchestrator, ScanTargets

        config = jmo.ScanConfig(results_dir=tmp_path, tools=["nuclei"])
        orchestrator = ScanOrchestrator(config)
        (tmp_path / "proj").mkdir()
        targets = ScanTargets(repos=[tmp_path / "proj"])

        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_orchestrator"):
            results = orchestrator.scan_all(targets, {})

        assert len(results) == 1
        name, statuses = results[0]
        assert {k: v for k, v in statuses.items() if not k.startswith("__")} == {}
        assert classify_target_outcome(statuses) == TARGET_FAILED

        # The warning and the verdict must agree -- one without the other is how
        # this went unnoticed.
        visible = [
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        ]
        assert any(
            "applicable to no target type" in m for m in visible
        ), f"expected the unrouted-tool warning; got {visible}"
