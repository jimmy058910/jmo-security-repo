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


class TestStubbedToolIsNotASuccess:
    """#825: `--allow-missing-tools` recorded a tool that never ran as `True`.

    Every scanner had the shape::

        elif allow_missing_tools:
            _write_stub("trivy", trivy_out)
            statuses["trivy"] = True

    so a tool that was never executed carried the same value as one that ran
    and succeeded, and an empty stub was written that the report phase reads as
    "this tool found nothing". That is the `zero-secrets` shape: an empty result
    from a secret scanner that never ran satisfies a zero-secrets policy.

    On a normal host the pre-flight removes missing tools before the scanners
    run, so this fires only when `find_tool` disagrees with it at scan time.
    **In a container the pre-flight is skipped entirely** -- `jmo.py` gates it
    on `DOCKER_CONTAINER` -- so it is the normal path there, not an edge case:
    a `deep` image is expected to be missing the four MANUAL_INSTALL_TOOLS.
    """

    @pytest.mark.parametrize(
        ("statuses", "expected", "why"),
        [
            pytest.param(
                {"trivy": False, "__not_attempted__": {"trivy": "not installed"}},
                TARGET_NOT_ATTEMPTED,
                "the only tool was stubbed",
                id="all-stubbed",
            ),
            pytest.param(
                {
                    "trivy": True,
                    "nuclei": False,
                    "__not_attempted__": {"nuclei": "not installed"},
                },
                TARGET_OK,
                "what ran, worked",
                id="one-ran-one-stubbed",
            ),
            pytest.param(
                {
                    "trivy": False,
                    "nuclei": False,
                    "__not_attempted__": {"nuclei": "not installed"},
                },
                TARGET_FAILED,
                "the tool that ran failed; the stub does not soften that",
                id="one-failed-one-stubbed",
            ),
            pytest.param(
                {"trivy": False, "trufflehog": False},
                TARGET_FAILED,
                "no stubs: both genuinely ran and failed",
                id="no-stubs-still-failed",
            ),
        ],
    )
    def test_a_stub_does_not_vote(self, statuses, expected, why):
        """A tool that never ran gets no vote, in either direction.

        `True` was the original bug. `False` would be the opposite error: a
        target where one tool ran cleanly and two were not installed has not
        partially failed.
        """
        assert classify_target_outcome(statuses) == expected, why

    def test_record_not_attempted_sets_false_and_records_the_reason(self):
        from scripts.cli.scan_utils import (
            NOT_ATTEMPTED_KEY,
            not_attempted_tools,
            record_not_attempted,
        )

        statuses: dict = {}
        record_not_attempted(statuses, "trivy")
        record_not_attempted(statuses, "mobsf", "nothing for it to scan")

        # False, not True: the tool did not run, so it did not succeed.
        assert statuses["trivy"] is False
        assert statuses["mobsf"] is False
        assert not_attempted_tools(statuses) == ["mobsf", "trivy"]
        # The two reasons are kept apart: one is a gap in the environment the
        # user can close, the other is a correct decision about this target.
        assert statuses[NOT_ATTEMPTED_KEY]["trivy"] == "not installed"
        assert statuses[NOT_ATTEMPTED_KEY]["mobsf"] == "nothing for it to scan"

    def _stubbed_scan(self, scan_env, tmp_path, monkeypatch):
        """A scan where no tool resolves, so every one is stubbed."""
        scan_env.allow_missing_tools = True
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.repository_scanner.find_tool",
            lambda *a, **k: None,
        )
        return jmo.cmd_scan(scan_env)

    def test_a_fully_stubbed_target_still_exits_zero(
        self, scan_env, tmp_path, monkeypatch, capsys
    ):
        """`--allow-missing-tools` is what makes this reachable.

        Making it non-zero would invert what the flag is for, which is the
        objection the issue raises against simply flipping True to False.
        """
        rc = self._stubbed_scan(scan_env, tmp_path, monkeypatch)
        assert rc == 0

    @staticmethod
    def _lines(err: str, needle: str) -> list[str]:
        return [ln for ln in err.splitlines() if needle in ln]

    def test_the_per_target_line_says_no_tool_ran(
        self, scan_env, tmp_path, monkeypatch, capsys
    ):
        """The progress line for this target, specifically.

        Asserted separately from the end-of-scan summary below, because both
        carry the tool's name and the word STUBBED -- so a test that only looks
        at the whole stream passes with either one deleted. Both survived a
        mutation run for exactly that reason.
        """
        self._stubbed_scan(scan_env, tmp_path, monkeypatch)
        err = capsys.readouterr().err

        # `[1/1]` is the progress line and nothing else.
        progress = self._lines(err, "[1/1]")
        assert len(progress) == 1, f"expected one progress line: {progress}"
        line = progress[0]
        assert '"level": "WARN"' in line, "the progress line was logged at INFO"
        assert "NO tool ran against this target" in line
        assert "trufflehog" in line, "the stubbed tool is not named on its own line"
        # The glyph is matched escaped: `_log` emits JSON, and json.dumps'
        # ensure_ascii default renders U+25CB as the six characters `○`.
        assert "\\u25cb" in line, "the progress line still shows a pass/fail glyph"
        assert "\\u2713" not in line, "a fully stubbed target rendered as a success"

    def test_the_end_of_scan_summary_names_the_stubbed_tools(
        self, scan_env, tmp_path, monkeypatch, capsys
    ):
        """The run-level line, which is what a user reads after a long scan.

        A per-target line scrolls past on a 50-repo run; this one does not.
        """
        self._stubbed_scan(scan_env, tmp_path, monkeypatch)
        err = capsys.readouterr().err

        summary = self._lines(err, "were STUBBED, not executed")
        assert len(summary) == 1, f"expected one end-of-scan summary: {summary}"
        line = summary[0]
        assert '"level": "WARN"' in line
        assert "proj: trufflehog" in line, "the summary does not attribute per target"
        assert "not the same as finding nothing" in line

    def test_the_scan_metadata_carries_which_tools_were_stubbed(
        self, scan_env, tmp_path, monkeypatch, capsys
    ):
        """The report phase cannot tell a stub from a clean run on its own.

        A stub is that tool's own empty-result shape, in a file with that
        tool's own name, so once the scan process is gone there is nothing to
        distinguish it. The scan->report handoff has to carry it.
        """
        self._stubbed_scan(scan_env, tmp_path, monkeypatch)
        capsys.readouterr()

        meta = json.loads(
            (tmp_path / "results" / ".scan_metadata.json").read_bytes().decode("utf-8")
        )
        assert meta["stubbed_tools"] == {"proj": ["trufflehog"]}

    def test_a_real_scan_reports_no_stubs(self, scan_env, capsys):
        """Negative control, in both directions.

        Without it, reporting every target as stubbed would satisfy every test
        above, and `stubbed_tools` would be noise rather than a signal.
        """
        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("proj", {"trufflehog": True})
            assert jmo.cmd_scan(scan_env) == 0

        err = capsys.readouterr().err
        assert "STUBBED" not in err
        assert "\\u2713" in err, "a clean target should still carry the tick"

    def test_no_stub_site_records_a_bare_true(self):
        """Drift guard: the next `elif allow_missing_tools:` must not regress.

        38 sites wrote a stub and then claimed success. An AST scan is what
        keeps the 39th from doing the same -- and it covers all five scanners,
        which is where a per-scanner test would leave gaps.

        Derived, with a floor, so an extractor that finds nothing cannot pass.
        """
        import ast

        scan_jobs = Path(jmo.__file__).parent / "scan_jobs"
        offenders: list[str] = []
        stub_calls = 0
        for path in sorted(scan_jobs.glob("*.py")):
            tree = ast.parse(path.read_bytes().decode("utf-8"), filename=str(path))
            for node in ast.walk(tree):
                body = getattr(node, "body", None)
                if not isinstance(body, list):
                    continue
                for first, second in itertools.pairwise(body):
                    if not (
                        isinstance(first, ast.Expr)
                        and isinstance(first.value, ast.Call)
                        and "write_stub" in ast.unparse(first.value.func)
                    ):
                        continue
                    stub_calls += 1
                    if (
                        isinstance(second, ast.Assign)
                        and "statuses[" in ast.unparse(second.targets[0])
                        and isinstance(second.value, ast.Constant)
                        and second.value.value is True
                    ):
                        offenders.append(f"{path.name}:{second.lineno}")

        assert (
            stub_calls >= 30
        ), f"AST scan found only {stub_calls} stub calls; extractor is broken"
        assert not offenders, (
            "a stub is written and the tool recorded as a successful run at:\n"
            + "\n".join(f"  {o}" for o in offenders)
            + "\nUse record_not_attempted(statuses, <tool>) instead."
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

    ``cmd_scan`` unconditionally calls ``_show_kofi_reminder()`` near the end
    (#933), which resolves ``Path.home() / ".jmo" / "config.yml"`` with no
    injection point. Redirect it here so every test using this fixture writes
    to ``tmp_path`` instead of the developer's real config file.
    """
    repos_dir = tmp_path / "repos"
    (repos_dir / "proj").mkdir(parents=True)
    cfg_path = tmp_path / "jmo.yml"
    cfg_path.write_text(
        yaml.safe_dump({"tools": ["trufflehog"], "outputs": ["json"]}), encoding="utf-8"
    )
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    return _scan_args(tmp_path, cfg_path, repos_dir)


class TestProfileShortcutsStoreHistory:
    """#870: `jmo fast|balanced|full` silently stored nothing.

    `cmd_profile` copies the *profile* parser's namespace into `cmd_ci`, and
    that parser defined 12 dests to `jmo ci`'s 42. `store_history` was among the
    30 missing, and `report_orchestrator` gates storage on
    `getattr(args, "store_history", False)` -- so an absent attribute meant OFF
    while the parser that defines it defaults it ON. `jmo history list` and
    `jmo trends` were permanently empty for anyone who only ran `jmo fast`, and
    the shortcuts had no `--no-store-history` to turn it on either.

    The parser-parity guards live in `test_ci_arg_forwarding.py`. This asserts
    the behaviour they exist to protect, because "the dest is defined" and "a
    row reaches the database" are different claims.
    """

    def _profile_args(self, scan_env, tmp_path, db):
        """The shortcut's namespace, as its own parser would produce it."""
        import sys

        from scripts.cli.jmo import parse_args

        argv = [
            "jmo",
            "fast",
            "--repos-dir",
            scan_env.repos_dir,
            "--results-dir",
            str(tmp_path / "results"),
            "--config",
            scan_env.config,
            "--history-db",
            str(db),
            # Pinned for the same reason as the duration test: naming a profile
            # otherwise resolves the full tool list and the version check spawns
            # a real binary, which the #907 guard refuses.
            "--tools",
            "trufflehog",
        ]
        with patch.object(sys, "argv", argv):
            return parse_args()

    def test_jmo_fast_records_the_scan_in_history(self, scan_env, tmp_path):
        db = tmp_path / "history.db"
        args = self._profile_args(scan_env, tmp_path, db)

        assert (
            args.store_history is True
        ), "the shortcut parser still does not define store_history"

        with (
            patch("scripts.cli.scan_jobs.scan_repository") as mock_scan,
            patch("scripts.cli.jmo._open_results"),
        ):
            mock_scan.return_value = ("proj", {"trufflehog": True})
            rc = jmo.cmd_profile(args, "fast")

        assert rc == 0
        assert db.exists(), "jmo fast created no history database at all"
        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        try:
            rows = con.execute("SELECT profile FROM scans").fetchall()
        finally:
            con.close()
        assert len(rows) == 1, f"expected exactly one stored scan, got {rows}"
        assert rows[0][0] == "fast", "the row must name the shortcut's profile"

    def test_no_store_history_now_turns_it_off(self, scan_env, tmp_path):
        """The other half of the fix: the flag has to exist AND work.

        Without this the test above passes on a build that stores
        unconditionally, which was option 2 in the issue and the thing option 1
        was chosen over.
        """
        import sys

        from scripts.cli.jmo import parse_args

        db = tmp_path / "history.db"
        argv = [
            "jmo",
            "fast",
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
            "--no-store-history",
        ]
        with patch.object(sys, "argv", argv):
            args = parse_args()
        assert args.store_history is False

        with (
            patch("scripts.cli.scan_jobs.scan_repository") as mock_scan,
            patch("scripts.cli.jmo._open_results"),
        ):
            mock_scan.return_value = ("proj", {"trufflehog": True})
            assert jmo.cmd_profile(args, "fast") == 0

        assert not db.exists(), "--no-store-history still wrote a database"

    def test_a_contradictory_profile_name_is_refused(self, scan_env, tmp_path):
        """`--profile-name` now exists on the shortcuts and cmd_profile sets it.

        Overriding what the user typed in silence is the class this campaign
        keeps finding, so the contradiction is an error instead.
        """
        import sys

        from scripts.cli.jmo import parse_args

        argv = [
            "jmo",
            "fast",
            "--repos-dir",
            scan_env.repos_dir,
            "--results-dir",
            str(tmp_path / "results"),
            "--config",
            scan_env.config,
            # Isolation that has to hold for the MUTATED path, not just this
            # one. The assertion below is that cmd_profile refuses before
            # scanning -- so in a passing run nothing here is reached. Mutating
            # the refusal away is exactly what makes it run, and without these
            # two flags it then resolved the full 9-tool fast profile and wrote
            # two rows into the developer's real .jmo/history.db, because #870
            # gave the shortcuts store_history=True. A test is only isolated if
            # it is isolated when its guard is removed.
            "--history-db",
            str(tmp_path / "history.db"),
            "--tools",
            "trufflehog",
            "--profile-name",
            "deep",
        ]
        with patch.object(sys, "argv", argv):
            args = parse_args()

        assert jmo.cmd_profile(args, "fast") == 2
        assert not (
            tmp_path / "history.db"
        ).exists(), "the refusal happened after a scan, not before it"

    @pytest.mark.parametrize(
        ("extra", "expected"),
        [
            pytest.param([], True, id="default-allows-missing-tools"),
            pytest.param(["--strict"], False, id="strict-disables-stubs"),
        ],
    )
    def test_strict_still_controls_stubbing(self, scan_env, tmp_path, extra, expected):
        """`--allow-missing-tools` now exists here too, so say which one wins.

        The shortcuts allow missing tools by default -- the opposite of
        `jmo ci` -- and `--strict` is the flag that turns that off. Both rows
        matter: without the first, setting the value to a constant `False`
        passes; without the second, a constant `True` passes.
        """
        import sys

        from scripts.cli.jmo import parse_args

        argv = [
            "jmo",
            "fast",
            "--repos-dir",
            scan_env.repos_dir,
            "--results-dir",
            str(tmp_path / "results"),
            "--config",
            scan_env.config,
            "--no-store-history",
            *extra,
        ]
        with patch.object(sys, "argv", argv):
            args = parse_args()

        captured = {}

        def fake_ci(ns):
            captured["ns"] = ns
            return 0

        with (
            patch("scripts.cli.jmo.cmd_ci", fake_ci),
            patch("scripts.cli.jmo._open_results"),
        ):
            assert jmo.cmd_profile(args, "fast") == 0

        assert captured["ns"].allow_missing_tools is expected

    def test_a_matching_profile_name_is_accepted(self, scan_env, tmp_path):
        """Negative control: only a contradiction may be refused."""
        import sys

        from scripts.cli.jmo import parse_args

        argv = [
            "jmo",
            "fast",
            "--repos-dir",
            scan_env.repos_dir,
            "--results-dir",
            str(tmp_path / "results"),
            "--config",
            scan_env.config,
            "--tools",
            "trufflehog",
            "--no-store-history",
            "--profile-name",
            "fast",
        ]
        with patch.object(sys, "argv", argv):
            args = parse_args()

        with (
            patch("scripts.cli.scan_jobs.scan_repository") as mock_scan,
            patch("scripts.cli.jmo._open_results"),
        ):
            mock_scan.return_value = ("proj", {"trufflehog": True})
            assert jmo.cmd_profile(args, "fast") == 0


class TestScanRecordsItsOwnDuration:
    """#981: `scans.duration_seconds` was NULL on 2472 of 2472 rows.

    The column, the `store_scan` parameter and both readers all existed. No
    production caller ever passed a value, so the number a user sees was `N/A`
    for the entire recorded history of the database.

    The tempting one-line fix -- pass the report phase's `elapsed`, which is
    already in scope at the call site -- is wrong: that times aggregation,
    roughly thirty seconds standing in for a twenty-minute scan. A wrong number
    reads as measured, while NULL renders as honestly empty. So the scan phase
    records its own wall clock and hands it over in `.scan_metadata.json`.

    This drives the whole chain rather than any one link, because each link was
    individually present and working before the fix.
    """

    def test_a_scan_stores_a_duration_a_user_can_read(
        self, scan_env, tmp_path, monkeypatch
    ):
        db = tmp_path / "history.db"
        scan_env.store_history = True
        scan_env.history_db = str(db)
        # The shared fixture's config names no default_profile, which makes
        # cmd_scan record profile="custom" -- a value store_scan rejects, so
        # the run would exit 0 having stored nothing and this test would be
        # asserting against an empty table.
        #
        # --tools is pinned alongside it because naming a profile otherwise
        # resolves the full 17-tool balanced list, and the version check then
        # spawns a real `semgrep --version` -- which the #907 guard correctly
        # refuses. The profile here is a label on the row, not a tool list.
        scan_env.profile_name = "balanced"
        scan_env.tools = ["trufflehog"]

        # A clock that advances 1000s per read, so the recorded value cannot be
        # confused with the real wall clock of a mocked scan (well under a
        # second). Patching rather than sleeping is the same call as the
        # attestation-ordering fix: make the guard deterministic instead of
        # widening its tolerance.
        #
        # It starts at a large offset on purpose. `perf_counter`'s zero point is
        # undefined, so a duration must be a *delta* between two reads -- and
        # with the clock based at zero, forgetting the subtraction produces a
        # number that passes every "is it plausible" check. The offset is what
        # makes the two cases distinguishable.
        clock_base = 500_000.0
        ticks = itertools.count(clock_base, 1000.0)
        monkeypatch.setattr(time, "perf_counter", lambda: next(ticks))

        with patch("scripts.cli.scan_jobs.scan_repository") as mock_scan:
            mock_scan.return_value = ("proj", {"trufflehog": True})
            assert jmo.cmd_scan(scan_env) == 0

        meta = json.loads(
            (tmp_path / "results" / ".scan_metadata.json").read_bytes().decode("utf-8")
        )
        assert "duration_seconds" in meta, (
            "the scan phase did not record its duration, so the report phase "
            "has nothing to store"
        )
        assert meta["duration_seconds"] >= 1000.0, (
            "the recorded duration did not come from the patched clock: "
            f"{meta['duration_seconds']}"
        )
        assert meta["duration_seconds"] < clock_base, (
            "the duration is an absolute clock reading, not an elapsed time -- "
            f"{meta['duration_seconds']} is past the clock's own base offset"
        )

        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        try:
            stored = con.execute("SELECT duration_seconds FROM scans").fetchone()[0]
        finally:
            con.close()
        assert stored == meta["duration_seconds"], (
            "the scan's duration did not reach the database: "
            f"stored={stored!r} recorded={meta['duration_seconds']!r}"
        )


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
