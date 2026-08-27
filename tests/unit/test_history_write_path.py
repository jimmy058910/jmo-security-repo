"""Write-path guards for `jmo history` (chunk 14).

Three defects are covered here, each of which produced data that looked
plausible and was not measured:

* **#780** -- git context came from the *results* directory. `store_scan()`
  walked up from `results_dir/individual-repos/<name>` looking for a `.git`,
  which finds whatever repository happens to contain the results folder. The
  same `findings.json` stored from two locations recorded two different
  branches and commits.
* **#895** -- `jmo_version` was a literal default that no caller overrode, so
  every scan claimed `1.0.0` whatever was running.
* **`--json` failing open** -- `history migrate` and `history repair` computed
  their exit code inside the human-output branch, so the mode automation uses
  reported a failed destructive operation as success.

The tests pass explicit `db_path`/`--db` values rather than relying on
`DEFAULT_DB_PATH`, which cannot be monkeypatched into functions that bind it as
a default argument (see the `isolate_database` fixtures in test_history_db.py,
which patch `sqlite3.connect` for exactly that reason).
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from scripts.cli import history_commands as hc
from scripts.core.history_db import _scanned_repo_paths, store_scan
from scripts.core.jmo_version import UNKNOWN_VERSION, get_jmo_version


def _git(repo: Path, *args: str) -> None:
    """Run a git command with identity forced, so a bare CI box works."""
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _make_repo(root: Path, branch: str) -> Path:
    """Create a git repository on `branch` with one commit."""
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    _git(root, "checkout", "-q", "-b", branch)
    (root / "file.txt").write_bytes(b"x\n")
    _git(root, "add", "file.txt")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _make_results(root: Path, repo_paths: list[Path] | None) -> Path:
    """Build a minimal results directory `store_scan()` accepts.

    `repo_paths=None` writes no `.scan_metadata.json` at all, which is what a
    results directory produced before that key existed looks like.
    """
    (root / "summaries").mkdir(parents=True, exist_ok=True)
    (root / "individual-repos" / "target").mkdir(parents=True, exist_ok=True)
    (root / "summaries" / "findings.json").write_bytes(b"[]")
    if repo_paths is not None:
        meta = {
            "profile": "balanced",
            "tools": ["semgrep"],
            "timestamp": "2026-08-18T00:00:00+00:00",
            "target_count": len(repo_paths),
            "repo_paths": [str(p) for p in repo_paths],
        }
        (root / ".scan_metadata.json").write_bytes(json.dumps(meta).encode())
    return root


def _stored_row(db_path: Path) -> sqlite3.Row:
    """Read the single stored scan back through a read-only connection."""
    con = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        return con.execute("SELECT * FROM scans").fetchone()
    finally:
        con.close()


class TestScannedRepoPaths:
    """`_scanned_repo_paths()` must never guess."""

    def test_reads_recorded_paths(self, tmp_path):
        results = _make_results(tmp_path / "res", [tmp_path / "a", tmp_path / "b"])
        assert _scanned_repo_paths(results) == [tmp_path / "a", tmp_path / "b"]

    @pytest.mark.parametrize(
        "payload,label",
        [
            (None, "no .scan_metadata.json at all"),
            (b"{ not json", "malformed JSON"),
            (b'"a string, not an object"', "JSON that is not an object"),
            (b"{}", "object with no repo_paths key"),
            (b'{"repo_paths": "not-a-list"}', "repo_paths of the wrong type"),
            (b'{"repo_paths": [1, null, ""]}', "repo_paths with no usable strings"),
        ],
    )
    def test_returns_empty_rather_than_guessing(self, tmp_path, payload, label):
        results = _make_results(tmp_path / "res", None)
        if payload is not None:
            (results / ".scan_metadata.json").write_bytes(payload)
        assert _scanned_repo_paths(results) == [], label


class TestBranchComesFromTheScannedRepo:
    """#780: the results directory's own location must not decide the answer."""

    def test_records_the_scanned_repo_not_the_containing_one(self, tmp_path):
        scanned = _make_repo(tmp_path / "scanned", "feature-branch")
        containing = _make_repo(tmp_path / "containing", "unrelated-branch")

        # The results live INSIDE `containing`, but name `scanned`. Before the
        # fix this recorded `unrelated-branch`, because the walk started at the
        # results directory.
        results = _make_results(containing / "res", [scanned])
        db = tmp_path / "h.db"
        store_scan(
            results_dir=results, profile="balanced", tools=["semgrep"], db_path=db
        )

        row = _stored_row(db)
        assert row["branch"] == "feature-branch"

        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=scanned,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert row["commit_hash"] == head

    def test_leaves_branch_null_when_the_scanned_path_is_unknown(self, tmp_path):
        containing = _make_repo(tmp_path / "containing", "unrelated-branch")
        # No .scan_metadata.json: a results directory from before the key
        # existed. NULL is correct -- "not recorded" is true, and a branch
        # copied off the containing repository would not be.
        results = _make_results(containing / "res", None)
        db = tmp_path / "h.db"
        store_scan(
            results_dir=results, profile="balanced", tools=["semgrep"], db_path=db
        )

        row = _stored_row(db)
        assert row["branch"] is None
        assert row["commit_hash"] is None

    def test_explicit_branch_still_wins(self, tmp_path):
        scanned = _make_repo(tmp_path / "scanned", "feature-branch")
        results = _make_results(tmp_path / "res", [scanned])
        db = tmp_path / "h.db"
        store_scan(
            results_dir=results,
            profile="balanced",
            tools=["semgrep"],
            db_path=db,
            branch="explicit",
            commit_hash="deadbeef",
        )
        row = _stored_row(db)
        assert row["branch"] == "explicit"


class TestStoredVersionIsTheRunningVersion:
    """#895: the column must not be a constant."""

    def test_records_the_resolved_version(self, tmp_path):
        results = _make_results(tmp_path / "res", None)
        db = tmp_path / "h.db"
        store_scan(
            results_dir=results, profile="balanced", tools=["semgrep"], db_path=db
        )

        stored = _stored_row(db)["jmo_version"]
        assert stored == get_jmo_version()
        # The specific value that made #895 invisible: it is only wrong when it
        # disagrees with the resolver, so assert against the resolver above and
        # pin the literal here only when the resolver itself is not "1.0.0".
        if get_jmo_version() != "1.0.0":
            assert stored != "1.0.0"

    def test_caller_supplied_version_still_wins(self, tmp_path):
        results = _make_results(tmp_path / "res", None)
        db = tmp_path / "h.db"
        store_scan(
            results_dir=results,
            profile="balanced",
            tools=["semgrep"],
            db_path=db,
            jmo_version="9.9.9",
        )
        assert _stored_row(db)["jmo_version"] == "9.9.9"


class TestDestructiveCommandsHonourJsonInTheirExitCode:
    """`--json` must not change what an exit code means."""

    @pytest.fixture
    def db(self, tmp_path):
        path = tmp_path / "h.db"
        sqlite3.connect(str(path)).close()
        return path

    class _Args:
        def __init__(self, db, as_json):
            self.db = str(db)
            self.json = as_json
            self.force = True
            self.target_version = None

    OK = {
        "migrate": {
            "applied": ["1.3.0"],
            "errors": [],
            "final_version": "1.3.0",
            "rollback_performed": False,
        },
        "repair": {
            "success": True,
            "errors": [],
            "backup_path": "b",
            "recovery_time_sec": 0.1,
            "rows_recovered": {},
        },
        "verify": {"is_valid": True, "errors": [], "stats": {}},
    }
    FAIL = {
        "migrate": {
            "applied": [],
            "errors": [{"version": "1.3.0", "error": "boom"}],
            "final_version": "1.2.0",
            "rollback_performed": True,
        },
        "repair": {
            "success": False,
            "errors": ["boom"],
            "backup_path": "b",
            "recovery_time_sec": 0.0,
            "rows_recovered": {},
        },
        "verify": {"is_valid": False, "errors": ["boom"], "stats": {}},
    }
    PATCH = {
        "migrate": "run_migrations",
        "repair": "recover_database",
        "verify": "verify_database_integrity",
    }
    COMMAND = {
        "migrate": "cmd_history_migrate",
        "repair": "cmd_history_repair",
        "verify": "cmd_history_verify",
    }

    @pytest.mark.parametrize("command", ["migrate", "repair", "verify"])
    @pytest.mark.parametrize("outcome", ["ok", "fail"])
    @pytest.mark.parametrize("as_json", [False, True], ids=["human", "json"])
    def test_exit_code_matches_the_outcome_in_both_formats(
        self, db, monkeypatch, capsys, command, outcome, as_json
    ):
        payload = (self.OK if outcome == "ok" else self.FAIL)[command]
        monkeypatch.setattr(hc, self.PATCH[command], lambda *a, **k: payload)
        monkeypatch.setattr(hc, "get_current_version", lambda *a, **k: "1.2.0")

        rc = getattr(hc, self.COMMAND[command])(self._Args(db, as_json))
        capsys.readouterr()

        assert rc == (
            0 if outcome == "ok" else 1
        ), f"{command} --json={as_json} returned {rc} for a {outcome} result"

    @pytest.mark.parametrize("command", ["migrate", "repair", "verify"])
    def test_json_output_is_parseable_on_the_failure_path(
        self, db, monkeypatch, capsys, command
    ):
        """A non-zero exit must still emit JSON, not prose."""
        monkeypatch.setattr(hc, self.PATCH[command], lambda *a, **k: self.FAIL[command])
        monkeypatch.setattr(hc, "get_current_version", lambda *a, **k: "1.2.0")

        getattr(hc, self.COMMAND[command])(self._Args(db, True))
        out = capsys.readouterr().out
        # The command prints a header line before the payload; take the JSON body.
        body = out[out.index("{") :]
        assert json.loads(body)["errors"]


class TestMigrationRelabelsFabricatedVersions:
    """v1.3.0 must relabel exactly the fabricated rows and nothing else."""

    @staticmethod
    def _db_with_versions(path: Path, versions: list[str]) -> None:
        con = sqlite3.connect(str(path))
        con.execute(
            "CREATE TABLE scans (id TEXT PRIMARY KEY, jmo_version TEXT NOT NULL)"
        )
        con.executemany(
            "INSERT INTO scans (id, jmo_version) VALUES (?, ?)",
            [(str(i), v) for i, v in enumerate(versions)],
        )
        con.commit()
        con.close()

    def _apply(self, path: Path) -> None:
        from scripts.migrations.v1_3_0 import Migration_1_2_0_to_1_3_0

        con = sqlite3.connect(str(path))
        try:
            with con:
                Migration_1_2_0_to_1_3_0().migrate_up(con)
        finally:
            con.close()

    @staticmethod
    def _versions(path: Path) -> dict[str, int]:
        con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            return dict(
                con.execute(
                    "SELECT jmo_version, COUNT(*) FROM scans GROUP BY 1"
                ).fetchall()
            )
        finally:
            con.close()

    def test_relabels_the_fabricated_value(self, tmp_path):
        db = tmp_path / "h.db"
        self._db_with_versions(db, ["1.0.0"] * 5)
        self._apply(db)
        assert self._versions(db) == {UNKNOWN_VERSION: 5}

    def test_leaves_real_versions_alone(self, tmp_path):
        db = tmp_path / "h.db"
        self._db_with_versions(
            db, ["1.0.0", "1.0.0", "1.0.8", "1.1.0", UNKNOWN_VERSION]
        )
        self._apply(db)
        assert self._versions(db) == {UNKNOWN_VERSION: 3, "1.0.8": 1, "1.1.0": 1}

    def test_is_idempotent(self, tmp_path):
        db = tmp_path / "h.db"
        self._db_with_versions(db, ["1.0.0", "1.0.8"])
        self._apply(db)
        first = self._versions(db)
        self._apply(db)
        assert self._versions(db) == first

    def test_preserves_row_count(self, tmp_path):
        db = tmp_path / "h.db"
        self._db_with_versions(db, ["1.0.0"] * 17)
        self._apply(db)
        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        try:
            assert con.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 17
        finally:
            con.close()

    def test_no_scans_table_is_a_no_op(self, tmp_path):
        db = tmp_path / "h.db"
        sqlite3.connect(str(db)).close()
        self._apply(db)  # must not raise


class TestStoreProfileValidationIsNotDuplicatedInArgparse:
    """The CLI must not be a narrower gate than the validator behind it.

    `--profile` used to carry `choices=list(PROFILE_TOOLS)`, the tool registry
    only, while `store_scan()` validates against `get_known_profiles()` -- the
    registry PLUS any profile defined under `profiles:` in jmo.yml. A
    user-defined profile was therefore rejected by argparse before it could
    reach the validator that accepts it: the #721 enumeration class one layer
    above the SQL CHECK that #725 removed.

    Uses the real parser (`parse_args`), not a hand-built stand-in -- a mirror
    of a parser cannot notice what the parser rejects.
    """

    def test_real_parser_accepts_a_profile_outside_the_registry(
        self, tmp_path, monkeypatch
    ):
        import sys

        from scripts.cli.jmo import parse_args

        # parse_args() reads sys.argv rather than taking a list.
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "jmo",
                "history",
                "store",
                "--results-dir",
                str(tmp_path),
                "--profile",
                "custom-audit",
            ],
        )
        args = parse_args()
        assert args.profile == "custom-audit"

    def test_get_known_profiles_includes_jmo_yml_profiles(self, monkeypatch):
        from types import SimpleNamespace

        import scripts.core.config as config_module
        from scripts.core.history_db import get_known_profiles
        from scripts.core.tool_registry import PROFILE_TOOLS

        monkeypatch.setattr(
            config_module,
            "load_config",
            lambda *a, **k: SimpleNamespace(profiles={"custom-audit": {}}),
        )
        known = get_known_profiles()
        assert "custom-audit" in known
        assert set(PROFILE_TOOLS) <= known

    def test_unknown_profile_is_a_clean_error_not_a_traceback(self, tmp_path, capsys):
        results = _make_results(tmp_path / "res", None)

        class _Args:
            results_dir = str(results)
            profile = "definitely-not-a-profile"
            db = str(tmp_path / "h.db")
            commit = None
            branch = None
            tag = None

        rc = hc.cmd_history_store(_Args())
        err = capsys.readouterr().err

        assert rc == 1
        assert "Unknown profile" in err
        # store_scan()'s message names every known profile, so the traceback
        # adds noise and no information.
        assert "Traceback" not in err


class TestStoreAcceptsBothFindingsShapes:
    """`jmo history store` must accept every shape `store_scan()` accepts.

    `cmd_history_store` derives the tool list by calling `data.get("findings")`
    on the parsed artifact. That is only valid for the dict shape, so a
    bare-list `findings.json` -- which `store_scan()` handles explicitly --
    crashed the command with `AttributeError: 'list' object has no attribute
    'get'` and printed a traceback.
    """

    @pytest.mark.parametrize(
        "payload,label",
        [
            (b"[]", "empty list"),
            (b'[{"id": "a", "tool": {"name": "semgrep"}}]', "list of findings"),
            (b'{"meta": {}, "findings": []}', "dict, as the report phase writes"),
            (
                b'{"meta": {}, "findings": [{"id": "a", "tool": {"name": "trivy"}}]}',
                "dict with findings",
            ),
            (b'"neither"', "neither shape"),
        ],
    )
    def test_store_does_not_crash_on_any_shape(self, tmp_path, capsys, payload, label):
        results = _make_results(tmp_path / "res", None)
        (results / "summaries" / "findings.json").write_bytes(payload)

        class _Args:
            results_dir = str(results)
            profile = "balanced"
            db = str(tmp_path / "h.db")
            commit = None
            branch = None
            tag = None

        rc = hc.cmd_history_store(_Args())
        err = capsys.readouterr().err
        assert rc == 0, f"{label}: rc={rc} err={err[:200]}"
        assert "Traceback" not in err, label

    def test_tools_are_derived_from_a_list_shaped_artifact(self, tmp_path, capsys):
        results = _make_results(tmp_path / "res", None)
        (results / "summaries" / "findings.json").write_bytes(
            b'[{"id": "a", "tool": {"name": "semgrep"}}, {"id": "b", "tool": {"name": "trivy"}}]'
        )

        class _Args:
            results_dir = str(results)
            profile = "balanced"
            db = str(tmp_path / "h.db")
            commit = None
            branch = None
            tag = None

        assert hc.cmd_history_store(_Args()) == 0
        capsys.readouterr()
        assert json.loads(_stored_row(tmp_path / "h.db")["tools"]) == [
            "semgrep",
            "trivy",
        ]


def _results_with_findings(root: Path, entries: list[dict]) -> Path:
    """A results directory whose `findings.json` holds exactly `entries`."""
    results = _make_results(root, [])
    (results / "summaries" / "findings.json").write_bytes(
        json.dumps(entries).encode("utf-8")
    )
    return results


def _stored_fingerprints(db_path: Path) -> list[str]:
    con = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    try:
        return [r[0] for r in con.execute("SELECT fingerprint FROM findings")]
    finally:
        con.close()


class TestOneBadFindingDoesNotDiscardTheScan:
    """#901 -- a fingerprint collision aborted the entire transaction.

    `findings` has PRIMARY KEY (scan_id, fingerprint) and the fingerprint is
    the finding's id, so two findings that collide raised
    `sqlite3.IntegrityError` and the scan row plus every other finding in it
    went with them. Measured before the fix: 0 scans stored, both times.

    Both triggers are covered. The issue names only the falsy one, but a
    repeated non-empty id aborts identically and is reachable the same way --
    `jmo history store` accepts any findings.json. Fixing half of a defect
    leaves the defect.

    Every assertion checks what was stored, not that the call returned an id:
    `store_scan` returning a UUID is exactly what it did while writing nothing.
    """

    def test_two_findings_with_no_id_no_longer_discard_the_scan(self, tmp_path):
        results = _results_with_findings(
            tmp_path / "res",
            [{"tool": {"name": "semgrep"}}, {"tool": {"name": "trivy"}}],
        )
        store_scan(results, "balanced", ["semgrep"], db_path=tmp_path / "h.db")

        assert (
            _stored_row(tmp_path / "h.db") is not None
        ), "the scan row itself was discarded because two findings collided"
        assert _stored_fingerprints(tmp_path / "h.db") == []

    def test_two_findings_sharing_an_id_no_longer_discard_the_scan(self, tmp_path):
        results = _results_with_findings(
            tmp_path / "res",
            [
                {"id": "same", "tool": {"name": "semgrep"}},
                {"id": "same", "tool": {"name": "trivy"}},
            ],
        )
        store_scan(results, "balanced", ["semgrep"], db_path=tmp_path / "h.db")

        assert _stored_row(tmp_path / "h.db") is not None
        assert _stored_fingerprints(tmp_path / "h.db") == [
            "same"
        ], "the first of a colliding pair must survive"

    def test_good_findings_survive_alongside_bad_ones(self, tmp_path):
        """The point of the fix: losing one finding must not lose the rest."""
        results = _results_with_findings(
            tmp_path / "res",
            [
                {"id": "a", "tool": {"name": "semgrep"}},
                {"tool": {"name": "trivy"}},
                {"id": "a", "tool": {"name": "gosec"}},
                {"id": "b", "tool": {"name": "trivy"}},
            ],
        )
        store_scan(results, "balanced", ["semgrep"], db_path=tmp_path / "h.db")

        assert sorted(_stored_fingerprints(tmp_path / "h.db")) == ["a", "b"]

    def test_distinct_ids_are_all_stored(self, tmp_path):
        """Negative control: the skip must not be over-broad."""
        results = _results_with_findings(
            tmp_path / "res",
            [
                {"id": "a", "tool": {"name": "semgrep"}},
                {"id": "b", "tool": {"name": "trivy"}},
                {"id": "c", "tool": {"name": "gosec"}},
            ],
        )
        store_scan(results, "balanced", ["semgrep"], db_path=tmp_path / "h.db")

        assert sorted(_stored_fingerprints(tmp_path / "h.db")) == ["a", "b", "c"]

    def test_the_two_causes_are_reported_separately_and_by_tool(self, tmp_path, caplog):
        """A silent skip is the failure this campaign keeps meeting.

        WARNING, not INFO: `configure_scan_logging` floors the `scripts` logger
        at WARNING for a normal run, so INFO would be invisible in exactly the
        situation this exists to make visible.
        """
        import logging

        results = _results_with_findings(
            tmp_path / "res",
            [
                {"id": "a", "tool": {"name": "semgrep"}},
                {"tool": {"name": "trivy"}},
                {"id": "a", "tool": {"name": "gosec"}},
            ],
        )
        with caplog.at_level(logging.WARNING, logger="scripts.core.history_db"):
            store_scan(results, "balanced", ["semgrep"], db_path=tmp_path / "h.db")

        warnings = [
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        ]
        no_id = [m for m in warnings if "had no id" in m]
        dup = [m for m in warnings if "repeated an id" in m]
        assert len(no_id) == 1, f"missing the no-id report: {warnings}"
        assert len(dup) == 1, f"missing the duplicate-id report: {warnings}"
        # Attribution, not just a count: a number nobody can act on is not a
        # report. The two causes must name their own tool, not each other's.
        assert "trivy=1" in no_id[0]
        assert "gosec=1" in dup[0]

    def test_a_clean_scan_reports_nothing(self, tmp_path, caplog):
        """Negative control for the reporter, so it cannot fire unconditionally."""
        import logging

        results = _results_with_findings(
            tmp_path / "res", [{"id": "a", "tool": {"name": "semgrep"}}]
        )
        with caplog.at_level(logging.WARNING, logger="scripts.core.history_db"):
            store_scan(results, "balanced", ["semgrep"], db_path=tmp_path / "h.db")

        assert not [
            r for r in caplog.records if "NOT recorded" in r.getMessage()
        ], "a clean scan produced a data-loss warning"


def _results_with_duration(root: Path, duration: object) -> Path:
    """A results directory whose `.scan_metadata.json` carries `duration`.

    Written as a separate helper rather than a parameter on `_make_results`
    because the point of several tests below is a *malformed* value, and the
    metadata has to be built without the shaping `_make_results` applies.
    """
    results = _make_results(root, [])
    meta = json.loads((results / ".scan_metadata.json").read_bytes().decode("utf-8"))
    meta["duration_seconds"] = duration
    (results / ".scan_metadata.json").write_bytes(json.dumps(meta).encode("utf-8"))
    return results


class TestScanDurationReachesTheDatabase:
    """#981 -- `duration_seconds` was NULL on 2472 of 2472 rows.

    The column, the parameter and both readers all existed; no production
    caller ever passed a value, so `jmo history list`'s Duration column and
    `jmo history show`'s `Duration:` line were dead branches in the product.

    Every assertion here checks the value, not that the call succeeded. A test
    asserting `store_scan()` returns an id passes today against a column that
    is 100% NULL, which is the shape that let this survive.
    """

    def test_the_scans_own_duration_is_stored(self, tmp_path):
        results = _results_with_duration(tmp_path / "res", 1234.5)
        store_scan(results, "balanced", ["semgrep"], db_path=tmp_path / "h.db")
        assert _stored_row(tmp_path / "h.db")["duration_seconds"] == 1234.5

    def test_absent_metadata_stores_null_rather_than_a_guess(self, tmp_path):
        """`jmo history store` on a directory with no metadata has no duration.

        NULL renders as "N/A", which is honestly empty. The failure this issue
        is about is the opposite -- filling the column with the report phase's
        ~30 seconds, which reads as measured.
        """
        results = _make_results(tmp_path / "res", None)
        store_scan(results, "balanced", ["semgrep"], db_path=tmp_path / "h.db")
        assert _stored_row(tmp_path / "h.db")["duration_seconds"] is None

    def test_an_explicit_argument_wins_over_the_metadata(self, tmp_path):
        """The parameter stays usable for a caller with a better measurement."""
        results = _results_with_duration(tmp_path / "res", 1234.5)
        store_scan(
            results,
            "balanced",
            ["semgrep"],
            db_path=tmp_path / "h.db",
            duration_seconds=7.0,
        )
        assert _stored_row(tmp_path / "h.db")["duration_seconds"] == 7.0

    @pytest.mark.parametrize(
        "junk",
        [
            pytest.param(True, id="bool-True-would-store-as-1.0-seconds"),
            pytest.param("1234.5", id="string"),
            pytest.param(-1.0, id="negative"),
            pytest.param(None, id="explicit-null"),
            pytest.param([12], id="list"),
        ],
    )
    def test_a_malformed_duration_stores_null(self, tmp_path, junk):
        """`.scan_metadata.json` is a file on disk and can say anything.

        `True` is the one that matters: bool is an int subclass, so an
        unguarded isinstance check stores it as a 1.0-second scan.
        """
        results = _results_with_duration(tmp_path / "res", junk)
        store_scan(results, "balanced", ["semgrep"], db_path=tmp_path / "h.db")
        assert _stored_row(tmp_path / "h.db")["duration_seconds"] is None

    def test_history_list_renders_the_duration_it_stored(self, tmp_path, capsys):
        """The reader end: the Duration column had never printed a number.

        Goes through `cmd_history_list` rather than asserting on the row again,
        because "the column is populated" and "a user can see it" are different
        claims and only the second is what the issue is about.
        """
        results = _results_with_duration(tmp_path / "res", 1234.5)
        store_scan(results, "balanced", ["semgrep"], db_path=tmp_path / "h.db")

        class _Args:
            db = str(tmp_path / "h.db")
            limit = 10
            profile = None
            branch = None
            json = False

        assert hc.cmd_history_list(_Args()) == 0
        out = capsys.readouterr().out
        assert "1234.5" in out, f"duration is still not rendered:\n{out}"

    def test_history_list_still_says_na_when_there_is_no_duration(
        self, tmp_path, capsys
    ):
        """Negative control: without it, the test above passes on any output
        that happens to contain the number, including a findings count.

        Matched on the bare cell rather than the old fallback's prose "in N/A":
        `history list` now renders one Rich table instead of an unaligned line
        per scan, because the aligned branch it used to have could never run --
        `tabulate` is not a runtime dependency (#1011).
        """
        results = _make_results(tmp_path / "res", None)
        store_scan(results, "balanced", ["semgrep"], db_path=tmp_path / "h.db")

        class _Args:
            db = str(tmp_path / "h.db")
            limit = 10
            profile = None
            branch = None
            json = False

        assert hc.cmd_history_list(_Args()) == 0
        out = capsys.readouterr().out
        assert "Duration (s)" in out, f"the column header is missing:\n{out}"
        assert "N/A" in out, f"an absent duration is not marked N/A:\n{out}"
        assert "1234.5" not in out

    def test_history_show_prints_the_duration_line(self, tmp_path, capsys):
        """The second reader: `Duration:` is guarded on a truthy value, so it
        had never printed for any scan in the database's recorded history."""
        results = _results_with_duration(tmp_path / "res", 1234.5)
        scan_id = store_scan(
            results, "balanced", ["semgrep"], db_path=tmp_path / "h.db"
        )

        class _Args:
            db = str(tmp_path / "h.db")
            scan_id = None
            json = False

        _Args.scan_id = scan_id
        assert hc.cmd_history_show(_Args()) == 0
        out = capsys.readouterr().out
        assert "Duration:" in out and "1234.5" in out, out
