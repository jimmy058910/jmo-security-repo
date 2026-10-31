#!/usr/bin/env python3
"""A report holds only what THIS scan's tools produced (#1371, #1432).

The report phase read every `<tool>.json` in a target's folder. Two ways that
put a finding in a report that its scan did not produce:

- **#1371**: a results directory reused from an earlier scan keeps that scan's
  outputs, so a scan of `--tools shellcheck` into it reported the earlier scan's
  trivy findings.
- **#1432**: a tool that fails can leave output behind (osv-scanner, rc 130 on
  an invalid `osv-scanner.toml`, wrote its 4 findings first), so the log said
  the tool "did NOT contribute findings" while `findings.json` held them.

The scan now records one row per requested tool in each target's
`scan-timings.json`, and the report reads a tool's output only when its row
says the tool ran (or a run of it worked, #1369's `kept_findings`).

Each test builds a results directory in the shape `jmo scan` writes: the rows
through the module's own writer beside the `<tool>.json` files, and the
`.scan_metadata.json` the report phase reads for the history row. No scanner is
needed, so these run on every CI shard; a test that passed when its scanner was
absent would be the silent-failure class this change removes.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from scripts.cli import jmo
from scripts.core import normalize_and_report as nr
from scripts.core.scan_timings import Reason, State, ToolRun, write_scan_timings

TARGET = "individual-repos/proj"


def _trivy(n: int) -> bytes:
    """A trivy report of `n` vulnerabilities, in the shape its adapter reads."""
    return json.dumps(
        {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": f"CVE-2026-000{i}",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.15",
                            "Severity": "HIGH",
                            "Title": f"flaw {i}",
                        }
                        for i in range(n)
                    ],
                }
            ]
        }
    ).encode()


def _shellcheck(n: int) -> bytes:
    """A shellcheck report of `n` findings."""
    return json.dumps(
        [
            {
                "file": "run.sh",
                "line": 3 + i,
                "endLine": 3 + i,
                "column": 1,
                "endColumn": 5,
                "level": "warning",
                "code": 2086,
                "message": f"Double quote to prevent globbing {i}",
            }
            for i in range(n)
        ]
    ).encode()


def _osv(n: int) -> bytes:
    """An osv-scanner SARIF report of `n` findings."""
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "osv-scanner",
                            "rules": [{"id": "JMO-TEST-2026-0001"}],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "JMO-TEST-2026-0001",
                            "ruleIndex": 0,
                            "message": {
                                "text": f"Package 'left-pad@1.0.{i}' is vulnerable "
                                "to 'JMO-TEST-2026-0001'."
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "package-lock.json"}
                                    }
                                }
                            ],
                        }
                        for i in range(n)
                    ],
                }
            ],
        }
    ).encode()


def _ran(tool: str) -> ToolRun:
    return ToolRun(tool, State.RAN)


def _scan_wrote(
    results: Path,
    rows: dict[str, ToolRun],
    outputs: dict[str, bytes],
    *,
    target: str = TARGET,
    timings: bool = True,
) -> Path:
    """A target's folder as `jmo scan` leaves it: the tool outputs, the rows in
    `scan-timings.json`, and the run record the report phase reads for history.
    `timings=False` is a folder `jmo scan` did not write."""
    out = results / target
    out.mkdir(parents=True, exist_ok=True)
    for name, data in outputs.items():
        (out / name).write_bytes(data)
    if timings:
        write_scan_timings(
            out, rows, target=out.name, target_type="repo", wall_seconds=1.0
        )
    (results / ".scan_metadata.json").write_bytes(
        json.dumps(
            {
                "tools": list(rows),
                "tool_runs": [
                    {"target": out.name, "target_type": "repo", **row.to_dict()}
                    for row in rows.values()
                ],
                "repo_paths": [],
            }
        ).encode()
    )
    return out


@pytest.fixture
def report(tmp_path: Path, monkeypatch):
    """`jmo report` over a results directory, with the scan's history storage.

    Returns what a user reads afterwards: `findings.json` and the history
    database's findings.
    """
    results = tmp_path / "results"
    (tmp_path / "jmo.yml").write_bytes(b"outputs: [json]\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    def run() -> SimpleNamespace:
        argv = ["jmo", "report", "--results-dir", str(results)]
        with patch.object(sys, "argv", argv):
            args = jmo.parse_args()
        # The two attributes `jmo scan` hands its report phase.
        args.store_history = True
        args.history_db = str(tmp_path / "history.db")
        code = jmo.cmd_report(args)
        document = json.loads((results / "summaries" / "findings.json").read_bytes())
        with closing(sqlite3.connect(tmp_path / "history.db")) as conn:
            stored = dict(
                conn.execute("SELECT tool, COUNT(*) FROM findings GROUP BY 1")
            )
        return SimpleNamespace(
            code=code,
            by_tool=_by_tool(document["findings"]),
            stored=stored,
        )

    return SimpleNamespace(results=results, run=run)


def _by_tool(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["tool"]["name"]] = counts.get(f["tool"]["name"], 0) + 1
    return counts


def _withheld(caplog) -> list[str]:
    """What the report said at WARNING about an output it did not read."""
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == nr.logger.name and r.levelno >= logging.WARNING
    ]


class TestTheReportReadsThisScansRows:
    def test_a_tool_this_scan_did_not_request_is_not_reported(self, report, caplog):
        """#1371: the earlier scan's trivy.json (4 findings) is still in the
        folder; this scan asked for shellcheck only."""
        _scan_wrote(
            report.results,
            {"shellcheck": _ran("shellcheck")},
            {"shellcheck.json": _shellcheck(2), "trivy.json": _trivy(4)},
        )

        with caplog.at_level(logging.WARNING):
            result = report.run()

        assert result.by_tool == {"shellcheck": 2}
        assert result.stored == {"shellcheck": 2}
        # Said, naming the tool whose file was left out.
        said = _withheld(caplog)
        assert any("trivy" in m for m in said), said
        # And only that one: a healthy tool's file is not a warning.
        assert not any("shellcheck" in m for m in said), said

    def test_a_failed_row_with_no_kept_findings_is_not_reported(self, report, caplog):
        """#1432: osv-scanner exited 130 on a bad osv-scanner.toml, wrote its 4
        findings first, and no run of it worked."""
        failed = ToolRun(
            "osv-scanner",
            State.FAILED,
            Reason.EXIT_CODE,
            exit_code=130,
            detail="invalid osv-scanner.toml",
        )
        _scan_wrote(
            report.results,
            {"osv-scanner": failed, "shellcheck": _ran("shellcheck")},
            {"osv-scanner.json": _osv(4), "shellcheck.json": _shellcheck(1)},
        )

        with caplog.at_level(logging.WARNING):
            result = report.run()

        assert result.by_tool == {"shellcheck": 1}
        assert result.stored == {"shellcheck": 1}
        # The report's account names the row: the tool and why it is not here.
        said = [m for m in _withheld(caplog) if "osv-scanner" in m]
        assert said, _withheld(caplog)
        assert failed.label in said[0], said[0]

    def test_a_failed_row_keeps_what_its_working_runs_found(self, report, caplog):
        """#1369: one lockfile osv-scanner could not read beside a readable one
        fails the row, and the readable one's findings are in the report."""
        partial = ToolRun(
            "osv-scanner",
            State.FAILED,
            Reason.EXIT_CODE,
            exit_code=127,
            detail="sub/package-lock.json: Return code 127 not in (0, 1)",
            kept_findings=2,
        )
        _scan_wrote(
            report.results, {"osv-scanner": partial}, {"osv-scanner.json": _osv(2)}
        )

        with caplog.at_level(logging.WARNING):
            result = report.run()

        assert result.by_tool == {"osv-scanner": 2}
        assert result.stored == {"osv-scanner": 2}
        assert not _withheld(caplog), _withheld(caplog)

    def test_a_results_dir_without_timings_reads_everything(self, report, caplog):
        """Output `jmo scan` did not write (`jmo report` on a directory from
        elsewhere) has no rows to filter by: every `<tool>.json` is read."""
        _scan_wrote(
            report.results,
            {},
            {"shellcheck.json": _shellcheck(2), "trivy.json": _trivy(4)},
            timings=False,
        )

        with caplog.at_level(logging.WARNING):
            result = report.run()

        assert result.by_tool == {"shellcheck": 2, "trivy": 4}
        assert not _withheld(caplog), _withheld(caplog)


def _names(loaded: list[Path]) -> list[str]:
    return sorted(p.name for p in loaded)


def _loaded(monkeypatch) -> list[Path]:
    """Record the files `gather_results` hands an adapter, and parse nothing.
    Every tool name has an adapter here, so a file is read or not by its row
    alone."""
    loaded: list[Path] = []

    def record(_plugin_class, path, _profiling=False):
        loaded.append(path)
        return []

    monkeypatch.setattr(nr, "_safe_load_plugin", record)
    monkeypatch.setattr(
        nr, "get_plugin_registry", lambda: SimpleNamespace(get=lambda _name: object)
    )
    return loaded


class TestWhichOutputsAreRead:
    def test_a_tool_is_matched_by_its_name_before_the_first_dot(
        self, tmp_path, monkeypatch
    ):
        """`yara.json` and `yara-x.json` are two tools. A `yara*` prefix match
        read the second as the first's."""
        _scan_wrote(
            tmp_path,
            {"yara": _ran("yara")},
            {"yara.json": b"[]", "yara-x.json": b"[]"},
        )
        loaded = _loaded(monkeypatch)

        nr.gather_results(tmp_path)

        assert _names(loaded) == ["yara.json"]

    @pytest.mark.parametrize("extra", ["trivy.git.json", "trivy.part2.json"])
    @pytest.mark.parametrize(
        ("trivy_row", "reads_trivy"),
        [
            (ToolRun("trivy", State.RAN), True),
            (ToolRun("trivy", State.FAILED, Reason.EXIT_CODE), False),
        ],
        ids=["ran", "failed-nothing-kept"],
    )
    def test_every_file_of_a_tool_follows_its_row(
        self, tmp_path, monkeypatch, extra, trivy_row, reads_trivy
    ):
        """A tool's second invocation writes `<tool>.git.json`, a fallback
        `<tool>.part<N>.json`: all are the tool's, so all follow its row."""
        _scan_wrote(
            tmp_path,
            {"trivy": trivy_row, "shellcheck": _ran("shellcheck")},
            {"trivy.json": b"{}", extra: b"{}", "shellcheck.json": b"[]"},
        )
        loaded = _loaded(monkeypatch)

        nr.gather_results(tmp_path)

        expected = ["shellcheck.json"] + (["trivy.json", extra] if reads_trivy else [])
        assert _names(loaded) == sorted(expected)

    @pytest.mark.parametrize(
        "row",
        [
            ToolRun("trivy", State.SKIPPED, Reason.NOT_INSTALLED),
            ToolRun("trivy", State.FAILED, Reason.TIMED_OUT),
        ],
        ids=["skipped", "failed-nothing-kept"],
    )
    def test_a_row_that_did_not_run_and_kept_nothing_is_not_read(
        self, tmp_path, monkeypatch, row
    ):
        _scan_wrote(tmp_path, {"trivy": row}, {"trivy.json": b'{"Results": []}'})
        loaded = _loaded(monkeypatch)

        nr.gather_results(tmp_path)

        assert _names(loaded) == []

    def test_kept_findings_is_a_count_so_zero_is_kept(self, tmp_path, monkeypatch):
        """A failed row whose working run found nothing has `kept_findings=0`,
        which is a run that worked: its output is read, as #1369 decided."""
        zero = ToolRun("trivy", State.FAILED, Reason.EXIT_CODE, kept_findings=0)
        _scan_wrote(tmp_path, {"trivy": zero}, {"trivy.json": b'{"Results": []}'})
        loaded = _loaded(monkeypatch)

        nr.gather_results(tmp_path)

        assert _names(loaded) == ["trivy.json"]

    def test_each_target_is_filtered_by_its_own_rows(self, tmp_path, monkeypatch):
        """One target the scan wrote, one it did not: the second reads all."""
        _scan_wrote(
            tmp_path,
            {"shellcheck": _ran("shellcheck")},
            {"shellcheck.json": b"[]", "trivy.json": b"{}"},
            target="individual-repos/scanned",
        )
        _scan_wrote(
            tmp_path,
            {},
            {"shellcheck.json": b"[]", "trivy.json": b"{}"},
            target="individual-repos/outside",
            timings=False,
        )
        loaded = _loaded(monkeypatch)

        nr.gather_results(tmp_path)

        assert sorted((p.parent.name, p.name) for p in loaded) == [
            ("outside", "shellcheck.json"),
            ("outside", "trivy.json"),
            ("scanned", "shellcheck.json"),
        ]

    def test_an_unreadable_timings_file_reads_everything_and_says_so(
        self, tmp_path, monkeypatch, caplog
    ):
        """A scan-timings.json that is there and not JSON is not a scan that
        listed no tools: nothing can be filtered by it, and the report must
        not drop a whole target's findings on the strength of it."""
        out = _scan_wrote(tmp_path, {}, {"trivy.json": b"{}"}, timings=False)
        (out / "scan-timings.json").write_bytes(b"{not json")
        loaded = _loaded(monkeypatch)

        with caplog.at_level(logging.WARNING):
            nr.gather_results(tmp_path)

        assert _names(loaded) == ["trivy.json"]
        assert any("scan-timings.json" in m for m in _withheld(caplog)), _withheld(
            caplog
        )


class TestDiagnosticsFilterTheSameWay:
    def test_a_withheld_output_contributes_no_diagnostics(self, tmp_path):
        """`collect_tool_diagnostics` reads the same files `gather_results` does.
        opengrep's error channel on an output the report does not read would
        name files of a tool this scan did not run."""
        broken = json.dumps(
            {
                "results": [],
                "errors": [{"path": "/r/broken/a.py", "message": "Syntax error"}],
            }
        ).encode()
        _scan_wrote(
            tmp_path,
            {"shellcheck": _ran("shellcheck")},
            {"shellcheck.json": b"[]", "opengrep.json": broken},
        )
        with_rows = nr.collect_tool_diagnostics(tmp_path)

        # The same folder as `jmo scan` did not write it: opengrep's is read.
        (tmp_path / TARGET / "scan-timings.json").unlink()
        without_rows = nr.collect_tool_diagnostics(tmp_path)

        assert [d.tool for d in without_rows] == ["opengrep"], "negative control"
        assert with_rows == []


def _v1_timings(tools: list[dict]) -> bytes:
    """A `scan-timings.json` exactly as JMo v1.1.1 wrote it (`schema_version`
    2): a row is `ToolResult.to_dict()`, with `status` and no `state`. Written
    out literally, because `write_scan_timings` can only write today's shape."""
    return json.dumps(
        {
            "schema_version": 2,
            "target": "proj",
            "target_type": "repo",
            "wall_seconds": 2.4,
            "outcome": "completed",
            "error": None,
            "tools": tools,
        },
        indent=2,
    ).encode()


_V1_SHELLCHECK_ROW = {
    "tool": "shellcheck",
    "status": "success",
    "returncode": 1,
    "attempts": 1,
    "duration": 0.41,
    "output_file": "results/individual-repos/proj/shellcheck.json",
    "error_message": None,
    "timed_out": False,
}


class TestAResultsDirWrittenByV1x:
    """A row of v1.x names no `state`, so none parses (`KeyError: 'state'`).
    Read as v4 rows they are all "a tool this scan did not run", and a report
    over a v1.x directory said so for every tool and held 0 findings."""

    def test_a_v1x_directory_is_read_whole_and_says_so_once(self, tmp_path, caplog):
        out = _scan_wrote(
            tmp_path, {}, {"shellcheck.json": _shellcheck(1)}, timings=False
        )
        (out / "scan-timings.json").write_bytes(_v1_timings([_V1_SHELLCHECK_ROW]))

        with caplog.at_level(logging.WARNING):
            findings = nr.gather_results(tmp_path)

        assert [f["tool"]["name"] for f in findings] == ["shellcheck"]
        said = _withheld(caplog)
        assert len(said) == 1, said
        assert "v1.x" in said[0], said[0]
        assert "schema_version 2" in said[0], said[0]

    def test_a_directory_with_no_schema_version_is_read_whole_too(
        self, tmp_path, caplog
    ):
        """No release wrote one without a version (v1.0.x wrote no
        `scan-timings.json`, v1.1.x wrote 2), but one that lacks it, edited by
        hand, say, is read whole like v1.x's rather than withheld."""
        out = _scan_wrote(
            tmp_path, {}, {"shellcheck.json": _shellcheck(1)}, timings=False
        )
        document = json.loads(_v1_timings([_V1_SHELLCHECK_ROW]))
        del document["schema_version"]
        (out / "scan-timings.json").write_bytes(json.dumps(document).encode())

        with caplog.at_level(logging.WARNING):
            findings = nr.gather_results(tmp_path)

        assert len(findings) == 1
        assert len(_withheld(caplog)) == 1, _withheld(caplog)

    def test_a_v1x_scan_that_ran_no_tool_withholds_everything(self, tmp_path, caplog):
        """`failed-before-tools` wrote `tools: []`. It has no rows to read the
        folder by, and a file in it is an earlier scan's, as for a v4 document."""
        out = _scan_wrote(
            tmp_path, {}, {"shellcheck.json": _shellcheck(1)}, timings=False
        )
        document = json.loads(_v1_timings([]))
        document["outcome"] = "failed-before-tools"
        (out / "scan-timings.json").write_bytes(json.dumps(document).encode())

        with caplog.at_level(logging.WARNING):
            findings = nr.gather_results(tmp_path)

        assert findings == []
        assert any("shellcheck" in m for m in _withheld(caplog)), _withheld(caplog)

    def test_a_v3_document_is_still_read_by_its_rows(self, tmp_path, caplog):
        """Version 3 is the first whose rows name a `state` (without v4's
        `kept_findings`). It is read by its rows, as today's: only the output
        of a tool it lists is reported."""
        out = _scan_wrote(
            tmp_path,
            {},
            {"shellcheck.json": _shellcheck(1), "trivy.json": _trivy(2)},
            timings=False,
        )
        row = {
            "tool": "shellcheck",
            "state": "ran",
            "reason": None,
            "seconds": 0.4,
            "exit_code": 1,
            "attempts": 1,
            "invocations": 1,
            "detail": None,
        }
        document = json.loads(_v1_timings([row]))
        document["schema_version"] = 3
        (out / "scan-timings.json").write_bytes(json.dumps(document).encode())

        with caplog.at_level(logging.WARNING):
            findings = nr.gather_results(tmp_path)

        assert [f["tool"]["name"] for f in findings] == ["shellcheck"]
        said = _withheld(caplog)
        assert len(said) == 1 and "trivy" in said[0], said

    @pytest.mark.parametrize("version", [True, False])
    def test_a_bool_schema_version_is_not_taken_for_v1x(
        self, tmp_path, caplog, version
    ):
        """No JMo wrote a bool version, but Python's `True < 3` (and `False < 3`)
        holds, so it read as v1.x and the folder was read whole: the earlier
        scan's trivy.json was reported again (#1371). A bool is read by its rows,
        like any other version this reader does not recognise."""
        out = _scan_wrote(
            tmp_path,
            {},
            {"shellcheck.json": _shellcheck(1), "trivy.json": _trivy(2)},
            timings=False,
        )
        row = {
            "tool": "shellcheck",
            "state": "ran",
            "reason": None,
            "seconds": 0.4,
            "exit_code": 1,
            "attempts": 1,
            "invocations": 1,
            "detail": None,
        }
        document = json.loads(_v1_timings([row]))
        document["schema_version"] = version
        (out / "scan-timings.json").write_bytes(json.dumps(document).encode())

        with caplog.at_level(logging.WARNING):
            findings = nr.gather_results(tmp_path)

        assert [f["tool"]["name"] for f in findings] == ["shellcheck"]
        said = _withheld(caplog)
        assert len(said) == 1 and "trivy" in said[0], said
