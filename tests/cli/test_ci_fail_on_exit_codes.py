"""`jmo ci --fail-on`, run as a user runs it: the real CLI in a subprocess.

A CI pipeline reads only the exit code, so this is the contract a user's build
depends on: 1 when a finding reaches the threshold, 0 when none does, 2 when
nothing was scanned. Every other `--fail-on` test calls `cmd_ci` or
`cmd_report` in-process with arguments built by hand; the e2e U12 case runs
the CLI but asserts behind an `if` and needs scanners, so it runs only in the
scheduled job.

jmo-native is built in (it runs as `python -m scripts.core.native_checks`),
so these scan for real on every PR shard with no scanner installed. Its sample
is the one its golden fixture records: 7 HIGH and 1 LOW, no CRITICAL
(tests/fixtures/golden/jmo_native/).
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path

import pytest

from tests.conftest import scanner_states

SAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "samples" / "native"
EXPECTED = {"HIGH": 7, "LOW": 1}


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """The report downloads the CISA KEV catalogue even when no finding names
    a CVE; a proxy on a closed port makes that fail at once, so the test needs
    no network and the report is written all the same (measured)."""
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def ci(jmo_runner, tmp_path):
    """Run `jmo ci` with jmo-native on a copy of its sample; return the exit
    code and the severities the scan found."""

    def _run(*extra: str) -> tuple[int, Counter, str]:
        repo = tmp_path / "app"
        shutil.copytree(SAMPLE, repo)
        results = tmp_path / "results"
        done = jmo_runner(
            [
                "ci",
                "--repo",
                str(repo),
                "--tools",
                "jmo-native",
                "--results-dir",
                str(results),
                "--history-db",
                str(tmp_path / "history.db"),
                *extra,
            ],
            timeout=120,
        )
        # The exit code means something only if the scanner ran and found
        # what its sample holds: a scan of nothing also exits 0.
        assert scanner_states(results) == {"jmo-native": "ran"}, done.stderr[-2000:]
        findings = json.loads((results / "summaries" / "findings.json").read_bytes())
        found = Counter(f["severity"] for f in findings["findings"])
        assert found == EXPECTED, done.stderr[-2000:]
        return done.returncode, found, done.stderr

    return _run


@pytest.mark.parametrize(
    "threshold,expected_rc",
    [
        ("HIGH", 1),  # 7 HIGH reach it
        ("LOW", 1),  # every finding reaches it
        ("CRITICAL", 0),  # none reaches it
    ],
)
def test_the_exit_code_says_whether_a_finding_reached_the_threshold(
    ci, threshold: str, expected_rc: int
):
    rc, _found, stderr = ci("--fail-on", threshold)
    assert rc == expected_rc, stderr[-2000:]


def test_without_fail_on_findings_do_not_fail_the_build(ci):
    rc, found, stderr = ci()
    assert found["HIGH"] > 0
    assert rc == 0, stderr[-2000:]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "#1718, jmo ci exits 1, not 2, when every target was rejected: "
        "since #1708 jmo ci skips its report when the scan wrote nothing, and "
        "the 2 came from that report refusing the missing results directory; "
        "the scan's own 1 is the code for findings at the threshold"
    ),
)
def test_a_repository_that_does_not_exist_exits_2(jmo_runner, tmp_path):
    """Nothing was scanned, so neither 0 ("clean") nor 1 ("findings") is true.

    Measured: 2 before #1708 (22fa69c2), 1 after it.
    """
    done = jmo_runner(
        [
            "ci",
            "--repo",
            str(tmp_path / "missing"),
            "--tools",
            "jmo-native",
            "--fail-on",
            "HIGH",
            "--results-dir",
            str(tmp_path / "results"),
            "--history-db",
            str(tmp_path / "history.db"),
        ],
        timeout=120,
    )
    assert done.returncode == 2, done.stderr[-2000:]
    assert "path does not exist" in done.stderr


def test_report_on_a_directory_with_no_scan_in_it_exits_2(jmo_runner, tmp_path):
    """Decided 2026-11-18 (#1670): an empty results directory is refused."""
    empty = tmp_path / "empty"
    empty.mkdir()
    done = jmo_runner(["report", str(empty), "--fail-on", "HIGH"], timeout=120)
    assert done.returncode == 2, done.stderr[-2000:]
    assert list(empty.iterdir()) == [], "a refused report wrote into the directory"
