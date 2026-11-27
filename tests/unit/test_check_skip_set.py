"""scripts/dev/check_skip_set.py fails an e2e suite whose skips moved.

The scheduled e2e gate counted failures and errors and never skips, so a test
that began to skip read as a pass. A count is the wrong measure as well: on
main's run 45625803839 the Ubuntu suite skipped 10 ids, and this branch's
expected set also holds 10, yet they differ in two ids. These run the script
on reports in pytest-json-report's shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts.dev import check_skip_set

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_FILE = ROOT / "tests" / "e2e" / "expected-skips.yml"

A = "tests/e2e/test_a.py::test_one"
B = "tests/e2e/test_a.py::test_two[x]"
C = "tests/e2e/test_b.py::test_three"


def _report(tmp_path: Path, tests: dict[str, str], collectors=()) -> Path:
    doc = {
        "tests": [{"nodeid": n, "outcome": o} for n, o in tests.items()],
        "collectors": [{"nodeid": n, "outcome": "skipped"} for n in collectors]
        + [{"nodeid": "", "outcome": "passed"}],
    }
    path = tmp_path / "pytest-report.json"
    path.write_bytes(json.dumps(doc).encode())
    return path


def _expected(tmp_path: Path, ids: dict[str, str]) -> Path:
    path = tmp_path / "expected.yml"
    path.write_bytes(yaml.safe_dump({"ubuntu": ids, "macos": {}}).encode())
    return path


def _check(report: Path, expected: Path, capsys, suite: str = "ubuntu"):
    rc = check_skip_set.main(
        [str(report), "--expected", str(expected), "--suite", suite]
    )
    return rc, capsys.readouterr().out


def test_the_expected_skips_pass(tmp_path, capsys):
    report = _report(tmp_path, {A: "skipped", B: "passed", C: "failed"})
    rc, out = _check(report, _expected(tmp_path, {A: "Linux only"}), capsys)
    assert rc == 0, out
    assert "1 skipped, 1 expected, 0 unexpected" in out


def test_a_skip_the_file_does_not_list_fails(tmp_path, capsys):
    report = _report(tmp_path, {A: "skipped", B: "skipped"})
    rc, out = _check(report, _expected(tmp_path, {A: "Linux only"}), capsys)
    assert rc == 1
    assert f"::error::{B} skipped" in out


def test_a_listed_test_that_ran_fails(tmp_path, capsys):
    report = _report(tmp_path, {A: "skipped", B: "passed"})
    rc, out = _check(report, _expected(tmp_path, {A: "x", B: "no cluster"}), capsys)
    assert rc == 1
    assert f"::error::{B} is listed to skip (no cluster) and did not" in out


def test_a_listed_test_that_is_gone_fails(tmp_path, capsys):
    report = _report(tmp_path, {A: "skipped"})
    rc, out = _check(report, _expected(tmp_path, {A: "x", C: "renamed since"}), capsys)
    assert rc == 1
    assert C in out


def test_the_same_count_with_different_ids_fails(tmp_path, capsys):
    """One new skip and one fixed skip leave the count where it was."""
    report = _report(tmp_path, {A: "skipped", B: "skipped", C: "passed"})
    rc, out = _check(report, _expected(tmp_path, {A: "x", C: "y"}), capsys)
    assert rc == 1
    assert "2 skipped, 2 expected, 1 unexpected, 1 listed but not skipped" in out


def test_a_module_that_skipped_at_import_counts(tmp_path, capsys):
    """An importorskip names no test; its collector carries the skip."""
    module = "tests/e2e/test_dashboard_visual.py"
    report = _report(tmp_path, {A: "passed"}, collectors=[module])
    rc, out = _check(report, _expected(tmp_path, {}), capsys)
    assert rc == 1
    assert f"::error::{module} skipped" in out


def test_no_report_fails(tmp_path, capsys):
    rc, out = _check(tmp_path / "missing.json", _expected(tmp_path, {}), capsys)
    assert rc == 1
    assert "nothing ran" in out


def test_a_suite_the_file_lacks_fails(tmp_path, capsys):
    report = _report(tmp_path, {A: "passed"})
    with pytest.raises(SystemExit, match="'windows' is not a suite"):
        _check(report, _expected(tmp_path, {}), capsys, suite="windows")


def test_an_entry_without_a_reason_fails(tmp_path, capsys):
    report = _report(tmp_path, {A: "skipped"})
    with pytest.raises(SystemExit, match="no reason"):
        _check(report, _expected(tmp_path, {A: ""}), capsys)


def test_the_shipped_file_names_each_suite_the_workflow_checks():
    """Every suite the workflow passes is in the file, each id is a test of
    tests/e2e with a reason, and no id is listed twice."""
    workflow = (ROOT / ".github" / "workflows" / "scheduled.yml").read_text(
        encoding="utf-8"
    )
    checked = {
        line.split("--suite", 1)[1].split()[0]
        for line in workflow.splitlines()
        if "--expected tests/e2e/expected-skips.yml --suite" in line
    }
    assert checked == {"ubuntu", "macos"}, checked
    expected = yaml.safe_load(EXPECTED_FILE.read_bytes())
    assert set(expected) == checked
    for suite, ids in expected.items():
        assert ids, suite
        for node, why in ids.items():
            assert node.startswith("tests/e2e/test_") and "::" in node, node
            assert (ROOT / node.split("::")[0]).is_file(), node
            assert str(why).strip(), node
