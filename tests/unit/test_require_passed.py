"""`scripts/dev/require_passed.py`: a pytest run that passed nothing fails its step.

pytest exits 0 for a run of skips, so a job whose every test skips reads green:
the juice-shop smoke job did, 22 or 24 skipped and 0 passed every night for
months (#1349). The workflows run this after a pytest step that writes
`--junitxml`.
"""

from __future__ import annotations

from pathlib import Path

from scripts.dev import require_passed


def _junit(path: Path, *, tests: int, skipped: int, failures: int = 0, errors: int = 0):
    """A report as pytest writes one: a testcase each, its outcome a child."""
    cases = (
        ['<testcase name="s"><skipped type="pytest.skip" message="why"/></testcase>']
        * skipped
        + ['<testcase name="f"><failure message="no"/></testcase>'] * failures
        + ['<testcase name="e"><error message="no"/></testcase>'] * errors
    )
    cases += ['<testcase name="p"/>'] * (tests - len(cases))
    path.write_bytes(
        (
            '<?xml version="1.0" encoding="utf-8"?><testsuites>'
            f'<testsuite name="pytest" tests="{tests}" skipped="{skipped}" '
            f'failures="{failures}" errors="{errors}">{"".join(cases)}</testsuite></testsuites>'
        ).encode()
    )
    return path


def test_a_run_of_skips_fails(tmp_path, capsys) -> None:
    report = _junit(tmp_path / "j.xml", tests=24, skipped=24)
    assert require_passed.main([str(report)]) == 1
    assert "0 passed" in capsys.readouterr().out


def test_a_run_that_passed_one_test_passes(tmp_path) -> None:
    report = _junit(tmp_path / "j.xml", tests=24, skipped=23)
    assert require_passed.main([str(report)]) == 0


def test_a_floor_counts_passed_tests_not_collected_ones(tmp_path) -> None:
    report = _junit(tmp_path / "j.xml", tests=40, skipped=5, failures=1, errors=1)
    assert require_passed.main([str(report), "--min", "33"]) == 0  # 40 - 7 = 33
    assert require_passed.main([str(report), "--min", "34"]) == 1


def test_a_missing_report_fails(tmp_path, capsys) -> None:
    # No report is no evidence: never a pass.
    assert require_passed.main([str(tmp_path / "absent.xml")]) == 1
    assert "no pytest report" in capsys.readouterr().out


def test_a_bare_testsuite_root_is_read_too(tmp_path) -> None:
    report = tmp_path / "j.xml"
    report.write_bytes(
        b'<testsuite tests="3" skipped="1" failures="0" errors="0">'
        b'<testcase name="a"/><testcase name="b"/>'
        b'<testcase name="c"><skipped type="pytest.skip"/></testcase></testsuite>'
    )
    assert require_passed.main([str(report), "--min", "2"]) == 0


def test_a_skip_fails_where_none_is_allowed(tmp_path, capsys) -> None:
    # After the answer keys are fetched, a test that skips for want of its key
    # graded nothing: windows-opengrep's step fails on any skip for that reason.
    report = _junit(tmp_path / "j.xml", tests=20, skipped=1)
    assert require_passed.main([str(report)]) == 0
    assert require_passed.main([str(report), "--max-skipped", "0"]) == 1
    assert "1 skipped" in capsys.readouterr().out


def test_an_expected_failure_is_not_a_skip(tmp_path) -> None:
    # junit has no xfail: pytest writes one as <skipped type="pytest.xfail">,
    # and the suite's `skipped` total counts it. vibeproof's key carries three
    # (the classes the native pack does not cover, recorded as such).
    report = tmp_path / "j.xml"
    report.write_bytes(
        b'<testsuites><testsuite tests="3" skipped="2" failures="0" errors="0">'
        b'<testcase name="a"/>'
        b'<testcase name="b"><skipped type="pytest.xfail" message="known"/></testcase>'
        b'<testcase name="c"><skipped type="pytest.xfail" message="known"/></testcase>'
        b"</testsuite></testsuites>"
    )
    assert require_passed.main([str(report), "--max-skipped", "0"]) == 0
    assert require_passed.main([str(report), "--min", "2"]) == 1  # xfails pass nothing
