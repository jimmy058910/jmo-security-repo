"""Sixteen of the 23 lockfile patterns JMo claims reach osv-scanner, offline (Phase 6, T4).

`osv_database.LOCKFILE_ECOSYSTEMS` is what JMo says osv-scanner reads. Until this test
nothing held a real lockfile of each format up to the real binary: a mapping that
named a file osv-scanner reads but JMo never hands over left that format with no
findings and nothing said. The scan reads the frozen database below, so it cannot
catch an ecosystem whose database JMo never fills.

Not covered, because sca-kitchen-sink has no such file: `npm-shrinkwrap.json`,
`Pipfile.lock`, `pdm.lock`, `pylock.toml`, `pubspec.lock`, `mix.lock` and `renv.lock`.
Pub, Hex and CRAN have no lockfile there at all, so those ecosystems have no
coverage here.

The inputs are QuackatronHQ/sca-kitchen-sink's lockfiles at a pinned commit, fetched by
`scripts/dev/fetch_answer_keys.py` and never committed (they are vulnerable on purpose,
so tracking them would raise Dependabot alerts on this repository). The answer key is
`tests/fixtures/osv-db-lockfiles`, a frozen database of synthetic advisories, one per
lockfile, built by `scripts/dev/build_lockfile_osv_db.py`, which also holds the
`EXPECTED_PAIRS` a scan must produce. The scan is JMo's own: `tool_loop.run_tools`, the
walk and the flags the product uses, with every proxy pointed at a closed port.

Two lockfiles of one ecosystem that pin the same package@version share an advisory's
hit, so the oracle is not "one pair per lockfile" but the exact set of (lockfile,
advisory) pairs: each format's own advisory, nothing from a format that does not pin
its package, and nothing else.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import PurePath

import pytest

from scripts.core.adapters.osv_scanner_adapter import OsvScannerAdapter
from scripts.core.scan_timings import State
from scripts.dev import build_lockfile_osv_db as oracle
from scripts.dev import fetch_answer_keys as keys
from tests.unit.test_osv_scanner_wiring import _real_scan

pytestmark = pytest.mark.requires_tools

FETCH_COMMAND = "python scripts/dev/fetch_answer_keys.py sca-kitchen-sink"


def lockfile_of(location: str, known: Iterable[str]) -> str:
    """The key-relative path of the lockfile a result's location names. osv-scanner's
    SARIF names it by absolute path; one that is none of `known` stays as it is, and
    so shows up in `grade` as a pair nobody expected."""
    for relative in known:
        if location == relative or location.endswith("/" + relative):
            return relative
    return location


def grade(observed: set[tuple[str, str]]) -> list[str]:
    """What is wrong with the (lockfile, advisory id) pairs a scan produced, one
    line each; empty when they are exactly `EXPECTED_PAIRS`. A format that yields
    no pair at all is named first, by its file name and ecosystem."""
    ecosystem = {a.lockfile: a.ecosystem for a in oracle.ADVISORIES}
    problems = []
    unreached = {lockfile for lockfile, _ in oracle.EXPECTED_PAIRS} - {
        lockfile for lockfile, _ in observed
    }
    if unreached:
        named = ", ".join(
            f"{PurePath(lockfile).name} ({ecosystem[lockfile]}, {lockfile})"
            for lockfile in sorted(unreached)
        )
        problems.append(f"no advisory reached osv-scanner from: {named}")
    missing = sorted(oracle.EXPECTED_PAIRS - observed)
    if missing:
        problems.append(f"expected and not found: {missing}")
    extra = sorted(observed - oracle.EXPECTED_PAIRS)
    if extra:
        problems.append(f"found and not expected: {extra}")
    return problems


@pytest.fixture(scope="module")
def kitchen_sink() -> dict[str, bytes]:
    """The pinned sca-kitchen-sink files, relative path to bytes; the test skips
    when the key is not fetched and fails when what is there is not the pin."""
    root = keys.sca_kitchen_sink_dir()
    files: dict[str, bytes] = {}
    for rel, expected in keys.SCA_KITCHEN_SINK_FILES.items():
        path = root / rel
        if not path.is_file():
            pytest.skip(
                f"answer key {keys.SCA_KITCHEN_SINK} is not fetched: run `{FETCH_COMMAND}`"
            )
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            pytest.fail(
                f"{path} is not the pinned file (sha256 {actual}, pinned {expected}): "
                f"run `{FETCH_COMMAND}`",
                pytrace=False,
            )
        files[rel] = data
    return files


@pytest.mark.timeout(300)
def test_every_lockfile_format_reaches_osv_scanner_offline(
    kitchen_sink, tmp_path, monkeypatch
) -> None:
    row, out, _ = _real_scan(tmp_path, monkeypatch, kitchen_sink, db=oracle.DEFAULT_OUT)

    # A run that did not read everything has no answer worth grading: a lockfile it
    # could not extract splits the run, and `row.detail` names it.
    assert row.state is State.RAN, f"{row.state.name} {row.label!r}: {row.detail}"
    # Nothing osv-scanner skipped without saying (#1472's class) counts as read.
    assert "partly audited" not in (row.detail or ""), row.detail
    report = out / "osv-scanner.json"
    assert report.is_file(), f"no report written; row detail: {row.detail}"

    observed = {
        (lockfile_of(finding.location["path"], kitchen_sink), finding.ruleId)
        for finding in OsvScannerAdapter().parse(report)
    }

    problems = grade(observed)
    assert not problems, "\n".join(problems)


@pytest.mark.timeout(300)
def test_a_name_osv_scanner_rejects_beside_a_deps_json_does_not_cost_its_findings(
    kitchen_sink, tmp_path, monkeypatch
) -> None:
    """osv-scanner reads `<name>.deps.json` and rejects a bare `deps.json` and
    `x.DEPS.JSON` (rc 127 for the whole run; measured on 2.6.0 and 2.7.0). The
    pattern is what keeps the rejected names from being handed over, so they sit
    beside two it reads and every advisory of the readable ones is still found."""
    manifest = kitchen_sink["csharp/API.deps.json"]
    files = {
        "a/API.deps.json": manifest,
        "b/deps.json": manifest,
        "c/.deps.json": manifest,
        "d/X.DEPS.JSON": manifest,
    }

    row, out, _ = _real_scan(tmp_path, monkeypatch, files, db=oracle.DEFAULT_OUT)

    assert row.state is State.RAN, f"{row.state.name} {row.label!r}: {row.detail}"
    observed = {
        (lockfile_of(finding.location["path"], files), finding.ruleId)
        for finding in OsvScannerAdapter().parse(out / "osv-scanner.json")
    }
    assert observed == {
        ("a/API.deps.json", "JMO-TEST-2026-0116"),
        ("c/.deps.json", "JMO-TEST-2026-0116"),
    }
