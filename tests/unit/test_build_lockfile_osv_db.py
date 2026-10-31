"""scripts/dev/build_lockfile_osv_db.py: the answer key of the lockfile-format oracle.

`tests/integration/test_lockfile_formats.py` runs the real osv-scanner over sca-kitchen-sink's
lockfiles against `tests/fixtures/osv-db-lockfiles`. These tests need neither: they hold
the answer key to what it claims to be (one synthetic advisory per lockfile, exactly one
version each, zips that rebuild byte for byte) and hold the oracle's grading to naming
the format that yielded nothing.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from scripts.core.osv_database import ECOSYSTEMS, ecosystem_of
from scripts.dev import build_lockfile_osv_db as build
from scripts.dev.fetch_answer_keys import SCA_KITCHEN_SINK_FILES
from tests.integration.test_lockfile_formats import grade

COMMITTED = build.DEFAULT_OUT


def _members(path: Path) -> dict[str, dict]:
    with zipfile.ZipFile(path) as archive:
        return {name: json.loads(archive.read(name)) for name in archive.namelist()}


def _lockfile_name(relative: str) -> str:
    return PurePosixPath(relative).name


# --- the table -------------------------------------------------------------------


def test_the_ids_run_from_0101_in_order() -> None:
    assert [a.id for a in build.ADVISORIES] == [
        f"JMO-TEST-2026-{number:04d}"
        for number in range(101, 101 + len(build.ADVISORIES))
    ]


def test_each_advisory_is_in_the_ecosystem_its_lockfile_is_matched_in() -> None:
    """The ecosystem is the bucket osv-scanner reads the database from, so an
    advisory filed under another is one that lockfile can never find."""
    for advisory in build.ADVISORIES:
        assert advisory.ecosystem in ECOSYSTEMS, advisory
        assert ecosystem_of(_lockfile_name(advisory.lockfile)) == advisory.ecosystem, (
            advisory
        )


def test_every_fetched_file_osv_database_reads_has_exactly_one_advisory_of_its_own() -> (
    None
):
    """Add a lockfile pattern JMo claims for a file the key already fetches and this
    fails: that format has no advisory, so the oracle would not see it fail."""
    read = {
        relative
        for relative in SCA_KITCHEN_SINK_FILES
        if ecosystem_of(_lockfile_name(relative)) is not None
    }
    picked = [a.lockfile for a in build.ADVISORIES]

    assert sorted(picked) == sorted(read)


def test_the_advisories_name_the_package_they_are_about_once_each() -> None:
    packages = [(a.ecosystem, a.package, a.version) for a in build.ADVISORIES]

    assert len(set(packages)) == len(packages)


# --- the expected pairs ----------------------------------------------------------


def test_every_lockfile_has_its_own_advisory_in_the_expected_pairs() -> None:
    for advisory in build.ADVISORIES:
        assert (advisory.lockfile, advisory.id) in build.EXPECTED_PAIRS, advisory


def test_a_pair_is_a_fetched_lockfile_and_an_advisory_of_its_own_ecosystem() -> None:
    """A sibling yields an advisory only through the same package@version, which
    is only possible inside one ecosystem."""
    ecosystem = {a.id: a.ecosystem for a in build.ADVISORIES}
    for lockfile, advisory_id in build.EXPECTED_PAIRS:
        assert lockfile in SCA_KITCHEN_SINK_FILES, lockfile
        assert advisory_id in ecosystem, advisory_id
        assert ecosystem_of(_lockfile_name(lockfile)) == ecosystem[advisory_id], (
            lockfile,
            advisory_id,
        )


def test_the_expected_pairs_are_the_siblings_that_pin_the_same_package() -> None:
    """The only lockfiles that find another's advisory (read off the lockfile text):
    three npm lockfiles hold identical packages, pom.xml's are all in gradle.lockfile,
    and packages.config's are all in packages.lock.json."""
    shared = {
        "JMO-TEST-2026-0102": {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"},
        "JMO-TEST-2026-0103": {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"},
        "JMO-TEST-2026-0104": {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"},
        "JMO-TEST-2026-0112": {"pom.xml", "gradle.lockfile"},
        "JMO-TEST-2026-0115": {"packages.config", "packages.lock.json"},
    }
    found: dict[str, set[str]] = {}
    for lockfile, advisory_id in build.EXPECTED_PAIRS:
        found.setdefault(advisory_id, set()).add(_lockfile_name(lockfile))

    for advisory in build.ADVISORIES:
        assert found[advisory.id] == shared.get(
            advisory.id, {_lockfile_name(advisory.lockfile)}
        ), advisory.id


# --- the records -----------------------------------------------------------------


@pytest.mark.parametrize("advisory", build.ADVISORIES, ids=lambda a: a.id)
def test_an_advisory_affects_its_one_version_and_says_it_is_synthetic(advisory) -> None:
    record = build.record(advisory)

    (affected,) = record["affected"]
    assert affected["package"] == {
        "ecosystem": advisory.ecosystem,
        "name": advisory.package,
    }
    (range_,) = affected["ranges"]
    assert range_["type"] == "ECOSYSTEM"
    assert range_["events"] == [
        {"introduced": advisory.version},
        {"last_affected": advisory.version},
    ]
    assert "versions" not in affected
    assert record["id"] == advisory.id
    assert record["schema_version"] == "1.6.0"
    assert record["details"] == (
        "Synthetic advisory for JMo's tests; not a real vulnerability."
    )
    assert record["summary"].startswith("Synthetic advisory")
    assert record["published"] == record["modified"]


# --- the zips --------------------------------------------------------------------


def test_the_committed_databases_are_one_zip_per_ecosystem_and_nothing_else() -> None:
    files = sorted(
        path.relative_to(COMMITTED).as_posix()
        for path in COMMITTED.rglob("*")
        if path.is_file()
    )

    assert files == sorted(f"osv-scalibr/{e}/all.zip" for e in build.ecosystems())


def test_the_committed_databases_hold_each_advisory_once_under_its_id() -> None:
    held = {}
    for ecosystem in build.ecosystems():
        members = _members(build.database_path(COMMITTED, ecosystem))
        assert list(members) == sorted(members)
        for name, record in members.items():
            assert name == f"{record['id']}.json"
            held[record["id"]] = record

    assert held == {a.id: build.record(a) for a in build.ADVISORIES}


def test_rebuilding_gives_the_committed_bytes(tmp_path) -> None:
    """The databases are generated, so a hand edit or a change to the table that
    nobody regenerated fails here, on every platform (the zips are stored, not
    deflated: a deflate stream is a function of the zlib that wrote it)."""
    written = build.build(tmp_path)

    assert len(written) == len(build.ecosystems())
    for path in written:
        committed = COMMITTED / path.relative_to(tmp_path)
        assert path.read_bytes() == committed.read_bytes(), committed


def test_two_builds_are_byte_identical(tmp_path) -> None:
    first = {
        p.relative_to(tmp_path / "a"): p.read_bytes()
        for p in build.build(tmp_path / "a")
    }
    second = {
        p.relative_to(tmp_path / "b"): p.read_bytes()
        for p in build.build(tmp_path / "b")
    }

    assert first == second


def test_a_zip_entry_carries_nothing_of_the_machine_that_wrote_it() -> None:
    for ecosystem in build.ecosystems():
        with zipfile.ZipFile(build.database_path(COMMITTED, ecosystem)) as archive:
            for info in archive.infolist():
                assert info.date_time == build.ZIP_TIME
                assert info.compress_type == zipfile.ZIP_STORED
                assert info.create_system == 3
                assert info.external_attr == 0o600 << 16
                assert info.comment == b""
                assert info.extra == b""


def test_the_committed_databases_hold_no_lockfile() -> None:
    """Tracked vulnerable lockfiles would raise Dependabot alerts on this repository."""
    names = {_lockfile_name(relative) for relative in SCA_KITCHEN_SINK_FILES}
    for path in COMMITTED.rglob("*"):
        assert path.name not in names, path


# --- the oracle's grading --------------------------------------------------------


def test_the_expected_pairs_grade_as_correct() -> None:
    assert grade(set(build.EXPECTED_PAIRS)) == []


def test_a_format_that_yields_nothing_is_named_by_file_and_ecosystem() -> None:
    observed = {
        p for p in build.EXPECTED_PAIRS if _lockfile_name(p[0]) != "pnpm-lock.yaml"
    }

    problems = grade(observed)

    assert problems[0].startswith("no advisory reached osv-scanner from: ")
    assert "pnpm-lock.yaml (npm, javascript/pnpm/pnpm-lock.yaml)" in problems[0]
    assert "package-lock.json" not in problems[0]  # it yielded; only pnpm did not
    assert len(problems) == 2  # and the pairs that therefore went missing


def test_an_advisory_found_through_a_sibling_does_not_stand_for_the_lockfile() -> None:
    """pnpm-lock.yaml's own advisory (0103) is also found in package-lock.json and
    yarn.lock; without pnpm-lock.yaml in the scan the advisory is still there and
    the format is not."""
    observed = {p for p in build.EXPECTED_PAIRS if "pnpm" not in p[0]}

    assert any(i == "JMO-TEST-2026-0103" for _, i in observed)
    assert "pnpm-lock.yaml" in grade(observed)[0]


def test_a_pair_nobody_expected_is_reported() -> None:
    observed = set(build.EXPECTED_PAIRS) | {
        ("javascript/bun/bun.lock", "JMO-TEST-2026-0102")
    }

    problems = grade(observed)

    assert len(problems) == 1
    assert problems[0].startswith("found and not expected: ")
    assert "javascript/bun/bun.lock" in problems[0]
    assert "JMO-TEST-2026-0102" in problems[0]


def test_a_pair_that_is_missing_is_reported_beside_the_ones_found() -> None:
    gone = ("java/gradle/gradle.lockfile", "JMO-TEST-2026-0112")

    problems = grade(set(build.EXPECTED_PAIRS) - {gone})

    assert len(problems) == 1  # gradle.lockfile still yielded its own other advisory
    assert problems[0].startswith("expected and not found: ")
    assert "JMO-TEST-2026-0112" in problems[0]
