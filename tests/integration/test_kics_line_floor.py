"""KICS's expected Dockerfile lines, graded through `jmo scan` (Phase 6, E6; J7).

Checkmarx/kics ships, for each of its 48 Dockerfile queries, positive samples and the
lines a scanner should flag in them (`test/positive_expected_result.json`). They are the
answer key here, fetched by commit and pinned per file, never committed:

    python scripts/dev/fetch_answer_keys.py kics

KICS's checks are not JMo's. hadolint and trivy flag a line for reasons of their own, so
a line hit is a floor, never recall, and a missed line may be one no JMo tool checks.
The scan test fails when a line the baseline records as hit is missed, and prints the
lines hit for the first time.

How it counts (the baseline's `counted`): each positive sample is its own target,
written as `Dockerfile` (`positive1.dockerfile` is no Dockerfile spelling); one
`jmo scan --tools hadolint trivy` reads them all; a line is hit when a finding in that
target's hadolint or trivy output, parsed by JMo's adapter, covers it (`startLine` to
`endLine`, the end defaulting to the start). The raw outputs are graded rather than
`findings.json`: the report merges a same-check trivy and hadolint pair into one finding
with one location (E1), which hides the partner's line. `findings.json`'s count is
recorded beside it.

The key's traps, measured on its Kubernetes half too (F6b): the file is named
`fileName`, `filename` or `fineName`; an entry naming no file belongs to its query's
only positive; a (file, line) listed twice counts once.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from scripts.core.adapters.hadolint_adapter import HadolintAdapter
from scripts.core.adapters.trivy_adapter import TrivyAdapter
from scripts.dev import fetch_answer_keys as keys
from tests.conftest import scanner_installed

FETCH_COMMAND = "python scripts/dev/fetch_answer_keys.py kics"
BASELINE = Path(__file__).parent / "baselines" / "kics-lines.json"
# Set to write the baseline from this run instead of grading against it.
RECORD = "JMO_RECORD_KICS_LINES"
TOOLS = ("hadolint", "trivy")
EXPECTED = "positive_expected_result.json"
FILE_KEYS = ("fileName", "filename", "fineName")

# (query, sample file, line)
Line = tuple[str, str, int]


def expected_entries(queries: Path, suffix: str) -> list[Line]:
    """KICS's entries for every query under `queries`, a line listed twice
    kept twice. `suffix` picks a query's positive samples (`.dockerfile`)."""
    entries: list[Line] = []
    for expected in sorted(queries.glob(f"*/test/{EXPECTED}")):
        query = expected.parent.parent.name
        positives = sorted(
            p.name for p in expected.parent.glob(f"positive*{suffix}") if p.is_file()
        )
        for entry in json.loads(expected.read_bytes()):
            named = [entry[k] for k in FILE_KEYS if k in entry]
            if named:
                (file,) = named
            elif len(positives) == 1:
                (file,) = positives
            else:
                raise ValueError(
                    f"{query}: an entry names no file and the query has "
                    f"{len(positives)} positives: {entry}"
                )
            entries.append((query, file, int(entry["line"])))
    return entries


def target_of(query: str, file: str) -> str:
    """The target a sample is staged as: one directory per sample."""
    return f"{query}--{Path(file).stem}"


def label(line: Line) -> str:
    query, file, number = line
    return f"{query}/{file}:{number}"


# --- the key's parser, no tools -------------------------------------------------


def _query(root: Path, name: str, entries: list[dict], positives: list[str]) -> None:
    test = root / name / "test"
    test.mkdir(parents=True)
    (test / EXPECTED).write_bytes(json.dumps(entries).encode())
    for positive in positives:
        (test / positive).write_bytes(b"FROM alpine\n")


def test_every_spelling_of_the_file_key_is_read(tmp_path) -> None:
    _query(
        tmp_path,
        "q",
        [
            {"line": 1, "fileName": "positive1.dockerfile"},
            {"line": 2, "filename": "positive2.dockerfile"},
            {"line": 3, "fineName": "positive3.dockerfile"},
        ],
        ["positive1.dockerfile", "positive2.dockerfile", "positive3.dockerfile"],
    )

    assert expected_entries(tmp_path, ".dockerfile") == [
        ("q", "positive1.dockerfile", 1),
        ("q", "positive2.dockerfile", 2),
        ("q", "positive3.dockerfile", 3),
    ]


def test_an_entry_naming_no_file_belongs_to_the_only_positive(tmp_path) -> None:
    _query(tmp_path, "q", [{"line": 4}], ["positive.dockerfile", "negative.dockerfile"])

    assert expected_entries(tmp_path, ".dockerfile") == [
        ("q", "positive.dockerfile", 4)
    ]


def test_an_entry_naming_no_file_among_several_positives_is_refused(tmp_path) -> None:
    _query(
        tmp_path, "q", [{"line": 4}], ["positive1.dockerfile", "positive2.dockerfile"]
    )

    with pytest.raises(ValueError, match="names no file"):
        expected_entries(tmp_path, ".dockerfile")


def test_a_line_listed_twice_is_two_entries_and_one_line(tmp_path) -> None:
    entry = {"line": 8, "fileName": "positive1.dockerfile"}
    _query(tmp_path, "q", [entry, dict(entry)], ["positive1.dockerfile"])

    entries = expected_entries(tmp_path, ".dockerfile")

    assert len(entries) == 2
    assert set(entries) == {("q", "positive1.dockerfile", 8)}


# --- the floor, through jmo scan ------------------------------------------------


@pytest.fixture(scope="module")
def dockerfile_queries() -> Path:
    """The pinned Dockerfile half of the key; skips when it is not fetched and
    fails when what is there is not the pin."""
    root = keys.kics_dir()
    for rel, expected in keys.KICS_FILES.items():
        path = root / rel
        if not path.is_file():
            pytest.skip(f"answer key {keys.KICS} is not fetched: run `{FETCH_COMMAND}`")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            pytest.fail(
                f"{path} is not the pinned file (sha256 {actual}, pinned {expected}): "
                f"run `{FETCH_COMMAND}`",
                pytrace=False,
            )
    return root / "assets" / "queries" / "dockerfile"


def _covered(found: list[tuple[str, int, int]], line: int) -> list[str]:
    return sorted({tool for tool, start, end in found if start <= line <= end})


def _spans(found) -> list[tuple[str, int, int]]:
    """(tool, first line, last line) for each (tool name, location) pair."""
    spans = []
    for tool, location in found:
        start = location.get("startLine") or 0
        spans.append((tool, start, location.get("endLine") or start))
    return spans


def _adapted(out: Path) -> list[tuple[str, int, int]]:
    """A target's hadolint and trivy findings, as JMo's adapters read them."""
    found = [*HadolintAdapter().parse(out / "hadolint.json")]
    found += TrivyAdapter().parse(out / "trivy.json")
    return _spans((f.tool["name"], f.location) for f in found)


@pytest.mark.requires_tools
@pytest.mark.timeout(1800)
def test_kics_dockerfile_lines_are_a_floor_through_jmo_scan(
    dockerfile_queries, jmo_runner, tmp_path
) -> None:
    for tool in TOOLS:
        if not scanner_installed(tool):
            pytest.skip(f"{tool} is not installed")
    entries = expected_entries(dockerfile_queries, ".dockerfile")
    lines = set(entries)
    stage = tmp_path / "stage"
    for sample in sorted(dockerfile_queries.glob("*/test/positive*.dockerfile")):
        target = stage / target_of(sample.parent.parent.name, sample.name)
        target.mkdir(parents=True)
        (target / "Dockerfile").write_bytes(sample.read_bytes())
    results = tmp_path / "results"

    run = jmo_runner(
        [
            "scan",
            "--repos-dir",
            str(stage),
            "--tools",
            *TOOLS,
            "--results-dir",
            str(results),
            "--no-store-history",
        ],
        timeout=1500,
    )
    assert run.returncode == 0, run.stderr[-2000:]

    hit: dict[str, list[str]] = {}
    for line in sorted(lines):
        query, file, number = line
        out = results / "individual-repos" / target_of(query, file)
        rows = json.loads((out / "scan-timings.json").read_bytes())["tools"]
        # A target a tool skipped or failed on would read as a miss.
        assert all(r["state"] == "ran" for r in rows), (target_of(query, file), rows)
        hit[label(line)] = _covered(_adapted(out), number)
    report = json.loads((results / "summaries" / "findings.json").read_bytes())
    by_target: dict[str, list] = {}
    for finding in report["findings"]:
        by_target.setdefault(finding["target"]["name"], []).append(finding)
    in_report = sum(
        bool(
            _covered(
                _spans(
                    (x["tool"]["name"], x["location"])
                    for x in by_target.get(target_of(q, f), [])
                ),
                n,
            )
        )
        for q, f, n in lines
    )
    distinct_hit = sum(bool(tools) for tools in hit.values())
    entries_hit = sum(bool(hit[label(e)]) for e in entries)
    measured = {
        "source": {
            "repository": "Checkmarx/kics",
            "commit": keys.KICS_COMMIT,
            "path": "assets/queries/dockerfile",
        },
        "tools": list(TOOLS),
        # A scanner upgrade is the likeliest reason a line changes.
        "versions": {
            finding["tool"]["name"]: finding["tool"].get("version")
            for finding in report["findings"]
        },
        "counted": (
            "one target per positive sample, written as Dockerfile; one jmo scan "
            "--tools hadolint trivy; a line is hit when a finding in that target's "
            "hadolint or trivy output, parsed by JMo's adapter, spans it "
            "(startLine..endLine, end defaulting to start); before the report's "
            "merging of same-check pairs"
        ),
        "entries": len(entries),
        "entries_hit": entries_hit,
        "distinct": len(lines),
        "distinct_hit": distinct_hit,
        "distinct_hit_in_findings_json": in_report,
        "lines": hit,
    }

    if os.environ.get(RECORD):
        BASELINE.write_bytes((json.dumps(measured, indent=2) + "\n").encode())
        pytest.skip(f"recorded {BASELINE.name}: {distinct_hit} of {len(lines)} lines")

    recorded = json.loads(BASELINE.read_bytes())
    assert recorded["source"]["commit"] == keys.KICS_COMMIT, "baseline of another key"
    assert set(recorded["lines"]) == set(hit), (
        "the key's lines are not the recorded ones"
    )
    lost = sorted(k for k, tools in recorded["lines"].items() if tools and not hit[k])
    gained = sorted(k for k, tools in hit.items() if tools and not recorded["lines"][k])
    if gained:
        print(f"newly hit ({len(gained)}), record them with {RECORD}=1:", *gained)
    # The report merges a same-check pair into one finding with one location
    # (E1); a change there that hides a partner's line shows here.
    assert in_report >= recorded["distinct_hit_in_findings_json"], (
        f"findings.json covers {in_report} of the lines, "
        f"{recorded['distinct_hit_in_findings_json']} when recorded"
    )
    assert not lost, (
        f"{len(lost)} line(s) hit before are missed now: {lost} (recorded with "
        f"{recorded.get('versions')}, now {measured['versions']})"
    )
