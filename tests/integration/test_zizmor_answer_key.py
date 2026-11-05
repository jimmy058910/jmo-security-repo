"""zizmor's own integration tests, graded through `jmo scan` (Phase 6, F6; J7).

zizmor's `crates/zizmor/tests/integration/audit/*.rs` hold insta snapshots of
its text output on inputs under `test-data/`. They are the answer key here,
pinned at zizmor's v1.31.1 tag and fetched, never committed:

    python scripts/dev/fetch_answer_keys.py zizmor

A test is comparable when it runs zizmor as JMo does: one input and the test
harness's defaults (`--offline`, the regular persona, no config) and nothing
else, since an argument, a config, a network mode or an environment variable
changes what zizmor reports. Each finding in a snapshot is a header,
`warning[artipacked]: ...`, then its primary location, `--> @@INPUT@@:22:9`
(a directory input names the file: `@@INPUT@@/action.yml:9:13`). The key is the
(audit, line, column) of each, and a snapshot with none says the input must
produce nothing.

Every comparable input goes into one repository where JMo's zizmor row reads
it: a workflow under `.github/workflows/`, an action as `<dir>/action.yml`, a
Dependabot config at `.github/dependabot.yml`. One `jmo scan --tools zizmor`
reads them all, and each file's findings, as JMo's adapter reads them, must
equal its snapshot's. A pre-commit config, which zizmor audits and JMo never
hands it, is out of scope.

Measured at v1.31.1 (2026-11-05): 279 snapshots, 72 comparable, 199 findings;
the 69 inputs JMo reads hold 192 of them, and all 69 match. The three
pre-commit inputs hold the other 7.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import pytest

from scripts.core.adapters.zizmor_adapter import ZizmorAdapter
from scripts.core.tool_descriptors import DESCRIPTORS
from scripts.dev import fetch_answer_keys as keys
from tests.conftest import scanner_installed

FETCH_COMMAND = "python scripts/dev/fetch_answer_keys.py zizmor"
INTEGRATION = "crates/zizmor/tests/integration"

# (audit, line, column)
Finding = tuple[str, int, int]

_CALL = "insta::assert_snapshot!("
_SNAPSHOT = re.compile(r'@(?:r#"(.*?)"#|r?"((?:[^"\\]|\\.)*)")', re.DOTALL)
_HEADER = re.compile(r"^\s*(?:error|warning|help|info|note)\[([a-z0-9-]+)\]:")
_LOCATION = re.compile(r"-->\s*@@INPUT@@(?:[\\/][^\s:]*)?:(\d+):(\d+)")
_INPUT = re.compile(r'input_under_test\("([^"]+)"\)')
_BUILDER_CALL = re.compile(r"\.([a-z_]+)\(")
# The calls a comparable test may make: anything else changes what zizmor runs.
_PLAIN = {"cargo_bin", "input", "run"}


@dataclass
class Case:
    source: str  # the audit test file
    input: str  # relative to test-data/
    findings: Counter[Finding] = field(default_factory=Counter)


def snapshot_calls(text: str) -> list[str]:
    """The argument text of each `insta::assert_snapshot!(...)` in a Rust file,
    parentheses inside its string literals left alone."""
    calls = []
    start = text.find(_CALL)
    while start != -1:
        i = start + len(_CALL)
        depth = 1
        while depth and i < len(text):
            literal = _SNAPSHOT.match(text, i)
            if literal:
                i = literal.end()
                continue
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        calls.append(text[start + len(_CALL) : i - 1])
        start = text.find(_CALL, i)
    return calls


def findings_of(snapshot: str) -> Counter[Finding]:
    """Each header's audit at the location on the lines that follow it."""
    lines = snapshot.splitlines()
    found: Counter[Finding] = Counter()
    for k, line in enumerate(lines):
        header = _HEADER.match(line)
        if not header:
            continue
        for nxt in lines[k + 1 : k + 4]:
            where = _LOCATION.search(nxt)
            if where:
                found[(header.group(1), int(where.group(1)), int(where.group(2)))] += 1
                break
    return found


def comparable_cases(source: str, text: str) -> list[Case]:
    """The tests in one audit file that run zizmor as JMo does."""
    cases = []
    for call in snapshot_calls(text):
        snapshot = _SNAPSHOT.search(call)
        if not snapshot or "Zizmor::cargo_bin()" not in call[: snapshot.start()]:
            continue
        chain = call[: snapshot.start()]
        inputs = _INPUT.findall(chain)
        if set(_BUILDER_CALL.findall(chain)) - _PLAIN or len(inputs) != 1:
            continue
        body = snapshot.group(1) if snapshot.group(1) is not None else snapshot.group(2)
        cases.append(Case(source, inputs[0], findings_of(body)))
    return cases


def placement(input_file: str) -> str:
    """Where a repository holds an input so that JMo's zizmor row reads it."""
    path = PurePosixPath(input_file.rstrip("/"))
    flat = "__".join(path.parts)
    name = path.name
    if name in ("action.yml", "action.yaml"):
        return f"{flat.rsplit('.', 1)[0]}/{name}"
    if name in ("dependabot.yml", "dependabot.yaml"):
        return f".github/{name}"
    if name.startswith(".pre-commit-config."):
        return f"{flat}/{name}"
    return f".github/workflows/{flat}"


def jmo_reads(placed: str) -> bool:
    """Whether a file at `placed` is one JMo hands zizmor: its row's patterns."""
    return any(
        PurePosixPath(placed).match(pattern.removeprefix("**/"))
        for pattern in DESCRIPTORS["zizmor"].file_patterns
    )


# --- the parser, on text written here -----------------------------------------------

PLAIN_TEST = """
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin().input(input_under_test("artipacked.yml")).run()?,
        @"
    warning[artipacked]: credential persistence (see (this))
      --> @@INPUT@@:22:9
       |
    2 findings (1 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "
    );
"""


def test_a_plain_test_is_parsed_to_its_audit_line_and_column() -> None:
    (case,) = comparable_cases("artipacked.rs", PLAIN_TEST)
    assert case.input == "artipacked.yml"
    assert case.findings == Counter({("artipacked", 22, 9): 1})


def test_a_test_with_any_other_call_is_not_comparable() -> None:
    for extra in ('.args(["--persona=pedantic"])', ".offline(NetworkMode::Implicit)"):
        text = PLAIN_TEST.replace(".run()?", f"{extra}.run()?")
        assert comparable_cases("x.rs", text) == []


def test_a_directory_input_names_its_file_in_the_location() -> None:
    text = PLAIN_TEST.replace("@@INPUT@@:22:9", "@@INPUT@@/action.yml:9:13")
    (case,) = comparable_cases("x.rs", text)
    assert case.findings == Counter({("artipacked", 9, 13): 1})


def test_a_snapshot_with_no_finding_is_a_case_that_wants_none() -> None:
    text = PLAIN_TEST.split("@")[0] + '@"No findings to report. Good job!"\n    );\n'
    (case,) = comparable_cases("x.rs", text)
    assert case.findings == Counter()


def test_each_kind_of_input_lands_where_jmo_reads_it() -> None:
    assert placement("cache-poisoning/issue-343-repro.yml") == (
        ".github/workflows/cache-poisoning__issue-343-repro.yml"
    )
    assert placement("github-env/action.yml") == "github-env__action/action.yml"
    # A directory input is placed by the one file it holds.
    assert placement("archived-uses/action/action.yml") == (
        "archived-uses__action__action/action.yml"
    )
    assert placement("dependabot-cooldown/x/dependabot.yml") == ".github/dependabot.yml"
    for read in (".github/workflows/a.yml", "d/action.yml", ".github/dependabot.yml"):
        assert jmo_reads(read), read


def test_jmo_hands_zizmor_no_pre_commit_config() -> None:
    """The exclusion in the scan test rests on this. It fails by design when
    issue #1592 lands (zizmor's row reads pre-commit configs): then delete this
    test, and the three pre-commit cases come into scope on their own."""
    assert not jmo_reads(placement("archived-uses/pre-commit/.pre-commit-config.yaml"))


# --- the key, through jmo scan ------------------------------------------------------


@pytest.fixture(scope="module")
def zizmor_key() -> Path:
    """The pinned key; skips when it is not fetched and fails when what is
    there is not the pin."""
    root = keys.zizmor_dir()
    for rel, expected in keys.ZIZMOR_FILES.items():
        path = root / rel
        if not path.is_file():
            pytest.skip(
                f"answer key {keys.ZIZMOR} is not fetched: run `{FETCH_COMMAND}`"
            )
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            pytest.fail(
                f"{path} is not the pinned file (sha256 {actual}, pinned {expected}): "
                f"run `{FETCH_COMMAND}`",
                pytrace=False,
            )
    return root / INTEGRATION


@pytest.mark.requires_tools
@pytest.mark.timeout(900)
def test_zizmor_reports_its_own_snapshots_through_jmo_scan(
    zizmor_key, jmo_runner, tmp_path
) -> None:
    if not scanner_installed("zizmor"):
        pytest.skip("zizmor is not installed")
    cases = [
        case
        for rs in sorted((zizmor_key / "audit").glob("*.rs"))
        for case in comparable_cases(rs.name, rs.read_bytes().decode())
    ]
    repo = tmp_path / "repo"
    placed: dict[str, Case] = {}
    for case in cases:
        source = zizmor_key / "test-data" / case.input
        files = (
            [p for p in source.rglob("*") if p.is_file()]
            if source.is_dir()
            else [source]
        )
        (file,) = files
        where = placement(
            case.input if source.is_file() else f"{case.input}{file.name}"
        )
        if not jmo_reads(where):
            continue
        assert where not in placed, f"two inputs land at {where}"
        (repo / where).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, repo / where)
        placed[where] = case
    # A parser that found nothing would pass everything below.
    assert len(placed) >= 69, len(placed)
    assert sum(sum(c.findings.values()) for c in placed.values()) >= 192

    results = tmp_path / "results"
    run = jmo_runner(
        [
            "scan",
            "--repo",
            str(repo),
            "--tools",
            "zizmor",
            "--results-dir",
            str(results),
            "--no-store-history",
        ],
        timeout=600,
    )
    assert run.returncode == 0, run.stderr[-2000:]
    (out,) = (results / "individual-repos").iterdir()
    got: dict[str, Counter[Finding]] = {}
    for f in ZizmorAdapter().parse(out / "zizmor.json"):
        audit = f.ruleId.split("/")[-1]
        got.setdefault(f.location["path"], Counter())[
            (audit, f.location["startLine"], f.location["startColumn"])
        ] += 1

    wrong = {
        where: (
            dict(case.findings - got.get(where, Counter())),
            dict(got.get(where, Counter()) - case.findings),
        )
        for where, case in sorted(placed.items())
        if got.get(where, Counter()) != case.findings
    }
    assert not wrong, (
        f"{len(wrong)} of {len(placed)} inputs differ from zizmor {keys.ZIZMOR_VERSION}'s "
        "snapshots, as (expected only, reported only). If installed zizmor is "
        "another version, re-pin the key to its tag in scripts/dev/fetch_answer_keys.py: "
        f"{wrong}"
    )
    assert set(got) <= set(placed), set(got) - set(placed)
