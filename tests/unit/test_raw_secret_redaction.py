"""The secret scanners' raw outputs lose their secrets once the report has read them (#1329).

The report and history never hold a secret: trufflehog's adapter drops `Raw`,
gitleaks' binding drops `region.snippet`. The raw outputs under
`results/individual-*/` held every one in plaintext, the history files included,
and a results directory gets uploaded as a CI artifact.

A later `jmo report` reads those files again, and reads the secret for two
things: the digest that pairs a secret's tree record with its history records,
and trufflehog's filter for pytest names its Lob detector matches. So each
secret becomes its own stand-in, equal for equal secrets: one marker for all of
them would pair every secret at a path with every other, which is the trap
gitleaks' own `--redact` sets (#1323).
"""

from __future__ import annotations

import json
import logging
import os
import stat
import sys
from pathlib import Path

import pytest

import scripts.core.secret_output_redaction as sor
from scripts.core.adapters.common import safe_load_ndjson_file
from scripts.core.normalize_and_report import gather_results
from scripts.core.secret_output_redaction import (
    STAND_IN_PREFIX,
    redact_secret_outputs,
)

ALPHA = "jmo-fixture-secret-alpha-31d5e8a0"  # in the tree and in history
BRAVO = "jmo-fixture-secret-bravo-7c42f9b1"  # in the tree only
CHARLIE = "jmo-fixture-secret-charlie-0e9a6d2c"  # deleted: in history only
DELTA = "jmo-fixture-secret-delta-5b18c3e4"  # rotated in: the tree's key
ECHO = "jmo-fixture-secret-echo-a9f07b65"  # rotated out: history's key
SECRETS = (ALPHA, BRAVO, CHARLIE, DELTA, ECHO)
# A pytest name trufflehog's Lob detector matches: not a secret, and the
# adapter drops it, before and after redaction alike.
LOB_PYTEST_NAME = "test_a_function_name_lob_matches_x"
C1, C2, C3 = "1" * 40, "2" * 40, "3" * 40


def _th_tree(raw: str, path: str, detector: str = "PrivateKey") -> dict:
    return {
        "SourceMetadata": {"Data": {"Filesystem": {"file": path, "line": 1}}},
        "DetectorName": detector,
        "DecoderName": "PLAIN",
        "Verified": False,
        "Raw": raw,
        "RawV2": raw + "-v2",
        "Redacted": raw[:12],
        "SecretParts": {"key": raw},
        "ExtraData": None,
        "StructuredData": None,
    }


def _th_git(raw: str, path: str, commit: str) -> dict:
    record = _th_tree(raw, path)
    record["SourceMetadata"] = {
        "Data": {
            "Git": {
                "commit": commit,
                "file": path,
                "email": "Fixture Author <fixture@example.invalid>",
                "repository": "file:///repo",
                "timestamp": "2026-01-02 03:04:05 +0000",
                "line": 1,
            }
        }
    }
    return record


def _gl(snippet: str, path: str, commit: str = "") -> dict:
    return {
        "ruleId": "generic-api-key",
        "message": {"text": f"generic-api-key has detected secret for file {path}."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                        "snippet": {"text": snippet},
                    },
                }
            }
        ],
        "partialFingerprints": {
            "commitSha": commit,
            "email": "fixture@example.invalid" if commit else "",
            "author": "Fixture Author" if commit else "",
            "date": "2026-01-02T03:04:05Z" if commit else "",
            "commitMessage": "add" if commit else "",
        },
    }


def _sarif(*results: dict) -> bytes:
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": list(results)}],
    }
    return json.dumps(document, indent=1).encode()


def _ndjson(*records: dict) -> bytes:
    return "".join(json.dumps(r) + "\n" for r in records).encode()


def _target(results: Path, name: str = "app") -> Path:
    """One repository's folder, as `jmo scan` leaves it: both secret scanners,
    tree and history, with a key in both, one only in the tree, one deleted,
    and one rotated in place (two secrets at one path)."""
    target = results / "individual-repos" / name
    target.mkdir(parents=True)
    (target / "trufflehog.json").write_bytes(
        _ndjson(
            _th_tree(ALPHA, "keys/live.pem"),
            _th_tree(BRAVO, "config.py"),
            _th_tree(DELTA, "keys/rot.pem"),
            _th_tree(LOB_PYTEST_NAME, "tests/test_x.py", detector="Lob"),
        )
    )
    (target / "trufflehog.git.json").write_bytes(
        _ndjson(
            _th_git(ALPHA, "keys/live.pem", C1),
            _th_git(CHARLIE, "old/gone.pem", C2),
            _th_git(ECHO, "keys/rot.pem", C3),
        )
    )
    (target / "gitleaks.json").write_bytes(
        _sarif(
            _gl(ALPHA, "keys/live.pem"),
            _gl(BRAVO, "config.py"),
            _gl(DELTA, "keys/rot.pem"),
        )
    )
    (target / "gitleaks.git.json").write_bytes(
        _sarif(
            _gl(ALPHA, "keys/live.pem", C1),
            _gl(CHARLIE, "old/gone.pem", C2),
            _gl(ECHO, "keys/rot.pem", C3),
        )
    )
    return target


def _leaks(results: Path) -> dict[str, list[str]]:
    """Every file under `results` holding a planted secret, with the secrets."""
    found: dict[str, list[str]] = {}
    for path in sorted(results.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            hits = [s for s in SECRETS if s.encode() in data]
            if hits:
                found[path.relative_to(results).as_posix()] = hits
    return found


def _shape(findings: list[dict]) -> list[tuple]:
    return sorted(
        (
            f["id"],
            f["tool"]["name"],
            f["location"]["path"],
            (f.get("secretContext") or {}).get("commit"),
        )
        for f in findings
    )


def test_the_fixture_holds_every_secret_before_a_report(tmp_path: Path) -> None:
    """Meta-guard: without the secrets in the files, the tests below pass vacuously."""
    _target(tmp_path)
    leaks = _leaks(tmp_path)
    assert set(leaks) == {
        f"individual-repos/app/{name}"
        for name in (
            "trufflehog.json",
            "trufflehog.git.json",
            "gitleaks.json",
            "gitleaks.git.json",
        )
    }
    assert set(leaks["individual-repos/app/trufflehog.git.json"]) == {
        ALPHA,
        CHARLIE,
        ECHO,
    }


def test_no_secret_survives_in_the_secret_scanners_outputs(tmp_path: Path) -> None:
    _target(tmp_path)

    gather_results(tmp_path)

    assert _leaks(tmp_path) == {}


def test_a_second_report_reads_the_same_findings(tmp_path: Path) -> None:
    """The decisive property: the stand-ins pair a tree record with its
    history as the secrets did, keep a rotated key two findings, and leave
    the Lob pytest name to the adapter's filter."""
    _target(tmp_path)

    first = _shape(gather_results(tmp_path))
    second = _shape(gather_results(tmp_path))

    assert second == first
    by_tool: dict[str, list[tuple[str, str | None]]] = {}
    for _, tool, path, commit in first:
        by_tool.setdefault(tool, []).append((path, commit))
    expected = sorted(
        [
            ("keys/live.pem", C1),  # the tree's key, with the commit that added it
            ("config.py", None),
            ("old/gone.pem", C2),
            ("keys/rot.pem", None),  # the new key
            ("keys/rot.pem", C3),  # the old one, still in history
        ],
        key=str,
    )
    assert {t: sorted(v, key=str) for t, v in by_tool.items()} == {
        "trufflehog": expected,
        "gitleaks": expected,
    }


def test_a_second_report_rewrites_nothing(tmp_path: Path) -> None:
    target = _target(tmp_path)
    gather_results(tmp_path)
    after_first = {p.name: p.read_bytes() for p in target.iterdir()}

    gather_results(tmp_path)

    assert {p.name: p.read_bytes() for p in target.iterdir()} == after_first


def test_an_earlier_scans_withheld_output_is_redacted_too(tmp_path: Path) -> None:
    """A reused results directory keeps an earlier scan's output, which the
    report withholds (this scan has no row for its tool) but which still holds
    its secrets."""
    target = _target(tmp_path)
    (target / "scan-timings.json").write_bytes(
        json.dumps(
            {"schema_version": 5, "tools": [{"tool": "gitleaks", "state": "ran"}]}
        ).encode()
    )

    findings = gather_results(tmp_path)

    assert {f["tool"]["name"] for f in findings} == {"gitleaks"}
    assert _leaks(tmp_path) == {}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_a_rewritten_output_keeps_its_mode(tmp_path: Path) -> None:
    target = _target(tmp_path)
    for path in target.iterdir():
        path.chmod(0o640)

    gather_results(tmp_path)

    assert {stat.S_IMODE(p.stat().st_mode) for p in target.iterdir()} == {0o640}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory modes")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root writes into a read-only directory",
)
def test_an_output_that_cannot_be_rewritten_is_named_and_the_report_runs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A report on a mounted, read-only results directory still reports."""
    target = _target(tmp_path)
    target.chmod(0o555)
    try:
        with caplog.at_level(logging.WARNING):
            findings = gather_results(tmp_path)
    finally:
        target.chmod(0o755)

    assert len(findings) == 10
    warned = [r.getMessage() for r in caplog.records if "still hold" in r.getMessage()]
    assert len(warned) == 4, warned
    assert any("trufflehog.git.json" in message for message in warned)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory modes")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root searches any directory",
)
def test_a_target_folder_that_cannot_be_searched_does_not_end_the_report(
    tmp_path: Path,
) -> None:
    """Python 3.12's `Path.is_file()` raises inside a folder that cannot be
    searched, and looking for an unfinished pass's key there ended the report
    (a review of #1593's fix). The report reads nothing from that folder, as
    before."""
    target = _target(tmp_path)
    target.chmod(0)
    try:
        findings = gather_results(tmp_path)
    finally:
        target.chmod(0o755)

    assert findings == []


@pytest.mark.parametrize(
    "body",
    [
        # One line holding an array, beside a plain record.
        json.dumps([_th_tree(ALPHA, "a.pem"), _th_tree(BRAVO, "b.pem")])
        + "\n"
        + json.dumps(_th_tree(CHARLIE, "c.pem"))
        + "\n",
        # A nested array, the whole file one JSON document.
        json.dumps([[_th_tree(ALPHA, "a.pem")], _th_tree(BRAVO, "b.pem")]),
        # A pretty-printed array.
        json.dumps([_th_tree(ALPHA, "a.pem"), _th_tree(BRAVO, "b.pem")], indent=2),
        # Records split by the line breaks str.splitlines() also splits on.
        json.dumps(_th_tree(ALPHA, "a.pem"))
        + "\u2028"
        + json.dumps(_th_tree(BRAVO, "b.pem"))
        + "\x85"
        + json.dumps(_th_tree(CHARLIE, "c.pem")),
        # A byte that is not UTF-8 after a record, which the adapter drops.
        (json.dumps(_th_tree(ALPHA, "a.pem")) + "\n").encode()
        + b"\xff"
        + (json.dumps(_th_tree(BRAVO, "b.pem")) + "\n").encode(),
    ],
    ids=[
        "array-on-a-line",
        "nested-array",
        "pretty-array",
        "unicode-line-breaks",
        "invalid-byte",
    ],
)
def test_every_record_the_adapter_reads_is_redacted(
    tmp_path: Path, body: str | bytes
) -> None:
    """The adapter reads a trufflehog file through `safe_load_ndjson_file`:
    decoded dropping bytes that are not UTF-8, split with str.splitlines(),
    and arrays flattened at any depth. Whatever it reads, the redaction must
    have reached (reviews of #1329: these shapes kept their secrets)."""
    path = tmp_path / "trufflehog.json"
    path.write_bytes(body if isinstance(body, bytes) else body.encode())
    assert len(list(safe_load_ndjson_file(path))) >= 2  # meta: the adapter reads them

    redact_secret_outputs([path])

    records = list(safe_load_ndjson_file(path))
    assert records
    assert all(r["Raw"].startswith(STAND_IN_PREFIX) for r in records), records
    assert not [s for s in SECRETS if s.encode() in path.read_bytes()]


def test_an_output_too_deep_to_read_is_named_and_the_rest_redacted(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """json.loads raises RecursionError, not a decode error, on deep nesting;
    it must not end the report."""
    deep = tmp_path / "gitleaks.json"
    deep.write_bytes(b"[" * 100_000 + b"]" * 100_000)
    target = _target(tmp_path / "results")

    with caplog.at_level(logging.WARNING):
        redact_secret_outputs([deep, *sorted(target.glob("*.json"))])

    assert any("gitleaks.json" in r.getMessage() for r in caplog.records)
    assert _leaks(tmp_path / "results") == {}


def test_an_empty_output_is_left_without_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A tool killed after creating its file leaves it empty: nothing to hold."""
    for name in ("gitleaks.json", "trufflehog.json"):
        (tmp_path / name).write_bytes(b"")

    with caplog.at_level(logging.WARNING):
        redact_secret_outputs(sorted(tmp_path.glob("*.json")))

    assert caplog.records == []


# A tool's tree and history outputs rewritten in two passes (#1593) --------


def _failing_rewrite(
    monkeypatch: pytest.MonkeyPatch, name: str, error: BaseException
) -> None:
    """Make the rewrite of the output called `name` raise `error`, as a file
    locked on Windows, a full disk or a stopped run does."""
    real = sor._replace

    def replace(path: Path, data: bytes) -> None:
        if path.name == name:
            raise error
        real(path, data)

    monkeypatch.setattr(sor, "_replace", replace)


def _tool_shape(results: Path, tool: str) -> list[tuple[str, str | None]]:
    return sorted(
        (
            (path, commit)
            for _, name, path, commit in _shape(gather_results(results))
            if name == tool
        ),
        key=str,
    )


#: Each tool's findings in `_target`, its tree key paired with its history.
_PAIRED = sorted(
    [
        ("keys/live.pem", C1),
        ("config.py", None),
        ("old/gone.pem", C2),
        ("keys/rot.pem", None),
        ("keys/rot.pem", C3),
    ],
    key=str,
)


@pytest.mark.parametrize("tool", ["trufflehog", "gitleaks"])
def test_a_history_output_rewritten_a_report_late_still_pairs(
    tmp_path: Path,
    tool: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The first report rewrites the tree output and not the history one. The
    next reports must pair the two again: before #1593 the next pass keyed the
    history output's secrets anew, and `keys/live.pem` read as a tree finding
    with no commit beside a history finding, in this report and every later
    one."""
    _target(tmp_path)
    with monkeypatch.context() as m, caplog.at_level(logging.WARNING):
        _failing_rewrite(m, f"{tool}.git.json", PermissionError(13, "locked"))
        assert _tool_shape(tmp_path, tool) == _PAIRED  # read before any rewrite

    # Said, by file, and never by secret.
    assert any(
        f"{tool}.git.json could not be rewritten" in r.getMessage()
        for r in caplog.records
    )
    assert not [r for r in caplog.records if any(s in r.getMessage() for s in SECRETS)]
    assert list(_leaks(tmp_path)) == [f"individual-repos/app/{tool}.git.json"]

    assert _tool_shape(tmp_path, tool) == _PAIRED  # the report that finishes it
    assert _leaks(tmp_path) == {}
    assert _tool_shape(tmp_path, tool) == _PAIRED  # and the next


@pytest.mark.parametrize("tool", ["trufflehog", "gitleaks"])
def test_a_report_stopped_between_the_rewrites_pairs_in_the_next(
    tmp_path: Path, tool: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run stopped (Ctrl-C) between a tool's two rewrites has no chance to
    save anything on its way out, so the key has to be on disk before the
    first. The outputs go in sorted order, history first."""
    target = _target(tmp_path)
    with monkeypatch.context() as m:
        _failing_rewrite(m, f"{tool}.json", KeyboardInterrupt())
        with pytest.raises(KeyboardInterrupt):
            gather_results(tmp_path)
    # Meta: the pair is split, one output rewritten and the other not.
    leaks = _leaks(tmp_path)
    assert f"individual-repos/app/{tool}.json" in leaks
    assert f"individual-repos/app/{tool}.git.json" not in leaks

    assert _tool_shape(tmp_path, tool) == _PAIRED
    assert _leaks(tmp_path) == {}
    assert not sor.has_unfinished_pass(target)


def test_the_key_stays_only_while_an_output_is_unrewritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The key confirms a guessed secret against a stand-in. It is kept only
    while a raw secret sits beside it, readable by its owner alone, and under
    a name no adapter reads."""
    target = _target(tmp_path)
    gather_results(tmp_path)
    assert not (target / sor.KEY_FILE).exists()

    target = _target(tmp_path, name="second")
    with monkeypatch.context() as m:
        _failing_rewrite(m, "gitleaks.git.json", PermissionError(13, "locked"))
        gather_results(tmp_path)
    key_file = target / sor.KEY_FILE
    assert key_file.read_bytes() and not key_file.match("*.json")
    if sys.platform != "win32":
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    # No temporary file is left beside it.
    assert sorted(p.name for p in target.iterdir() if p.name.startswith(".")) == [
        sor.KEY_FILE
    ]

    gather_results(tmp_path)
    assert not key_file.exists()


def test_an_output_that_never_parses_keeps_no_key(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A later pass cannot redact what does not parse, so keeping the key for
    it would keep the key for good."""
    target = _target(tmp_path)
    with (target / "trufflehog.git.json").open("ab") as handle:
        handle.write(b"{not json\n")

    with caplog.at_level(logging.WARNING):
        redact_secret_outputs(sorted(target.glob("*.json")))

    assert any("do not parse" in r.getMessage() for r in caplog.records)
    assert not sor.has_unfinished_pass(target)


@pytest.mark.parametrize(
    "bad_key",
    [b"", b"short", b"x" * 64],
    ids=["empty", "short", "long"],
)
def test_a_key_file_that_is_not_a_key_is_named_and_replaced(
    tmp_path: Path, bad_key: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    target = _target(tmp_path)
    (target / sor.KEY_FILE).write_bytes(bad_key)

    with caplog.at_level(logging.WARNING):
        gather_results(tmp_path)

    assert any("is not a redaction key" in r.getMessage() for r in caplog.records)
    assert _leaks(tmp_path) == {}
    assert not (target / sor.KEY_FILE).exists()


def test_a_key_that_cannot_be_saved_does_not_stop_the_redaction(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Skipping the redaction for want of a key would leave every secret on
    disk because of the fix. A directory in the key's place can be neither
    read nor replaced, on any platform."""
    target = _target(tmp_path)
    (target / sor.KEY_FILE).mkdir()

    with caplog.at_level(logging.WARNING):
        findings = gather_results(tmp_path)

    messages = [r.getMessage() for r in caplog.records]
    assert any("could not be saved" in m for m in messages), messages
    assert _leaks(tmp_path) == {}
    assert len(findings) == 10
    assert sorted(p.name for p in target.iterdir() if p.name.startswith(".")) == [
        sor.KEY_FILE
    ]
