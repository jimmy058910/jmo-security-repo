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

from scripts.core.normalize_and_report import gather_results

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
