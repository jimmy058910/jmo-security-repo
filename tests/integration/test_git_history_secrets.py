"""G1: secrets in git history, through `jmo scan` and `jmo report` (Phase 3, PR C).

Before PR C the scan read the working tree only, with `.git/` excluded
(#1134), so a key committed and then deleted was invisible. trufflehog and
gitleaks now also read history when the target has a `.git`, and each
reports the commit that added the key.

A key still in the tree is in history too, so each tool sees it twice. The
report pairs the two by the secret itself (decided 2026-09-26): one finding,
keeping the tree's location and taking the adding commit. Pairing by location
cannot work: once a line is inserted above the key, the tree says line 2 and
history says line 1 (measured). A key rotated in place is two secrets at one
location, and stays two findings.

The real binaries run here, so the module is `requires_tools`. Keys are
generated at test time.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.cli.scan_utils import find_tool
from tests.conftest import generated_rsa_pem, git_commit_all

pytestmark = pytest.mark.requires_tools

TOOLS = ("trufflehog", "gitleaks")
AUTHOR = "Fixture Author <fixture@example.invalid>"
DAY1, DAY2, DAY3, DAY4 = (
    "2026-01-02T03:04:05Z",
    "2026-01-03T03:04:05Z",
    "2026-01-04T03:04:05Z",
    "2026-01-05T03:04:05Z",
)


@pytest.fixture
def scan(tmp_path: Path, monkeypatch):
    """Run `jmo scan` then `jmo report` on a repository; return findings.json
    and the scan's rows. The binaries are resolved before `Path.home()` moves
    (`cmd_scan` writes its Ko-fi counter there, and a moved home hides
    `~/.jmo/bin`)."""
    real = {tool: find_tool(tool) for tool in TOOLS}
    missing = sorted(tool for tool, path in real.items() if not path)
    if missing:
        pytest.skip(f"not installed: {', '.join(missing)}")

    cfg = tmp_path / "jmo.yml"
    cfg.write_bytes(yaml.safe_dump({"outputs": ["json"]}).encode())
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    monkeypatch.setattr(
        "scripts.cli.tool_manager.ToolManager._find_binary", lambda *a, **k: None
    )
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(
        "scripts.cli.scan_jobs.tool_loop.find_tool",
        lambda name, *a, **k: real.get(name),
    )

    def run(repo: Path) -> tuple[list[dict], list[dict]]:
        results = tmp_path / f"results-{repo.name}"
        argv = [
            "jmo",
            "scan",
            "--repo",
            str(repo),
            "--tools",
            *TOOLS,
            "--results-dir",
            str(results),
            "--config",
            str(cfg),
            "--history-db",
            str(tmp_path / "history.db"),
        ]
        with patch.object(sys, "argv", argv):
            assert jmo.cmd_scan(jmo.parse_args()) == 0
        with patch.object(
            sys, "argv", ["jmo", "report", str(results), "--config", str(cfg)]
        ):
            assert jmo.cmd_report(jmo.parse_args()) == 0
        findings = json.loads((results / "summaries" / "findings.json").read_bytes())
        meta = json.loads((results / ".scan_metadata.json").read_bytes())
        return findings["findings"], meta["tool_runs"]

    return run


def _by_tool(findings: list[dict]) -> dict[str, list[tuple[str, str | None]]]:
    """Per tool: (path, the commit a finding names), sorted."""
    out: dict[str, list[tuple[str, str | None]]] = {t: [] for t in TOOLS}
    for f in findings:
        commit = (f.get("secretContext") or {}).get("commit")
        out[f["tool"]["name"]].append((f["location"]["path"], commit))
    return {t: sorted(v, key=str) for t, v in out.items()}


def _key_text(pem: bytes) -> str:
    """A stretch of the key's body: if it appears in a report, the key leaked."""
    return pem.decode().splitlines()[3]


def test_a_key_only_in_history_is_reported_with_its_commit(tmp_path, scan) -> None:
    repo = tmp_path / "app"
    (repo / "keys").mkdir(parents=True)
    (repo / "old").mkdir()
    (repo / "app.py").write_bytes(b"print('hello')\n")
    live, gone = generated_rsa_pem(), generated_rsa_pem()
    (repo / "keys" / "live.pem").write_bytes(live)
    added_live = git_commit_all(repo, "add live key", DAY1)
    (repo / "old" / "gone.pem").write_bytes(gone)
    added_gone = git_commit_all(repo, "add gone key", DAY2)
    (repo / "old" / "gone.pem").unlink()
    git_commit_all(repo, "delete gone key", DAY3)

    findings, rows = scan(repo)

    # One finding per key per tool: the live key's tree and history records
    # are one, and the deleted key is found at all.
    expected = sorted(
        [("keys/live.pem", added_live), ("old/gone.pem", added_gone)], key=str
    )
    assert _by_tool(findings) == dict.fromkeys(TOOLS, expected)
    for f in findings:
        context = f["secretContext"]
        assert set(context) == {"commit", "author", "date"}, context
        assert context["author"] == AUTHOR
        when = datetime.fromisoformat(context["date"])
        expected_day = DAY1 if context["commit"] == added_live else DAY2
        assert when == datetime.fromisoformat(expected_day)

    written = json.dumps(findings)
    assert _key_text(live) not in written
    assert _key_text(gone) not in written

    # One row per tool, covering both of its invocations.
    assert {(r["tool"], r["state"], r["invocations"]) for r in rows} == {
        (tool, "ran", 2) for tool in TOOLS
    }


def test_a_line_inserted_above_a_committed_key_still_leaves_one(tmp_path, scan) -> None:
    """The tree says line 2, history says line 1 (measured): the pairing is by
    the secret, not by where it is."""
    repo = tmp_path / "moved"
    (repo / "keys").mkdir(parents=True)
    key = generated_rsa_pem()
    (repo / "keys" / "live.pem").write_bytes(key)
    added = git_commit_all(repo, "add key", DAY1)
    (repo / "keys" / "live.pem").write_bytes(b"# deploy key\n" + key)
    git_commit_all(repo, "comment above it", DAY2)

    findings, _ = scan(repo)

    assert _by_tool(findings) == {tool: [("keys/live.pem", added)] for tool in TOOLS}
    # It keeps the tree's location.
    assert {f["location"]["startLine"] for f in findings} == {2}


def test_a_shallow_clone_names_no_commit_rather_than_the_wrong_one(
    tmp_path, scan
) -> None:
    """A `--depth 1` clone's one commit holds the whole tree, so both tools'
    git mode name it, and its author, for every secret: here the unrelated
    commit's author on day 5, not the one who added the key on day 1
    (measured by the review). GitLab targets and `actions/checkout` both clone
    with depth 1. History is not read there; each row says so."""
    origin = tmp_path / "origin"
    (origin / "keys").mkdir(parents=True)
    (origin / "keys" / "live.pem").write_bytes(generated_rsa_pem())
    git_commit_all(origin, "add key", DAY1)
    (origin / "app.py").write_bytes(b"print('hello')\n")
    git_commit_all(origin, "unrelated change", DAY4)
    clone = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", origin.as_uri(), str(clone)],
        check=True,
        capture_output=True,
        timeout=60,
    )

    findings, rows = scan(clone)

    assert _by_tool(findings) == {tool: [("keys/live.pem", None)] for tool in TOOLS}
    for row in rows:
        assert (row["state"], row["invocations"]) == ("ran", 1), row
        assert row["detail"].startswith("history not read: a shallow clone,"), row


def test_a_path_a_url_would_misread_still_reads_history(tmp_path, scan) -> None:
    """`#` ends a URL's path and `%41` is an escape: unescaped, trufflehog's
    history run failed on every scan of such a directory (measured by the
    review, 3.97.1)."""
    repo = tmp_path / "C#proj" / "pct%41x"
    (repo / "keys").mkdir(parents=True)
    (repo / "keys" / "live.pem").write_bytes(generated_rsa_pem())
    added = git_commit_all(repo, "add key", DAY1)

    findings, rows = scan(repo)

    assert _by_tool(findings) == {tool: [("keys/live.pem", added)] for tool in TOOLS}
    assert {(r["tool"], r["state"], r["invocations"]) for r in rows} == {
        (tool, "ran", 2) for tool in TOOLS
    }


def test_history_is_excluded_like_the_tree(tmp_path, scan) -> None:
    """Keys committed under vendored trees and JMo's state directory, then
    deleted, so only history holds them. (A `results/` of the repository's
    own is not excluded: the results directory is, by name, only when this
    scan's output sits inside the tree.) trufflehog's git mode needs its own,
    unanchored patterns: its paths are repository-relative, and a pattern
    anchored below the scan root never matches one. This repository's own
    history cannot show it: a clone at 66b3ab49 has 0 such records with or
    without exclusions (measured)."""
    repo = tmp_path / "vendored"
    excluded = (
        "node_modules/pkg/k.pem",
        "src/vendor/k.pem",
        ".venv/k.pem",
        ".jmo/k.pem",
    )
    for rel in (*excluded, "kept.pem"):
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(generated_rsa_pem())
    added = git_commit_all(repo, "add keys", DAY1)
    for rel in (*excluded, "kept.pem"):
        (repo / rel).unlink()
    (repo / "app.py").write_bytes(b"print('hello')\n")
    git_commit_all(repo, "remove keys", DAY2)

    findings, _ = scan(repo)

    assert _by_tool(findings) == {tool: [("kept.pem", added)] for tool in TOOLS}


def test_a_key_rotated_in_place_is_two_findings(tmp_path, scan) -> None:
    """Old key in history, new key in the tree, same file and line: two
    secrets. Deduplicating them by location would hide the old one, which is
    still readable by anyone with the history.

    The new key names no commit, and that is the tools, measured: the
    rotation's diff keeps the unchanged `BEGIN`/`END` lines out of the added
    hunk, so neither tool's git mode sees a whole key in it. Only the first
    key, added whole, is found in history."""
    repo = tmp_path / "rotated"
    (repo / "keys").mkdir(parents=True)
    (repo / "keys" / "live.pem").write_bytes(generated_rsa_pem())
    first = git_commit_all(repo, "add key", DAY1)
    (repo / "keys" / "live.pem").write_bytes(generated_rsa_pem())
    git_commit_all(repo, "rotate key", DAY4)

    findings, _ = scan(repo)

    expected = sorted([("keys/live.pem", first), ("keys/live.pem", None)], key=str)
    assert _by_tool(findings) == dict.fromkeys(TOOLS, expected)
    assert len({f["id"] for f in findings}) == len(findings)
