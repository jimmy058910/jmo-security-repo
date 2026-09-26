"""G1's pieces, each alone (v2.0.0 Phase 3, PR C).

`tests/integration/test_git_history_secrets.py` runs the real binaries end to
end. These pin each seam without them, so a mutation of one is not hidden by
another: the second invocation and its gate on `.git`, its own exclusion
file, the row that covers both, the output file's name, what each adapter
reads from a history record, the pairing, and a history record's id.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

import pytest

from scripts.cli.scan_jobs import tool_loop
from scripts.cli.scan_utils import trufflehog_exclude_pattern
from scripts.core.adapters.gitleaks_adapter import GitleaksAdapter
from scripts.core.adapters.trufflehog_adapter import TruffleHogAdapter
from scripts.core.common_finding import fingerprint
from scripts.core.normalize_and_report import (
    _normalize_paths_and_ids,
    gather_results,
    pair_history_with_tree,
    tool_of_output,
)
from scripts.core.tool_descriptors import read_history
from scripts.core.tool_runner import ToolResult
from tests.conftest import git_commit_all

# A made-up value: these tests never need a real-looking secret.
SECRET = "not-a-secret-7f3a9c"
OTHER = "not-a-secret-0b41d2"
COMMIT = "8ededd62c61f4d3e7894f8990bd179e868f6b0a3"


# --- the invocations ------------------------------------------------------------


def _definitions(
    tmp_path: Path,
    tool: str,
    *,
    history: tuple[bool, str] = (True, ""),
    per_tool: dict | None = None,
    runner_results=None,
    folder: str = "repo",
):
    """`run_tools` with a recording runner. `history` stands in for the git
    probe, which `TestReadHistory` runs against real repositories."""
    from unittest.mock import patch

    repo = tmp_path / folder
    repo.mkdir(parents=True)
    (repo / "a.py").write_bytes(b"x = 1\n")
    out = tmp_path / "out"
    out.mkdir()
    captured: list = []

    class Recorder:
        def __init__(self, tools, progress_callback=None):
            captured.extend(tools)

        def run_all_parallel(self):
            return runner_results(captured) if runner_results else []

    with patch.object(tool_loop, "read_history", return_value=history):
        rows = tool_loop.run_tools(
            tools=[tool],
            target_type="repo",
            target=repo,
            target_label="repo",
            out_dir=out,
            timeout=60,
            retries=0,
            per_tool_config=per_tool or {},
            allow_missing_tools=False,
            runner_cls=Recorder,
            find_tool_func=lambda name: f"/bin/{name}",
            repo_root=repo,
        )
    return captured, rows, repo.resolve(), out


class TestTrufflehogInvocations:
    def test_without_readable_history_there_is_no_git_mode(self, tmp_path) -> None:
        (definition,), _, _, _ = _definitions(
            tmp_path, "trufflehog", history=(False, "")
        )
        assert definition.command[1] == "filesystem"

    def test_with_history_it_reads_it_too(self, tmp_path) -> None:
        definitions, _, root, out = _definitions(tmp_path, "trufflehog")

        assert [d.command[1] for d in definitions] == ["filesystem", "git"]
        history = definitions[1]
        # file://C:/x on Windows: file:///C:/x doubles the drive (measured).
        assert history.command[:6] == [
            "/bin/trufflehog",
            "git",
            "file://" + root.as_posix(),
            "--json",
            "--no-update",
            "--no-verification",
        ]
        assert history.output_file == out / "trufflehog.git.json"
        assert history.capture_stdout is True

    def test_the_url_escapes_what_a_url_would_read(self, tmp_path) -> None:
        """Unescaped, trufflehog cut the path at `#` and decoded `%41` to `A`,
        and the history run failed on every scan (measured, 3.97.1). A space
        worked either way; escaped, all of them work."""
        definitions, _, root, _ = _definitions(
            tmp_path, "trufflehog", folder="C#proj/pct%41x y"
        )
        url = definitions[1].command[2]

        assert url.endswith("/C%23proj/pct%2541x%20y")
        assert "#" not in url
        assert url.startswith("file://")

    def test_git_mode_gets_unanchored_patterns_and_filesystem_anchored(
        self, tmp_path
    ) -> None:
        """git mode reports repository-relative paths, so a pattern anchored
        below the scan root never matches there; filesystem mode matches the
        root's own path, so an unanchored one excludes a repository under
        `vendor/` entirely (B5)."""
        definitions, _, root, _ = _definitions(tmp_path, "trufflehog")

        def patterns(definition) -> list[str]:
            command = definition.command
            path = Path(command[command.index("--exclude-paths") + 1])
            return path.read_bytes().decode().splitlines()

        filesystem, history = (patterns(d) for d in definitions)
        assert trufflehog_exclude_pattern("node_modules") in history
        assert trufflehog_exclude_pattern("node_modules", str(root)) in filesystem
        assert trufflehog_exclude_pattern("node_modules") not in filesystem

    def test_verification_is_off_unless_asked_for(self, tmp_path) -> None:
        """Verification sends each candidate secret to its issuer; git mode
        multiplies the candidates (decided 2026-09-26: off by default)."""
        definitions, _, _, _ = _definitions(tmp_path, "trufflehog")
        assert all("--no-verification" in d.command for d in definitions)

    def test_verify_true_turns_it_back_on(self, tmp_path) -> None:
        definitions, _, _, _ = _definitions(
            tmp_path, "trufflehog", per_tool={"trufflehog": {"verify": True}}
        )
        assert len(definitions) == 2
        assert not any("--no-verification" in d.command for d in definitions)

    @pytest.mark.parametrize(
        "flags",
        [
            ["--only-verified"],
            ["--results=verified"],
            ["--results", "verified,unknown"],
        ],
    )
    def test_flags_asking_for_verified_results_keep_verification(
        self, tmp_path, flags
    ) -> None:
        """With `--no-verification`, nothing is verified, so a filter to
        verified results reports nothing, rc 0, row `ran` (measured). A user
        who asks for verified results has asked for verification."""
        definitions, _, _, _ = _definitions(
            tmp_path, "trufflehog", per_tool={"trufflehog": {"flags": flags}}
        )
        assert not any("--no-verification" in d.command for d in definitions)

    def test_unverified_results_do_not_ask_for_verification(self, tmp_path) -> None:
        definitions, _, _, _ = _definitions(
            tmp_path,
            "trufflehog",
            per_tool={"trufflehog": {"flags": ["--results=unknown,unverified"]}},
        )
        assert all("--no-verification" in d.command for d in definitions)


class TestGitleaksInvocations:
    def test_with_git_it_reads_history_from_the_repository(self, tmp_path) -> None:
        definitions, _, root, out = _definitions(tmp_path, "gitleaks")

        assert [d.command[1:3] for d in definitions] == [["dir", "."], ["git", "."]]
        assert {d.cwd for d in definitions} == {root}
        history = definitions[1]
        path = history.command[history.command.index("--report-path") + 1]
        assert path == str((out / "gitleaks.git.json").resolve())
        # The one config, so history has the same exclusions as the tree.
        configs = {d.command[d.command.index("--config") + 1] for d in definitions}
        assert len(configs) == 1

    def test_without_readable_history_one_invocation(self, tmp_path) -> None:
        definitions, _, _, _ = _definitions(tmp_path, "gitleaks", history=(False, ""))
        assert [d.command[1] for d in definitions] == ["dir"]


class TestReadHistory:
    """The one git probe per target, against real repositories."""

    def test_a_repository_with_its_history_is_read(self, tmp_path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.py").write_bytes(b"x = 1\n")
        git_commit_all(repo, "one", "2026-01-02T03:04:05Z")

        assert read_history(repo) == (True, "")

    def test_a_worktree_is_read(self, tmp_path) -> None:
        """Its `.git` is a file naming the gitdir."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.py").write_bytes(b"x = 1\n")
        git_commit_all(repo, "one", "2026-01-02T03:04:05Z")
        worktree = tmp_path / "wt"
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "add", "-q", str(worktree)],
            check=True,
            capture_output=True,
            timeout=60,
        )
        assert (worktree / ".git").is_file()

        assert read_history(worktree) == (True, "")

    def test_a_shallow_clone_is_not_read(self, tmp_path) -> None:
        """Its oldest commit holds the whole tree, so both tools name it as
        the commit, author and date that added every secret there (measured
        by the review: a `--depth 1` clone blamed whoever wrote HEAD). GitLab
        targets and `actions/checkout` both clone with depth 1."""
        origin = tmp_path / "origin"
        origin.mkdir()
        (origin / "a.py").write_bytes(b"x = 1\n")
        git_commit_all(origin, "one", "2026-01-02T03:04:05Z")
        (origin / "b.py").write_bytes(b"y = 2\n")
        git_commit_all(origin, "two", "2026-01-03T03:04:05Z")
        clone = tmp_path / "clone"
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1", origin.as_uri(), str(clone)],
            check=True,
            capture_output=True,
            timeout=60,
        )

        readable, why = read_history(clone)
        assert readable is False
        # The reason itself, not a fallback that happens to say "shallow".
        assert why.startswith("a shallow clone, whose oldest commit"), why

    def test_an_answer_git_should_not_give_is_not_read(self, tmp_path) -> None:
        """git before 2.15 does not know the option and echoes it back."""
        from unittest.mock import patch

        (tmp_path / ".git").mkdir()
        echoed = subprocess.CompletedProcess(
            [], 0, stdout="--is-shallow-repository\n", stderr=""
        )
        with patch("scripts.core.tool_descriptors.subprocess.run", return_value=echoed):
            readable, why = read_history(tmp_path)
        assert readable is False
        assert why.startswith("git could not tell whether it is a shallow clone"), why

    def test_a_git_that_cannot_be_read_says_why(self, tmp_path) -> None:
        """gitleaks' git mode exits 0 with "0 commits scanned" when git
        itself fails (measured by the review), so the row read `ran`: a
        broken gitdir here, "dubious ownership" in a container."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").write_bytes(b"gitdir: ../missing\n")

        readable, why = read_history(repo)
        assert readable is False
        assert why.startswith("git cannot read it:"), why

    def test_no_git_directory_is_no_history_and_nothing_to_say(self, tmp_path) -> None:
        assert read_history(tmp_path) == (False, "")

    def test_a_git_directory_that_cannot_be_checked_is_not_read(self, tmp_path) -> None:
        """Python 3.12 raises PermissionError from `exists()` where 3.11
        returned False (#1163): the tree is still scanned, history is not."""
        from unittest.mock import patch

        (tmp_path / ".git").mkdir()

        def denied(self, *args, **kwargs):
            raise PermissionError(13, "denied", str(self))

        # Patched only around the read: the suite's guards call exists() too.
        with patch.object(Path, "exists", denied):
            readable, why = read_history(tmp_path)
        assert readable is False
        assert why


def test_the_golden_generator_never_writes_the_digest(tmp_path) -> None:
    """`generate_golden` serialises findings with `asdict`, which includes
    every field: a fixture holding the digest would change on every run (its
    key is random per process), and nothing is meant to write it."""
    from scripts.dev.generate_golden import run_adapter

    path = tmp_path / "t.json"
    path.write_bytes(json.dumps(_trufflehog_fs_record(SECRET)).encode())
    config = {
        "adapter_module": "scripts.core.adapters.trufflehog_adapter",
        "adapter_class": "TruffleHogAdapter",
    }

    (found,) = run_adapter("trufflehog", config, path)
    assert "secretDigest" not in found
    assert found["location"]["path"] == "keys/live.pem"  # it did parse


def test_the_image_lets_git_read_a_mounted_repository() -> None:
    """A mounted repository belongs to another UID (the runner's 1001, the
    image runs as 1000), and git refuses it: measured in ubuntu:24.04, git
    2.43, rc 128 "detected dubious ownership"; with a system-wide
    `safe.directory '*'`, rc 0. Without it every scan in the image skips
    history (decided 2026-09-26). Written as root, before `USER jmo`."""
    dockerfile = (Path(__file__).resolve().parents[2] / "Dockerfile").read_text(
        encoding="utf-8"
    )
    runtime = dockerfile.split("AS runtime", 1)[1]
    line = "RUN git config --system --add safe.directory '*'"

    assert line in runtime
    assert runtime.index(line) < runtime.index("USER jmo")


def test_history_that_cannot_be_read_is_said_on_the_row(tmp_path, caplog) -> None:
    """The tree still ran, so the row is `ran`; the detail and a WARNING say
    that history did not."""
    with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_jobs.tool_loop"):
        _, rows, _, _ = _definitions(
            tmp_path,
            "gitleaks",
            history=(False, "a shallow clone"),
            runner_results=_results(fail_git=False),
        )
    row = rows["gitleaks"]
    assert (row.state.value, row.invocations) == ("ran", 1)
    assert row.detail == "history not read: a shallow clone"
    assert "git history not read (a shallow clone)" in caplog.text


# --- the row --------------------------------------------------------------------


def _results(fail_git: bool):
    def make(definitions) -> list[ToolResult]:
        out = []
        for d in definitions:
            history = "git" in d.command[1:2]
            failed = fail_git and history
            out.append(
                ToolResult(
                    tool=d.name,
                    status="error" if failed else "success",
                    returncode=2 if failed else 0,
                    output_file=d.output_file,
                    capture_stdout=d.capture_stdout,
                    stdout="" if failed else '{"from": "' + d.command[1] + '"}\n',
                    error_message="exit 2" if failed else "",
                    failure="crash" if failed else None,
                )
            )
        return out

    return make


def test_one_row_covers_both_invocations(tmp_path) -> None:
    _, rows, _, out = _definitions(
        tmp_path, "trufflehog", runner_results=_results(fail_git=False)
    )
    row = rows["trufflehog"]
    assert (row.state.value, row.invocations) == ("ran", 2)
    assert json.loads((out / "trufflehog.json").read_bytes()) == {"from": "filesystem"}
    assert json.loads((out / "trufflehog.git.json").read_bytes()) == {"from": "git"}


def test_a_failed_history_run_fails_the_row_and_keeps_the_tree_findings(
    tmp_path,
) -> None:
    """The row is `failed` and says which run failed; the run that worked
    still writes its output, so the tree's findings are not thrown away."""
    _, rows, _, out = _definitions(
        tmp_path, "trufflehog", runner_results=_results(fail_git=True)
    )
    row = rows["trufflehog"]
    assert row.state.value == "failed"
    # The runner's own message says nothing about which run it came from.
    assert row.detail == "git: exit 2", row.detail
    assert json.loads((out / "trufflehog.json").read_bytes()) == {"from": "filesystem"}


# --- the output file's name -----------------------------------------------------


@pytest.mark.parametrize(
    ("name", "tool"),
    [
        ("trufflehog.json", "trufflehog"),
        ("trufflehog.git.json", "trufflehog"),
        ("gitleaks.git.json", "gitleaks"),
        ("osv-scanner.json", "osv-scanner"),
    ],
)
def test_an_output_file_names_its_tool_before_the_first_dot(name, tool) -> None:
    assert tool_of_output(Path(name)) == tool


def test_the_report_reads_a_history_file_with_its_tools_adapter(
    tmp_path, caplog
) -> None:
    target = tmp_path / "individual-repos" / "app"
    target.mkdir(parents=True)
    (target / "trufflehog.git.json").write_bytes(
        (json.dumps(_trufflehog_git_record(SECRET)) + "\n").encode()
    )

    with caplog.at_level(logging.WARNING):
        findings = gather_results(tmp_path)

    assert [f["location"]["path"] for f in findings] == ["keys/live.pem"]
    assert "No adapter plugin found" not in caplog.text


# --- the adapters ---------------------------------------------------------------


def _trufflehog_git_record(raw: str, line: int = 1) -> dict:
    return {
        "SourceMetadata": {
            "Data": {
                "Git": {
                    "commit": COMMIT,
                    "file": "keys/live.pem",
                    "email": "Fixture Author <fixture@example.invalid>",
                    "repository": "file://C:/repo",
                    "timestamp": "2026-01-02 03:04:05 +0000",
                    "line": line,
                }
            }
        },
        "DetectorName": "PrivateKey",
        "Verified": False,
        "Raw": raw,
    }


def _trufflehog_fs_record(raw: str, line: int = 1) -> dict:
    return {
        "SourceMetadata": {
            "Data": {"Filesystem": {"file": "keys/live.pem", "line": line}}
        },
        "DetectorName": "PrivateKey",
        "Verified": False,
        "Raw": raw,
    }


def _parse_trufflehog(tmp_path: Path, *records: dict):
    path = tmp_path / "t.json"
    path.write_bytes("\n".join(json.dumps(r) for r in records).encode())
    return TruffleHogAdapter().parse(path)


class TestTrufflehogAdapter:
    def test_a_history_record_names_its_file_line_and_commit(self, tmp_path) -> None:
        (finding,) = _parse_trufflehog(tmp_path, _trufflehog_git_record(SECRET, 7))

        assert finding.location == {"path": "keys/live.pem", "startLine": 7}
        # ISO 8601, which the schema's date-time asks for; trufflehog's own
        # `2026-01-02 03:04:05 +0000` is not.
        assert finding.secretContext == {
            "commit": COMMIT,
            "author": "Fixture Author <fixture@example.invalid>",
            "date": "2026-01-02T03:04:05+00:00",
        }
        assert COMMIT in finding.message
        assert SECRET not in json.dumps(finding.to_dict())

    def test_a_tree_record_has_no_secret_context(self, tmp_path) -> None:
        (finding,) = _parse_trufflehog(tmp_path, _trufflehog_fs_record(SECRET))
        assert finding.secretContext is None

    def test_history_and_tree_ids_differ_at_one_location(self, tmp_path) -> None:
        """A key rotated in place: dedup by id must not fold the old key into
        the new one."""
        tree, history = _parse_trufflehog(
            tmp_path, _trufflehog_fs_record(OTHER), _trufflehog_git_record(SECRET)
        )
        assert tree.id != history.id

    def test_one_secret_has_one_digest_in_both_modes(self, tmp_path) -> None:
        tree, history, other = _parse_trufflehog(
            tmp_path,
            _trufflehog_fs_record(SECRET),
            _trufflehog_git_record(SECRET, 9),
            _trufflehog_fs_record(OTHER),
        )
        assert tree.secretDigest == history.secretDigest
        assert tree.secretDigest != other.secretDigest
        assert SECRET not in tree.secretDigest


def _sarif(*results: dict) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": list(results)}],
    }


def _gitleaks_result(snippet: str, commit: str = "") -> dict:
    return {
        "ruleId": "private-key",
        "message": {
            "text": "private-key has detected secret for file keys/live.pem"
            + (f" at commit {commit}." if commit else ".")
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "keys/live.pem"},
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
            "commitMessage": "add key" if commit else "",
        },
    }


def _parse_gitleaks(tmp_path: Path, *results: dict):
    path = tmp_path / "g.json"
    path.write_bytes(json.dumps(_sarif(*results)).encode())
    return GitleaksAdapter().parse(path)


class TestGitleaksAdapter:
    def test_a_history_result_names_its_commit(self, tmp_path) -> None:
        (finding,) = _parse_gitleaks(tmp_path, _gitleaks_result(SECRET, COMMIT))
        assert finding.secretContext == {
            "commit": COMMIT,
            "author": "Fixture Author <fixture@example.invalid>",
            "date": "2026-01-02T03:04:05Z",
        }

    def test_a_dir_result_has_none(self, tmp_path) -> None:
        """gitleaks writes the commit keys empty in dir mode (measured)."""
        (finding,) = _parse_gitleaks(tmp_path, _gitleaks_result(SECRET))
        assert finding.secretContext is None

    def test_one_secret_has_one_digest_in_both_modes(self, tmp_path) -> None:
        tree, history, other = _parse_gitleaks(
            tmp_path,
            _gitleaks_result(SECRET),
            _gitleaks_result(SECRET, COMMIT),
            _gitleaks_result(OTHER),
        )
        assert tree.secretDigest == history.secretDigest
        assert tree.secretDigest != other.secretDigest

    def test_the_commit_is_in_a_history_id_whatever_the_message_says(
        self, tmp_path
    ) -> None:
        """gitleaks names the commit in its message, but an id reads the
        message's first 120 characters: a long path pushes the commit out,
        and two commits' records would share an id."""
        long_path = "a/" * 60 + "k.pem"
        first, second = (
            _gitleaks_result(SECRET, commit) for commit in ("1" * 40, "2" * 40)
        )
        for result in (first, second):
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
                long_path
            )
            result["message"]["text"] = (
                f"private-key has detected secret for file {long_path} at commit "
                + result["partialFingerprints"]["commitSha"]
            )
        a, b = _parse_gitleaks(tmp_path, first, second)
        assert a.id != b.id


# --- the pairing ----------------------------------------------------------------


def _f(tool, digest, *, commit=None, date=None, path="keys/live.pem", line=1):
    finding = {
        "id": f"{tool}-{digest}-{commit}-{line}",
        "tool": {"name": tool},
        "ruleId": "private-key",
        "location": {"path": path, "startLine": line},
        "secretDigest": digest,
    }
    if commit:
        finding["secretContext"] = {"commit": commit, "author": "A", "date": date}
    return finding


class TestPairing:
    def test_a_tree_finding_takes_its_history_records_commit(self) -> None:
        tree = _f("gitleaks", "d1", line=2)
        history = _f("gitleaks", "d1", commit="c1", date="2026-01-02T03:04:05Z")

        (kept,) = pair_history_with_tree([history, tree])

        assert kept["id"] == tree["id"]  # the tree's id and location stay
        assert kept["location"]["startLine"] == 2
        assert kept["secretContext"]["commit"] == "c1"

    def test_the_earliest_commit_is_the_one_that_added_it(self) -> None:
        # 22:00 UTC on the 2nd.
        later = _f("gitleaks", "d1", commit="c2", date="2026-01-02T22:00:00+00:00")
        # 20:00 UTC on the 2nd: earlier in time, though later as a string.
        earlier = _f("gitleaks", "d1", commit="c1", date="2026-01-03T01:00:00+05:00")
        tree = _f("gitleaks", "d1")

        (kept,) = pair_history_with_tree([later, tree, earlier])
        assert kept["secretContext"]["commit"] == "c1"

    def test_history_records_of_one_deleted_key_collapse_to_the_earliest(self) -> None:
        a = _f("trufflehog", "d1", commit="c1", date="2026-01-02T00:00:00Z")
        b = _f("trufflehog", "d1", commit="c2", date="2026-01-05T00:00:00Z")

        (kept,) = pair_history_with_tree([b, a])
        assert kept["secretContext"]["commit"] == "c1"

    def test_two_identical_history_records_leave_one(self) -> None:
        """Dropped by identity: two records can be equal dicts, and an
        equality test would keep both."""
        a = _f("trufflehog", "d1", commit="c1", date="2026-01-02T00:00:00Z")
        b = dict(a, secretContext=dict(a["secretContext"]))
        assert a == b

        assert len(pair_history_with_tree([a, b])) == 1

    def test_a_date_with_no_offset_is_read_as_utc(self) -> None:
        naive = _f("gitleaks", "d1", commit="c1", date="2026-01-02T00:00:00")
        aware = _f("gitleaks", "d1", commit="c2", date="2026-01-03T00:00:00+00:00")

        (kept,) = pair_history_with_tree([aware, naive])
        assert kept["secretContext"]["commit"] == "c1"

    def test_a_date_that_does_not_parse_sorts_last(self) -> None:
        bad = _f("gitleaks", "d1", commit="c0", date="yesterday")
        good = _f("gitleaks", "d1", commit="c1", date="2026-01-03T00:00:00+00:00")

        (kept,) = pair_history_with_tree([bad, good])
        assert kept["secretContext"]["commit"] == "c1"

    def test_a_different_secret_is_not_paired(self) -> None:
        tree = _f("gitleaks", "new")
        old = _f("gitleaks", "old", commit="c1", date="2026-01-02T00:00:00Z")
        assert len(pair_history_with_tree([tree, old])) == 2

    @pytest.mark.parametrize(
        "other",
        [
            {"tool": "trufflehog"},
            {"path": "other.pem"},
            {"rule": "jwt"},
        ],
    )
    def test_pairs_only_within_one_tool_rule_and_path(self, other) -> None:
        tree = _f("gitleaks", "d1")
        history = _f(
            other.get("tool", "gitleaks"),
            "d1",
            commit="c1",
            date="2026-01-02T00:00:00Z",
            path=other.get("path", "keys/live.pem"),
        )
        if "rule" in other:
            history["ruleId"] = other["rule"]
        assert len(pair_history_with_tree([tree, history])) == 2

    def test_the_digest_never_leaves_the_report_phase(self) -> None:
        findings = [
            _f("gitleaks", "d1"),
            _f("gitleaks", "d2", commit="c1", date="2026-01-02T00:00:00Z"),
            {"id": "x", "tool": {"name": "trivy"}, "location": {"path": "a"}},
        ]
        kept = pair_history_with_tree(findings)
        assert len(kept) == 3
        assert not any("secretDigest" in f for f in kept)


# --- a history record's id --------------------------------------------------------


def test_the_commit_joins_the_id_only_when_given() -> None:
    base = fingerprint("gitleaks", "private-key", "k.pem", 1, "m", start_column=1)
    assert (
        fingerprint("gitleaks", "private-key", "k.pem", 1, "m", 1, commit=None) == base
    )
    assert (
        fingerprint("gitleaks", "private-key", "k.pem", 1, "m", 1, commit="c") != base
    )


def test_path_normalisation_rekeys_a_history_id_with_its_commit() -> None:
    """The re-key only fires when the old id can be reproduced (#861); one
    keyed on its commit is reproduced with it, so it is re-keyed rather than
    left carrying the old path."""
    old_path = "C:/scan/app/keys/live.pem"
    finding = {
        "id": fingerprint("trufflehog", "PrivateKey", old_path, 1, "m", commit=COMMIT),
        "tool": {"name": "trufflehog"},
        "ruleId": "PrivateKey",
        "message": "m",
        "location": {"path": old_path, "startLine": 1},
        "secretContext": {"commit": COMMIT},
    }

    _normalize_paths_and_ids([finding], ("C:/scan/app",))

    assert finding["location"]["path"] == "keys/live.pem"
    assert finding["id"] == fingerprint(
        "trufflehog", "PrivateKey", "keys/live.pem", 1, "m", commit=COMMIT
    )
