#!/usr/bin/env python3
"""One target, one name, one folder (#1315, #1312).

A target's accounting rows live in three places: its ``scan-timings.json``, the
``tool_runs`` of ``.scan_metadata.json``, and history's ``scan_tool_runs``.
PR B's review found them naming one target differently (#1315). Every job but
the repository one handed ``run_tools`` a folder-safe label (``nginx_latest``)
while returning the target's identity (``nginx:latest``); a GitLab clone
recorded its clone folder (``app``) for ``group/app``; an IaC scanner that
raised was recorded under the file's path, where success records
``terraform:main.tf``; and ``--repo .`` was named ``unknown``. A history query
grouping by target split each of them in two.

Its sibling (#1312): URL and IaC targets took their results folder from
something two targets can share, the host and the file's stem, so two targets
wrote into one folder and the last writer's output stood for both.

These run the real scan jobs through ``jmo scan``. Only the tool runner is
fake: every invocation "succeeds" and writes the file it was told to, naming
the command it was given, so an overwritten file names the wrong target.
Mocking a job instead would hide the defect: a mocked job returns whatever
name the test chose.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.core.tool_runner import ToolResult
from scripts.dev.reconcile_scan_accounting import reconcile
from tests.conftest import unix_only

JOB_MODULES = (
    "repository_scanner",
    "image_scanner",
    "iac_scanner",
    "url_scanner",
    "k8s_scanner",
)


class _WritingRunner:
    """Stands in for `ToolRunner`: every invocation succeeds and writes its
    output file, naming the command it was given."""

    def __init__(self, tools, progress_callback=None):
        self._definitions = tools

    def run_all_parallel(self) -> list[ToolResult]:
        results = []
        for d in self._definitions:
            if d.output_file is not None:
                d.output_file.write_bytes(json.dumps({"command": d.command}).encode())
            results.append(
                ToolResult(
                    tool=d.name,
                    status="success",
                    returncode=0,
                    output_file=d.output_file,
                )
            )
        return results


_real_run = subprocess.run


def _clone_or_run(cmd, *args, **kwargs):
    """`git clone` makes a one-file repository where it was told to; anything
    else runs for real (history's git context calls `git` too)."""
    if list(cmd[:2]) == ["git", "clone"]:
        clone = Path(cmd[-1])
        clone.mkdir(parents=True)
        (clone / "README.md").write_bytes(b"# app\n")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")
    return _real_run(cmd, *args, **kwargs)


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    """`jmo scan` in `tmp_path`, with a repository `myproj` holding a README
    and IaC files, and every tool resolving to the writing runner.

    The pre-flight and the update check are pinned for the reasons
    `test_scan_runtime_accounting.scan_env` gives; `Path.home()` is redirected
    because `cmd_scan` writes the Ko-fi counter there.
    """
    project = tmp_path / "myproj"
    project.mkdir()
    (project / "README.md").write_bytes(b"# myproj\n")
    for name in ("main.tf", "main.json", "main.yaml"):
        (project / name).write_bytes(b"{}\n")
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
        lambda name, *a, **k: "/usr/bin/" + name,
    )
    for module in JOB_MODULES:
        monkeypatch.setattr(
            f"scripts.cli.scan_jobs.{module}.ToolRunner", _WritingRunner
        )
    monkeypatch.setattr(
        "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run", _clone_or_run
    )

    results = tmp_path / "results"
    db = tmp_path / "history.db"

    def run(*argv: str) -> int:
        full = [
            "jmo",
            "scan",
            *argv,
            "--results-dir",
            str(results),
            "--config",
            str(cfg),
            "--history-db",
            str(db),
        ]
        with patch.object(sys, "argv", full):
            args = jmo.parse_args()
        return jmo.cmd_scan(args)

    return types.SimpleNamespace(run=run, results=results, db=db, project=project)


def _timings(results: Path) -> dict[str, tuple[str, str]]:
    """Each target's folder, relative to the results root, and the
    (target_type, target) its scan-timings.json records."""
    found = {}
    for doc in results.glob("individual-*/*/scan-timings.json"):
        data = json.loads(doc.read_bytes())
        found[doc.parent.relative_to(results).as_posix()] = (
            data["target_type"],
            data["target"],
        )
    return found


def _tool_runs(results: Path) -> list[tuple[str, str, str]]:
    meta = json.loads((results / ".scan_metadata.json").read_bytes())
    return sorted((r["target_type"], r["target"], r["tool"]) for r in meta["tool_runs"])


def _history(db: Path) -> list[tuple[str, str, str]]:
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        return sorted(
            con.execute("SELECT target_type, target, tool FROM scan_tool_runs")
        )
    finally:
        con.close()


def _scan_row(db: Path) -> tuple[list[str], set[str], str | None]:
    """History's one `scans` row: its targets, the table's columns, its branch."""
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        targets, branch = con.execute("SELECT targets, branch FROM scans").fetchone()
        columns = {row[1] for row in con.execute("PRAGMA table_info(scans)")}
    finally:
        con.close()
    return json.loads(targets), columns, branch


class TestOneTargetOneName:
    """#1315: scan-timings.json, tool_runs and scan_tool_runs agree."""

    @pytest.mark.parametrize(
        ("argv", "folder", "expected"),
        [
            pytest.param(
                ["--image", "nginx:latest", "--tools", "trivy"],
                "individual-images/nginx_latest",
                ("image", "nginx:latest"),
                id="image",
            ),
            pytest.param(
                ["--url", "http://staging.example.com/app1", "--tools", "zap"],
                "individual-web/staging.example.com",
                ("url", "http://staging.example.com/app1"),
                id="url",
            ),
            pytest.param(
                ["--terraform-state", "myproj/main.tf", "--tools", "trivy"],
                "individual-iac/main",
                ("iac", "terraform:main.tf"),
                id="iac",
            ),
            pytest.param(
                ["--gitlab-repo", "group/app", "--gitlab-token", "t"]
                + ["--gitlab-url", "https://gitlab.example.com"]
                + ["--tools", "trufflehog"],
                "individual-gitlab/group_app",
                ("gitlab", "group/app"),
                id="gitlab",
            ),
            pytest.param(
                ["--k8s-context", "ctx", "--k8s-namespace", "ns", "--tools", "trivy"],
                "individual-k8s/ctx_ns",
                ("k8s", "ctx:ns"),
                id="k8s",
            ),
        ],
    )
    def test_every_record_names_the_target_alike(self, env, argv, folder, expected):
        assert env.run(*argv) == 0

        tool = argv[-1]
        assert _timings(env.results) == {folder: expected}
        assert _tool_runs(env.results) == [(*expected, tool)]
        assert _history(env.db) == [(*expected, tool)]
        # The acceptance instrument agrees, now that it compares per target.
        assert reconcile(env.results).ok

    def test_repo_dot_is_named_after_the_directory(self, env, monkeypatch):
        """`Path(".").name` is `""`, which sanitized to `unknown`: the folder,
        the rows and history all said so."""
        monkeypatch.chdir(env.project)

        assert env.run("--repo", ".", "--tools", "trufflehog") == 0

        expected = ("repo", "myproj")
        assert _timings(env.results) == {"individual-repos/myproj": expected}
        assert _tool_runs(env.results) == [(*expected, "trufflehog")]
        assert _history(env.db) == [(*expected, "trufflehog")]

    @unix_only
    def test_a_symlinked_repository_keeps_the_name_it_was_given(self, env, tmp_path):
        """Named through `abspath`, not `resolve`: `--repo link` to `myproj`
        is `link`, the name the user typed, not its target's."""
        (tmp_path / "link").symlink_to(env.project, target_is_directory=True)

        assert env.run("--repo", "link", "--tools", "trufflehog") == 0

        assert _timings(env.results) == {"individual-repos/link": ("repo", "link")}

    @pytest.mark.parametrize(
        ("key", "scanned"), [("include", True), ("exclude", False)]
    )
    def test_repo_dot_is_filtered_by_the_name_it_is_recorded_under(
        self, env, tmp_path, monkeypatch, key, scanned
    ):
        """`include`/`exclude` matched `Path(".").name`, which is "":
        `include: [myproj]` found nothing to scan, and `exclude: [myproj]`
        scanned the repository it names."""
        (tmp_path / "jmo.yml").write_bytes(
            yaml.safe_dump({"outputs": ["json"], key: ["myproj"]}).encode()
        )
        monkeypatch.chdir(env.project)

        rc = env.run("--repo", ".", "--tools", "trufflehog")

        if scanned:
            assert rc == 0
            assert _timings(env.results) == {
                "individual-repos/myproj": ("repo", "myproj")
            }
        else:
            assert _timings(env.results) == {}

    def test_an_iac_scanner_that_raises_keeps_the_name_success_records(
        self, env, monkeypatch
    ):
        """The except path recorded `str(iac_path)`; success records
        `terraform:main.tf`. The repository is there so a tool runs and the
        scan reaches history."""

        def explode(*args, **kwargs):
            raise RuntimeError("scanner exploded")

        monkeypatch.setattr("scripts.cli.scan_jobs.scan_iac_file", explode)

        env.run(
            "--repo",
            "myproj",
            "--terraform-state",
            "myproj/main.tf",
            "--tools",
            "trufflehog,trivy",
        )

        expected = [
            ("iac", "terraform:main.tf", "trivy"),
            ("iac", "terraform:main.tf", "trufflehog"),
            ("repo", "myproj", "trivy"),
            ("repo", "myproj", "trufflehog"),
        ]
        assert _tool_runs(env.results) == expected
        assert _history(env.db) == expected


class TestHistoryListsEveryTarget:
    """#1321: the fourth record. History's `scans` row typed every scan `repo`
    and listed only `individual-repos`' folders, since
    `setup_results_directories` always creates that folder: an image scan was
    `repo` with no targets. The row now lists the targets its own rows name,
    and `scans.target_type` is gone: a scan of two types has no one type, and
    `scan_tool_runs` types each target."""

    @pytest.mark.parametrize(
        ("argv", "expected"),
        [
            pytest.param(
                ["--image", "nginx:latest", "--tools", "trivy"],
                ["nginx:latest"],
                id="image",
            ),
            pytest.param(
                ["--url", "http://h.test/b", "--tools", "zap"],
                ["http://h.test/b"],
                id="url",
            ),
            pytest.param(
                ["--repo", "myproj", "--image", "nginx:latest", "--tools", "trivy"],
                ["myproj", "nginx:latest"],
                id="mixed",
            ),
        ],
    )
    def test_the_scan_row_names_every_target(self, env, argv, expected):
        assert env.run(*argv) == 0

        targets, columns, _ = _scan_row(env.db)
        assert sorted(targets) == expected
        assert sorted({target for _t, target, _tool in _history(env.db)}) == expected
        assert "target_type" not in columns

    def test_a_repository_among_other_types_still_records_its_branch(self, env):
        """The git context was read only when the scan was typed `repo`. It
        reads the repositories the scan visited, which only a repository
        target records."""
        git = ["git", "-C", str(env.project)]
        identity = ["-c", "user.name=t", "-c", "user.email=t@example.com"]
        for cmd in (
            [*git, "init", "-q", "-b", "b3-branch"],
            [*git, "add", "-A"],
            [*git, *identity, "commit", "-q", "-m", "init"],
        ):
            subprocess.run(cmd, check=True, capture_output=True, timeout=60)

        assert (
            env.run("--repo", "myproj", "--image", "nginx:latest", "--tools", "trivy")
            == 0
        )

        assert _scan_row(env.db)[2] == "b3-branch"


class TestOneTargetOneFolder:
    """#1312: two targets never share a results folder."""

    @staticmethod
    def _own_output(results: Path, tool: str) -> dict[str, list[str]]:
        """Each target (by its timings document) and the command recorded in
        the tool output beside it."""
        return {
            target: json.loads((results / folder / f"{tool}.json").read_bytes())[
                "command"
            ]
            for folder, (_type, target) in _timings(results).items()
        }

    def test_two_urls_on_one_host_keep_their_own_results(self, env, tmp_path):
        app1 = "http://staging.example.com/app1"
        app2 = "http://staging.example.com/app2"
        urls = tmp_path / "urls.txt"
        urls.write_bytes(f"{app1}\n{app2}\n".encode())

        assert env.run("--urls-file", str(urls), "--tools", "zap") == 0

        written = self._own_output(env.results, "zap")
        assert sorted(written) == [app1, app2], "one folder held both targets"
        for url, command in written.items():
            assert any(url in part for part in command), (url, command)
        assert sorted(_timings(env.results)) == [
            "individual-web/staging.example.com",
            "individual-web/staging.example.com-2",
        ]

    def test_two_images_that_sanitize_alike_keep_their_own_results(self, env, tmp_path):
        """`/` and `:` both become `_`, so two valid references share a
        folder name."""
        images = tmp_path / "images.txt"
        images.write_bytes(b"registry/app:1\nregistry_app:1\n")

        assert env.run("--images-file", str(images), "--tools", "trivy") == 0

        written = self._own_output(env.results, "trivy")
        assert sorted(written) == ["registry/app:1", "registry_app:1"]
        for image, command in written.items():
            assert image in command, (image, command)
        assert sorted(_timings(env.results)) == [
            "individual-images/registry_app_1",
            "individual-images/registry_app_1-2",
        ]

    def test_two_iac_files_with_one_stem_keep_their_own_results(self, env):
        assert (
            env.run(
                "--cloudformation",
                "myproj/main.json",
                "--k8s-manifest",
                "myproj/main.yaml",
                "--tools",
                "trivy",
            )
            == 0
        )

        written = self._own_output(env.results, "trivy")
        assert sorted(written) == ["cloudformation:main.json", "k8s:main.yaml"]
        for target, command in written.items():
            file_name = target.partition(":")[2]
            assert any(part.endswith(file_name) for part in command), (target, command)
        # Each flag takes one file, so a shared stem is two types: the type
        # tells the folders apart where a counter would not.
        assert sorted(_timings(env.results)) == [
            "individual-iac/cloudformation__main",
            "individual-iac/k8s__main",
        ]

    @pytest.mark.parametrize(
        ("flag", "file_flag", "value", "tool"),
        [
            ("--url", "--urls-file", "http://staging.example.com/app1", "zap"),
            ("--image", "--images-file", "nginx:latest", "trivy"),
        ],
    )
    def test_a_target_listed_twice_is_scanned_once(
        self, env, tmp_path, flag, file_flag, value, tool
    ):
        """Two targets with one name would put two rows per tool under that
        name. Scanning it twice finds nothing the first scan did not."""
        listing = tmp_path / "targets.txt"
        listing.write_bytes(f"{value}\n".encode())

        assert env.run(flag, value, file_flag, str(listing), "--tools", tool) == 0

        target_type = "url" if flag == "--url" else "image"
        assert _tool_runs(env.results) == [(target_type, value, tool)]
        assert len(_timings(env.results)) == 1


class TestTheSessionKnowsEveryTarget:
    """`cmd_scan` registers each target in the resume session under an id,
    and `scan_all` checkpoints it under an id it derives again. An id the two
    derive differently is never marked complete (`mark_target_complete`
    ignores an id it does not know), so `--resume` scans that target again,
    and nothing says so. IaC was registered by path and checkpointed by
    `terraform:main.tf` once #1315 named it one way."""

    def test_every_registered_target_is_checkpointed_under_its_name(
        self, env, monkeypatch
    ):
        from scripts.cli import scan_session

        real_save = scan_session.save_session
        last: dict[str, bool] = {}

        def recording_save(session, path):
            last.clear()
            last.update({tid: t.completed for tid, t in session.targets.items()})
            real_save(session, path)

        monkeypatch.setattr(scan_session, "save_session", recording_save)

        env.run(
            "--repo",
            "myproj",
            "--image",
            "nginx:latest",
            "--terraform-state",
            "myproj/main.tf",
            "--url",
            "http://staging.example.com/app1",
            "--gitlab-repo",
            "group/app",
            "--gitlab-token",
            "t",
            "--gitlab-url",
            "https://gitlab.example.com",
            "--k8s-context",
            "ctx",
            "--k8s-namespace",
            "ns",
            "--tools",
            "trufflehog,trivy,zap",
        )

        assert last == {
            "myproj": True,
            "nginx:latest": True,
            "terraform:main.tf": True,
            "http://staging.example.com/app1": True,
            "group/app": True,
            "ctx:ns": True,
        }
        assert {target for _type, target, _tool in _tool_runs(env.results)} == set(last)


class TestAGitLabCloneIsNormalisedLikeARepository:
    """#1332: the report makes paths repository-relative against the roots
    the scan recorded, and only `--repo` targets were recorded. A GitLab
    target is cloned into a random temporary directory, so its findings kept
    the host's temp path, and their ids changed on every scan."""

    class _TrufflehogRunner(_WritingRunner):
        """Writes what trufflehog filesystem does: the absolute path under
        the root it was given."""

        def run_all_parallel(self) -> list[ToolResult]:
            results = []
            for d in self._definitions:
                record = {
                    "SourceMetadata": {
                        "Data": {"Filesystem": {"file": f"{d.command[2]}/secret.txt"}}
                    },
                    "DetectorName": "Generic",
                    "Verified": False,
                    "Raw": "not-a-secret-1332",
                }
                d.output_file.write_bytes((json.dumps(record) + "\n").encode())
                results.append(
                    ToolResult(
                        tool=d.name,
                        status="success",
                        returncode=0,
                        output_file=d.output_file,
                    )
                )
            return results

    def test_its_findings_are_relative_and_keep_their_id(self, env, monkeypatch):
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.repository_scanner.ToolRunner",
            self._TrufflehogRunner,
        )
        seen = []
        for _ in range(2):
            assert (
                env.run(
                    "--gitlab-repo",
                    "group/app",
                    "--gitlab-token",
                    "t",
                    "--gitlab-url",
                    "https://gitlab.example.com",
                    "--tools",
                    "trufflehog",
                )
                == 0
            )
            document = json.loads(
                (env.results / "summaries" / "findings.json").read_bytes()
            )
            (finding,) = document["findings"]
            seen.append((finding["location"]["path"], finding["id"]))

        assert seen[0][0] == "secret.txt", seen
        assert seen[0] == seen[1], seen


def _clone_holding(files: dict[str, bytes], clones: list[Path] | None = None):
    """`git clone` makes a repository holding `files` where it was told to,
    and records where; anything else runs for real."""

    def run(cmd, *args, **kwargs):
        if list(cmd[:2]) == ["git", "clone"]:
            clone = Path(cmd[-1])
            clone.mkdir(parents=True)
            for name, body in files.items():
                (clone / name).write_bytes(body)
            if clones is not None:
                clones.append(clone)
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        return _real_run(cmd, *args, **kwargs)

    return run


GITLAB = ["--gitlab-repo", "group/app", "--gitlab-token", "t"] + [
    "--gitlab-url",
    "https://gitlab.example.com",
]


class TestAGitLabTargetScansTheImagesItNames:
    """#1311: a GitLab target discovered the images its repository names and
    scanned none. Every call raised TypeError into an except, and what it
    would have written went to a temporary directory deleted with the clone.
    Each image it names is now an image target of its own."""

    def test_each_named_image_is_an_image_target_with_its_own_rows(
        self, env, monkeypatch
    ):
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
            _clone_holding({"Dockerfile": b"FROM alpine:3.19\n"}),
        )

        assert env.run(*GITLAB, "--tools", "trivy,syft") == 0

        folder = "individual-images/group_app__alpine_3.19"
        assert _timings(env.results) == {
            "individual-gitlab/group_app": ("gitlab", "group/app"),
            folder: ("image", "alpine:3.19"),
        }
        expected = [
            (target_type, target, tool)
            for target_type, target in (
                ("gitlab", "group/app"),
                ("image", "alpine:3.19"),
            )
            for tool in ("syft", "trivy")
        ]
        assert _tool_runs(env.results) == expected
        assert _history(env.db) == expected
        assert reconcile(env.results).ok
        # Each tool was pointed at the image, not at the clone.
        for tool in ("syft", "trivy"):
            output = env.results / folder / f"{tool}.json"
            assert "alpine:3.19" in json.loads(output.read_bytes())["command"]

    def test_the_image_has_the_rows_an_image_target_has(self, env, monkeypatch):
        """One image target, one behaviour, whatever named it: every requested
        tool, with the one that reads no image skipped as `--image` skips it."""
        tools = "trivy,syft,hadolint"
        assert env.run("--image", "alpine:3.19", "--tools", tools) == 0
        meta = json.loads((env.results / ".scan_metadata.json").read_bytes())
        as_image = {r["tool"]: (r["state"], r["reason"]) for r in meta["tool_runs"]}

        monkeypatch.setattr(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
            _clone_holding({"Dockerfile": b"FROM alpine:3.19\n"}),
        )
        assert env.run(*GITLAB, "--tools", tools) == 0
        meta = json.loads((env.results / ".scan_metadata.json").read_bytes())
        named = {
            r["tool"]: (r["state"], r["reason"])
            for r in meta["tool_runs"]
            if r["target_type"] == "image"
        }

        assert named == as_image
        assert as_image["hadolint"][0] == "skipped"

    def test_an_image_no_registry_serves_is_a_failed_row_naming_it(
        self, env, monkeypatch
    ):
        """What trivy and syft say about a reference they cannot pull, on that
        image's own rows: the repository's rows and the scan go on."""
        missing = "registry.example.invalid/private/app:1.0"

        class _NoSuchImage(_WritingRunner):
            def run_all_parallel(self) -> list[ToolResult]:
                return [
                    ToolResult(
                        tool=d.name,
                        status="error",
                        returncode=1,
                        failure="crash",
                        output_file=d.output_file,
                        error_message=f"unable to find the specified image {missing}",
                    )
                    for d in self._definitions
                ]

        monkeypatch.setattr(
            "scripts.cli.scan_jobs.image_scanner.ToolRunner", _NoSuchImage
        )
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
            _clone_holding({"Dockerfile": f"FROM {missing}\n".encode()}),
        )

        # 1, as for `--image` with that reference: a target produced nothing.
        assert env.run(*GITLAB, "--tools", "trivy,syft") == 1

        meta = json.loads((env.results / ".scan_metadata.json").read_bytes())
        rows = {
            (r["target_type"], r["target"], r["tool"]): r for r in meta["tool_runs"]
        }
        for tool in ("trivy", "syft"):
            assert rows[("gitlab", "group/app", tool)]["state"] == "ran"
            image_row = rows[("image", missing, tool)]
            assert (image_row["state"], image_row["reason"]) == (
                "failed",
                "unaccepted exit code",
            )
            assert missing in image_row["detail"]
        assert reconcile(env.results).ok

    def test_a_project_named_results_is_not_scanned_with_its_own_results(
        self, env, monkeypatch
    ):
        """#1364: `group/results` was cloned to `<tmp>/results`, the directory
        its scan then wrote to, so every tool's output landed in the tree the
        tools were reading."""
        clones: list[Path] = []
        written: list[Path] = []

        class _Recording(_WritingRunner):
            def run_all_parallel(self) -> list[ToolResult]:
                written.extend(d.output_file for d in self._definitions)
                return super().run_all_parallel()

        monkeypatch.setattr(
            "scripts.cli.scan_jobs.repository_scanner.ToolRunner", _Recording
        )
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
            _clone_holding({"README.md": b"# results\n"}, clones),
        )

        rc = env.run(
            "--gitlab-repo",
            "group/results",
            "--gitlab-token",
            "t",
            "--gitlab-url",
            "https://gitlab.example.com",
            "--tools",
            "trufflehog,trivy",
        )

        assert rc == 0
        (clone,) = clones
        assert written, "no tool ran"
        inside = [p for p in written if clone in p.parents]
        assert not inside, f"outputs written inside the clone {clone}: {inside}"
        assert _timings(env.results) == {
            "individual-gitlab/group_results": ("gitlab", "group/results")
        }

    def test_two_images_that_sanitize_alike_keep_their_own_results(
        self, env, monkeypatch
    ):
        """`/` and `:` both become `_`: one repository naming both would put
        both images in one folder, and the last writer stood for both (#1312)."""
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
            _clone_holding(
                {
                    "Dockerfile": b"FROM registry/app:1\n",
                    "web.Dockerfile": b"FROM registry_app:1\n",
                }
            ),
        )

        assert env.run(*GITLAB, "--tools", "trivy") == 0

        images = {
            folder: target
            for folder, (target_type, target) in _timings(env.results).items()
            if target_type == "image"
        }
        assert images == {
            "individual-images/group_app__registry_app_1": "registry/app:1",
            "individual-images/group_app__registry_app_1-2": "registry_app:1",
        }
        for folder, image in images.items():
            output = env.results / folder / "trivy.json"
            assert image in json.loads(output.read_bytes())["command"]

    def test_an_image_the_scan_already_scans_is_scanned_once(self, env, monkeypatch):
        """Two targets with one name put two rows per tool under it (#1312):
        the reconciler fails the scan and history keeps one of them."""
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
            _clone_holding({"Dockerfile": b"FROM alpine:3.19\n"}),
        )

        assert env.run(*GITLAB, "--image", "alpine:3.19", "--tools", "trivy") == 0

        assert _tool_runs(env.results) == [
            ("gitlab", "group/app", "trivy"),
            ("image", "alpine:3.19", "trivy"),
        ]
        assert sorted(_timings(env.results)) == [
            "individual-gitlab/group_app",
            "individual-images/alpine_3.19",
        ]
        assert reconcile(env.results).ok


def _gitlab_target(full_path: str) -> dict[str, str]:
    """What `_discover_gitlab_repos` builds for `--gitlab-repo`."""
    group, _, repo = full_path.partition("/")
    return {
        "full_path": full_path,
        "url": "https://gitlab.example.com",
        "token": "t",
        "repo": repo,
        "group": group,
        "name": full_path.replace("/", "_"),
    }


class TestTheScanRecordsAndResumesTheImagesItFound:
    """The orchestrator's side of #1311: an image a GitLab target names is
    found mid-scan, so no target list and no session registration knows it
    beforehand. It must still be one target in the results, checkpointed,
    and reported, not rescanned, by a resumed scan."""

    def test_two_gitlab_targets_naming_one_image_scan_it_once(self, env, monkeypatch):
        from scripts.cli.scan_orchestrator import (
            ScanConfig,
            ScanOrchestrator,
            ScanTargets,
        )

        monkeypatch.setattr(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
            _clone_holding({"Dockerfile": b"FROM alpine:3.19\n"}),
        )
        orchestrator = ScanOrchestrator(
            ScanConfig(results_dir=env.results, tools=["trivy"])
        )
        targets = ScanTargets(
            gitlab_repos=[_gitlab_target("group/app"), _gitlab_target("group/web")]
        )
        orchestrator.setup_results_directories(targets)

        results = orchestrator.scan_all(targets, {})

        assert sorted((t, name) for t, name, _rows in results) == [
            ("gitlab", "group/app"),
            ("gitlab", "group/web"),
            ("image", "alpine:3.19"),
        ]
        assert len(list(env.results.glob("individual-images/*"))) == 1

    def test_a_found_image_is_checkpointed_and_a_resume_reports_it(
        self, env, monkeypatch
    ):
        from scripts.cli.scan_orchestrator import (
            ScanConfig,
            ScanOrchestrator,
            ScanTargets,
        )
        from scripts.cli.scan_session import ScanSession, load_session

        monkeypatch.setattr(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run",
            _clone_holding({"Dockerfile": b"FROM alpine:3.19\n"}),
        )
        tools = ["trivy", "syft"]
        orchestrator = ScanOrchestrator(
            ScanConfig(results_dir=env.results, tools=tools)
        )
        targets = ScanTargets(gitlab_repos=[_gitlab_target("group/app")])
        path = env.results.parent / "session.json"
        session = ScanSession(session_id="s", config_hash="h", started_at=0.0, pid=1)
        session.register_target("gitlab", "group/app", tools)
        orchestrator.setup_results_directories(targets)

        first = orchestrator.scan_all(targets, {}, session=session, session_path=path)

        saved = load_session(path)
        assert saved is not None
        record = saved.targets["alpine:3.19"]
        assert (record.target_type, record.completed, record.found_in) == (
            "image",
            True,
            "group/app",
        )

        def must_not_run(*args, **kwargs):
            raise AssertionError("a completed GitLab target was scanned again")

        monkeypatch.setattr("scripts.cli.scan_jobs.scan_gitlab_repo", must_not_run)
        monkeypatch.setattr("scripts.cli.scan_jobs.scan_image", must_not_run)

        resumed = orchestrator.scan_all(targets, {}, session=saved, session_path=path)

        def labels(results):
            return sorted(
                (t, name, tool, row.label)
                for t, name, rows in results
                for tool, row in rows.items()
            )

        assert labels(resumed) == labels(first)
        assert {(t, name) for t, name, _rows in resumed} == {
            ("gitlab", "group/app"),
            ("image", "alpine:3.19"),
        }


class TestDiscoveryHandsEachJobWhatItCanScan:
    """Two flags whose targets discovery accepted and the job then could not
    scan: the scan failed after the fact instead of refusing up front."""

    def test_a_gitlab_repo_without_a_url_is_cloned_from_gitlab_com(
        self, env, monkeypatch
    ):
        """#1319: `--gitlab-url` has no parser default, so `args.gitlab_url`
        is None and a `getattr` default never applied. The job called
        `None.rstrip` before cloning anything."""
        clones: list[list[str]] = []

        def recording(cmd, *args, **kwargs):
            if list(cmd[:2]) == ["git", "clone"]:
                clones.append(list(cmd))
            return _clone_or_run(cmd, *args, **kwargs)

        monkeypatch.setattr(
            "scripts.cli.scan_jobs.gitlab_scanner.subprocess.run", recording
        )

        rc = env.run(
            "--gitlab-repo", "group/app", "--gitlab-token", "t", "--tools", "trufflehog"
        )

        assert rc == 0
        assert [cmd[-2] for cmd in clones] == ["https://gitlab.com/group/app.git"]

    def test_a_local_api_spec_is_refused_with_its_reason(self, env, tmp_path, caplog):
        """#1320: a local spec became `file://C:\\...` (malformed on Windows),
        which the URL job rejects for its scheme after the scan started. zap
        runs a URL scan and cannot import a spec until #1331, so discovery
        refuses the file and says why."""
        (tmp_path / "openapi.yaml").write_bytes(b"openapi: 3.0.0\n")

        rc = env.run("--api-spec", "openapi.yaml", "--tools", "zap")

        assert rc == 1
        refusals = [
            r.getMessage()
            for r in caplog.records
            if "--api-spec openapi.yaml" in r.getMessage()
        ]
        assert refusals, [r.getMessage() for r in caplog.records]
        assert all("#1331" in message for message in refusals), refusals
        assert not (env.results / "individual-web").exists()

    def test_a_remote_api_spec_is_scanned_as_a_url_and_says_so(self, env, caplog):
        """An http(s) spec is still scanned, as the plain URL it is: zap
        crawls the document's address, not the API it describes (#1331)."""
        spec = "http://h.test/openapi.json"

        assert env.run("--api-spec", spec, "--tools", "zap") == 0

        assert _tool_runs(env.results) == [("url", spec, "zap")]
        warnings = [
            r.getMessage()
            for r in caplog.records
            if r.levelname == "WARNING" and spec in r.getMessage()
        ]
        assert len(warnings) == 1, [r.getMessage() for r in caplog.records]
        assert "plain URL" in warnings[0]
        assert "#1331" in warnings[0]
