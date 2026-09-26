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
