"""`jmo scan --tsv FILE --dest DIR`: clone what a TSV lists, then scan the clones.

The wizard's tsv mode emitted this command for as long as it existed, and
`jmo scan` never accepted it: `unrecognized arguments`, exit 2, natively and in
Docker (#1299). These tests go through the real parser and `cmd_scan`, with
real git against the `git_remote` fixture (no network).
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.cli.scan_orchestrator import ScanConfig, ScanOrchestrator
from scripts.core.scan_timings import State, ToolRun


def _tsv(tmp_path: Path, *rows: str, header: str = "url") -> Path:
    tsv = tmp_path / "repos.tsv"
    tsv.write_bytes(("\n".join([header, *rows]) + "\n").encode("utf-8"))
    return tsv


class TestParser:
    @pytest.mark.parametrize("sub", ["scan", "ci"])
    def test_tsv_and_dest_parse(self, sub) -> None:
        ns = jmo.build_parser().parse_args([sub, "--tsv", "r.tsv", "--dest", "c"])

        assert (ns.tsv, ns.dest) == ("r.tsv", "c")

    def test_tsv_is_one_repository_source_among_the_others(self) -> None:
        """Like `--repo`, `--repos-dir` and `--targets`: one of them."""
        with pytest.raises(SystemExit) as exc:
            jmo.build_parser().parse_args(
                ["scan", "--repo", ".", "--tsv", "r.tsv", "--dest", "c"]
            )

        assert exc.value.code == 2


def _discover(tmp_path: Path, include=(), exclude=(), **kw):
    args = SimpleNamespace(
        repo=None,
        repos_dir=None,
        targets=None,
        tsv=None,
        dest=None,
        image=None,
        images_file=None,
        terraform_state=None,
        cloudformation=None,
        k8s_manifest=None,
        url=None,
        urls_file=None,
        api_spec=None,
        gitlab_url=None,
        gitlab_repo=None,
        gitlab_group=None,
        k8s_context=None,
        k8s_namespace=None,
        k8s_all_namespaces=False,
    )
    for key, value in kw.items():
        setattr(args, key, value)
    orch = ScanOrchestrator(
        ScanConfig(
            tools=["trufflehog"],
            results_dir=tmp_path / "results",
            include_patterns=list(include),
            exclude_patterns=list(exclude),
        )
    )
    return orch.discover_targets(args)


class TestDiscovery:
    """Each refusal is named, the way `--targets`' are (#805, #806)."""

    def test_clones_become_the_repositories_to_scan(self, git_remote, tmp_path):
        dest = tmp_path / "clones"

        targets = _discover(
            tmp_path, tsv=str(_tsv(tmp_path, git_remote.url)), dest=str(dest)
        )

        assert targets.repos == [(dest / "owner" / "repo").resolve()]
        assert targets.rejected == []

    def test_tsv_without_dest_is_refused_by_name(self, tmp_path):
        """No default: see the plan's T1 decisions for why each one is wrong."""
        tsv = _tsv(tmp_path, "https://example.invalid/owner/repo.git")

        targets = _discover(tmp_path, tsv=str(tsv))

        assert targets.is_empty()
        assert any("--tsv" in r and "--dest" in r for r in targets.rejected)

    @pytest.mark.parametrize(
        ("content", "fragment"),
        [
            (None, "file does not exist"),
            (b"", "no header"),
            (b"name\tstars\nx\t1\n", "must include either"),
            (b"url\n", "lists no repositories"),
        ],
        ids=["missing", "empty", "no-url-column", "header-only"],
    )
    def test_an_unusable_file_is_named(self, content, fragment, tmp_path):
        tsv = tmp_path / "repos.tsv"
        if content is not None:
            tsv.write_bytes(content)

        targets = _discover(tmp_path, tsv=str(tsv), dest=str(tmp_path / "clones"))

        assert targets.is_empty()
        assert any(
            r.startswith(f"--tsv {tsv}") and fragment in r for r in targets.rejected
        ), targets.rejected

    def test_each_failed_row_is_named_and_the_rest_are_scanned(
        self, git_remote, tmp_path
    ):
        dest = tmp_path / "clones"
        tsv = _tsv(tmp_path, "-h", git_remote.url, "https://example.invalid/o/gone.git")

        targets = _discover(tmp_path, tsv=str(tsv), dest=str(dest))

        assert targets.repos == [(dest / "owner" / "repo").resolve()]
        assert any(r.startswith("--tsv -h:") for r in targets.rejected)
        assert any(
            r.startswith("--tsv https://example.invalid/o/gone.git:")
            for r in targets.rejected
        )

    def test_every_row_failing_is_a_target_failure(self, tmp_path):
        tsv = _tsv(tmp_path, "-h", "http://example.invalid/o/r.git")

        targets = _discover(tmp_path, tsv=str(tsv), dest=str(tmp_path / "clones"))

        assert targets.is_empty()
        assert any(
            r.startswith(f"--tsv {tsv}") and "no listed repository" in r
            for r in targets.rejected
        ), targets.rejected

    def test_some_rows_filtered_and_the_rest_failing_is_a_clone_failure(
        self, git_remote, tmp_path
    ):
        """#1318: with one row excluded and the other refused, nothing was
        cloned because a clone failed, not because the filters left nothing.
        Only the all-filtered case was pinned, so the message could blame the
        filters for a failed clone."""
        tsv = _tsv(tmp_path, git_remote.url, "http://example.invalid/o/other.git")

        targets = _discover(
            tmp_path, tsv=str(tsv), dest=str(tmp_path / "clones"), exclude=["repo"]
        )

        assert targets.is_empty()
        assert f"--tsv {tsv}: no listed repository could be cloned" in targets.rejected
        assert not [r for r in targets.rejected if "left no row" in r], targets.rejected

    def test_two_repositories_of_one_name_are_both_scanned(self, git_remote, tmp_path):
        """#1303: forks clone to `<dest>/<owner>/<repo>`, so two rows of one
        repository name are the normal case here. PR T refused the second as a
        stopgap; each now gets a results folder of its own."""
        other = git_remote.add_owner("someone-else")
        dest = tmp_path / "clones"

        targets = _discover(
            tmp_path, tsv=str(_tsv(tmp_path, git_remote.url, other)), dest=str(dest)
        )

        assert targets.repos == [
            (dest / "owner" / "repo").resolve(),
            (dest / "someone-else" / "repo").resolve(),
        ]
        assert targets.repo_names == ["owner__repo", "someone-else__repo"]
        assert targets.rejected == []

    def test_include_and_exclude_drop_a_row_before_it_is_cloned(
        self, git_remote, tmp_path, monkeypatch
    ):
        """Decided 2026-09-25 (handoff 3.3): the filters match the folder a row
        clones into, which its URL already names, so an excluded row costs no
        clone and no fetch."""
        import scripts.cli.clone_from_tsv as clone_from_tsv

        cloned: list[str] = []
        real = clone_from_tsv.clone_or_update

        def spy(url, dest):
            cloned.append(url)
            return real(url, dest)

        monkeypatch.setattr(clone_from_tsv, "clone_or_update", spy)
        other = git_remote.add_owner("someone-else")
        dest = tmp_path / "clones"
        tsv = _tsv(tmp_path, git_remote.url, other)

        targets = _discover(tmp_path, tsv=str(tsv), dest=str(dest), exclude=["repo"])

        assert cloned == [], f"an excluded row was cloned: {cloned}"
        assert targets.repos == []
        assert targets.rejected == [
            f"--tsv {tsv}: include/exclude left no row to clone"
        ]
        assert not (dest / "owner").exists()

    def test_a_row_listed_twice_is_scanned_once(self, git_remote, tmp_path):
        dest = tmp_path / "clones"

        targets = _discover(
            tmp_path,
            tsv=str(_tsv(tmp_path, git_remote.url, git_remote.url)),
            dest=str(dest),
        )

        assert targets.repos == [(dest / "owner" / "repo").resolve()]
        assert targets.rejected == []

    def test_a_dest_that_is_a_file_is_refused_once_not_raised(self, tmp_path):
        """Measured before the fix: FileExistsError out of the scan."""
        a_file = tmp_path / "clones"
        a_file.write_bytes(b"x")
        tsv = _tsv(
            tmp_path,
            "https://example.invalid/o/a.git",
            "https://example.invalid/o/b.git",
        )

        targets = _discover(tmp_path, tsv=str(tsv), dest=str(a_file))

        assert targets.is_empty()
        assert len(targets.rejected) == 1
        assert "--dest" in targets.rejected[0]

    def test_a_rejection_line_carries_no_credentials(self, tmp_path):
        """Rejections are logged. git strips userinfo from its own messages
        (measured); the line naming the row has to do the same."""
        tsv = _tsv(
            tmp_path,
            "https://user:tok123@example.invalid/../x.git",
            "http://user:tok123@example.invalid/o/r.git",
        )

        targets = _discover(tmp_path, tsv=str(tsv), dest=str(tmp_path / "clones"))

        assert len(targets.rejected) >= 2
        assert not [r for r in targets.rejected if "tok123" in r]


class TestCmdScan:
    """Through `parse_args` and `cmd_scan`, as `jmo scan` runs it.

    `_check_scan_tools` and `_find_binary` are pinned so a runner with no
    scanner installed reaches discovery instead of bailing in the pre-flight,
    and `scan_repository` stands in for the scanners: what it is handed is the
    claim under test.
    """

    @staticmethod
    def _run(tmp_path, monkeypatch, tsv: Path):
        cfg = tmp_path / "jmo.yml"
        cfg.write_text(
            yaml.safe_dump({"tools": ["trufflehog"], "outputs": ["json"]}),
            encoding="utf-8",
        )
        monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
        monkeypatch.setattr(
            "scripts.cli.tool_manager.ToolManager._find_binary", lambda *a, **k: None
        )
        monkeypatch.setenv("CI", "true")
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        db = tmp_path / "history.db"
        argv = [
            "jmo",
            "scan",
            "--tsv",
            str(tsv),
            "--dest",
            str(tmp_path / "clones"),
            "--results-dir",
            str(tmp_path / "results"),
            "--config",
            str(cfg),
            "--history-db",
            str(db),
            "--tools",
            "trufflehog",
        ]
        with patch.object(sys, "argv", argv):
            args = jmo.parse_args()
        with patch("scripts.cli.scan_jobs.scan_repository") as scan:
            scan.return_value = (
                "repo",
                {"trufflehog": ToolRun("trufflehog", State.RAN)},
            )
            rc = jmo.cmd_scan(args)
        return rc, [c.args[0] for c in scan.call_args_list], db

    def test_jmo_scan_tsv_scans_what_it_cloned(self, git_remote, tmp_path, monkeypatch):
        rc, scanned, db = self._run(
            tmp_path, monkeypatch, _tsv(tmp_path, git_remote.url)
        )

        assert rc == 0
        assert scanned == [(tmp_path / "clones" / "owner" / "repo").resolve()]
        assert (scanned[0] / "app.py").is_file()
        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        try:
            (stored,) = con.execute("SELECT COUNT(*) FROM scans").fetchone()
        finally:
            con.close()
        assert stored == 1

    def test_all_rows_failing_exits_non_zero_naming_them(
        self, tmp_path, monkeypatch, capsys
    ):
        rc, scanned, _db = self._run(tmp_path, monkeypatch, _tsv(tmp_path, "-h"))

        assert rc == 1
        assert scanned == []
        err = capsys.readouterr().err
        assert "Every target was rejected" in err
        assert "--tsv -h:" in err
