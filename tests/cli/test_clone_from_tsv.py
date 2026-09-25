#!/usr/bin/env python3
"""Tests for scripts/cli/clone_from_tsv.py, the clone half of `jmo scan --tsv`.

Every TSV row is untrusted input that reaches git. The clone tests run real git
against a local bare repository (the `git_remote` fixture, which rewrites an
allowed `https://example.invalid/...` URL onto it), because the tests they
replace mocked `run` with fixed call sequences: they never ran git, and passed
over option injection, a destination that escaped `--dest`, a fetch in the
wrong repository and an update that never updated.
"""

from __future__ import annotations

import csv
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

import scripts.cli.clone_from_tsv as clone_mod
from scripts.cli.clone_from_tsv import (
    GIT_TIMEOUT,
    clone_or_update,
    ensure_unshallowed,
    parse_tsv,
    redact,
    run,
)
from tests.cli.conftest import REMOTE_URL, commit, git
from tests.conftest import IS_WINDOWS, skip_on_windows


class TestRun:
    """Tests for run helper function."""

    def test_successful_command(self) -> None:
        """Test run with successful command."""
        rc, stdout, stderr = run(["echo", "hello"])
        assert rc == 0
        assert "hello" in stdout

    def test_failed_command(self) -> None:
        """Test run with failing command."""
        rc, stdout, stderr = run(["false"])
        assert rc != 0

    def test_command_not_found(self) -> None:
        """Test run with nonexistent command."""
        from tests.conftest import is_command_not_found_error

        rc, stdout, stderr = run(["nonexistent_command_12345"])
        assert rc == 127
        # Use cross-platform error pattern matching
        assert is_command_not_found_error(stderr)

    def test_git_can_neither_hang_nor_prompt(self, monkeypatch) -> None:
        """A private https repository makes git ask for a username.

        With no timeout and a terminal attached, that prompt waited forever
        inside a scan. `GIT_TERMINAL_PROMPT=0` alone is not enough: git runs an
        askpass program *before* consulting it (measured under WSL against a
        local 401 server: with `GIT_ASKPASS` set, as a VS Code terminal sets
        it, the askpass program ran). Both askpass variables point at a path
        that cannot run, and `SSH_ASKPASS_REQUIRE=force` makes ssh use it even
        with a terminal attached, so an unknown host key or a key's passphrase
        fails the row instead of waiting (measured: `Host key verification
        failed.` where ssh had sat at "Are you sure you want to continue
        connecting").
        """
        monkeypatch.setenv("GIT_ASKPASS", "/some/askpass")
        monkeypatch.setenv("SSH_ASKPASS", "/some/ssh-askpass")
        with patch("scripts.cli.clone_from_tsv.subprocess.run") as sp:
            sp.return_value = subprocess.CompletedProcess([], 0, "", "")
            run(["git", "status"])

        kwargs = sp.call_args.kwargs
        assert kwargs["timeout"] == GIT_TIMEOUT
        env = kwargs["env"]
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert env["GCM_INTERACTIVE"] == "never"
        assert env["GIT_ASKPASS"] == "/dev/null"
        assert env["SSH_ASKPASS"] == "/dev/null"
        assert env["SSH_ASKPASS_REQUIRE"] == "force"
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs.get("shell", False) is False

    def test_no_askpass_program_runs_not_even_one_git_config_names(
        self, tmp_path, monkeypatch
    ) -> None:
        """Real git against a local server that answers 401.

        `core.askPass` in the user's git config is a third askpass source, and
        removing the two variables left it live: measured on Windows and under
        WSL, the configured program ran. A set `GIT_ASKPASS` outranks it.
        """
        import http.server
        import threading

        class Unauthorized(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="x"')
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Unauthorized)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        marker = tmp_path / "askpass.sh"
        marker.write_bytes(b'#!/bin/sh\ntouch "$(dirname "$0")/ASKPASS_RAN"\necho x\n')
        marker.chmod(0o755)
        monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.askPass")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", marker.as_posix())
        # No credential helper, so nothing answers before a prompt would.
        monkeypatch.setenv("GIT_CONFIG_KEY_1", "credential.helper")
        monkeypatch.setenv("GIT_CONFIG_VALUE_1", "")
        try:
            url = f"http://127.0.0.1:{server.server_port}/o/r.git"
            rc, _out, err = run(["git", "clone", "--", url, str(tmp_path / "c")])
        finally:
            server.shutdown()
            thread.join(timeout=10)

        assert rc != 0
        assert not (tmp_path / "ASKPASS_RAN").exists(), err
        assert "terminal prompts disabled" in err

    def test_a_cwd_that_cannot_be_entered_is_a_failure_not_a_traceback(
        self, tmp_path
    ) -> None:
        a_file = tmp_path / "not-a-dir"
        a_file.write_bytes(b"x")

        rc, _out, err = run(["git", "status"], cwd=a_file)

        assert rc == 126
        assert err

    def test_a_timeout_is_a_failure_not_a_traceback(self) -> None:
        with patch(
            "scripts.cli.clone_from_tsv.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["git"], GIT_TIMEOUT),
        ):
            rc, _out, err = run(["git", "clone", "--", REMOTE_URL, "x"])

        assert rc == 124
        assert "timed out" in err


class TestParseTsv:
    """Tests for parse_tsv function."""

    def test_parse_with_url_column(self, tmp_path: Path) -> None:
        """Test parsing TSV with url column."""
        tsv = tmp_path / "repos.tsv"
        with tsv.open("w", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["url", "stars", "description"])
            writer.writerow(["https://github.com/owner/repo1.git", "100", "desc"])
            writer.writerow(["https://github.com/owner/repo2.git", "200", "desc"])

        urls = parse_tsv(tsv)
        assert len(urls) == 2
        assert urls[0] == "https://github.com/owner/repo1.git"

    def test_parse_with_full_name_column(self, tmp_path: Path) -> None:
        """Test parsing TSV with full_name column (no url)."""
        tsv = tmp_path / "repos.tsv"
        with tsv.open("w", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["full_name", "stars"])
            writer.writerow(["owner/repo1", "100"])

        urls = parse_tsv(tsv)
        assert len(urls) == 1
        assert urls[0] == "https://github.com/owner/repo1.git"

    def test_parse_single_column_file(self, tmp_path: Path) -> None:
        """A one-column file must parse -- it is the documented example.

        `csv.Sniffer` raises `_csv.Error: Could not determine delimiter` when a
        file contains no delimiter, which a single column necessarily does not.
        Measured before the fix, with the exact file below: exit 1 and an
        unhandled traceback out of `parse_tsv`. Two columns: exit 0.

        Every other test in this class builds its fixture with `csv.writer` and
        incidentally includes a second column ("stars", "description"), because
        that is the shape of a real GitHub export. So `parse_tsv` had full line
        coverage while the *documented* minimal input crashed:

            docs/examples/scan_from_tsv.md
                full_name
                example/project-a
                example/project-b

        Written without csv.writer on purpose -- the point is the exact bytes a
        user gets by copying the documentation, not a round-trip through the
        same library that reads it back.
        """
        tsv = tmp_path / "repos.tsv"
        tsv.write_bytes(b"full_name\nexample/project-a\nexample/project-b\n")

        urls = parse_tsv(tsv)

        assert urls == [
            "https://github.com/example/project-a.git",
            "https://github.com/example/project-b.git",
        ]

    def test_parse_single_column_url_file(self, tmp_path: Path) -> None:
        """The other documented single-column form: a bare `url` column."""
        tsv = tmp_path / "repos.tsv"
        tsv.write_bytes(
            b"url\n"
            b"https://github.com/example/project-a.git\n"
            b"https://github.com/example/project-b\n"
        )

        urls = parse_tsv(tsv)

        assert urls == [
            "https://github.com/example/project-a.git",
            "https://github.com/example/project-b",
        ]

    def test_parse_empty_header_raises(self, tmp_path: Path) -> None:
        """Test parsing TSV with no header raises error."""
        tsv = tmp_path / "repos.tsv"
        tsv.write_bytes(b"")

        with pytest.raises(RuntimeError, match="no header"):
            parse_tsv(tsv)

    def test_parse_missing_columns_raises(self, tmp_path: Path) -> None:
        """Test parsing TSV without url or full_name raises error."""
        tsv = tmp_path / "repos.tsv"
        with tsv.open("w", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["stars", "language"])
            writer.writerow(["100", "Python"])

        with pytest.raises(RuntimeError, match="must include either"):
            parse_tsv(tsv)

    def test_parse_comma_delimited(self, tmp_path: Path) -> None:
        """Test parsing CSV (comma-delimited) file."""
        csv_file = tmp_path / "repos.csv"
        with csv_file.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "stars"])
            writer.writerow(["https://github.com/owner/repo.git", "100"])

        urls = parse_tsv(csv_file)
        assert len(urls) == 1

    def test_a_spreadsheet_export_parses(self, tmp_path: Path) -> None:
        """A BOM and a capitalised header, as a spreadsheet saves them.

        Measured before the fix: the BOM made the header `\\ufeffurl`, so
        "must include either"; a `URL` header was found, then every row read as
        empty, so "lists no repositories".
        """
        tsv = tmp_path / "repos.tsv"
        tsv.write_bytes(b"\xef\xbb\xbfURL\thint\nhttps://github.com/o/r.git\tx\n")

        assert parse_tsv(tsv) == ["https://github.com/o/r.git"]

    def test_parse_skips_blank_urls(self, tmp_path: Path) -> None:
        """Test parsing skips rows with blank urls."""
        tsv = tmp_path / "repos.tsv"
        with tsv.open("w", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["url", "stars"])
            writer.writerow(["https://github.com/owner/repo1.git", "100"])
            writer.writerow(["", "200"])  # blank url
            writer.writerow(["https://github.com/owner/repo2.git", "300"])

        urls = parse_tsv(tsv)
        assert len(urls) == 2


class TestEnsureUnshallowed:
    """Tests for ensure_unshallowed function."""

    def test_nonshallow_repo(self, tmp_path: Path) -> None:
        """Test ensure_unshallowed with non-shallow repo."""
        with patch("scripts.cli.clone_from_tsv.run") as mock_run:
            mock_run.return_value = (0, "false\n", "")

            assert ensure_unshallowed(tmp_path) is None

            # Should only check shallow status, not unshallow
            assert mock_run.call_count == 2  # shallow check + fetch tags

    def test_shallow_repo_unshallow_success(self, tmp_path: Path) -> None:
        """Test ensure_unshallowed successfully unshallows."""
        with patch("scripts.cli.clone_from_tsv.run") as mock_run:
            mock_run.side_effect = [
                (0, "true\n", ""),  # is shallow
                (0, "", ""),  # unshallow success
                (0, "", ""),  # fetch tags
            ]

            assert ensure_unshallowed(tmp_path) is None
            assert mock_run.call_count == 3

    def test_rev_parse_fails(self, tmp_path: Path) -> None:
        """A directory git cannot read is reported, not waved through."""
        with patch("scripts.cli.clone_from_tsv.run") as mock_run:
            mock_run.return_value = (1, "", "fatal: not a git repo")

            assert "not a git repo" in ensure_unshallowed(tmp_path)

    def test_a_failed_fetch_is_reported(self, tmp_path: Path) -> None:
        """The update path scans what it fetched, so a fetch that failed
        must stop it rather than leave the old checkout to be scanned."""
        with patch("scripts.cli.clone_from_tsv.run") as mock_run:
            mock_run.side_effect = [
                (0, "false\n", ""),
                (128, "", "fatal: unable to access 'https://h/o/r.git/'"),
            ]

            assert "unable to access" in ensure_unshallowed(tmp_path)


def _spy(monkeypatch, execute: bool = True) -> list[tuple[list[str], str | None]]:
    """Record every git command and its cwd; run it only if `execute`."""
    calls: list[tuple[list[str], str | None]] = []
    real = clone_mod.run

    def spy(cmd, cwd=None):
        calls.append((list(cmd), str(cwd) if cwd else None))
        if execute:
            return real(cmd, cwd=cwd)
        return 1, "", "spy: not executed"

    monkeypatch.setattr(clone_mod, "run", spy)
    return calls


class TestCloneOrUpdate:
    """The happy path, with real git against the fixture."""

    def test_clones_into_dest_owner_repo(self, git_remote, tmp_path) -> None:
        dest = tmp_path / "dest"

        repo, why = clone_or_update(git_remote.url, dest)

        assert why is None
        assert repo == (dest / "owner" / "repo").resolve()
        # `in`, not `==`: a checkout honours the machine's core.autocrlf.
        assert b"print('hello')" in (repo / "app.py").read_bytes()
        assert git("config", "--get", "remote.origin.url", cwd=repo) == git_remote.url

    def test_scp_form_lands_in_owner_repo(self, git_remote, tmp_path) -> None:
        """`git@host:owner/repo` is allowed, and its folder is `owner/repo`.

        The folder used to be the last two `/`-segments, which for this form is
        `git@host:owner`. On Windows a `:` cannot appear in a folder name:
        `mkdir` raised `NotADirectoryError` (WinError 267) out of the clone.
        """
        dest = tmp_path / "dest"

        repo, why = clone_or_update(git_remote.scp_url, dest)

        assert why is None
        assert repo == (dest / "owner" / "repo").resolve()
        assert (repo / "app.py").is_file()

    def test_a_trailing_slash_does_not_change_the_folder(
        self, tmp_path, monkeypatch
    ) -> None:
        """The empty last segment used to become the repository name, landing
        the clone at `dest/repo`."""
        calls = _spy(monkeypatch, execute=False)
        dest = tmp_path / "dest"

        clone_or_update("https://example.invalid/owner/repo/", dest)

        (cmd, _cwd) = calls[-1]
        assert Path(cmd[-1]) == (dest / "owner" / "repo").resolve()

    def test_second_run_scans_the_new_commit(self, git_remote, tmp_path) -> None:
        """An update that only fetches leaves the checkout where it was.

        Measured before the fix: after a new upstream commit the clone stayed
        on the first one, so a second run scanned the first run's files.
        """
        dest = tmp_path / "dest"
        clone_or_update(git_remote.url, dest)
        new_sha = git_remote.push_commit("added.py")

        repo, why = clone_or_update(git_remote.url, dest)

        assert why is None
        assert git("rev-parse", "HEAD", cwd=repo) == new_sha
        assert (repo / "added.py").is_file()

    def test_a_clone_that_cannot_fast_forward_fails_its_row(
        self, git_remote, tmp_path
    ) -> None:
        dest = tmp_path / "dest"
        repo, _ = clone_or_update(git_remote.url, dest)
        commit(repo, "local.py", b"local change\n")
        git_remote.push_commit("upstream.py")

        again, why = clone_or_update(git_remote.url, dest)

        assert again is None
        assert "fast-forward" in why
        assert f"delete {repo}" in why  # stuck until deleted, so say so

    def test_an_update_whose_fetch_fails_fails_its_row(
        self, git_remote, tmp_path
    ) -> None:
        dest = tmp_path / "dest"
        clone_or_update(git_remote.url, dest)
        git_remote.bare.rename(git_remote.bare.with_name("moved.git"))

        repo, why = clone_or_update(git_remote.url, dest)

        assert repo is None
        assert why and "could not update" in why

    def test_a_failed_clone_says_why(self, git_remote, tmp_path) -> None:
        repo, why = clone_or_update(
            "https://example.invalid/owner/missing.git", tmp_path / "dest"
        )

        assert repo is None
        assert why and why.startswith("clone failed")

    def test_a_token_never_becomes_a_folder_name(self, tmp_path, monkeypatch) -> None:
        """A one-segment path makes the host the owner, and the host carried
        the userinfo: measured, `dest/user:TOK@example.invalid/project`."""
        calls = _spy(monkeypatch, execute=False)
        dest = tmp_path / "dest"

        clone_or_update("https://user:tok123@example.invalid:8443/project.git", dest)

        (cmd, _cwd) = calls[-1]
        assert Path(cmd[-1]) == (dest / "example.invalid" / "project").resolve()
        assert not [p for p in tmp_path.rglob("*") if "tok123" in p.name]


class TestOneRowNeverEndsTheScan:
    """Every filesystem call on a row can raise; each one used to crash the
    scan with a traceback instead of failing its row (measured)."""

    def test_a_dest_that_is_a_file(self, tmp_path) -> None:
        a_file = tmp_path / "dest"
        a_file.write_bytes(b"x")

        repo, why = clone_or_update(REMOTE_URL, a_file)

        assert repo is None
        assert why and "cannot create" in why

    def test_a_folder_name_the_filesystem_refuses(self, git_remote, tmp_path) -> None:
        """`:` in a segment: Windows refuses it (WinError 267); POSIX clones,
        and the fixture's remote has no such repository, so the clone fails."""
        repo, why = clone_or_update(
            "https://example.invalid/own:er/r.git", tmp_path / "dest"
        )

        assert repo is None
        assert why

    @skip_on_windows  # symlinks need privileges there
    def test_a_symlink_loop_under_dest(self, tmp_path) -> None:
        dest = tmp_path / "dest"
        dest.mkdir()
        os.symlink(dest / "owner", dest / "owner")

        repo, why = clone_or_update(REMOTE_URL, dest)

        assert repo is None
        assert why


class TestRowsAreUntrusted:
    """Each guard between a TSV row and git, red without it.

    None of these executes anything a row names: the option-injection row is
    git's own `-h`, and the traversal rows point at repositories the test made,
    which have no remotes.
    """

    def test_a_row_starting_with_dash_never_reaches_git(
        self, tmp_path, monkeypatch
    ) -> None:
        """CWE-88. Measured before the fix: `git clone -h <dest>/misc/-h`,
        rc 129 and git's usage text: the row was parsed as an option."""
        calls = _spy(monkeypatch)

        repo, why = clone_or_update("-h", tmp_path / "dest")

        assert repo is None
        assert "not an allowed clone URL" in why
        assert calls == []

    @pytest.mark.parametrize(
        "row",
        [
            "http://example.invalid/owner/repo.git",
            "ssh://-oProxyCommand=x/owner/repo",
            "git@-oProxyCommand=x:owner/repo",
            "https://example.invalid/owner/re po.git",
            # Userinfo first: the old pattern checked its first character and
            # read the dash host behind it as allowed.
            "ssh://a@-oProxyCommand=x/owner/repo",
            # An ssh host reaches ssh, which may expand it into a ProxyCommand
            # (the CVE-2023-51385 class); measured allowed by the old pattern.
            "ssh://h$(x)/owner/repo",
            "https://h$(x)/owner/repo.git",
            # A dash host spelled only in the host alphabet: nothing but the
            # leading-character rule refuses these.
            "ssh://-host/owner/repo",
            "git@-host:owner/repo",
            "https://-host/owner/repo.git",
        ],
        ids=[
            "plain-http",
            "ssh-dash-host",
            "scp-dash-host",
            "whitespace",
            "ssh-dash-host-after-user",
            "ssh-shell-host",
            "https-shell-host",
            "ssh-leading-dash",
            "scp-leading-dash",
            "https-leading-dash",
        ],
    )
    def test_rows_outside_the_allowlist_never_reach_git(
        self, row, tmp_path, monkeypatch
    ) -> None:
        calls = _spy(monkeypatch)

        repo, why = clone_or_update(row, tmp_path / "dest")

        assert repo is None
        assert "not an allowed clone URL" in why
        assert calls == []

    @pytest.mark.parametrize("form", ["file-url", "bare-path"])
    def test_a_local_repository_is_not_copied_in(
        self, form, git_remote, tmp_path
    ) -> None:
        """Without the allowlist, both forms clone the local repository."""
        row = git_remote.bare.as_uri() if form == "file-url" else str(git_remote.bare)
        dest = tmp_path / "dest"

        repo, why = clone_or_update(row, dest)

        assert repo is None
        assert "not an allowed clone URL" in why
        assert not dest.exists() or not any(dest.rglob("app.py"))

    def test_git_is_told_where_options_end(self, tmp_path, monkeypatch) -> None:
        """`--` before the URL: a second guard behind the allowlist."""
        calls = _spy(monkeypatch, execute=False)

        clone_or_update(REMOTE_URL, tmp_path / "dest")

        (cmd, _cwd) = calls[-1]
        assert cmd[:2] == ["git", "clone"]
        assert cmd[cmd.index(REMOTE_URL) - 1] == "--"

    def test_dotdot_owner_cannot_reach_a_repository_outside_dest(
        self, tmp_path, monkeypatch
    ) -> None:
        """CWE-22. Measured before the fix: `dest/../escape` was returned as a
        repository to scan, and `fetch --all --tags --prune` ran in it."""
        escape = tmp_path / "escape"
        escape.mkdir()
        git("init", "-q", cwd=escape)
        calls = _spy(monkeypatch)

        repo, why = clone_or_update(
            "https://example.invalid/../escape.git", tmp_path / "dest"
        )

        assert repo is None
        assert "outside --dest" in why
        assert calls == []

    def test_dotdot_repo_cannot_resolve_to_dest_itself(
        self, tmp_path, monkeypatch
    ) -> None:
        """`owner/..` is `dest`. Inside another repository, `remote -v` walked
        up to it and the fetch ran there."""
        enclosing = tmp_path / "enclosing"
        enclosing.mkdir()
        git("init", "-q", cwd=enclosing)
        dest = enclosing / "dest"
        dest.mkdir()
        calls = _spy(monkeypatch)

        repo, why = clone_or_update("https://example.invalid/owner/..", dest)

        assert repo is None
        assert "outside --dest" in why
        assert calls == []

    @pytest.mark.skipif(
        not IS_WINDOWS,
        reason="`\\` separates folders only on Windows; elsewhere it is one name "
        "inside --dest and the test would pass without the guard",
    )
    def test_backslash_segments_create_nothing_outside_dest(
        self, tmp_path, monkeypatch
    ) -> None:
        """On Windows `\\` separates folders. Measured before the fix: `mkdir`
        made `made-outside\\o` two levels above `--dest` before git ran."""
        _spy(monkeypatch, execute=False)
        dest = tmp_path / "a" / "b" / "dest"
        dest.mkdir(parents=True)

        clone_or_update(r"https://example.invalid/..\..\made-outside\o/r.git", dest)

        outside = [
            p for p in tmp_path.rglob("*") if dest not in p.parents and p != dest
        ]
        assert not [p for p in outside if "made-outside" in p.name]

    def test_a_plain_directory_inside_a_repository_is_not_a_clone(
        self, git_remote, tmp_path, monkeypatch
    ) -> None:
        """Contained, but not a clone: `remote -v` walked up to the enclosing
        repository, which was then fetched and scanned in the row's name.

        The enclosing repository is a clone of the row's own URL, so the origin
        check passes after the walk-up; only `--show-toplevel` can refuse it.
        """
        enclosing = tmp_path / "enclosing"
        git("clone", "-q", "--", git_remote.url, str(enclosing))
        dest = enclosing / "dest"
        (dest / "owner" / "repo").mkdir(parents=True)
        calls = _spy(monkeypatch)

        repo, why = clone_or_update(REMOTE_URL, dest)

        assert repo is None
        assert "not a clone" in why
        assert not [cmd for cmd, _ in calls if "fetch" in cmd or "merge" in cmd]

    def test_a_clone_of_another_url_is_not_updated_in_this_rows_name(
        self, git_remote, tmp_path, monkeypatch
    ) -> None:
        """Two hosts' `owner/repo` share a folder; the second row must not
        fetch the first row's clone and scan it again under its own name."""
        dest = tmp_path / "dest"
        repo, _ = clone_or_update(git_remote.url, dest)
        other = "https://example.invalid/someone-else/repo.git"
        git("remote", "set-url", "origin", other, cwd=repo)
        calls = _spy(monkeypatch)

        again, why = clone_or_update(git_remote.url, dest)

        assert again is None
        assert "not a clone of this row" in why
        assert not [cmd for cmd, _ in calls if "fetch" in cmd or "merge" in cmd]


class TestRedact:
    """Rejection lines are logged; a token in a row's URL must not be."""

    @pytest.mark.parametrize(
        ("url", "shown"),
        [
            ("https://user:tok123@host/o/r.git", "https://***@host/o/r.git"),
            ("https://tok123@host/o/r.git", "https://***@host/o/r.git"),
            ("https://host/o/r.git", "https://host/o/r.git"),
            ("git@host:o/r.git", "git@host:o/r.git"),
            # Refused rows are logged too, whatever their scheme or case.
            ("http://user:tok123@host/o/r.git", "http://***@host/o/r.git"),
            ("HTTPS://user:tok123@host/o/r.git", "HTTPS://***@host/o/r.git"),
            ("ssh://u:tok123@host/o/r", "ssh://***@host/o/r"),
        ],
    )
    def test_userinfo_is_hidden(self, url, shown) -> None:
        assert redact(url) == shown
