#!/usr/bin/env python3
"""Tests for scripts/cli/clone_from_tsv.py repository cloning utility."""

from __future__ import annotations

import csv
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.cli.clone_from_tsv import (
    clone_or_update,
    ensure_unshallowed,
    main,
    parse_tsv,
    run,
)


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

        urls = parse_tsv(tsv, max_count=None)
        assert len(urls) == 2
        assert urls[0] == "https://github.com/owner/repo1.git"

    def test_parse_with_full_name_column(self, tmp_path: Path) -> None:
        """Test parsing TSV with full_name column (no url)."""
        tsv = tmp_path / "repos.tsv"
        with tsv.open("w", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["full_name", "stars"])
            writer.writerow(["owner/repo1", "100"])

        urls = parse_tsv(tsv, max_count=None)
        assert len(urls) == 1
        assert urls[0] == "https://github.com/owner/repo1.git"

    def test_parse_with_max_count(self, tmp_path: Path) -> None:
        """Test parsing TSV with max_count limit."""
        tsv = tmp_path / "repos.tsv"
        with tsv.open("w", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["url", "stars"])
            for i in range(10):
                writer.writerow([f"https://github.com/owner/repo{i}.git", str(i * 10)])

        urls = parse_tsv(tsv, max_count=3)
        assert len(urls) == 3

    def test_parse_empty_header_raises(self, tmp_path: Path) -> None:
        """Test parsing TSV with no header raises error."""
        tsv = tmp_path / "repos.tsv"
        tsv.write_text("")

        with pytest.raises(RuntimeError, match="no header"):
            parse_tsv(tsv, max_count=None)

    def test_parse_missing_columns_raises(self, tmp_path: Path) -> None:
        """Test parsing TSV without url or full_name raises error."""
        tsv = tmp_path / "repos.tsv"
        with tsv.open("w", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["stars", "language"])
            writer.writerow(["100", "Python"])

        with pytest.raises(RuntimeError, match="must include either"):
            parse_tsv(tsv, max_count=None)

    def test_parse_comma_delimited(self, tmp_path: Path) -> None:
        """Test parsing CSV (comma-delimited) file."""
        csv_file = tmp_path / "repos.csv"
        with csv_file.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "stars"])
            writer.writerow(["https://github.com/owner/repo.git", "100"])

        urls = parse_tsv(csv_file, max_count=None)
        assert len(urls) == 1

    def test_parse_skips_blank_urls(self, tmp_path: Path) -> None:
        """Test parsing skips rows with blank urls."""
        tsv = tmp_path / "repos.tsv"
        with tsv.open("w", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["url", "stars"])
            writer.writerow(["https://github.com/owner/repo1.git", "100"])
            writer.writerow(["", "200"])  # blank url
            writer.writerow(["https://github.com/owner/repo2.git", "300"])

        urls = parse_tsv(tsv, max_count=None)
        assert len(urls) == 2


class TestEnsureUnshallowed:
    """Tests for ensure_unshallowed function."""

    def test_nonshallow_repo(self, tmp_path: Path) -> None:
        """Test ensure_unshallowed with non-shallow repo."""
        with patch("scripts.cli.clone_from_tsv.run") as mock_run:
            # First call: check if shallow
            mock_run.return_value = (0, "false\n", "")

            ensure_unshallowed(tmp_path)

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

            ensure_unshallowed(tmp_path)
            assert mock_run.call_count == 3

    def test_rev_parse_fails(self, tmp_path: Path) -> None:
        """Test ensure_unshallowed handles rev-parse failure gracefully."""
        with patch("scripts.cli.clone_from_tsv.run") as mock_run:
            mock_run.return_value = (1, "", "fatal: not a git repo")

            # Should not raise, just return
            ensure_unshallowed(tmp_path)


class TestCloneOrUpdate:
    """Tests for clone_or_update function."""

    def test_clone_new_repo(self, tmp_path: Path) -> None:
        """Test cloning a new repository."""
        with patch("scripts.cli.clone_from_tsv.run") as mock_run:
            mock_run.side_effect = [
                (0, "", ""),  # git clone
                (0, "false\n", ""),  # shallow check
                (0, "", ""),  # fetch tags
            ]

            result = clone_or_update("https://github.com/owner/repo.git", tmp_path)

            assert result is not None
            assert result == tmp_path / "owner" / "repo"

    def test_update_existing_repo(self, tmp_path: Path) -> None:
        """Test updating an existing repository."""
        # Create existing repo directory
        repo_dir = tmp_path / "owner" / "repo"
        repo_dir.mkdir(parents=True)

        with patch("scripts.cli.clone_from_tsv.run") as mock_run:
            mock_run.side_effect = [
                (0, "origin\thttps://...", ""),  # git remote -v
                (0, "", ""),  # fetch all
                (0, "false\n", ""),  # shallow check
                (0, "", ""),  # fetch tags
            ]

            result = clone_or_update("https://github.com/owner/repo.git", tmp_path)

            assert result == repo_dir

    def test_clone_failure(self, tmp_path: Path) -> None:
        """Test clone_or_update returns None on clone failure."""
        with patch("scripts.cli.clone_from_tsv.run") as mock_run:
            mock_run.return_value = (1, "", "fatal: could not clone")

            result = clone_or_update("https://github.com/owner/repo.git", tmp_path)

            assert result is None

    def test_url_parsing_strips_git_suffix(self, tmp_path: Path) -> None:
        """Test URL parsing strips .git suffix for directory name."""
        with patch("scripts.cli.clone_from_tsv.run") as mock_run:
            mock_run.side_effect = [
                (0, "", ""),  # clone
                (0, "false\n", ""),  # shallow
                (0, "", ""),  # fetch
            ]

            result = clone_or_update("https://github.com/owner/myrepo.git", tmp_path)

            assert result is not None
            assert result.name == "myrepo"  # not myrepo.git


class TestMain:
    """Tests for main CLI function."""

    def test_missing_tsv_file(self, tmp_path: Path) -> None:
        """Test main returns error when TSV not found."""
        result = main(
            [
                "--tsv",
                str(tmp_path / "nonexistent.tsv"),
                "--dest",
                str(tmp_path / "repos"),
            ]
        )
        assert result == 2

    def test_empty_tsv(self, tmp_path: Path) -> None:
        """Test main returns error when no URLs in TSV."""
        tsv = tmp_path / "empty.tsv"
        with tsv.open("w", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["url", "stars"])  # header only, needs 2 cols for sniffer

        result = main(
            [
                "--tsv",
                str(tsv),
                "--dest",
                str(tmp_path / "repos"),
            ]
        )
        assert result == 2

    def test_successful_clone(self, tmp_path: Path) -> None:
        """Test main successfully clones repos."""
        tsv = tmp_path / "repos.tsv"
        with tsv.open("w", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["url", "stars"])
            writer.writerow(["https://github.com/owner/repo.git", "100"])

        targets_out = tmp_path / "targets.txt"

        with patch("scripts.cli.clone_from_tsv.clone_or_update") as mock_clone:
            mock_clone.return_value = tmp_path / "repos" / "owner" / "repo"

            result = main(
                [
                    "--tsv",
                    str(tsv),
                    "--dest",
                    str(tmp_path / "repos"),
                    "--targets-out",
                    str(targets_out),
                ]
            )

            assert result == 0
            assert targets_out.exists()

    def test_no_repos_cloned(self, tmp_path: Path) -> None:
        """Test main returns error when all clones fail."""
        tsv = tmp_path / "repos.tsv"
        with tsv.open("w", newline="") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["url", "stars"])
            writer.writerow(["https://github.com/owner/repo.git", "100"])

        with patch("scripts.cli.clone_from_tsv.clone_or_update") as mock_clone:
            mock_clone.return_value = None  # Clone failed

            result = main(
                [
                    "--tsv",
                    str(tsv),
                    "--dest",
                    str(tmp_path / "repos"),
                ]
            )

            assert result == 1
