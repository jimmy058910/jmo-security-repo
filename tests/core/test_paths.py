"""Tests for scripts.core.paths - isolated venv path utilities."""

import sys
from pathlib import Path

import pytest

from scripts.core.paths import (
    clean_isolated_venvs,
    get_isolated_tool_path,
    get_isolated_venv_path,
)


class TestGetIsolatedVenvPath:
    """Tests for get_isolated_venv_path()."""

    def test_returns_correct_path(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = get_isolated_venv_path("checkov")
        assert result == tmp_path / ".jmo" / "tools" / "venvs" / "checkov"

    def test_different_tools_different_paths(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        p1 = get_isolated_venv_path("checkov")
        p2 = get_isolated_venv_path("bandit")
        assert p1 != p2
        assert p1.name == "checkov"
        assert p2.name == "bandit"


class TestGetIsolatedToolPath:
    """Tests for get_isolated_tool_path()."""

    def test_returns_none_when_venv_missing(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert get_isolated_tool_path("nonexistent") is None

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix bin layout test")
    def test_finds_unix_executable(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        venv = tmp_path / ".jmo" / "tools" / "venvs" / "checkov"
        bin_dir = venv / "bin"
        bin_dir.mkdir(parents=True)
        exe = bin_dir / "checkov"
        exe.touch()

        result = get_isolated_tool_path("checkov")
        assert result == exe

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows Scripts layout test")
    def test_finds_windows_executable(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        venv = tmp_path / ".jmo" / "tools" / "venvs" / "checkov"
        scripts_dir = venv / "Scripts"
        scripts_dir.mkdir(parents=True)
        exe = scripts_dir / "checkov.exe"
        exe.touch()

        result = get_isolated_tool_path("checkov")
        assert result == exe

    def test_tries_alternate_names(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        venv = tmp_path / ".jmo" / "tools" / "venvs" / "osv-scanner"
        if sys.platform == "win32":
            bin_dir = venv / "Scripts"
            exe_name = "osv-scanner-cli.exe"
        else:
            bin_dir = venv / "bin"
            exe_name = "osv-scanner-cli"
        bin_dir.mkdir(parents=True)
        exe = bin_dir / exe_name
        exe.touch()

        # Primary name doesn't exist, but osv-scanner-cli does
        result = get_isolated_tool_path("osv-scanner")
        assert result == exe

    def test_returns_none_when_no_matching_exe(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        venv = tmp_path / ".jmo" / "tools" / "venvs" / "sometool"
        if sys.platform == "win32":
            (venv / "Scripts").mkdir(parents=True)
        else:
            (venv / "bin").mkdir(parents=True)

        assert get_isolated_tool_path("sometool") is None


class TestCleanIsolatedVenvs:
    """Tests for clean_isolated_venvs()."""

    def test_dry_run_does_not_delete(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        venvs = tmp_path / ".jmo" / "tools" / "venvs"
        (venvs / "checkov").mkdir(parents=True)
        (venvs / "bandit").mkdir(parents=True)

        result = clean_isolated_venvs(dry_run=True)
        assert len(result) == 2
        assert (venvs / "checkov").exists()
        assert (venvs / "bandit").exists()

    def test_actual_delete(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        venvs = tmp_path / ".jmo" / "tools" / "venvs"
        (venvs / "checkov").mkdir(parents=True)
        (venvs / "bandit").mkdir(parents=True)

        result = clean_isolated_venvs(dry_run=False)
        assert len(result) == 2
        assert not (venvs / "checkov").exists()
        assert not (venvs / "bandit").exists()

    def test_empty_venvs_dir(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        venvs = tmp_path / ".jmo" / "tools" / "venvs"
        venvs.mkdir(parents=True)

        result = clean_isolated_venvs(dry_run=False)
        assert result == []

    def test_missing_venvs_dir(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        result = clean_isolated_venvs(dry_run=False)
        assert result == []
