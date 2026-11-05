"""The wizard reads its history where the scan it launches writes it (#1484).

The wizard read `~/.jmo/history.db`; the scan it ran stored to the working
directory's `.jmo/history.db`. The two agreed only when the wizard ran from the
home directory, so its trend step reported "No history database found" after
any number of scans. In Docker mode the scan stored inside a `--rm` container
and the history was lost outright.

Decided 2026-11-05: one default, the working directory's `.jmo/history.db`, as
every other subcommand has; the wizard passes `--history-db` to its scan, and in
Docker mode mounts the database's directory.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from scripts.cli.jmo import build_parser
from scripts.cli.wizard_flows.command_builder import (
    build_command_parts,
    docker_output_dirs,
)
from scripts.cli.wizard_flows.config_models import WizardConfig
from scripts.cli.wizard_generators import JMO_DOCKER_IMAGE_FULL
from scripts.core.history_db import DEFAULT_DB_PATH


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    WizardConfig.set_db_path(None)
    cfg = WizardConfig()
    cfg.results_dir = "results"
    cfg.target.type = "repo"
    cfg.target.repo_mode = "repo"
    cfg.target.repo_path = str(tmp_path / "repo")
    yield cfg
    WizardConfig.set_db_path(None)


def _scan_args(parts: list[str], use_docker: bool):
    anchor = JMO_DOCKER_IMAGE_FULL if use_docker else "jmo"
    return build_parser().parse_args(parts[parts.index(anchor) + 1 :])


def test_the_default_is_the_scans_default(config):
    assert WizardConfig.get_db_path() == DEFAULT_DB_PATH


@pytest.mark.parametrize("custom", [None, "~/hist/scans.db"], ids=["default", "custom"])
def test_native_scan_stores_where_the_wizard_reads(
    config, custom, tmp_path, monkeypatch
):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    WizardConfig.set_db_path(custom)
    config.use_docker = False

    stored = _scan_args(build_command_parts(config), use_docker=False).history_db

    assert stored is not None, "the scan was not told where to store"
    assert Path(stored).resolve() == WizardConfig.get_db_path().resolve()


def test_docker_scan_stores_through_a_mount_of_the_wizards_database(config):
    config.use_docker = True

    parts = build_command_parts(config)
    stored = _scan_args(parts, use_docker=True).history_db

    mounts = dict(parts[i + 1].rsplit(":", 1) for i, p in enumerate(parts) if p == "-v")
    host = WizardConfig.get_db_path().resolve()
    # The container path is POSIX whatever the host is; read on Windows as a
    # WindowsPath, `/history` became `\\history`.
    container = PurePosixPath(stored)
    assert mounts.get(str(host.parent)) == str(container.parent), (mounts, stored)
    assert container.name == host.name
    # Created before docker runs, or the engine makes it root-owned (#1307).
    assert str(host.parent) in docker_output_dirs(config)


def test_the_wizard_flag_documents_the_real_default():
    wizard = next(
        a.choices["wizard"]
        for a in build_parser()._actions
        if getattr(a, "choices", None) and "wizard" in a.choices
    )
    (option,) = [a for a in wizard._actions if "--history-db" in a.option_strings]
    assert ".jmo/history.db" in option.help
    assert "~/.jmo" not in option.help
