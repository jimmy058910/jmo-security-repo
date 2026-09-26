"""Tool names on the command line and in jmo.yml (#1279), and `--dest` alone.

Three faces of one gap: `--tools trivy,syft` was ONE tool named "trivy,syft"
that ran nowhere, so e2e tests written that way passed while scanning nothing;
a removed tool (`--tools bandit`) was reported as "applicable to no target
type"; and a typo selected nothing without a word. Decision 4 (2026-09-24):
split on commas and spaces, and reject an unknown name as a usage error, exit
2, naming it, with "removed in v2.0.0" for the sixteen the cut removed.

`--dest` without `--tsv` was ignored; decided 2026-09-25 (handoff 3.3) to be a
usage error too.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo


@pytest.mark.parametrize("sub", ["scan", "ci"])
@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--tools", "trivy,syft"], ["trivy", "syft"]),
        (["--tools", "trivy", "syft"], ["trivy", "syft"]),
        (["--tools", "trivy, syft", "grype"], ["trivy", "syft", "grype"]),
        (["--tools", "syft", "trivy,syft"], ["syft", "trivy"]),
    ],
)
def test_tools_split_on_commas_and_spaces(sub, argv, expected):
    ns = jmo.build_parser().parse_args([sub, "--repo", ".", *argv])

    assert ns.tools == expected


@pytest.mark.parametrize("flag", ["--tools", "--skip-tools"])
@pytest.mark.parametrize(
    ("name", "says"),
    [
        ("bandit", "removed in v2.0.0"),
        ("kubescape", "removed in v2.0.0"),
        ("trivvy", "unknown tool 'trivvy'"),
    ],
)
def test_an_unknown_name_is_a_usage_error_naming_it(flag, name, says, capsys):
    with pytest.raises(SystemExit) as exc:
        jmo.build_parser().parse_args(["scan", "--repo", ".", flag, "trivy", name])

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert name in err
    assert says in err
    assert flag in err


def _scan_args(tmp_path: Path, **overrides) -> types.SimpleNamespace:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "a.py").write_bytes(b"x = 1\n")
    base = {
        "cmd": "scan",
        "repo": str(repo),
        "repos_dir": None,
        "targets": None,
        "tsv": None,
        "dest": None,
        "results_dir": str(tmp_path / "results"),
        "config": str(tmp_path / "jmo.yml"),
        "tools": None,
        "skip_tools": [],
        "timeout": None,
        "threads": None,
        "allow_missing_tools": False,
        "log_level": "INFO",
        "human_logs": False,
        "no_store_history": True,
        "no_resume": True,
    }
    base.update(overrides)
    return types.SimpleNamespace(**base)


def _config(tmp_path: Path, tools: list[str]) -> None:
    (tmp_path / "jmo.yml").write_text(
        yaml.safe_dump({"tools": tools}), encoding="utf-8"
    )


def test_a_removed_name_in_jmo_yml_stops_the_scan_with_exit_2(
    tmp_path, capsys, monkeypatch
):
    """The same rule in `tools:`: a bandit entry used to scan nothing, rc 1,
    with a message about target types."""
    _config(tmp_path, ["trivy", "bandit"])
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    called = []
    monkeypatch.setattr(
        jmo, "_check_scan_tools", lambda *a: called.append(a) or (a[1], [])
    )

    rc = jmo.cmd_scan(_scan_args(tmp_path))

    assert rc == 2
    err = capsys.readouterr().err
    assert "bandit" in err and "removed in v2.0.0" in err
    assert called == [], "the scan went on to pre-flight after a usage error"
    assert not (tmp_path / "results").exists()


def test_commas_in_jmo_yml_split_too(tmp_path, monkeypatch):
    _config(tmp_path, ["trivy,syft"])

    eff = jmo._effective_scan_settings(_scan_args(tmp_path))

    assert eff["tools"] == ["trivy", "syft"]
    assert eff["explicit_tools"] is True


def test_the_matrix_default_is_not_an_explicit_request(tmp_path):
    """#1279 item 1: a defaulted tool must never produce the "applicable to no
    target type" line, so the default has to be told apart from a request."""
    eff = jmo._effective_scan_settings(_scan_args(tmp_path))

    assert eff["explicit_tools"] is False
    assert eff["tools"] == list(jmo.load_config(None).tools)


def test_dest_without_tsv_is_a_usage_error(tmp_path, capsys, monkeypatch):
    """Decided 2026-09-25: `--dest` names where `--tsv` clones; alone it did
    nothing and said nothing."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    rc = jmo.cmd_scan(_scan_args(tmp_path, dest=str(tmp_path / "clones")))

    assert rc == 2
    assert "--dest only applies to --tsv" in capsys.readouterr().err
    assert not (tmp_path / "clones").exists()
    assert not (tmp_path / "results").exists()


def test_dest_with_tsv_is_not_refused(tmp_path, capsys, monkeypatch):
    """The control: the pair is the supported use."""
    tsv = tmp_path / "repos.tsv"
    tsv.write_bytes(b"url\n-h\n")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    # The startup version check probes every requested tool on the real PATH.
    monkeypatch.setattr(
        "scripts.cli.tool_manager.ToolManager._find_binary", lambda *a, **k: None
    )
    monkeypatch.setenv("CI", "true")

    rc = jmo.cmd_scan(
        _scan_args(tmp_path, repo=None, tsv=str(tsv), dest=str(tmp_path / "clones"))
    )

    err = capsys.readouterr().err
    assert "--dest only applies to --tsv" not in err
    assert rc == 1, "every row refused: a target failure, not a usage error"


def test_the_e2e_comma_form_now_selects_both_tools():
    """The six e2e sites (#1279 item 3) pass `--tools trivy,syft`; through the
    real parser that is two tools now, where it was one that ran nowhere."""
    argv = ["jmo", "ci", "--image", "alpine:3.19", "--tools", "trivy,syft"]
    with patch.object(sys, "argv", argv):
        ns = jmo.parse_args()

    assert ns.tools == ["trivy", "syft"]
