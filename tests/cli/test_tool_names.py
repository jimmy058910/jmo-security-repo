"""Tool names on the command line and in jmo.yml (#1279), and `--dest` alone.

Three faces of one gap: `--tools trivy,syft` was ONE tool named "trivy,syft"
that ran nowhere, so e2e tests written that way passed while scanning nothing;
a removed tool (`--tools bandit`) was reported as "applicable to no target
type"; and a typo selected nothing without a word. Decision 4 (2026-09-24):
split on commas and spaces, and reject an unknown name as a usage error, exit
2, naming it, with "removed in v2.0.0" for the tools v2.0.0 removed.

`--dest` without `--tsv` was ignored; decided 2026-09-25 (handoff 3.3) to be a
usage error too.
"""

from __future__ import annotations

import logging
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
        ("gosec", "removed in v2.0.0"),
        ("semgrep", "removed in v2.0.0"),
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


def test_semgrep_is_removed_and_the_error_names_its_replacement(capsys):
    """semgrep is not a typo and not a retired tool with no successor: opengrep
    replaced it, so a user who typed it is told what to type instead."""
    with pytest.raises(SystemExit) as exc:
        jmo.build_parser().parse_args(["scan", "--repo", ".", "--tools", "semgrep"])

    assert exc.value.code == 2
    err = capsys.readouterr().err
    said = err.split("error:", 1)[1].split("The tools are:")[0]
    assert "removed in v2.0.0" in said
    assert "opengrep" in said, "the replacement must be named outside the tool list"


def test_a_v1_semgrep_config_is_named_not_dropped(tmp_path, caplog):
    """A v1 `per_tool.semgrep.configs` holds the user's own packs. v2 reads
    `per_tool.opengrep.configs`; the old key is read by nothing, so without a
    word the user's packs would stop running and the scan would say nothing."""
    cfg = tmp_path / "jmo.yml"
    cfg.write_text(
        yaml.safe_dump({"per_tool": {"semgrep": {"configs": ["p/python"]}}}),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        loaded = jmo.load_config(str(cfg))

    warnings = [r.getMessage() for r in caplog.records if "semgrep" in r.getMessage()]
    assert len(warnings) == 1, warnings
    assert "per_tool.opengrep.configs" in warnings[0]
    assert "p/python" in warnings[0], "the packs it names must be shown, not just a key"
    assert "semgrep" in loaded.per_tool, "the user's entry is left as written"


def test_a_v1_semgrep_config_written_as_one_bare_pack_is_named_whole(tmp_path, caplog):
    cfg = tmp_path / "jmo.yml"
    cfg.write_text("per_tool:\n  semgrep:\n    configs: p/python\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        jmo.load_config(str(cfg))

    (warning,) = [r.getMessage() for r in caplog.records if "semgrep" in r.getMessage()]
    assert "(p/python)" in warning, warning


@pytest.mark.parametrize(
    "per_tool",
    [
        {"semgrep": {"configs": 5}},
        {"semgrep": {"configs": {"p/python": True}}},
        {"semgrep": {"configs": [["nested"], None, 3]}},
        {"semgrep": True},
        {"semgrep": ["--exclude", "x"]},
        {"semgrep": 7},
        {"semgrep": {}},
        {"semgrep": {1: "a", None: "b"}},
    ],
    ids=[
        "int-configs",
        "dict-configs",
        "odd-list-configs",
        "bool-entry",
        "list-entry",
        "int-entry",
        "empty-entry",
        "non-str-keys",
    ],
)
def test_a_v1_semgrep_entry_of_any_shape_is_named_and_never_raises(
    tmp_path, caplog, per_tool
):
    """The warning runs inside load_config, so a shape it did not expect must
    not turn a mistake into a crash of every command that reads the file."""
    cfg = tmp_path / "jmo.yml"
    cfg.write_text(yaml.safe_dump({"per_tool": per_tool}), encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        loaded = jmo.load_config(str(cfg))

    assert "semgrep" in loaded.per_tool
    (warning,) = [r.getMessage() for r in caplog.records if "semgrep" in r.getMessage()]
    assert "per_tool.opengrep" in warning, warning


def test_a_v1_semgrep_entry_names_every_key_it_carries(tmp_path, caplog):
    """v1 docs also recommended `per_tool.semgrep.timeout`, which opengrep
    reads under its own name."""
    cfg = tmp_path / "jmo.yml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "per_tool": {
                    "semgrep": {
                        "configs": ["p/python"],
                        "flags": ["--exclude", "x"],
                        "timeout": 900,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        jmo.load_config(str(cfg))

    (warning,) = [r.getMessage() for r in caplog.records if "semgrep" in r.getMessage()]
    for key in ("configs", "flags", "timeout"):
        assert f"per_tool.opengrep.{key}" in warning, warning


def test_a_v1_semgrep_entry_beside_an_opengrep_one_says_which_applies(tmp_path, caplog):
    """With both set, opengrep's applies and the old one is dead weight: the
    warning says so, and offers only the keys opengrep does not have."""
    cfg = tmp_path / "jmo.yml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "per_tool": {
                    "semgrep": {"configs": ["p/python"], "timeout": 900},
                    "opengrep": {"configs": ["rules/"]},
                }
            }
        ),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        loaded = jmo.load_config(str(cfg))

    (warning,) = [r.getMessage() for r in caplog.records if "semgrep" in r.getMessage()]
    assert "only per_tool.opengrep applies" in warning, warning
    assert "per_tool.opengrep.timeout" in warning, "the key opengrep lacks"
    assert "per_tool.opengrep.configs" not in warning, "opengrep already has it"
    assert loaded.per_tool["opengrep"] == {"configs": ["rules/"]}, "left as written"


def test_a_v1_semgrep_entry_that_opengrep_already_covers_is_to_be_deleted(
    tmp_path, caplog
):
    cfg = tmp_path / "jmo.yml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "per_tool": {
                    "semgrep": {"timeout": 900},
                    "opengrep": {"timeout": 300},
                }
            }
        ),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        jmo.load_config(str(cfg))

    (warning,) = [r.getMessage() for r in caplog.records if "semgrep" in r.getMessage()]
    assert "Delete per_tool.semgrep" in warning, warning


def test_a_v1_semgrep_config_is_named_once_however_often_it_is_loaded(tmp_path, caplog):
    """A scan loads jmo.yml about ten times (measured); the user reads one line."""
    cfg = tmp_path / "jmo.yml"
    cfg.write_text(
        yaml.safe_dump({"per_tool": {"semgrep": {"flags": ["--exclude", "x"]}}}),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        for _ in range(3):
            jmo.load_config(str(cfg))

    warnings = [r.getMessage() for r in caplog.records if "semgrep" in r.getMessage()]
    assert len(warnings) == 1, warnings
    assert "per_tool.opengrep.flags" in warnings[0]


def test_an_opengrep_config_raises_no_semgrep_warning(tmp_path, caplog):
    """The control: the v2 spelling is the supported one."""
    cfg = tmp_path / "jmo.yml"
    cfg.write_text(
        yaml.safe_dump({"per_tool": {"opengrep": {"configs": ["rules/"]}}}),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        jmo.load_config(str(cfg))

    assert not [r for r in caplog.records if "semgrep" in r.getMessage()]


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
