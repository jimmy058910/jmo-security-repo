"""yara-x is a dependency of JMo, not an installed tool (v2.0.0 Phase 6, PR Y,
Task Y2, J2).

The engine arrives with `pip install jmo-security`, so there is no versions.yaml
row and nothing for `jmo tools install` to download for it. What that command
still provides is the pinned rule bundle, and an engine with no rules reports
every scan clean (#1282). So "installed" stays "the engine imports", and the
rules are a readiness question that both install paths act on.
"""

from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path
from unittest.mock import patch

from scripts.cli.tool_manager import ToolManager
from scripts.core.attestation.provenance import ProvenanceGenerator
from scripts.core.install_config import YARA_RULES_BUNDLE
from scripts.core.tool_descriptors import DESCRIPTORS
from scripts.core.tool_registry import DEPENDENCY_TOOLS, ToolRegistry

REPO = Path(__file__).resolve().parents[2]


def _locked_version(package: str) -> str:
    lock = tomllib.loads((REPO / "uv.lock").read_bytes().decode("utf-8"))
    return next(p["version"] for p in lock["package"] if p["name"] == package)


def _rules(tmp_path: Path, ref: str | None) -> Path:
    rules_dir = tmp_path / "yara-rules"
    rules_dir.mkdir()
    (rules_dir / "a.yar").write_bytes(b"rule A { condition: true }\n")
    if ref is not None:
        (rules_dir / "manifest.json").write_bytes(json.dumps({"ref": ref}).encode())
    return rules_dir


def test_yara_x_is_importable_where_jmo_is() -> None:
    probe = DESCRIPTORS["yara-x"].version_probe
    assert probe is not None and isinstance(probe.command, list)

    out = subprocess.run(
        probe.command, capture_output=True, text=True, timeout=60, check=False
    )

    assert out.returncode == 0, out.stderr
    found = probe.pattern.search(out.stdout)
    assert found and found.group(1) == _locked_version("yara-x")


def test_the_engine_has_no_versions_yaml_row() -> None:
    # A row would be a second pin of the engine, beside pyproject.toml's.
    assert ToolRegistry().get_tool("yara-x") is None


def test_rules_at_another_pin_leave_yara_x_not_ready(tmp_path: Path) -> None:
    # An install from before the pin moved, or v1's ReversingLabs tree.
    rules_dir = _rules(tmp_path, ref="an-older-pin")
    with patch("scripts.core.paths.get_yara_rules_dir", return_value=rules_dir):
        status = ToolManager().check_tool("yara-x")

    assert status.installed
    assert not status.execution_ready
    assert status.missing_deps == ["yara-rules"]
    assert "jmo tools install yara-x" in (status.execution_warning or "")


def test_the_pinned_rules_make_yara_x_ready(tmp_path: Path) -> None:
    rules_dir = _rules(tmp_path, ref=YARA_RULES_BUNDLE["ref"])
    with patch("scripts.core.paths.get_yara_rules_dir", return_value=rules_dir):
        status = ToolManager().check_tool("yara-x")

    assert status.installed
    assert status.execution_ready


def test_a_default_install_picks_up_missing_rules(tmp_path: Path) -> None:
    # `jmo tools install` with no names installs what get_missing_tools lists;
    # the engine is always present, so the rules have to put yara-x on it.
    rules_dir = _rules(tmp_path, ref=None)
    with patch("scripts.core.paths.get_yara_rules_dir", return_value=rules_dir):
        missing = ToolManager().get_missing_tools(["yara-x"])

    assert [s.name for s in missing] == ["yara-x"]


def test_every_dependency_tool_is_a_declared_dependency() -> None:
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_bytes().decode("utf-8"))
    declared = {
        dep.split("==")[0].split(">=")[0].strip()
        for dep in pyproject["project"]["dependencies"]
    }

    assert DEPENDENCY_TOOLS == {"yara-x": "yara-x"}
    assert set(DEPENDENCY_TOOLS.values()) <= declared


def test_an_attestation_records_the_engine_version() -> None:
    # With no versions.yaml row, the registry would record "unknown".
    (dep,) = ProvenanceGenerator()._get_tool_versions(["yara-x"])

    assert dep["annotations"]["version"] == _locked_version("yara-x")
    assert dep["uri"] == "https://pypi.org/project/yara-x/"
