"""yara-x is a dependency of JMo, not an installed tool (v2.0.0 Phase 6, PR Y,
Task Y2, J2), and since #1577 the optional one: the `yara` extra.

The engine arrives with `pip install "jmo-security[yara]"`, so there is no
versions.yaml row and nothing for `jmo tools install` to download for it. What that command
still provides is the pinned rule bundle, and an engine with no rules reports
every scan clean (#1282). So "installed" stays "the engine imports", and the
rules are a readiness question that both install paths act on.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.cli.tool_manager import ToolManager
from scripts.core.attestation.provenance import ProvenanceGenerator
from scripts.core.install_config import YARA_RULES_BUNDLE
from scripts.core.tool_descriptors import DESCRIPTORS, ScanContext
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


def _names(requirements: list[str]) -> set[str]:
    return {re.split(r"[=<>!~\[;\s]", req, maxsplit=1)[0] for req in requirements}


def test_the_engine_is_the_yara_extra_not_a_hard_dependency() -> None:
    # yara-x publishes wheels only, so as a hard dependency it failed the whole
    # JMo install on Alpine, Windows ARM64, glibc < 2.28 and macOS 13 (#1577).
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_bytes().decode("utf-8"))

    assert DEPENDENCY_TOOLS == {"yara-x": "yara-x"}
    assert "yara-x" not in _names(pyproject["project"]["dependencies"])
    assert _names(pyproject["project"]["optional-dependencies"]["yara"]) == {"yara-x"}
    # The dev environment, and so every CI job, still has the engine.
    assert "jmo-security[yara]" in pyproject["dependency-groups"]["dev"]


def test_a_missing_engine_is_reported_with_the_extra_that_adds_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # As on a platform yara-x has no wheel for: the module cannot be imported.
    monkeypatch.setitem(sys.modules, "yara_x", None)

    status = ToolManager().check_tool("yara-x")

    assert not status.installed
    assert 'install "jmo-security[yara]"' in status.install_hint
    assert status.execution_warning == status.install_hint


def test_a_scan_without_the_engine_says_which_extra_adds_it(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The scan's own row and log, not only `jmo tools check`, give the reason
    # (#1577): "its executable could not be found" says nothing about an extra.
    from scripts.cli.scan_jobs.repository_scanner import scan_repository
    from scripts.core.scan_timings import Reason, State

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_bytes(b"import os\n")

    with (
        caplog.at_level(logging.ERROR),
        patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner"),
    ):
        _, rows = scan_repository(
            repo=repo,
            results_dir=tmp_path / "out",
            tools=["yara-x"],
            timeout=60,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
            find_tool_func=lambda _tool: None,
        )

    row = rows["yara-x"]
    assert row.state is State.FAILED and row.reason is Reason.NOT_INSTALLED
    assert 'install "jmo-security[yara]"' in (row.detail or "")
    assert 'install "jmo-security[yara]"' in caplog.text


def test_a_skipped_row_without_the_engine_says_which_extra_adds_it(
    tmp_path: Path,
) -> None:
    # --allow-missing-tools records an empty result instead of failing; the
    # row still says why the tool did not run.
    from scripts.cli.scan_jobs.repository_scanner import scan_repository
    from scripts.core.scan_timings import Reason, State

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_bytes(b"import os\n")

    with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner"):
        _, rows = scan_repository(
            repo=repo,
            results_dir=tmp_path / "out",
            tools=["yara-x"],
            timeout=60,
            retries=0,
            per_tool_config={},
            allow_missing_tools=True,
            find_tool_func=lambda _tool: None,
        )

    row = rows["yara-x"]
    assert row.state is State.SKIPPED and row.reason is Reason.NOT_INSTALLED
    assert 'install "jmo-security[yara]"' in (row.detail or "")


def test_a_default_install_leaves_out_an_engine_it_cannot_add(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Decided 2026-11-05: a bare install works everywhere, so a default `jmo
    # tools install` cannot fail on the one tool it can never install where the
    # yara extra has no wheel (Alpine). `tools check` still reports it.
    monkeypatch.setitem(sys.modules, "yara_x", None)
    manager = ToolManager()

    assert manager.get_missing_tools(["yara-x"]) == []
    assert not manager.check_tool("yara-x").installed


def test_the_image_installs_the_yara_extra() -> None:
    # The image is the way on the platforms the extra cannot reach, so it must
    # carry the engine; docker-smoke's `import yara_x` checks it only when the
    # Dockerfile changes.
    dockerfile = (REPO / "Dockerfile").read_bytes().decode("utf-8")
    (extras,) = re.findall(r'-e "/opt/jmo-security\[([^\]]*)\]"', dockerfile)

    assert "yara" in extras.split(",")


def test_an_attestation_records_the_engine_version() -> None:
    # With no versions.yaml row, the registry would record "unknown".
    (dep,) = ProvenanceGenerator()._get_tool_versions(["yara-x"])

    assert dep["annotations"]["version"] == _locked_version("yara-x")
    assert dep["uri"] == "https://pypi.org/project/yara-x/"


# The image carries the rules (Task Y4, #1282). `~/.jmo` is the documented
# persistence mount, and a mount hides whatever the image put beneath it, so
# the image keeps its rules elsewhere. A scan reads the user's install when
# there is one, and the image's otherwise.


def _rule_set(where: Path, ref: str) -> Path:
    where.mkdir(parents=True)
    (where / "a.yar").write_bytes(b"rule A { condition: true }\n")
    (where / "manifest.json").write_bytes(json.dumps({"ref": ref}).encode())
    return where


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home with no rules of its own."""
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    return home


@pytest.fixture
def image_rules(tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The pinned rules an image carries."""
    image = _rule_set(tmp_path / "opt" / "yara-rules", YARA_RULES_BUNDLE["ref"])
    monkeypatch.setattr("scripts.core.paths.IMAGE_YARA_RULES_DIR", image)
    return image


def test_the_images_rules_make_yara_x_ready_without_a_home_install(
    image_rules: Path,
) -> None:
    # A container with nothing (or an empty volume) at ~/.jmo.
    status = ToolManager().check_tool("yara-x")

    assert status.execution_ready, status.execution_warning


def test_a_stale_home_install_is_reported_not_hidden_by_the_images(
    home: Path, image_rules: Path
) -> None:
    # A volume that kept an older pin: the user's tree is the one a scan
    # reads, so readiness must say it needs re-installing.
    _rule_set(home / ".jmo" / "yara-rules", "an-older-pin")

    status = ToolManager().check_tool("yara-x")

    assert not status.execution_ready
    assert "jmo tools install yara-x" in (status.execution_warning or "")


@pytest.mark.parametrize(
    ("home_has_rules", "image_has_rules", "reads"),
    [
        (True, True, "home"),
        (False, True, "image"),
        # Neither: the path `jmo tools install yara-x` fills, which the
        # runner then names when it finds nothing there.
        (False, False, "home"),
    ],
)
def test_a_scan_reads_the_home_rules_else_the_images(
    tmp_path: Path,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    home_has_rules: bool,
    image_has_rules: bool,
    reads: str,
) -> None:
    home_rules = home / ".jmo" / "yara-rules"
    image = tmp_path / "opt" / "yara-rules"
    if home_has_rules:
        _rule_set(home_rules, YARA_RULES_BUNDLE["ref"])
    if image_has_rules:
        _rule_set(image, YARA_RULES_BUNDLE["ref"])
    monkeypatch.setattr("scripts.core.paths.IMAGE_YARA_RULES_DIR", image)
    ctx = ScanContext(
        tool="yara-x",
        target_type="repo",
        target=tmp_path / "repo",
        out_dir=tmp_path / "out",
        binary=sys.executable,
    )

    (invocation,) = DESCRIPTORS["yara-x"].invocations["repo"](ctx)

    command = list(invocation.command)
    rules = Path(command[command.index("--rules") + 1])
    assert rules == {"home": home_rules, "image": image}[reads]


def test_the_image_path_is_where_the_dockerfile_puts_the_rules() -> None:
    # docker-smoke's path filter does not include paths.py: a move on one side
    # alone would ship an image whose rules nothing reads, and no PR check
    # would build it.
    from scripts.core.paths import IMAGE_YARA_RULES_DIR

    dockerfile = (REPO / "Dockerfile").read_bytes().decode("utf-8")
    # The move's destination, not a comment that names the path.
    moved_to = re.findall(r"^\s*mv \S+ (\S+)", dockerfile, re.MULTILINE)

    assert IMAGE_YARA_RULES_DIR.as_posix() in moved_to
