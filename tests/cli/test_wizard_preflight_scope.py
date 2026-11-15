"""The wizard probes only the tools its scan will run, once each, after it knows
the target (#1584).

Measured at 449cf442 with 14 tools installed: the wizard probed every matrix tool
before its second question, twice (the pre-flight and the version-drift check
each built their own ToolManager, and the status memo is per instance), then
again before "Customize advanced settings?" and again before "Proceed with
scan?": four passes, 49 s, 8.5 s of each pass zap's JVM. A repository scan never
runs zap, and a URL scan runs only zap and nuclei.

The probe is stubbed below the memo: `check_tool` and its cache are the real ones,
so a second ToolManager, or a step that asks again for the whole matrix, shows up
as a second probe of the same tool.
"""

from __future__ import annotations

import collections
from pathlib import Path

import pytest

from scripts.cli import wizard
from scripts.cli.scan_orchestrator import ScanTargets, tools_read_by
from scripts.cli.tool_manager import ToolManager
from scripts.cli.wizard_flows.config_models import TargetConfig
from scripts.core.tool_registry import TOOL_MATRIX, TOOL_SCAN_TYPES

# Where each wizard target type lands in the scan: the ScanTargets field that the
# wizard's generated command fills (command_builder.build_<type>_args), with one
# target of that field's shape.
SCAN_FIELD: dict[str, ScanTargets] = {
    "repo": ScanTargets(repos=[Path("repo")]),
    "image": ScanTargets(images=["nginx:1.27"]),
    "iac": ScanTargets(iac_files=[("terraform", Path("main.tf"))]),
    "url": ScanTargets(urls=["https://example.com"]),
    "gitlab": ScanTargets(gitlab_repos=[{"repo": "group/repo"}]),
    "k8s": ScanTargets(k8s_resources=[{"context": "dev"}]),
}


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[tuple[str, str]]:
    """What happened, in order: ("asked", question) and ("probe", tool).

    Every tool is installed at its pinned version and runs, so no step stops to
    ask about a missing or drifted tool. The working directory is empty, so no
    jmo.yml there turns policies on."""
    happened: list[tuple[str, str]] = []

    def find_binary(self: ToolManager, binary_name: str) -> str:
        return f"/fake/bin/{binary_name}"

    def version(self: ToolManager, tool_name: str, binary_path: str):
        happened.append(("probe", tool_name))
        info = self.registry.get_tool(tool_name)
        return ((info.version if info and info.version else "1.0.0"), None)

    monkeypatch.setattr(ToolManager, "_find_binary", find_binary)
    monkeypatch.setattr(ToolManager, "_get_tool_version", version)
    monkeypatch.setattr(
        ToolManager, "_verify_execution", lambda self, tool_name: (True, None, [])
    )
    monkeypatch.chdir(tmp_path)
    return happened


def _target(target_type: str, tmp_path: Path) -> TargetConfig:
    target = TargetConfig()
    target.type = target_type
    if target_type == "repo":
        target.repo_mode = "repo"
        target.repo_path = str(tmp_path)
    elif target_type == "url":
        target.url = "https://example.com"
    return target


def _run_interactively(
    monkeypatch: pytest.MonkeyPatch,
    events: list[tuple[str, str]],
    target_type: str,
    tmp_path: Path,
) -> int:
    """Native mode, `target_type`, no advanced settings, and "no" to the review:
    every step that reads tool status runs, and no scan starts."""
    monkeypatch.setattr(wizard, "stdin_closed", lambda: False)

    def mode(force_docker: bool = False) -> bool:
        events.append(("asked", "execution mode"))
        return False

    def pick() -> str:
        events.append(("asked", "target type"))
        return target_type

    monkeypatch.setattr(wizard, "select_execution_mode", mode)
    monkeypatch.setattr(wizard, "select_target_type", pick)
    target = _target(target_type, tmp_path)
    monkeypatch.setattr(wizard, f"configure_{target_type}_target", lambda: target)

    def no(question: str, *args, **kwargs) -> bool:
        events.append(("asked", question.strip()))
        return False

    monkeypatch.setattr(wizard, "_prompt_yes_no", no)
    return wizard.run_wizard()


@pytest.mark.parametrize("target_type", ["repo", "url"])
def test_no_tool_is_probed_before_the_target_type_is_known(
    monkeypatch: pytest.MonkeyPatch,
    events: list[tuple[str, str]],
    target_type: str,
    tmp_path: Path,
) -> None:
    """The first two questions come at once; the probes wait for the answer
    that decides which tools the scan runs."""
    rc = _run_interactively(monkeypatch, events, target_type, tmp_path)

    assert rc == 0
    asked_type = events.index(("asked", "target type"))
    probes = [i for i, (kind, _) in enumerate(events) if kind == "probe"]
    assert probes, "nothing was probed"
    assert min(probes) > asked_type, events[: asked_type + 1]


@pytest.mark.parametrize("target_type", ["repo", "url"])
def test_each_tool_the_scan_runs_is_probed_once_and_no_other(
    monkeypatch: pytest.MonkeyPatch,
    events: list[tuple[str, str]],
    target_type: str,
    tmp_path: Path,
) -> None:
    """Pre-flight, version check, advanced settings and review all read tool
    status. One probe per tool across all four, of the target's tools only."""
    _run_interactively(monkeypatch, events, target_type, tmp_path)

    probed = collections.Counter(tool for kind, tool in events if kind == "probe")
    assert set(probed) == TOOL_SCAN_TYPES[target_type]
    assert {tool: n for tool, n in probed.items() if n > 1} == {}


@pytest.mark.parametrize(
    ("presets", "target_type"),
    [
        ({"target_type": "url", "target": "https://example.com"}, "url"),
        ({"target_type": "image", "target": "nginx:1.27"}, "image"),
        ({"yes": True}, "repo"),  # --yes alone scans the working directory
    ],
)
def test_without_questions_the_preset_targets_tools_are_checked_once(
    events: list[tuple[str, str]],
    tmp_path: Path,
    presets: dict,
    target_type: str,
) -> None:
    """`--yes` and full presets ask nothing, and check the same tools the
    interactive wizard would for that target: `--auto-fix` installs those."""
    script = tmp_path / "scan.sh"

    rc = wizard.run_wizard(use_docker=False, emit_script=str(script), **presets)

    assert rc == 0
    assert script.exists()
    probed = collections.Counter(tool for kind, tool in events if kind == "probe")
    assert set(probed) == TOOL_SCAN_TYPES[target_type]
    assert {tool: n for tool, n in probed.items() if n > 1} == {}


@pytest.mark.parametrize("target_type", sorted(SCAN_FIELD))
def test_the_wizard_checks_exactly_the_tools_the_scan_runs(target_type: str) -> None:
    """A tool the scan runs that the wizard never checked would fail mid-scan
    with no offer to install it; a tool checked but never run is the wait this
    issue is about. Both are the scan's own rule, `tools_read_by`."""
    assert wizard.tools_for_target_type(target_type) == tools_read_by(
        SCAN_FIELD[target_type], list(TOOL_MATRIX)
    )


def test_the_wizard_offers_exactly_the_target_types_the_scan_knows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    offered: list[str] = []

    def capture(title: str, options: list[tuple[str, str]], default: str) -> str:
        offered.extend(key for key, _ in options)
        return default

    monkeypatch.setattr(wizard, "_select_mode", capture)
    wizard.select_target_type()

    assert sorted(offered) == sorted(SCAN_FIELD) == sorted(TOOL_SCAN_TYPES)
