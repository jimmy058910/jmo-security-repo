"""Unit tests for MANUAL_INSTALL_TOOLS handling in check_outdated_and_create_issues().

The 4 manual-install tools (falco, afl++, mobsf, akto) carry synthetic versions
in versions.yaml (e.g. falco 0.0.0), so they ALWAYS read as outdated. Before this
behavior, the weekly check-versions cron filed a fresh "Update <tool>" GitHub issue
for each of them every run — pure recurring noise, since they can't be auto-updated
or baked into any Docker image. These tests pin two guarantees:

1. Drift guard: update_versions.py's local MANUAL_INSTALL_TOOLS mirror stays in sync
   with the source-of-truth set in scripts/core/tool_registry.py. The mirror exists
   because update_versions.py runs in CI WITHOUT `pip install -e .`, so it can't
   reliably import the scripts.core package there — but the test env CAN.
2. Behavior: no GitHub issue is created for a manual tool, while normal/critical
   tools still get one.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


def _load_module():
    script = (
        Path(__file__).resolve().parents[2] / "scripts" / "dev" / "update_versions.py"
    )
    spec = importlib.util.spec_from_file_location("update_versions", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


update_versions = _load_module()


def test_local_mirror_matches_registry_source_of_truth():
    """The local mirror must equal scripts.core.tool_registry.MANUAL_INSTALL_TOOLS.

    This runs in the dev/test env where `pip install -e .[dev]` makes the
    scripts.core package importable. If the registry set changes, this fails
    and forces the mirror in update_versions.py to be updated too.
    """
    from scripts.core.tool_registry import MANUAL_INSTALL_TOOLS as registry_manual

    assert set(update_versions.MANUAL_INSTALL_TOOLS) == set(registry_manual)


def _gh_mock_side_effect(created_titles: list[str]):
    """Return a subprocess.run side_effect that records `gh issue create` titles.

    Handles the three gh calls this code path makes:
      - `gh issue list ... --json ...` -> returns empty JSON (no existing issues)
      - `gh issue create --title <T> ...` -> records T, returncode 0
      - `gh issue close ...` -> returncode 0
    """

    def _run(cmd, *args, **kwargs):
        result = MagicMock(spec=subprocess.CompletedProcess)
        result.returncode = 0
        result.stdout = ""
        if "list" in cmd:
            result.stdout = "[]"
        elif "create" in cmd:
            # cmd looks like [..., "create", "--title", <title>, "--body", ...]
            title_idx = cmd.index("--title") + 1
            created_titles.append(cmd[title_idx])
        return result

    return _run


def test_manual_tools_do_not_get_issues_but_normal_tools_do():
    """A manual tool that's outdated must not spawn an issue; a normal one must."""
    created_titles: list[str] = []

    fake_results = {
        "bandit": ("1.9.3", "1.9.4", True),  # normal, outdated -> issue
        "falco": ("0.0.0", "0.43.1", True),  # manual, outdated -> NO issue
        "ruff": ("0.6.0", "0.6.0", False),  # up to date -> skipped
    }
    fake_versions = {
        "python_tools": {"bandit": {"critical": False}},
        "binary_tools": {},
        "special_tools": {"falco": {"critical": False}},
    }

    with (
        patch.object(
            update_versions, "check_latest_versions", return_value=fake_results
        ),
        patch.object(update_versions, "load_versions", return_value=fake_versions),
        patch.object(
            update_versions.subprocess,
            "run",
            side_effect=_gh_mock_side_effect(created_titles),
        ),
    ):
        count = update_versions.check_outdated_and_create_issues(create_issues=True)

    # Both outdated tools are counted (messaging stays honest)...
    assert count == 2
    # ...but only the normal tool got an issue.
    assert any("Update bandit to " in t for t in created_titles)
    assert not any("falco" in t for t in created_titles)
    for manual in update_versions.MANUAL_INSTALL_TOOLS:
        assert not any(manual in t for t in created_titles)


def test_only_manual_outdated_creates_no_issues():
    """If ONLY manual tools are outdated, zero issues are created."""
    created_titles: list[str] = []

    fake_results = {
        "falco": ("0.0.0", "0.43.1", True),
        "akto": ("mini-testing-1.53.7", "1.98.0", True),
    }
    fake_versions = {"python_tools": {}, "binary_tools": {}, "special_tools": {}}

    with (
        patch.object(
            update_versions, "check_latest_versions", return_value=fake_results
        ),
        patch.object(update_versions, "load_versions", return_value=fake_versions),
        patch.object(
            update_versions.subprocess,
            "run",
            side_effect=_gh_mock_side_effect(created_titles),
        ),
    ):
        count = update_versions.check_outdated_and_create_issues(create_issues=True)

    assert count == 2  # both manual tools counted as outdated
    assert created_titles == []  # but no issues filed


def test_lingering_manual_issue_is_swept_closed():
    """A pre-existing 'Update <manual-tool>' issue must be auto-closed (self-healing).

    The superseded-issue sweep now includes manual tools, so issues filed before
    this behavior change get closed and never re-created.
    """
    closed_numbers: list[str] = []

    def _run(cmd, *args, **kwargs):
        result = MagicMock(spec=subprocess.CompletedProcess)
        result.returncode = 0
        result.stdout = ""
        if "list" in cmd:
            # An old manual-tool issue is still open.
            result.stdout = '[{"number": 529, "title": "Update falco to v0.43.1"}]'
        elif "close" in cmd:
            closed_numbers.append(cmd[cmd.index("close") + 1])
        elif "create" in cmd:  # pragma: no cover - manual tools never create
            raise AssertionError("manual tool must not create an issue")
        return result

    fake_results = {"falco": ("0.0.0", "0.43.1", True)}
    fake_versions = {"python_tools": {}, "binary_tools": {}, "special_tools": {}}

    with (
        patch.object(
            update_versions, "check_latest_versions", return_value=fake_results
        ),
        patch.object(update_versions, "load_versions", return_value=fake_versions),
        patch.object(update_versions.subprocess, "run", side_effect=_run),
    ):
        update_versions.check_outdated_and_create_issues(create_issues=True)

    assert "529" in closed_numbers
