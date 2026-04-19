"""Unit tests for check_profile's per-tool exception guard.

Regression: previously, an uncaught exception from any single
check_tool() call would kill `jmo tools check --profile <X>` with
zero stdout and exit code 1. The --json output never made it to the
pipe because json.dumps was never reached. This blocked CI validation
of the v1.0.2 deep Docker image where one of yara/scancode/etc.
segfaulted or raised during the check.

The guard converts any per-tool exception to an installed=False
ToolStatus with the exception details in install_hint.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture
def manager():
    from scripts.cli.tool_manager import ToolManager

    return ToolManager()


def test_check_profile_isolates_per_tool_exceptions(manager) -> None:
    """One crashing tool should not kill the rest of the profile."""
    from scripts.cli.tool_manager import ToolStatus

    def fake_check(name: str) -> ToolStatus:
        if name == "nuclei":
            raise RuntimeError("simulated segfault probe")
        return ToolStatus(name=name, installed=True)

    with patch.object(manager, "check_tool", side_effect=fake_check):
        result = manager.check_profile("fast")

    # Every tool in PROFILE_TOOLS["fast"] must still be in the result
    from scripts.core.tool_registry import PROFILE_TOOLS

    assert set(result.keys()) == set(PROFILE_TOOLS["fast"])

    # The crashing tool reports installed=False with the exception in install_hint
    assert result["nuclei"].installed is False
    assert "RuntimeError" in result["nuclei"].install_hint
    assert "simulated segfault probe" in result["nuclei"].install_hint

    # All other tools still report installed=True
    for name, status in result.items():
        if name != "nuclei":
            assert status.installed is True


def test_check_profile_empty_on_unknown_profile(manager) -> None:
    """Unknown profile returns empty dict, no exception."""
    assert manager.check_profile("nonexistent-profile") == {}


def test_check_profile_still_works_when_all_tools_succeed(manager) -> None:
    """Smoke: no crash path, all tools return cleanly."""
    from scripts.cli.tool_manager import ToolStatus

    with patch.object(
        manager,
        "check_tool",
        side_effect=lambda n: ToolStatus(name=n, installed=True),
    ):
        result = manager.check_profile("fast")
    assert len(result) > 0
    assert all(s.installed for s in result.values())


def test_check_profile_multiple_tools_can_crash_independently(manager) -> None:
    """Two crashing tools don't interfere with each other or block healthy ones."""
    from scripts.cli.tool_manager import ToolStatus

    def fake_check(name: str) -> ToolStatus:
        if name == "nuclei":
            raise OSError("disk full")
        if name == "semgrep":
            raise ImportError("yara-python segfault probe")
        return ToolStatus(name=name, installed=True)

    with patch.object(manager, "check_tool", side_effect=fake_check):
        result = manager.check_profile("fast")

    assert result["nuclei"].installed is False
    assert "OSError" in result["nuclei"].install_hint
    assert result["semgrep"].installed is False
    assert "ImportError" in result["semgrep"].install_hint
    # Other tools unaffected
    assert result["trufflehog"].installed is True
