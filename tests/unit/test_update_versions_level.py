"""Unit tests for _select_tools_for_update() and the --level cumulative filter.

The bump-level filter decides which tools `--update-all` actually writes to
versions.yaml. It's the load-bearing gate that keeps major and `unknown` bumps
out of the weekly auto-merge PR — getting it wrong would auto-merge a risky
bump on green CI, which is exactly what the 24h soak window + contract-test
gate exist to prevent.

These tests pin the cumulative semantics:
  --level=patch    → {patch}
  --level=minor    → {patch, minor}
  --level=major    → {patch, minor, major}   (unknown stays out)
  --level=all      → {patch, minor, major, unknown}
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


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
_select_tools_for_update = update_versions._select_tools_for_update
_LEVEL_INCLUDES = update_versions._LEVEL_INCLUDES


# Representative mixed-bump fixture covering every classification outcome.
# Each entry maps tool name to (current, latest, is_outdated).
MIXED_RESULTS: dict[str, tuple[str, str, bool]] = {
    "bandit": ("1.9.3", "1.9.4", True),  # patch
    "semgrep": ("1.151.0", "1.159.0", True),  # minor
    "kubescape": ("3.0.47", "4.0.5", True),  # major
    "falco": ("0.0.0", "0.43.1", True),  # major (0.x)
    "akto": ("mini-testing-1.53.7", "1.98.0", True),  # unknown
    "ruff": ("0.6.0", "0.6.0", False),  # up-to-date — always skipped
}

# critical flag layout mirroring versions.yaml structure (category → tool → info).
MIXED_VERSIONS: dict = {
    "python_tools": {
        "bandit": {"version": "1.9.3", "critical": False},
        "semgrep": {"version": "1.151.0", "critical": True},
        "ruff": {"version": "0.6.0", "critical": False},
    },
    "binary_tools": {
        "kubescape": {"version": "3.0.47", "critical": True},
        "falco": {"version": "0.0.0", "critical": False},
    },
    "special_tools": {
        "akto": {"version": "mini-testing-1.53.7", "critical": False},
    },
}


def _tool_names(selected: list[tuple[str, str, str]]) -> set[str]:
    return {entry[0] for entry in selected}


@pytest.mark.parametrize(
    ("level", "expected_selected"),
    [
        ("patch", {"bandit"}),
        ("minor", {"bandit", "semgrep"}),
        ("major", {"bandit", "semgrep", "kubescape", "falco"}),
        ("all", {"bandit", "semgrep", "kubescape", "falco", "akto"}),
    ],
)
def test_select_tools_by_level_cumulative(
    level: str, expected_selected: set[str]
) -> None:
    """--level is a cumulative filter — lower levels always include higher-priority bumps."""
    to_update, skipped = _select_tools_for_update(
        MIXED_RESULTS, MIXED_VERSIONS, critical_only=False, level=level
    )
    assert _tool_names(to_update) == expected_selected
    # Up-to-date tools never appear in either list.
    assert "ruff" not in _tool_names(to_update)
    assert all(name != "ruff" for name, *_ in skipped)


def test_select_tools_excludes_unknown_even_at_major() -> None:
    """'unknown' is only included with explicit --level=all."""
    to_update, skipped = _select_tools_for_update(
        MIXED_RESULTS, MIXED_VERSIONS, critical_only=False, level="major"
    )
    assert "akto" not in _tool_names(to_update)
    skipped_names = {name for name, *_ in skipped}
    assert "akto" in skipped_names


def test_select_tools_critical_only_narrows_after_level() -> None:
    """critical_only filters further — tools must be critical AND within the level."""
    to_update, skipped = _select_tools_for_update(
        MIXED_RESULTS, MIXED_VERSIONS, critical_only=True, level="all"
    )
    # Only semgrep and kubescape are critical in the fixture.
    assert _tool_names(to_update) == {"semgrep", "kubescape"}
    # Non-critical tools should appear in skipped with reason "non-critical".
    skipped_map = {name: reason for name, _, _, reason in skipped}
    assert skipped_map.get("bandit") == "non-critical"


def test_select_tools_rejects_invalid_level() -> None:
    with pytest.raises(ValueError, match="Unknown bump level"):
        _select_tools_for_update(
            MIXED_RESULTS, MIXED_VERSIONS, critical_only=False, level="banana"
        )


def test_level_includes_hierarchy_is_monotonic() -> None:
    """Guardrail: any future edit to _LEVEL_INCLUDES must preserve strict subset ordering."""
    assert _LEVEL_INCLUDES["patch"] <= _LEVEL_INCLUDES["minor"]
    assert _LEVEL_INCLUDES["minor"] <= _LEVEL_INCLUDES["major"]
    assert _LEVEL_INCLUDES["major"] <= _LEVEL_INCLUDES["all"]
    # 'unknown' must remain gated behind --level=all, never bleed into lower tiers.
    assert "unknown" not in _LEVEL_INCLUDES["major"]
    assert "unknown" in _LEVEL_INCLUDES["all"]
