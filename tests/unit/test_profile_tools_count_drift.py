#!/usr/bin/env python3
"""SSOT drift guard: tool counts across Python, test, and YAML must agree.

`scripts/core/tool_registry.py` is the canonical source of truth for which
tools belong to each profile (`PROFILE_TOOLS`) and which are intentionally
not in any Docker image (`MANUAL_INSTALL_TOOLS`). Two downstream constants
mirror PROFILE_TOOLS - MANUAL_INSTALL_TOOLS counts:

1. `tests/e2e/test_docker_workflows.py::DOCKER_VARIANTS` (Python test constant)
2. `.github/workflows/scheduled.yml` `validate-variants` matrix (YAML workflow)

Both must equal `len(PROFILE_TOOLS[v]) - len(MANUAL_INSTALL_TOOLS & PROFILE_TOOLS[v])`
for each variant. A YAML matrix can't `import PROFILE_TOOLS`, so this test
keeps both downstream constants hardcoded but asserts the runtime relationship
at PR time. This catches the drift class that took 5 cascading PRs to resolve
during the v1.0.3 cycle (#343 → #344 → #345 → #346 → #347 after bearer removal).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.core.tool_registry import MANUAL_INSTALL_TOOLS, PROFILE_TOOLS

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_VARIANTS = {"fast", "slim", "balanced", "deep"}


def _expected_image_tool_count(variant: str) -> int:
    """Tools that should be in the variant's Docker image.

    MANUAL_INSTALL_TOOLS appear in PROFILE_TOOLS so users can opt into them
    via `jmo tools install`, but are intentionally NOT baked into Docker
    images (too heavy, license-restricted, or upstream packaging issues).
    """
    profile_set = set(PROFILE_TOOLS[variant])
    return len(profile_set) - len(MANUAL_INSTALL_TOOLS & profile_set)


@pytest.fixture(scope="module")
def docker_variants_constant() -> dict[str, int]:
    """Extract {variant: expected_tools} from tests/e2e/test_docker_workflows.py."""
    from tests.e2e.test_docker_workflows import DOCKER_VARIANTS

    out: dict[str, int] = {}
    for entry in DOCKER_VARIANTS:
        variant_name, count = entry.values
        out[str(variant_name)] = int(count)  # type: ignore[arg-type]
    return out


@pytest.fixture(scope="module")
def scheduled_yml_matrix() -> dict[str, int]:
    """Extract {variant: expected_tools} from scheduled.yml validate-variants matrix."""
    yml_path = REPO_ROOT / ".github" / "workflows" / "scheduled.yml"
    with yml_path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    matrix = data["jobs"]["validate-variants"]["strategy"]["matrix"]["include"]
    return {row["variant"]: row["expected_tools"] for row in matrix}


@pytest.mark.parametrize("variant", sorted(EXPECTED_VARIANTS))
def test_docker_variants_constant_matches_profile_tools(
    variant: str, docker_variants_constant: dict[str, int]
) -> None:
    """tests/e2e/test_docker_workflows.py::DOCKER_VARIANTS counts match PROFILE_TOOLS."""
    expected = _expected_image_tool_count(variant)
    actual = docker_variants_constant[variant]
    assert actual == expected, (
        f"DOCKER_VARIANTS for '{variant}' has expected_tools={actual}, "
        f"but PROFILE_TOOLS['{variant}'] - MANUAL_INSTALL_TOOLS = {expected}.\n"
        f"When changing PROFILE_TOOLS, update BOTH:\n"
        f"  - tests/e2e/test_docker_workflows.py::DOCKER_VARIANTS\n"
        f"  - .github/workflows/scheduled.yml validate-variants matrix"
    )


@pytest.mark.parametrize("variant", sorted(EXPECTED_VARIANTS))
def test_scheduled_yml_matrix_matches_profile_tools(
    variant: str, scheduled_yml_matrix: dict[str, int]
) -> None:
    """scheduled.yml validate-variants matrix counts match PROFILE_TOOLS."""
    expected = _expected_image_tool_count(variant)
    actual = scheduled_yml_matrix[variant]
    assert actual == expected, (
        f"scheduled.yml validate-variants matrix for '{variant}' has "
        f"expected_tools={actual}, but PROFILE_TOOLS['{variant}'] - "
        f"MANUAL_INSTALL_TOOLS = {expected}.\n"
        f"When changing PROFILE_TOOLS, update BOTH:\n"
        f"  - .github/workflows/scheduled.yml validate-variants matrix\n"
        f"  - tests/e2e/test_docker_workflows.py::DOCKER_VARIANTS"
    )


def test_all_three_sources_define_same_variants(
    docker_variants_constant: dict[str, int],
    scheduled_yml_matrix: dict[str, int],
) -> None:
    """PROFILE_TOOLS, DOCKER_VARIANTS, and scheduled.yml matrix all enumerate the same 4 variants."""
    assert set(PROFILE_TOOLS.keys()) == EXPECTED_VARIANTS, (
        f"PROFILE_TOOLS variants drifted: expected {EXPECTED_VARIANTS}, "
        f"got {set(PROFILE_TOOLS.keys())}"
    )
    assert set(docker_variants_constant.keys()) == EXPECTED_VARIANTS, (
        f"DOCKER_VARIANTS drifted: expected {EXPECTED_VARIANTS}, "
        f"got {set(docker_variants_constant.keys())}"
    )
    assert set(scheduled_yml_matrix.keys()) == EXPECTED_VARIANTS, (
        f"scheduled.yml matrix drifted: expected {EXPECTED_VARIANTS}, "
        f"got {set(scheduled_yml_matrix.keys())}"
    )


def test_manual_install_tools_subset_of_deep_profile() -> None:
    """All MANUAL_INSTALL_TOOLS must appear in PROFILE_TOOLS['deep'].

    MANUAL_INSTALL_TOOLS only makes sense as a subset of a profile — these
    are tools users can opt into via `jmo tools install` but that aren't
    baked into images. If one is in MANUAL_INSTALL_TOOLS but not in any
    profile, it's unreachable.
    """
    deep_set = set(PROFILE_TOOLS["deep"])
    orphans = MANUAL_INSTALL_TOOLS - deep_set
    assert not orphans, (
        f"MANUAL_INSTALL_TOOLS contains tools not in PROFILE_TOOLS['deep']: "
        f"{orphans}. Either add them to a profile or remove from "
        f"MANUAL_INSTALL_TOOLS."
    )
