"""
Golden tests: each adapter replays a real output of its tool and must produce
the findings recorded beside it.

These catch:
- Silent adapter failures (parsing returns [] when it should find issues)
- Tool output format changes (upstream tools change JSON structure)
- Adapter regressions (bugs in parsing logic)

Every tool in TOOL_MATRIX has a fixture, and the guards below fail when one is
missing, empty or incomplete (#1097). Until v2.0.0 Phase 6 a registered tool
with no fixture generated no test at all, a fixture holding 0 findings passed
`0 == 0`, and an adapter that would not import skipped: kubescape's adapter
returned [] on every real scan for two major versions (#1094) with nothing here
to say so.

The adapter is the one the report reads a tool's output with (`count_findings`
in `scripts/core/normalize_and_report.py`): the registry entry named
`tool.replace("-", "_")`, which is also the fixture directory's name.

Usage:
    pytest tests/adapters/test_adapter_golden.py -v
    pytest tests/adapters/test_adapter_golden.py -v -k "trivy"

Capturing a fixture (needs the tool installed):
    python scripts/dev/generate_golden.py --tool <tool>
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from scripts.core.plugin_loader import get_plugin_loader, get_plugin_registry
from scripts.core.tool_registry import TOOL_MATRIX

GOLDEN_DIR = Path(__file__).parent.parent / "fixtures" / "golden"

# The three files a capture writes (scripts/dev/generate_golden.py).
RAW = "raw-output.json"
EXPECTED = "expected-findings.json"
METADATA = "metadata.json"


def adapter_name(tool: str) -> str:
    """The name the report looks a tool's adapter up by, and the fixture
    directory's: `osv-scanner` -> `osv_scanner`."""
    return get_plugin_loader()._tool_to_adapter_name(tool)


def get_golden_test_cases() -> list[tuple[str, str, Path]]:
    """Every version directory under every tool directory, whatever it holds,
    so an incomplete one fails its case rather than going missing."""
    if not GOLDEN_DIR.is_dir():
        return []
    return [
        (tool_dir.name, version_dir.name, version_dir)
        for tool_dir in sorted(p for p in GOLDEN_DIR.iterdir() if p.is_dir())
        for version_dir in sorted(p for p in tool_dir.iterdir() if p.is_dir())
    ]


def get_adapter_for_tool(name: str) -> Any:
    """The adapter registered as `name`. A name with none fails the test: a skip
    here is how an unimportable adapter went unnoticed."""
    plugin = get_plugin_registry().get(name)
    assert plugin is not None, f"no adapter is registered as {name!r}"
    return plugin()


def findings_to_comparable(findings: list[Any]) -> set[str]:
    """Findings as a set of ids, or (ruleId, path, line) where one has none."""
    identifiers = set()
    for f in findings:
        f_dict = asdict(f) if hasattr(f, "__dataclass_fields__") else f
        if f_dict.get("id"):
            identifiers.add(f_dict["id"])
        else:
            location = f_dict.get("location", {})
            path = location.get("path", "") if isinstance(location, dict) else ""
            line = location.get("startLine", 0) if isinstance(location, dict) else 0
            identifiers.add(f"{f_dict.get('ruleId', '')}:{path}:{line}")
    return identifiers


def _load(path: Path) -> Any:
    return json.loads(path.read_bytes())


GOLDEN_TEST_CASES = get_golden_test_cases()
CASE_IDS = [f"{t}-{v}" for t, v, _ in GOLDEN_TEST_CASES]


class TestAdapterGolden:
    """Each adapter against each of its tool's real outputs."""

    @pytest.mark.parametrize("tool,version,golden_dir", GOLDEN_TEST_CASES, ids=CASE_IDS)
    def test_adapter_produces_expected_findings(
        self, tool: str, version: str, golden_dir: Path
    ):
        """The findings must match the recorded ones, by count and by id."""
        expected_findings = _load(golden_dir / EXPECTED)
        actual_findings = get_adapter_for_tool(tool).parse(golden_dir / RAW)

        actual_ids = findings_to_comparable(actual_findings)
        expected_ids = findings_to_comparable(expected_findings)

        assert len(actual_findings) == len(expected_findings), (
            f"Finding count mismatch for {tool} {version}:\n"
            f"  Expected: {len(expected_findings)} findings\n"
            f"  Actual:   {len(actual_findings)} findings\n"
            f"  This may indicate the tool's output format changed!\n"
            f"  Missing: {expected_ids - actual_ids}\n"
            f"  Extra:   {actual_ids - expected_ids}"
        )
        assert actual_ids == expected_ids, (
            f"Finding IDs don't match for {tool} {version}:\n"
            f"  Missing (expected but not found): {expected_ids - actual_ids}\n"
            f"  Extra (found but not expected):   {actual_ids - expected_ids}"
        )

    @pytest.mark.parametrize("tool,version,golden_dir", GOLDEN_TEST_CASES, ids=CASE_IDS)
    def test_adapter_findings_have_valid_schema(
        self, tool: str, version: str, golden_dir: Path
    ):
        """Every finding has a ruleId or id, a known severity, a located path and
        a named tool."""
        findings = get_adapter_for_tool(tool).parse(golden_dir / RAW)
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

        for i, finding in enumerate(findings):
            f_dict = asdict(finding)
            assert "ruleId" in f_dict or "id" in f_dict, f"Finding {i} has no ruleId/id"
            assert f_dict.get("severity") in valid_severities, (
                f"Finding {i} has invalid severity {f_dict.get('severity')!r}"
            )
            location = f_dict.get("location", {})
            if location:
                assert "path" in location, f"Finding {i} location missing 'path'"
            tool_info = f_dict.get("tool", {})
            if tool_info:
                assert "name" in tool_info, f"Finding {i} tool missing 'name'"


class TestGoldenInfrastructure:
    """The fixtures themselves: one per matrix tool, none empty, none partial."""

    def test_every_matrix_tool_has_an_adapter(self):
        for tool in TOOL_MATRIX:
            assert get_plugin_registry().get(adapter_name(tool)) is not None, (
                f"{tool}: no adapter is registered as {adapter_name(tool)!r}"
            )

    def test_every_matrix_tool_has_a_fixture(self):
        # A tool with no directory generated no case before #1097's guard: six
        # registered tools were "covered" that way.
        missing = [
            tool
            for tool in TOOL_MATRIX
            if not any(p.is_dir() for p in (GOLDEN_DIR / adapter_name(tool)).glob("v*"))
        ]
        assert not missing, (
            f"no golden fixture for {missing}: "
            "python scripts/dev/generate_golden.py --tool <tool>"
        )

    def test_every_fixture_directory_is_a_matrix_tool(self):
        # One spelling: the adapter name. An `osv-scanner/` beside
        # `osv_scanner/` would be a second, unguarded copy.
        names = {adapter_name(tool) for tool in TOOL_MATRIX}
        strays = [
            p.name for p in GOLDEN_DIR.iterdir() if p.is_dir() and p.name not in names
        ]
        assert not strays, f"fixture directories for no matrix tool: {strays}"

    @pytest.mark.parametrize("tool,version,golden_dir", GOLDEN_TEST_CASES, ids=CASE_IDS)
    def test_a_fixture_is_the_three_files_a_capture_writes(
        self, tool: str, version: str, golden_dir: Path
    ):
        # metadata.json used to count as the "raw output" a fixture needed.
        assert sorted(p.name for p in golden_dir.iterdir()) == sorted(
            [EXPECTED, METADATA, RAW]
        )

    @pytest.mark.parametrize("tool,version,golden_dir", GOLDEN_TEST_CASES, ids=CASE_IDS)
    def test_a_fixture_holds_findings_and_says_how_many(
        self, tool: str, version: str, golden_dir: Path
    ):
        # `0 == 0` passed semgrep's empty fixture until Phase 5 removed it.
        expected = _load(golden_dir / EXPECTED)
        metadata = _load(golden_dir / METADATA)
        assert isinstance(expected, list) and len(expected) > 0, (
            f"{tool} {version}: no expected finding"
        )
        assert metadata["finding_count"] == len(expected)
        assert adapter_name(metadata["tool"]) == tool
        assert version == f"v{metadata['version']}"
