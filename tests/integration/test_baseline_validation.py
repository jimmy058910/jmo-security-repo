#!/usr/bin/env python3
"""
Baseline validation tests for JMo Security.

These tests validate scan results against known vulnerability baselines,
ensuring that JMo Security correctly detects expected vulnerabilities in
well-known vulnerable applications.

Requires:
- Security tools installed (`jmo tools install`)
- Network access to clone each target at its pinned commit (tests/integration/targets.py)
- About two minutes per target on a workstation (measured), clone and scan

Targets:
- OWASP Juice Shop (Node.js)
- OWASP WebGoat (Java)
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from tests.integration.juice_shop_markers import (
    MARKERS_FILE,
    detection_table,
    parse_markers,
    recall_by_type,
)
from tests.integration.targets import (
    JUICE_SHOP_COMMIT,
    PINNED_TARGETS,
    SCAN_TIMEOUT,
    clone_at_commit,
    count_by_tool,
    finding_cwes,
    load_findings,
    run_scan,
)

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
BASELINES_DIR = PROJECT_ROOT / "tests" / "integration" / "baselines"

# Clone and scan of one target. Above run_scan's own timeout on purpose: with
# timeout_method = "thread", pytest-timeout firing first kills the whole run,
# where the scan's TimeoutExpired is an ordinary failure.
TARGET_TEST_TIMEOUT = SCAN_TIMEOUT + 900

# stderr lines quoted when the scan itself fails.
STDERR_TAIL_LINES = 20

# What parse_markers finds at the pinned juice-shop commit: marked lines, files,
# and (file, line, challenge) triples (a line may name several challenges). A
# different count means the pin moved or the parser is wrong. Two more lines
# (lib/codingChallenges.ts) name the directive inside juice-shop's own
# marker-reading code; they are not markers and are not counted.
EXPECTED_MARKER_COUNTS = {"lines": 38, "files": 16, "triples": 44}


@dataclass
class BaselineValidationResult:
    """Results from validating a scan against a baseline."""

    target: str
    total_expected: int
    total_found: int
    missing_critical: int
    missing_high: int
    missing_medium: int
    extra_count: int
    missing_rules: list[str]
    passed: bool


@dataclass(frozen=True)
class TargetScan:
    """One target cloned and scanned: where, and how the scan ended."""

    target_path: Path
    results_dir: Path
    returncode: int
    stderr: str


def load_baseline(baseline_file: Path) -> dict[str, Any]:
    """Load a baseline file."""
    with open(baseline_file, encoding="utf-8") as f:
        return json.load(f)


def load_marker_table() -> dict[str, Any]:
    """Load the recorded marker detection table."""
    if not MARKERS_FILE.exists():
        raise FileNotFoundError(
            f"{MARKERS_FILE} is not recorded: scan juice-shop at its pin, then run "
            "python -m tests.integration.juice_shop_markers record <clone> <results_dir>"
        )
    return json.loads(MARKERS_FILE.read_bytes())


def extract_rule_ids(findings: list[dict[str, Any]]) -> Counter[str]:
    """Extract and count rule IDs from findings.

    Extracts both tool-specific ruleIds and CWE identifiers. Every CWE is reduced
    to its bare id (``"CWE-89: Improper ..."`` counts as ``CWE-89``) and a finding
    counts once per distinct id, the way scripts/dev/generate_baseline.py records
    it. See ``finding_cwes`` for where the CWE data is read from.
    """
    rule_counts: Counter[str] = Counter()

    for finding in findings:
        rule_id = finding.get("ruleId", finding.get("rule_id", ""))
        if rule_id:
            rule_counts[rule_id] += 1

        rule_counts.update(finding_cwes(finding))

    return rule_counts


def compare_to_baseline(
    findings: list[dict[str, Any]],
    baseline: dict[str, Any],
) -> BaselineValidationResult:
    """Compare scan findings to a baseline."""
    expected = baseline["expected_findings"]
    tolerance = baseline["tolerance"]
    target = baseline["metadata"]["target"]

    # Extract found rule IDs
    found_rules = extract_rule_ids(findings)

    # Track missing findings by severity
    missing_critical = 0
    missing_high = 0
    missing_medium = 0
    missing_rules = []

    for expected_finding in expected:
        rule_id = expected_finding["rule_id"]
        severity = expected_finding["severity"]
        min_count = expected_finding.get("min_count", 1)

        found_count = found_rules.get(rule_id, 0)

        if found_count < min_count:
            missing_rules.append(
                f"{rule_id} (expected {min_count}, found {found_count})"
            )

            if severity == "CRITICAL":
                missing_critical += 1
            elif severity == "HIGH":
                missing_high += 1
            elif severity == "MEDIUM":
                missing_medium += 1

    # Calculate extra findings
    expected_total = sum(e.get("min_count", 1) for e in expected)
    total_found = sum(found_rules.values())
    extra_count = max(0, total_found - expected_total)
    extra_ratio = extra_count / expected_total if expected_total > 0 else 0

    # Determine if passed
    passed = (
        missing_critical <= tolerance.get("missing_critical", 0)
        and missing_high <= tolerance.get("missing_high", 2)
        and missing_medium <= tolerance.get("missing_medium", 5)
        and extra_ratio <= tolerance.get("extra_findings_ratio", 0.3)
    )

    return BaselineValidationResult(
        target=target,
        total_expected=len(expected),
        total_found=len(findings),
        missing_critical=missing_critical,
        missing_high=missing_high,
        missing_medium=missing_medium,
        extra_count=extra_count,
        missing_rules=missing_rules,
        passed=passed,
    )


@pytest.fixture(scope="module")
def scanned_target(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Callable[[str], TargetScan]]:
    """Clone and scan each target once per module and share the result.

    A full scan takes minutes, so a second test about the same target (the
    marker-recall test reads juice-shop's findings too) must not pay for another.
    A clone that fails or times out raises, and is not cached. The commit is the
    one the target's baseline was derived at (see tests/integration/targets.py).
    """
    scans: dict[str, TargetScan] = {}
    short_dirs: list[Path] = []

    def scratch_dir(name: str) -> Path:
        if sys.platform != "win32":
            return tmp_path_factory.mktemp(name)
        # Deep repos exceed Windows MAX_PATH under pytest's long tmp_path; the
        # function-scoped short_tmp_path fixture cannot serve a module scope.
        short_base = Path("C:/tmp")
        short_base.mkdir(exist_ok=True)
        short_dir = Path(tempfile.mkdtemp(prefix="jmo-", dir=short_base))
        short_dirs.append(short_dir)
        return short_dir

    def scan(name: str) -> TargetScan:
        if name not in scans:
            root = scratch_dir(name)
            target_path = root / "target"
            results_dir = root / "results"
            pin = PINNED_TARGETS[name]
            clone_at_commit(pin.url, pin.commit, target_path)
            done = run_scan(target_path, results_dir)
            scans[name] = TargetScan(
                target_path, results_dir, done.returncode, done.stderr
            )
        return scans[name]

    yield scan

    for short_dir in short_dirs:
        shutil.rmtree(short_dir, ignore_errors=True)


@pytest.mark.integration
@pytest.mark.baseline
@pytest.mark.slow
@pytest.mark.requires_tools
class TestBaselineValidation:
    """Validate scan results against known vulnerability baselines."""

    @pytest.mark.parametrize("name", list(PINNED_TARGETS))
    @pytest.mark.timeout(TARGET_TEST_TIMEOUT)
    def test_scan_matches_baseline(
        self, name: str, scanned_target: Callable[[str], TargetScan]
    ):
        """A scan must succeed, meet every expected row, and keep every tool reporting."""
        baseline = load_baseline(BASELINES_DIR / f"{name}.baseline.json")
        scan = scanned_target(name)

        stderr_tail = "\n".join(scan.stderr.splitlines()[-STDERR_TAIL_LINES:])
        assert scan.returncode == 0, (
            f"jmo scan of {name} exited {scan.returncode}; "
            f"last {STDERR_TAIL_LINES} stderr lines:\n{stderr_tail}"
        )

        findings = load_findings(scan.results_dir)
        result = compare_to_baseline(findings, baseline)

        # Report results
        print(f"\nBaseline Validation: {result.target}")
        print(f"  Expected: {result.total_expected} findings")
        print(f"  Found: {result.total_found} findings")
        print(f"  Missing CRITICAL: {result.missing_critical}")
        print(f"  Missing HIGH: {result.missing_high}")
        print(f"  Missing MEDIUM: {result.missing_medium}")

        # Tools: each one recorded as producing findings must still produce some.
        recorded = baseline["metadata"]["findings_per_tool"]
        current = count_by_tool(findings)
        for tool, was in sorted(recorded.items()):
            print(f"  {tool}: {current.get(tool, 0)} findings (recorded {was})")
        silent = sorted(tool for tool in recorded if current.get(tool, 0) < 1)

        problems = []
        if result.missing_rules:
            problems.append(f"expected rows not met: {result.missing_rules}")
        if silent:
            problems.append(f"tools with no findings now: {silent}")
        assert not problems, f"{result.target} drifted from its baseline: " + "; ".join(
            problems
        )


@pytest.mark.integration
@pytest.mark.baseline
@pytest.mark.slow
@pytest.mark.requires_tools
class TestJuiceShopMarkers:
    """juice-shop's own vulnerable-line markers grade the whole scan, line by line."""

    @pytest.mark.timeout(TARGET_TEST_TIMEOUT)
    def test_lines_detected_before_are_still_detected(
        self, scanned_target: Callable[[str], TargetScan]
    ):
        """A marked line some tool reported when recorded must still have one.

        Lines newly detected, and lines whose detecting tools changed, are
        printed, not failed on: record them (python -m
        tests.integration.juice_shop_markers record) in the change that made them.
        """
        scan = scanned_target("juice-shop")

        markers = parse_markers(scan.target_path)
        counts = {
            "lines": len({(m.file, m.line) for m in markers}),
            "files": len({m.file for m in markers}),
            "triples": len(markers),
        }
        assert counts == EXPECTED_MARKER_COUNTS, (
            f"juice-shop at the pin has {counts} marked lines, files and triples, "
            f"expected {EXPECTED_MARKER_COUNTS}: the pin moved or the parser is wrong"
        )

        stderr_tail = "\n".join(scan.stderr.splitlines()[-STDERR_TAIL_LINES:])
        assert scan.returncode == 0, (
            f"jmo scan of juice-shop exited {scan.returncode}; "
            f"last {STDERR_TAIL_LINES} stderr lines:\n{stderr_tail}"
        )

        recorded = {
            (row["file"], row["line"]): tuple(row["tools"])
            for row in load_marker_table()["lines"]
        }
        rows = detection_table(markers, load_findings(scan.results_dir))

        print("\nJuice Shop marker recall (marked lines a tool reported):")
        detected = sum(bool(row.tools) for row in rows)
        for kind, count in recall_by_type(rows).items():
            print(f"  {kind}: {count['detected']} of {count['marked']}")
        print(f"  total: {detected} of {len(rows)}")

        lost = []
        for row in rows:
            before = recorded.get((row.file, row.line), ())
            where = f"{row.file}:{row.line}"
            if before and not row.tools:
                lost.append(f"{where} (recorded: {', '.join(before)})")
            elif row.tools and not before:
                print(f"  newly detected: {where} by {', '.join(row.tools)}")
            elif row.tools != before:
                print(
                    f"  tools changed: {where} was {', '.join(before)}, "
                    f"now {', '.join(row.tools)}"
                )
        assert not lost, (
            "marked lines detected when recorded, by no tool now: " + "; ".join(lost)
        )


@pytest.mark.integration
@pytest.mark.baseline
class TestBaselineSchemaValidation:
    """Test that baseline files conform to the schema."""

    def test_baseline_files_exist(self):
        """Baseline files should exist."""
        assert BASELINES_DIR.exists(), "Baselines directory not found"

        baseline_files = list(BASELINES_DIR.glob("*.baseline.json"))
        assert len(baseline_files) >= 1, "No baseline files found"

    def test_baseline_files_valid_json(self):
        """All baseline files should be valid JSON."""
        for baseline_file in BASELINES_DIR.glob("*.baseline.json"):
            with open(baseline_file, encoding="utf-8") as f:
                data = json.load(f)

            # Check required top-level keys
            assert "metadata" in data, f"{baseline_file.name} missing metadata"
            assert "expected_findings" in data, (
                f"{baseline_file.name} missing expected_findings"
            )
            assert "tolerance" in data, f"{baseline_file.name} missing tolerance"

    def test_baseline_metadata_complete(self):
        """Baseline metadata should have required fields."""
        for baseline_file in BASELINES_DIR.glob("*.baseline.json"):
            baseline = load_baseline(baseline_file)
            metadata = baseline["metadata"]

            assert "target" in metadata, f"{baseline_file.name} metadata missing target"
            assert "version" in metadata, (
                f"{baseline_file.name} metadata missing version"
            )

            # What the scan test asserts tool by tool; an empty map asserts nothing.
            per_tool = metadata.get("findings_per_tool")
            assert per_tool, f"{baseline_file.name} has no findings_per_tool"
            assert all(isinstance(n, int) and n >= 1 for n in per_tool.values()), (
                f"{baseline_file.name} lists a tool with no findings: {per_tool}"
            )
            assert metadata.get("tools_used") == sorted(per_tool), (
                f"{baseline_file.name} tools_used disagrees with findings_per_tool"
            )

    def test_baseline_files_match_the_schema(self):
        """Every baseline validates against baseline_schema.json."""
        with open(BASELINES_DIR / "baseline_schema.json", encoding="utf-8") as f:
            schema = json.load(f)

        baseline_files = list(BASELINES_DIR.glob("*.baseline.json"))
        assert baseline_files, "No baseline files found"
        for baseline_file in baseline_files:
            jsonschema.validate(load_baseline(baseline_file), schema)

    @pytest.mark.parametrize("name", list(PINNED_TARGETS))
    def test_baselines_pin_the_commit_the_test_scans(self, name: str):
        """A baseline describes one revision; the test must scan that revision.

        Bumping a pin without re-deriving the baseline (or the reverse) would
        compare one revision's findings against another's expectations.
        """
        pin = PINNED_TARGETS[name]
        metadata = load_baseline(BASELINES_DIR / f"{name}.baseline.json")["metadata"]
        assert metadata["target"] == pin.slug
        assert metadata["version"] == pin.commit, (
            f"{name}.baseline.json was derived at {metadata['version']} but the "
            f"test scans {pin.commit}: re-run scripts/dev/generate_baseline.py "
            f"--target {name}"
        )

    def test_marker_table_pins_the_commit_the_test_scans(self):
        """The recorded marker table describes one revision, as the baseline does."""
        commit = load_marker_table()["metadata"]["commit"]
        assert commit == JUICE_SHOP_COMMIT, (
            f"juice-shop.markers.json was derived at {commit} but the test scans "
            f"{JUICE_SHOP_COMMIT}: re-record it (python -m "
            f"tests.integration.juice_shop_markers record <clone> <results_dir>)"
        )

    def test_expected_findings_have_required_fields(self):
        """Each expected finding should have required fields."""
        for baseline_file in BASELINES_DIR.glob("*.baseline.json"):
            baseline = load_baseline(baseline_file)

            for i, finding in enumerate(baseline["expected_findings"]):
                assert "rule_id" in finding, (
                    f"{baseline_file.name} finding {i} missing rule_id"
                )
                assert "severity" in finding, (
                    f"{baseline_file.name} finding {i} missing severity"
                )
                assert "category" in finding, (
                    f"{baseline_file.name} finding {i} missing category"
                )


class TestExtractRuleIds:
    """Unit tests for extract_rule_ids() CWE extraction logic."""

    def test_extracts_rule_id(self):
        """Should count tool-specific ruleIds."""
        findings = [{"ruleId": "semgrep.xss.rule"}]
        counts = extract_rule_ids(findings)
        assert counts["semgrep.xss.rule"] == 1

    def test_extracts_cwe_from_risk_field(self):
        """Should extract CWE from risk.cwe (CommonFinding v1.2.0 schema)."""
        findings = [{"ruleId": "semgrep.rule", "risk": {"cwe": ["CWE-79", "CWE-89"]}}]
        counts = extract_rule_ids(findings)
        assert counts["CWE-79"] == 1
        assert counts["CWE-89"] == 1
        assert counts["semgrep.rule"] == 1

    def test_normalizes_cwe_without_prefix(self):
        """Should add CWE- prefix if missing in risk.cwe entries."""
        findings = [{"ruleId": "rule-1", "risk": {"cwe": ["79"]}}]
        counts = extract_rule_ids(findings)
        assert counts["CWE-79"] == 1

    def test_extracts_cwe_from_metadata_fallback(self):
        """Should fall back to metadata.cwe when risk.cwe is absent."""
        findings = [{"ruleId": "some-rule", "metadata": {"cwe": "79"}}]
        counts = extract_rule_ids(findings)
        assert counts["CWE-79"] == 1

    def test_risk_cwe_takes_priority_over_metadata(self):
        """When risk.cwe exists, metadata.cwe should be ignored (no double-counting)."""
        findings = [
            {
                "ruleId": "rule-1",
                "risk": {"cwe": ["CWE-79"]},
                "metadata": {"cwe": "79"},
            }
        ]
        counts = extract_rule_ids(findings)
        assert counts["CWE-79"] == 1

    def test_handles_empty_risk_dict(self):
        """Should handle risk dict with no cwe key gracefully."""
        findings = [{"ruleId": "rule-1", "risk": {"owasp": ["A03:2021"]}}]
        counts = extract_rule_ids(findings)
        assert counts["rule-1"] == 1
        assert "CWE-" not in "".join(counts.keys())

    def test_handles_missing_rule_id(self):
        """Should extract CWE even when ruleId is missing."""
        findings = [{"risk": {"cwe": ["CWE-502"]}}]
        counts = extract_rule_ids(findings)
        assert counts["CWE-502"] == 1

    def test_multiple_findings_aggregate(self):
        """Should correctly aggregate counts across multiple findings."""
        findings = [
            {"ruleId": "rule-a", "risk": {"cwe": ["CWE-79"]}},
            {"ruleId": "rule-b", "risk": {"cwe": ["CWE-79", "CWE-89"]}},
            {"ruleId": "rule-c", "metadata": {"cwe": "79"}},
        ]
        counts = extract_rule_ids(findings)
        assert counts["CWE-79"] == 3  # 2 from risk + 1 from metadata fallback
        assert counts["CWE-89"] == 1

    def test_normalizes_cwe_that_carries_its_title(self):
        """opengrep's bundle spells risk.cwe as "CWE-89: Improper ..."; a baseline
        row says CWE-89, so the title must not be part of the key."""
        title = (
            "CWE-89: Improper Neutralization of Special Elements used in an SQL "
            "Command ('SQL Injection')"
        )
        counts = extract_rule_ids([{"ruleId": "r", "risk": {"cwe": [title]}}])
        assert counts["CWE-89"] == 1
        assert title not in counts

    def test_counts_a_finding_once_per_distinct_cwe(self):
        """Both spellings of one id on a finding are one hit, as the generator counts."""
        findings = [{"risk": {"cwe": ["CWE-89", "CWE-89: Improper Neutralization"]}}]
        assert extract_rule_ids(findings)["CWE-89"] == 1
