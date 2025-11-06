"""
Unit tests for diff_engine module.

Tests cover:
- Directory comparison (happy path, edge cases)
- SQLite comparison
- Modification detection (5 change types)
- Risk delta calculation
- Statistics generation
- Performance benchmarks

Target coverage: ≥95%
"""

import json
import sqlite3
from pathlib import Path

import pytest

from scripts.core.diff_engine import DiffEngine, DiffSource


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_findings_baseline():
    """Sample baseline findings for testing."""
    return [
        {
            "id": "fp1_baseline",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret detected",
            "compliance": {"owaspTop10_2021": ["A02:2021"]},
            "risk": {"cwe": "CWE-798"},
        },
        {
            "id": "fp2_baseline",
            "severity": "MEDIUM",
            "ruleId": "CWE-89",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/db.py", "startLine": 127},
            "message": "SQL injection possible",
            "compliance": {"owaspTop10_2021": ["A03:2021"]},
            "risk": {"cwe": "CWE-89"},
        },
    ]


@pytest.fixture
def sample_findings_current():
    """Sample current findings for testing."""
    return [
        {
            "id": "fp2_current",
            "severity": "MEDIUM",
            "ruleId": "CWE-89",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/db.py", "startLine": 127},
            "message": "SQL injection possible",
            "compliance": {"owaspTop10_2021": ["A03:2021"]},
            "risk": {"cwe": "CWE-89"},
        },
        {
            "id": "fp3_current",
            "severity": "CRITICAL",
            "ruleId": "CWE-79",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/web.py", "startLine": 89},
            "message": "XSS vulnerability detected",
            "compliance": {"owaspTop10_2021": ["A03:2021"]},
            "risk": {"cwe": "CWE-79"},
        },
    ]


@pytest.fixture
def temp_baseline_dir(tmp_path, sample_findings_baseline):
    """Create temporary baseline results directory."""
    baseline_dir = tmp_path / "baseline-results"
    summaries_dir = baseline_dir / "summaries"
    summaries_dir.mkdir(parents=True)

    findings_json = {
        "meta": {
            "jmo_version": "1.0.0",
            "timestamp": "2025-11-04T10:00:00Z",
            "profile": "balanced",
        },
        "findings": sample_findings_baseline,
    }

    findings_path = summaries_dir / "findings.json"
    findings_path.write_text(json.dumps(findings_json, indent=2))

    return baseline_dir


@pytest.fixture
def temp_current_dir(tmp_path, sample_findings_current):
    """Create temporary current results directory."""
    current_dir = tmp_path / "current-results"
    summaries_dir = current_dir / "summaries"
    summaries_dir.mkdir(parents=True)

    findings_json = {
        "meta": {
            "jmo_version": "1.0.0",
            "timestamp": "2025-11-05T10:00:00Z",
            "profile": "balanced",
        },
        "findings": sample_findings_current,
    }

    findings_path = summaries_dir / "findings.json"
    findings_path.write_text(json.dumps(findings_json, indent=2))

    return current_dir


# ============================================================================
# Basic Functionality Tests
# ============================================================================


def test_compare_directories_basic(temp_baseline_dir, temp_current_dir):
    """
    Test basic directory comparison.

    Baseline: fp1, fp2
    Current: fp2, fp3
    Expected: new=[fp3], resolved=[fp1], unchanged=[fp2]
    """
    engine = DiffEngine(detect_modifications=False)

    # Note: We need to mock gather_results since we don't have full directory structure
    # For now, test the algorithm logic directly
    baseline_findings = [
        {
            "id": "fp1",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret",
        },
        {
            "id": "fp2",
            "severity": "MEDIUM",
            "ruleId": "CWE-89",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/db.py", "startLine": 127},
            "message": "SQL injection",
        },
    ]

    current_findings = [
        {
            "id": "fp2",
            "severity": "MEDIUM",
            "ruleId": "CWE-89",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/db.py", "startLine": 127},
            "message": "SQL injection",
        },
        {
            "id": "fp3",
            "severity": "CRITICAL",
            "ruleId": "CWE-79",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/web.py", "startLine": 89},
            "message": "XSS vulnerability",
        },
    ]

    baseline_source = DiffSource(
        source_type="directory",
        path=str(temp_baseline_dir),
        timestamp="2025-11-04T10:00:00Z",
        profile="balanced",
        total_findings=2,
    )

    current_source = DiffSource(
        source_type="directory",
        path=str(temp_current_dir),
        timestamp="2025-11-05T10:00:00Z",
        profile="balanced",
        total_findings=2,
    )

    diff = engine._compare_findings(
        baseline_findings, current_findings, baseline_source, current_source
    )

    # Assertions
    assert len(diff.new) == 1
    assert len(diff.resolved) == 1
    assert len(diff.unchanged) == 1
    assert len(diff.modified) == 0

    assert diff.new[0]["id"] == "fp3"
    assert diff.resolved[0]["id"] == "fp1"
    assert diff.unchanged[0]["id"] == "fp2"


def test_empty_directories():
    """Handle empty scan directories gracefully."""
    engine = DiffEngine()

    empty_source = DiffSource(
        source_type="directory",
        path="/empty",
        timestamp="",
        profile="",
        total_findings=0,
    )

    diff = engine._compare_findings([], [], empty_source, empty_source)

    assert len(diff.new) == 0
    assert len(diff.resolved) == 0
    assert len(diff.unchanged) == 0
    assert len(diff.modified) == 0
    assert diff.statistics["trend"] == "stable"


def test_identical_scans():
    """Handle identical scans (no changes)."""
    engine = DiffEngine()

    findings = [
        {
            "id": "fp1",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret",
        }
    ]

    source = DiffSource(
        source_type="directory",
        path="/test",
        timestamp="",
        profile="",
        total_findings=1,
    )

    diff = engine._compare_findings(findings, findings, source, source)

    assert len(diff.new) == 0
    assert len(diff.resolved) == 0
    assert len(diff.unchanged) == 1
    assert diff.statistics["net_change"] == 0
    assert diff.statistics["trend"] == "stable"


# ============================================================================
# Modification Detection Tests
# ============================================================================


def test_modification_detection_severity():
    """Detect when severity upgrades."""
    engine = DiffEngine(detect_modifications=True)

    baseline = [
        {
            "id": "fp1",
            "severity": "MEDIUM",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret",
        }
    ]

    current = [
        {
            "id": "fp1",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret",
        }
    ]

    source = DiffSource("directory", "/test", "", "", 1)

    diff = engine._compare_findings(baseline, current, source, source)

    assert len(diff.modified) == 1
    assert diff.modified[0].changes["severity"] == ["MEDIUM", "HIGH"]
    assert diff.modified[0].risk_delta == "worsened"


def test_modification_detection_priority():
    """Detect priority score changes >5 points."""
    engine = DiffEngine(detect_modifications=True)

    baseline = [
        {
            "id": "fp1",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Secret",
            "cvss": {"baseScore": 4.5},  # Priority = 45
        }
    ]

    current = [
        {
            "id": "fp1",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Secret",
            "cvss": {"baseScore": 7.9},  # Priority = 79 (delta > 5)
        }
    ]

    source = DiffSource("directory", "/test", "", "", 1)

    diff = engine._compare_findings(baseline, current, source, source)

    assert len(diff.modified) == 1
    assert "priority" in diff.modified[0].changes
    baseline_pri, current_pri = diff.modified[0].changes["priority"]
    assert abs(current_pri - baseline_pri) > 5


def test_modification_detection_compliance():
    """Detect compliance framework additions."""
    engine = DiffEngine(detect_modifications=True)

    baseline = [
        {
            "id": "fp1",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Secret",
            "compliance": {},
        }
    ]

    current = [
        {
            "id": "fp1",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Secret",
            "compliance": {"owaspTop10_2021": ["A02:2021"]},
        }
    ]

    source = DiffSource("directory", "/test", "", "", 1)

    diff = engine._compare_findings(baseline, current, source, source)

    assert len(diff.modified) == 1
    assert "compliance_added" in diff.modified[0].changes
    assert "owaspTop10_2021:A02:2021" in diff.modified[0].changes["compliance_added"]


def test_modification_detection_disabled():
    """When disabled, should not detect modifications."""
    engine = DiffEngine(detect_modifications=False)

    baseline = [
        {
            "id": "fp1",
            "severity": "MEDIUM",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Secret",
        }
    ]

    current = [
        {
            "id": "fp1",
            "severity": "HIGH",  # Changed severity
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Secret",
        }
    ]

    source = DiffSource("directory", "/test", "", "", 1)

    diff = engine._compare_findings(baseline, current, source, source)

    assert len(diff.modified) == 0
    assert len(diff.unchanged) == 1


# ============================================================================
# Statistics Tests
# ============================================================================


def test_statistics_calculation():
    """Test summary statistics calculation."""
    engine = DiffEngine()

    new = [
        {"id": "f1", "severity": "CRITICAL"},
        {"id": "f2", "severity": "HIGH"},
        {"id": "f3", "severity": "MEDIUM"},
    ]

    resolved = [
        {"id": "f4", "severity": "HIGH"},
        {"id": "f5", "severity": "LOW"},
    ]

    unchanged = [
        {"id": "f6", "severity": "INFO"},
    ]

    modified = []

    stats = engine._calculate_statistics(new, resolved, unchanged, modified)

    assert stats["total_new"] == 3
    assert stats["total_resolved"] == 2
    assert stats["total_unchanged"] == 1
    assert stats["total_modified"] == 0
    assert stats["net_change"] == 1  # 3 new - 2 resolved
    assert stats["trend"] == "worsening"

    assert stats["new_by_severity"]["CRITICAL"] == 1
    assert stats["new_by_severity"]["HIGH"] == 1
    assert stats["new_by_severity"]["MEDIUM"] == 1


def test_trend_improving():
    """Test trend calculation when improving."""
    engine = DiffEngine()

    new = [{"id": "f1", "severity": "LOW"}]
    resolved = [
        {"id": "f2", "severity": "CRITICAL"},
        {"id": "f3", "severity": "HIGH"},
        {"id": "f4", "severity": "HIGH"},
    ]

    stats = engine._calculate_statistics(new, resolved, [], [])

    assert stats["net_change"] == -2  # More resolved than new
    assert stats["trend"] == "improving"


# ============================================================================
# Helper Function Tests
# ============================================================================


def test_extract_priority_epss():
    """Test priority extraction with EPSS score."""
    engine = DiffEngine()

    finding = {"risk": {"epss_score": 0.72}}

    priority = engine._extract_priority(finding)
    assert priority == 72.0  # 0.72 * 100


def test_extract_priority_cvss():
    """Test priority extraction with CVSS score."""
    engine = DiffEngine()

    finding = {"cvss": {"baseScore": 7.5}}

    priority = engine._extract_priority(finding)
    assert priority == 75.0  # 7.5 * 10


def test_extract_priority_fallback():
    """Test priority extraction fallback to severity."""
    engine = DiffEngine()

    finding = {"severity": "HIGH"}

    priority = engine._extract_priority(finding)
    assert priority == 70  # HIGH = 70 points


def test_flatten_compliance():
    """Test compliance flattening."""
    engine = DiffEngine()

    compliance = {
        "owaspTop10_2021": ["A02:2021", "A03:2021"],
        "cweTop25_2024": [{"id": "CWE-79", "rank": 1}],
    }

    flat = engine._flatten_compliance(compliance)

    assert "owaspTop10_2021:A02:2021" in flat
    assert "owaspTop10_2021:A03:2021" in flat
    assert "cweTop25_2024:CWE-79" in flat


def test_risk_delta_worsened():
    """Test risk delta calculation when worsened."""
    engine = DiffEngine()

    baseline = {"severity": "MEDIUM"}
    current = {"severity": "CRITICAL"}

    delta = engine._calculate_risk_delta(baseline, current)
    assert delta == "worsened"


def test_risk_delta_improved():
    """Test risk delta calculation when improved."""
    engine = DiffEngine()

    baseline = {"severity": "HIGH"}
    current = {"severity": "LOW"}

    delta = engine._calculate_risk_delta(baseline, current)
    assert delta == "improved"


# ============================================================================
# Error Handling Tests
# ============================================================================


def test_directory_not_found():
    """Test FileNotFoundError when directory doesn't exist."""
    engine = DiffEngine()

    with pytest.raises(FileNotFoundError):
        engine.compare_directories(Path("/nonexistent1"), Path("/nonexistent2"))


def test_invalid_scan_id(tmp_path):
    """Test ValueError when scan ID doesn't exist."""
    # Create empty test database with full schema
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)

    # Create complete schema (matching history_db.py)
    conn.execute(
        """
        CREATE TABLE scans (
            id TEXT PRIMARY KEY,
            timestamp_iso TEXT,
            profile TEXT,
            total_findings INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE findings (
            scan_id TEXT,
            fingerprint TEXT PRIMARY KEY,
            severity TEXT,
            tool TEXT,
            rule_id TEXT,
            path TEXT,
            start_line INTEGER,
            message TEXT,
            raw_finding TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        """
    )
    conn.commit()
    conn.close()

    engine = DiffEngine()

    with pytest.raises(ValueError, match="Baseline scan not found"):
        engine.compare_scans("invalid_id1", "invalid_id2", db_path)


# ============================================================================
# Performance Tests
# ============================================================================


def test_large_diff_performance():
    """Test performance with 1000 findings (target: <500ms)."""
    engine = DiffEngine(detect_modifications=False)

    # Generate 1000 baseline findings (500 unique)
    baseline = [
        {
            "id": f"fp_{i}",
            "severity": "MEDIUM",
            "ruleId": "TEST-001",
            "tool": {"name": "test"},
            "location": {"path": f"file_{i}.py", "startLine": 1},
            "message": "Test finding",
        }
        for i in range(500, 1000)
    ]

    # Generate 1000 current findings (500 unique, 500 new)
    current = [
        {
            "id": f"fp_{i}",
            "severity": "MEDIUM",
            "ruleId": "TEST-001",
            "tool": {"name": "test"},
            "location": {"path": f"file_{i}.py", "startLine": 1},
            "message": "Test finding",
        }
        for i in range(500)
    ]

    source = DiffSource("directory", "/test", "", "", 500)

    import time

    start = time.time()
    diff = engine._compare_findings(baseline, current, source, source)
    elapsed = time.time() - start

    # Assertions
    assert len(diff.new) == 500
    assert len(diff.resolved) == 500
    assert elapsed < 0.5  # <500ms target


# ============================================================================
# Integration-Style Tests
# ============================================================================


def test_complete_workflow():
    """Test complete diff workflow end-to-end."""
    engine = DiffEngine(detect_modifications=True)

    baseline = [
        {
            "id": "fp1",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret detected",
        },
        {
            "id": "fp2",
            "severity": "MEDIUM",
            "ruleId": "CWE-89",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/db.py", "startLine": 127},
            "message": "SQL injection possible",
        },
    ]

    # Current: fp1 resolved, fp2 severity upgraded, fp3 new
    current = [
        {
            "id": "fp2",
            "severity": "HIGH",  # Upgraded from MEDIUM
            "ruleId": "CWE-89",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/db.py", "startLine": 127},
            "message": "SQL injection possible",
        },
        {
            "id": "fp3",
            "severity": "CRITICAL",
            "ruleId": "CWE-79",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/web.py", "startLine": 89},
            "message": "XSS vulnerability detected",
        },
    ]

    source = DiffSource("directory", "/test", "", "", 2)

    diff = engine._compare_findings(baseline, current, source, source)

    # Verify all aspects
    assert len(diff.new) == 1
    assert len(diff.resolved) == 1
    assert len(diff.unchanged) == 0  # fp2 is modified, not unchanged
    assert len(diff.modified) == 1

    # Verify statistics
    assert diff.statistics["total_new"] == 1
    assert diff.statistics["total_resolved"] == 1
    assert diff.statistics["total_modified"] == 1
    assert diff.statistics["net_change"] == 0

    # Verify modification
    assert diff.modified[0].fingerprint == "fp2"
    assert diff.modified[0].changes["severity"] == ["MEDIUM", "HIGH"]
    assert diff.modified[0].risk_delta == "worsened"
