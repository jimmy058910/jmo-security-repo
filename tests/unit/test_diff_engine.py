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


# ============================================================================
# Directory Loading Tests (Lines 290-310, 353-374)
# ============================================================================


class TestDirectoryLoading:
    """Test directory findings loading methods."""

    def test_load_directory_findings_plain_list(self, tmp_path):
        """Test loading plain list format (pre-v1.0.0)."""
        results_dir = tmp_path / "results"
        summaries = results_dir / "summaries"
        summaries.mkdir(parents=True)

        findings = [
            {"id": "fp1", "severity": "HIGH"},
            {"id": "fp2", "severity": "MEDIUM"},
        ]

        findings_json = summaries / "findings.json"
        findings_json.write_text(json.dumps(findings))

        engine = DiffEngine()
        loaded = engine._load_directory_findings(results_dir)

        assert len(loaded) == 2
        assert loaded[0]["id"] == "fp1"

    def test_load_directory_findings_dict_format_not_supported(self, tmp_path):
        """Test that dict format (v1.0.0 wrapper) is NOT supported by _load_directory_findings."""
        results_dir = tmp_path / "results"
        summaries = results_dir / "summaries"
        summaries.mkdir(parents=True)

        findings_data = {
            "meta": {
                "jmo_version": "1.0.0",
                "timestamp": "2025-11-05T10:00:00Z",
                "profile": "balanced",
            },
            "findings": [
                {"id": "fp1", "severity": "CRITICAL"},
                {"id": "fp2", "severity": "HIGH"},
            ],
        }

        findings_json = summaries / "findings.json"
        findings_json.write_text(json.dumps(findings_data))

        engine = DiffEngine()

        # _load_directory_findings expects plain list, not dict
        with pytest.raises(ValueError, match="Expected findings.json to contain"):
            engine._load_directory_findings(results_dir)

    def test_load_directory_findings_missing_file(self, tmp_path):
        """Test error when findings.json missing."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        engine = DiffEngine()

        with pytest.raises(FileNotFoundError, match="findings.json not found"):
            engine._load_directory_findings(results_dir)

    def test_load_directory_findings_invalid_json(self, tmp_path):
        """Test error when findings.json contains invalid JSON."""
        results_dir = tmp_path / "results"
        summaries = results_dir / "summaries"
        summaries.mkdir(parents=True)

        findings_json = summaries / "findings.json"
        findings_json.write_text("{invalid json")

        engine = DiffEngine()

        with pytest.raises(ValueError, match="Invalid JSON"):
            engine._load_directory_findings(results_dir)

    def test_load_directory_findings_wrong_type(self, tmp_path):
        """Test error when findings.json is not a list or dict."""
        results_dir = tmp_path / "results"
        summaries = results_dir / "summaries"
        summaries.mkdir(parents=True)

        findings_json = summaries / "findings.json"
        findings_json.write_text(json.dumps("string value"))

        engine = DiffEngine()

        with pytest.raises(ValueError, match="Expected findings.json to contain"):
            engine._load_directory_findings(results_dir)

    def test_extract_source_info_with_metadata(self, tmp_path):
        """Test extracting source info from v1.0.0 metadata."""
        results_dir = tmp_path / "results"
        summaries = results_dir / "summaries"
        summaries.mkdir(parents=True)

        findings_data = {
            "meta": {
                "jmo_version": "1.0.0",
                "timestamp": "2025-11-05T12:34:56Z",
                "profile": "deep",
            },
            "findings": [{"id": "fp1"}],
        }

        findings_json = summaries / "findings.json"
        findings_json.write_text(json.dumps(findings_data))

        engine = DiffEngine()
        source = engine._extract_source_info(results_dir, [{"id": "fp1"}])

        assert source.source_type == "directory"
        assert source.timestamp == "2025-11-05T12:34:56Z"
        assert source.profile == "deep"
        assert source.total_findings == 1

    def test_extract_source_info_fallback(self, tmp_path):
        """Test fallback when no metadata available."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        engine = DiffEngine()
        source = engine._extract_source_info(results_dir, [{"id": "fp1"}])

        assert source.source_type == "directory"
        assert source.timestamp == ""
        assert source.profile == ""
        assert source.total_findings == 1

    def test_extract_source_info_invalid_json(self, tmp_path):
        """Test fallback when findings.json has invalid JSON."""
        results_dir = tmp_path / "results"
        summaries = results_dir / "summaries"
        summaries.mkdir(parents=True)

        findings_json = summaries / "findings.json"
        findings_json.write_text("{invalid")

        engine = DiffEngine()
        source = engine._extract_source_info(results_dir, [{"id": "fp1"}])

        # Should fall back to minimal metadata
        assert source.timestamp == ""
        assert source.profile == ""


# ============================================================================
# SQLite Loading Tests (Lines 322-344, 248-274)
# ============================================================================


class TestSQLiteLoading:
    """Test SQLite findings loading methods."""

    def test_load_sqlite_findings_basic(self, tmp_path):
        """Test loading findings from SQLite database."""
        db_path = tmp_path / "history.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access

        # Create schema
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
                scan_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                severity TEXT,
                tool TEXT,
                rule_id TEXT,
                path TEXT,
                start_line INTEGER,
                message TEXT,
                raw_finding TEXT,
                PRIMARY KEY (scan_id, fingerprint)
            )
            """
        )

        # Insert test data
        conn.execute(
            """
            INSERT INTO scans VALUES
            ('scan1', '2025-11-05T10:00:00Z', 'balanced', 2)
            """
        )
        conn.execute(
            """
            INSERT INTO findings VALUES
            ('scan1', 'fp1', 'HIGH', 'semgrep', 'G101', 'src/auth.py', 42,
             'Hardcoded secret', '{"cvss": {"baseScore": 7.5}}')
            """
        )
        conn.execute(
            """
            INSERT INTO findings VALUES
            ('scan1', 'fp2', 'MEDIUM', 'trivy', 'CVE-2024-1234', 'package.json', 0,
             'Vulnerable dependency', '{}')
            """
        )
        conn.commit()

        engine = DiffEngine()
        findings = engine._load_sqlite_findings(conn, "scan1")

        assert len(findings) == 2

        # Find fp1 finding (order not guaranteed)
        fp1 = next((f for f in findings if f["id"] == "fp1"), None)
        assert fp1 is not None
        assert fp1["severity"] == "HIGH"
        assert fp1["tool"]["name"] == "semgrep"
        assert fp1["location"]["path"] == "src/auth.py"
        assert fp1["cvss"]["baseScore"] == 7.5

        conn.close()

    def test_load_sqlite_findings_invalid_json(self, tmp_path):
        """Test handling of invalid JSON in raw_finding."""
        db_path = tmp_path / "history.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access

        # Create schema
        conn.execute(
            """
            CREATE TABLE findings (
                scan_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                severity TEXT,
                tool TEXT,
                rule_id TEXT,
                path TEXT,
                start_line INTEGER,
                message TEXT,
                raw_finding TEXT,
                PRIMARY KEY (scan_id, fingerprint)
            )
            """
        )

        # Insert with invalid JSON
        conn.execute(
            """
            INSERT INTO findings VALUES
            ('scan1', 'fp1', 'HIGH', 'semgrep', 'G101', 'src/auth.py', 42,
             'Secret', '{invalid json}')
            """
        )
        conn.commit()

        engine = DiffEngine()
        findings = engine._load_sqlite_findings(conn, "scan1")

        # Should still load with basic fields
        assert len(findings) == 1
        assert findings[0]["id"] == "fp1"
        # raw_finding parsing failed, so only basic fields present

        conn.close()

    def test_compare_scans_success(self, tmp_path):
        """Test compare_scans() method with SQLite database."""
        db_path = tmp_path / "history.db"
        conn = sqlite3.connect(db_path)

        # Create schema
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
                scan_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                severity TEXT,
                tool TEXT,
                rule_id TEXT,
                path TEXT,
                start_line INTEGER,
                message TEXT,
                raw_finding TEXT,
                PRIMARY KEY (scan_id, fingerprint)
            )
            """
        )

        # Insert baseline scan
        conn.execute(
            """
            INSERT INTO scans VALUES
            ('baseline', '2025-11-01T10:00:00Z', 'balanced', 2)
            """
        )
        conn.execute(
            """
            INSERT INTO findings VALUES
            ('baseline', 'fp1', 'HIGH', 'semgrep', 'G101', 'src/auth.py', 42,
             'Hardcoded secret', '{}')
            """
        )
        conn.execute(
            """
            INSERT INTO findings VALUES
            ('baseline', 'fp2', 'MEDIUM', 'trivy', 'CVE-2024-1234', 'package.json', 0,
             'Vulnerable dependency', '{}')
            """
        )

        # Insert current scan
        conn.execute(
            """
            INSERT INTO scans VALUES
            ('current', '2025-11-05T10:00:00Z', 'balanced', 2)
            """
        )
        conn.execute(
            """
            INSERT INTO findings VALUES
            ('current', 'fp2', 'MEDIUM', 'trivy', 'CVE-2024-1234', 'package.json', 0,
             'Vulnerable dependency', '{}')
            """
        )
        conn.execute(
            """
            INSERT INTO findings VALUES
            ('current', 'fp3', 'CRITICAL', 'semgrep', 'CWE-79', 'src/web.py', 89,
             'XSS vulnerability', '{}')
            """
        )
        conn.commit()
        conn.close()

        engine = DiffEngine()
        diff = engine.compare_scans("baseline", "current", db_path=db_path)

        # Verify diff results
        assert len(diff.new) == 1  # fp3 is new
        assert len(diff.resolved) == 1  # fp1 is resolved
        assert len(diff.unchanged) == 1  # fp2 unchanged

        assert diff.new[0]["id"] == "fp3"
        assert diff.resolved[0]["id"] == "fp1"

        # Verify source metadata
        assert diff.baseline_source.source_type == "sqlite"
        assert diff.baseline_source.path == "baseline"
        assert diff.baseline_source.profile == "balanced"

        assert diff.current_source.source_type == "sqlite"
        assert diff.current_source.path == "current"

    def test_compare_scans_missing_current(self, tmp_path):
        """Test compare_scans() with missing current scan."""
        db_path = tmp_path / "history.db"
        conn = sqlite3.connect(db_path)

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
                scan_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                severity TEXT,
                tool TEXT,
                rule_id TEXT,
                path TEXT,
                start_line INTEGER,
                message TEXT,
                raw_finding TEXT,
                PRIMARY KEY (scan_id, fingerprint)
            )
            """
        )

        # Insert only baseline scan
        conn.execute(
            """
            INSERT INTO scans VALUES
            ('baseline', '2025-11-01T10:00:00Z', 'balanced', 0)
            """
        )
        conn.commit()
        conn.close()

        engine = DiffEngine()

        with pytest.raises(ValueError, match="Current scan not found"):
            engine.compare_scans("baseline", "missing", db_path=db_path)


# ============================================================================
# Edge Case Tests (Phase 1.1 Expansion)
# ============================================================================


class TestDiffEngineEdgeCases:
    """Additional edge case tests for comprehensive Phase 1.1 coverage."""

    def test_diff_with_empty_baseline_specific(self):
        """Test diff when baseline has zero findings (all new)."""
        engine = DiffEngine()

        baseline = []

        current = [
            {
                "id": f"fp{i}",
                "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"][i % 5],
                "ruleId": "TEST-001",
                "tool": {"name": "test"},
                "location": {"path": f"file_{i}.py", "startLine": 1},
                "message": "Test finding",
            }
            for i in range(100)
        ]

        source = DiffSource("directory", "/test", "", "", 0)
        current_source = DiffSource("directory", "/test", "", "", 100)

        diff = engine._compare_findings(baseline, current, source, current_source)

        # All findings should be new
        assert len(diff.new) == 100
        assert len(diff.resolved) == 0
        assert len(diff.unchanged) == 0
        assert len(diff.modified) == 0
        assert diff.statistics["net_change"] == 100
        assert diff.statistics["trend"] == "worsening"

    def test_diff_with_empty_current_specific(self):
        """Test diff when current has zero findings (all fixed)."""
        engine = DiffEngine()

        baseline = [
            {
                "id": f"fp{i}",
                "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"][i % 5],
                "ruleId": "TEST-001",
                "tool": {"name": "test"},
                "location": {"path": f"file_{i}.py", "startLine": 1},
                "message": "Test finding",
            }
            for i in range(100)
        ]

        current = []

        source = DiffSource("directory", "/test", "", "", 100)
        current_source = DiffSource("directory", "/test", "", "", 0)

        diff = engine._compare_findings(baseline, current, source, current_source)

        # All findings should be resolved
        assert len(diff.new) == 0
        assert len(diff.resolved) == 100
        assert len(diff.unchanged) == 0
        assert len(diff.modified) == 0
        assert diff.statistics["net_change"] == -100
        assert diff.statistics["trend"] == "improving"

    def test_diff_with_severity_changes_comprehensive(self):
        """Test diff with comprehensive severity changes across all levels."""
        engine = DiffEngine(detect_modifications=True)

        # Test all severity upgrade/downgrade combinations
        baseline = [
            {
                "id": "fp1",
                "severity": "INFO",
                "ruleId": "TEST-001",
                "tool": {"name": "test"},
                "location": {"path": "file.py", "startLine": 1},
                "message": "Finding 1",
            },
            {
                "id": "fp2",
                "severity": "LOW",
                "ruleId": "TEST-002",
                "tool": {"name": "test"},
                "location": {"path": "file.py", "startLine": 2},
                "message": "Finding 2",
            },
            {
                "id": "fp3",
                "severity": "MEDIUM",
                "ruleId": "TEST-003",
                "tool": {"name": "test"},
                "location": {"path": "file.py", "startLine": 3},
                "message": "Finding 3",
            },
            {
                "id": "fp4",
                "severity": "HIGH",
                "ruleId": "TEST-004",
                "tool": {"name": "test"},
                "location": {"path": "file.py", "startLine": 4},
                "message": "Finding 4",
            },
        ]

        current = [
            {
                "id": "fp1",
                "severity": "CRITICAL",  # Upgraded from INFO
                "ruleId": "TEST-001",
                "tool": {"name": "test"},
                "location": {"path": "file.py", "startLine": 1},
                "message": "Finding 1",
            },
            {
                "id": "fp2",
                "severity": "HIGH",  # Upgraded from LOW
                "ruleId": "TEST-002",
                "tool": {"name": "test"},
                "location": {"path": "file.py", "startLine": 2},
                "message": "Finding 2",
            },
            {
                "id": "fp3",
                "severity": "LOW",  # Downgraded from MEDIUM
                "ruleId": "TEST-003",
                "tool": {"name": "test"},
                "location": {"path": "file.py", "startLine": 3},
                "message": "Finding 3",
            },
            {
                "id": "fp4",
                "severity": "INFO",  # Downgraded from HIGH
                "ruleId": "TEST-004",
                "tool": {"name": "test"},
                "location": {"path": "file.py", "startLine": 4},
                "message": "Finding 4",
            },
        ]

        source = DiffSource("directory", "/test", "", "", 4)

        diff = engine._compare_findings(baseline, current, source, source)

        # All findings should be classified as modified
        assert len(diff.modified) == 4
        assert len(diff.new) == 0
        assert len(diff.resolved) == 0
        assert len(diff.unchanged) == 0

        # Check specific severity changes
        fp1_mod = next(m for m in diff.modified if m.fingerprint == "fp1")
        assert fp1_mod.changes["severity"] == ["INFO", "CRITICAL"]
        assert fp1_mod.risk_delta == "worsened"

        fp3_mod = next(m for m in diff.modified if m.fingerprint == "fp3")
        assert fp3_mod.changes["severity"] == ["MEDIUM", "LOW"]
        assert fp3_mod.risk_delta == "improved"

    def test_diff_with_very_large_datasets(self):
        """Test diff performance with 10,000 findings per scan (target: <2s)."""
        engine = DiffEngine(detect_modifications=False)

        # Generate 10,000 baseline findings (5,000 unique)
        baseline = [
            {
                "id": f"fp_{i}",
                "severity": "MEDIUM",
                "ruleId": "TEST-001",
                "tool": {"name": "test"},
                "location": {"path": f"file_{i}.py", "startLine": 1},
                "message": "Test finding",
            }
            for i in range(5000, 10000)
        ]

        # Generate 10,000 current findings (5,000 from baseline + 5,000 new)
        current = [
            {
                "id": f"fp_{i}",
                "severity": "MEDIUM",
                "ruleId": "TEST-001",
                "tool": {"name": "test"},
                "location": {"path": f"file_{i}.py", "startLine": 1},
                "message": "Test finding",
            }
            for i in range(5000)
        ]

        source = DiffSource("directory", "/test", "", "", 5000)

        import time

        start = time.time()
        diff = engine._compare_findings(baseline, current, source, source)
        elapsed = time.time() - start

        # Assertions
        assert len(diff.new) == 5000
        assert len(diff.resolved) == 5000
        assert len(diff.unchanged) == 0
        assert elapsed < 2.0  # <2s target for 10K findings

    def test_diff_fingerprint_stability_across_runs(self):
        """Test fingerprint IDs are deterministic across multiple runs."""
        engine = DiffEngine()

        # Create same finding in two separate runs
        finding_run1 = {
            "id": "fp_stable",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret detected",
        }

        finding_run2 = {
            "id": "fp_stable",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret detected",
        }

        source = DiffSource("directory", "/test", "", "", 1)

        # Run diff twice with identical data
        diff1 = engine._compare_findings([finding_run1], [finding_run2], source, source)
        diff2 = engine._compare_findings([finding_run1], [finding_run2], source, source)

        # Fingerprints should be identical across runs
        assert len(diff1.unchanged) == 1
        assert len(diff2.unchanged) == 1
        assert diff1.unchanged[0]["id"] == diff2.unchanged[0]["id"]
        assert diff1.unchanged[0]["id"] == "fp_stable"

    def test_diff_with_compliance_framework_additions(self):
        """Test diff when compliance frameworks are added to existing findings."""
        engine = DiffEngine(detect_modifications=True)

        baseline = [
            {
                "id": "fp1",
                "severity": "HIGH",
                "ruleId": "CWE-79",
                "tool": {"name": "semgrep"},
                "location": {"path": "src/web.py", "startLine": 89},
                "message": "XSS vulnerability",
                "compliance": {"owaspTop10_2021": ["A03:2021"]},
            }
        ]

        current = [
            {
                "id": "fp1",
                "severity": "HIGH",
                "ruleId": "CWE-79",
                "tool": {"name": "semgrep"},
                "location": {"path": "src/web.py", "startLine": 89},
                "message": "XSS vulnerability",
                "compliance": {
                    "owaspTop10_2021": ["A03:2021"],
                    "cweTop25_2024": [{"id": "CWE-79", "rank": 1}],
                    "nistCsf2_0": [
                        {
                            "function": "Protect",
                            "category": "PR.DS",
                            "subcategory": "PR.DS-5",
                        }
                    ],
                },
            }
        ]

        source = DiffSource("directory", "/test", "", "", 1)

        diff = engine._compare_findings(baseline, current, source, source)

        # Should be classified as modified due to compliance additions
        assert len(diff.modified) == 1
        assert "compliance_added" in diff.modified[0].changes

        added = diff.modified[0].changes["compliance_added"]
        assert "cweTop25_2024:CWE-79" in added
        # NIST CSF format is "nistCsf2_0:PR.DS" (category level, not subcategory)
        assert "nistCsf2_0:PR.DS" in added


# ============================================================================
# Full Directory Comparison Tests (Lines 174-193)
# ============================================================================


class TestCompareDirectories:
    """Test compare_directories() method with real directory structures."""

    def test_compare_directories_success(self, tmp_path):
        """Test compare_directories() with real directory structure."""
        # Create baseline directory
        baseline_dir = tmp_path / "baseline"
        baseline_summaries = baseline_dir / "summaries"
        baseline_summaries.mkdir(parents=True)

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

        baseline_json = baseline_summaries / "findings.json"
        baseline_json.write_text(json.dumps(baseline_findings))

        # Create current directory
        current_dir = tmp_path / "current"
        current_summaries = current_dir / "summaries"
        current_summaries.mkdir(parents=True)

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

        current_json = current_summaries / "findings.json"
        current_json.write_text(json.dumps(current_findings))

        # Run comparison
        engine = DiffEngine()
        diff = engine.compare_directories(baseline_dir, current_dir)

        # Verify results
        assert len(diff.new) == 1
        assert len(diff.resolved) == 1
        assert len(diff.unchanged) == 1

        assert diff.new[0]["id"] == "fp3"
        assert diff.resolved[0]["id"] == "fp1"
        assert diff.unchanged[0]["id"] == "fp2"

        # Verify source metadata extracted (minimal since no meta wrapper)
        assert diff.baseline_source.source_type == "directory"
        assert diff.current_source.source_type == "directory"

    def test_compare_directories_current_not_found(self, tmp_path):
        """Test compare_directories() when current directory missing."""
        baseline_dir = tmp_path / "baseline"
        baseline_dir.mkdir()

        current_dir = tmp_path / "nonexistent"

        engine = DiffEngine()

        with pytest.raises(FileNotFoundError, match="Current directory not found"):
            engine.compare_directories(baseline_dir, current_dir)


# ============================================================================
# Trend Integration Tests (Lines 753-790)
# ============================================================================


class TestTrendIntegration:
    """Test compare_with_trends() method."""

    def test_compare_with_trends_failure_graceful_degradation(
        self, tmp_path, monkeypatch
    ):
        """Test that trend analysis failure doesn't crash diff."""
        db_path = tmp_path / "history.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        # Create schema
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
                scan_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                severity TEXT,
                tool TEXT,
                rule_id TEXT,
                path TEXT,
                start_line INTEGER,
                message TEXT,
                raw_finding TEXT,
                PRIMARY KEY (scan_id, fingerprint)
            )
            """
        )

        # Insert baseline and current scans
        conn.execute(
            """
            INSERT INTO scans VALUES
            ('baseline', '2025-11-01T10:00:00Z', 'balanced', 1)
            """
        )
        conn.execute(
            """
            INSERT INTO findings VALUES
            ('baseline', 'fp1', 'HIGH', 'semgrep', 'G101', 'src/auth.py', 42,
             'Hardcoded secret', '{}')
            """
        )
        conn.execute(
            """
            INSERT INTO scans VALUES
            ('current', '2025-11-05T10:00:00Z', 'balanced', 1)
            """
        )
        conn.execute(
            """
            INSERT INTO findings VALUES
            ('current', 'fp1', 'HIGH', 'semgrep', 'G101', 'src/auth.py', 42,
             'Hardcoded secret', '{}')
            """
        )
        conn.commit()
        conn.close()

        # Mock TrendAnalyzer to raise an exception
        def mock_trend_analyzer_init(*args, **kwargs):
            raise RuntimeError("Trend analysis failed")

        import scripts.core.trend_analyzer

        # Mock the TrendAnalyzer import
        _original_trend_analyzer = getattr(
            scripts.core.trend_analyzer, "TrendAnalyzer", None
        )
        monkeypatch.setattr(
            scripts.core.trend_analyzer, "TrendAnalyzer", mock_trend_analyzer_init
        )

        engine = DiffEngine()

        # Should not crash, trend_context should be None
        diff = engine.diff_with_context("baseline", "current", db_path=db_path)

        # Verify diff still works
        assert len(diff.new) == 0
        assert len(diff.resolved) == 0
        assert len(diff.unchanged) == 1

        # Trend context should be None due to failure
        assert hasattr(diff, "trend_context")
        assert diff.trend_context is None
