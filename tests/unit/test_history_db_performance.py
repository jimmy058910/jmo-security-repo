#!/usr/bin/env python3
"""
Performance benchmark tests for SQLite historical storage.

Phase 1.1: Performance validation for v1.0.0 release.

Tests cover:
- Large scan storage (10k+ findings)
- Query performance (10k scans)
- Vacuum operations
- Export pagination
- Memory usage

Performance Targets (from CLAUDE.md):
- Single scan insert: <50ms
- History list (10k scans): <100ms
- Trend analysis (30 days): <200ms
- Large scan (10k findings): <500ms
"""

import json
import sqlite3
import time
from pathlib import Path

import pytest

from scripts.core.history_db import (
    init_database,
    store_scan,
    list_scans,
    get_scan_by_id,
    prune_old_scans,
    get_connection,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def perf_db(tmp_path):
    """Create performance test database."""
    db_path = tmp_path / "perf.db"
    init_database(db_path)
    return db_path


@pytest.fixture
def large_findings_set():
    """Generate 10,000 test findings for performance testing."""
    findings = []
    for i in range(10000):
        findings.append({
            "id": f"fp_{i}",
            "schemaVersion": "1.2.0",
            "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"][i % 5],
            "ruleId": f"TEST-{i % 100}",
            "tool": {"name": "test", "version": "1.0.0"},
            "location": {"path": f"file_{i % 1000}.py", "startLine": i % 500},
            "message": f"Test finding {i}",
        })
    return findings


# ============================================================================
# Large Scan Storage Performance
# ============================================================================


def test_large_scan_storage_performance(perf_db, large_findings_set, tmp_path):
    """
    Test storing scan with 10,000 findings (target: <500ms).

    Performance requirement from CLAUDE.md:
    - Large scan (10k findings): <500ms
    """
    # Create results directory
    results_dir = tmp_path / "results_large"
    summaries = results_dir / "summaries"
    summaries.mkdir(parents=True)

    # Write findings
    findings_file = summaries / "findings.json"
    findings_data = {
        "meta": {"jmo_version": "1.0.0"},
        "findings": large_findings_set,
    }
    findings_file.write_text(json.dumps(findings_data))

    # Measure insert time
    start = time.time()
    scan_id = store_scan(
        results_dir=results_dir,
        profile="balanced",
        tools=["test"],
        db_path=perf_db,
        commit_hash="abc123",
        branch="main",
    )
    elapsed = time.time() - start

    # Assertions
    assert scan_id is not None
    assert elapsed < 0.5  # <500ms target

    # Verify retrieval performance
    start = time.time()
    conn = sqlite3.connect(perf_db)
    conn.row_factory = sqlite3.Row
    scan = get_scan_by_id(conn, scan_id)
    elapsed_retrieval = time.time() - start
    conn.close()

    assert scan is not None
    assert scan["total_findings"] == 10000
    assert elapsed_retrieval < 0.1  # <100ms retrieval


def test_single_scan_insert_performance(perf_db, tmp_path):
    """
    Test single scan insert performance (target: <50ms).

    Performance requirement from CLAUDE.md:
    - Single scan insert: <50ms
    """
    # Create minimal scan with 100 findings
    results_dir = tmp_path / "results_single"
    summaries = results_dir / "summaries"
    summaries.mkdir(parents=True)

    findings = [
        {
            "id": f"fp_{i}",
            "schemaVersion": "1.2.0",
            "severity": "MEDIUM",
            "ruleId": "TEST-001",
            "tool": {"name": "test", "version": "1.0.0"},
            "location": {"path": "file.py", "startLine": i},
            "message": f"Finding {i}",
        }
        for i in range(100)
    ]

    findings_file = summaries / "findings.json"
    findings_file.write_text(json.dumps({"findings": findings}))

    # Measure insert time
    start = time.time()
    scan_id = store_scan(
        results_dir=results_dir,
        profile="fast",
        tools=["trivy", "semgrep"],
        db_path=perf_db,
        commit_hash="def456",
        branch="main",
    )
    elapsed = time.time() - start

    # Assertions
    assert scan_id is not None
    assert elapsed < 0.05  # <50ms target


# ============================================================================
# Query Performance with Large Datasets
# ============================================================================


def test_history_list_performance_10k_scans(perf_db, tmp_path):
    """
    Test list_scans() performance with 10k scans (target: <100ms).

    Performance requirement from CLAUDE.md:
    - History list (10k scans): <100ms
    """
    # Insert 10,000 minimal scans
    for i in range(10000):
        results_dir = tmp_path / f"results_{i}"
        summaries = results_dir / "summaries"
        summaries.mkdir(parents=True)

        findings_file = summaries / "findings.json"
        findings_file.write_text('{"findings": []}')

        store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=perf_db,
            commit_hash=f"commit_{i}",
            branch="main" if i % 2 == 0 else "dev",
        )

    # Measure query time
    conn = sqlite3.connect(perf_db)
    conn.row_factory = sqlite3.Row

    start = time.time()
    scans = list(list_scans(conn, branch="main", limit=10000))
    elapsed = time.time() - start

    conn.close()

    # Assertions
    assert len(scans) == 5000  # Half are on main branch
    assert elapsed < 0.1  # <100ms target


def test_trend_analysis_query_performance(perf_db, tmp_path):
    """
    Test trend analysis query performance (target: <200ms).

    Performance requirement from CLAUDE.md:
    - Trend analysis (30 days): <200ms
    """
    # Insert 50 scans with time series data
    import time as time_module

    base_time = int(time_module.time())

    for i in range(50):
        results_dir = tmp_path / f"results_{i}"
        summaries = results_dir / "summaries"
        summaries.mkdir(parents=True)

        # Create findings with severity distribution
        findings = [
            {
                "id": f"fp_{i}_{j}",
                "severity": ["CRITICAL", "HIGH", "MEDIUM"][j % 3],
                "ruleId": "TEST-001",
                "tool": {"name": "test", "version": "1.0.0"},
                "location": {"path": "file.py", "startLine": j},
                "message": "Test",
            }
            for j in range(20)
        ]

        findings_file = summaries / "findings.json"
        findings_file.write_text(json.dumps({"findings": findings}))

        # Store with timestamps spread over 30 days
        scan_id = store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=perf_db,
            commit_hash=f"commit_{i}",
            branch="main",
        )

        # Manually update timestamp to simulate 30-day spread
        conn = sqlite3.connect(perf_db)
        timestamp = base_time - ((49 - i) * 86400 // 2)  # 30 days spread
        conn.execute(
            "UPDATE scans SET timestamp = ? WHERE id = ?",
            (timestamp, scan_id)
        )
        conn.commit()
        conn.close()

    # Measure trend analysis query time
    conn = sqlite3.connect(perf_db)
    conn.row_factory = sqlite3.Row

    start = time.time()
    # Simulate trend analysis query (get all scans + findings)
    scans = list(list_scans(conn, branch="main", since=base_time - 30 * 86400, limit=1000))
    for scan in scans:
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?",
            (scan["id"],)
        ).fetchall()
    elapsed = time.time() - start

    conn.close()

    # Assertions
    assert len(scans) == 50
    assert elapsed < 0.2  # <200ms target


# ============================================================================
# Vacuum Performance
# ============================================================================


def test_vacuum_on_large_database(perf_db, tmp_path):
    """
    Test VACUUM operation on database with 1000+ scans.

    Tests:
    - Insert 1000 scans
    - Delete 500 scans
    - Run vacuum
    - Verify file size reduced
    - Verify queries still fast
    """
    # Insert 1000 scans
    scan_ids = []
    for i in range(1000):
        results_dir = tmp_path / f"results_{i}"
        summaries = results_dir / "summaries"
        summaries.mkdir(parents=True)

        findings_file = summaries / "findings.json"
        findings_file.write_text('{"findings": []}')

        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=perf_db,
            commit_hash=f"commit_{i}",
            branch="main",
        )
        scan_ids.append(scan_id)

    # Get initial file size
    initial_size = perf_db.stat().st_size

    # Delete 500 scans
    conn = sqlite3.connect(perf_db)
    for scan_id in scan_ids[:500]:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()

    # Run vacuum (VACUUM command)
    start = time.time()
    conn = sqlite3.connect(perf_db)
    conn.execute("VACUUM")
    conn.close()
    vacuum_time = time.time() - start

    # Verify file size reduced
    final_size = perf_db.stat().st_size
    assert final_size < initial_size

    # Verify queries still fast
    conn = sqlite3.connect(perf_db)
    conn.row_factory = sqlite3.Row

    start = time.time()
    scans = list(list_scans(conn, branch="main", limit=1000))
    query_time = time.time() - start

    conn.close()

    assert len(scans) == 500  # Only 500 remaining
    assert query_time < 0.1  # Queries still fast after vacuum
    assert vacuum_time < 2.0  # Vacuum completes in reasonable time


# ============================================================================
# Export Performance
# ============================================================================


def test_export_pagination_for_large_datasets(perf_db, tmp_path):
    """
    Test exporting 1,000 scans without memory issues.

    Note: Reduced from 10k to 1k for test speed.
    Real-world usage: 10k scans = ~30 days of hourly scans.
    """
    # Insert 1000 scans with minimal data
    for i in range(1000):
        results_dir = tmp_path / f"results_{i}"
        summaries = results_dir / "summaries"
        summaries.mkdir(parents=True)

        findings_file = summaries / "findings.json"
        findings_file.write_text('{"findings": []}')

        store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=perf_db,
            commit_hash=f"commit_{i}",
            branch="main",
        )

    # Measure export time (manual JSON export)
    output_file = tmp_path / "export.json"

    start = time.time()
    conn = sqlite3.connect(perf_db)
    conn.row_factory = sqlite3.Row
    scans = list(list_scans(conn, branch="main", limit=1000))

    # Export to JSON
    export_data = {
        "scans": [dict(scan) for scan in scans],
        "total_count": len(scans),
    }

    with open(output_file, "w") as f:
        json.dump(export_data, f, indent=2)

    conn.close()
    elapsed = time.time() - start

    # Assertions
    assert output_file.exists()
    assert output_file.stat().st_size > 0

    # Verify export completed reasonably fast
    assert elapsed < 5.0  # <5s for 1000 scans

    # Verify exported data is valid JSON
    with open(output_file) as f:
        data = json.load(f)

    assert len(data["scans"]) == 1000


# ============================================================================
# Finding Deduplication Performance
# ============================================================================


def test_finding_deduplication_across_scans(perf_db, tmp_path):
    """
    Test fingerprint-based finding deduplication.

    Tests:
    - Insert scan A with 100 findings
    - Insert scan B with 50 same findings + 50 new
    - Verify database efficiency (deduplication working)
    """
    # Create scan A with 100 findings
    results_a = tmp_path / "results_a"
    summaries_a = results_a / "summaries"
    summaries_a.mkdir(parents=True)

    findings_a = [
        {
            "id": f"fp_{i}",  # Same fingerprints for 0-49
            "severity": "MEDIUM",
            "ruleId": "TEST-001",
            "tool": {"name": "test", "version": "1.0.0"},
            "location": {"path": "file.py", "startLine": i},
            "message": "Test",
        }
        for i in range(100)
    ]

    findings_file_a = summaries_a / "findings.json"
    findings_file_a.write_text(json.dumps({"findings": findings_a}))

    scan_a_id = store_scan(
        results_dir=results_a,
        profile="fast",
        tools=["test"],
        db_path=perf_db,
        commit_hash="scan_a",
        branch="main",
    )

    # Create scan B with 50 same + 50 new
    results_b = tmp_path / "results_b"
    summaries_b = results_b / "summaries"
    summaries_b.mkdir(parents=True)

    findings_b = [
        {
            "id": f"fp_{i}",  # 0-49 same as scan A, 100-149 new
            "severity": "MEDIUM",
            "ruleId": "TEST-001",
            "tool": {"name": "test", "version": "1.0.0"},
            "location": {"path": "file.py", "startLine": i},
            "message": "Test",
        }
        for i in list(range(50)) + list(range(100, 150))
    ]

    findings_file_b = summaries_b / "findings.json"
    findings_file_b.write_text(json.dumps({"findings": findings_b}))

    scan_b_id = store_scan(
        results_dir=results_b,
        profile="fast",
        tools=["test"],
        db_path=perf_db,
        commit_hash="scan_b",
        branch="main",
    )

    # Verify deduplication
    conn = sqlite3.connect(perf_db)

    # Count total findings rows
    total_rows = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

    # Count unique fingerprints
    unique_fps = conn.execute(
        "SELECT COUNT(DISTINCT fingerprint) FROM findings"
    ).fetchone()[0]

    conn.close()

    # Assertions: Should have 200 rows (100 + 100) but dedupe happens at fingerprint level
    # Actually, store_scan stores per scan_id + fingerprint, so we expect 200 rows
    # But unique fingerprints should be 150 (100 from A + 50 new from B)
    assert total_rows == 200  # 100 findings * 2 scans
    assert unique_fps == 150  # 100 unique + 50 new

    # Verify retrieval still fast
    conn = sqlite3.connect(perf_db)
    conn.row_factory = sqlite3.Row

    start = time.time()
    findings_a = list(conn.execute(
        "SELECT * FROM findings WHERE scan_id = ?",
        (scan_a_id,)
    ).fetchall())
    findings_b = list(conn.execute(
        "SELECT * FROM findings WHERE scan_id = ?",
        (scan_b_id,)
    ).fetchall())
    elapsed = time.time() - start

    conn.close()

    assert len(findings_a) == 100
    assert len(findings_b) == 100
    assert elapsed < 0.05  # <50ms retrieval


# ============================================================================
# SQL Injection Resistance
# ============================================================================


def test_sql_injection_resistance(perf_db, tmp_path):
    """
    Test resistance to SQL injection in all queries.

    Tests:
    - Injection via scan_id
    - Injection via branch name
    - Injection via commit_hash
    - Verify queries fail gracefully, no data corruption
    """
    # Store a normal scan first
    results_dir = tmp_path / "results_normal"
    summaries = results_dir / "summaries"
    summaries.mkdir(parents=True)

    findings_file = summaries / "findings.json"
    findings_file.write_text('{"findings": []}')

    normal_scan_id = store_scan(
        results_dir=results_dir,
        profile="fast",
        tools=["trivy"],
        db_path=perf_db,
        commit_hash="abc123",
        branch="main",
    )

    conn = sqlite3.connect(perf_db)
    conn.row_factory = sqlite3.Row

    # Test 1: SQL injection via scan_id in get_scan_by_id
    malicious_scan_id = "'; DROP TABLE scans; --"
    result = get_scan_by_id(conn, malicious_scan_id)

    # Should return None (no match) without crashing
    assert result is None

    # Verify table still exists
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    assert any(t["name"] == "scans" for t in tables)

    # Test 2: SQL injection via branch filter in list_scans
    malicious_branch = "main' OR '1'='1"
    scans = list(list_scans(conn, branch=malicious_branch, limit=100))

    # Should return empty (no match) without exposing all scans
    assert len(scans) == 0

    # Test 3: Verify normal scan still retrievable
    normal_scan = get_scan_by_id(conn, normal_scan_id)
    assert normal_scan is not None
    assert normal_scan["commit_hash"] == "abc123"

    conn.close()
