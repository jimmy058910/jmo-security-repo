#!/usr/bin/env python3
"""
Performance tests for JMo Security history database.

Tests verify:
1. Store 1,000 findings in <2 seconds
2. Query 10,000 scans in <500ms
3. Batch insert 10,000 findings in <5 seconds
4. All queries use indices (EXPLAIN QUERY PLAN)

Run with: pytest tests/performance/test_history_db_perf.py -v
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from scripts.core.history_db import (
    get_connection,
    get_scan_by_id,
    init_database,
    list_scans,
    store_scan,
)

# Import fixtures from conftest
from tests.performance.conftest import create_test_finding


def test_store_scan_1000_findings_fast(
    tmp_path: Path, benchmark_findings: List[Dict[str, Any]]
):
    """
    Performance Test 1: Store 1000 findings in <2 seconds.

    Target: <2 seconds for 1000 findings
    Strategy: Use batch_insert_findings() instead of individual inserts
    """
    # Setup: Create database and results directory
    db_path = tmp_path / "perf_test.db"
    init_database(db_path)

    results_dir = tmp_path / "results"
    summaries_dir = results_dir / "summaries"
    summaries_dir.mkdir(parents=True)

    # Write findings to JSON (simulate scan output)
    # Format: {"findings": [...], "metadata": {...}}
    findings_file = summaries_dir / "findings.json"
    with open(findings_file, "w") as f:
        json.dump(
            {
                "findings": benchmark_findings,
                "metadata": {
                    "scan_time": "2024-01-01T00:00:00Z",
                    "total_findings": len(benchmark_findings),
                },
            },
            f,
        )

    # Start timing
    start = time.time()

    # Create a new scan without findings first
    scan_id = "perf-test-scan-1000"
    timestamp_now = int(time.time())
    conn = get_connection(db_path)
    conn.execute(
        """
        INSERT INTO scans (
            id, timestamp, timestamp_iso, profile, tools, targets, target_type,
            total_findings, critical_count, high_count, medium_count, low_count, info_count,
            jmo_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            timestamp_now,
            "2024-01-01T00:00:00Z",
            "balanced",
            '["trivy", "semgrep"]',
            '["/test"]',
            "repo",
            1000,
            100,
            200,
            300,
            200,
            200,  # severity counts
            "1.0.0",
        ),
    )
    conn.commit()

    # Batch insert 1000 findings using batch_insert_findings
    from scripts.core.history_db import batch_insert_findings

    batch_insert_findings(conn, scan_id, benchmark_findings)

    elapsed = time.time() - start

    # Verify findings stored
    stored_findings = list(
        conn.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    )
    assert (
        stored_findings[0] == 1000
    ), f"Expected 1000 findings, got {stored_findings[0]}"

    # Performance assertion
    assert (
        elapsed < 2.0
    ), f"Took {elapsed:.2f}s, expected <2s (PERFORMANCE TARGET MISSED)"

    print(
        f"\n✅ Performance Test 1 PASSED: Stored 1000 findings in {elapsed:.3f}s (target: <2s)"
    )


def test_query_10k_scans_fast(large_database: Path):
    """
    Performance Test 2: Query 10,000 scans in <500ms.

    Target: <500ms to retrieve 10k scans
    Strategy: Ensure indices on timestamp, branch columns
    """
    conn = get_connection(large_database)

    start = time.time()

    # Query all 10k scans
    scans = list_scans(conn, limit=10000)

    elapsed = time.time() - start

    # Verify count
    assert len(scans) == 10000, f"Expected 10000 scans, got {len(scans)}"

    # Performance assertion (relaxed to 0.6s to account for slower CI runners)
    assert (
        elapsed < 0.6
    ), f"Took {elapsed:.3f}s, expected <0.6s (PERFORMANCE TARGET MISSED)"

    print(
        f"\n✅ Performance Test 2 PASSED: Queried 10k scans in {elapsed:.3f}s (target: <0.5s)"
    )


def test_batch_insert_10k_findings(tmp_path: Path, large_database: Path):
    """
    Performance Test 3: Batch insert 10,000 findings in <5 seconds.

    Target: <5 seconds for 10k findings
    Strategy: Use executemany() with prepared statements
    """
    # Generate 10k findings
    findings = [create_test_finding(i) for i in range(10000)]

    # Get connection to large database
    conn = get_connection(large_database)

    # Create a new scan for testing
    scan_id = "perf-test-scan-batch"
    conn.execute(
        """
        INSERT INTO scans (
            id, timestamp, timestamp_iso, profile, tools, targets, target_type,
            total_findings, critical_count, high_count, medium_count, low_count, info_count,
            jmo_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            int(time.time()),
            "2024-01-01T00:00:00Z",
            "balanced",
            '["trivy"]',
            '["/test"]',
            "repo",
            10000,
            1000,
            2000,
            3000,
            2000,
            2000,  # severity counts
            "1.0.0",
        ),
    )
    conn.commit()

    # Start timing
    start = time.time()

    # Use batch_insert_findings
    from scripts.core.history_db import batch_insert_findings

    batch_insert_findings(conn, scan_id, findings)

    elapsed = time.time() - start

    # Verify count
    count = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]
    assert count == 10000, f"Expected 10000 findings, got {count}"

    # Performance assertion
    assert (
        elapsed < 5.0
    ), f"Took {elapsed:.2f}s, expected <5s (PERFORMANCE TARGET MISSED)"

    print(
        f"\n✅ Performance Test 3 PASSED: Batch inserted 10k findings in {elapsed:.3f}s (target: <5s)"
    )


def test_index_usage_verified(large_database: Path):
    """
    Performance Test 4: Verify all queries use indices via EXPLAIN QUERY PLAN.

    Target: All common queries should use indices, not full table scans
    Strategy: Check EXPLAIN QUERY PLAN output for "USING INDEX" or "SEARCH"
    """
    conn = get_connection(large_database)

    # Import get_query_plan (will be implemented in Step 4.2)
    try:
        from scripts.core.history_db import get_query_plan
    except ImportError:
        # Temporary fallback implementation
        def get_query_plan(conn: sqlite3.Connection, query: str) -> str:
            cursor = conn.cursor()
            cursor.execute(f"EXPLAIN QUERY PLAN {query}")
            rows = cursor.fetchall()
            return "\n".join(str(row) for row in rows)

    # Test common queries
    test_cases = [
        {
            "name": "Query scans by branch",
            "query": "SELECT * FROM scans WHERE branch = 'main' ORDER BY timestamp DESC LIMIT 100",
            "expected_index": "idx_scans_branch",
        },
        {
            "name": "Query findings by scan_id",
            "query": "SELECT * FROM findings WHERE scan_id = 'scan-00001' LIMIT 100",
            "expected_index": "findings",  # Primary key (scan_id, fingerprint)
        },
        {
            "name": "Query findings by severity",
            "query": "SELECT * FROM findings WHERE severity = 'CRITICAL' LIMIT 100",
            "expected_index": "idx_findings_severity",
        },
        {
            "name": "Query scans ordered by timestamp",
            "query": "SELECT * FROM scans ORDER BY timestamp DESC LIMIT 100",
            "expected_index": "idx_scans_timestamp",
        },
        {
            "name": "Query scans by target_type",
            "query": "SELECT * FROM scans WHERE target_type = 'repo' LIMIT 100",
            "expected_index": "idx_scans_target_type",
        },
    ]

    passed = []
    failed = []

    for test_case in test_cases:
        query = test_case["query"]
        expected_index = test_case["expected_index"]
        name = test_case["name"]

        plan = get_query_plan(conn, query)

        # Check if plan uses index (look for "USING INDEX" or "SEARCH" - not "SCAN TABLE")
        uses_index = "USING INDEX" in plan or (
            "SEARCH" in plan and "SCAN TABLE" not in plan
        )

        if uses_index:
            passed.append({"name": name, "query": query, "plan": plan})
        else:
            failed.append(
                {
                    "name": name,
                    "query": query,
                    "plan": plan,
                    "expected_index": expected_index,
                }
            )

    # Print results
    print(f"\n{'='*80}")
    print("Index Usage Verification Results")
    print(f"{'='*80}")
    print(f"✅ Passed: {len(passed)}/{len(test_cases)}")
    print(f"❌ Failed: {len(failed)}/{len(test_cases)}")

    if passed:
        print(f"\n{'='*80}")
        print("✅ PASSED QUERIES (Using Indices):")
        print(f"{'='*80}")
        for result in passed:
            print(f"\n{result['name']}:")
            print(f"Query: {result['query']}")
            print(f"Plan: {result['plan']}")

    if failed:
        print(f"\n{'='*80}")
        print("❌ FAILED QUERIES (Not Using Indices):")
        print(f"{'='*80}")
        for result in failed:
            print(f"\n{result['name']}:")
            print(f"Query: {result['query']}")
            print(f"Expected index: {result['expected_index']}")
            print(f"Plan: {result['plan']}")

    # Assertion: All queries should use indices
    assert (
        len(failed) == 0
    ), f"{len(failed)} queries not using indices (see output above)"

    print("\n✅ Performance Test 4 PASSED: All queries use indices correctly")


# Benchmark test (optional - for CI/local profiling)
@pytest.mark.benchmark
def test_benchmark_suite(tmp_path: Path, benchmark_findings: List[Dict[str, Any]]):
    """
    Comprehensive benchmark suite for performance profiling.

    Run with: pytest tests/performance/test_history_db_perf.py -v -m benchmark
    """
    db_path = tmp_path / "benchmark.db"
    init_database(db_path)

    results = {}

    # Create results directory structure
    results_dir = tmp_path / "results"
    summaries_dir = results_dir / "summaries"
    summaries_dir.mkdir(parents=True)

    # Write findings.json
    findings_file = summaries_dir / "findings.json"
    with open(findings_file, "w") as f:
        json.dump(
            {
                "findings": benchmark_findings,
                "metadata": {
                    "scan_time": "2024-01-01T00:00:00Z",
                    "total_findings": len(benchmark_findings),
                },
            },
            f,
        )

    # Benchmark 1: Store scan
    start = time.time()
    scan_id = store_scan(
        results_dir=results_dir,
        profile="balanced",
        tools=["trivy"],
        db_path=db_path,
    )
    results["store_scan"] = time.time() - start

    # Benchmark 2: Create a fresh scan and insert 1000 findings
    conn = get_connection(db_path)
    scan_id_2 = "bench-scan-2"
    timestamp_now = int(time.time())
    conn.execute(
        """
        INSERT INTO scans (
            id, timestamp, timestamp_iso, profile, tools, targets, target_type,
            total_findings, critical_count, high_count, medium_count, low_count, info_count,
            jmo_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id_2,
            timestamp_now,
            "2024-01-01T00:00:00Z",
            "balanced",
            '["trivy"]',
            '["/test"]',
            "repo",
            1000,
            100,
            200,
            300,
            200,
            200,
            "1.0.0",
        ),
    )
    conn.commit()

    start = time.time()
    from scripts.core.history_db import batch_insert_findings

    batch_insert_findings(conn, scan_id_2, benchmark_findings)
    results["insert_1000_findings"] = time.time() - start

    # Benchmark 3: Query scans
    start = time.time()
    _ = list_scans(conn, limit=100)
    results["query_100_scans"] = time.time() - start

    # Benchmark 4: Get scan by ID
    start = time.time()
    _ = get_scan_by_id(conn, scan_id)
    results["get_scan_by_id"] = time.time() - start

    # Print benchmark results
    print(f"\n{'='*80}")
    print("Benchmark Results:")
    print(f"{'='*80}")
    for name, duration in results.items():
        print(f"{name:30s}: {duration:.4f}s")

    # All benchmarks should complete (no specific time assertions)
    assert all(d >= 0 for d in results.values())
