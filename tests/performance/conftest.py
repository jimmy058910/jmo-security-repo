#!/usr/bin/env python3
"""
Performance test fixtures for JMo Security history database.

Provides realistic large-scale test data:
- Large databases with 10k scans and 100k findings
- Benchmark finding generators
- Performance profiling utilities
"""

from __future__ import annotations

import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Import from history_db module
from scripts.core.history_db import (
    get_connection,
    init_database,
)


@pytest.fixture
def benchmark_findings() -> List[Dict[str, Any]]:
    """
    Generate 1000 realistic findings for benchmarking.

    Returns:
        List of 1000 CommonFinding v1.2.0 compliant findings
    """
    findings = []

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    tools = ["trivy", "semgrep", "trufflehog", "checkov", "bandit"]
    rule_ids = [
        "CVE-2024-1234",
        "CWE-79",
        "CWE-89",
        "G101",
        "semgrep.rules.security",
        "hardcoded-secret",
    ]

    for i in range(1000):
        finding = {
            "schemaVersion": "1.2.0",
            "id": f"fingerprint-{i:06d}-test",
            "fingerprint": f"fingerprint-{i:06d}-test",
            "ruleId": random.choice(rule_ids),
            "severity": random.choice(severities),
            "tool": {"name": random.choice(tools), "version": "1.0.0"},
            "location": {
                "path": f"src/test/file{i % 100}.py",
                "startLine": random.randint(1, 1000),
                "endLine": random.randint(1, 1000),
            },
            "message": f"Test security finding {i}",
            "title": f"Security Issue {i}",
            "description": f"Detailed description of security issue {i}",
            "remediation": "Fix the issue by doing X, Y, Z",
            "references": [f"https://example.com/issue/{i}"],
            "tags": ["security", "test"],
            "compliance": {
                "owaspTop10_2021": ["A03:2021"],
                "cweTop25_2024": [
                    {"id": "CWE-79", "rank": 2, "category": "Improper Neutralization"}
                ],
                "cisControlsV8_1": [{"control": "16.1", "title": "Test", "ig": "IG1"}],
                "nistCsf2_0": [
                    {"function": "PR", "category": "PR.DS", "subcategory": "PR.DS-1"}
                ],
                "pciDss4_0": [{"requirement": "6.2.4", "priority": "P1"}],
                "mitreAttack": [
                    {"tactic": "TA0001", "technique": "T1190", "subtechnique": None}
                ],
            },
            "risk": {
                "cwe": "CWE-79",
                "confidence": "HIGH",
                "likelihood": "MEDIUM",
                "impact": "HIGH",
            },
            "raw": {"original_tool_data": f"test_data_{i}"},
        }
        findings.append(finding)

    return findings


@pytest.fixture
def large_database(tmp_path: Path) -> Path:
    """
    Create database with 10k scans and 100k findings for performance testing.

    This fixture simulates a production database with realistic data:
    - 10,000 scans spanning 180 days
    - 100,000 findings (avg 10 per scan)
    - Multiple branches, profiles, target types
    - Realistic severity distribution

    Returns:
        Path to the large database file
    """
    db_path = tmp_path / "large.db"
    init_database(db_path)

    conn = get_connection(db_path)

    # Generate 10k scans
    branches = ["main", "dev", "feature/auth", "feature/api"]
    profiles = ["fast", "balanced", "deep"]
    target_types = ["repo", "image", "iac", "url", "gitlab", "k8s"]
    tools_list = [
        '["trivy", "semgrep"]',
        '["trufflehog", "semgrep", "trivy"]',
        '["checkov", "trivy"]',
        '["bandit", "semgrep"]',
    ]

    # Base timestamp (180 days ago)
    base_time = datetime.now(timezone.utc) - timedelta(days=180)

    print(f"\nGenerating 10k scans in {db_path}...")
    start = time.time()

    scan_rows = []
    finding_rows = []

    for i in range(10000):
        scan_id = f"scan-{i:05d}"
        timestamp_dt = base_time + timedelta(minutes=i * 25)  # ~25 min apart
        timestamp = int(timestamp_dt.timestamp())

        # Realistic severity distribution
        critical_count = random.randint(0, 5)
        high_count = random.randint(0, 15)
        medium_count = random.randint(0, 30)
        low_count = random.randint(0, 40)
        info_count = random.randint(0, 20)
        total_findings = (
            critical_count + high_count + medium_count + low_count + info_count
        )

        scan_row = (
            scan_id,
            timestamp,
            timestamp_dt.isoformat(),
            f"commit-{i:05d}",
            f"commit-{i:05d}"[:7],
            random.choice(branches),
            None,  # tag
            random.choice([0, 0, 0, 1]),  # is_dirty (mostly clean)
            random.choice(profiles),
            random.choice(tools_list),
            f'["/test/repo-{i % 100}"]',
            random.choice(target_types),
            total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            "1.0.0",
            "test-host",
            "test-user",
            random.choice([None, "github", "gitlab"]),
            None,  # ci_build_id
            random.uniform(30.0, 300.0),  # duration_seconds
        )
        scan_rows.append(scan_row)

        # Generate findings for this scan (avg 10 per scan = 100k total)
        for j in range(total_findings):
            severity = "CRITICAL"
            if j >= critical_count:
                severity = "HIGH"
            if j >= critical_count + high_count:
                severity = "MEDIUM"
            if j >= critical_count + high_count + medium_count:
                severity = "LOW"
            if j >= critical_count + high_count + medium_count + low_count:
                severity = "INFO"

            finding_row = (
                scan_id,
                f"{scan_id}-finding-{j:03d}",
                severity,
                random.choice(["CVE-2024-1234", "CWE-79", "CWE-89", "G101"]),
                random.choice(["trivy", "semgrep", "trufflehog"]),
                "1.0.0",
                f"src/file{j % 50}.py",
                random.randint(1, 500),
                random.randint(1, 500),
                f"Test finding {j}",
                json.dumps({"test": f"data-{j}"}),
            )
            finding_rows.append(finding_row)

    # Batch insert scans
    with conn:
        conn.executemany(
            """
            INSERT INTO scans (
                id, timestamp, timestamp_iso, commit_hash, commit_short, branch, tag, is_dirty,
                profile, tools, targets, target_type, total_findings, critical_count, high_count,
                medium_count, low_count, info_count, jmo_version, hostname, username, ci_provider,
                ci_build_id, duration_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            scan_rows,
        )

        # Batch insert findings
        conn.executemany(
            """
            INSERT INTO findings (
                scan_id, fingerprint, severity, rule_id, tool, tool_version,
                path, start_line, end_line, message, raw_finding
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            finding_rows,
        )

    elapsed = time.time() - start
    print(f"Generated 10k scans + {len(finding_rows)} findings in {elapsed:.2f}s")

    return db_path


@pytest.fixture
def benchmark_context(tmp_path: Path) -> Dict[str, Any]:
    """
    Provide benchmark context with timing utilities.

    Returns:
        Dict with helper functions for timing and assertions
    """
    return {
        "tmp_path": tmp_path,
        "start_time": None,
        "elapsed": None,
    }


def create_test_finding(index: int) -> Dict[str, Any]:
    """
    Create a single test finding with CommonFinding v1.2.0 schema.

    Args:
        index: Unique index for the finding

    Returns:
        Dict representing a CommonFinding
    """
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    return {
        "schemaVersion": "1.2.0",
        "id": f"test-fingerprint-{index:06d}",
        "fingerprint": f"test-fingerprint-{index:06d}",
        "ruleId": f"TEST-RULE-{index % 10}",
        "severity": severities[index % len(severities)],
        "tool": {"name": "test-tool", "version": "1.0.0"},
        "location": {
            "path": f"test/file{index % 100}.py",
            "startLine": index,
            "endLine": index + 5,
        },
        "message": f"Test finding {index}",
        "title": f"Test Issue {index}",
        "description": f"Description for test finding {index}",
        "remediation": "Fix it",
        "references": [],
        "tags": ["test"],
        "compliance": {
            "owaspTop10_2021": [],
            "cweTop25_2024": [],
            "cisControlsV8_1": [],
            "nistCsf2_0": [],
            "pciDss4_0": [],
            "mitreAttack": [],
        },
        "risk": {
            "cwe": "CWE-79",
            "confidence": "HIGH",
            "likelihood": "MEDIUM",
            "impact": "HIGH",
        },
        "raw": {},
    }
