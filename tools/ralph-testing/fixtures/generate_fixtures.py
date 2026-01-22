#!/usr/bin/env python3
"""
Generate test fixtures for Ralph CLI Testing Loop.

Creates:
- results-baseline/ with 15 findings
- results-current/ with 17 findings (12 overlap, 5 new)
- test-history.db with 5 scans and ~100 findings

Usage:
    python .claude/ralph-cli-testing/fixtures/generate_fixtures.py
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Fixture directory (relative to script location)
FIXTURE_DIR = Path(__file__).parent
BASELINE_DIR = FIXTURE_DIR / "results-baseline"
CURRENT_DIR = FIXTURE_DIR / "results-current"
HISTORY_DB = FIXTURE_DIR / "test-history.db"

# Schema version
SCHEMA_VERSION = "1.2.0"
OUTPUT_VERSION = "1.0.0"


def generate_finding(
    idx: int,
    tool: str,
    severity: str,
    rule_prefix: str,
    path_prefix: str = "src",
    extra_tags: list[str] | None = None,
) -> dict[str, Any]:
    """Generate a single CommonFinding v1.2.0 object."""
    base_tags = extra_tags or []
    finding = {
        "schemaVersion": SCHEMA_VERSION,
        "id": f"fp-{tool}-{idx:04d}",
        "ruleId": f"{rule_prefix}-{idx:03d}",
        "severity": severity,
        "tool": {"name": tool, "version": get_tool_version(tool)},
        "location": {
            "path": f"{path_prefix}/module_{idx % 5}.py",
            "startLine": 10 + (idx * 3),
            "endLine": 12 + (idx * 3),
            "startColumn": 1,
            "endColumn": 40,
        },
        "message": f"Finding {idx} from {tool}: {get_message_for_severity(severity)}",
        "title": f"Security Issue {idx} ({severity})",
        "description": f"Detailed description for finding {idx}.",
        "remediation": {
            "description": f"Remediation for finding {idx}.",
            "references": [f"https://cwe.mitre.org/data/definitions/{100 + idx}.html"],
        },
        "tags": base_tags + [tool.lower(), severity.lower()],
        "context": {
            "snippet": f"# Line {10 + idx * 3}: vulnerable code\ndata = user_input\n",
            "language": "python",
        },
    }

    # Add compliance mappings for CRITICAL/HIGH findings
    if severity in ("CRITICAL", "HIGH"):
        finding["compliance"] = {
            "owaspTop10": [f"A0{(idx % 10) + 1}:2021"],
            "cweTop25": [f"CWE-{79 + (idx % 20)}"],
            "cisControls": [f"4.{idx % 8 + 1}"],
        }

    return finding


def get_tool_version(tool: str) -> str:
    """Return mock version for tool."""
    versions = {
        "semgrep": "1.45.0",
        "trivy": "0.48.0",
        "bandit": "1.7.9",
        "trufflehog": "3.63.0",
        "checkov": "3.2.0",
        "gitleaks": "8.18.0",
        "hadolint": "2.12.0",
        "shellcheck": "0.9.0",
    }
    return versions.get(tool, "1.0.0")


def get_message_for_severity(severity: str) -> str:
    """Return message based on severity."""
    messages = {
        "CRITICAL": "Critical security vulnerability detected",
        "HIGH": "High severity issue requires immediate attention",
        "MEDIUM": "Medium severity issue should be addressed",
        "LOW": "Low severity issue for consideration",
        "INFO": "Informational finding",
    }
    return messages.get(severity, "Security finding")


def generate_baseline_findings() -> list[dict[str, Any]]:
    """Generate 15 findings for baseline results."""
    findings = []
    tools_severities = [
        ("semgrep", "CRITICAL"),
        ("semgrep", "HIGH"),
        ("semgrep", "MEDIUM"),
        ("trivy", "CRITICAL"),
        ("trivy", "HIGH"),
        ("trivy", "MEDIUM"),
        ("trivy", "LOW"),
        ("bandit", "HIGH"),
        ("bandit", "MEDIUM"),
        ("bandit", "LOW"),
        ("trufflehog", "CRITICAL"),
        ("gitleaks", "HIGH"),
        ("checkov", "MEDIUM"),
        ("hadolint", "LOW"),
        ("shellcheck", "INFO"),
    ]

    for idx, (tool, severity) in enumerate(tools_severities):
        findings.append(
            generate_finding(
                idx=idx,
                tool=tool,
                severity=severity,
                rule_prefix="CWE",
                extra_tags=["baseline"],
            )
        )

    return findings


def generate_current_findings() -> list[dict[str, Any]]:
    """Generate 17 findings for current results (12 overlap, 5 new)."""
    # Start with 12 findings that overlap with baseline (indices 0-11)
    findings = []
    tools_severities = [
        ("semgrep", "CRITICAL"),  # idx 0 - overlap
        ("semgrep", "HIGH"),  # idx 1 - overlap
        ("semgrep", "MEDIUM"),  # idx 2 - overlap
        ("trivy", "CRITICAL"),  # idx 3 - overlap
        ("trivy", "HIGH"),  # idx 4 - overlap
        ("trivy", "MEDIUM"),  # idx 5 - overlap
        ("trivy", "LOW"),  # idx 6 - overlap
        ("bandit", "HIGH"),  # idx 7 - overlap
        ("bandit", "MEDIUM"),  # idx 8 - overlap
        ("bandit", "LOW"),  # idx 9 - overlap
        ("trufflehog", "CRITICAL"),  # idx 10 - overlap
        ("gitleaks", "HIGH"),  # idx 11 - overlap
    ]

    for idx, (tool, severity) in enumerate(tools_severities):
        findings.append(
            generate_finding(
                idx=idx,
                tool=tool,
                severity=severity,
                rule_prefix="CWE",
                extra_tags=["current"],
            )
        )

    # Add 5 new findings (indices 15-19, different from baseline 12-14)
    new_findings = [
        ("semgrep", "CRITICAL", "NEW-VULN"),
        ("trivy", "HIGH", "CVE-2024"),
        ("bandit", "MEDIUM", "B301"),
        ("checkov", "LOW", "CKV"),
        ("nuclei", "INFO", "NUCLEI"),
    ]

    for offset, (tool, severity, prefix) in enumerate(new_findings):
        findings.append(
            generate_finding(
                idx=15 + offset,
                tool=tool,
                severity=severity,
                rule_prefix=prefix,
                path_prefix="new_src",
                extra_tags=["new", "current"],
            )
        )

    return findings


def wrap_findings(findings: list[dict[str, Any]], timestamp: str | None = None) -> dict[str, Any]:
    """Wrap findings in output envelope."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "meta": {
            "output_version": OUTPUT_VERSION,
            "schema_version": SCHEMA_VERSION,
            "finding_count": len(findings),
            "timestamp_iso": timestamp,
            "tools_run": list({f["tool"]["name"] for f in findings}),
        },
        "findings": findings,
    }


def create_history_database():
    """Create test-history.db with 5 scans and ~100 findings."""
    if HISTORY_DB.exists():
        HISTORY_DB.unlink()

    conn = sqlite3.connect(HISTORY_DB)
    cursor = conn.cursor()

    # Create schema
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS schema_version (
        version TEXT PRIMARY KEY,
        applied_at INTEGER NOT NULL,
        applied_at_iso TEXT NOT NULL
    )
    """
    )

    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        timestamp INTEGER NOT NULL,
        timestamp_iso TEXT NOT NULL,
        commit_hash TEXT,
        commit_short TEXT,
        branch TEXT,
        tag TEXT,
        is_dirty INTEGER DEFAULT 0,
        profile TEXT NOT NULL,
        tools TEXT NOT NULL,
        targets TEXT NOT NULL,
        target_type TEXT NOT NULL,
        total_findings INTEGER NOT NULL DEFAULT 0,
        critical_count INTEGER NOT NULL DEFAULT 0,
        high_count INTEGER NOT NULL DEFAULT 0,
        medium_count INTEGER NOT NULL DEFAULT 0,
        low_count INTEGER NOT NULL DEFAULT 0,
        info_count INTEGER NOT NULL DEFAULT 0,
        jmo_version TEXT NOT NULL,
        hostname TEXT,
        username TEXT,
        ci_provider TEXT,
        ci_build_id TEXT,
        duration_seconds REAL
    )
    """
    )

    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS findings (
        scan_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        severity TEXT NOT NULL,
        tool TEXT NOT NULL,
        tool_version TEXT,
        rule_id TEXT NOT NULL,
        path TEXT NOT NULL,
        start_line INTEGER,
        end_line INTEGER,
        title TEXT,
        message TEXT NOT NULL,
        remediation TEXT,
        owasp_top10 TEXT,
        cwe_top25 TEXT,
        cis_controls TEXT,
        nist_csf TEXT,
        pci_dss TEXT,
        mitre_attack TEXT,
        cvss_score REAL,
        confidence TEXT,
        likelihood TEXT,
        impact TEXT,
        raw_finding TEXT,
        PRIMARY KEY (scan_id, fingerprint),
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )
    """
    )

    # Insert schema version
    now = datetime.now(timezone.utc)
    cursor.execute(
        "INSERT INTO schema_version VALUES (?, ?, ?)",
        ("1.0.0", int(now.timestamp()), now.isoformat()),
    )

    # Insert 5 scans with different severity distributions
    scan_configs = [
        {"critical": 5, "high": 8, "medium": 10, "low": 5, "info": 2, "days_ago": 30},
        {"critical": 4, "high": 7, "medium": 8, "low": 4, "info": 2, "days_ago": 21},
        {"critical": 3, "high": 6, "medium": 7, "low": 4, "info": 2, "days_ago": 14},
        {"critical": 2, "high": 5, "medium": 6, "low": 3, "info": 2, "days_ago": 7},
        {"critical": 1, "high": 4, "medium": 5, "low": 3, "info": 2, "days_ago": 0},
    ]

    tools = ["semgrep", "trivy", "bandit", "trufflehog", "gitleaks"]

    for scan_idx, config in enumerate(scan_configs):
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        scan_time = now - timedelta(days=config["days_ago"])
        total = sum(
            config[k] for k in ["critical", "high", "medium", "low", "info"]
        )

        cursor.execute(
            """
        INSERT INTO scans (
            id, timestamp, timestamp_iso, commit_hash, commit_short, branch,
            profile, tools, targets, target_type, total_findings,
            critical_count, high_count, medium_count, low_count, info_count,
            jmo_version, hostname, username, duration_seconds
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                scan_id,
                int(scan_time.timestamp()),
                scan_time.isoformat(),
                f"abc{scan_idx}def123456789",
                f"abc{scan_idx}def",
                "main",
                "balanced",
                json.dumps(tools),
                json.dumps(["."]),
                "repo",
                total,
                config["critical"],
                config["high"],
                config["medium"],
                config["low"],
                config["info"],
                "1.0.0",
                "test-host",
                "test-user",
                120.5 + scan_idx * 10,
            ),
        )

        # Insert findings for this scan
        finding_idx = 0
        severity_counts = {
            "CRITICAL": config["critical"],
            "HIGH": config["high"],
            "MEDIUM": config["medium"],
            "LOW": config["low"],
            "INFO": config["info"],
        }

        for severity, count in severity_counts.items():
            for i in range(count):
                tool = tools[finding_idx % len(tools)]
                fingerprint = f"fp-{tool}-{scan_idx}-{finding_idx:04d}"
                cursor.execute(
                    """
                INSERT INTO findings (
                    scan_id, fingerprint, severity, tool, tool_version,
                    rule_id, path, start_line, end_line, title, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        scan_id,
                        fingerprint,
                        severity,
                        tool,
                        get_tool_version(tool),
                        f"CWE-{79 + finding_idx}",
                        f"src/module_{finding_idx % 5}.py",
                        10 + finding_idx,
                        12 + finding_idx,
                        f"Finding {finding_idx} ({severity})",
                        f"Security finding from {tool}",
                    ),
                )
                finding_idx += 1

    conn.commit()
    conn.close()
    print(f"Created {HISTORY_DB} with 5 scans")


def main():
    """Generate all fixtures."""
    print("Generating Ralph CLI Testing fixtures...")

    # Ensure directories exist
    (BASELINE_DIR / "summaries").mkdir(parents=True, exist_ok=True)
    (CURRENT_DIR / "summaries").mkdir(parents=True, exist_ok=True)

    # Generate baseline findings
    baseline_findings = generate_baseline_findings()
    baseline_output = wrap_findings(baseline_findings, "2026-01-15T00:00:00Z")

    baseline_path = BASELINE_DIR / "summaries" / "findings.json"
    with open(baseline_path, "w") as f:
        json.dump(baseline_output, f, indent=2)
    print(f"Created {baseline_path} with {len(baseline_findings)} findings")

    # Generate current findings
    current_findings = generate_current_findings()
    current_output = wrap_findings(current_findings, "2026-01-17T00:00:00Z")

    current_path = CURRENT_DIR / "summaries" / "findings.json"
    with open(current_path, "w") as f:
        json.dump(current_output, f, indent=2)
    print(f"Created {current_path} with {len(current_findings)} findings")

    # Generate history database
    create_history_database()

    print("Done!")


if __name__ == "__main__":
    main()
