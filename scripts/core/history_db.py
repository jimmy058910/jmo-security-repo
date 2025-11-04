#!/usr/bin/env python3
"""
SQLite Historical Storage implementation for JMo Security.

This module provides:
- Database initialization and schema creation
- Scan storage and retrieval
- Connection management with pooling
- Transaction management
- Query helpers for historical analysis
- Integration with CommonFinding v1.2.0 schema

Database Location: .jmo/history.db (default)
Schema Version: 1.0.0
"""

from __future__ import annotations

import json
import logging
import sqlite3
import subprocess
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Configure logging
logger = logging.getLogger(__name__)

# Schema version for migrations
SCHEMA_VERSION = "1.0.0"

# Default database location
DEFAULT_DB_PATH = Path(".jmo/history.db")

# SQL statements for schema creation
CREATE_SCHEMA_VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_version (
    version TEXT PRIMARY KEY,
    applied_at INTEGER NOT NULL,
    applied_at_iso TEXT NOT NULL
);
"""

CREATE_SCANS_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
    -- Primary Key
    id TEXT PRIMARY KEY,

    -- Timestamp
    timestamp INTEGER NOT NULL,
    timestamp_iso TEXT NOT NULL,

    -- Git Context (nullable for non-repo targets)
    commit_hash TEXT,
    commit_short TEXT,
    branch TEXT,
    tag TEXT,
    is_dirty INTEGER DEFAULT 0,

    -- Scan Configuration
    profile TEXT NOT NULL,
    tools TEXT NOT NULL,
    targets TEXT NOT NULL,
    target_type TEXT NOT NULL,

    -- Results Summary
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,

    -- Metadata
    jmo_version TEXT NOT NULL,
    hostname TEXT,
    username TEXT,
    ci_provider TEXT,
    ci_build_id TEXT,

    -- Performance
    duration_seconds REAL,

    -- Constraints
    CHECK (profile IN ('fast', 'balanced', 'deep')),
    CHECK (target_type IN ('repo', 'image', 'iac', 'url', 'gitlab', 'k8s', 'unknown'))
);
"""

CREATE_FINDINGS_TABLE = """
CREATE TABLE IF NOT EXISTS findings (
    -- Composite Primary Key
    scan_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,

    -- Core Finding Data
    severity TEXT NOT NULL,
    tool TEXT NOT NULL,
    tool_version TEXT,
    rule_id TEXT NOT NULL,

    -- Location
    path TEXT NOT NULL,
    start_line INTEGER,
    end_line INTEGER,

    -- Content
    title TEXT,
    message TEXT NOT NULL,
    remediation TEXT,

    -- Compliance (v1.2.0)
    owasp_top10 TEXT,
    cwe_top25 TEXT,
    cis_controls TEXT,
    nist_csf TEXT,
    pci_dss TEXT,
    mitre_attack TEXT,

    -- Risk Scoring (v1.1.0)
    cvss_score REAL,
    confidence TEXT,
    likelihood TEXT,
    impact TEXT,

    -- Raw Data
    raw_finding TEXT NOT NULL,

    -- Constraints
    PRIMARY KEY (scan_id, fingerprint),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    CHECK (confidence IN ('HIGH', 'MEDIUM', 'LOW', NULL)),
    CHECK (likelihood IN ('HIGH', 'MEDIUM', 'LOW', NULL)),
    CHECK (impact IN ('HIGH', 'MEDIUM', 'LOW', NULL))
);
"""

CREATE_SCAN_METADATA_TABLE = """
CREATE TABLE IF NOT EXISTS scan_metadata (
    scan_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,

    PRIMARY KEY (scan_id, key),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
"""

# Indices for performance
CREATE_INDICES = [
    "CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS idx_scans_branch ON scans(branch) WHERE branch IS NOT NULL;",
    "CREATE INDEX IF NOT EXISTS idx_scans_tag ON scans(tag) WHERE tag IS NOT NULL;",
    "CREATE INDEX IF NOT EXISTS idx_scans_commit ON scans(commit_hash) WHERE commit_hash IS NOT NULL;",
    "CREATE INDEX IF NOT EXISTS idx_scans_target_type ON scans(target_type);",
    "CREATE INDEX IF NOT EXISTS idx_scans_profile ON scans(profile);",
    "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);",
    "CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool);",
    "CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_path ON findings(path);",
    "CREATE INDEX IF NOT EXISTS idx_findings_cvss ON findings(cvss_score DESC) WHERE cvss_score IS NOT NULL;",
    "CREATE INDEX IF NOT EXISTS idx_metadata_scan_id ON scan_metadata(scan_id);",
]

# Triggers for auto-updating scan summary counts
CREATE_TRIGGERS = [
    """
    CREATE TRIGGER IF NOT EXISTS update_scan_counts_on_insert
    AFTER INSERT ON findings
    BEGIN
        UPDATE scans
        SET
            total_findings = total_findings + 1,
            critical_count = critical_count + CASE WHEN NEW.severity = 'CRITICAL' THEN 1 ELSE 0 END,
            high_count = high_count + CASE WHEN NEW.severity = 'HIGH' THEN 1 ELSE 0 END,
            medium_count = medium_count + CASE WHEN NEW.severity = 'MEDIUM' THEN 1 ELSE 0 END,
            low_count = low_count + CASE WHEN NEW.severity = 'LOW' THEN 1 ELSE 0 END,
            info_count = info_count + CASE WHEN NEW.severity = 'INFO' THEN 1 ELSE 0 END
        WHERE id = NEW.scan_id;
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS update_scan_counts_on_delete
    AFTER DELETE ON findings
    BEGIN
        UPDATE scans
        SET
            total_findings = total_findings - 1,
            critical_count = critical_count - CASE WHEN OLD.severity = 'CRITICAL' THEN 1 ELSE 0 END,
            high_count = high_count - CASE WHEN OLD.severity = 'HIGH' THEN 1 ELSE 0 END,
            medium_count = medium_count - CASE WHEN OLD.severity = 'MEDIUM' THEN 1 ELSE 0 END,
            low_count = low_count - CASE WHEN OLD.severity = 'LOW' THEN 1 ELSE 0 END,
            info_count = info_count - CASE WHEN OLD.severity = 'INFO' THEN 1 ELSE 0 END
        WHERE id = OLD.scan_id;
    END;
    """,
]

# Views for common queries
CREATE_VIEWS = [
    """
    CREATE VIEW IF NOT EXISTS latest_scan_by_branch AS
    SELECT
        s.branch,
        MAX(s.timestamp) AS latest_timestamp,
        s.id AS scan_id
    FROM scans s
    WHERE s.branch IS NOT NULL
    GROUP BY s.branch;
    """,
    """
    CREATE VIEW IF NOT EXISTS finding_history AS
    SELECT
        f.fingerprint,
        f.severity,
        f.rule_id,
        f.path,
        MIN(s.timestamp) AS first_seen,
        MAX(s.timestamp) AS last_seen,
        COUNT(DISTINCT s.id) AS scan_count
    FROM findings f
    JOIN scans s ON f.scan_id = s.id
    GROUP BY f.fingerprint;
    """,
]


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """
    Get database connection with optimizations.

    Args:
        db_path: Path to SQLite database file

    Returns:
        sqlite3.Connection with row_factory set

    Note:
        - Creates .jmo directory if it doesn't exist
        - Enables WAL mode for better concurrency
        - Sets pragmas for performance
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row

    # Performance optimizations
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA cache_size=10000;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA foreign_keys=ON;")

    return conn


@contextmanager
def transaction(conn: sqlite3.Connection):
    """Context manager for transactions with automatic rollback on error."""
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_database(db_path: Path = DEFAULT_DB_PATH) -> None:
    """
    Initialize database schema.

    Args:
        db_path: Path to SQLite database file

    Creates:
        - All tables (scans, findings, scan_metadata, schema_version)
        - All indices for performance
        - All triggers for auto-updating counts
        - All views for common queries
    """
    conn = get_connection(db_path)

    try:
        with transaction(conn):
            # Create tables
            conn.execute(CREATE_SCHEMA_VERSION_TABLE)
            conn.execute(CREATE_SCANS_TABLE)
            conn.execute(CREATE_FINDINGS_TABLE)
            conn.execute(CREATE_SCAN_METADATA_TABLE)

            # Create indices
            for idx_sql in CREATE_INDICES:
                conn.execute(idx_sql)

            # Create triggers
            for trigger_sql in CREATE_TRIGGERS:
                conn.execute(trigger_sql)

            # Create views
            for view_sql in CREATE_VIEWS:
                conn.execute(view_sql)

            # Record schema version
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM schema_version WHERE version = ?",
                (SCHEMA_VERSION,),
            )
            if cursor.fetchone()[0] == 0:
                now = int(time.time())
                now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
                cursor.execute(
                    "INSERT INTO schema_version (version, applied_at, applied_at_iso) VALUES (?, ?, ?)",
                    (SCHEMA_VERSION, now, now_iso),
                )

        logger.info(f"Database initialized: {db_path} (schema v{SCHEMA_VERSION})")

    except sqlite3.Error as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    finally:
        conn.close()


def get_git_context(repo_path: Path) -> Dict[str, Any]:
    """
    Extract Git metadata for scan.

    Args:
        repo_path: Path to Git repository

    Returns:
        Dict with git context (commit_hash, branch, tag, etc.)
        Returns empty values if not a Git repo or on error
    """
    try:
        # Commit hash
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        commit_hash = result.stdout.strip()

        # Short commit hash
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        commit_short = result.stdout.strip()

        # Branch name
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        branch = result.stdout.strip()

        # Tag (if on tagged commit)
        result = subprocess.run(
            ["git", "describe", "--tags", "--exact-match"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        tag = result.stdout.strip() if result.returncode == 0 else None

        # Check for uncommitted changes
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        is_dirty = 1 if result.stdout.strip() else 0

        return {
            "commit_hash": commit_hash,
            "commit_short": commit_short,
            "branch": branch,
            "tag": tag,
            "is_dirty": is_dirty,
        }

    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
    ):
        # Not a Git repo or git command failed
        return {
            "commit_hash": None,
            "commit_short": None,
            "branch": None,
            "tag": None,
            "is_dirty": 0,
        }


def detect_target_type(results_dir: Path) -> str:
    """
    Detect primary target type based on results directory structure.

    Args:
        results_dir: Path to scan results directory

    Returns:
        Target type: "repo" | "image" | "iac" | "url" | "gitlab" | "k8s" | "unknown"
    """
    if (results_dir / "individual-repos").exists():
        return "repo"
    elif (results_dir / "individual-images").exists():
        return "image"
    elif (results_dir / "individual-iac").exists():
        return "iac"
    elif (results_dir / "individual-web").exists():
        return "url"
    elif (results_dir / "individual-gitlab").exists():
        return "gitlab"
    elif (results_dir / "individual-k8s").exists():
        return "k8s"
    else:
        return "unknown"


def collect_targets(results_dir: Path) -> List[str]:
    """
    Collect target names from results directory.

    Args:
        results_dir: Path to scan results directory

    Returns:
        List of target names (e.g., ["myrepo", "nginx:latest"])
    """
    targets: list[str] = []
    target_type = detect_target_type(results_dir)

    if target_type == "unknown":
        return targets

    target_dir_map = {
        "repo": "individual-repos",
        "image": "individual-images",
        "iac": "individual-iac",
        "url": "individual-web",
        "gitlab": "individual-gitlab",
        "k8s": "individual-k8s",
    }

    target_dir = results_dir / target_dir_map[target_type]
    if target_dir.exists():
        targets = [d.name for d in target_dir.iterdir() if d.is_dir()]

    return targets


def store_scan(
    results_dir: Path,
    profile: str,
    tools: List[str],
    db_path: Path = DEFAULT_DB_PATH,
    commit_hash: Optional[str] = None,
    branch: Optional[str] = None,
    tag: Optional[str] = None,
    jmo_version: str = "1.0.0",
    duration_seconds: Optional[float] = None,
) -> str:
    """
    Store a completed scan in the history database.

    Args:
        results_dir: Path to scan results directory (contains findings.json)
        profile: Profile name ("fast" | "balanced" | "deep")
        tools: List of tool names that were run
        db_path: Path to SQLite database file
        commit_hash: Git commit hash (optional, auto-detected if None)
        branch: Git branch name (optional, auto-detected if None)
        tag: Git tag (optional, auto-detected if None)
        jmo_version: JMo Security version
        duration_seconds: Total scan duration in seconds

    Returns:
        Scan UUID (e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479")

    Raises:
        FileNotFoundError: If results_dir doesn't exist or findings.json not found
        ValueError: If invalid profile or data
        sqlite3.Error: On database errors
    """
    results_dir = Path(results_dir)

    # Validate inputs
    if not results_dir.exists():
        raise FileNotFoundError(f"Results directory not found: {results_dir}")

    findings_json = results_dir / "summaries" / "findings.json"
    if not findings_json.exists():
        raise FileNotFoundError(f"findings.json not found: {findings_json}")

    if profile not in ("fast", "balanced", "deep"):
        raise ValueError(f"Invalid profile: {profile}")

    # Load findings
    with open(findings_json, "r", encoding="utf-8") as f:
        findings_data = json.load(f)

    findings = findings_data.get("findings", [])

    # Generate scan ID
    scan_id = str(uuid.uuid4())

    # Current timestamp
    now = int(time.time())
    now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

    # Detect target type
    target_type = detect_target_type(results_dir)
    targets = collect_targets(results_dir)

    # Get Git context (if repo target and not provided)
    git_ctx = {}
    if target_type == "repo" and not all([commit_hash, branch]):
        # Try to detect Git context from first repo
        if targets:
            first_repo = results_dir / "individual-repos" / targets[0]
            # Try parent directories to find .git
            candidate = first_repo
            for _ in range(5):  # Max 5 levels up
                if (candidate / ".git").exists():
                    git_ctx = get_git_context(candidate)
                    break
                candidate = candidate.parent
                if candidate == candidate.parent:  # Reached filesystem root
                    break

    # Use provided values or detected values
    commit_hash = commit_hash or git_ctx.get("commit_hash")
    commit_short = (
        git_ctx.get("commit_short")
        if git_ctx
        else (commit_hash[:7] if commit_hash else None)
    )
    branch = branch or git_ctx.get("branch")
    tag = tag or git_ctx.get("tag")
    is_dirty = git_ctx.get("is_dirty", 0) if git_ctx else 0

    # Note: Severity counts are automatically calculated by database triggers
    # when findings are inserted. No need to pre-calculate them here.

    # Get environment metadata
    hostname = None
    username = None
    ci_provider = None
    ci_build_id = None

    try:
        import socket

        hostname = socket.gethostname()
    except Exception:
        pass

    try:
        import os

        username = os.environ.get("USER") or os.environ.get("USERNAME")
    except Exception:
        pass

    # Detect CI environment
    import os

    if os.environ.get("GITHUB_ACTIONS"):
        ci_provider = "github"
        ci_build_id = os.environ.get("GITHUB_RUN_ID")
    elif os.environ.get("GITLAB_CI"):
        ci_provider = "gitlab"
        ci_build_id = os.environ.get("CI_PIPELINE_ID")
    elif os.environ.get("JENKINS_URL"):
        ci_provider = "jenkins"
        ci_build_id = os.environ.get("BUILD_NUMBER")

    # Initialize database
    init_database(db_path)
    conn = get_connection(db_path)

    try:
        with transaction(conn):
            # Insert scan record
            conn.execute(
                """
                INSERT INTO scans (
                    id, timestamp, timestamp_iso,
                    commit_hash, commit_short, branch, tag, is_dirty,
                    profile, tools, targets, target_type,
                    total_findings, critical_count, high_count, medium_count, low_count, info_count,
                    jmo_version, hostname, username, ci_provider, ci_build_id,
                    duration_seconds
                ) VALUES (
                    ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?
                )
                """,
                (
                    scan_id,
                    now,
                    now_iso,
                    commit_hash,
                    commit_short,
                    branch,
                    tag,
                    is_dirty,
                    profile,
                    json.dumps(tools),
                    json.dumps(targets),
                    target_type,
                    0,  # total_findings - will be updated by trigger
                    0,  # critical_count - will be updated by trigger
                    0,  # high_count - will be updated by trigger
                    0,  # medium_count - will be updated by trigger
                    0,  # low_count - will be updated by trigger
                    0,  # info_count - will be updated by trigger
                    jmo_version,
                    hostname,
                    username,
                    ci_provider,
                    ci_build_id,
                    duration_seconds,
                ),
            )

            # Insert findings (batch insert for performance)
            finding_rows = []
            for finding in findings:
                fingerprint = finding.get("id", "")
                severity = finding.get("severity", "INFO").upper()
                tool_info = finding.get("tool", {})
                tool_name = (
                    tool_info.get("name", "unknown")
                    if isinstance(tool_info, dict)
                    else str(tool_info)
                )
                tool_version = (
                    tool_info.get("version") if isinstance(tool_info, dict) else None
                )
                rule_id = finding.get("ruleId", "")
                location = finding.get("location", {})
                path = location.get("path", "") if isinstance(location, dict) else ""
                start_line = (
                    location.get("startLine") if isinstance(location, dict) else None
                )
                end_line = (
                    location.get("endLine") if isinstance(location, dict) else None
                )
                title = finding.get("title")
                message = finding.get("message", "")
                remediation = finding.get("remediation")

                # Compliance data (v1.2.0)
                compliance = finding.get("compliance", {})
                owasp_top10 = (
                    json.dumps(compliance.get("owaspTop10_2021"))
                    if compliance.get("owaspTop10_2021")
                    else None
                )
                cwe_top25 = (
                    json.dumps(compliance.get("cweTop25_2024"))
                    if compliance.get("cweTop25_2024")
                    else None
                )
                cis_controls = (
                    json.dumps(compliance.get("cisControlsV8_1"))
                    if compliance.get("cisControlsV8_1")
                    else None
                )
                nist_csf = (
                    json.dumps(compliance.get("nistCsf2_0"))
                    if compliance.get("nistCsf2_0")
                    else None
                )
                pci_dss = (
                    json.dumps(compliance.get("pciDss4_0"))
                    if compliance.get("pciDss4_0")
                    else None
                )
                mitre_attack = (
                    json.dumps(compliance.get("mitreAttack"))
                    if compliance.get("mitreAttack")
                    else None
                )

                # Risk scoring (v1.1.0)
                risk = finding.get("risk", {})
                cvss_score = (
                    finding.get("cvss", {}).get("score")
                    if finding.get("cvss")
                    else None
                )
                confidence = risk.get("confidence")
                likelihood = risk.get("likelihood")
                impact = risk.get("impact")

                # Raw finding data
                raw_finding = json.dumps(finding)

                finding_rows.append(
                    (
                        scan_id,
                        fingerprint,
                        severity,
                        tool_name,
                        tool_version,
                        rule_id,
                        path,
                        start_line,
                        end_line,
                        title,
                        message,
                        remediation,
                        owasp_top10,
                        cwe_top25,
                        cis_controls,
                        nist_csf,
                        pci_dss,
                        mitre_attack,
                        cvss_score,
                        confidence,
                        likelihood,
                        impact,
                        raw_finding,
                    )
                )

            # Batch insert findings
            if finding_rows:
                conn.executemany(
                    """
                    INSERT INTO findings (
                        scan_id, fingerprint,
                        severity, tool, tool_version, rule_id,
                        path, start_line, end_line,
                        title, message, remediation,
                        owasp_top10, cwe_top25, cis_controls, nist_csf, pci_dss, mitre_attack,
                        cvss_score, confidence, likelihood, impact,
                        raw_finding
                    ) VALUES (
                        ?, ?,
                        ?, ?, ?, ?,
                        ?, ?, ?,
                        ?, ?, ?,
                        ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?,
                        ?
                    )
                    """,
                    finding_rows,
                )

            # Store metadata (results_dir path)
            conn.execute(
                "INSERT INTO scan_metadata (scan_id, key, value) VALUES (?, 'results_dir', ?)",
                (scan_id, str(results_dir.absolute())),
            )

        logger.info(
            f"Stored scan {scan_id}: {len(findings)} findings from {len(tools)} tools"
        )
        return scan_id

    except sqlite3.Error as e:
        logger.error(f"Failed to store scan: {e}")
        raise
    finally:
        conn.close()


def get_scan_by_id(conn: sqlite3.Connection, scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve scan metadata by ID.

    Args:
        conn: Database connection
        scan_id: Full or partial scan UUID

    Returns:
        Dict with scan metadata, or None if not found
    """
    cursor = conn.cursor()

    # Try exact match first
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()

    # Try prefix match if exact fails
    if not row:
        cursor.execute("SELECT * FROM scans WHERE id LIKE ? LIMIT 1", (f"{scan_id}%",))
        row = cursor.fetchone()

    if not row:
        return None

    return dict(row)


def list_scans(
    conn: sqlite3.Connection,
    branch: Optional[str] = None,
    profile: Optional[str] = None,
    since: Optional[int] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    List scans with optional filters.

    Args:
        conn: Database connection
        branch: Filter by branch name
        profile: Filter by profile name
        since: Filter by timestamp (Unix epoch seconds)
        limit: Maximum number of results

    Returns:
        List of scan metadata dicts
    """
    cursor = conn.cursor()

    where_clauses = []
    params = []

    if branch:
        where_clauses.append("branch = ?")
        params.append(branch)

    if profile:
        where_clauses.append("profile = ?")
        params.append(profile)

    if since:
        where_clauses.append("timestamp >= ?")
        params.append(str(since))

    where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

    cursor.execute(
        f"""
        SELECT * FROM scans
        WHERE {where_sql}
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        params + [limit],
    )

    return [dict(row) for row in cursor.fetchall()]


def get_findings_for_scan(
    conn: sqlite3.Connection,
    scan_id: str,
    severity: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve all findings for a specific scan.

    Args:
        conn: Database connection
        scan_id: Scan UUID
        severity: Optional severity filter

    Returns:
        List of finding dicts
    """
    cursor = conn.cursor()

    if severity:
        cursor.execute(
            "SELECT * FROM findings WHERE scan_id = ? AND severity = ? ORDER BY severity DESC, path",
            (scan_id, severity.upper()),
        )
    else:
        cursor.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity DESC, path",
            (scan_id,),
        )

    return [dict(row) for row in cursor.fetchall()]


def compute_diff(
    conn: sqlite3.Connection,
    scan_id_1: str,
    scan_id_2: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare two scans and identify new, resolved, and unchanged findings.

    Uses fingerprint-based matching to determine if a finding is the same
    across scans. Fingerprints are stable hashes of (tool, rule, location, message).

    Args:
        conn: Database connection
        scan_id_1: First scan ID (baseline)
        scan_id_2: Second scan ID (comparison)

    Returns:
        Dictionary with keys "new", "resolved", "unchanged"
        Each value is a list of findings (dict format)

    Raises:
        ValueError: If either scan ID doesn't exist

    Example:
        >>> diff = compute_diff(conn, scan1_id, scan2_id)
        >>> print(f"New: {len(diff['new'])}, Resolved: {len(diff['resolved'])}")
    """
    # 1. Validate scan IDs exist
    scan_1 = get_scan_by_id(conn, scan_id_1)
    scan_2 = get_scan_by_id(conn, scan_id_2)
    if not scan_1 or not scan_2:
        raise ValueError(f"Invalid scan ID: {scan_id_1 if not scan_1 else scan_id_2}")

    # 2. Get all findings for both scans
    findings_1 = get_findings_for_scan(conn, scan_id_1)
    findings_2 = get_findings_for_scan(conn, scan_id_2)

    # 3. Build sets of fingerprints
    fingerprints_1 = {f["fingerprint"]: f for f in findings_1}
    fingerprints_2 = {f["fingerprint"]: f for f in findings_2}

    # 4. Compute set differences
    new_fps = set(fingerprints_2.keys()) - set(fingerprints_1.keys())
    resolved_fps = set(fingerprints_1.keys()) - set(fingerprints_2.keys())
    unchanged_fps = set(fingerprints_1.keys()) & set(fingerprints_2.keys())

    # 5. Build result dictionary
    return {
        "new": [fingerprints_2[fp] for fp in new_fps],
        "resolved": [fingerprints_1[fp] for fp in resolved_fps],
        "unchanged": [fingerprints_2[fp] for fp in unchanged_fps],
    }


def get_trend_summary(
    conn: sqlite3.Connection,
    branch: str,
    days: int = 30,
) -> Optional[Dict[str, Any]]:
    """
    Analyze security trends for a branch over time.

    Computes severity trends, top recurring rules, and improvement metrics.

    Args:
        conn: Database connection
        branch: Git branch name (e.g., "main", "dev")
        days: Number of days to analyze (default: 30)

    Returns:
        Dictionary with trend data or None if no scans found:
        {
            "scan_count": int,
            "date_range": {"start": ISO timestamp, "end": ISO timestamp},
            "severity_trends": {
                "CRITICAL": [counts over time],
                "HIGH": [...],
                ...
            },
            "top_rules": [
                {"rule_id": str, "count": int, "severity": str},
                ...
            ],
            "improvement_metrics": {
                "trend": "improving" | "degrading" | "stable" | "insufficient_data",
                "total_change": int (negative = improvement),
                "critical_change": int,
                "high_change": int
            }
        }

    Example:
        >>> trend = get_trend_summary(conn, "main", days=30)
        >>> print(trend["improvement_metrics"]["trend"])
        improving
    """
    import time

    # 1. Calculate time window
    end_time = int(time.time())
    start_time = end_time - (days * 86400)

    # 2. Query scans in time window for branch
    cursor = conn.execute(
        """
        SELECT id, timestamp, timestamp_iso,
               total_findings, critical_count, high_count,
               medium_count, low_count, info_count
        FROM scans
        WHERE branch = ? AND timestamp >= ? AND timestamp <= ?
        ORDER BY timestamp ASC
        """,
        (branch, start_time, end_time),
    )
    scans = [dict(row) for row in cursor.fetchall()]

    if not scans:
        return None

    # 3. Build severity trends (time series)
    severity_trends = {
        "CRITICAL": [s["critical_count"] for s in scans],
        "HIGH": [s["high_count"] for s in scans],
        "MEDIUM": [s["medium_count"] for s in scans],
        "LOW": [s["low_count"] for s in scans],
        "INFO": [s["info_count"] for s in scans],
    }

    # 4. Get top rules (most frequent across all scans)
    scan_ids = [s["id"] for s in scans]
    placeholders = ",".join("?" * len(scan_ids))
    cursor = conn.execute(
        f"""
        SELECT rule_id, severity, COUNT(*) as count
        FROM findings
        WHERE scan_id IN ({placeholders})
        GROUP BY rule_id, severity
        ORDER BY count DESC
        LIMIT 10
        """,
        scan_ids,
    )
    top_rules = [dict(row) for row in cursor.fetchall()]

    # 5. Compute improvement metrics
    if len(scans) >= 2:
        first_scan = scans[0]
        last_scan = scans[-1]
        total_change = last_scan["total_findings"] - first_scan["total_findings"]
        critical_change = last_scan["critical_count"] - first_scan["critical_count"]
        high_change = last_scan["high_count"] - first_scan["high_count"]

        if total_change < -5:  # Threshold: 5+ fewer findings
            trend = "improving"
        elif total_change > 5:
            trend = "degrading"
        else:
            trend = "stable"
    else:
        total_change = 0
        critical_change = 0
        high_change = 0
        trend = "insufficient_data"

    return {
        "scan_count": len(scans),
        "date_range": {"start": scans[0]["timestamp_iso"], "end": scans[-1]["timestamp_iso"]},
        "severity_trends": severity_trends,
        "top_rules": top_rules,
        "improvement_metrics": {
            "trend": trend,
            "total_change": total_change,
            "critical_change": critical_change,
            "high_change": high_change,
        },
    }


def get_database_stats(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    Get database statistics.

    Args:
        conn: Database connection

    Returns:
        Dict with statistics (scan count, finding count, etc.)
    """
    cursor = conn.cursor()

    # Total scans
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    # Total findings
    cursor.execute("SELECT COUNT(*) FROM findings")
    total_findings = cursor.fetchone()[0]

    # Date range
    cursor.execute("SELECT MIN(timestamp_iso), MAX(timestamp_iso) FROM scans")
    date_range = cursor.fetchone()
    min_date = date_range[0]
    max_date = date_range[1]

    # Scans by branch
    cursor.execute(
        """
        SELECT branch, COUNT(*) as count
        FROM scans
        WHERE branch IS NOT NULL
        GROUP BY branch
        ORDER BY count DESC
        LIMIT 10
        """
    )
    scans_by_branch = [{"branch": row[0], "count": row[1]} for row in cursor.fetchall()]

    # Scans by profile
    cursor.execute(
        """
        SELECT profile, COUNT(*) as count
        FROM scans
        GROUP BY profile
        ORDER BY count DESC
        """
    )
    scans_by_profile = [
        {"profile": row[0], "count": row[1]} for row in cursor.fetchall()
    ]

    # Findings by severity
    cursor.execute(
        """
        SELECT severity, COUNT(*) as count
        FROM findings
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                WHEN 'INFO' THEN 5
            END
        """
    )
    findings_by_severity = [
        {"severity": row[0], "count": row[1]} for row in cursor.fetchall()
    ]

    # Top tools
    cursor.execute(
        """
        SELECT tool, COUNT(*) as count
        FROM findings
        GROUP BY tool
        ORDER BY count DESC
        LIMIT 10
        """
    )
    top_tools = [{"tool": row[0], "count": row[1]} for row in cursor.fetchall()]

    # Database file size
    db_path = conn.execute("PRAGMA database_list").fetchone()[2]
    db_size = Path(db_path).stat().st_size if Path(db_path).exists() else 0

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "min_date": min_date,
        "max_date": max_date,
        "scans_by_branch": scans_by_branch,
        "scans_by_profile": scans_by_profile,
        "findings_by_severity": findings_by_severity,
        "top_tools": top_tools,
        "db_size_bytes": db_size,
        "db_size_mb": round(db_size / (1024 * 1024), 2),
    }


def delete_scan(conn: sqlite3.Connection, scan_id: str) -> bool:
    """
    Delete a scan and all its findings.

    Args:
        conn: Database connection
        scan_id: Scan UUID

    Returns:
        True if scan was deleted, False if not found
    """
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return cursor.rowcount > 0


def prune_old_scans(
    conn: sqlite3.Connection,
    older_than_seconds: int,
) -> int:
    """
    Delete scans older than specified age.

    Args:
        conn: Database connection
        older_than_seconds: Age threshold in seconds

    Returns:
        Number of scans deleted
    """
    cutoff = int(time.time()) - older_than_seconds
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE timestamp < ?", (cutoff,))
    return cursor.rowcount
