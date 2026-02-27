"""
Tests for query_findings_db MCP tool.

Coverage:
- Security validation (reject INSERT, UPDATE, DELETE, DROP, ATTACH, unsafe PRAGMA, etc.)
- Multi-statement rejection
- Read-only connection enforcement
- Functional queries (SELECT, CTE, EXPLAIN, PRAGMA, parameterized)
- Row limit enforcement
- Database-not-found handling
- Empty / comment-only queries
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from scripts.core.history_db import (
    QuerySecurityError,
    _validate_readonly_query,
    execute_readonly_query,
)

# ---------------------------------------------------------------------------
# Fixture: temporary SQLite database with minimal schema and test data
# ---------------------------------------------------------------------------


@pytest.fixture()
def test_db(tmp_path: Path) -> Path:
    """Create a temporary SQLite database with scans and findings tables."""
    db_path = tmp_path / "test_history.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Create simplified scans table
    cursor.execute("""
        CREATE TABLE scans (
            id TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            profile TEXT NOT NULL,
            branch TEXT,
            total_findings INTEGER NOT NULL DEFAULT 0
        )
        """)

    # Create simplified findings table
    cursor.execute("""
        CREATE TABLE findings (
            scan_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            severity TEXT NOT NULL,
            tool TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            path TEXT NOT NULL,
            message TEXT NOT NULL,
            PRIMARY KEY (scan_id, fingerprint),
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        """)

    # Insert test scans
    cursor.executemany(
        "INSERT INTO scans (id, timestamp, profile, branch, total_findings) VALUES (?, ?, ?, ?, ?)",
        [
            ("scan-001", 1700000000, "balanced", "main", 3),
            ("scan-002", 1700001000, "fast", "dev", 2),
            ("scan-003", 1700002000, "deep", "main", 1),
        ],
    )

    # Insert test findings
    cursor.executemany(
        "INSERT INTO findings (scan_id, fingerprint, severity, tool, rule_id, path, message) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (
                "scan-001",
                "fp-1",
                "CRITICAL",
                "semgrep",
                "CWE-89",
                "src/db.py",
                "SQL injection",
            ),
            (
                "scan-001",
                "fp-2",
                "HIGH",
                "trivy",
                "CVE-2023-1234",
                "Dockerfile",
                "Vulnerable base image",
            ),
            (
                "scan-001",
                "fp-3",
                "LOW",
                "bandit",
                "B201",
                "tests/test.py",
                "Assert used",
            ),
            (
                "scan-002",
                "fp-4",
                "HIGH",
                "trufflehog",
                "aws-key",
                "config.py",
                "AWS key leaked",
            ),
            ("scan-002", "fp-5", "MEDIUM", "semgrep", "CWE-79", "src/app.js", "XSS"),
            (
                "scan-003",
                "fp-6",
                "CRITICAL",
                "trivy",
                "CVE-2024-9999",
                "go.mod",
                "RCE vuln",
            ),
        ],
    )

    conn.commit()
    conn.close()
    return db_path


# ==============================================================================
# Security Tests (Critical)
# ==============================================================================


class TestSecurityRejections:
    """Queries that MUST be rejected for security."""

    def test_reject_insert(self):
        """INSERT is rejected (prefix check blocks it)."""
        with pytest.raises(QuerySecurityError):
            _validate_readonly_query("INSERT INTO scans VALUES ('x')")

    def test_reject_update(self):
        """UPDATE is rejected (prefix check blocks it)."""
        with pytest.raises(QuerySecurityError):
            _validate_readonly_query("UPDATE scans SET branch='hacked'")

    def test_reject_delete(self):
        """DELETE is rejected (prefix check blocks it)."""
        with pytest.raises(QuerySecurityError):
            _validate_readonly_query("DELETE FROM findings")

    def test_reject_drop(self):
        """DROP is rejected (prefix check blocks it)."""
        with pytest.raises(QuerySecurityError):
            _validate_readonly_query("DROP TABLE scans")

    def test_reject_create(self):
        """CREATE is rejected (prefix check blocks it)."""
        with pytest.raises(QuerySecurityError):
            _validate_readonly_query("CREATE TABLE evil (id INT)")

    def test_reject_alter(self):
        """ALTER is rejected (prefix check blocks it)."""
        with pytest.raises(QuerySecurityError):
            _validate_readonly_query("ALTER TABLE scans ADD COLUMN x TEXT")

    def test_reject_attach(self):
        """ATTACH is rejected (prefix check blocks it)."""
        with pytest.raises(QuerySecurityError):
            _validate_readonly_query("ATTACH DATABASE ':memory:' AS ext")

    def test_reject_detach(self):
        """DETACH is rejected (prefix check blocks it)."""
        with pytest.raises(QuerySecurityError):
            _validate_readonly_query("DETACH DATABASE ext")

    def test_reject_replace(self):
        """REPLACE is rejected (prefix check blocks it)."""
        with pytest.raises(QuerySecurityError):
            _validate_readonly_query(
                "REPLACE INTO scans VALUES ('x', 0, 'fast', 'main', 0)"
            )

    def test_reject_multiple_statements(self, test_db):
        with pytest.raises(QuerySecurityError, match="Multiple statements"):
            execute_readonly_query(test_db, "SELECT 1; SELECT 2")

    def test_reject_multiple_statements_with_drop(self, test_db):
        """Multi-statement with DROP is rejected (forbidden keyword or multi-stmt)."""
        with pytest.raises(QuerySecurityError):
            execute_readonly_query(test_db, "SELECT 1; DROP TABLE scans")

    def test_reject_multiple_statements_validation(self):
        with pytest.raises(QuerySecurityError, match="Multiple statements"):
            _validate_readonly_query("SELECT 1; SELECT 2")

    def test_reject_unsafe_pragma(self):
        with pytest.raises(QuerySecurityError, match="Unsafe PRAGMA"):
            _validate_readonly_query("PRAGMA writable_schema = ON")

    def test_reject_pragma_journal_mode(self):
        """PRAGMA journal_mode is unsafe (it can change DB behavior)."""
        with pytest.raises(QuerySecurityError, match="Unsafe PRAGMA"):
            _validate_readonly_query("PRAGMA journal_mode = WAL")

    def test_reject_pragma_integrity_check(self):
        with pytest.raises(QuerySecurityError, match="Unsafe PRAGMA"):
            _validate_readonly_query("PRAGMA integrity_check")

    def test_empty_query_rejected(self):
        with pytest.raises(QuerySecurityError, match="Empty query"):
            _validate_readonly_query("")

    def test_whitespace_only_query_rejected(self):
        with pytest.raises(QuerySecurityError, match="Empty query"):
            _validate_readonly_query("   \t\n  ")

    def test_comment_only_query_rejected(self):
        with pytest.raises(QuerySecurityError, match="only comments"):
            _validate_readonly_query("-- just a comment\n/* block */")

    def test_readonly_connection_blocks_write(self, test_db):
        """Direct write on a ro connection must raise OperationalError."""
        import sqlite3 as _sqlite3

        abs_path = test_db.resolve()
        uri_path = abs_path.as_posix()
        if not uri_path.startswith("/"):
            uri_path = "/" + uri_path
        conn = _sqlite3.connect(f"file://{uri_path}?mode=ro", uri=True)
        try:
            with pytest.raises(_sqlite3.OperationalError, match="readonly"):
                conn.execute("INSERT INTO scans VALUES ('evil', 0, 'fast', 'main', 0)")
        finally:
            conn.close()

    def test_forbidden_keyword_in_subquery(self):
        """Forbidden keywords inside sub-expressions are still caught."""
        with pytest.raises(QuerySecurityError, match="DELETE"):
            _validate_readonly_query("SELECT * FROM (DELETE FROM scans)")

    def test_select_with_forbidden_column_name_allowed(self):
        """Column names that *contain* forbidden words should not trigger rejection.

        E.g. ``created_at`` contains 'CREATE' but is not a standalone keyword.
        Word-boundary regex prevents this false positive.
        """
        # This should NOT raise — "created_at" is not the keyword CREATE
        _validate_readonly_query("SELECT created_at FROM scans")

    def test_select_with_update_in_alias_rejected(self):
        """The word UPDATE as a standalone alias IS caught."""
        with pytest.raises(QuerySecurityError, match="UPDATE"):
            _validate_readonly_query("SELECT 1 AS UPDATE")

    def test_insert_in_select_context_rejected(self):
        """INSERT keyword within a SELECT is still blocked."""
        with pytest.raises(QuerySecurityError, match="INSERT"):
            _validate_readonly_query("SELECT INSERT FROM scans")


# ==============================================================================
# Functional Tests
# ==============================================================================


class TestFunctionalQueries:
    """Queries that MUST succeed."""

    def test_query_select_basic(self, test_db):
        result = execute_readonly_query(
            test_db, "SELECT id, profile FROM scans ORDER BY timestamp"
        )
        assert result["columns"] == ["id", "profile"]
        assert result["row_count"] == 3
        assert result["truncated"] is False
        assert result["rows"][0] == ["scan-001", "balanced"]

    def test_query_select_with_params(self, test_db):
        result = execute_readonly_query(
            test_db,
            "SELECT severity, COUNT(*) AS cnt FROM findings WHERE scan_id = ? GROUP BY severity",
            params=["scan-001"],
        )
        assert result["columns"] == ["severity", "cnt"]
        assert result["row_count"] > 0
        # scan-001 has 3 findings: CRITICAL, HIGH, LOW
        severities = {row[0] for row in result["rows"]}
        assert severities == {"CRITICAL", "HIGH", "LOW"}

    def test_query_schema_discovery(self, test_db):
        result = execute_readonly_query(
            test_db,
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name",
        )
        assert "name" in result["columns"]
        table_names = {row[0] for row in result["rows"]}
        assert "scans" in table_names
        assert "findings" in table_names

    def test_query_with_cte(self, test_db):
        result = execute_readonly_query(
            test_db,
            """
            WITH recent AS (
                SELECT id, profile FROM scans ORDER BY timestamp DESC LIMIT 2
            )
            SELECT * FROM recent
            """,
        )
        assert result["row_count"] == 2
        assert result["truncated"] is False

    def test_query_explain(self, test_db):
        result = execute_readonly_query(test_db, "EXPLAIN SELECT * FROM scans LIMIT 1")
        assert result["row_count"] > 0
        assert len(result["columns"]) > 0

    def test_allow_safe_pragma(self, test_db):
        result = execute_readonly_query(test_db, "PRAGMA table_info(scans)")
        assert result["row_count"] > 0
        # table_info returns columns: cid, name, type, notnull, dflt_value, pk
        assert "name" in result["columns"]

    def test_allow_pragma_table_list(self, test_db):
        """PRAGMA table_list is a safe read-only pragma."""
        result = execute_readonly_query(test_db, "PRAGMA table_list")
        assert result["row_count"] > 0

    def test_allow_pragma_compile_options(self, test_db):
        result = execute_readonly_query(test_db, "PRAGMA compile_options")
        assert result["row_count"] > 0

    def test_row_limit_enforced(self, test_db):
        """When more than max_rows exist, results are truncated."""
        # Insert many rows
        conn = sqlite3.connect(str(test_db))
        cursor = conn.cursor()
        for i in range(600):
            cursor.execute(
                "INSERT INTO findings VALUES (?, ?, 'LOW', 'test', 'R1', 'f.py', 'msg')",
                ("scan-001", f"bulk-{i:04d}"),
            )
        conn.commit()
        conn.close()

        result = execute_readonly_query(
            test_db,
            "SELECT * FROM findings",
            max_rows=500,
        )
        assert result["row_count"] == 500
        assert result["truncated"] is True

    def test_custom_max_rows(self, test_db):
        result = execute_readonly_query(
            test_db,
            "SELECT * FROM findings",
            max_rows=2,
        )
        # There are 6 findings in the fixture; max_rows=2 should cap it
        assert result["row_count"] == 2
        assert result["truncated"] is True

    def test_database_not_found(self, tmp_path):
        missing = tmp_path / "nonexistent.db"
        with pytest.raises(ValueError, match="Database not found"):
            execute_readonly_query(missing, "SELECT 1")

    def test_empty_query_value_error(self, test_db):
        with pytest.raises(ValueError, match="must not be empty"):
            execute_readonly_query(test_db, "")

    def test_query_no_params_default(self, test_db):
        """params=None (default) works correctly."""
        result = execute_readonly_query(test_db, "SELECT COUNT(*) AS n FROM scans")
        assert result["rows"][0][0] == 3

    def test_semicolon_inside_string_literal(self):
        """Semicolons inside string literals should not cause rejection."""
        _validate_readonly_query("SELECT * FROM scans WHERE id = 'a;b'")


# ==============================================================================
# Helper
# ==============================================================================


def _validate_readonly_query_raises(query: str, expected_keyword: str):
    """Assert that _validate_readonly_query raises QuerySecurityError."""
    with pytest.raises(QuerySecurityError, match=expected_keyword):
        _validate_readonly_query(query)
