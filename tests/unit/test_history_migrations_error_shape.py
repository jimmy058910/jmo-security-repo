"""One failed migration is one error entry (#908).

``run_migrations`` appended inside the rollback handler *and* again
unconditionally afterwards, so ``len(result["errors"])`` was 1 or 2 for the same
single failure depending only on whether ``migrate_down`` also raised -- and the
loop ``break``s either way, so it is always one migration.

``cmd_history_migrate`` renders every entry, so the double-failure case printed
the same version and message twice with the more informative entry (the one
naming ``rollback_error``) indistinguishable from the less. Now that
``jmo history migrate --json`` returns a correct exit code (#902/#904), the
``errors`` array is the natural next thing for automation to count.
"""

from __future__ import annotations

import sqlite3

import pytest

from scripts.core import history_migrations as hm


class _FailingUp:
    """A migration whose `migrate_up` always raises."""

    version = "9.9.9"
    description = "deliberately explodes"

    def migrate_up(self, conn):
        raise RuntimeError("up failed")

    def migrate_down(self, conn):
        return None


class _FailingBoth(_FailingUp):
    """...and whose rollback also raises."""

    def migrate_down(self, conn):
        raise RuntimeError("down failed")


@pytest.fixture
def db(tmp_path):
    """A history db with a schema_version table and nothing else."""
    path = tmp_path / "history.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE schema_version (version TEXT, applied_at INTEGER,"
        " applied_at_iso TEXT)"
    )
    conn.commit()
    conn.close()
    return path


def _run_with(monkeypatch, db, migration):
    monkeypatch.setattr(hm, "discover_migrations", lambda *a, **k: [migration])
    return hm.run_migrations(db)


def test_one_entry_when_rollback_succeeds(monkeypatch, db):
    result = _run_with(monkeypatch, db, _FailingUp())
    assert len(result["errors"]) == 1
    assert result["rollback_performed"] is True


def test_one_entry_when_rollback_also_fails(monkeypatch, db):
    """The regression. This returned 2 entries for one failed migration."""
    result = _run_with(monkeypatch, db, _FailingBoth())
    assert len(result["errors"]) == 1, (
        f"one failed migration produced {len(result['errors'])} error entries: "
        f"{result['errors']}"
    )


def test_the_two_paths_agree_on_the_count(monkeypatch, db, tmp_path):
    """States the invariant directly: the count must not depend on whether
    rollback happened to succeed."""
    ok = _run_with(monkeypatch, db, _FailingUp())

    second = tmp_path / "second.db"
    conn = sqlite3.connect(second)
    conn.execute(
        "CREATE TABLE schema_version (version TEXT, applied_at INTEGER,"
        " applied_at_iso TEXT)"
    )
    conn.commit()
    conn.close()
    bad = _run_with(monkeypatch, second, _FailingBoth())

    assert len(ok["errors"]) == len(bad["errors"])


def test_the_surviving_entry_keeps_the_rollback_detail(monkeypatch, db):
    """Deduplicating must not drop the more informative of the two entries.

    The obvious wrong fix -- delete the append inside the handler -- also passes
    every count assertion above while silently losing `rollback_error`.
    """
    result = _run_with(monkeypatch, db, _FailingBoth())
    (entry,) = result["errors"]
    assert entry["version"] == "9.9.9"
    assert entry["error"] == "up failed"
    assert entry["rollback_error"] == "down failed"


def test_rollback_error_is_absent_when_rollback_worked(monkeypatch, db):
    """The complementary control: the key is conditional, not always present
    and sometimes empty."""
    result = _run_with(monkeypatch, db, _FailingUp())
    (entry,) = result["errors"]
    assert "rollback_error" not in entry


def test_a_clean_run_reports_no_errors(monkeypatch, db):
    """Positive control -- proves these tests observe a real signal rather than
    an `errors` list that is always length 1."""

    class _Fine:
        version = "9.9.9"
        description = "no-op"

        def migrate_up(self, conn):
            return None

        def migrate_down(self, conn):
            return None

    result = _run_with(monkeypatch, db, _Fine())
    assert result["errors"] == []
    assert result["applied"] == ["9.9.9"]
