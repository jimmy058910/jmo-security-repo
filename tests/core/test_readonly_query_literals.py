"""A read-only guard must inspect SQL, not the strings inside it (#953).

`_validate_readonly_query` scanned the raw query text for forbidden keywords
with a word-boundary regex, so a legitimate `SELECT` whose *data* mentioned a
forbidden word was refused:

    SELECT * FROM findings WHERE message LIKE '%DROP%'
      -> Query rejected: Forbidden keyword: DROP

That is not hypothetical for this product. A security tool's own findings table
is full of the words its keyword scan forbids -- measured on a real 1833-scan
database, `message LIKE '%DROP%'` matches **410 findings**, all unreachable
through `query_findings_db` in that form.

The issue proposed `sqlglot` or `sqlparse`. Measured, and not needed: **the
same function already strips string literals**, one step later, for exactly this
reason -- step 3's multi-statement check runs on `re.sub(r"'[^']*'", "", clean)`
so that a semicolon inside a string does not trip it. Step 2 simply did not use
it. Replacing a working security check with a new dependency was the expensive
option; teaching it the distinction the function already draws is the cheap one.

The scan is now a single left-to-right pass that knows where literals and
comments begin and end, and every later check runs on the code-only text. That
also fixes a bug the issue did not name: comments were stripped **before**
literals, so a `--` inside a string literal was treated as a comment
(`SELECT '--x'` became `SELECT '`).

Safety is unchanged and asserted below. The connection is opened `mode=ro`
independently, so writes were impossible either way; these tests pin that the
guard still rejects every mutation shape it was written for.
"""

from __future__ import annotations

import pytest

from scripts.core.history_db import QuerySecurityError, _validate_readonly_query


def _rejects(query: str) -> bool:
    try:
        _validate_readonly_query(query)
    except QuerySecurityError:
        return True
    return False


# ---------------------------------------------------------------------------
# The bug: a keyword inside a string literal is data, not SQL.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "SELECT * FROM findings WHERE message LIKE '%DROP%'",
        "SELECT * FROM findings WHERE title LIKE '%update%'",
        "SELECT * FROM findings WHERE rule_id = 'sql-injection-create'",
        "SELECT * FROM findings WHERE message LIKE '%DELETE FROM%'",
        "SELECT * FROM findings WHERE description LIKE '%ALTER TABLE%'",
        "SELECT COUNT(*) FROM findings WHERE rule_id IN ('drop-priv', 'insert-xss')",
        # The escaped-quote form, which the naive strip must also survive.
        "SELECT * FROM findings WHERE message LIKE '%it''s a DROP%'",
        # A double-quoted identifier is an identifier, not a keyword.
        'SELECT "update" FROM findings',
    ],
)
def test_a_forbidden_word_inside_a_literal_is_allowed(query: str) -> None:
    """These are the queries a security tool's users actually write."""
    assert not _rejects(query), f"rejected a legitimate read-only query: {query}"


def test_a_comment_marker_inside_a_literal_is_not_a_comment() -> None:
    """Comments were stripped before literals, so `--` inside a string won.

    `SELECT '--x'` became `SELECT '` -- an unterminated literal that reached
    SQLite and errored there instead of being understood here.
    """
    assert not _rejects("SELECT * FROM findings WHERE message LIKE '%-- DROP%'")


# ---------------------------------------------------------------------------
# Safety: everything the guard was written to reject, it must still reject.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "DROP TABLE findings",
        "DELETE FROM findings",
        "UPDATE findings SET severity = 'LOW'",
        "INSERT INTO findings VALUES (1)",
        "CREATE TABLE evil (x INT)",
        "ALTER TABLE findings ADD COLUMN x INT",
        "ATTACH DATABASE '/tmp/evil.db' AS evil",
        "DETACH DATABASE evil",
        "REPLACE INTO findings VALUES (1)",
        "SELECT load_extension('evil.so')",
        # Real SQL after a literal: the literal is elided, the SQL is not.
        "SELECT * FROM findings WHERE a = 'x'; DROP TABLE findings",
        # A keyword after a comment must still be seen.
        "SELECT 1 /* hidden */ ; DROP TABLE findings",
    ],
)
def test_a_real_write_is_still_rejected(query: str) -> None:
    """The negative controls.

    Without these, "stop matching inside literals" could be satisfied by not
    matching at all -- turning a usability fix into a security regression.
    """
    assert _rejects(query), f"a write slipped through: {query}"


def test_an_unterminated_literal_is_rejected() -> None:
    """The one way literal-elision could hide real SQL.

    If a quote never closes, everything after it is swallowed as string
    content. That is invalid SQL anyway, so refusing it is both safe and
    honest -- and it is what makes eliding literals sound rather than a hole.
    """
    assert _rejects("SELECT * FROM findings WHERE a = 'x; DROP TABLE findings")


def test_an_unterminated_block_comment_is_rejected() -> None:
    """Same argument for `/*` with no `*/`."""
    assert _rejects("SELECT 1 /* DROP TABLE findings")


@pytest.mark.parametrize(
    "query",
    [
        "",
        "   ",
        "-- only a comment",
        "/* only a comment */",
        "EXEC sp_evil",
        "PRAGMA writable_schema = 1",
        "SELECT 1; SELECT 2",
    ],
)
def test_the_other_gates_are_intact(query: str) -> None:
    """Prefix check, empty query, multi-statement and unsafe PRAGMA."""
    assert _rejects(query), f"an existing gate stopped firing for: {query}"


@pytest.mark.parametrize(
    "query",
    [
        "SELECT COUNT(*) FROM findings",
        "EXPLAIN SELECT * FROM findings",
        "WITH t AS (SELECT 1) SELECT * FROM t",
        "PRAGMA table_info(findings)",
        "SELECT * FROM findings -- a trailing comment",
        "SELECT 1; ",
    ],
)
def test_ordinary_read_only_queries_still_pass(query: str) -> None:
    """The other negative control: the guard must not reject everything."""
    assert not _rejects(query), f"rejected a plainly read-only query: {query}"


@pytest.mark.parametrize(
    "query",
    [
        "SELECT dr'x'op FROM t",
        "SELECT up'y'date FROM t",
        "SELECT cre'x'ate FROM t",
        "SELECT DR/*x*/OP FROM t",
    ],
)
def test_eliding_a_literal_does_not_fabricate_a_keyword(query: str) -> None:
    """Elided text is replaced by a space, never deleted.

    Deleting it closes the gap between whatever sat either side, so two
    innocent fragments become a forbidden keyword and a legitimate query is
    rejected. Measured: these four are accepted when the literal is blanked and
    rejected as `Forbidden keyword: DROP` / `UPDATE` / `CREATE` when it is
    removed.

    Added because a mutation changing the blank to a deletion survived the
    whole suite -- the property held, and nothing asserted it.
    """
    assert not _rejects(query), f"elision fabricated a keyword in: {query}"


def test_a_second_statement_with_no_forbidden_word_is_still_rejected() -> None:
    """The multi-statement gate, isolated from the keyword scan.

    Every multi-statement case in `test_a_real_write_is_still_rejected` also
    contains a forbidden keyword, so the keyword scan catches them first and
    they would pass with the multi-statement gate entirely disabled. This one
    can only be caught by that gate.
    """
    assert _rejects("SELECT 1; PRAGMA writable_schema = 1")
    assert _rejects("SELECT 1; SELECT 2")
