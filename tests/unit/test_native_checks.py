"""Contracts for `jmo-native`, JMo's own check pack (`scripts/core/native_checks.py`).

Invoked as a subprocess, exactly like every other scanner::

    python -m scripts.core.native_checks --target <dir> --output <file>

The runner is engine-free Python (Decision 3,
`docs/superpowers/plans/2026-09-27-phase-4-new-tools.md`): six checks over
Next.js/Supabase/Firebase code, reproducing three archived opengrep rules,
an RLS-migration check, and a Firebase-rules check, with no rule-engine
dependency.

Every fixture text below is placeholder-only, matching
`tests/fixtures/samples/native/README.md`'s policy: nothing shaped like a real
provider key, so this file itself never becomes something a secret scanner
reacts to.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.core import native_checks
from tests.conftest import median_seconds

FIXTURE = Path(__file__).parent.parent / "fixtures" / "samples" / "native"
README = FIXTURE / "README.md"

ALL_RULE_IDS = {
    native_checks.RULE_PUBLIC_ENV,
    native_checks.RULE_SERVICE_ROLE,
    native_checks.RULE_BROWSER_LLM,
    native_checks.RULE_TABLE_NO_RLS,
    native_checks.RULE_RLS_NO_POLICY,
    native_checks.RULE_FIREBASE_OPEN,
}


def _readme_expected_triples() -> list[tuple[str, str, int]]:
    """Parse the fixture README's "Expected findings" table into
    (rule_id, uri, line) triples.

    Parsing the README rather than hand-copying its numbers into this file
    means the two cannot silently drift apart -- a wrong number in one place
    would otherwise just be re-asserted by a second wrong copy in the other.
    """
    triples: list[tuple[str, str, int]] = []
    in_table = False
    for line in README.read_text(encoding="utf-8").splitlines():
        if line.startswith("| # | Rule id"):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.startswith("|"):
            break
        if line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        rule_id = cells[1].strip("`")
        uri = cells[2].strip("`")
        lineno = int(cells[3])
        triples.append((rule_id, uri, lineno))
    return triples


def _run(target: Path, out: Path, *extra: str) -> int:
    return native_checks.main(["--target", str(target), "--output", str(out), *extra])


def _results(out: Path) -> list[dict]:
    return json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"]


def _triples(results: list[dict]) -> list[tuple[str, str, int]]:
    return sorted(
        (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in results
    )


def _plant(target: Path, rel: str, body: bytes) -> None:
    path = target / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


class TestFixtureContract:
    """The tracked fixture is the gate: 8 of 8, and the 4 negatives silent."""

    def test_readme_lists_exactly_eight(self):
        assert len(_readme_expected_triples()) == 8

    def test_fixture_produces_exactly_the_readmes_eight(self, tmp_path):
        out = tmp_path / "native.sarif"
        rc = _run(FIXTURE, out)

        assert rc == 1
        assert _triples(_results(out)) == sorted(_readme_expected_triples())

    def test_the_four_negatives_produce_nothing(self, tmp_path):
        """Assert by (rule, uri), not only by the total count -- a
        property-only test passed a wrong answer once already (PR O)."""
        out = tmp_path / "native.sarif"
        _run(FIXTURE, out)
        results = _results(out)
        uris = {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in results
        }

        # (1) the API route: server path, must not appear at all.
        assert "app/api/admin/route.ts" not in uris
        # (2) storage.rules: closed, must not appear.
        assert "storage.rules" not in uris
        # (3) supabase.ts: exactly the one positive (service-role), never two
        # -- the comment naming service_role must not add a second finding.
        supabase_hits = [
            r
            for r in results
            if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "src/lib/supabase.ts"
        ]
        assert len(supabase_hits) == 1
        assert supabase_hits[0]["ruleId"] == native_checks.RULE_SERVICE_ROLE
        # (4) profiles: RLS + a policy, so neither migration rule names it.
        assert not any(
            "profiles" in r["message"]["text"]
            for r in results
            if r["ruleId"]
            in (native_checks.RULE_TABLE_NO_RLS, native_checks.RULE_RLS_NO_POLICY)
        )

    def test_crlf_fixture_produces_the_same_findings(self, tmp_path):
        """GitHub's Windows runners check the fixture out CRLF."""
        crlf_root = tmp_path / "crlf"
        for path in sorted(FIXTURE.rglob("*")):
            if path.is_dir():
                continue
            dest = crlf_root / path.relative_to(FIXTURE)
            dest.parent.mkdir(parents=True, exist_ok=True)
            text = path.read_bytes().decode("utf-8")
            dest.write_bytes(
                text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
            )
        out = tmp_path / "native.sarif"

        rc = _run(crlf_root, out)

        assert rc == 1
        assert _triples(_results(out)) == sorted(_readme_expected_triples())


class TestCommentStripping:
    """String-aware, line-preserving comment stripping.

    The spike's `line.find("//")` truncates the idiomatic one-line
    `createClient("https://x.supabase.co", ...SERVICE_ROLE_KEY)` at the URL,
    silently losing the match the rule exists to catch.
    """

    def test_line_comment_is_blanked_but_line_count_is_kept(self):
        text = "a\n// full line comment naming service_role\nb\n"

        stripped = native_checks.strip_code_comments(text)

        assert stripped.count("\n") == text.count("\n")
        assert "service_role" not in stripped

    def test_block_comment_spans_lines_and_keeps_line_count(self):
        text = "a\n/* line one\nline two */\nb\n"

        stripped = native_checks.strip_code_comments(text)

        assert stripped.count("\n") == text.count("\n")
        assert "line one" not in stripped
        assert "line two" not in stripped

    def test_double_quoted_string_protects_a_double_slash(self):
        text = 'const u = "https://x.example.com";\n'

        stripped = native_checks.strip_code_comments(text)

        assert "https://x.example.com" in stripped

    def test_single_quoted_string_protects_a_double_slash(self):
        text = "const u = 'https://x.example.com';\n"

        stripped = native_checks.strip_code_comments(text)

        assert "https://x.example.com" in stripped

    def test_template_literal_protects_a_double_slash(self):
        text = "const u = `https://x.example.com`;\n"

        stripped = native_checks.strip_code_comments(text)

        assert "https://x.example.com" in stripped

    def test_url_on_the_same_line_is_caught_after_the_string(self, tmp_path):
        """The regression the spike's naive stripper would have missed."""
        target = tmp_path / "t"
        (target / "src" / "lib").mkdir(parents=True)
        (target / "src" / "lib" / "x.ts").write_bytes(
            b'export const admin = createClient("https://x.supabase.co", '
            b"process.env.SUPABASE_SERVICE_ROLE_KEY);\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert native_checks.RULE_SERVICE_ROLE in [r["ruleId"] for r in _results(out)]

    @pytest.mark.parametrize("newline", ["\n", "\r\n"])
    def test_an_apostrophe_in_jsx_text_does_not_keep_a_later_comment(
        self, tmp_path, newline
    ):
        """A `'` or `"` string ends at its line's end, since
        JS forbids a raw newline in one, so `Don't` in JSX text costs one line.
        It used to open a "string" that ran on to the next quote in the file,
        and a later comment naming service_role read as code."""
        target = tmp_path / "t"
        lines = [
            '"use client";',
            "export default function Page() {",
            "  return <p>Don't have an account?</p>;",
            "}",
            "// never put the service_role key here",
            "const x = 1;",
            "",
        ]
        _plant(target, "app/login/page.tsx", newline.join(lines).encode())
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    def test_the_url_then_key_line_after_an_apostrophe_is_still_caught(self, tmp_path):
        """The other half of I1: after `You're`, the idiomatic one-line
        createClient call was read as the inside of a string, and missed."""
        target = tmp_path / "t"
        _plant(
            target,
            "components/Admin.tsx",
            b"export function Admin() {\n"
            b"  return <p>You're signed in</p>;\n"
            b"}\n"
            b"const admin = createClient('https://x.supabase.co', "
            b"process.env.SUPABASE_SERVICE_ROLE_KEY);\n",
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_SERVICE_ROLE, "components/Admin.tsx", 4)
        ]

    @pytest.mark.parametrize(
        "replace",
        [b"s.replace(/'/g, '');\n", b's.replace(/"/g, "");\n'],
    )
    def test_a_regex_literal_holding_a_quote_does_not_keep_a_later_comment(
        self, tmp_path, replace
    ):
        target = tmp_path / "t"
        _plant(
            target,
            "src/b.ts",
            b"const clean = "
            + replace
            + b"// service_role is only used on the server\n"
            b"const x = 2;\n",
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    def test_a_quoted_string_ends_at_its_line_and_columns_are_kept(self):
        text = "x = <p>Don't</p>;\n// a comment\nconst b = 1;\n"

        stripped = native_checks.strip_code_comments(text)

        assert len(stripped) == len(text)
        assert stripped.split("\n") == [
            "x = <p>Don't</p>;",
            " " * 12,
            "const b = 1;",
            "",
        ]

    def test_a_template_literal_may_span_lines(self):
        text = "const t = `one\n// not a comment\n`;\n// a comment\n"

        stripped = native_checks.strip_code_comments(text)

        assert stripped.split("\n")[1] == "// not a comment"
        assert stripped.split("\n")[3] == " " * 12

    @pytest.mark.parametrize("eol", ["\n", "\r\n"], ids=["LF", "CRLF"])
    @pytest.mark.parametrize("quote", ["'", '"', "`"])
    def test_a_backslash_before_a_line_break_continues_the_string(self, quote, eol):
        """A backslash before a CRLF ended the string at the line break, so the
        next line's closing quote opened a new string and swallowed the
        comment after it: the LF and CRLF checkouts of one file differed."""
        text = f"x = {quote}a \\{eol}b{quote}; // gone{eol}y = 1;{eol}"

        stripped = native_checks.strip_code_comments(text)

        assert "gone" not in stripped
        assert stripped.startswith(f"x = {quote}a \\{eol}b{quote};")
        assert stripped.count("\n") == text.count("\n")
        assert len(stripped) == len(text)

    @pytest.mark.parametrize("eol", [b"\n", b"\r\n"], ids=["LF", "CRLF"])
    def test_lf_and_crlf_checkouts_of_one_file_give_the_same_findings(
        self, tmp_path, eol
    ):
        """The named key sits in the comment after a string continued over a
        line break, so it is not a finding; the same key in code is."""
        commented = (
            b'const u = "https://a.example/ \\' + eol + b'  b"; '
            b"// process.env.SUPABASE_SERVICE_ROLE_KEY" + eol
        )
        coded = (
            b'const u = "https://a.example/ \\' + eol + b'  b"; '
            b"const k = process.env.SUPABASE_SERVICE_ROLE_KEY;" + eol
        )
        results = {}
        for name, body in (("commented", commented), ("coded", coded)):
            target = tmp_path / name
            _plant(target, "src/a.ts", body)
            out = tmp_path / f"{name}.sarif"
            results[name] = (_run(target, out), _triples(_results(out)))

        assert results["commented"] == (0, [])
        assert results["coded"] == (
            1,
            [(native_checks.RULE_SERVICE_ROLE, "src/a.ts", 2)],
        )

    def test_commented_out_firestore_rule_is_not_caught(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        (target / "firestore.rules").write_bytes(
            b"// allow read, write: if true;\n"
            b"allow read, write: if request.auth != null;\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0

    def test_sql_line_comment_is_blanked_but_line_count_is_kept(self):
        text = "select 1;\n-- a comment naming notes\nselect 2;\n"

        stripped = native_checks.strip_sql_comments(text)

        assert stripped.count("\n") == text.count("\n")
        assert "notes" not in stripped

    def test_sql_block_comment_is_blanked_but_line_count_is_kept(self):
        text = "select 1;\n/* block\ncomment */\nselect 2;\n"

        stripped = native_checks.strip_sql_comments(text)

        assert stripped.count("\n") == text.count("\n")
        assert "block" not in stripped
        assert "comment" not in stripped

    def test_sql_literals_and_comments_are_blanked_but_line_breaks_are_kept(self):
        text = "a 'b\n c' $t$ d\n$t$ -- e\n/* f */ g\n"

        blanked = native_checks.blank_sql_literals(text)

        assert len(blanked) == len(text)
        assert [i for i, c in enumerate(blanked) if c == "\n"] == [
            i for i, c in enumerate(text) if c == "\n"
        ]
        assert blanked.split() == ["a", "g"]


class TestMigrationRules:
    """SQL findings are located at their `create table` statement,
    only public-schema tables are checked, and RLS state is the migration
    set's final state, read in filename order."""

    def _migrations(self, tmp_path: Path) -> Path:
        target = tmp_path / "t"
        (target / "supabase" / "migrations").mkdir(parents=True)
        return target

    def test_non_public_schema_table_is_skipped(self, tmp_path):
        target = self._migrations(tmp_path)
        (target / "supabase" / "migrations" / "1.sql").write_bytes(
            b"create table private.secrets (id int);\n"
            b"create table auth.users (id int);\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0

    def test_bare_policy_name_is_recognised(self, tmp_path):
        target = self._migrations(tmp_path)
        (target / "supabase" / "migrations" / "1.sql").write_bytes(
            b"create table public.things (id int);\n"
            b"alter table public.things enable row level security;\n"
            b"create policy own_row on public.things for select using (true);\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0

    def test_alter_table_if_exists_only_is_recognised(self, tmp_path):
        target = self._migrations(tmp_path)
        (target / "supabase" / "migrations" / "1.sql").write_bytes(
            b"create table public.things (id int);\n"
            b"alter table if exists only public.things enable row level security;\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        results = _results(out)
        assert [r["ruleId"] for r in results] == [native_checks.RULE_RLS_NO_POLICY]

    def test_final_state_is_read_across_two_migration_files_in_filename_order(
        self, tmp_path
    ):
        """A table secured in an EARLIER file, by a LATER file that does not
        repeat the enable/policy statements, must still read as secured: the
        final state is the whole set applied in order, not whatever the last
        file alone says. (A per-file-reset bug would forget the earlier RLS
        state as soon as it saw the second, unrelated file.)"""
        target = self._migrations(tmp_path)
        (target / "supabase" / "migrations" / "1_init.sql").write_bytes(
            b"create table public.orders (id int);\n"
            b"alter table public.orders enable row level security;\n"
            b'create policy "own" on public.orders for select using (true);\n'
        )
        (target / "supabase" / "migrations" / "2_unrelated.sql").write_bytes(
            b"create table public.notes (id int);\n"
            b"alter table public.notes enable row level security;\n"
            b'create policy "own" on public.notes for select using (true);\n'
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0

    def test_rls_disabled_by_a_later_migration_is_a_finding(self, tmp_path):
        """The "RLS was blocking me, so I turned it off"
        migration. State only accumulated, so this read as secured."""
        target = self._migrations(tmp_path)
        mig = target / "supabase" / "migrations"
        (mig / "1_init.sql").write_bytes(
            b"create table public.orders (id int);\n"
            b"alter table public.orders enable row level security;\n"
            b"create policy p on public.orders for select using (true);\n"
        )
        (mig / "2_debug.sql").write_bytes(
            b"alter table public.orders disable row level security;\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_TABLE_NO_RLS, "supabase/migrations/1_init.sql", 1)
        ]

    @pytest.mark.parametrize(
        ("created", "dropped"),
        [
            (b"create table public.todos (id int);\n", b"drop table public.todos;\n"),
            (
                b"create table public.todos (id int);\ncreate table other (id int);\n",
                b"drop table if exists other, public.todos cascade;\n",
            ),
        ],
    )
    def test_a_dropped_table_is_not_reported(self, tmp_path, created, dropped):
        target = self._migrations(tmp_path)
        mig = target / "supabase" / "migrations"
        (mig / "1_init.sql").write_bytes(created)
        (mig / "2_drop.sql").write_bytes(dropped)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    @pytest.mark.parametrize(
        "statement",
        [
            b"create function f() returns void as $$ begin\n"
            b"  execute 'drop table public.notes';\n"
            b"end $$ language plpgsql;\n",
            b"comment on table public.notes is 'drop table public.notes';\n",
            b"insert into log values ('it''s; drop table public.notes');\n",
            b"create function f() returns void as $fn$ begin\n"
            b"  drop table public.notes;\n"
            b"end $fn$ language plpgsql;\n",
            # A different tag, or `$$`, inside a tagged body does not close it.
            b"select $a$ $$ drop table public.notes $$ $a$;\n",
        ],
        ids=["dollar body", "string", "string with ''", "tagged body", "nested tag"],
    )
    def test_a_drop_table_inside_a_string_or_a_body_does_not_drop_the_table(
        self, tmp_path, statement
    ):
        """`drop table` in a function body or a string literal ran no drop at
        migration time, but popped the table from the RLS state, so a table
        without Row Level Security read as gone."""
        target = self._migrations(tmp_path)
        (target / "supabase" / "migrations" / "1.sql").write_bytes(
            b"create table public.notes (id int);\n" + statement
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_TABLE_NO_RLS, "supabase/migrations/1.sql", 1)
        ]

    @pytest.mark.parametrize(
        "before",
        [
            b"select 'a''b';\n",
            b"create function f() returns void as $$ begin null; end $$;\n",
            b"select $1, $2;\n",
            # A `--` or `/*` inside a string is not a comment, and a quote
            # inside a comment does not open a string.
            b"comment on table public.notes is 'x -- y';\n",
            b"select '/*';\n",
            b"-- it's a comment\n",
            b"/* don't */\n",
        ],
    )
    def test_a_real_drop_after_a_string_or_a_body_still_drops_the_table(
        self, tmp_path, before
    ):
        target = self._migrations(tmp_path)
        (target / "supabase" / "migrations" / "1.sql").write_bytes(
            b"create table public.notes (id int);\n"
            + before
            + b"drop table public.notes;\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    def test_dropping_the_only_policy_leaves_rls_without_policy(self, tmp_path):
        target = self._migrations(tmp_path)
        mig = target / "supabase" / "migrations"
        (mig / "1_init.sql").write_bytes(
            b"create table public.orders (id int);\n"
            b"alter table public.orders enable row level security;\n"
            b'create policy "own" on public.orders for select using (true);\n'
        )
        (mig / "2_drop.sql").write_bytes(
            b'drop policy if exists "own" on public.orders;\n'
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_RLS_NO_POLICY, "supabase/migrations/1_init.sql", 1)
        ]

    def test_another_schemas_table_does_not_stand_in_for_the_public_one(self, tmp_path):
        """Tables were keyed by bare name, so `private.orders`' RLS and policy
        hid a `public.orders` that has neither."""
        target = self._migrations(tmp_path)
        (target / "supabase" / "migrations" / "1.sql").write_bytes(
            b"create table public.orders (id int);\n"
            b"create table private.orders (id int);\n"
            b"alter table private.orders enable row level security;\n"
            b"create policy p on private.orders for select using (true);\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_TABLE_NO_RLS, "supabase/migrations/1.sql", 1)
        ]

    def test_a_table_recreated_after_a_drop_is_located_at_the_new_create(
        self, tmp_path
    ):
        """The rebuilt table starts with no RLS and no policy, whatever the
        dropped one had."""
        target = self._migrations(tmp_path)
        mig = target / "supabase" / "migrations"
        (mig / "1_init.sql").write_bytes(
            b"create table public.orders (id int);\n"
            b"alter table public.orders enable row level security;\n"
            b"create policy p on public.orders for select using (true);\n"
        )
        (mig / "2_rebuild.sql").write_bytes(
            b"\n"
            b"drop table public.orders;\n"
            b"create table public.orders (id int, total int);\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_TABLE_NO_RLS, "supabase/migrations/2_rebuild.sql", 3)
        ]

    def test_a_plain_create_of_an_existing_table_starts_a_new_one(self, tmp_path):
        """Postgres lets a plain create succeed only on a table that does not
        exist, so the table was dropped by something this reader does not
        parse (a `drop` inside a `do` block, say): read it as new."""
        target = self._migrations(tmp_path)
        mig = target / "supabase" / "migrations"
        (mig / "1_init.sql").write_bytes(
            b"create table public.orders (id int);\n"
            b"alter table public.orders enable row level security;\n"
            b"create policy p on public.orders for select using (true);\n"
        )
        (mig / "2_rebuild.sql").write_bytes(
            b"create table public.orders (id int, total int);\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_TABLE_NO_RLS, "supabase/migrations/2_rebuild.sql", 1)
        ]

    def test_create_if_not_exists_on_an_existing_table_changes_nothing(self, tmp_path):
        """Postgres skips it, so an idempotent migration that repeats the
        create must not wipe the RLS and policy the table already has."""
        target = self._migrations(tmp_path)
        mig = target / "supabase" / "migrations"
        (mig / "1_init.sql").write_bytes(
            b"create table public.orders (id int);\n"
            b"alter table public.orders enable row level security;\n"
            b"create policy p on public.orders for select using (true);\n"
        )
        (mig / "2_again.sql").write_bytes(
            b"create table if not exists public.orders (id int);\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    def test_finding_is_located_at_the_create_table_line_not_line_zero(self, tmp_path):
        target = self._migrations(tmp_path)
        (target / "supabase" / "migrations" / "1.sql").write_bytes(
            b"\n\ncreate table public.orders (id int);\n"
        )
        out = tmp_path / "o.sarif"

        _run(target, out)

        result = _results(out)[0]
        region = result["locations"][0]["physicalLocation"]["region"]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert region["startLine"] == 3
        assert uri == "supabase/migrations/1.sql"


class TestWalk:
    """Prune VENDORED_DIRS + `.next` (never `dist`/`build`),
    `--exclude-dir` at any depth, `allow_abbrev=False`."""

    def test_next_directory_is_pruned(self, tmp_path):
        target = tmp_path / "t"
        (target / ".next" / "app").mkdir(parents=True)
        (target / ".next" / "app" / "x.ts").write_bytes(
            b"dangerouslyAllowBrowser: true\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0

    def test_a_vendored_dirs_name_is_pruned(self, tmp_path):
        target = tmp_path / "t"
        (target / "node_modules" / "pkg").mkdir(parents=True)
        (target / "node_modules" / "pkg" / "x.ts").write_bytes(
            b"dangerouslyAllowBrowser: true\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0

    def test_dist_and_build_are_not_pruned(self, tmp_path):
        """The repository's stated policy (comment above VENDORED_DIRS in
        tool_descriptors.py): dist/build hold real build output a user who
        points JMo at a release tree means to scan."""
        target = tmp_path / "t"
        (target / "dist").mkdir(parents=True)
        (target / "dist" / "x.ts").write_bytes(b"dangerouslyAllowBrowser: true\n")
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1

    def test_exclude_dir_is_honoured_at_any_depth(self, tmp_path):
        target = tmp_path / "t"
        (target / "sub" / "results").mkdir(parents=True)
        (target / "sub" / "results" / "x.ts").write_bytes(
            b"dangerouslyAllowBrowser: true\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out, "--exclude-dir", "results")

        assert rc == 0

    def test_exclude_dir_repeats_and_reaches_the_walk(self, monkeypatch, tmp_path):
        seen: list[frozenset[str]] = []

        def fake_iter(target, exclude_dirs=frozenset()):
            seen.append(exclude_dirs)
            return []

        monkeypatch.setattr(native_checks, "iter_target_files", fake_iter)
        target = tmp_path / "t"
        target.mkdir()
        out = tmp_path / "o.sarif"

        _run(target, out, "--exclude-dir", "a", "--exclude-dir", "b")

        assert seen == [frozenset({"a", "b"})]

    def test_output_flag_abbreviation_is_rejected(self, tmp_path):
        """`--out` must not silently reach `--output` (allow_abbrev=False)."""
        target = tmp_path / "t"
        target.mkdir()

        with pytest.raises(SystemExit):
            native_checks.main(
                ["--target", str(target), "--out", str(tmp_path / "o.sarif")]
            )


class TestExitCodes:
    def test_clean_scan_exits_0_and_writes_a_valid_empty_sarif(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        (target / "clean.ts").write_bytes(b"export const x = 1;\n")
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0
        sarif = json.loads(out.read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"] == []

    def test_findings_exit_1(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        (target / "x.ts").write_bytes(b"dangerouslyAllowBrowser: true\n")
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1

    def test_missing_target_is_an_error(self, tmp_path):
        out = tmp_path / "o.sarif"

        rc = _run(tmp_path / "does-not-exist", out)

        assert rc == 2

    def test_target_that_is_a_file_is_an_error(self, tmp_path):
        target = tmp_path / "a-file"
        target.write_bytes(b"not a directory")
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 2

    def test_unwritable_output_is_an_error(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        blocker = tmp_path / "blocker"
        blocker.write_bytes(b"a file, not a directory")
        out = blocker / "o.sarif"  # its parent is a FILE

        rc = _run(target, out)

        assert rc == 2

    def test_an_unexpected_exception_exits_2_and_says_why(
        self, tmp_path, monkeypatch, capsys
    ):
        """An uncaught exception exited 1, which the row accepts as
        "findings". 2 is "did not scan"."""

        def crash(path, root):
            raise RuntimeError("planted failure")

        monkeypatch.setattr(native_checks, "scan_file", crash)
        target = tmp_path / "t"
        _plant(target, "x.ts", b"export const x = 1;\n")
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 2
        assert not out.exists()
        err = capsys.readouterr().err
        assert "RuntimeError: planted failure" in err
        assert "Traceback" in err

    def test_a_stale_output_is_gone_after_a_crashed_run(self, tmp_path, monkeypatch):
        """Else a crash on a re-used results directory reads as the previous
        scan's findings."""

        def crash(root):
            raise PermissionError("planted failure")

        monkeypatch.setattr(native_checks, "scan_migrations", crash)
        target = tmp_path / "t"
        target.mkdir()
        out = tmp_path / "o.sarif"
        out.write_bytes(b'{"stale": true}')

        rc = _run(target, out)

        assert rc == 2
        assert not out.exists()


class TestEnvCommentSkip:
    def test_a_commented_out_env_line_is_not_a_finding(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        (target / ".env.example").write_bytes(
            b"# NEXT_PUBLIC_STRIPE_SECRET_KEY=placeholder\n"
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0


class TestPublicEnvName:
    """Next.js, Vite, CRA and Expo inline only the
    exact upper-case prefixes, and a `.env` line's value is never read."""

    def test_a_prefix_inside_a_longer_name_is_not_a_finding(self, tmp_path):
        """`INVITE_SECRET` was reported as `VITE_SECRET`."""
        target = tmp_path / "t"
        _plant(target, ".env", b"INVITE_SECRET=x\nINVITE_ACCESS_TOKEN_TTL=3600\n")
        _plant(
            target,
            "lib/invites.ts",
            b"export const s = process.env.INVITE_SECRET;\n",
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    def test_a_lower_case_prefix_is_not_a_finding(self, tmp_path):
        target = tmp_path / "t"
        _plant(target, ".env", b"next_public_secret=x\n")
        _plant(target, "lib/invites.ts", b"const vite_private_link = true;\n")
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    def test_no_part_of_a_value_is_read_or_reaches_the_output(self, tmp_path):
        """A value holding a public-prefixed, secret-looking token put that
        token, and whatever followed it, into the finding's message."""
        target = tmp_path / "t"
        _plant(
            target,
            ".env.local",
            b"CALLBACK_URL=https://app.example.com/join/NEXT_PUBLIC_X_SECRET_SENTINEL\n",
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))
        assert "SENTINEL" not in out.read_text(encoding="utf-8")

    def test_an_exported_name_is_still_read(self, tmp_path):
        target = tmp_path / "t"
        _plant(target, ".env", b"export NEXT_PUBLIC_X_SECRET=placeholder\n")
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        [result] = _results(out)
        assert result["message"]["text"].startswith("NEXT_PUBLIC_X_SECRET is ")
        assert result["locations"][0]["physicalLocation"]["region"] == {
            "startLine": 1,
            "startColumn": 8,
        }

    @pytest.mark.parametrize(
        ("line", "column"),
        [
            (b"NEXT_PUBLIC_STRIPE_SECRET_KEY: placeholder", 1),
            (b"NEXT_PUBLIC_STRIPE_SECRET_KEY : placeholder", 1),
            (b"export NEXT_PUBLIC_STRIPE_SECRET_KEY: placeholder", 8),
            # `=` first: the name ends there whatever the value holds.
            (b"NEXT_PUBLIC_STRIPE_SECRET_KEY=a:b", 1),
            # `:` first: the `=` belongs to the value.
            (b"NEXT_PUBLIC_STRIPE_SECRET_KEY: a=b", 1),
        ],
    )
    def test_either_separator_ends_the_name(self, tmp_path, line, column):
        """dotenv's `KEY: value` form was not read: only the text left of the
        first `=` was examined, and that line has none."""
        target = tmp_path / "t"
        _plant(target, ".env", b"# a comment\n" + line + b"\n")
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        [result] = _results(out)
        assert result["locations"][0]["physicalLocation"]["region"] == {
            "startLine": 2,
            "startColumn": column,
        }

    @pytest.mark.parametrize(
        "line",
        [
            # The secret-looking text is the value, behind either separator.
            b"CALLBACK_URL: https://app.example.com/NEXT_PUBLIC_X_SECRET_SENTINEL",
            b"CALLBACK_URL=NEXT_PUBLIC_X_SECRET_SENTINEL: x",
            b"NEXT_PUBLIC_X_SECRET_SENTINEL",
        ],
    )
    def test_a_value_is_never_read_behind_either_separator(self, tmp_path, line):
        target = tmp_path / "t"
        _plant(target, ".env", line + b"\n")
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))
        assert "SENTINEL" not in out.read_text(encoding="utf-8")


_SERVICE_ROLE_LINE = (
    b"const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);\n"
)


class TestServerModules:
    """Four markers Next.js itself enforces make a
    module under a client directory server code, so none can hide a real
    client reference."""

    @pytest.mark.parametrize(
        ("rel", "head"),
        [
            ("lib/supabase/admin.ts", b'import "server-only";\n'),
            ("lib/supabase/admin.js", b"import 'server-only';\n"),
            ("app/auth/callback/route.ts", b""),
            ("src/app/webhooks/route.js", b""),
            ("app/actions.ts", b'"use server";\n'),
            ("src/lib/save.ts", b"// Server actions.\n\n'use server'\n"),
            ("src/lib/bom.ts", b'\xef\xbb\xbf"use server";\n'),
            ("src/middleware.ts", b""),
            # Next.js 16 renamed `middleware` to `proxy`.
            ("src/proxy.ts", b""),
            ("src/proxy.js", b""),
            # An import on a later line, and on the first behind a BOM.
            ("lib/a.ts", b'import x from "y";\nimport "server-only";\n'),
            ("lib/bom.ts", b'\xef\xbb\xbfimport "server-only";\n'),
            # A real import still counts after a template literal holding the text.
            (
                "lib/a.ts",
                b'const d = `\nimport "server-only"\n`;\nimport "server-only";\n',
            ),
            # Route groups and an underscore inside a name are still routes.
            ("app/(shop)/checkout/route.ts", b""),
            ("src/app/route_x/route.ts", b""),
        ],
    )
    def test_a_server_module_under_a_client_directory_is_not_client_code(
        self, tmp_path, rel, head
    ):
        target = tmp_path / "t"
        _plant(target, rel, head + _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    def test_many_template_literal_decoys_are_scanned_in_linear_time(self, tmp_path):
        """Crafted input: each `import "server-only"` text was checked against
        every string in the file, so 20,000 decoys (720 KB) took 6 s and twice
        that many, four times as long. The bound is generous (linear is well
        under a second), on the median of three scans: a rescan of a fixed
        file is repeatable, and one descheduled run cannot trip it."""
        decoy = b'const d = `\nimport "server-only"\n`;\n'
        target = tmp_path / "t"
        _plant(target, "lib/a.ts", decoy * 30_000 + _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rcs: list[int] = []
        elapsed = median_seconds(lambda: rcs.append(_run(target, out)), samples=3)

        assert rcs == [1] * 3
        assert _triples(_results(out)) == [
            (native_checks.RULE_SERVICE_ROLE, "lib/a.ts", 30_000 * 3 + 1)
        ]
        assert elapsed < 5, f"{elapsed:.1f} s for 30,000 decoys"

    @pytest.mark.parametrize(
        ("rel", "head"),
        [
            ("lib/admin.ts", b""),
            ("lib/admin.ts", b'// import "server-only";\n'),
            ("lib/admin.ts", b'import x from "y";\n"use server";\n'),
            ("lib/route.ts", b""),
            ("src/lib/middleware.ts", b""),
            ("src/lib/proxy.ts", b""),
            ("app/proxy.ts", b""),
            # `import "server-only"` held in a string is not an import.
            ("lib/a.ts", b"const msg = 'import \"server-only\"';\n"),
            ("lib/a.ts", b"const msg = \"import 'server-only'\";\n"),
            # ...and in a template literal, whose lines may start `import`.
            ("lib/a.ts", b'const docs = `\nimport "server-only"\n`;\n'),
            ("lib/a.ts", b"const docs = `\nimport 'server-only';\n`;\n"),
            ("lib/a.ts", b'const a = `x ${y}\nimport "server-only"\n`;\n'),
            # ...and in a string continued over a line end with a backslash.
            ("lib/a.ts", b"const s = \"x\\\nimport 'server-only'\";\n"),
            # Next.js private folders: `route.*` below one is not a route.
            ("src/app/_private/route.ts", b""),
            ("app/_lib/route.ts", b""),
            ("app/shop/_internal/deep/route.js", b""),
        ],
    )
    def test_the_same_reference_elsewhere_is_still_client_code(
        self, tmp_path, rel, head
    ):
        """The negative controls: a plain module, and each marker in a shape
        Next.js does not honour (commented out, not the first statement, a
        `route` outside `app/`, a `middleware` below the root or `src/`)."""
        target = tmp_path / "t"
        _plant(target, rel, head + _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        line = head.count(b"\n") + 1
        assert _triples(_results(out)) == [(native_checks.RULE_SERVICE_ROLE, rel, line)]


_BACKEND = b'{"dependencies": {"express": "4"}}'


_SERVER_FRAMEWORKS = [
    "express",
    "fastify",
    "hono",
    "koa",
    "@nestjs/core",
    "@hapi/hapi",
    "restify",
]
_BROWSER_FRAMEWORKS = [
    "next",
    "vite",
    "react-scripts",
    "expo",
    "react",
    "react-dom",
    "vue",
    "@vue/cli-service",
    "nuxt",
    "svelte",
    "@sveltejs/kit",
    "@angular/core",
    "gatsby",
    "astro",
    "@remix-run/react",
    "solid-js",
    "preact",
    "parcel",
    "webpack",
    "esbuild",
    "rollup",
    "browserify",
    "@rspack/core",
    "@rsbuild/core",
    "lit",
]


def _package(**sections: object) -> bytes:
    return json.dumps(sections).encode()


class TestSrcOfABackendOnlyRepository:
    """`src/` is client code unless the root `package.json` names a server
    framework (Express, Fastify, Hono, ...) and no browser framework (Next.js,
    React, Angular, ...): only positive evidence of a backend makes it an
    Express or Hono service's server code."""

    @pytest.mark.parametrize("section", ["dependencies", "devDependencies"])
    @pytest.mark.parametrize("framework", _SERVER_FRAMEWORKS)
    def test_a_server_framework_alone_makes_src_server_code(
        self, tmp_path, section, framework
    ):
        target = tmp_path / "t"
        _plant(target, "package.json", _package(**{section: {framework: "1"}}))
        _plant(target, "src/index.ts", _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    @pytest.mark.parametrize(
        "package",
        [
            b"\xef\xbb\xbf" + _BACKEND,
            _package(dependencies={"express": "4", "typescript": "5"}),
            _package(
                dependencies={"express": "4"}, devDependencies={"@types/node": "22"}
            ),
            # Only `dependencies` and `devDependencies` count, and only as objects.
            _package(dependencies={"express": "4"}, peerDependencies={"next": "16"}),
            _package(dependencies={"express": "4"}, devDependencies=["react"]),
        ],
        ids=[
            "BOM",
            "typescript beside",
            "types beside",
            "peer ignored",
            "list ignored",
        ],
    )
    def test_src_is_server_code(self, tmp_path, package):
        target = tmp_path / "t"
        _plant(target, "package.json", package)
        _plant(target, "src/index.ts", _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    @pytest.mark.parametrize("section", ["dependencies", "devDependencies"])
    @pytest.mark.parametrize("framework", _BROWSER_FRAMEWORKS)
    def test_a_browser_framework_keeps_src_client_code(
        self, tmp_path, section, framework
    ):
        target = tmp_path / "t"
        sections: dict[str, dict[str, str]] = {"dependencies": {"express": "4"}}
        sections.setdefault(section, {})[framework] = "1"
        _plant(target, "package.json", _package(**sections))
        _plant(target, "src/index.ts", _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_SERVICE_ROLE, "src/index.ts", 1)
        ]

    @pytest.mark.parametrize(
        "package",
        [
            # No server framework named: an Angular, Gatsby, React or webpack
            # app, or nothing at all, ships `src/` to the browser.
            _package(name="svc"),
            _package(devDependencies={"typescript": "5"}),
            _package(dependencies={"@angular/core": "19"}),
            _package(dependencies={"gatsby": "5"}),
            _package(dependencies={"react": "19"}),
            _package(devDependencies={"webpack": "5"}),
            _package(peerDependencies={"next": "16"}),
            # A backend on a framework the list does not know keeps `src/` client.
            _package(dependencies={"sails": "1"}),
            # A list where an object belongs names nothing.
            _package(dependencies=["next"]),
            _package(dependencies=["express"]),
        ],
        ids=[
            "names nothing",
            "typescript only",
            "angular",
            "gatsby",
            "react",
            "webpack",
            "peer only",
            "unlisted server framework",
            "list of next",
            "list of express",
        ],
    )
    def test_without_a_server_framework_src_is_client_code(self, tmp_path, package):
        target = tmp_path / "t"
        _plant(target, "package.json", package)
        _plant(target, "src/index.ts", _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_SERVICE_ROLE, "src/index.ts", 1)
        ]

    @pytest.mark.parametrize(
        "package",
        [None, b"{", b"[]", b'"next"', b"\xff\xfe\x00"],
        ids=["absent", "truncated", "a list", "a string", "not text"],
    )
    def test_without_a_usable_root_package_json_src_is_client_code(
        self, tmp_path, package
    ):
        target = tmp_path / "t"
        if package is not None:
            _plant(target, "package.json", package)
        _plant(target, "src/index.ts", _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_SERVICE_ROLE, "src/index.ts", 1)
        ]

    def test_a_package_json_that_is_a_directory_is_no_package_json(self, tmp_path):
        target = tmp_path / "t"
        _plant(target, "package.json/x", b"")
        _plant(target, "src/index.ts", _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1

    @pytest.mark.parametrize(
        "package",
        [
            # Express beside code bundled by esbuild, or by rollup around lit.
            _package(dependencies={"express": "4"}, devDependencies={"esbuild": "0"}),
            _package(
                dependencies={"express": "4", "lit": "3"},
                devDependencies={"rollup": "4"},
            ),
            # Express alone, serving static scripts.
            _BACKEND,
        ],
        ids=["esbuild", "lit and rollup", "express only"],
    )
    @pytest.mark.parametrize(
        "rel",
        ["src/client/main.ts", "src/client/ui/app.js", "src/public/app.js"],
    )
    def test_the_browser_folders_of_src_stay_client_code(self, tmp_path, package, rel):
        """A backend repository's `src/client/` and `src/public/` hold browser
        code: the service-role key there is a leak whatever the root
        `package.json` lists."""
        target = tmp_path / "t"
        _plant(target, "package.json", package)
        _plant(target, rel, _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [(native_checks.RULE_SERVICE_ROLE, rel, 1)]

    @pytest.mark.parametrize(
        "rel",
        [
            "src/index.ts",
            "src/routes/users.ts",
            # `src/client` is a folder name, not a prefix of one.
            "src/clientele/x.ts",
            "src/public_api/x.ts",
            "src/publicity.ts",
            # Another folder's `client/` is not `src/client/`, and a root
            # `client/` sits in no client directory at all.
            "src/lib/client/x.ts",
            "client/x.ts",
            # A server marker below `src/client/` still wins.
            "src/client/api/x.ts",
        ],
    )
    def test_the_rest_of_a_backends_src_is_still_server_code(self, tmp_path, rel):
        target = tmp_path / "t"
        _plant(target, "package.json", _BACKEND)
        _plant(target, rel, _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    @pytest.mark.parametrize(
        "rel", ["app/a.ts", "lib/a.ts", "components/a.ts", "pages/a.ts"]
    )
    def test_only_src_changes(self, tmp_path, rel):
        target = tmp_path / "t"
        _plant(target, "package.json", _BACKEND)
        _plant(target, rel, _SERVICE_ROLE_LINE)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [(native_checks.RULE_SERVICE_ROLE, rel, 1)]

    def test_only_the_root_package_json_decides(self, tmp_path):
        """A nested app's `package.json` changes nothing (#1381 tracks
        monorepos): a backend-only one under a root without a `package.json`
        leaves `src/` client code, and a Next.js one under a backend-only
        root does not make it so."""
        without_root = tmp_path / "a"
        _plant(without_root, "apps/api/package.json", _BACKEND)
        _plant(without_root, "src/index.ts", _SERVICE_ROLE_LINE)
        backend_root = tmp_path / "b"
        _plant(backend_root, "package.json", _BACKEND)
        _plant(backend_root, "apps/web/package.json", b'{"dependencies":{"next":"16"}}')
        _plant(backend_root, "src/index.ts", _SERVICE_ROLE_LINE)

        assert _run(without_root, tmp_path / "a.sarif") == 1
        assert _run(backend_root, tmp_path / "b.sarif") == 0

    def test_the_other_checks_still_read_a_backend_only_src(self, tmp_path):
        target = tmp_path / "t"
        _plant(target, "package.json", _BACKEND)
        _plant(
            target,
            "src/llm.ts",
            b"const c = new OpenAI({ dangerouslyAllowBrowser: true });\n",
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_BROWSER_LLM, "src/llm.ts", 1)
        ]

    def test_each_run_reads_the_package_json_afresh(self, tmp_path):
        target = tmp_path / "t"
        _plant(target, "package.json", _BACKEND)
        _plant(target, "src/index.ts", _SERVICE_ROLE_LINE)

        before = _run(target, tmp_path / "before.sarif")
        _plant(target, "package.json", b'{"dependencies": {"next": "16"}}')
        after = _run(target, tmp_path / "after.sarif")

        assert (before, after) == (0, 1)


class TestLineNumbers:
    def test_only_a_newline_ends_a_line(self, tmp_path):
        """`str.splitlines()` also splits on a form feed and
        on U+2028, so a finding after one was reported lines late. Editors,
        SARIF viewers and this runner's SQL path count newlines only."""
        target = tmp_path / "t"
        _plant(
            target,
            "src/a.ts",
            b"const a = 1;\x0c\n"
            b"const s = '\xe2\x80\xa8';\n"
            b"const c = new OpenAI({ dangerouslyAllowBrowser: true });\n",
        )
        out = tmp_path / "o.sarif"

        _run(target, out)

        assert _triples(_results(out)) == [
            (native_checks.RULE_BROWSER_LLM, "src/a.ts", 3)
        ]


def _firestore(rule: bytes) -> bytes:
    return (
        b"rules_version = '2';\n"
        b"service cloud.firestore {\n"
        b"  match /databases/{database}/documents {\n"
        b"    match /x/{id} {\n"
        b"      " + rule + b"\n"
        b"    }\n"
        b"  }\n"
        b"}\n"
    )


class TestFirebaseRules:
    """Every Firestore/Storage verb, the `;` optional."""

    @pytest.mark.parametrize(
        "rule",
        [
            b"allow create: if true;",
            b"allow get, list: if true",
            b"allow update, delete: if true }",
        ],
    )
    def test_any_verb_granted_unconditionally_is_a_finding(self, tmp_path, rule):
        target = tmp_path / "t"
        _plant(target, "firestore.rules", _firestore(rule))
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_FIREBASE_OPEN, "firestore.rules", 5)
        ]

    @pytest.mark.parametrize(
        "rule",
        [
            b"allow read: if request.auth != null;",
            b"allow read: if true && request.auth != null;",
        ],
    )
    def test_a_conditional_rule_is_not_a_finding(self, tmp_path, rule):
        target = tmp_path / "t"
        _plant(target, "firestore.rules", _firestore(rule))
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    @pytest.mark.parametrize(
        "rule",
        [
            # No condition: unconditional.
            b"allow read;",
            b"allow read, write;",
            b"allow get , list ;",
            b"allow create }",
            # The condition is `if true` however it is laid out.
            b"allow read: if true }",
            b"allow read:\n      if true;",
            b"allow read: if\n      true\n      ;",
            b"allow read: if true /* why */;",
        ],
    )
    @pytest.mark.parametrize("eol", [b"\n", b"\r\n"], ids=["LF", "CRLF"])
    def test_a_statement_is_judged_whole_and_found_at_its_allow(
        self, tmp_path, rule, eol
    ):
        """A rule is one statement, `allow` to its `;`, which may span lines:
        a bare `allow read;` is unconditional, and the finding sits at the
        `allow`, not at a later line of the statement."""
        target = tmp_path / "t"
        _plant(target, "firestore.rules", _firestore(rule).replace(b"\n", eol))
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        [result] = _results(out)
        assert result["ruleId"] == native_checks.RULE_FIREBASE_OPEN
        assert result["locations"][0]["physicalLocation"]["region"] == {
            "startLine": 5,
            "startColumn": 7,
        }

    @pytest.mark.parametrize(
        "rule",
        [
            # The condition continues on the next line.
            b"allow read: if true\n        && request.auth != null;",
            b"allow read: if true &&\n        request.auth != null;",
            b"allow read, write: if true // for now\n        && request.auth != null;",
            # Not `if true`, whatever else it holds.
            b"allow read: if false;",
            b"allow read: if request.auth != null && true;",
            b"allow read: if trueish;",
            # Not the keyword, a verb or a whole statement.
            b"disallow read;",
            b"allow readwrite;",
            b"allow reads;",
            b"// allow read;",
            b"/* allow read, write: if true; */",
        ],
    )
    @pytest.mark.parametrize("eol", [b"\n", b"\r\n"], ids=["LF", "CRLF"])
    def test_a_statement_that_is_not_unconditional_is_not_a_finding(
        self, tmp_path, rule, eol
    ):
        """`if true` followed on the next line by `&& request.auth != null`
        was read as open, because each line was matched alone."""
        target = tmp_path / "t"
        _plant(target, "firestore.rules", _firestore(rule).replace(b"\n", eol))
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    def test_a_statement_closed_by_its_block_brace_is_still_judged(self, tmp_path):
        target = tmp_path / "t"
        _plant(
            target,
            "firestore.rules",
            b"service cloud.firestore {\n"
            b"  match /databases/{d}/documents {\n"
            b"    match /a/{x} { allow read: if true }\n"
            b"    match /b/{x} { allow read: if request.auth != null }\n"
            b"    match /c/{x} { allow write }\n"
            b"  }\n"
            b"}\n",
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_FIREBASE_OPEN, "firestore.rules", 3),
            (native_checks.RULE_FIREBASE_OPEN, "firestore.rules", 5),
        ]

    @pytest.mark.parametrize(
        "run", [b"\n", b"\r\n", b" \n"], ids=["LF", "CRLF", "SP-LF"]
    )
    def test_a_long_run_of_blank_lines_is_scanned_in_linear_time(self, tmp_path, run):
        """Crafted input: each newline's look-ahead for the next statement
        rescanned the whole whitespace run after it, so 50,000 blank lines
        took 16 s and a megabyte, minutes. The bound is generous (linear is
        well under a tenth of a second) so a slow runner cannot trip it, on the
        median of three scans of the fixed file (one descheduled run cannot)."""
        target = tmp_path / "t"
        _plant(target, "firestore.rules", b"allow read: if true" + run * 40_000)
        out = tmp_path / "o.sarif"

        rcs: list[int] = []
        elapsed = median_seconds(lambda: rcs.append(_run(target, out)), samples=3)

        assert rcs == [1] * 3
        assert _triples(_results(out)) == [
            (native_checks.RULE_FIREBASE_OPEN, "firestore.rules", 1)
        ]
        assert elapsed < 5, f"{elapsed:.1f} s for 40,000 blank lines"

    @pytest.mark.parametrize(
        ("rule", "findings"),
        [
            # A statement with no `;` ends where the next line starts another.
            (b"allow read: if true\n      allow write: if request.auth != null", [5]),
            (b"allow read: if true\n\n      // why\n      allow write: if false", [5]),
            (b"allow read\n      allow write: if request.auth != null", [5]),
            (b"allow read: if true\n      allow write: if true", [5, 6]),
            (b"allow read: if request.auth != null\n      allow write: if true", [6]),
            (b"allow read: if true\n      function ok() { return true; }", [5]),
            (
                b"allow read: if true\n      match /y/{id} { allow write: if false }",
                [5],
            ),
            # The line after `if true` may still continue it.
            (b"allow read: if true\n      allow write: if true\n      && false", [5]),
        ],
        ids=[
            "allow after",
            "comment between",
            "bare allow",
            "both open",
            "second open",
            "function after",
            "match after",
            "continued last",
        ],
    )
    @pytest.mark.parametrize("eol", [b"\n", b"\r\n"], ids=["LF", "CRLF"])
    def test_a_statement_without_a_semicolon_does_not_swallow_the_next(
        self, tmp_path, rule, findings, eol
    ):
        """`allow read: if true` then `allow write: if request.auth != null`
        read as one statement whose condition was not `if true`, so the open
        read went unreported."""
        target = tmp_path / "t"
        _plant(target, "firestore.rules", _firestore(rule).replace(b"\n", eol))
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_FIREBASE_OPEN, "firestore.rules", line)
            for line in findings
        ]

    @pytest.mark.parametrize("eol", [b"\n", b"\r\n"], ids=["LF", "CRLF"])
    def test_storage_rules_with_a_function_after_an_open_read(self, tmp_path, eol):
        target = tmp_path / "t"
        _plant(
            target,
            "storage.rules",
            (
                b"rules_version = '2';\n"
                b"service firebase.storage {\n"
                b"  match /b/{bucket}/o {\n"
                b"    allow read: if true\n"
                b"    function signedIn() { return request.auth != null; }\n"
                b"    allow write: if signedIn();\n"
                b"  }\n"
                b"}\n"
            ).replace(b"\n", eol),
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_FIREBASE_OPEN, "storage.rules", 4)
        ]

    def test_each_statement_is_judged_alone(self, tmp_path):
        rules = (
            b"allow read: if true;\n"
            b"      allow write: if request.auth != null;\n"
            b"      allow create;\n"
            b"      allow delete: if request.auth != null; allow update;"
        )
        target = tmp_path / "t"
        _plant(target, "firestore.rules", _firestore(rules))
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_FIREBASE_OPEN, "firestore.rules", line)
            for line in (5, 7, 8)
        ]
        last = _results(out)[-1]["locations"][0]["physicalLocation"]["region"]
        assert (
            last["startColumn"]
            == len(b"      allow delete: if request.auth != null; ") + 1
        )

    def test_a_file_named_database_rules_is_not_read(self, tmp_path):
        """Realtime Database rules are JSON, in `database.rules.json`
        (`TestRealtimeDatabaseRules`); no Firebase file is named
        `database.rules`."""
        target = tmp_path / "t"
        _plant(target, "database.rules", b"allow read, write: if true;\n")
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))


_RTDB_PRETTY = (
    b"{\n"
    b'  "rules": {\n'
    b'    ".read": true,\n'
    b'    "public": { ".write": "true" },\n'
    b'    "private": {\n'
    b'      ".read": "auth != null",\n'
    b'      ".write": false\n'
    b"    },\n"
    b'    "list": [{ ".read": true }]\n'
    b"  }\n"
    b"}\n"
)


class TestRealtimeDatabaseRules:
    """`database.rules.json` is JSON, not the rules language: a `.read` or
    `.write` key of `true` (or `"true"`), at any depth, is open."""

    @pytest.mark.parametrize("eol", [b"\n", b"\r\n"], ids=["LF", "CRLF"])
    def test_a_true_read_or_write_is_a_finding_at_its_own_line(self, tmp_path, eol):
        target = tmp_path / "t"
        _plant(target, "database.rules.json", _RTDB_PRETTY.replace(b"\n", eol))
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_FIREBASE_OPEN, "database.rules.json", line)
            for line in (3, 4, 9)
        ]
        first = _results(out)[0]
        assert first["locations"][0]["physicalLocation"]["region"] == {
            "startLine": 3,
            "startColumn": 5,
        }
        assert '".read": true' in first["message"]["text"]

    def test_a_nested_file_is_read_by_its_name(self, tmp_path):
        target = tmp_path / "t"
        _plant(target, "firebase/database.rules.json", b'{"rules": {".read": true}}')
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_FIREBASE_OPEN, "firebase/database.rules.json", 1)
        ]

    @pytest.mark.parametrize(
        "rules",
        [
            b'{"rules": {".read": false, ".write": false}}',
            b'{"rules": {".read": "auth != null"}}',
            b'{"rules": {".write": "true && auth != null"}}',
            b'{"rules": {".read": "false", ".write": null}}',
            b'{"rules": {".read": 1}}',
            # Other keys, and the word `true` anywhere else.
            b'{"rules": {".validate": true, ".indexOn": "true", "read": true}}',
            b'{"rules": {"x": ".read", "y": true}}',
            # The key's text inside a string, or inside a longer key.
            b'{"note": "see \\".read\\": true"}',
            b'{"x\\".read": true}',
            b"{}",
            b"[]",
        ],
    )
    def test_anything_else_is_not_a_finding(self, tmp_path, rules):
        target = tmp_path / "t"
        _plant(target, "database.rules.json", rules)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    @pytest.mark.parametrize(
        "rules",
        [
            b'{"rules": {".read": true,}}',
            b'{"rules": {".read": true}',
            b"",
            b"allow read, write: if true;\n",
            b"[" * 100000,
        ],
        ids=["trailing comma", "truncated", "empty", "not JSON", "deeply nested"],
    )
    def test_unparseable_json_is_no_finding_and_no_crash(self, tmp_path, rules):
        target = tmp_path / "t"
        _plant(target, "database.rules.json", rules)
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))

    def test_a_byte_order_mark_does_not_hide_the_file(self, tmp_path):
        target = tmp_path / "t"
        _plant(target, "database.rules.json", b'\xef\xbb\xbf{"rules": {".read": true}}')
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1

    def test_a_comment_is_not_part_of_the_rules(self, tmp_path):
        """Firebase's tooling accepts `//` and `/* */` in this file; a
        commented-out key grants nothing."""
        target = tmp_path / "t"
        _plant(
            target,
            "database.rules.json",
            b"{\n"
            b'  "rules": {\n'
            b'    // ".read": true,\n'
            b'    /* ".write": true, */\n'
            b'    ".read": "auth != null",\n'
            b'    ".write": true // open\n'
            b"  }\n"
            b"}\n",
        )
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        assert _triples(_results(out)) == [
            (native_checks.RULE_FIREBASE_OPEN, "database.rules.json", 6)
        ]

    def test_the_rules_language_files_are_not_read_as_json(self, tmp_path):
        target = tmp_path / "t"
        _plant(target, "firestore.rules", b'{"rules": {".read": true}}\n')
        _plant(target, "storage.rules", b'{"rules": {".write": "true"}}\n')
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 0, _triples(_results(out))


class TestVersionFlag:
    def test_version_flag_prints_the_jmo_version_and_exits_0(self, capsys):
        with pytest.raises(SystemExit) as exc:
            native_checks.main(["--version"])

        assert exc.value.code == 0
        assert native_checks.JMO_VERSION in capsys.readouterr().out


class TestNoSecretLeak:
    def test_no_secret_value_reaches_the_output(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        (target / ".env.example").write_bytes(b"NEXT_PUBLIC_X_SECRET=sentinel-value\n")
        out = tmp_path / "o.sarif"

        rc = _run(target, out)

        assert rc == 1
        raw = out.read_text(encoding="utf-8")
        assert "sentinel-value" not in raw


class TestSarifShape:
    def test_rules_array_declares_all_six_with_required_fields(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        out = tmp_path / "o.sarif"

        _run(target, out)

        driver = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["tool"][
            "driver"
        ]
        assert driver["name"] == "jmo-native"
        assert driver["version"] == native_checks.JMO_VERSION
        assert {r["id"] for r in driver["rules"]} == ALL_RULE_IDS
        for rule in driver["rules"]:
            assert rule["shortDescription"]["text"], rule["id"]
            assert rule["fullDescription"]["text"], rule["id"]
            assert rule["help"]["text"], rule["id"]
            assert any(
                k == "severity" or k.endswith("/severity") for k in rule["properties"]
            ), rule["id"]

    def test_severity_and_cwe_match_the_brief_exactly(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        out = tmp_path / "o.sarif"

        _run(target, out)

        rules = {
            r["id"]: r["properties"]
            for r in json.loads(out.read_text(encoding="utf-8"))["runs"][0]["tool"][
                "driver"
            ]["rules"]
        }
        expected = {
            native_checks.RULE_PUBLIC_ENV: ("HIGH", "CWE-540"),
            native_checks.RULE_SERVICE_ROLE: ("HIGH", "CWE-284"),
            native_checks.RULE_BROWSER_LLM: ("HIGH", "CWE-798"),
            native_checks.RULE_TABLE_NO_RLS: ("HIGH", "CWE-862"),
            native_checks.RULE_RLS_NO_POLICY: ("LOW", None),
            native_checks.RULE_FIREBASE_OPEN: ("HIGH", "CWE-862"),
        }
        for rule_id, (severity, cwe) in expected.items():
            props = rules[rule_id]
            sev_value = next(
                v
                for k, v in props.items()
                if k == "severity" or k.endswith("/severity")
            )
            assert sev_value == severity, rule_id
            if cwe is None:
                assert "cwe" not in props, rule_id
            else:
                assert props.get("cwe") == cwe, rule_id

    def test_results_are_sorted_by_uri_then_line_then_rule_id(self, tmp_path):
        rc_out = tmp_path / "o.sarif"
        _run(FIXTURE, rc_out)

        triples = [
            (
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                r["locations"][0]["physicalLocation"]["region"]["startLine"],
                r["ruleId"],
            )
            for r in _results(rc_out)
        ]

        assert triples == sorted(triples)
