"""Contracts for `jmo-native`, JMo's own check pack (`scripts/core/native_checks.py`).

Invoked as a subprocess, exactly like every other scanner::

    python -m scripts.core.native_checks --target <dir> --output <file>

The runner is engine-free Python (Decision 3, `.superpowers/sdd/2026-09-27-
phase-4-new-tools/task-N1a-brief.md`): six checks over Next.js/Supabase/
Firebase code, reproducing three archived opengrep rules, an RLS-migration
check, and a Firebase-rules check, with no rule-engine dependency.

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
    """Ruling 60: string-aware, line-preserving comment stripping.

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


class TestMigrationRules:
    """Ruling 61: SQL findings are located at their `create table` statement,
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
        final state is the accumulation over the whole set, not whatever the
        last file alone says. (A per-file-reset bug would forget the earlier
        RLS state as soon as it saw the second, unrelated file.)"""
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
    """Ruling 62: prune VENDORED_DIRS + `.next` (never `dist`/`build`),
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
