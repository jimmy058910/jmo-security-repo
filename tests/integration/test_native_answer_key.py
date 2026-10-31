"""JMo's native check pack (`jmo-native`) graded against vibeproof's fixtures.

humora2504/vibeproof (MIT) is a similar scanner: it ships a vulnerable project and a
clean one, and its own runner lists the twelve rule ids the vulnerable one must
raise. Those fixtures are the answer key. They are fetched by commit, checked
against a sha256 each and kept OUTSIDE the repository (trufflehog finds three
Postgres URIs in them):

    python scripts/dev/fetch_answer_keys.py vibeproof

A test that needs the files skips when they are not there, naming that command. A
file that IS there with another hash fails: the key was altered, and a grade
against it would mean nothing.

Each of vibeproof's twelve ids has exactly one status in `GRADES`:

  covered       the pack has a check for the class; the (file, line) sites it must
                report on the vulnerable fixture are recorded and asserted
  missing       a class the pack lacks; `xfail(strict=True)` tests assert it is
                reported, so the day a check lands the test turns red and the
                table is brought up to date
  other-tool    a secret VALUE; gitleaks and trufflehog read values, not the pack
  out-of-scope  application-level checks the pack does not attempt

The vulnerable fixture's WHOLE finding set is asserted too: every finding the pack
raises there belongs to a covered class, and nothing else.

The two files that carry credentials are not stored as such upstream. vibeproof's
runner builds `.env` and `.env.example` from `env.fixture` and
`env.example.fixture` at run time, so this does the same, with the tokens built
here at run time: nothing shaped like a key sits in this source. Without that the
pack would see no `.env` at all. The values are never printed; every message here
carries rule ids, files and lines only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

from scripts.core import native_checks
from scripts.dev import fetch_answer_keys as fak

FETCH_COMMAND = "python scripts/dev/fetch_answer_keys.py vibeproof"

# (file relative to the scanned directory, 1-based line)
Site = tuple[str, int]
Triple = tuple[str, str, int]

MIGRATION = "supabase/migrations/001_init.sql"

COVERED = "covered"
MISSING = "missing"
OTHER_TOOL = "other-tool"
OUT_OF_SCOPE = "out-of-scope"
STATUSES = (COVERED, MISSING, OTHER_TOOL, OUT_OF_SCOPE)

# vibeproof's `test/run.js` `EXPECTED`, in its order. Hard-coded here because
# `run.js` is not in the fetched set. When the pin moves, read `EXPECTED` again:
# an id added upstream fails `test_the_table_holds_exactly_the_pinned_ids` until
# it is graded below, so it cannot go ungraded.
PINNED_IDS = (
    "SECRET-SUPABASE-SERVICE-ROLE",
    "SECRET-STRIPE-SECRET",
    "DB-CONNECTION-STRING",
    "DB-RLS-NOT-ENABLED",
    "DB-POLICY-ALWAYS-TRUE",
    "DB-GRANT-ANON-WRITE",
    "DB-PUBLIC-BUCKET",
    "DB-FIREBASE-OPEN-RULE",
    "APP-SERVICE-CLIENT-IN-BROWSER",
    "APP-UNAUTHENTICATED-MUTATION",
    "APP-WEAK-SIGNING-SECRET",
    "APP-GITIGNORE-MISSING-ENV",
)


@dataclass(frozen=True)
class Grade:
    status: str
    why: str
    # covered: the JMo rule id that answers the class. Otherwise empty.
    rule: str = ""
    # covered: the sites that rule must report on the vulnerable fixture.
    # missing: the sites a check for the class would have to report.
    sites: frozenset[Site] = frozenset()


GRADES: dict[str, Grade] = {
    "SECRET-SUPABASE-SERVICE-ROLE": Grade(
        COVERED,
        "the service-role key under a NEXT_PUBLIC_ name: declared at .env:3 and "
        "read at src/lib/admin.ts:2, and the pack reports both, by name",
        native_checks.RULE_PUBLIC_ENV,
        frozenset({(".env", 3), ("src/lib/admin.ts", 2)}),
    ),
    "DB-RLS-NOT-ENABLED": Grade(
        COVERED,
        "profiles (line 1) and invoices (line 2) have no RLS; posts (line 3) has "
        "it on and must not be reported",
        native_checks.RULE_TABLE_NO_RLS,
        frozenset({(MIGRATION, 1), (MIGRATION, 2)}),
    ),
    "DB-FIREBASE-OPEN-RULE": Grade(
        COVERED,
        "firestore.rules allows read and write to everyone",
        native_checks.RULE_FIREBASE_OPEN,
        frozenset({("firestore.rules", 4)}),
    ),
    "APP-SERVICE-CLIENT-IN-BROWSER": Grade(
        COVERED,
        "a service-role client built in src/lib/admin.ts, which no server marker "
        "puts on the server",
        native_checks.RULE_SERVICE_ROLE,
        frozenset({("src/lib/admin.ts", 2)}),
    ),
    "DB-POLICY-ALWAYS-TRUE": Grade(
        MISSING,
        "`using (true)` on posts: the pack checks that RLS is on and that a "
        "policy exists, not what the policy says",
        sites=frozenset({(MIGRATION, 5)}),
    ),
    "DB-GRANT-ANON-WRITE": Grade(
        MISSING,
        "`grant all ... to anon`: the pack reads no GRANT statement",
        sites=frozenset({(MIGRATION, 6)}),
    ),
    "DB-PUBLIC-BUCKET": Grade(
        MISSING,
        "a storage bucket inserted with public = true: the pack reads no "
        "storage.buckets statement",
        sites=frozenset({(MIGRATION, 7)}),
    ),
    "SECRET-STRIPE-SECRET": Grade(
        OTHER_TOOL,
        "a secret VALUE (.env:4): gitleaks and trufflehog read values, which "
        "are in the matrix",
    ),
    "DB-CONNECTION-STRING": Grade(
        OTHER_TOOL,
        "a connection string carrying a password (.env:6): a value, so "
        "gitleaks and trufflehog",
    ),
    "APP-UNAUTHENTICATED-MUTATION": Grade(
        OUT_OF_SCOPE,
        "a route handler that deletes with no auth check: application logic the "
        "pack does not attempt",
    ),
    "APP-WEAK-SIGNING-SECRET": Grade(
        OUT_OF_SCOPE,
        "NEXTAUTH_SECRET=dev: a judgement about a value's strength, which the "
        "pack does not attempt",
    ),
    "APP-GITIGNORE-MISSING-ENV": Grade(
        OUT_OF_SCOPE,
        "a .gitignore that does not list .env: repository hygiene the pack does "
        "not attempt",
    ),
}

# The one finding the pack raises on vibeproof's clean fixture, recorded and
# asserted as an exact set (a second finding there must still fail). vibeproof
# accepts a service-role client in a file NAMED `server.ts`; JMo trusts only
# Next.js's own server markers (a route handler, middleware or proxy,
# `import 'server-only'`, "use server", a `.server.` infix, a `/server/`
# folder), so it reads src/lib/server.ts as client code. The remedy on the
# code's side is `import 'server-only'` at the top of that file.
RECORDED_CLEAN: frozenset[Triple] = frozenset(
    {(native_checks.RULE_SERVICE_ROLE, "src/lib/server.ts", 3)}
)

# (the credential-free source in the key, the file vibeproof's runner builds)
MATERIALISED = {
    "vulnerable": ("env.fixture", ".env"),
    "clean": ("env.example.fixture", ".env.example"),
}


# --- the credentials, built at run time ---------------------------------------


def _b64url(obj: dict[str, str]) -> str:
    # Compact separators: the JSON the runner's `JSON.stringify` writes.
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(role: str) -> str:
    return ".".join(
        [
            _b64url({"alg": "HS256", "typ": "JWT"}),
            _b64url({"role": role, "iss": "supabase", "ref": "abcdefgh"}),
            "fixture" + "signature" + str(len(role)),
        ]
    )


def _tokens() -> dict[bytes, bytes]:
    # Split so the finished literal never sits in this file.
    values = {
        "__ANON_JWT__": _jwt("anon"),
        "__SERVICE_JWT__": _jwt("service_role"),
        "__STRIPE_LIVE__": "_".join(
            ["sk", "live", "51QaBcDeFgHiJkL" + "mNoPqRsTuVwXyZ0987"]
        ),
        "__DB_PASSWORD__": "fixture" + "Only" + "Passw0rd",
    }
    return {k.encode(): v.encode() for k, v in values.items()}


def _materialise(target: Path, source: str, built: str) -> None:
    """Write `target/built` from `target/source`, every token replaced. Bytes
    in and out: no newline translation, whatever the platform."""
    body = (target / source).read_bytes()
    for token, value in _tokens().items():
        body = body.replace(token, value)
    # Names only, and not an `assert` (which would print `body`, the secrets
    # materialised): a leftover would be silently scanned as itself, and a
    # token upstream adds later is caught too.
    left = sorted(set(re.findall(rb"__[A-Z_]+__", body)))
    if left:
        pytest.fail(
            f"{source}: unreplaced token(s) {[t.decode() for t in left]}",
            pytrace=False,
        )
    (target / built).write_bytes(body)


def test_an_unknown_leftover_token_fails_naming_only_the_token(
    tmp_path: Path,
) -> None:
    """A token the table does not replace (one upstream adds later) fails, and
    the message carries its name: not the file, nor any materialised value."""
    (tmp_path / "env.fixture").write_bytes(
        b"A=__ANON_JWT__\nB=__NEW_UPSTREAM_TOKEN__\n"
    )

    with pytest.raises(pytest.fail.Exception) as raised:
        _materialise(tmp_path, "env.fixture", ".env")

    message = str(raised.value)
    assert "__NEW_UPSTREAM_TOKEN__" in message
    assert "__ANON_JWT__" not in message
    assert not any(value.decode() in message for value in _tokens().values())


def test_a_pack_that_prints_a_secret_value_fails_naming_only_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = _tokens()[b"__DB_PASSWORD__"]

    def leaky(argv: list[str]) -> int:
        out = Path(argv[argv.index("--output") + 1])
        out.write_bytes(b'{"runs": [{"results": []}], "x": "' + value + b'"}')
        return native_checks.EXIT_CLEAN

    monkeypatch.setattr(native_checks, "main", leaky)

    with pytest.raises(pytest.fail.Exception) as raised:
        _run_pack(tmp_path, tmp_path / "o.sarif")

    message = str(raised.value)
    assert "__DB_PASSWORD__" in message
    assert value.decode() not in message


# --- the key ------------------------------------------------------------------


def _require_key(root: Path) -> None:
    """Return when every pinned file is in `root` with its pinned hash. A file
    with another hash FAILS (the key was altered); a file that is not there
    SKIPS, naming the command that fetches it."""
    wrong: list[str] = []
    missing: list[str] = []
    for rel, pinned in fak.VIBEPROOF_FILES.items():
        try:
            actual = hashlib.sha256((root / rel).read_bytes()).hexdigest()
        except FileNotFoundError:
            missing.append(rel)
            continue
        if actual != pinned:
            wrong.append(rel)
    if wrong:
        pytest.fail(
            f"the cached answer key under {root} is not the pinned one: "
            f"{', '.join(wrong)} do not match their sha256. Do not edit the "
            f"cache; delete the directory and run: {FETCH_COMMAND}"
        )
    if missing:
        pytest.skip(
            f"the vibeproof answer key is not in place ({len(missing)} of "
            f"{len(fak.VIBEPROOF_FILES)} files missing under {root}); fetch it "
            f"with: {FETCH_COMMAND}"
        )


@pytest.fixture(scope="module")
def key_dir() -> Path:
    """The cached fixtures directory, read and never written."""
    root = fak.vibeproof_dir()
    _require_key(root)
    return root / "test" / "fixtures"


def _run_pack(target: Path, out: Path) -> set[Triple]:
    rc = native_checks.main(["--target", str(target), "--output", str(out)])
    assert rc in (native_checks.EXIT_CLEAN, native_checks.EXIT_FINDINGS), (
        f"the pack did not scan {target.name}: exit {rc}"
    )
    sarif = out.read_bytes()
    # Names only: vibeproof's own runner asserts no secret is printed in full.
    printed = [name.decode() for name, value in _tokens().items() if value in sarif]
    if printed:
        pytest.fail(
            f"{target.name}: the pack's output holds the value of {printed}",
            pytrace=False,
        )
    results = json.loads(sarif)["runs"][0]["results"]
    return {
        (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in results
    }


@pytest.fixture(scope="module")
def scans(
    key_dir: Path, tmp_path_factory: pytest.TempPathFactory
) -> dict[str, set[Triple]]:
    """The pack's findings on each materialised fixture, scanned from a copy in
    a temporary directory: nothing is written beside the cache."""
    work = tmp_path_factory.mktemp("vibeproof")
    found: dict[str, set[Triple]] = {}
    for name, (source, built) in MATERIALISED.items():
        target = work / name
        shutil.copytree(key_dir / name, target)
        _materialise(target, source, built)
        found[name] = _run_pack(target, work / f"{name}.sarif")
    return found


def _sites(found: set[Triple], rule: str) -> set[Site]:
    return {(uri, line) for r, uri, line in found if r == rule}


def _expected_vulnerable() -> set[Triple]:
    return {
        (grade.rule, uri, line)
        for grade in GRADES.values()
        if grade.status == COVERED
        for uri, line in grade.sites
    }


# --- the table (needs no key) --------------------------------------------------


def test_the_table_holds_exactly_the_pinned_ids() -> None:
    assert len(PINNED_IDS) == 12
    assert len(set(PINNED_IDS)) == 12
    assert set(GRADES) == set(PINNED_IDS)


def test_every_id_has_one_known_status_and_a_reason() -> None:
    for vp_id, grade in GRADES.items():
        assert grade.status in STATUSES, vp_id
        assert grade.why, vp_id
    assert {g.status for g in GRADES.values()} == set(STATUSES)


def test_a_covered_class_names_its_rule_and_sites_and_no_other_class_does() -> None:
    for vp_id, grade in GRADES.items():
        if grade.status == COVERED:
            assert grade.rule and grade.sites, vp_id
        elif grade.status == MISSING:
            assert not grade.rule and grade.sites, vp_id
        else:
            assert not grade.rule and not grade.sites, vp_id


def test_a_covered_class_names_a_rule_the_pack_has() -> None:
    known = {
        native_checks.RULE_PUBLIC_ENV,
        native_checks.RULE_SERVICE_ROLE,
        native_checks.RULE_BROWSER_LLM,
        native_checks.RULE_TABLE_NO_RLS,
        native_checks.RULE_RLS_NO_POLICY,
        native_checks.RULE_FIREBASE_OPEN,
    }
    for vp_id, grade in GRADES.items():
        if grade.status == COVERED:
            assert grade.rule in known, vp_id


# --- the credentials and the key's checks (need no key) ------------------------


def test_the_service_jwt_is_a_three_part_token_with_the_service_role() -> None:
    header, payload, signature = _jwt("service_role").split(".")

    def decode(part: str) -> dict[str, str]:
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))

    assert decode(header) == {"alg": "HS256", "typ": "JWT"}
    assert decode(payload) == {
        "role": "service_role",
        "iss": "supabase",
        "ref": "abcdefgh",
    }
    assert signature


def test_materialising_replaces_every_token_and_leaves_the_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "env.fixture"
    original = (
        b"A=__ANON_JWT__\r\nB=__SERVICE_JWT__\nC=__STRIPE_LIVE__\nD=__DB_PASSWORD__"
    )
    source.write_bytes(original)

    _materialise(tmp_path, "env.fixture", ".env")

    body = (tmp_path / ".env").read_bytes()
    assert b"__" not in body
    assert body.count(b"\r\n") == 1  # bytes in, bytes out
    assert source.read_bytes() == original


def test_a_key_with_every_file_in_place_is_accepted(
    tmp_path: Path, monkeypatch
) -> None:
    good = {"a/one.txt": b"one", "b/two.txt": b"two"}
    for rel, data in good.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_bytes(data)
    monkeypatch.setattr(
        fak,
        "VIBEPROOF_FILES",
        {p: hashlib.sha256(d).hexdigest() for p, d in good.items()},
    )

    _require_key(tmp_path)


def test_a_missing_key_skips_naming_the_fetch_command(tmp_path: Path) -> None:
    with pytest.raises(pytest.skip.Exception, match="fetch_answer_keys.py vibeproof"):
        _require_key(tmp_path / "absent")


def test_a_cached_file_with_another_hash_fails_and_does_not_skip(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "a.txt").write_bytes(b"altered")
    (tmp_path / "b.txt").write_bytes(b"fine")
    monkeypatch.setattr(
        fak,
        "VIBEPROOF_FILES",
        {
            "a.txt": hashlib.sha256(b"pinned").hexdigest(),
            "b.txt": hashlib.sha256(b"fine").hexdigest(),
            "c.txt": hashlib.sha256(b"missing").hexdigest(),
        },
    )

    # An altered file wins over a missing one: it is not a key to grade against.
    # Not `pytest.raises(pytest.fail.Exception)`: a skip would pass straight
    # through it and this test would itself report SKIPPED, so the regression it
    # guards (the guard skipping) could never turn anything red.
    try:
        _require_key(tmp_path)
    except pytest.skip.Exception:
        pytest.fail("a cached file with another hash skipped; it must fail")
    except pytest.fail.Exception as failed:
        assert "a.txt do not match" in str(failed)
    else:
        pytest.fail("a cached file with another hash was accepted")


# --- the grade (needs the key) -------------------------------------------------


@pytest.mark.parametrize("vp_id", [i for i, g in GRADES.items() if g.status == COVERED])
def test_the_covered_class_is_reported_at_every_site(
    vp_id: str, scans: dict[str, set[Triple]]
) -> None:
    """Per-class recall on the classes the pack and vibeproof both cover: 1.0."""
    grade = GRADES[vp_id]
    found = _sites(scans["vulnerable"], grade.rule)

    recall = len(grade.sites & found) / len(grade.sites)

    assert recall == 1.0, (
        f"{vp_id}: recall {recall:.2f} ({len(grade.sites & found)} of "
        f"{len(grade.sites)}); {grade.rule} did not report {sorted(grade.sites - found)}"
    )


def test_the_table_with_rls_on_is_not_reported(
    scans: dict[str, set[Triple]],
) -> None:
    """vibeproof's `protected table not reported`: posts is line 3, RLS on."""
    reported = _sites(scans["vulnerable"], native_checks.RULE_TABLE_NO_RLS)

    assert (MIGRATION, 3) not in reported
    assert (MIGRATION, 4) not in reported


def test_the_vulnerable_fixture_raises_the_covered_classes_and_nothing_else(
    scans: dict[str, set[Triple]],
) -> None:
    expected = _expected_vulnerable()
    found = scans["vulnerable"]

    assert not expected - found, f"not reported: {sorted(expected - found)}"
    assert not found - expected, (
        f"reported, but in no covered class: {sorted(found - expected)}"
    )


def test_the_clean_fixture_raises_exactly_the_one_recorded_finding(
    scans: dict[str, set[Triple]],
) -> None:
    """Not zero: see `RECORDED_CLEAN`. An exact set, so a second finding fails."""
    found = scans["clean"]

    assert found == RECORDED_CLEAN, (
        f"expected {sorted(RECORDED_CLEAN)}; "
        f"missing {sorted(RECORDED_CLEAN - found)}, extra {sorted(found - RECORDED_CLEAN)}"
    )


@pytest.mark.parametrize(
    "vp_id",
    [
        pytest.param(
            i,
            marks=pytest.mark.xfail(
                strict=True, raises=AssertionError, reason=f"{i}: {g.why}"
            ),
        )
        for i, g in GRADES.items()
        if g.status == MISSING
    ],
)
def test_the_class_the_pack_lacks_is_reported(
    vp_id: str, scans: dict[str, set[Triple]]
) -> None:
    """Strict: the day the pack reports one of these, this passes unexpectedly
    and fails the run, so the class moves to `covered` in the table."""
    reported = {(uri, line) for _, uri, line in scans["vulnerable"]}

    assert GRADES[vp_id].sites <= reported
