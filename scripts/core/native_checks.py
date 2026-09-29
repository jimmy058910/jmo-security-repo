#!/usr/bin/env python3
"""JMo's own check pack: six checks over Next.js/Supabase/Firebase code, no
rule-engine dependency.

Invoked as a subprocess, exactly like every other scanner::

    python -m scripts.core.native_checks --target <dir> --output <file>

**Why this exists.** Phase 4's native pack started as three archived opengrep
rules plus a standalone RLS-migration script (`rls_check.py`) plus an
unprototyped Firebase rule -- four different invocations for one conceptual
check pack, one of them requiring an engine JMo does not otherwise depend on.
A plain-Python runner, on the model of `yara_runner.py`, reproduces all six
checks with zero engine dependency: 8 of 8 on the tracked fixture with no
false positive (Decision 3, `.superpowers/sdd/2026-09-27-phase-4-new-tools/`).

The six rules, exactly:

- ``jmo.nextjs.public-env-holds-server-secret`` -- a ``NEXT_PUBLIC_``/``VITE_``/
  ``REACT_APP_``/``EXPO_PUBLIC_`` prefixed name that looks like a server secret.
- ``jmo.supabase.service-role-key-in-client-code`` -- the Supabase
  ``service_role`` key referenced from code that ships to the browser.
- ``jmo.ai.llm-api-key-in-browser-code`` -- an LLM client constructed with
  ``dangerouslyAllowBrowser: true``.
- ``jmo.supabase.table-without-rls`` -- a public-schema table with Row Level
  Security never enabled.
- ``jmo.supabase.rls-without-policy`` -- RLS enabled, but no policy: the table
  is locked to everyone, including the application itself.
- ``jmo.firebase.rules-open`` -- a Firebase rule granting unconditional access
  (``if true``).

Exit codes match `yara_runner.py`'s:

===  ===========================================================
  0  scanned, no findings
  1  scanned, findings found
  2  did NOT scan (bad target, unwritable output)
===  ===========================================================

**Comments are stripped before any rule runs (Ruling 60).** The naive
``line.find("//")`` a first-cut spike used truncates the idiomatic one-line
``createClient("https://x.supabase.co", process.env.SUPABASE_SERVICE_ROLE_KEY)``
at the URL's own ``//`` -- a silent miss on exactly the line the rule exists
for. :func:`strip_code_comments` is string-aware (a ``//``/``/*`` inside a
``'...'``, ``"..."`` or backtick literal is not a comment) and preserves every
line break, so line numbers never shift. :func:`strip_sql_comments` does the
same for ``--`` and ``/* */`` in migration SQL.

**A SQL finding is located at its ``create table`` statement (Ruling 61)**,
never a synthetic path or line 0, and only public-schema tables are checked
(unqualified name = public; ``private.x``, ``auth.x`` etc. are skipped --
Supabase's Data API exposes ``public``, and another schema is Supabase's own
guidance for keeping a table private). A table's RLS state is the migration
set's *final* state, read across every ``supabase/migrations/*.sql`` file in
filename order.

**No secret value ever reaches the output.** The public-env-secret rule
reports the variable *name* the regex matched -- never the rest of the line,
so the value after `=` on a real `.env` line is never in the message text.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.core.tool_descriptors import VENDORED_DIRS

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _jmo_version() -> str:
    """The same `__version__` `scripts/cli/jmo.py` declares, read from its
    source text rather than imported.

    A `core` module may not import from `cli` (the `import-direction`
    pre-commit hook enforces this layering), so this mirrors
    `release_validator._get_jmo_version`'s regex extraction instead of
    `scripts.cli.wizard_generators`'s `from scripts.cli.jmo import
    __version__` -- that import is fine there because it is `cli` importing
    `cli`, not `core` reaching up into it.
    """
    jmo_py = Path(__file__).resolve().parents[2] / "scripts" / "cli" / "jmo.py"
    try:
        text = jmo_py.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "unknown"
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    return match.group(1) if match else "unknown"


JMO_VERSION = _jmo_version()

TOOL_NAME = "jmo-native"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "Schemata/sarif-schema-2.1.0.json"
)

# `.next` is Next.js's own build cache; VENDORED_DIRS otherwise. Deliberately
# NOT `dist`/`build` -- the repository's stated policy (the comment above
# VENDORED_DIRS in tool_descriptors.py): those hold real build output, and a
# user who points a scan at a release tree means to scan it.
PRUNE_DIRS: frozenset[str] = frozenset(VENDORED_DIRS) | {".next"}

CODE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs")
CLIENT_DIRS = ("app/", "src/", "components/", "pages/", "lib/")
SERVER_MARKERS = (".server.", "/api/", "/server/", "/actions/", "supabase/functions/")
RULES_FILE_NAMES = ("firestore.rules", "storage.rules", "database.rules")

PUBLIC_SECRET = re.compile(
    r"(?i)(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)[A-Z0-9_]*"
    r"(SECRET|SERVICE_ROLE|PRIVATE|ACCESS_TOKEN|_SK_|SECRET_KEY|OPENAI|ANTHROPIC|"
    r"STRIPE_SECRET|DATABASE_URL|SMTP_PASS)[A-Z0-9_]*"
)
SERVICE_ROLE = re.compile(
    r"process\.env\.(NEXT_PUBLIC_)?SUPABASE_SERVICE_ROLE_KEY|service_role"
)
BROWSER_LLM = re.compile(r"dangerouslyAllowBrowser\s*:\s*true")
FIREBASE_OPEN = re.compile(r"allow\s+[a-z ,]*\b(read|write)\b[a-z ,]*:\s*if\s+true\s*;")

_NAME = r'(?:"?(?P<schema>\w+)"?\.)?"?(?P<table>\w+)"?'
CREATE_TABLE_RE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?" + _NAME, re.IGNORECASE
)
ENABLE_RLS_RE = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?"
    r'(?:"?\w+"?\.)?"?(?P<table>\w+)"?\s+enable\s+row\s+level\s+security',
    re.IGNORECASE,
)
POLICY_RE = re.compile(
    r'create\s+policy\s+(?:"[^"]*"|\w+)\s+on\s+(?:"?\w+"?\.)?"?(?P<table>\w+)"?',
    re.IGNORECASE,
)

RULE_PUBLIC_ENV = "jmo.nextjs.public-env-holds-server-secret"
RULE_SERVICE_ROLE = "jmo.supabase.service-role-key-in-client-code"
RULE_BROWSER_LLM = "jmo.ai.llm-api-key-in-browser-code"
RULE_TABLE_NO_RLS = "jmo.supabase.table-without-rls"
RULE_RLS_NO_POLICY = "jmo.supabase.rls-without-policy"
RULE_FIREBASE_OPEN = "jmo.firebase.rules-open"


@dataclass(frozen=True)
class RuleMeta:
    short: str
    full: str
    help: str
    severity: str
    cwe: str | None


# Messages for the three rules the archived opengrep pack already prototyped
# (`jmo-archetype-rules.yaml`) are reused verbatim; the other three (the RLS
# pair and the Firebase rule) are written fresh here, in the same voice.
RULES: dict[str, RuleMeta] = {
    RULE_PUBLIC_ENV: RuleMeta(
        short="Public env var name suggests a server secret",
        full=(
            "A NEXT_PUBLIC_ / VITE_ prefixed variable is inlined into the "
            "browser bundle; a name like $NAME suggests a server-side secret."
        ),
        help=(
            "Rename the variable without the public prefix and read the real "
            "value only on the server."
        ),
        severity="HIGH",
        cwe="CWE-540",
    ),
    RULE_SERVICE_ROLE: RuleMeta(
        short="service_role key referenced from client-side code",
        full=(
            "The Supabase service_role key bypasses Row Level Security and "
            "must never be referenced from code that ships to the browser."
        ),
        help=(
            "Move this reference into server-only code: an API route, a "
            "server action, or a Supabase Edge Function."
        ),
        severity="HIGH",
        cwe="CWE-284",
    ),
    RULE_BROWSER_LLM: RuleMeta(
        short="LLM client exposes its API key to the browser",
        full=(
            "An LLM provider client is constructed with dangerouslyAllowBrowser, "
            "which ships the API key to every visitor."
        ),
        help=(
            "Remove dangerouslyAllowBrowser and call the LLM provider from a "
            "server route instead."
        ),
        severity="HIGH",
        cwe="CWE-798",
    ),
    RULE_TABLE_NO_RLS: RuleMeta(
        short="Public table has no Row Level Security",
        full=(
            "A public-schema table has no Row Level Security policy enabled, "
            "so Supabase's PostgREST API exposes every row to any caller "
            "holding the anon key."
        ),
        help="Run `alter table <name> enable row level security;` and add at least one policy.",
        severity="HIGH",
        cwe="CWE-862",
    ),
    RULE_RLS_NO_POLICY: RuleMeta(
        short="Row Level Security enabled with no policy",
        full=(
            "Row Level Security is enabled with no policy defined, which locks "
            "the table to every caller, including the application itself; this "
            "is often a mistake rather than an intentional lockdown."
        ),
        help=(
            "Add a policy with `create policy ... on <table> ...`, or confirm "
            "the lockdown is intentional."
        ),
        severity="LOW",
        cwe=None,
    ),
    RULE_FIREBASE_OPEN: RuleMeta(
        short="Firebase rule allows unconditional access",
        full=(
            "A Firebase security rule grants read and/or write access "
            "unconditionally (`if true`), exposing the resource to any client."
        ),
        help="Replace `if true` with an authorization check such as `if request.auth != null`.",
        severity="HIGH",
        cwe="CWE-862",
    ),
}


@dataclass(frozen=True)
class NativeFinding:
    rule_id: str
    uri: str  # repository-relative, POSIX
    line: int
    column: int | None
    message: str


def _log(message: str) -> None:
    """Write a progress/diagnostic line to stderr (stdout is reserved for
    programmatic output across this codebase)."""
    print(message, file=sys.stderr, flush=True)


# --- comment stripping ------------------------------------------------------


def strip_code_comments(text: str) -> str:
    """Blank `//` and `/* */` comments in JS/TS-like source, preserving every
    line break so line numbers never shift.

    A small state machine, not a parser: `//`/`/*` found while inside a
    ``'...'``, ``"..."`` or backtick literal is not a comment (an escaped
    quote does not end the literal early), and a block comment may span
    lines. Comment characters are replaced with spaces one-for-one, except
    newlines, which are always kept, so both line AND column offsets in the
    stripped text still line up with the original file.
    """
    out: list[str] = []
    i, n = 0, len(text)
    state = "code"
    quote = ""
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line"
                out.append("  ")
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block"
                out.append("  ")
                i += 2
                continue
            if ch in ("'", '"', "`"):
                state = "string"
                quote = ch
                out.append(ch)
                i += 1
                continue
            out.append(ch)
            i += 1
        elif state == "line":
            if ch == "\n":
                state = "code"
                out.append(ch)
            else:
                out.append(" ")
            i += 1
        elif state == "block":
            if ch == "*" and nxt == "/":
                out.append("  ")
                i += 2
                state = "code"
                continue
            out.append(ch if ch == "\n" else " ")
            i += 1
        else:  # state == "string"
            if ch == "\\" and nxt:
                out.append(ch)
                out.append(nxt)
                i += 2
                continue
            out.append(ch)
            if ch == quote:
                state = "code"
                quote = ""
            i += 1
    return "".join(out)


def strip_sql_comments(text: str) -> str:
    """Blank `--` and `/* */` comments in migration SQL, preserving every
    line break. Not string-aware: no test in this pack needs a `--` or `/*`
    protected inside a SQL string literal, so this stays the small scanner
    the brief asks for rather than growing SQL-string handling nothing uses.
    """
    out: list[str] = []
    i, n = 0, len(text)
    state = "code"
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "-" and nxt == "-":
                state = "line"
                out.append("  ")
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block"
                out.append("  ")
                i += 2
                continue
            out.append(ch)
            i += 1
        elif state == "line":
            if ch == "\n":
                state = "code"
                out.append(ch)
            else:
                out.append(" ")
            i += 1
        else:  # state == "block"
            if ch == "*" and nxt == "/":
                out.append("  ")
                i += 2
                state = "code"
                continue
            out.append(ch if ch == "\n" else " ")
            i += 1
    return "".join(out)


# --- walk --------------------------------------------------------------------


def iter_target_files(
    target: Path, exclude_dirs: frozenset[str] = frozenset()
) -> list[Path]:
    """Walk `target`, pruning vendored trees, `--exclude-dir` names, and
    never following a directory symlink/junction out of the target -- the
    same shape as `yara_runner.iter_target_files`: pruning happens *during*
    the walk via the in-place `dirnames[:]` mutation, and `os.walk`'s default
    `followlinks=False` is what keeps a linked directory from being followed.
    """
    skip = PRUNE_DIRS | exclude_dirs
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            files.append(Path(dirpath) / name)
    return sorted(files)


def is_env_file(name: str) -> bool:
    """Whether the public-env check reads a file of this name. Public: the
    row's trigger asks the same question (`tool_descriptors`)."""
    return name.startswith(".env") or name.endswith((".env", ".env.example"))


def _public_env_finding(rel: str, lineno: int, match: re.Match[str]) -> NativeFinding:
    return NativeFinding(
        RULE_PUBLIC_ENV,
        rel,
        lineno,
        match.start() + 1,
        f"{match.group(0)} is a public-prefixed name inlined into the client bundle",
    )


def scan_file(path: Path, root: Path) -> list[NativeFinding]:
    """Every check that reads one file directly (the migration/RLS check is
    separate: it reads the whole `supabase/migrations/*.sql` set at once)."""
    rel = path.relative_to(root).as_posix()
    name = path.name
    findings: list[NativeFinding] = []

    is_env = is_env_file(name)
    is_code = path.suffix in CODE_SUFFIXES
    if is_env or is_code:
        try:
            raw = path.read_bytes()
        except OSError:
            return findings
        text = raw.decode("utf-8", errors="replace")
        body = text if is_env else strip_code_comments(text)
        is_client = (
            is_code
            and rel.startswith(CLIENT_DIRS)
            and not any(marker in f"/{rel}" for marker in SERVER_MARKERS)
        )
        for lineno, line in enumerate(body.splitlines(), start=1):
            if is_env and line.lstrip().startswith("#"):
                continue
            match = PUBLIC_SECRET.search(line)
            if match:
                findings.append(_public_env_finding(rel, lineno, match))
            if is_code:
                if is_client:
                    role_match = SERVICE_ROLE.search(line)
                    if role_match:
                        findings.append(
                            NativeFinding(
                                RULE_SERVICE_ROLE,
                                rel,
                                lineno,
                                role_match.start() + 1,
                                "the Supabase service_role key is referenced "
                                "from client-side code",
                            )
                        )
                llm_match = BROWSER_LLM.search(line)
                if llm_match:
                    findings.append(
                        NativeFinding(
                            RULE_BROWSER_LLM,
                            rel,
                            lineno,
                            llm_match.start() + 1,
                            "an LLM client is constructed with "
                            "dangerouslyAllowBrowser: true",
                        )
                    )
        return findings

    if name in RULES_FILE_NAMES:
        try:
            raw = path.read_bytes()
        except OSError:
            return findings
        text = raw.decode("utf-8", errors="replace")
        stripped = strip_code_comments(text)
        for lineno, line in enumerate(stripped.splitlines(), start=1):
            match = FIREBASE_OPEN.search(line)
            if match:
                findings.append(
                    NativeFinding(
                        RULE_FIREBASE_OPEN,
                        rel,
                        lineno,
                        match.start() + 1,
                        f"{name} allows unconditional read/write access (`if true`)",
                    )
                )
        return findings

    return findings


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    return line, offset - last_newline


MIGRATIONS_DIR = Path("supabase", "migrations")


def migration_files(root: Path) -> list[Path]:
    """The migrations the RLS checks read: the `*.sql` directly in the root's
    `supabase/migrations`, in filename order. The filesystem decides letter
    case (`Supabase/Migrations` and `init.SQL` count on Windows, not on
    Linux). Public: the row's trigger asks it the same question."""
    mig_dir = root / MIGRATIONS_DIR
    if not mig_dir.is_dir():
        return []
    return sorted(mig_dir.glob("*.sql"))


def scan_migrations(root: Path) -> list[NativeFinding]:
    """A table's RLS state is the *final* state of the whole migration set,
    read in filename order; a finding is located at the file and line of its
    `create table` statement. Only public-schema tables are checked."""
    created: dict[str, tuple[str, int, int]] = {}
    enabled: set[str] = set()
    policies: set[str] = set()

    for path in migration_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        stripped = strip_sql_comments(raw.decode("utf-8", errors="replace"))

        for match in CREATE_TABLE_RE.finditer(stripped):
            schema = match.group("schema")
            if schema is not None and schema.lower() != "public":
                continue
            table = match.group("table").lower()
            if table not in created:
                line, col = _line_col(stripped, match.start())
                created[table] = (rel, line, col)
        for match in ENABLE_RLS_RE.finditer(stripped):
            enabled.add(match.group("table").lower())
        for match in POLICY_RE.finditer(stripped):
            policies.add(match.group("table").lower())

    findings: list[NativeFinding] = []
    for table, (rel, line, col) in created.items():
        if table not in enabled:
            findings.append(
                NativeFinding(
                    RULE_TABLE_NO_RLS,
                    rel,
                    line,
                    col,
                    f'table "{table}" has no Row Level Security enabled',
                )
            )
        elif table not in policies:
            findings.append(
                NativeFinding(
                    RULE_RLS_NO_POLICY,
                    rel,
                    line,
                    col,
                    f'table "{table}" has Row Level Security enabled but no policy',
                )
            )
    return findings


# --- SARIF ---------------------------------------------------------------


def build_sarif(findings: list[NativeFinding]) -> dict[str, Any]:
    rules = []
    for rule_id in (
        RULE_PUBLIC_ENV,
        RULE_SERVICE_ROLE,
        RULE_BROWSER_LLM,
        RULE_TABLE_NO_RLS,
        RULE_RLS_NO_POLICY,
        RULE_FIREBASE_OPEN,
    ):
        meta = RULES[rule_id]
        # "jmo-native/severity": sarif_common._severity_property's rank-2
        # match is a property named `severity` or ending in `/severity`.
        properties: dict[str, str] = {"jmo-native/severity": meta.severity}
        if meta.cwe:
            properties["cwe"] = meta.cwe
        rules.append(
            {
                "id": rule_id,
                "shortDescription": {"text": meta.short},
                "fullDescription": {"text": meta.full},
                "help": {"text": meta.help},
                "properties": properties,
            }
        )

    results = []
    for finding in findings:
        region: dict[str, int] = {"startLine": finding.line}
        if finding.column is not None:
            region["startColumn"] = finding.column
        results.append(
            {
                "ruleId": finding.rule_id,
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.uri},
                            "region": region,
                        }
                    }
                ],
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": JMO_VERSION,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


# --- CLI -----------------------------------------------------------------


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="native_checks",
        description="Scan a tree for JMo's own check pack and write SARIF 2.1.0.",
        allow_abbrev=False,
    )
    parser.add_argument("--target", required=True, help="Directory to scan")
    parser.add_argument(
        "--output", required=True, help="Path to write the SARIF document"
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        metavar="NAME",
        help="A directory name to skip at any depth (repeatable)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {JMO_VERSION}",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    target = Path(args.target)
    if not target.is_dir():
        _log(
            f"jmo-native: target path is not a directory: {target} - "
            "nothing was scanned"
        )
        return EXIT_ERROR

    findings: list[NativeFinding] = []
    for path in iter_target_files(target, frozenset(args.exclude_dir)):
        findings.extend(scan_file(path, target))
    findings.extend(scan_migrations(target))
    findings.sort(key=lambda f: (f.uri, f.line, f.rule_id))

    sarif = build_sarif(findings)
    out_path = Path(args.output)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(json.dumps(sarif, indent=2).encode("utf-8"))
    except OSError as exc:
        _log(f"jmo-native: could not write output {out_path}: {exc}")
        return EXIT_ERROR

    _log(f"jmo-native: scanned {target}, {len(findings)} finding(s)")
    return EXIT_FINDINGS if findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
