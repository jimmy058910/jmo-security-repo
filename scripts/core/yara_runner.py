#!/usr/bin/env python3
"""Drive yara-x over a repository and emit the JSON the yara-x adapter parses.

Invoked as a subprocess, exactly like every other scanner::

    python -m scripts.core.yara_runner --rules <dir|file> --target <dir> --output <file>

yara-x, VirusTotal's rewrite of YARA, is a runtime dependency of JMo: its wheel
is the engine and its pin is `uv.lock`'s (v2.0.0 Phase 6, PR Y). The wheel
has no command line of JMo's shape, so this module supplies one and the walk.
Keeping it a subprocess rather than an in-process call preserves the uniform
ToolRunner model - timeouts, retries, ``ok_return_codes``, and the accounting
that ``scripts/dev/reconcile_scan_accounting.py`` validates - and puts a real
executable, this interpreter, at ``command[0]``.

Exit codes are the scanner's ``ok_return_codes=(0, 1)`` plus a distinct error:

===  ===========================================================
  0  scanned, no matches
  1  scanned, matches found
  2  did NOT scan (no engine, no rules, unreadable target, a crash)
===  ===========================================================

Code 2 matters as much as the other two. A run that examines nothing produces
byte-for-byte the same empty finding list as a genuinely clean repository, so
reporting it as 0 is the inert-scanner bug: trufflehog once reported its version
correctly while scanning nothing at all, and the ``zero-secrets`` gate passed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any

from scripts.core.yara_rules import RULE_SUFFIXES

EXIT_CLEAN = 0
EXIT_MATCHES = 1
EXIT_ERROR = 2

# yara-x is the one tool that reads vendored trees (decision 4): signature-base's
# npm supply-chain rules can match nowhere but `node_modules`. A git object
# store is never source, so it is pruned even when the scan names nothing.
SKIP_DIRS = frozenset({".git"})

# yara on a multi-gigabyte artifact costs minutes and finds nothing a rule set
# aimed at source trees would catch. Skipped files are counted and reported.
DEFAULT_MAX_FILE_BYTES = 50 * 1024 * 1024

# Per-file match timeout: some rule and input combinations are pathological,
# and without this a single file can hang the whole scan.
DEFAULT_MATCH_TIMEOUT = 60

# Per-file scan errors are reported individually up to this many, then counted.
# A locked or quarantined file is routine; thousands of them is a broken run.
MAX_REPORTED_FILE_ERRORS = 10

# The externals LOKI defines per file, which signature-base's rules read
# (`filename matches /.../`, `filepath == "/var/log"`, `extension == ".jpg"`).
EXTERNALS = ("filename", "filepath", "extension", "filetype", "owner")

# The binary entries of signature-base's `misc/file-type-signatures.txt`, the
# table LOKI sets `filetype` from. Two kept rules read it: one guards on
# `not filetype == "EXE"` beside a test for `MZ`, so with no label it fires on
# every such executable. Its text types (PHP, JSP, ASP, VBS, BATCH) are not
# read: a `.jpg` that is really one of those is not reported as cloaked.
FILE_TYPES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "EXE"),
    (b"\x7fE", "ELF"),
    (b"{\\rt", "RTF"),
    (b"MDMP", "MDMP"),
)


def _import_yara_x() -> Any | None:
    """Return the yara_x module, or None if this interpreter cannot import it.

    None means the yara extra is not installed (#1577), or is broken. Isolated
    into a function so tests can force that case: it must fail as loudly as
    any other way of scanning nothing.
    """
    try:
        # Deferred deliberately: this import IS the availability probe.
        import yara_x
    except ImportError:
        return None
    return yara_x


def _log(message: str) -> None:
    """Write a progress/diagnostic line to stderr.

    stdout is reserved for programmatic output across this codebase, and the
    scan captures stderr into its log. flush=True because install and scan
    output is otherwise block-buffered, which reads as a hang in CI logs.
    """
    print(message, file=sys.stderr, flush=True)


def collect_rule_files(rules_root: Path) -> list[Path]:
    """Return every rule file under `rules_root`, or the file itself."""
    if rules_root.is_file():
        return [rules_root]
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(rules_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(RULE_SUFFIXES):
                found.append(Path(dirpath) / name)
    return sorted(found)


def namespace_for(path: Path, rules_root: Path) -> str:
    """Name a rule file's namespace by its position in the rule set.

    yara-x reports the namespace on every match, and the adapter turns it into
    a `namespace:<value>` tag. Keying namespaces by absolute path put
    `C:\\Users\\<name>\\.jmo\\yara-rules\\...` in every finding, leaking local
    filesystem layout into reports, the history database and any shared export.
    The relative stem is both safe and more useful. A single rule file is its
    own root, and its namespace is its stem (#1413).
    """
    if path == rules_root:
        return path.stem
    try:
        rel = path.relative_to(rules_root)
    except ValueError:
        rel = Path(path.name)
    return rel.with_suffix("").as_posix()


def compile_rules(
    yara_x: Any, rule_files: list[Path], rules_root: Path
) -> tuple[Any | None, int, list[Path]]:
    """Compile `rule_files` into one rule set, one namespace per file.

    Returns (compiled Rules or None, files compiled cleanly, files with errors).

    yara-x compiles rule by rule: a rule that fails is left out and the rest of
    its file is kept (measured, 1.22.1: a rule after a syntax error still
    matched). So a broken file costs only its broken rules, and the run names
    the file. With no file compiled cleanly the result is None: what little
    might have compiled is not a scan anyone asked for.
    """
    compiler = yara_x.Compiler()
    for name in EXTERNALS:
        compiler.define_global(name, "")
    clean = 0
    with_errors: list[Path] = []
    for path in rule_files:
        compiler.new_namespace(namespace_for(path, rules_root))
        try:
            compiler.add_source(path.read_text(encoding="utf-8"), origin=path.name)
        except (yara_x.CompileError, UnicodeDecodeError, OSError) as exc:
            with_errors.append(path)
            _log(f"yara-x: skipped what would not compile in {path.name}:\n{exc}")
            continue
        clean += 1
    if clean == 0:
        return None, 0, with_errors
    return compiler.build(), clean, with_errors


def iter_target_files(
    target: Path, max_bytes: int, exclude_dirs: frozenset[str] = frozenset()
) -> tuple[list[Path], int]:
    """Walk `target`. Returns (files, skipped_over_the_cap).

    `exclude_dirs` adds directory names to prune: the scan passes `.git` and
    JMo's own results directory when it sits inside the tree, which yara read
    back on every later scan (#1235).

    Pruning happens *during* traversal via the in-place ``dirnames[:]``
    mutation, not by filtering paths afterwards. The post-filter form stats
    every pruned file on the way past (commit ded93df). `os.walk`'s default
    `followlinks=False` keeps a linked directory from being followed; a
    linked *file* is returned unread, for the scan to count and pass over. A
    file whose size cannot be read is kept, so the scan reports why.
    """
    skip = SKIP_DIRS | exclude_dirs
    files: list[Path] = []
    too_large = 0
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            path = Path(dirpath) / name
            if not path.is_symlink():
                try:
                    if path.stat().st_size > max_bytes:
                        too_large += 1
                        continue
                except OSError:
                    pass
            files.append(path)
    return sorted(files), too_large


def _owner(path: Path) -> str:
    """The owning account's name, as LOKI reads it; "" where none can be read."""
    if sys.platform == "win32":
        return ""
    import pwd

    try:
        return pwd.getpwuid(path.stat().st_uid).pw_name
    except (KeyError, OSError):
        return ""


def loki_externals(path: Path) -> dict[str, str]:
    """The five externals signature-base's rules read, as LOKI sets them for
    `path`: its name, its directory, its lower-case suffix with the dot, the
    type its first bytes name, and its owner."""
    with path.open("rb") as handle:
        head = handle.read(4)
    return {
        "filename": path.name,
        "filepath": str(path.absolute().parent),
        "extension": path.suffix.lower(),
        "filetype": next((t for magic, t in FILE_TYPES if head.startswith(magic)), ""),
        "owner": _owner(path),
    }


def _meta_value(value: Any) -> Any:
    """A metadata value JSON can hold. yara-x returns a string written with
    `\\x` escapes as bytes (measured, 1.22.1)."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def match_to_dict(rule: Any, path: Path) -> dict[str, Any]:
    """Shape one matching yara-x Rule into what the yara-x adapter reads.

    Matched *pattern identifiers* only, never the matched bytes. A malware rule
    can match on an embedded key or token, and these findings flow into shared
    reports and the history database - the adapter only uses the count and the
    identifiers, so the content buys nothing and leaks something.

    A key the rule repeats keeps every value, as a list: signature-base names
    two `reference`s on some rules, and DRL 1.1 wants them with the output.
    """
    meta: dict[str, Any] = {}
    for key, raw in rule.metadata:
        value = _meta_value(raw)
        if key not in meta:
            meta[key] = value
        elif isinstance(meta[key], list):
            meta[key].append(value)
        else:
            meta[key] = [meta[key], value]
    return {
        "rule": rule.identifier,
        "namespace": rule.namespace,
        "tags": [str(t) for t in rule.tags],
        "meta": meta,
        "strings": [p.identifier for p in rule.patterns if p.matches],
        "file": str(path),
    }


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="yara_runner",
        description="Scan a tree with yara-x and write JSON the yara-x adapter parses.",
        # `--outp x` would otherwise be `--output x`, and a user's flags come
        # after JMo's: the report would move (#1335).
        allow_abbrev=False,
    )
    parser.add_argument(
        "--rules", required=True, help="Rule file or directory of rules"
    )
    parser.add_argument("--target", required=True, help="Directory or file to scan")
    parser.add_argument("--output", required=True, help="Path to write the JSON array")
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_MATCH_TIMEOUT,
        help=f"Per-file match timeout in seconds (default: {DEFAULT_MATCH_TIMEOUT})",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help=f"Skip files larger than this (default: {DEFAULT_MAX_FILE_BYTES})",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        metavar="NAME",
        help="A directory name to skip at any depth (repeatable)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # An earlier scan's output must not outlive this run: the row reads this
    # run's file or none, and a stop before the scan would otherwise leave the
    # previous matches to be parsed as this scan's.
    out_path = Path(args.output)
    try:
        out_path.unlink(missing_ok=True)
    except OSError as exc:
        _log(
            f"yara-x: could not remove an earlier output {out_path}: {exc} - "
            "nothing was scanned"
        )
        return EXIT_ERROR

    try:
        return _scan(args, out_path)
    except Exception as exc:
        # Python exits 1 on an uncaught exception, which is EXIT_MATCHES and
        # which the row accepts; a crash is "did not scan", and says why.
        _log(f"yara-x: {type(exc).__name__}: {exc} - nothing was scanned")
        _log(traceback.format_exc().rstrip())
        return EXIT_ERROR


def _scan(args: argparse.Namespace, out_path: Path) -> int:
    yara_x = _import_yara_x()
    if yara_x is None:
        # Deferred: the registry is heavier than this runner, and only this
        # failure reads it.
        from scripts.core.tool_registry import DEPENDENCY_MISSING

        _log(
            f"yara-x: nothing was scanned, because {DEPENDENCY_MISSING['yara-x']} "
            f"(interpreter: {sys.executable})"
        )
        return EXIT_ERROR

    rules_root = Path(args.rules)
    if not rules_root.exists():
        _log(
            f"yara-x: rules path does not exist: {rules_root} - nothing was scanned. "
            "Install the pinned rule set with: jmo tools install yara-x"
        )
        return EXIT_ERROR

    target = Path(args.target)
    if not target.exists():
        _log(f"yara-x: target path does not exist: {target} - nothing was scanned")
        return EXIT_ERROR

    rule_files = collect_rule_files(rules_root)
    if not rule_files:
        _log(
            f"yara-x: no {' or '.join(RULE_SUFFIXES)} files under {rules_root} - "
            "nothing was scanned"
        )
        return EXIT_ERROR

    rules, compiled, with_errors = compile_rules(yara_x, rule_files, rules_root)
    if rules is None:
        _log(
            f"yara-x: 0 of {len(rule_files)} rule file(s) compiled - nothing was "
            "scanned. Reporting this as a clean scan would be a false all-clear."
        )
        return EXIT_ERROR
    if with_errors:
        _log(
            f"yara-x: compiled {compiled} rule file(s) cleanly; {len(with_errors)} "
            "had rules that would not compile, skipped"
        )

    files, too_large = iter_target_files(
        target, args.max_file_bytes, frozenset(args.exclude_dir)
    )

    scanner = yara_x.Scanner(rules)
    # Before the loop: a value no u64 holds raises OverflowError here, once,
    # rather than as a per-file error on every file.
    scanner.set_timeout(args.timeout)

    matches: list[dict[str, Any]] = []
    links = 0
    errored = 0
    for path in files:
        if path.is_symlink():
            links += 1
            continue
        try:
            for name, value in loki_externals(path).items():
                scanner.set_global(name, value)
            results = scanner.scan_file(str(path))
        except (yara_x.ScanError, yara_x.TimeoutError, OSError) as exc:
            # A single unscannable file must not abort the run, but it must not
            # vanish either. Naming the reason is not decoration: an early
            # version of this loop counted errors without printing them, and
            # every match test failed identically with "1 errored" while the
            # actual cause was Defender blocking the fixture at write time
            # (OSError 22 on a path Path.exists() reported as present).
            errored += 1
            if errored <= MAX_REPORTED_FILE_ERRORS:
                _log(f"yara-x: could not scan {path}: {exc}")
            continue
        matches.extend(match_to_dict(rule, path) for rule in results.matching_rules)

    attempted = len(files) - links
    scanned = attempted - errored
    if attempted and scanned == 0:
        # Every file failed. The findings list is empty for the same reason a
        # clean repository's is, and only this branch can tell them apart.
        _log(
            f"yara-x: all {attempted} file(s) failed to scan - nothing was "
            "examined. Reporting this as a clean scan would be a false all-clear."
        )
        return EXIT_ERROR

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(matches, indent=2), encoding="utf-8")

    _log(
        f"yara-x: scanned {scanned} of {attempted} file(s) with {compiled} rule "
        f"file(s); {len(matches)} match(es), {too_large} over the size cap, "
        f"{links} symlinks not followed, {errored} errored"
    )
    return EXIT_MATCHES if matches else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
