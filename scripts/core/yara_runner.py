#!/usr/bin/env python3
"""Drive libyara over a repository and emit the JSON the yara adapter parses.

Invoked as a subprocess, exactly like every other scanner::

    python -m scripts.core.yara_runner --rules <dir> --target <dir> --output <file>

**Why this module exists.** ``yara-python`` is libyara plus bindings, not a
command-line tool: the shipped artifact is a compiled extension
(``yara.cp312-win_amd64.pyd``) exposing ``compile()``/``match()``, with no
``main()`` and no console script. The scanner nevertheless built the *native C*
yara command line (``yara -r -w -s <rules> <repo>``), which the library cannot
satisfy, and ``find_tool`` bridged the gap by returning the pseudo-path
``python:yara`` - truthy, so yara passed pre-flight, then died at exec.

Using the native CLI instead is not an option: VirusTotal/yara publishes
prebuilt binaries for **Windows only**, and stopped even that at v4.5.6 (v4.5.7
and v4.5.8 ship zero release assets). Linux and macOS have never had one. The
PyPI wheels, by contrast, cover win32/win_amd64, manylinux and musllinux on
x86_64/aarch64/i686, and macOS on both arches - the same C engine
(``yara.YARA_VERSION``), distributed everywhere the CLI is not.

Keeping it a subprocess rather than an in-process call preserves the uniform
ToolRunner model - timeouts, retries, ``ok_return_codes``, and the accounting
that ``scripts/dev/reconcile_scan_accounting.py`` validates - and puts a real
executable at ``command[0]``, which is what the pseudo-path broke.

Exit codes are the scanner's ``ok_return_codes=(0, 1)`` plus a distinct error:

===  ===========================================================
  0  scanned, no matches
  1  scanned, matches found
  2  did NOT scan (no library, no rules, unreadable target)
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
from pathlib import Path
from typing import Any

EXIT_CLEAN = 0
EXIT_MATCHES = 1
EXIT_ERROR = 2

RULE_SUFFIXES = (".yar", ".yara")

# Repositories vendor dependencies; scanning node_modules or a bundled venv
# buries the repo's own findings in third-party noise. Mirrors the set in
# scripts/cli/scan_jobs/repository_scanner.py.
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv"}

# yara on a multi-gigabyte artifact costs minutes and finds nothing a rule set
# aimed at source trees would catch. Skipped files are counted and reported.
DEFAULT_MAX_FILE_BYTES = 50 * 1024 * 1024

# Per-file match timeout. libyara can pathologically backtrack on some rule and
# input combinations; without this a single file can hang the whole scan.
DEFAULT_MATCH_TIMEOUT = 60

# Per-file scan errors are reported individually up to this many, then counted.
# A locked or quarantined file is routine; thousands of them is a broken run.
MAX_REPORTED_FILE_ERRORS = 10


def _import_yara() -> Any | None:
    """Return the yara module, or None if it is not installed.

    Isolated into a function so tests can force the absent case without
    manipulating sys.modules: the "library missing" path is the one a machine
    that never ran `jmo tools install yara` actually takes, so it needs a test.
    """
    try:
        # Deferred deliberately: this import IS the availability probe.
        import yara
    except ImportError:
        return None
    return yara


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
    """Name a rule file's namespace by its position in the bundle.

    libyara reports the namespace on every match, and the adapter turns it into
    a `namespace:<value>` tag. Keying namespaces by absolute path - the obvious
    thing, since compile() wants unique keys - put
    `C:\\Users\\<name>\\.jmo\\yara-rules\\...` in every finding, leaking local
    filesystem layout into reports, the history database and any shared export.

    The relative stem is both safe and more useful: the pinned bundle is
    organised by category, so this yields `ransomware/Win32_Foo`, and the
    leading segment is real signal about what matched.
    """
    try:
        rel = path.relative_to(rules_root)
    except ValueError:
        rel = Path(path.name)
    return rel.with_suffix("").as_posix()


def compile_rules(
    yara: Any, rule_files: list[Path], rules_root: Path
) -> tuple[Any | None, int, list[Path]]:
    """Compile `rule_files`, skipping the ones this libyara cannot build.

    Returns (compiled Rules or None, compiled count, skipped files).

    A third-party bundle will always contain files a given build rejects - the
    pinned ReversingLabs set is 310 files, and rules referencing modules a build
    lacks (``cuckoo``, ``magic``) fail to compile. yara.compile() over a dict is
    all-or-nothing, so one such file would silently cost every rule, producing a
    confident all-clear. Try the bulk path first because it is much faster, and
    fall back to per-file only to identify what to drop.
    """
    namespaces = {namespace_for(p, rules_root): str(p) for p in rule_files}
    try:
        return yara.compile(filepaths=namespaces), len(rule_files), []
    except yara.Error:
        pass

    good: dict[str, str] = {}
    skipped: list[Path] = []
    for path in rule_files:
        try:
            yara.compile(filepath=str(path))
        except yara.Error as exc:
            skipped.append(path)
            _log(f"yara: skipping unusable rule file {path.name}: {exc}")
            continue
        good[namespace_for(path, rules_root)] = str(path)

    if not good:
        return None, 0, skipped
    try:
        return yara.compile(filepaths=good), len(good), skipped
    except yara.Error as exc:  # pragma: no cover - every file compiled alone
        _log(f"yara: rule set failed to link after filtering: {exc}")
        return None, 0, rule_files


def iter_target_files(target: Path, max_bytes: int) -> tuple[list[Path], int]:
    """Walk `target`, pruning vendored trees. Returns (files, skipped_too_large).

    Pruning happens *during* traversal via the in-place ``dirnames[:]``
    mutation, not by filtering paths afterwards. The post-filter form stats
    every vendored file on the way past, which descended into pnpm symlink
    farms and raised WinError 1920 on Windows while merely timing out on Linux -
    one cause, two symptoms that point nowhere near it (commit ded93df).
    """
    files: list[Path] = []
    too_large = 0
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            try:
                if path.stat().st_size > max_bytes:
                    too_large += 1
                    continue
            except OSError:
                # Broken symlink, race, or permission denied. Not scannable;
                # counted as unreadable rather than silently treated as clean.
                too_large += 1
                continue
            files.append(path)
    return sorted(files), too_large


def match_to_dict(match: Any, path: Path) -> dict[str, Any]:
    """Shape one libyara Match into what yara_adapter._load_yara_internal reads.

    Matched *string identifiers* only, never the matched bytes. A malware rule
    can match on an embedded key or token, and these findings flow into shared
    reports and the history database - the adapter only uses the count and the
    identifiers, so the content buys nothing and leaks something.
    """
    return {
        "rule": match.rule,
        "namespace": match.namespace,
        "tags": [str(t) for t in match.tags],
        "meta": {str(k): v for k, v in dict(match.meta).items()},
        "strings": [str(s.identifier) for s in match.strings],
        "file": str(path),
    }


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="yara_runner",
        description="Scan a tree with libyara and write JSON the yara adapter parses.",
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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    yara = _import_yara()
    if yara is None:
        _log(
            "yara: the yara-python library is not installed for this interpreter "
            f"({sys.executable}), so nothing was scanned. "
            "Install it with: jmo tools install yara"
        )
        return EXIT_ERROR

    rules_root = Path(args.rules)
    if not rules_root.exists():
        _log(
            f"yara: rules path does not exist: {rules_root} - nothing was scanned. "
            "Install the bundled rule set with: jmo tools install yara"
        )
        return EXIT_ERROR

    target = Path(args.target)
    if not target.exists():
        _log(f"yara: target path does not exist: {target} - nothing was scanned")
        return EXIT_ERROR

    rule_files = collect_rule_files(rules_root)
    if not rule_files:
        _log(
            f"yara: no {' or '.join(RULE_SUFFIXES)} files under {rules_root} - nothing was scanned"
        )
        return EXIT_ERROR

    rules, compiled, skipped = compile_rules(yara, rule_files, rules_root)
    if rules is None or compiled == 0:
        _log(
            f"yara: 0 of {len(rule_files)} rule file(s) compiled - nothing was "
            "scanned. Reporting this as a clean scan would be a false all-clear."
        )
        return EXIT_ERROR
    if skipped:
        _log(
            f"yara: compiled {compiled} rule file(s), skipped {len(skipped)} that would not build"
        )

    files, unreadable = iter_target_files(target, args.max_file_bytes)

    matches: list[dict[str, Any]] = []
    errored = 0
    for path in files:
        try:
            for match in rules.match(filepath=str(path), timeout=args.timeout):
                matches.append(match_to_dict(match, path))
        except (yara.Error, OSError) as exc:
            # A single unscannable file must not abort the run, but it must not
            # vanish either. Naming the reason is not decoration: an early
            # version of this loop counted errors without printing them, and
            # every match test failed identically with "1 errored" while the
            # actual cause was Defender blocking the fixture at write time
            # (OSError 22 on a path Path.exists() reported as present).
            errored += 1
            if errored <= MAX_REPORTED_FILE_ERRORS:
                _log(f"yara: could not scan {path}: {exc}")

    scanned = len(files) - errored
    if files and scanned == 0:
        # Every file failed. The findings list is empty for the same reason a
        # clean repository's is, and only this branch can tell them apart.
        _log(
            f"yara: all {len(files)} file(s) failed to scan - nothing was "
            "examined. Reporting this as a clean scan would be a false all-clear."
        )
        return EXIT_ERROR

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(matches, indent=2), encoding="utf-8")

    _log(
        f"yara: scanned {scanned} of {len(files)} file(s) with {compiled} rule "
        f"file(s); {len(matches)} match(es), {unreadable} skipped as too large "
        f"or unreadable, {errored} errored"
    )
    return EXIT_MATCHES if matches else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
