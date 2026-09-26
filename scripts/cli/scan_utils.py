"""
Utilities for scan jobs.

Centralized utility functions used by scan job modules.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Re-exported from core, which never imports from cli: find_tool/tool_exists
# live in scripts.core.tool_utils, the per-tool declarations in
# scripts.core.tool_descriptors.
from scripts.core.tool_descriptors import (  # noqa: F401
    DESCRIPTORS,
    TRIVY_UNSUPPORTED_FLAGS,
    VENDORED_DIRS,
    ExclusionStyle,
    filter_trivy_flags,
)
from scripts.core.tool_utils import (  # noqa: F401
    TOOL_INSTALL_HINTS,
    clear_tool_warnings,
    find_tool,
    tool_exists,
)

if TYPE_CHECKING:  # pragma: no cover - annotation only
    # Deferred: core must stay importable without cli, and this is the only
    # reference to it here.
    from scripts.core.tool_runner import ToolResult


def _run_inline_tool_update(drift_list: list[dict]) -> bool:
    """Run tool updates inline during wizard flow.

    Args:
        drift_list: List of drift dicts with 'tool' key for tools to update

    Returns:
        True if updates succeeded, False otherwise
    """
    if not drift_list:
        return True

    try:
        from scripts.cli.tool_installer import ToolInstaller

        installer = ToolInstaller()

        tools_to_update = [d["tool"] for d in drift_list]
        total = len(tools_to_update)
        success_count = 0
        fail_count = 0

        for i, tool_name in enumerate(tools_to_update, 1):
            print(f"  [{i}/{total}] Updating {tool_name}...", end=" ", flush=True)
            result = installer.install_tool(tool_name, force=True)
            if result.success:
                print(f"OK ({result.version_installed or 'installed'})")
                success_count += 1
            else:
                print(f"FAILED ({result.message})")
                fail_count += 1

        print(f"\nUpdate complete: {success_count} succeeded, {fail_count} failed")
        return fail_count == 0

    except Exception as e:
        logging.getLogger(__name__).error(f"Update failed: {e}")
        return False


def check_version_drift_before_scan(
    tools: Collection[str],
    interactive: bool = False,
) -> bool:
    """
    Pre-scan version check with context-aware behavior.

    Checks for version drift between installed tool versions and the pinned
    versions in versions.yaml. Behavior adapts based on context:
    - CLI mode (interactive=False): Log warning, continue
    - Wizard mode (interactive=True): Prompt user before continuing

    Args:
        tools: The tools the scan will run
        interactive: Whether to prompt user for confirmation

    Returns:
        True if scan should proceed, False if user cancelled in interactive mode
    """
    # Import here to avoid circular dependency
    from scripts.cli.tool_manager import ToolManager

    logger = logging.getLogger(__name__)
    manager = ToolManager()
    drift = manager.get_version_drift(tools)

    if not drift:
        return True  # All versions match

    # Categorize drift by direction
    ahead = [d for d in drift if d.get("direction") == "ahead"]
    behind = [d for d in drift if d.get("direction") == "behind"]
    unknown = [d for d in drift if d.get("direction") == "unknown"]

    # Log categorized drift
    if ahead:
        logger.info(
            f"{len(ahead)} tool(s) AHEAD of expected (newer versions installed):"
        )
        for d in ahead:
            logger.info(f"  {d['tool']}: {d['installed']} > {d['expected']}")

    if behind:
        level = logging.WARNING
        critical_behind = [d for d in behind if d["critical"]]
        if critical_behind:
            level = logging.ERROR
        logger.log(
            level, f"{len(behind)} tool(s) BEHIND expected (update recommended):"
        )
        for d in behind:
            marker = " [CRITICAL]" if d["critical"] else ""
            logger.log(
                level, f"  {d['tool']}: {d['installed']} < {d['expected']}{marker}"
            )

    if unknown:
        logger.warning(f"{len(unknown)} tool(s) with unknown version status:")
        for d in unknown:
            marker = " [CRITICAL]" if d["critical"] else ""
            # Clarify what "unknown" means
            if d["installed"] is None:
                status = "version detection failed"
            else:
                status = f"installed={d['installed']}"
            logger.warning(f"  {d['tool']}: {status} expected={d['expected']}{marker}")

    if interactive:
        # Wizard mode - improved display with consolidated info
        print(f"\n{'─' * 50}")
        print(f"Version Status ({len(drift)} tool(s) with differences):")

        if ahead:
            print(f"\n  ✓ {len(ahead)} ahead (newer installed - OK for security):")
            for d in ahead[:3]:
                print(f"    {d['tool']}: {d['installed']} > {d['expected']}")
            if len(ahead) > 3:
                print(f"    ... and {len(ahead) - 3} more")

        if behind:
            print(f"\n  ⚠ {len(behind)} behind (older - update recommended):")
            for d in behind:
                marker = " [CRITICAL]" if d["critical"] else ""
                print(f"    {d['tool']}: {d['installed']} < {d['expected']}{marker}")

        if unknown:
            print(f"\n  ? {len(unknown)} unknown (version detection failed):")
            for d in unknown:
                # Explain what unknown means
                explanation = (
                    "binary found, but --version parsing failed"
                    if d["installed"] is None
                    else f"got {d['installed']}"
                )
                print(f"    {d['tool']}: {explanation}")

        print(f"\n{'─' * 50}")

        # Only prompt if there are concerning issues (behind or critical unknown)
        critical_behind = [d for d in behind if d["critical"]]
        if not behind and not critical_behind:
            # Just ahead or unknown (non-critical) - auto-continue
            print("No critical version issues. Continuing with scan...")
            return True

        print("\nThis may affect scan reproducibility.\n")
        print("Options:")
        print("  [1] Continue anyway (recommended if versions are close)")
        print("  [2] Update outdated tools first")
        print("  [3] Cancel scan")

        try:
            choice = input("\nChoice [1]: ").strip() or "1"
            if choice == "3":
                print("Scan cancelled.")
                return False
            if choice == "2":
                # Run update inline and continue
                print("\nUpdating tools...")
                updated = _run_inline_tool_update(behind + unknown)
                if updated:
                    print("\nTools updated. Continuing with scan...\n")
                    return True
                else:
                    print(
                        "\nUpdate failed or cancelled. Continuing with current versions..."
                    )
                    return True
            # Default: continue
            print("Continuing with current tool versions...")
            return True
        except (KeyboardInterrupt, EOFError):
            print("\nScan cancelled.")
            return False
    else:
        # CLI mode - warn and continue
        if behind:
            logger.warning("Run 'jmo tools update' to synchronize versions")
        return True


# A tool's stderr is unbounded (semgrep is chatty). Keep the tail,
# where the fatal message is, rather than the head, where the banner is.
STDERR_TAIL_CHARS = 500


def report_tool_failure(result: ToolResult, reason: str) -> None:
    """State, on a durable stream, that a tool delivered no findings.

    Every scan job's results loop used to set ``statuses[tool] = False`` and
    discard ``result.error_message``. The only remaining trace was a ``x`` in
    the Rich progress display, which a non-TTY run - CI, cron, a detached scan -
    never renders at all. Measured on bridgecrewio/terragoat with the ``deep``
    profile: prowler, yara and dependency-check each failed leaving no record on
    any stream, while the scan exited 0 and the policy gate passed on the
    resulting empty finding set.

    Which tools land here is platform-dependent (dependency-check is silent on
    Windows and honest on Linux; noseyparker is the reverse), so this cannot be
    left to per-tool handling.

    It lives here, beside ``write_stub``, rather than as a private copy in each
    of the five scan jobs. Four modules each growing a private copy of one
    helper is the defect ``tests/cross_platform/test_encoding_drift_guard.py``
    exists to prevent; the reasoning is not specific to encoding.
    """
    logger = logging.getLogger(__name__)
    detail = result.error_message or f"status={result.status}"

    # error_message says what happened; stderr says why. For a non-zero exit it
    # is only "exited with return code 2", and ToolRunner captures the tool's
    # stderr into the result and nothing reads it - so the diagnosis is
    # collected and then dropped one line short of the log. yara exiting 2
    # writes "0 of 310 rule file(s) compiled - nothing was scanned" there;
    # without this the operator sees the code and never the cause.
    tail = (result.stderr or "").strip()
    if tail:
        if len(tail) > STDERR_TAIL_CHARS:
            tail = "..." + tail[-STDERR_TAIL_CHARS:]
        detail = f"{detail}; stderr: {tail}"

    logger.error(
        "%s: %s - it did NOT contribute findings to this scan (%s)",
        result.tool,
        reason,
        detail,
    )


# The per-tool tables below are derived from `tool_descriptors.DESCRIPTORS`,
# where each tool's exclusion style, vendored tier, timeout floor and stub
# shape are declared and justified. They keep their names because the scan
# jobs' helpers and the tests read them.

# Tools for which VENDORED_DIRS is noise: the source readers and the secret
# scanner. **Not every tool**: syft and grype exist to inventory exactly those
# trees (#1205) - #1080 measured 282 of syft's 878 artifacts inside `.venv/`.
VENDOR_NOISE_TOOLS: frozenset[str] = frozenset(
    name
    for name, d in DESCRIPTORS.items()
    if "repo" in d.target_types and d.excluded_vendored == VENDORED_DIRS
)

# How each tool spells "skip this directory" as (flag, style), for the styles
# that are a command-line flag. See `ExclusionStyle` for why the style cannot be
# read off the flag's name: trivy and checkov take the same `--flag VALUE` shape
# and the working value is opposite.
TOOL_EXCLUSION_FLAG: dict[str, tuple[str, str]] = {
    name: (d.exclusion_flag, d.exclusion_style.value)
    for name, d in DESCRIPTORS.items()
    if d.exclusion_flag
    and d.exclusion_style
    in (
        ExclusionStyle.INLINE,
        ExclusionStyle.INLINE_REGEX,
        ExclusionStyle.SEPARATE,
        ExclusionStyle.REGEX,
    )
}

# Per-tool minimum timeouts (seconds). A configured default may raise these but
# never lower them; an explicit `per_tool.<tool>.timeout` wins outright. One
# definition for every target type: when each scanner had its own copy, zap got
# its 900 s floor on a repository and the 600 s default on a URL.
TOOL_TIMEOUT_DEFAULTS: dict[str, int] = {
    name: d.timeout_floor for name, d in DESCRIPTORS.items() if d.timeout_floor
}


# Flags JMo passes itself to control **where a tool writes and in what format**.
# The adapter contract depends on both: `normalize_and_report` globs for a file
# at a path JMo chose and parses it as JSON.
#
# A `per_tool.<tool>.flags` entry repeating one of these wins, because JMo splices
# user flags in *after* its own and a scalar flag is last-one-wins. The tool then
# writes something the adapter cannot read, the file exists so the run grades as
# success, and the findings are gone. Measured on #822: `flags: ["-f","table"]`
# took a trivy target from **2 findings to 0**, `rc=0`, nothing on any stream.
#
# Derived from what the scanners actually pass rather than guessed:
#     git grep -oE '"(-o|--output|-f|--format|...)"' scripts/cli/scan_jobs/
#
# Deliberately narrow. Repeatable flags are **not** listed: `--scanners` unions
# rather than replaces (measured against trivy 0.70.0), and dropping a legitimate
# repeated `--exclude` would break working configs. Only the flags that decide
# whether the output is readable at all belong here.
RESERVED_OUTPUT_FLAGS: frozenset[str] = frozenset(
    {
        "-o",
        "--output",
        "--out",
        "--output-filename",
        "-f",
        "--format",
        "--output-formats",
    }
)


def tool_timeout(per_tool_config: Mapping[str, Any], tool: str, default: int) -> int:
    """Resolve one tool's timeout.

    Precedence: an explicit `per_tool.<tool>.timeout` wins outright; otherwise
    the configured default, raised to `TOOL_TIMEOUT_DEFAULTS` if the tool has a
    floor.

    Shared by all five scanners. It used to be copied into each, and only
    `repository_scanner`'s copy applied the floor.
    """
    tool_cfg = per_tool_config.get(tool, {})
    if isinstance(tool_cfg, dict):
        override = tool_cfg.get("timeout")
        if isinstance(override, int) and override > 0:
            return override
    return max(default, TOOL_TIMEOUT_DEFAULTS.get(tool, 0))


def tool_flags(per_tool_config: Mapping[str, Any], tool: str) -> list[str]:
    """Return a tool's configured extra flags, minus any JMo must own.

    Shared by all five scanners, which each carried an identical copy that did
    no filtering.

    A dropped flag takes its **value** with it. Removing only the flag from
    `["-f", "table"]` would leave a bare `table` in the argv, and trivy reads a
    bare word as a scan target -- strictly worse than the collision being
    fixed. `--format=json` is handled too, since there the value is not a
    separate token.
    """
    tool_cfg = per_tool_config.get(tool, {})
    if not isinstance(tool_cfg, dict):
        return []
    raw = tool_cfg.get("flags", [])
    if not isinstance(raw, list):
        return []
    flags = [str(f) for f in raw]

    kept: list[str] = []
    dropped: list[str] = []
    i = 0
    while i < len(flags):
        token = flags[i]
        if token.split("=", 1)[0] not in RESERVED_OUTPUT_FLAGS:
            kept.append(token)
            i += 1
            continue

        dropped.append(token)
        # `--format=json` carries its value inline; `-f json` does not. Only
        # consume a following token when it is a value rather than the next flag.
        if "=" not in token and i + 1 < len(flags) and not flags[i + 1].startswith("-"):
            dropped.append(flags[i + 1])
            i += 1
        i += 1

    if dropped:
        logging.getLogger(__name__).warning(
            "Ignoring %s flag(s) for %s that JMo must control -- they decide "
            "where it writes and in what format, and the report phase cannot "
            "read the output otherwise: %s",
            len(dropped),
            tool,
            " ".join(dropped),
        )
    return kept


#: Paths TruffleHog must not walk in filesystem mode, as newline-separated Go
#: regexes for its ``--exclude-paths`` file.
#:
#: ``.git/`` - a secret reported at ``.git/objects/03/f8eab...`` or
#: ``.git/logs/HEAD`` names no commit and no source file, so nobody can act on
#: it, and the reflog's 40-hex commit ids trip keyword-plus-40-character
#: detectors as Cloudflare tokens. Measured across the 2026-09-02 dogfood: 41
#: findings under ``.git/`` - 12 on jmoadaptivegolf (4 CloudflareApiToken, 8
#: CloudflareGlobalApiKey), 22 on jmo-security-repo, 7 on BetHedgeSlider.
#:
#: ``.jmo/`` - JMo's own state directory. ``history.db`` stores raw findings, so
#: scanning it re-reports every secret JMo has ever recorded, and each scan
#: feeds the next. Measured on jmo-security-repo: **394 of 773 findings, 51% of
#: the total** - against the 12 the issue estimated.
#:
#: The separator character class is load-bearing, not decoration. A bare
#: ``\.git`` is a substring match, and TruffleHog then also skips
#: ``.github/workflows/*.yml`` - measured on a tree holding a secret in each -
#: which is exactly where real deployment credentials live (#1134).
#:
#: ``(^|...)`` because git mode reports repository-relative paths
#: (``results/creds.txt``): the old ``[\\/]results[\\/]`` excluded a nested
#: ``results/`` and missed a root one there, while this form works in both
#: modes (measured 2026-09-25, trufflehog 3.97.1).
TRUFFLEHOG_EXCLUDE_PATTERNS: tuple[str, ...] = (
    r"(^|[\\/])\.git[\\/]",
    r"(^|[\\/])\.jmo[\\/]",
)


#: RE2's metacharacters. Python's ``re.escape`` is not an RE2 escaper: it also
#: escapes a space as ``\ ``, which is not a valid RE2 escape, and a scan root
#: or results directory can hold a space.
_RE2_SPECIAL = frozenset("\\.+*?()|[]{}^$")


def re2_escape(text: str) -> str:
    """``text`` as a literal inside a Go (RE2) regex: its metacharacters only."""
    return "".join("\\" + c if c in _RE2_SPECIAL else c for c in text)


def segment_regex(name: str) -> str:
    """A regex matching ``name`` as a whole path segment, at any depth."""
    return rf"(^|[\\/]){re2_escape(name)}([\\/]|$)"


def trufflehog_exclude_pattern(name: str, root: str | None = None) -> str:
    """One directory name as a trufflehog ``--exclude-paths`` regex.

    With ``root`` (filesystem mode) the pattern is anchored below it.
    trufflehog matches each pattern against the scan root's own path as well,
    so ``(^|[\\/])vendor[\\/]`` excluded every file of a repository that lives
    under a ``vendor`` directory: measured 2026-09-25, a planted secret found
    with no pattern and not at all with that one. ``root`` must be the exact
    string trufflehog is given. Without it, for git mode's repository-relative
    paths, the unanchored form.
    """
    tail = rf"{re2_escape(name)}[\\/]"
    if root is None:
        return rf"(^|[\\/]){tail}"
    return rf"^{re2_escape(root)}[\\/](.*[\\/])?{tail}"


def write_trufflehog_exclude_file(
    out_dir: Path, *, results_dir_name: str | None = None, root: str | None = None
) -> Path:
    """Write TruffleHog's ``--exclude-paths`` file and return its path.

    The vendored directories are in it (Phase 3: the secret scanner joins the
    tier - on a real Next.js application trufflehog took 295.8 s and returned
    253 findings, 222 of them in ``node_modules``; 18.8 s and 31 without), and
    ``results_dir_name`` adds JMo's own output directory when it sits inside
    the tree being scanned (#1156): trufflehog was one of the two tools measured
    reporting findings out of a previous scan's ``results/``.

    These are **Go** (RE2) regexes, so names and ``root`` are escaped with
    ``re2_escape``, not Python's ``re.escape`` (which escapes a space as
    ``\\ ``). ``root`` anchors every pattern below the scan root; see
    ``trufflehog_exclude_pattern``. Measured on Windows with a root holding a
    space, a hyphen and parentheses: the root's files were read and a nested
    ``vendor/`` was excluded.

    ``write_bytes`` rather than ``write_text``: the latter opens with
    ``newline=None`` and would emit CRLF on Windows. TruffleHog splits the file
    on newlines, so a trailing carriage return would ride along inside each
    regex.

    **The leading dot is load-bearing.** ``out_dir`` holds two kinds of thing:
    a tool's output, always ``<tool>.json``, and the scan phase's own scratch,
    which is dot-prefixed - ``.afl_corpus``, ``.afl_output``,
    ``.noseyparker_datastore``. This file shipped as ``trufflehog-exclude.txt``
    and matched neither, so
    ``test_scan_profile_include_exclude_only_scans_included`` read it as a tool
    that ran despite being excluded, and the 2026-09-04 nightly failed with
    ``['trufflehog-exclude.txt'] == []``.

    That test only fails where trufflehog resolves through ``PATH``. It passes
    on a machine whose trufflehog lives in ``~/.jmo/bin``, because the test
    patches ``Path.home()`` to its tmp dir, which hides it and takes the stub
    branch instead.
    """
    names = (
        ".git",
        ".jmo",
        *excluded_dirs_for("trufflehog", results_dir_name=results_dir_name),
    )
    patterns = list(dict.fromkeys(trufflehog_exclude_pattern(n, root) for n in names))
    path = out_dir / ".trufflehog-exclude"
    path.write_bytes(("\n".join(patterns) + "\n").encode("utf-8"))
    return path


def in_tree_results_name(repo: Path, results_dir: Path) -> str | None:
    """The directory NAME to exclude when ``results_dir`` sits inside ``repo``.

    ``None`` when the results directory is elsewhere -- the CI shape, where
    nothing needs excluding and excluding something would only risk hiding the
    user's own code.

    **A name rather than the path, and that is the measured choice, not the lazy
    one.** Every style in TOOL_EXCLUSION_FLAG already turns a bare directory
    name into its own spelling; that is how one list reaches every grammar. A
    *path* is not portable across them, measured at the pinned versions:

        trivy   --skip-dirs 'out/results'      works
        checkov --skip-path 'out/results'      excludes NOTHING -- it matches a
                                               path built with os.sep, and
                                               upstream's own TODO says so
        checkov --skip-path 'out\\results'      CRASHES (`\\r` is not a valid
                                               escape, and one of the two call
                                               sites compiles unguarded)

    The price is over-breadth: a repository whose own source lives in a second
    directory of the same name loses it too. Bounded deliberately -- this
    returns a name only when JMo's output really is inside the tree being
    scanned, so `--results-dir` outside the repo (the usual CI setup) adds
    nothing at all. The precise skip is applied on the Python side instead,
    where there is no pattern language to get wrong; see `_iter_repo_files`.

    The LAST segment, not the first: for `<repo>/out/results` the directory that
    holds JMo's output is `results`, and every style matches a name at any
    depth. Excluding `out` would take the user's whole `out/` tree with it.
    """
    try:
        rel = results_dir.resolve().relative_to(repo.resolve())
    except (ValueError, OSError):
        # ValueError: not inside the tree. OSError: an unresolvable path -- a
        # broken symlink or a permission error on a parent. Neither is a reason
        # to start excluding directories.
        return None
    if not rel.parts:
        # results_dir IS the repository. Excluding it would exclude everything;
        # a pathological configuration, but silently scanning nothing is the
        # failure mode this project has been bitten by most.
        return None
    return rel.parts[-1]


def excluded_dirs_for(
    tool: str, *, results_dir_name: str | None = None
) -> tuple[str, ...]:
    """Directory names ``tool`` should be told to skip.

    The VENDORED_DIRS entries its descriptor declares - all of them for the
    tools that read the repository's own code, none for syft, a virtualenv only
    for grype - plus the results directory when it resolves inside the tree
    being scanned, which is JMo's own output and belongs to no tool (#1156).

    Order is stable and duplicates are dropped, so a name appearing in both
    lists is passed once.
    """
    descriptor = DESCRIPTORS.get(tool)
    names: list[str] = list(descriptor.excluded_vendored) if descriptor else []
    if results_dir_name and results_dir_name not in names:
        names.append(results_dir_name)
    return tuple(names)


def tool_exclusion_flags(
    tool: str, *, results_dir_name: str | None = None
) -> list[str]:
    """Flags that keep ``tool`` out of directories it should not be reading.

    Rendered in the tool's own spelling (``ExclusionStyle``); they are not
    interchangeable. Empty for a tool whose exclusion is not a flag: the
    trufflehog pattern file, and the walk that picks hadolint's and
    shellcheck's files.
    """
    entry = TOOL_EXCLUSION_FLAG.get(tool)
    if entry is None:
        return []
    flag, style = entry
    dirs = excluded_dirs_for(tool, results_dir_name=results_dir_name)
    if style == ExclusionStyle.INLINE:
        return [f"{flag}={d}" for d in dirs]
    if style == ExclusionStyle.INLINE_REGEX:
        return [f"{flag}={segment_regex(d)}" for d in dirs]
    if style == ExclusionStyle.REGEX:
        # checkov: a bare name already matches at any depth, and `**/` would
        # not compile as a regex - it is dropped silently.
        return [arg for d in dirs for arg in (flag, d)]
    # SEPARATE: the `**/` is what makes a nested directory match at all, and
    # syft and grype reject a bare name outright.
    return [arg for d in dirs for arg in (flag, f"**/{d}")]


def write_stub(tool: str, out_path: Path) -> None:
    """Write ``tool``'s empty-result shape to ``out_path``.

    For a tool that applied to the target and did not run (not installed, or
    nothing of its kind in the tree) or timed out. The accounting row, not this
    file, is the record of why: an empty stub reads exactly like a clean run.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = DESCRIPTORS.get(tool)
    payload = descriptor.stub if descriptor else {}
    if isinstance(payload, str):
        # For NDJSON tools like nuclei, write empty string
        out_path.write_text(payload, encoding="utf-8")
    else:
        # For JSON tools, write JSON-encoded stub
        out_path.write_text(json.dumps(payload), encoding="utf-8")
