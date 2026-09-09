"""
Utilities for scan jobs.

Centralized utility functions used by scan job modules.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Re-export from core for backward compatibility.
# find_tool/tool_exists live in scripts.core.tool_utils to maintain clean
# dependency layering (core never imports from cli).
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
    profile: str,
    interactive: bool = False,
) -> bool:
    """
    Pre-scan version check with context-aware behavior.

    Checks for version drift between installed tool versions and the pinned
    versions in versions.yaml. Behavior adapts based on context:
    - CLI mode (interactive=False): Log warning, continue
    - Wizard mode (interactive=True): Prompt user before continuing

    Args:
        profile: Scan profile ('fast', 'slim', 'balanced', 'deep')
        interactive: Whether to prompt user for confirmation

    Returns:
        True if scan should proceed, False if user cancelled in interactive mode
    """
    # Import here to avoid circular dependency
    from scripts.cli.tool_manager import ToolManager

    logger = logging.getLogger(__name__)
    manager = ToolManager()
    drift = manager.get_version_drift(profile)

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


# A tool's stderr is unbounded (semgrep and horusec are chatty). Keep the tail,
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


# jmo.yml configures flags per *tool*, but trivy's flag surface is per
# *subcommand*, and JMo drives trivy with four of them (fs, image, config, k8s).
# Measured against trivy 0.70.0: `trivy config` is the only one that rejects
# --no-progress, and it rejects it fatally at argument parsing - so every IaC
# scan died before it started and contributed nothing. All four shipped profiles
# set that flag, so no profile escaped it.
#
# Only value-less flags belong here: dropping one must never orphan a value
# argument. --scanners is accepted by all four subcommands and is not listed.
TRIVY_UNSUPPORTED_FLAGS: dict[str, frozenset[str]] = {
    "config": frozenset({"--no-progress"}),
}


# Directories a JMo tool invocation creates *inside* the tree being scanned, and
# that every other scanner therefore walks unless it is told not to.
#
# `.horusec/<uuid>` is horusec's staging copy of the whole repository. Measured
# against `horusec start --help`: there is no flag to relocate it, so the only
# tractable defence is to exclude it everywhere else. It is worse than a stable
# directory because horusec creates and deletes it *while the other tools run* -
# a scanner that opens a path after horusec removes it records an error, not a
# skip. Measured on juice-shop (Windows, deep profile): semgrep-secrets recorded
# 346 `Unix_error: No such file or directory` errors under `<repo>/.horusec/`,
# and the report's "826 file(s) could not be analysed" warning was mostly those
# paths (#1132).
#
# semgrep-secrets was not the worst of it. Re-parsing the same dogfood run's
# dependency-check reports found 15,944 non-fatal analysis exceptions across
# three repositories - 8499 on jmoadaptivegolf alone - and almost every one of
# jmoadaptivegolf's names a vanished path under `.horusec/<uuid>/`.
SCAN_EXCLUDED_DIRS: tuple[str, ...] = (".horusec",)


# Directories holding code the scanned repository does not own: an installed
# virtualenv, a fetched `node_modules`, a vendored third-party tree. Scanning
# them buries the repo's own findings in dependency noise and costs most of the
# scan's budget. Measured on this repo at 3ffc73a8: 36,705 files on disk to
# analyse 985 tracked ones, and trivy, semgrep and checkov each hitting the
# 300s cap and contributing nothing at all (#1080).
#
# **This is not a new policy.** `_collect_files` has skipped exactly these names
# since #1132, for the two tools that take file arguments. What #1080 measured
# is that the tools taking a *directory* never got the same treatment. Naming
# the list once is what makes the two agree; `_collect_files` reads it from here
# rather than repeating it.
#
# Deliberately absent: `dist`, `build`, `target`, and any tool's output
# directory. Those hold the repository's *own* build output, and a user who
# points JMo at a release tree means it. The general case - honouring
# `.gitignore` - is a larger change than this one and is not what this list is.
VENDORED_DIRS: tuple[str, ...] = (
    ".git",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
)


# Tools for which VENDORED_DIRS is noise. **Not every tool**, which is the whole
# reason this is a set rather than a global: dependency-check and syft exist to
# inventory exactly those trees. #1080 measured 282 of syft's 878 artifacts
# inside `.venv/` and called them "arguably correct for an SBOM" - handing an
# SCA or SBOM tool this list would gut it while reporting success, which is the
# failure shape this project has been bitten by before.
#
# SCAN_EXCLUDED_DIRS has no such carve-out and goes to every tool in
# TOOL_EXCLUSION_FLAG: `.horusec/<uuid>` is JMo's own staging copy of the tree
# being scanned, so it is nobody's subject matter.
VENDOR_NOISE_TOOLS: frozenset[str] = frozenset(
    {"semgrep", "semgrep-secrets", "trivy", "trivy-rbac", "bandit", "checkov"}
)


# bandit's -x is an argparse `default=`, NOT an addition - supplying a value
# replaces upstream's list outright. Its own help text points at the config file
# ("in addition to the excluded paths provided in the config file"), which reads
# like the flag accumulates; it does not. Measured on bandit 1.9.2: with no -x,
# `.tox/vendored.py` is skipped and `.horusec/staged.py` scanned; with
# `-x .horusec` the two swap places. So JMo has to re-supply the defaults
# alongside its own, or excluding one directory silently starts scanning nine
# others - `.tox`, `.eggs` and `*.egg` hold vendored third-party code, so the
# regression would arrive as a flood of findings in code the user does not own.
BANDIT_DEFAULT_EXCLUDED_PATHS: tuple[str, ...] = (
    ".svn",
    "CVS",
    ".bzr",
    ".hg",
    ".git",
    "__pycache__",
    ".tox",
    ".eggs",
    "*.egg",
)


# How each tool spells "skip this directory", as (flag, style). A tool appears
# here only once its flag has been measured against the real binary; an unlisted
# tool gets nothing rather than an argument it would reject at parse time, which
# for trivy and semgrep is fatal (see TRIVY_UNSUPPORTED_FLAGS).
#
# The style cannot be inferred from the flag name: semgrep and dependency-check
# both spell it `--exclude` and want different things - a gitignore-style glob
# where a bare directory name matches at any depth, versus an Ant pattern where
# it does not and `**/<dir>/**` is required.
#
#   "inline"    one `--flag=VALUE` per directory      (semgrep)
#   "separate"  one `--flag **/VALUE` pair per directory (trivy)
#   "regex"     one `--flag VALUE` pair per directory   (checkov)
#   "ant"       one `--flag **/VALUE/**` pair         (dependency-check)
#   "csv"       a single flag with one comma-separated value that REPLACES the
#               tool's own defaults                   (bandit)
#   "glob-csv"  a single flag with one comma-separated value of **/VALUE/**
#               globs, ADDED to the tool's own defaults  (horusec)
#
# **`csv` and `glob-csv` differ on the thing that matters and look identical.**
# bandit's `-x` replaces its defaults, so JMo re-sends them; horusec's `-i`
# accumulates, so re-sending would be noise. Measured on horusec by planting a
# finding under `.vscode/` -- one of its defaults -- and confirming it stayed
# excluded with `-i` supplied. A bare name is also not enough for horusec:
# `-i results` excludes nothing, `-i '**/results/**'` works. That is the
# opposite of checkov, where the bare name is the only form that works.
#
# **trivy and checkov are the sharpest case of the warning above.** Both spell
# it as a repeatable `--flag VALUE` pair, and the value that works is opposite.
#
# trivy 0.74.0, `--skip-dirs`, glob, anchored at the scan root:
#     `node_modules`      skips a root `node_modules`, WALKS `deep/sub/node_modules`
#     `**/node_modules`   skips both
# The `**/` was missing until #1080 and the bug was invisible, because the only
# entry was `.horusec` and horusec stages it at the root of the scanned repo -
# which is trivy's scan root. This repo's own `node_modules` lives at
# `scripts/dashboard/node_modules`, where the bare form is inert.
#
# checkov 3.3.16, `--skip-path`, *regex*, matched against the whole path:
#     `vendor`            skips a root `vendor` AND `a/b/vendor`
#     `**/vendor`         skips NEITHER - and says nothing
# `**` is not a valid regex ("nothing to repeat"), and checkov's
# `filter_ignored_paths` wraps `re.compile` in `except re.error: continue`, so
# an unparseable pattern is dropped with no error and no warning. Its only
# fallback is a plain substring test, which `**/vendor` also fails. Handing
# checkov the trivy spelling produces a flag that looks right, parses, exits 0,
# and excludes nothing - so it gets its own style rather than sharing one.
#
# checkov also ignores `node_modules`, `.terraform`, `.serverless` and every
# dotted directory on its own (IGNORE_HIDDEN_DIRECTORY), so most of what JMo
# sends it is already covered; `vendor` and `venv` are the ones that are not.
# Worth sending anyway - those defaults are checkov's to change, not ours. And
# `filter_ignored_paths` mutates os.walk's `dirs` list in place, so a skip
# prunes the walk rather than filtering results afterwards.
TOOL_EXCLUSION_FLAG: dict[str, tuple[str, str]] = {
    "semgrep": ("--exclude", "inline"),
    "semgrep-secrets": ("--exclude", "inline"),
    "trivy": ("--skip-dirs", "separate"),
    "trivy-rbac": ("--skip-dirs", "separate"),
    "checkov": ("--skip-path", "regex"),
    "dependency-check": ("--exclude", "ant"),
    "bandit": ("-x", "csv"),
    "horusec": ("-i", "glob-csv"),
}


# Per-tool minimum timeouts (seconds) for tools that typically run long. A
# profile default may raise these but never lower them.
#
# Lived in repository_scanner.py, which is why only *repository* scans honoured
# it: the other four scanners had their own copy of `get_tool_timeout` with no
# floor at all. Measured consequence: `zap` carries a 900 s floor and also runs
# on `url` targets, so a `balanced` URL scan gave it the profile's 600 s -- 300 s
# short, a third of its budget -- while the identical tool on a repository
# target got 900 s. Shared here so one definition reaches every target type.
TOOL_TIMEOUT_DEFAULTS: dict[str, int] = {
    "cdxgen": 600,  # 10 min - with --no-install-deps optimization (was 30 min)
    "dependency-check": 1200,  # 20 min - NVD database sync can take a while
    "scancode": 1200,  # 20 min - license scanning large codebases
    "horusec": 900,  # 15 min - multi-language SAST
    "zap": 900,  # 15 min - DAST scanning
    "prowler": 600,  # 10 min - cloud config scanning
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
    the profile default, raised to `TOOL_TIMEOUT_DEFAULTS` if the tool has a
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
TRUFFLEHOG_EXCLUDE_PATTERNS: tuple[str, ...] = (
    r"[\\/]\.git[\\/]",
    r"[\\/]\.jmo[\\/]",
)


def write_trufflehog_exclude_file(
    out_dir: Path, *, results_dir_name: str | None = None
) -> Path:
    """Write TruffleHog's ``--exclude-paths`` file and return its path.

    ``results_dir_name`` adds JMo's own output directory when it sits inside
    the tree being scanned (#1156). trufflehog was one of the two tools measured
    reporting findings out of a previous scan's ``results/`` -- a "secret" in a
    `syft.json` it wrote itself. Spelled with the same separator class as the
    entries below, for the same reason: a bare name would also match a file
    whose name merely contains it.

    ``re.escape`` is **Python's** escaping and these are **Go** (RE2) regexes.
    They agree on what matters here: RE2 accepts an escaped ASCII punctuation
    character, which is all `re.escape` emits. Confirmed in practice on a
    directory name containing a hyphen -- `individual\\-repos` excluded as
    intended. A name holding something RE2 rejects would make trufflehog reject
    the file outright rather than silently ignore it, which is the failure
    direction to prefer.

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
    patterns = list(TRUFFLEHOG_EXCLUDE_PATTERNS)
    if results_dir_name:
        patterns.append(rf"[\\/]{re.escape(results_dir_name)}[\\/]")
    path = out_dir / ".trufflehog-exclude"
    path.write_bytes(("\n".join(patterns) + "\n").encode("utf-8"))
    return path


def filter_trivy_flags(subcommand: str, flags: list[str]) -> list[str]:
    """Drop configured trivy flags that ``subcommand`` does not accept.

    Args:
        subcommand: The trivy subcommand being invoked ("config", "fs", ...).
        flags: Flags from per-tool configuration.

    Returns:
        The flags the subcommand actually accepts.
    """
    unsupported = TRIVY_UNSUPPORTED_FLAGS.get(subcommand)
    if not unsupported:
        return list(flags)

    kept = [f for f in flags if f not in unsupported]
    dropped = [f for f in flags if f in unsupported]
    if dropped:
        logging.getLogger(__name__).warning(
            "trivy %s does not accept %s; dropping so the scan can run. "
            "Configure it under a profile that does not reach this subcommand "
            "if you need it.",
            subcommand,
            ", ".join(dropped),
        )
    return kept


def in_tree_results_name(repo: Path, results_dir: Path) -> str | None:
    """The directory NAME to exclude when ``results_dir`` sits inside ``repo``.

    ``None`` when the results directory is elsewhere -- the CI shape, where
    nothing needs excluding and excluding something would only risk hiding the
    user's own code.

    **A name rather than the path, and that is the measured choice, not the lazy
    one.** Every style in TOOL_EXCLUSION_FLAG already turns a bare directory
    name into its own spelling; that is how one list reaches five grammars. A
    *path* is not portable across them, measured at the pinned versions:

        trivy   --skip-dirs 'out/results'      works
        checkov --skip-path 'out/results'      excludes NOTHING -- it matches a
                                               path built with os.sep, and
                                               upstream's own TODO says so
        checkov --skip-path 'out\\results'      CRASHES (`\\r` is not a valid
                                               escape, and one of the two call
                                               sites compiles unguarded)
        horusec -i 'results'                   excludes NOTHING; it wants a glob

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

    Always JMo's own in-tree scratch (SCAN_EXCLUDED_DIRS), which is nobody's
    subject matter; plus VENDORED_DIRS for the tools that read the repository's
    own code rather than inventory its dependencies (VENDOR_NOISE_TOOLS); plus
    the results directory when it resolves inside the tree being scanned, which
    is JMo's own output and belongs to no tool (#1156).

    The results directory goes to **every** tool with a flag, not just
    VENDOR_NOISE_TOOLS. The carve-out below exists because a vendored tree is
    dependency-check's and syft's subject matter; JMo's own output is nobody's.

    Order is stable and duplicates are dropped, so a name appearing in both
    lists is passed once.
    """
    names = list(SCAN_EXCLUDED_DIRS)
    if tool in VENDOR_NOISE_TOOLS:
        names.extend(d for d in VENDORED_DIRS if d not in names)
    if results_dir_name and results_dir_name not in names:
        names.append(results_dir_name)
    return tuple(names)


def tool_exclusion_flags(
    tool: str, *, results_dir_name: str | None = None
) -> list[str]:
    """Flags that keep ``tool`` out of directories it should not be reading.

    Six tools, five spellings, and they are not interchangeable - see
    TOOL_EXCLUSION_FLAG for what each style means and why the style cannot be
    read off the flag name.

    Returns an empty list for any tool not in TOOL_EXCLUSION_FLAG, so adding a
    scanner never risks handing it an argument it would reject.
    """
    entry = TOOL_EXCLUSION_FLAG.get(tool)
    if entry is None:
        return []
    flag, style = entry
    dirs = excluded_dirs_for(tool, results_dir_name=results_dir_name)
    if style == "csv":
        # bandit's -x REPLACES its defaults, so they have to be re-sent. Its
        # defaults are bare names and bandit matches them itself, so the `**/`
        # the other styles need is not applied here.
        merged = list(BANDIT_DEFAULT_EXCLUDED_PATHS)
        merged.extend(d for d in dirs if d not in merged)
        return [flag, ",".join(merged)]
    if style == "inline":
        return [f"{flag}={d}" for d in dirs]
    if style == "ant":
        return [arg for d in dirs for arg in (flag, f"**/{d}/**")]
    if style == "glob-csv":
        # horusec: ONE flag, comma-separated, and the values must be globs --
        # a bare `results` excludes nothing (measured). Unlike bandit's `-x`
        # this ADDS to horusec's own defaults rather than replacing them:
        # verified by planting a finding under `.vscode/` (one of the defaults)
        # and watching it stay excluded with `-i` supplied. So the defaults are
        # deliberately NOT re-sent here.
        #
        # This hands horusec `**/.horusec/**` -- its OWN staging copy of the
        # tree. Measured safe: a repository with one planted secret reports it
        # identically with and without that flag (n=1, same file). horusec
        # analyses the staging copy internally and reports paths in the real
        # tree, so excluding the directory does not make it inert. Worth having
        # measured rather than assumed: an exclusion that silences the tool
        # sending it is the silent-zero shape this project keeps meeting.
        return [flag, ",".join(f"**/{d}/**" for d in dirs)]
    if style == "regex":
        # checkov: a bare name already matches at any depth, and `**/` would
        # not compile as a regex - it is dropped silently. See above.
        return [arg for d in dirs for arg in (flag, d)]
    # "separate" - the `**/` is what makes a nested directory match at all.
    return [arg for d in dirs for arg in (flag, f"**/{d}")]


# The key a scanner's status map carries its not-attempted tools under.
# `__`-prefixed by the same convention as `__attempts__`: every consumer of the
# map already skips those, so adding this one cannot make an existing reader
# mistake it for a tool.
NOT_ATTEMPTED_KEY = "__not_attempted__"

# Why a tool was never executed. Two reasons, because they mean different
# things to whoever reads the scan: one is a gap in the environment the user can
# close, the other is a correct decision about this target. Both are still
# "did not run", which is the distinction #825 is about, and both were recorded
# as a success before it.
NOT_ATTEMPTED_MISSING = "not installed"
NOT_ATTEMPTED_NOTHING_APPLICABLE = "nothing for it to scan"


def record_not_attempted(
    statuses: dict, tool: str, reason: str = NOT_ATTEMPTED_MISSING
) -> None:
    """Record that `tool` never ran, distinctly from having run and failed.

    Under `--allow-missing-tools` every scanner used to write
    ``statuses[tool] = True`` beside its stub -- the same value a tool that ran
    successfully gets. So a secret scanner that was never executed produced an
    empty result and a success, which is the `zero-secrets` shape: a policy
    certifying "no secrets" because nothing looked (#825).

    `False` is the honest boolean -- the tool did not run, so it did not
    succeed -- and the tool is also listed under `NOT_ATTEMPTED_KEY`, so
    `classify_target_outcome` can leave it out of the vote entirely rather than
    counting it as a failure. Those are different things: a target where one
    tool ran cleanly and two were never installed has not partially failed.

    On a normal host the pre-flight removes missing tools before the scanners
    run, so this fires only when `find_tool` disagrees with it at scan time.
    **In a container the pre-flight is skipped entirely** (`jmo.py` gates it on
    `DOCKER_CONTAINER`), so this is the normal path there -- a `deep` image is
    expected to be missing the four MANUAL_INSTALL_TOOLS.
    """
    statuses[tool] = False
    statuses.setdefault(NOT_ATTEMPTED_KEY, {})[tool] = reason


def not_attempted_tools(
    statuses: Mapping[str, Any] | None, *, reason: str | None = None
) -> list[str]:
    """The tools a target never ran, sorted. Empty when everything was tried.

    Takes a `Mapping` rather than a `dict` because every caller reads a status
    map it does not own -- `classify_target_outcome` and both progress
    reporters annotate theirs as `Mapping`.

    `reason` narrows to one of NOT_ATTEMPTED_MISSING / _NOTHING_APPLICABLE.
    Without it the two are indistinguishable here, which is how the distinction
    `record_not_attempted` records got lost on the way to the screen: three of
    the four callers only need membership -- to keep a skipped tool out of the
    failed-tools vote -- so nothing noticed that the fourth, the STUBBED
    warning, was telling users "nothing looked, which is not the same as
    finding nothing" about tools that correctly had nothing to look at (#1081).
    """
    if not statuses:
        return []
    recorded = statuses.get(NOT_ATTEMPTED_KEY) or {}
    if not isinstance(recorded, dict):
        return []
    if reason is None:
        return sorted(recorded)
    return sorted(tool for tool, why in recorded.items() if why == reason)


def write_stub(tool: str, out_path: Path) -> None:
    """Write empty JSON stub for missing tool."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stubs = {
        "trufflehog": [],
        "semgrep": {"results": []},
        "noseyparker": {"matches": []},
        "syft": {"artifacts": []},
        "trivy": {"Results": []},
        "grype": {"matches": []},
        "hadolint": [],
        "checkov": {"results": {"failed_checks": []}},
        "bandit": {"results": []},
        "zap": {"site": []},
        "nuclei": "",  # NDJSON format - empty string for empty file
        "falco": [],
        "afl++": {"crashes": []},
    }
    payload = stubs.get(tool, {})
    if isinstance(payload, str):
        # For NDJSON tools like nuclei, write empty string
        out_path.write_text(payload, encoding="utf-8")
    else:
        # For JSON tools, write JSON-encoded stub
        out_path.write_text(json.dumps(payload), encoding="utf-8")
