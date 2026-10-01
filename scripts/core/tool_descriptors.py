"""Every scanner in the matrix, declared once (v2.0.0 Phase 3).

A `ToolDescriptor` says, for one tool: which target types it reads and the
command line for each, what content it needs before it is worth running, how
it spells "skip this directory", its timeout floor, how to probe its version,
the empty-result shape of its output, and whether its output says how many
files it examined. The six scan jobs iterate this table
(`scripts/cli/scan_jobs/tool_loop.py`); `tool_registry`, `scan_utils` and
`tool_manager` derive their tables from it.

Before this module a tool was spread over eleven tables in four modules and
eighteen hand-written `if "<tool>" in tools:` blocks, and nothing checked that
they agreed. They did not: nuclei was "valid" for GitLab targets while the
GitLab job had no code path for it, and hadolint and shellcheck, with no
Dockerfile or script to read, returned nothing at all instead of a row (#1227).

This module is `core`: it imports nothing from `scripts.cli`. Exclusion
arguments are rendered by the scan loop from each descriptor's declared style
and handed in through `ScanContext`, so a builder only splices them.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import quote

from scripts.core import osv_database
from scripts.core.scan_timings import Reason

logger = logging.getLogger(__name__)

# Directories holding code the scanned repository does not own: an installed
# virtualenv, a fetched `node_modules`, a vendored third-party tree. Scanning
# them buries the repository's own findings in dependency noise and costs most
# of the scan's budget. Measured at 3ffc73a8: 36,705 files on disk to analyse
# 985 tracked ones, and trivy, semgrep and checkov each hitting the 300 s cap
# and contributing nothing (#1080).
#
# Deliberately absent: `dist`, `build`, `target`, and any tool's output
# directory. Those hold the repository's own build output, and a user who
# points JMo at a release tree means it. (semgrep skips `build/` and `dist/`
# anyway, by a built-in list JMo cannot turn off without writing a file into
# the user's tree: docs/KNOWN_LIMITATIONS.md.)
VENDORED_DIRS: tuple[str, ...] = (
    ".git",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
)

# jmo.yml configures flags per *tool*, but trivy's flag surface is per
# *subcommand*. Measured against trivy 0.70.0: `trivy config` is the only one
# that rejects --no-progress, and it rejects it fatally at argument parsing.
# Only value-less flags belong here: dropping one must never orphan a value.
TRIVY_UNSUPPORTED_FLAGS: dict[str, frozenset[str]] = {
    "config": frozenset({"--no-progress"}),
}


def filter_trivy_flags(subcommand: str, flags: Iterable[str]) -> list[str]:
    """Drop configured trivy flags that `subcommand` does not accept."""
    flags = list(flags)
    unsupported = TRIVY_UNSUPPORTED_FLAGS.get(subcommand)
    if not unsupported:
        return flags
    kept = [f for f in flags if f not in unsupported]
    dropped = [f for f in flags if f in unsupported]
    if dropped:
        logger.warning(
            "trivy %s does not accept %s; dropping so the scan can run.",
            subcommand,
            ", ".join(dropped),
        )
    return kept


# A fallback invocation's output file. The scan loop removes every file of this
# shape a tool left in its directory before the tool runs again: their number
# follows the inputs, and the report reads whatever is there.
PART_OUTPUT = "{tool}.part{n}.json"


class ExclusionStyle(StrEnum):
    """How a tool is told to skip a directory. Measured per tool, never guessed.

    The style cannot be inferred from the flag's name. trivy and checkov both
    take a repeatable `--flag VALUE`, and the value that works is opposite:
    trivy's is a glob anchored at the scan root (`**/vendor` for any depth);
    checkov's is a Python regex matched with `re.search` against the whole
    (absolute) path, so a bare name is a substring match everywhere -
    `vendor` also drops `vendor-accounts.tf`, and a repository living under a
    `vendor/` directory scans nothing at all (#1313). checkov's value is
    rendered `[\\/]NAME$`, the name escaped, by `checkov_skip_path_pattern`
    (`scripts/cli/scan_utils.py`) - see that function for why it is not the
    `(^|[\\/])NAME([\\/]|$)` shape trufflehog uses. `**` does not
    compile as a regex at all and is dropped without a word either way. syft
    and grype reject a bare name outright (rc 1: "must start with one of:
    './', '*/', or '**/'"), and `./results` covers only the root copy
    (measured 2026-09-25).
    """

    INLINE = "inline"  # one `--flag=NAME` per directory
    SEPARATE = "separate"  # one `--flag **/NAME` pair per directory
    # One `--flag PATTERN` pair per directory: checkov only. The pattern is
    # `[\\/]NAME$`, the name escaped (`checkov_skip_path_pattern`) - not a
    # bare name (#1313, a substring match) and not `(^|[\\/])NAME([\\/]|$)`
    # (crashes checkov on Windows and on every platform, see that function).
    REGEX = "regex"
    PATTERN_FILE = "pattern_file"  # a generated file of regexes, one flag
    # A generated config file, one flag: gitleaks has no exclude flag at all,
    # only a config's `[[allowlists]] paths`.
    CONFIG_FILE = "config_file"
    WALK = "walk"  # JMo walks the tree and hands the tool its files
    NOT_FILESYSTEM = "not_filesystem"  # reads a URL, never a directory


class FlagGrammar(StrEnum):
    """The parser that reads a tool's command line (#1335).

    It decides which spellings of a reserved flag reach the tool, so a user's
    `per_tool.<tool>.flags` is checked against what that tool will read. One
    list for every tool could not be: grype's `-f` is `--fail-on`, and trivy
    reads `-qftable` as `-q -f table`, which matches no listed token (42
    findings to 0, rc 0, measured). Measured per parser, on the tools named
    beside each.
    """

    PFLAG = "pflag"  # cobra's: trivy, grype, syft, gitleaks
    KINGPIN = "kingpin"  # trufflehog
    CMDLINER = "cmdliner"  # semgrep
    GETOPT = "getopt"  # Haskell's GetOpt: shellcheck
    OPTPARSE_APPLICATIVE = "optparse-applicative"  # hadolint
    ARGPARSE = "argparse"  # checkov (configargparse), JMo's own runners
    CLAP = "clap"  # zizmor
    # Go's flag package and what reads alike: nuclei (goflags), osv-scanner
    # (urfave/cli, measured to read `-format` and reject `-ftable` the same way).
    GO_FLAG = "go-flag"
    ZAP = "zap"  # zap's own: single-dash names, each a whole token

    @property
    def clusters(self) -> bool:
        """Short flags chain and take a value attached: trufflehog reads
        `-jx ex.txt` as `-j -x ex.txt`, zizmor `-qcfile` as `-q -c file`."""
        return self not in (FlagGrammar.GO_FLAG, FlagGrammar.ZAP)

    @property
    def abbreviates(self) -> bool:
        """A long option's unique prefix is that option: checkov reads
        `--output-f=x` as `--output-file-path`, shellcheck `--fo=tty` as
        `--format=tty`. semgrep, hadolint and zizmor reject `--outp` and
        `--form` themselves."""
        return self in (FlagGrammar.GETOPT, FlagGrammar.ARGPARSE)

    @property
    def either_dash(self) -> bool:
        """`-name` and `--name` are one flag (osv-scanner's `-format table`),
        and nothing chains: `-ftable` is "flag provided but not defined"."""
        return self is FlagGrammar.GO_FLAG

    @property
    def negates(self) -> bool:
        """`--no-X` sets X, so it repeats a flag JMo passes (`--no-json`:
        "flag 'json' cannot be repeated")."""
        return self is FlagGrammar.KINGPIN

    @property
    def refuses_repeats(self) -> bool:
        """A flag given twice is an error, so every flag JMo passes is the
        row's: trufflehog "flag 'exclude-paths' cannot be repeated", zizmor
        "the argument '--offline' cannot be used multiple times" (rc 2),
        semgrep "option '--json' cannot be repeated". A list option (semgrep's
        `--config`, `--exclude`) is the exception. The others take a repeat:
        zap ran `-cmd -cmd`, hadolint printed a second `-f json` report."""
        return self in (FlagGrammar.KINGPIN, FlagGrammar.CLAP, FlagGrammar.CMDLINER)


class Reserved(StrEnum):
    """Why a flag is JMo's and not the user's: what its refusal says (#1335)."""

    OUTPUT = (
        "it decides where the tool writes or what it writes, which the report "
        "phase reads"
    )
    # JMo passes it, and the parser refuses it twice or the user's replaces it.
    PASSED = "JMo already passes it, and a second one fails the run or replaces JMo's"
    EXIT_CODE = (
        "it sets the tool's exit code, and a code the row does not accept fails "
        "a run that worked. JMo's own --fail-on (jmo ci, jmo report) sets the "
        "failure threshold"
    )
    TARGET = "it would point the scan at another target"
    VERIFY = (
        "JMo already passes it, and trufflehog refuses it twice. Set "
        "per_tool.trufflehog.verify: true to verify secrets"
    )
    DOWNLOAD = "it downloads during the scan. `jmo tools update` fetches the databases"


def _reserve(**why: Iterable[str]) -> dict[str, Reserved]:
    """A row's `reserved_flags`, grouped by the `Reserved` member named:
    `_reserve(OUTPUT=("-f", "--format"), EXIT_CODE=("--exit-code",))`."""
    return {flag: Reserved[name] for name, flags in why.items() for flag in flags}


@dataclass(frozen=True)
class ScanContext:
    """What one tool's builder and trigger see for one target."""

    tool: str
    target_type: str
    target: Any  # Path (repo, iac), str (image, url), Mapping (k8s)
    out_dir: Path
    binary: str = ""
    # `per_tool.<tool>.flags` reach the tree's run and `history_flags` git
    # history's: each mode rejects flags the other needs (#1327, measured:
    # trufflehog filesystem exits 1 on `--since-commit`, gitleaks git 126 on
    # `--follow-symlinks`).
    flags: tuple[str, ...] = ()
    history_flags: tuple[str, ...] = ()
    tool_config: Mapping[str, Any] = field(default_factory=dict)
    exclusion_args: tuple[str, ...] = ()
    # The same exclusions for a git-history invocation, where they differ:
    # trufflehog's git mode reports repository-relative paths, so its patterns
    # cannot be anchored below the scan root (G1).
    history_exclusion_args: tuple[str, ...] = ()
    # Whether this target's git history is read (`read_history`, once per
    # target by the scan loop).
    history: bool = False
    files: tuple[str, ...] = ()
    iter_files: Callable[[], Iterator[Path]] | None = None

    @property
    def output(self) -> Path:
        return self.out_dir / f"{self.tool}.json"

    @property
    def history_output(self) -> Path:
        """A git-history invocation's file. The report maps an output to its
        tool by the name before the first dot, so it reaches the same adapter."""
        return self.out_dir / f"{self.tool}.git.json"

    def part_output(self, n: int) -> Path:
        """The file of a fallback's `n`th invocation (`Fallback`). It reaches
        the tool's adapter as `history_output` does."""
        return self.out_dir / PART_OUTPUT.format(tool=self.tool, n=n)

    def any_file(self, predicate: Callable[[Path], bool]) -> bool:
        """Stop at the first file of the pruned walk that satisfies `predicate`."""
        if self.iter_files is None:
            return False
        return any(predicate(p) for p in self.iter_files())


def read_history(root: Path) -> tuple[bool, str]:
    """Whether a target's git history can be read, and if not, why.

    ``(False, "")`` when there is no `.git` at all: nothing to say. Otherwise
    one git probe decides, since both ways it goes wrong are silent:

    - **A shallow clone.** Its oldest commit holds the whole tree, so both
      tools name that commit, and its author, as having added every secret in
      it (measured: a `--depth 1` clone blamed whoever wrote HEAD). GitLab
      targets and `actions/checkout` both clone with depth 1.
    - **A git that cannot read it** ("dubious ownership" in a container, a
      worktree whose gitdir is not mounted). gitleaks' git mode then exits 0
      with "0 commits scanned", and its row read `ran` (measured).

    `.git` is a file in a worktree or a submodule. Python 3.12 raises from
    `exists()` where 3.11 returned False (#1163), hence the guard.
    """
    try:
        if not (Path(root) / ".git").exists():
            return False, ""
    except OSError as exc:
        return False, f"its .git could not be checked: {exc}"
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-shallow-repository"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"git could not run: {exc}"
    answer = result.stdout.strip()
    if result.returncode != 0:
        lines = [line for line in result.stderr.splitlines() if line.strip()]
        return False, "git cannot read it: " + (
            lines[-1] if lines else f"exit {result.returncode}"
        )
    if answer == "true":
        return False, (
            "a shallow clone, whose oldest commit would be named as adding "
            "every secret in it; fetch its full history to read it"
        )
    if answer != "false":
        return False, f"git could not tell whether it is a shallow clone: {answer!r}"
    return True, ""


@dataclass(frozen=True)
class Invocation:
    """One command line. A tool may have more than one (PR C: git history)."""

    command: tuple[str, ...]
    output_file: Path
    capture_stdout: bool
    ok_return_codes: tuple[int, ...]
    # zap.bat resolves its jar against the working directory: run from anywhere
    # else, it fails with "Unable to access jarfile zap-2.17.0.jar" (measured).
    cwd: Path | None = None
    # Which of a tool's invocations this is, for a failed row to name.
    label: str = ""
    # Merged over the environment the runner builds for the child.
    env: Mapping[str, str] | None = None
    # What to run instead when this invocation fails in one known way.
    fallback: Fallback | None = None
    # The files it was handed, `/`-separated and relative to `cwd`, for a row
    # to name the ones the tool could not read (`ToolDescriptor.unread_inputs`).
    inputs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Fallback:
    """Run `invocations` instead of an invocation that exited with one of
    `returncodes` and wrote `stderr_marker` to stderr.

    For a tool that reads many inputs in one run and loses all of them to one
    it cannot read (osv-scanner: a truncated lockfile, rc 127, no output). One
    run per input then costs only the bad one's findings, and the row names
    each invocation that failed by its `label`. Each writes its own output
    (`ScanContext.part_output`).
    """

    returncodes: tuple[int, ...]
    stderr_marker: str
    invocations: tuple[Invocation, ...]


@dataclass(frozen=True)
class Shortfall:
    """What a tool's pre-run check (`ToolDescriptor.precheck`) found it cannot
    read. The row fails with `reason`, `detail` naming what was left out,
    whatever the run does; the tool runs on `files` only, and with none left
    it does not run at all."""

    reason: Reason
    detail: str
    files: tuple[str, ...]


@dataclass(frozen=True)
class VersionProbe:
    """How `jmo tools check` reads the installed version."""

    pattern: re.Pattern[str]
    # None: `<binary> --version`. A mapping is keyed by platform, with "default".
    command: list[str] | dict[str, list[str]] | None = None
    # None: tool_manager's default budget.
    timeout: int | None = None


@dataclass(frozen=True)
class NothingRead:
    """How a tool says it was handed inputs and read none of them: a run that
    exited with `returncode` and wrote `stderr_marker` to stderr is `skipped`
    with `reason`, not `failed` (zizmor: rc 3, "no inputs collected")."""

    returncode: int
    stderr_marker: str
    reason: Reason


# `(stderr, the files it was handed)` -> each file the tool did not read, with
# why. A tool that drops an invalid input and audits the others exits 0 and
# says so only on stderr.
UnreadInputs = Callable[[str, Sequence[str]], dict[str, str]]

Builder = Callable[[ScanContext], list[Invocation]]
Trigger = Callable[[ScanContext], Reason | None]
Precheck = Callable[[ScanContext], Shortfall | None]


@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    # target type -> the command lines for it. The keys are the tool's target
    # types; a GitLab target runs the repository builders on its clone.
    invocations: Mapping[str, Builder]
    version_probe: VersionProbe
    exclusion_style: ExclusionStyle
    # The parser that reads its command line: which other spellings of a
    # reserved flag reach it (`reserved_spelling`).
    flag_grammar: FlagGrammar
    exclusion_flag: str | None = None
    # Flags a user's `per_tool` flags may not set, each with why (`Reserved`):
    # this tool's own spellings of what decides where and how it writes, of
    # its exit code, and of what JMo passes when its parser refuses a repeat
    # (#1325, #1335). Per tool, since one tool's reserved flag is another's
    # option (semgrep's `-f` is `--config`, and gitleaks' `-r` is nuclei's
    # `-resolvers`).
    reserved_flags: Mapping[str, Reserved] = field(default_factory=dict)
    # Its short flags that take no value. A clustering parser chains them, so
    # a reserved short flag can follow one: `-qftable` is trivy's `-q -f table`.
    short_switches: frozenset[str] = frozenset()
    # VENDORED_DIRS entries this tool is told to skip (the results directory
    # is excluded for every filesystem tool regardless).
    excluded_vendored: tuple[str, ...] = VENDORED_DIRS
    # Content the tool needs: walk-fed file patterns, or a predicate.
    file_patterns: tuple[str, ...] = ()
    # For a walk-fed tool that decides by the exact file name: the walk's glob
    # ignores case on Windows, so what it found is checked again by name.
    accepts_name: Callable[[str], bool] | None = None
    no_files_reason: Reason | None = None
    trigger: Trigger | None = None
    # Run once the content is known to be there: what the tool cannot read
    # of it fails the row before it runs (a trigger can only skip).
    precheck: Precheck | None = None
    # The tool was handed files and read none of them: a skip, not a failure.
    nothing_read: NothingRead | None = None
    # Which of the files it was handed it did not read, from its stderr.
    unread_inputs: UnreadInputs | None = None
    # Files in the scanned repository's root that the tool reads as its own
    # configuration. The repository then decides part of its own audit, so the
    # scan says so (#1363, as for gitleaks' `.gitleaks.toml`).
    own_config: tuple[str, ...] = ()
    off_target_reason: Reason = Reason.NOT_FOR_TARGET
    timeout_floor: int = 0
    binary: str | None = None  # executable name, where it differs from `name`
    # Ships inside JMo and runs on its interpreter: nothing to install, pin or
    # update, and its version is JMo's own.
    builtin: bool = False
    # Reads a repository's git history too, when `read_history` allows (G1).
    reads_history: bool = False
    execution_commands: tuple[str, ...] = ()  # what must exist to execute it
    stub: Any = field(default_factory=dict)  # empty-result shape of its output
    # Files examined, read from the output file; None when it cannot tell.
    scanned_count: Callable[[Path], int | None] | None = None

    @property
    def target_types(self) -> frozenset[str]:
        types = set(self.invocations)
        if "repo" in types:
            types.add("gitlab")
        return frozenset(types)

    def reserved_spelling(self, token: str) -> tuple[str, bool] | None:
        """The reserved flag this tool's parser reads `token` as, and whether
        the token carries its value too (`-ftable`, `--format=table`); None
        for a token that sets none of them.

        A chained short flag is found by walking the letters after the dash:
        a no-value flag goes on to the next letter, and the first letter that
        takes a value ends the walk, taking the rest of the token, or the next
        token when nothing follows it (`-sqf` is trivy's severity `qf`). The
        token is refused when a letter on the way is reserved.
        """
        if not token.startswith("-"):
            return None
        grammar, reserved = self.flag_grammar, self.reserved_flags
        name, equals, _ = token.partition("=")
        inline = bool(equals)
        if name in reserved:
            # A no-value short flag leaves the next token alone.
            return name, inline or name in self.short_switches
        if grammar.either_dash:
            bare = name.lstrip("-")
            found = sorted(r for r in reserved if r.lstrip("-") == bare)
            return (found[0], inline) if found else None
        if name.startswith("--"):
            if grammar.negates and name.startswith("--no-"):
                negated = "--" + name.removeprefix("--no-")
                if negated in reserved:
                    return negated, inline
            if grammar.abbreviates and len(name) > 2:
                longer = sorted(r for r in reserved if r.startswith(name))
                if longer:
                    return longer[0], inline
            return None
        if grammar.clusters:
            # `-format` is `-f ormat` to a chaining parser, and its value
            # would be left a bare word: taken as `--format`, it goes too.
            if len(name) > 2 and "-" + name in reserved:
                return "-" + name, inline
            switch: str | None = None  # a reserved no-value flag passed over
            for at, letter in enumerate(token[1:], start=2):
                short = "-" + letter
                if short in self.short_switches:
                    if switch is None and short in reserved:
                        switch = short
                    continue
                if short in reserved:
                    return short, at < len(token)
                return (switch, at < len(token)) if switch else None
            return (switch, True) if switch else None
        return None


# --- content triggers ---------------------------------------------------------


_CFN_SUFFIXES = frozenset({".yaml", ".yml", ".json", ".template"})
_CFN_MARKERS = (b"AWSTemplateFormatVersion", b"AWS::")
_CFN_HEAD_BYTES = 8192


def _is_iac(path: Path) -> bool:
    """Terraform or CloudFormation.

    checkov's trigger (Phase 4, Task Z2): the Phase 3 cut folded checkov-cicd
    into checkov, so `.github/workflows` was checkov's until this task handed
    it to zizmor. **Not Helm either**: `Chart.yaml` used to count, but no helm
    binary exists on the host or in the image and checkov disables the
    framework silently, so a chart-only repository reading checkov `ran`
    reported nothing. The trigger now fires only on what checkov's narrowed
    `--framework terraform terraform_json cloudformation` (the repository
    invocation) actually reads. CloudFormation has no file name of its own, so
    a YAML or JSON file counts when its first 8 KB name an `AWS::` type or the
    template version.
    """
    name = path.name
    if name.endswith((".tf", ".tf.json")):
        return True
    if path.suffix in _CFN_SUFFIXES:
        try:
            with path.open("rb") as fh:
                head = fh.read(_CFN_HEAD_BYTES)
        except OSError:
            return False
        return any(marker in head for marker in _CFN_MARKERS)
    return False


def _iac_trigger(ctx: ScanContext) -> Reason | None:
    return None if ctx.any_file(_is_iac) else Reason.NO_IAC


def _native_trigger(ctx: ScanContext) -> Reason | None:
    """jmo-native reads JS/TS source, `.env` files, Firebase rules files and
    the root's `supabase/migrations/*.sql`, and nothing under the directories
    it prunes. Decided with the runner's own constants and functions, so the
    two cannot disagree about what it reads, letter case included."""
    # Imported here: the runner imports VENDORED_DIRS from this module.
    from scripts.core import native_checks

    root = Path(ctx.target)
    try:
        if native_checks.migration_files(root):
            return None
    except OSError:
        # The runner cannot read them either: run it, so the row fails and
        # says so rather than reading as a skip.
        return None

    def reads(path: Path) -> bool:
        parts = path.relative_to(root).parts
        if set(parts[:-1]) & native_checks.PRUNE_DIRS:
            return False
        return (
            path.suffix in native_checks.CODE_SUFFIXES
            or native_checks.is_env_file(path.name)
            or path.name in native_checks.RULES_FILE_NAMES
        )

    return None if ctx.any_file(reads) else Reason.NO_WEB_APP_FILES


# --- examined-files readers (G2, #1231) -----------------------------------------


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes().decode("utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _semgrep_scanned(path: Path) -> int | None:
    """`paths.scanned`: 0 when semgrep's git-based walk resolved to an
    enclosing repository with no tracked files (#1231, measured 0 vs 4)."""
    data = _load(path)
    if not isinstance(data, dict):
        return None
    scanned = (data.get("paths") or {}).get("scanned")
    return len(scanned) if isinstance(scanned, list) else None


# --- command lines ------------------------------------------------------------


def scan_root(target: Any) -> str:
    """The absolute root trufflehog is given, and its exclude patterns anchor on.

    One function for both, so they cannot disagree. Absolute because Go's
    `filepath.Join` cleans `./sub` to `sub`: a pattern anchored on `.`, which
    is what `--repo .` passes, would never match anything.
    """
    return str(Path(target).resolve())


def _asks_for_verified_results(flags: Sequence[str]) -> bool:
    """`--only-verified`, or `--results` naming `verified`. Unverified secrets
    are all there is under `--no-verification`, so either filter would report
    nothing, rc 0, row `ran` (measured, 3.97.1)."""
    for i, flag in enumerate(flags):
        if flag == "--only-verified":
            return True
        value = None
        if flag.startswith("--results="):
            value = flag.split("=", 1)[1]
        elif flag == "--results" and i + 1 < len(flags):
            value = flags[i + 1]
        if value is not None and "verified" in value.split(","):
            return True
    return False


def _verification(ctx: ScanContext, flags: Sequence[str]) -> tuple[str, ...]:
    """One trufflehog run's verification switch.

    Verification sends each candidate secret to its issuer, and git mode
    multiplies the candidates: off unless `per_tool.trufflehog.verify` is
    true (decided 2026-09-26), or that run's own flags ask for verified
    results (#1327: each run has its own).
    """
    verify = ctx.tool_config.get("verify") is True or _asks_for_verified_results(flags)
    return () if verify else ("--no-verification",)


def _trufflehog_repo(ctx: ScanContext) -> list[Invocation]:
    root = scan_root(ctx.target)
    invocations = [
        Invocation(
            command=(
                ctx.binary,
                "filesystem",
                root,
                "--json",
                "--no-update",
                *_verification(ctx, ctx.flags),
                *ctx.exclusion_args,
                *ctx.flags,
            ),
            output_file=ctx.output,
            capture_stdout=True,
            ok_return_codes=(0, 1),
            label="filesystem",
        )
    ]
    if ctx.history:
        # G1: history names the commit, so #1134's objection to a hit inside
        # `.git/objects` (no commit) does not apply. `file://C:/x` on Windows:
        # `file:///C:/x` doubles the drive (measured, 3.97.1). Escaped, since
        # a URL reads `#` as the end of its path and `%41` as `A`: unescaped,
        # the history run failed on every scan of such a directory (measured).
        invocations.append(
            Invocation(
                command=(
                    ctx.binary,
                    "git",
                    "file://" + quote(Path(root).as_posix(), safe="/:"),
                    "--json",
                    "--no-update",
                    *_verification(ctx, ctx.history_flags),
                    *ctx.history_exclusion_args,
                    *ctx.history_flags,
                ),
                output_file=ctx.history_output,
                capture_stdout=True,
                ok_return_codes=(0, 1),
                label="git",
            )
        )
    return invocations


def _gitleaks_repo(ctx: ScanContext) -> list[Invocation]:
    # Target `.`, run from the repository: given an absolute target, gitleaks
    # writes that path into every message, and a finding's id hashes the
    # message, so the same secret had a different id in every checkout
    # (measured, 8.30.1). This is also how the Phase 1 golden was made. Every
    # other path is absolute, since the working directory moves. History (G1)
    # reads the same config: its paths are repository-relative too.
    modes = [("dir", ctx.output, ctx.flags)]
    if ctx.history:
        modes.append(("git", ctx.history_output, ctx.history_flags))
    return [
        Invocation(
            command=(
                ctx.binary,
                mode,
                ".",
                "--report-format",
                "sarif",
                "--report-path",
                str(output.resolve()),
                "--no-banner",
                # A leak is not an error; anything nonzero is.
                "--exit-code",
                "0",
                *ctx.exclusion_args,
                *flags,
            ),
            output_file=output,
            capture_stdout=False,
            ok_return_codes=(0,),
            cwd=Path(scan_root(ctx.target)),
            label=mode,
        )
        for mode, output, flags in modes
    ]


def _semgrep_repo(ctx: ScanContext) -> list[Invocation]:
    # Default ["auto"]: the Semgrep Registry picks rules per language. A
    # `configs:` list in per_tool.semgrep allows offline packs.
    configs = ctx.tool_config.get("configs", ["auto"])
    config_args = [arg for cfg in configs for arg in ("--config", str(cfg))]
    return [
        Invocation(
            command=(
                ctx.binary,
                *config_args,
                "--json",
                "--output",
                str(ctx.output),
                # JMo's exclusions before the user's flags, so an explicit
                # per_tool entry still wins; repeatable forms accumulate.
                *ctx.exclusion_args,
                *ctx.flags,
                str(ctx.target),
            ),
            output_file=ctx.output,
            capture_stdout=False,
            ok_return_codes=(0, 1, 2),  # 2 = errors, with output written
        )
    ]


def _syft_repo(ctx: ScanContext) -> list[Invocation]:
    return [
        Invocation(
            command=(
                ctx.binary,
                f"dir:{ctx.target}",
                "-o",
                "json",
                *ctx.exclusion_args,
                *ctx.flags,
            ),
            output_file=ctx.output,
            capture_stdout=True,
            ok_return_codes=(0,),
        )
    ]


def _syft_image(ctx: ScanContext) -> list[Invocation]:
    return [
        Invocation(
            command=(ctx.binary, str(ctx.target), "-o", "json", *ctx.flags),
            output_file=ctx.output,
            capture_stdout=True,
            ok_return_codes=(0,),
        )
    ]


def _trivy(subcommand: str, *pre: str, excl: bool = False) -> Builder:
    def build(ctx: ScanContext) -> list[Invocation]:
        return [
            Invocation(
                command=(
                    ctx.binary,
                    subcommand,
                    "-q",
                    "-f",
                    "json",
                    *pre,
                    *(ctx.exclusion_args if excl else ()),
                    *filter_trivy_flags(subcommand, ctx.flags),
                    str(ctx.target),
                    "-o",
                    str(ctx.output),
                ),
                output_file=ctx.output,
                capture_stdout=False,
                ok_return_codes=(0, 1),
            )
        ]

    return build


def _trivy_k8s(ctx: ScanContext) -> list[Invocation]:
    info = ctx.target
    context = str(info.get("context", ""))
    namespace = str(info.get("namespace", ""))
    # Two producers build this dict and they disagree: live discovery writes
    # namespace="*" for every namespace and sets no all_namespaces key.
    all_namespaces = (
        str(info.get("all_namespaces", "False")) == "True" or namespace == "*"
    )
    command = [ctx.binary, "k8s", "-q", "-f", "json", *ctx.flags]
    # trivy scans every namespace unless told otherwise; "default" is the
    # sentinel discovery writes when the user named none.
    if not all_namespaces and namespace not in ("", "*", "default"):
        command += ["--include-namespaces", namespace]
    command += ["-o", str(ctx.output)]
    # The context is POSITIONAL (`trivy kubernetes [flags] [CONTEXT]`).
    if context and context != "current":
        command.append(context)
    return [
        Invocation(
            command=tuple(command),
            output_file=ctx.output,
            capture_stdout=False,
            ok_return_codes=(0, 1),
        )
    ]


# checkov's default (no `--framework`) evaluates every framework it ships,
# including `secrets` (195.8 s alone on one measured repository) and
# `github_actions` -- ground zizmor now owns. Narrowed to exactly what
# `_is_iac` triggers on.
# This narrowing is for the REPOSITORY invocation (`-d`) only. The
# single-file `iac` invocation (`-f`, for --terraform-state/--cloudformation/
# --k8s-manifest) keeps every framework -- the user named the file, and
# narrowing would drop checkov's kubernetes checks on --k8s-manifest.
_CHECKOV_IAC_FRAMEWORKS: tuple[str, ...] = (
    "terraform",
    "terraform_json",
    "cloudformation",
)


def _checkov(flag: str, excl: bool, framework: bool = False) -> Builder:
    def build(ctx: ScanContext) -> list[Invocation]:
        return [
            Invocation(
                command=(
                    ctx.binary,
                    flag,
                    str(ctx.target),
                    "-o",
                    "json",
                    *(("--framework", *_CHECKOV_IAC_FRAMEWORKS) if framework else ()),
                    *(ctx.exclusion_args if excl else ()),
                    *ctx.flags,
                ),
                output_file=ctx.output,
                capture_stdout=True,
                ok_return_codes=(0, 1),
            )
        ]

    return build


def _file_fed(*format_args: str) -> Builder:
    """hadolint and shellcheck take many paths per invocation; the scan loop
    walks the tree (pruning the excluded directories) and hands them over."""

    def build(ctx: ScanContext) -> list[Invocation]:
        return [
            Invocation(
                command=(ctx.binary, *format_args, *ctx.flags, *ctx.files),
                output_file=ctx.output,
                capture_stdout=True,
                ok_return_codes=(0, 1),  # 2+ are fatal parse/usage errors
            )
        ]

    return build


def _relative_to_target(ctx: ScanContext) -> tuple[Path, list[str]]:
    """The resolved root to run a walk-fed tool from, and its walked files
    relative to that root, `/`-separated.

    Relative to the target as given, not resolve()d: the walk globs from it,
    and a file reached through a link that leaves the repository resolves
    outside the root. That raised ValueError, and every tool on the target
    failed (measured on a junction). The path as found reaches the same file
    from the resolved root.
    """
    root = Path(scan_root(ctx.target)).resolve()
    target = Path(ctx.target).absolute()
    return root, [Path(f).absolute().relative_to(target).as_posix() for f in ctx.files]


_ZIZMOR_WARNING = re.compile(
    r"^\s*WARN collect_inputs: [\w:]+: (?P<message>.+?)\s*$", re.MULTILINE
)
# A warning that names its file (a YAML file of the wrong kind); one for a file
# that does not parse does not.
_ZIZMOR_NAMED = re.compile(
    r"failed to (?:parse|validate) file://(?P<file>\S+?)(?: as \w+)?: (?P<why>.+)"
)
# One line per input it audited, the path as the platform spells it.
_ZIZMOR_DONE = re.compile(
    r"^\s*INFO audit: .*? completed (?P<file>.+?)\s*$", re.MULTILINE
)


def _zizmor_unread(stderr: str, inputs: Sequence[str]) -> dict[str, str]:
    """The inputs zizmor 1.30.1 dropped and why: each `WARN collect_inputs`
    line, matched to a file by its own text or, for a file that does not parse
    (the warning carries no name), by the absence of a `completed` line."""
    warnings = _ZIZMOR_WARNING.findall(stderr)
    if not warnings:
        return {}
    unread: dict[str, str] = {}
    unnamed: list[str] = []
    for message in warnings:
        named = _ZIZMOR_NAMED.search(message)
        if named:
            unread[named.group("file")] = named.group("why")
        else:
            unnamed.append(message)
    audited = {m.replace("\\", "/") for m in _ZIZMOR_DONE.findall(stderr)}
    why = unnamed[0] if len(unnamed) == 1 else "it did not parse"
    for name in inputs:
        if name not in audited and name not in unread:
            unread[name] = why
    return unread


def _zizmor_repo(ctx: ScanContext) -> list[Invocation]:
    # Walk-fed and repository-relative, run from the root: zizmor has no
    # exclude flag and reads vendored workflows (a planted node_modules
    # workflow was audited, measured 1.30.1), and an absolute input puts an
    # absolute URI, so a checkout-dependent id, in every finding.
    root, inputs = _relative_to_target(ctx)
    return [
        Invocation(
            command=(
                ctx.binary,
                "--format",
                "sarif",
                # --offline, not --no-online-audits: zizmor reads GH_TOKEN,
                # and a scan makes no network call.
                "--offline",
                "--no-exit-codes",
                *ctx.flags,
                *inputs,
            ),
            output_file=ctx.output,
            capture_stdout=True,
            ok_return_codes=(0,),
            cwd=root,
            inputs=tuple(inputs),
        )
    ]


# osv-scanner exits 127 for every error. This line is its own for a lockfile it
# could not extract (2.6.0), the one failure a run per lockfile recovers from.
# A database it cannot load exits 127 too (measured: a lone pom.xml with no
# Maven database), and split, every run would fail the same way.
_OSV_UNREADABLE_LOCKFILE = "extraction failed on specified lockfile"


def _osv_scanner_repo(ctx: ScanContext) -> list[Invocation]:
    # Walk-fed, `-L` per lockfile: given a directory on Windows osv-scanner
    # walks nothing (rc 128, "No package sources found", 2.5.1 and 2.6.0).
    root, lockfiles = _relative_to_target(ctx)
    env = {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(osv_database.cache_dir())}

    def scan(
        files: Sequence[str],
        output: Path,
        label: str = "",
        fallback: Fallback | None = None,
    ) -> Invocation:
        return Invocation(
            command=(
                ctx.binary,
                "scan",
                "source",
                "--format",
                "sarif",
                # Absolute: it runs from the repository.
                "--output-file",
                str(output.absolute()),
                # Scans never download (decision 6), and never resolve:
                # `pom.xml` and `requirements.txt` were resolved over the
                # network (deps.dev) without `--no-resolve` (measured, 2.6.0).
                "--offline-vulnerabilities",
                "--no-resolve",
                # A lockfile with no packages is rc 128 and no output without
                # it; with it, rc 0 and an empty report. A lockfile it cannot
                # read is still 127 (measured).
                "--allow-no-lockfiles",
                # Go's call analysis is on by default and runs only where a Go
                # toolchain is installed, hiding the vulnerabilities it finds
                # uncalled: a result that depended on the scanning machine.
                # `all` also wins over a later `--call-analysis=` (measured).
                "--no-call-analysis=all",
                *ctx.flags,
                # `-L` is `[parse-as:]path`: `-L a:b/package-lock.json` read
                # `b/package-lock.json` as a lockfile of type `a` (rc 127, no
                # output, measured on Linux); a leading `:` keeps the whole
                # path, on Windows too.
                *(arg for f in files for arg in ("-L", f":{f}")),
            ),
            output_file=output,
            capture_stdout=False,
            ok_return_codes=(0, 1),  # 1 = findings
            cwd=root,
            label=label,
            env=env,
            fallback=fallback,
        )

    if len(lockfiles) == 1:
        return [scan(lockfiles, ctx.output, label=lockfiles[0])]
    # One run for all: a per-lockfile run loads the database each time (npm
    # ~11 s). But one unreadable lockfile loses every other's findings (a
    # truncated package-lock.json cost NodeGoat's 304: rc 127, no output), so
    # that failure falls back to one run each.
    each = tuple(
        scan([f], ctx.part_output(n), label=f) for n, f in enumerate(lockfiles, 1)
    )
    fallback = Fallback((127,), _OSV_UNREADABLE_LOCKFILE, each)
    return [scan(lockfiles, ctx.output, fallback=fallback)]


def _osv_reads(name: str) -> bool:
    """A file name osv-scanner reads through `-L`, spelled exactly."""
    return osv_database.ecosystem_of(name) is not None


# What a Dockerfile is, the one definition hadolint's row and the images a
# GitLab target names both read (#1311): the patterns find the candidates,
# `is_dockerfile` decides.
DOCKERFILE_PATTERNS = ("**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile")
# `Dockerfile.<suffix>` names that are not a Dockerfile: a document about one,
# Docker's own ignore file for one, a template that renders one, and code.
_NOT_DOCKERFILE_SUFFIXES = frozenset(
    {
        *("md", "txt", "rst", "adoc", "html"),
        "dockerignore",
        *("j2", "jinja", "jinja2", "tmpl", "tpl", "template", "in"),
        "py",
    }
)


def is_dockerfile(name: str) -> bool:
    """`Dockerfile`, `Dockerfile.<variant>` or `<variant>.Dockerfile`, case
    included: the walk's glob ignores case on Windows, where it matched a
    `dockerfile.py`. A `Dockerfile.<suffix>` that is not one is refused:
    hadolint linted a document's prose as a Dockerfile (`Dockerfile.md`) and
    reported a DL1000 at error level on `Dockerfile.dockerignore` and a
    `Dockerfile.j2` template, and discovery read `From the root...` and
    `FROM {{ base }}` as images to pull (measured)."""
    if name == "Dockerfile" or name.endswith(".Dockerfile"):
        return True
    if not name.startswith("Dockerfile."):
        return False
    return name.rsplit(".", 1)[1].lower() not in _NOT_DOCKERFILE_SUFFIXES


def _osv_databases(ctx: ScanContext) -> Shortfall | None:
    """Each lockfile's ecosystem must have an offline database, or osv-scanner
    does not read it. Decided here because osv-scanner's answer cannot be
    trusted: a Cargo.lock with no crates.io database beside NodeGoat's
    package-lock.json exited **1** with 40 of its 304 results (measured three
    times), and alone it is rc 127, which would read `unaccepted exit code`."""
    _, lockfiles = _relative_to_target(ctx)
    present = osv_database.present_ecosystems()
    kept: list[str] = []
    missing: dict[str, list[str]] = {}
    for path, lockfile in zip(ctx.files, lockfiles, strict=True):
        ecosystem = osv_database.ecosystem_of(lockfile) or lockfile
        if ecosystem in present:
            kept.append(path)
        else:
            missing.setdefault(ecosystem, []).append(lockfile)
    if not missing:
        return None
    named = "; ".join(f"{eco} ({', '.join(files)})" for eco, files in missing.items())
    return Shortfall(
        Reason.NO_OFFLINE_DB,
        f"no offline database for {named}: run `jmo tools update`",
        tuple(kept),
    )


def _yara_repo(ctx: ScanContext) -> list[Invocation]:
    # yara is libyara bindings, not a CLI: the binary is this interpreter and
    # scripts/core/yara_runner.py supplies the command line and the walk.
    # Imported here: paths -> install_config -> tool_registry -> this module.
    from scripts.core.paths import get_yara_rules_dir

    rules = ctx.tool_config.get("rules_path", str(get_yara_rules_dir()))
    return [
        Invocation(
            command=(
                ctx.binary,
                "-m",
                "scripts.core.yara_runner",
                "--rules",
                str(rules),
                "--target",
                str(ctx.target),
                "--output",
                str(ctx.output),
                *ctx.exclusion_args,
                *ctx.flags,
            ),
            output_file=ctx.output,
            # The runner writes --output itself; 2 means "did not scan".
            capture_stdout=False,
            ok_return_codes=(0, 1),
        )
    ]


def _native_repo(ctx: ScanContext) -> list[Invocation]:
    # JMo's own check pack (scripts/core/native_checks.py), run as yara_runner
    # is: the binary is this interpreter.
    return [
        Invocation(
            command=(
                ctx.binary,
                "-m",
                "scripts.core.native_checks",
                "--target",
                str(ctx.target),
                "--output",
                str(ctx.output),
                *ctx.exclusion_args,
                *ctx.flags,
            ),
            output_file=ctx.output,
            # The runner writes --output itself; 2 means "did not scan".
            capture_stdout=False,
            ok_return_codes=(0, 1),
        )
    ]


def _grype_repo(ctx: ScanContext) -> list[Invocation]:
    return [
        Invocation(
            command=(
                ctx.binary,
                f"dir:{ctx.target}",
                "-o",
                "json",
                *ctx.exclusion_args,
                *ctx.flags,
            ),
            output_file=ctx.output,
            capture_stdout=True,
            ok_return_codes=(0, 1),
        )
    ]


def _zap_url(ctx: ScanContext) -> list[Invocation]:
    binary = Path(ctx.binary)
    return [
        Invocation(
            command=(
                ctx.binary,
                "-cmd",
                "-quickurl",
                str(ctx.target),
                # Absolute: the working directory is zap's own, not the caller's.
                "-quickout",
                str(ctx.output.absolute()),
                "-quickprogress",
                *ctx.flags,
            ),
            output_file=ctx.output,
            capture_stdout=False,
            ok_return_codes=(0, 1, 2),
            cwd=binary.parent if binary.parent != Path() else None,
        )
    ]


def _nuclei_url(ctx: ScanContext) -> list[Invocation]:
    return [
        Invocation(
            command=(
                ctx.binary,
                "-u",
                str(ctx.target),
                # `-json` left in nuclei 3: "flag provided but not defined:
                # -json", exit 2, on every URL scan (measured 3.11.0).
                "-jsonl",
                "-o",
                str(ctx.output),
                "-silent",
                "-no-color",
                *ctx.flags,
            ),
            output_file=ctx.output,
            capture_stdout=False,
            ok_return_codes=(0, 1),
        )
    ]


_VERSION = re.compile(r"Version:\s*v?(\d+\.\d+\.\d+)")

# Order is TOOL_MATRIX's order: docs, the wizard and `jmo tools check` list it so.
DESCRIPTORS: dict[str, ToolDescriptor] = {
    d.name: d
    for d in (
        ToolDescriptor(
            name="trufflehog",
            invocations={"repo": _trufflehog_repo},
            version_probe=VersionProbe(re.compile(r"trufflehog\s+v?(\d+\.\d+\.\d+)")),
            exclusion_style=ExclusionStyle.PATTERN_FILE,
            exclusion_flag="--exclude-paths",
            flag_grammar=FlagGrammar.KINGPIN,
            # kingpin refuses a flag given twice, and JMo passes `--json`,
            # `--no-update`, `--no-verification` and `--exclude-paths`: a
            # user's `--no-verification` was rc 1, "flag 'no-verification'
            # cannot be repeated", no output (measured, 3.97.1), and
            # `--exclude-paths` or `-x` the same. `--fail` exits 183 on a find.
            reserved_flags=_reserve(
                OUTPUT=("-j", "--json", "--json-legacy", "--sarif", "--github-actions"),
                PASSED=("--no-update", "--exclude-paths", "-x"),
                VERIFY=("--no-verification",),
                EXIT_CODE=("--fail", "--fail-on-scan-errors"),
            ),
            short_switches=frozenset({"-h", "-j"}),
            stub=[],
            reads_history=True,
        ),
        ToolDescriptor(
            name="gitleaks",
            invocations={"repo": _gitleaks_repo},
            # `gitleaks version` prints the bare version (measured, 8.30.1).
            version_probe=VersionProbe(
                re.compile(r"^v?(\d+\.\d+\.\d+)$", re.MULTILINE),
                command=["gitleaks", "version"],
            ),
            exclusion_style=ExclusionStyle.CONFIG_FILE,
            exclusion_flag="--config",
            flag_grammar=FlagGrammar.PFLAG,
            # Its report flags (#1325, measured: `--report-format json` lost
            # every finding with the row `ran`; `--exit-code 1` failed a run
            # whose findings then reached the report). `--redact` makes every
            # snippet `REDACTED`, and the pairing digests the snippet (#1323).
            # `--config` would replace the one carrying JMo's exclusions; a
            # repository's own `.gitleaks.toml` is extended instead (#1327).
            # Chained, `-vrREPORT.sarif` (`-v -r`) wrote the unredacted report
            # into the repository, which gitleaks runs from (#1335, measured).
            reserved_flags=_reserve(
                OUTPUT=(
                    "-f",
                    "--report-format",
                    "-r",
                    "--report-path",
                    "--report-template",
                    "--redact",
                ),
                PASSED=("-c", "--config"),
                EXIT_CODE=("--exit-code",),
            ),
            short_switches=frozenset({"-h", "-v"}),
            stub={"version": "2.1.0", "runs": []},
            reads_history=True,
        ),
        ToolDescriptor(
            name="semgrep",
            invocations={"repo": _semgrep_repo},
            version_probe=VersionProbe(re.compile(r"^(\d+\.\d+\.\d+)$", re.MULTILINE)),
            exclusion_style=ExclusionStyle.INLINE,
            exclusion_flag="--exclude",
            flag_grammar=FlagGrammar.CMDLINER,
            # A second output or format is rc 2 with no output file ("options
            # '--output' and '-o' cannot be present at the same time", "option
            # '--json' cannot be repeated", and "Mutually exclusive options"
            # for `--sarif`), measured 1.175.0. Its `-f` is `--config`, which
            # adds rules, as a repeated `--exclude` adds exclusions.
            reserved_flags=_reserve(
                OUTPUT=(
                    "-o",
                    "--output",
                    "--json",
                    "--text",
                    "--sarif",
                    "--emacs",
                    "--vim",
                    "--junit-xml",
                    "--gitlab-sast",
                    "--gitlab-secrets",
                ),
                EXIT_CODE=("--error", "--strict"),
            ),
            short_switches=frozenset({"-a", "-d", "-q", "-v"}),
            # Its cost is its rule count, not the tree: 409.8 s and 583 s for
            # identical work on one machine (#1204). A floor caps wasted time.
            timeout_floor=900,
            stub={"results": []},
            scanned_count=_semgrep_scanned,
        ),
        ToolDescriptor(
            name="syft",
            invocations={"repo": _syft_repo, "image": _syft_image},
            version_probe=VersionProbe(_VERSION, command=["syft", "version"]),
            exclusion_style=ExclusionStyle.SEPARATE,
            exclusion_flag="--exclude",
            flag_grammar=FlagGrammar.PFLAG,
            # `-o` adds an output rather than replacing JMo's, so even `-ojson`
            # leaves two documents on stdout; `--file` moves it and leaves
            # stdout empty (measured, 1.51.1).
            reserved_flags=_reserve(OUTPUT=("-o", "--output", "--file")),
            short_switches=frozenset({"-h", "-q", "-v"}),
            # An SBOM inventories exactly those trees (#1205).
            excluded_vendored=(),
            stub={"artifacts": []},
        ),
        ToolDescriptor(
            name="trivy",
            invocations={
                # No `secret`: gitleaks and trufflehog already read a repository's
                # secrets, and trivy's own pass is redundant there. `--include-dev-deps`
                # reads devDependencies too -- trivy skips them by default, so a
                # JS app whose vulnerable packages are all dev-only reads 0
                # vulnerabilities otherwise (measured). `--offline-scan` stops it
                # calling out for a Maven lookup it cannot complete (measured: two
                # 429s and no output); the vulnerability database is already local.
                # No `license`: the adapter ignores license results (408 raw
                # entries, 0 findings measured on a real repository).
                "repo": _trivy(
                    "fs",
                    "--scanners",
                    "vuln,misconfig",
                    "--include-dev-deps",
                    "--offline-scan",
                    excl=True,
                ),
                # The image scan keeps its secret pass: nothing else reads an
                # image's layers, so a secret baked into one is only found here.
                "image": _trivy("image", "--scanners", "vuln,secret,misconfig"),
                "iac": _trivy("config"),
                "k8s": _trivy_k8s,
            },
            version_probe=VersionProbe(_VERSION),
            exclusion_style=ExclusionStyle.SEPARATE,
            exclusion_flag="--skip-dirs",
            flag_grammar=FlagGrammar.PFLAG,
            # `-ftable` took 42 findings to 0, rc 0, the row `ran` (#822,
            # measured 0.74.0). `--exit-code` sets the code for any finding.
            reserved_flags=_reserve(
                OUTPUT=("-f", "--format", "-o", "--output"),
                EXIT_CODE=("--exit-code",),
            ),
            short_switches=frozenset({"-d", "-h", "-q", "-v"}),
            stub={"Results": []},
        ),
        ToolDescriptor(
            name="checkov",
            invocations={
                "repo": _checkov("-d", excl=True, framework=True),
                "iac": _checkov("-f", excl=False),
            },
            version_probe=VersionProbe(
                re.compile(r"(?:checkov\s+)?(\d+\.\d+\.\d+)", re.IGNORECASE),
                # It imports its whole rule set before printing: 9.1 s cold
                # on Windows, straddling the 10 s default.
                timeout=30,
            ),
            exclusion_style=ExclusionStyle.REGEX,
            exclusion_flag="--skip-path",
            flag_grammar=FlagGrammar.ARGPARSE,
            # `-ocli` put the table where JMo reads JSON: 33 findings to 0
            # (measured, 3.3.16). Its `-f` is `--file`. `--no-fail-on-crash`
            # would turn a crash (rc 2) into rc 0.
            reserved_flags=_reserve(
                OUTPUT=("-o", "--output"),
                EXIT_CODE=(
                    "-s",
                    "--soft-fail",
                    "--soft-fail-on",
                    "--hard-fail-on",
                    "--no-fail-on-crash",
                ),
            ),
            short_switches=frozenset({"-h", "-l", "-s", "-v"}),
            trigger=_iac_trigger,
            stub={"results": {"failed_checks": []}},
        ),
        ToolDescriptor(
            name="hadolint",
            invocations={"repo": _file_fed("-f", "json")},
            version_probe=VersionProbe(
                re.compile(r"Haskell Dockerfile Linter\s+v?(\d+\.\d+\.\d+)")
            ),
            exclusion_style=ExclusionStyle.WALK,
            flag_grammar=FlagGrammar.OPTPARSE_APPLICATIVE,
            # A second `-f json` prints the report twice, which no JSON parser
            # reads (measured, 2.15.1).
            reserved_flags=_reserve(
                OUTPUT=("-f", "--format"),
                EXIT_CODE=("--no-fail", "-t", "--failure-threshold"),
            ),
            short_switches=frozenset({"-h", "-v", "-V"}),
            file_patterns=DOCKERFILE_PATTERNS,
            accepts_name=is_dockerfile,
            no_files_reason=Reason.NO_DOCKERFILES,
            stub=[],
        ),
        ToolDescriptor(
            name="shellcheck",
            invocations={"repo": _file_fed("--format=json")},
            version_probe=VersionProbe(
                re.compile(r"(?:version:?\s*)?(\d+\.\d+\.\d+)", re.IGNORECASE)
            ),
            exclusion_style=ExclusionStyle.WALK,
            flag_grammar=FlagGrammar.GETOPT,
            # JMo's `--format=json` comes first and wins today: `-ftty` changed
            # nothing (measured, 0.11.0). Refused anyway, since which one wins
            # is its parser's to decide. Its `-o` is `--enable`.
            reserved_flags=_reserve(OUTPUT=("-f", "--format")),
            short_switches=frozenset({"-a", "-V", "-x"}),
            file_patterns=("**/*.sh", "**/*.bash", "**/*.ksh"),
            no_files_reason=Reason.NO_SHELL_SCRIPTS,
        ),
        ToolDescriptor(
            name="zizmor",
            invocations={"repo": _zizmor_repo},
            # `zizmor --version` prints `zizmor 1.30.1` (measured).
            version_probe=VersionProbe(re.compile(r"zizmor\s+v?(\d+\.\d+\.\d+)")),
            exclusion_style=ExclusionStyle.WALK,
            flag_grammar=FlagGrammar.CLAP,
            # clap refuses a flag given twice, and JMo passes `--format`,
            # `--offline` (its `-o`) and `--no-exit-codes`: any of them again
            # is rc 2, "cannot be used multiple times" (measured, 1.30.1).
            # `--strict-collection` fails the run on an input it cannot read.
            reserved_flags=_reserve(
                OUTPUT=("--format",),
                PASSED=("-o", "--offline", "--no-exit-codes"),
                EXIT_CODE=("--strict-collection",),
            ),
            short_switches=frozenset({"-h", "-o", "-p", "-q", "-v", "-V"}),
            # The workflows GitHub runs (the root's, flat), every composite
            # action, and Dependabot's config, which has audits of its own
            # (6 `dependabot-cooldown` findings at 3098c766 without it).
            file_patterns=(
                ".github/workflows/*.yml",
                ".github/workflows/*.yaml",
                "**/action.yml",
                "**/action.yaml",
                ".github/dependabot.yml",
                ".github/dependabot.yaml",
            ),
            no_files_reason=Reason.NO_WORKFLOWS,
            # rc 3 with "no inputs collected": every file handed over was
            # invalid (measured, 1.30.1). Not a failure of zizmor.
            nothing_read=NothingRead(
                3, "no inputs collected", Reason.NO_READABLE_WORKFLOWS
            ),
            unread_inputs=_zizmor_unread,
            # Read from the root (measured, 1.30.1: a `zizmor.yml` in a
            # subdirectory is not).
            own_config=(
                "zizmor.yml",
                "zizmor.yaml",
                ".github/zizmor.yml",
                ".github/zizmor.yaml",
            ),
            stub={"version": "2.1.0", "runs": []},
        ),
        ToolDescriptor(
            name="jmo-native",
            invocations={"repo": _native_repo},
            # `--version` prints `jmo-native <JMo's version>`.
            version_probe=VersionProbe(
                re.compile(r"jmo-native\s+v?(\d+\.\d+\.\d+)"),
                command=[
                    sys.executable,
                    "-m",
                    "scripts.core.native_checks",
                    "--version",
                ],
            ),
            # As yara's: the runner prunes VENDORED_DIRS itself and takes the
            # results directory as --exclude-dir.
            exclusion_style=ExclusionStyle.INLINE,
            exclusion_flag="--exclude-dir",
            flag_grammar=FlagGrammar.ARGPARSE,
            # argparse is last-one-wins: a second --target re-points the scan
            # and a second --output moves the report.
            reserved_flags=_reserve(OUTPUT=("--output",), TARGET=("--target",)),
            short_switches=frozenset({"-h"}),
            trigger=_native_trigger,
            builtin=True,
            stub={"version": "2.1.0", "runs": []},
        ),
        ToolDescriptor(
            name="yara",
            invocations={"repo": _yara_repo},
            version_probe=VersionProbe(
                re.compile(r"v?(\d+\.\d+\.\d+)"),
                command=[sys.executable, "-c", "import yara; print(yara.YARA_VERSION)"],
            ),
            # JMo's own runner: it prunes VENDORED_DIRS itself and takes the
            # results directory as --exclude-dir.
            exclusion_style=ExclusionStyle.INLINE,
            exclusion_flag="--exclude-dir",
            flag_grammar=FlagGrammar.ARGPARSE,
            # As jmo-native's.
            reserved_flags=_reserve(OUTPUT=("--output",), TARGET=("--target",)),
            short_switches=frozenset({"-h"}),
        ),
        ToolDescriptor(
            name="grype",
            invocations={"repo": _grype_repo},
            version_probe=VersionProbe(_VERSION, command=["grype", "version"]),
            exclusion_style=ExclusionStyle.SEPARATE,
            exclusion_flag="--exclude",
            flag_grammar=FlagGrammar.PFLAG,
            # As syft's: `-otable` took 7 findings to 0 (measured, 0.118.0).
            # Its `-f` is `--fail-on`: rc 2 on a match at that severity, which
            # the row does not accept (measured).
            reserved_flags=_reserve(
                OUTPUT=("-o", "--output", "--file"),
                EXIT_CODE=("-f", "--fail-on"),
            ),
            short_switches=frozenset({"-h", "-q", "-v"}),
            # Reads vendored trees (#1205) except a virtualenv: 104 findings on
            # this repository were the dev machine's CPython (decided 2026-09-11).
            excluded_vendored=(".venv", "venv"),
            stub={"matches": []},
        ),
        ToolDescriptor(
            name="osv-scanner",
            invocations={"repo": _osv_scanner_repo},
            # `osv-scanner --version` prints `osv-scanner version: 2.6.0`, then
            # `osv-scalibr version: 0.5.2` (measured).
            version_probe=VersionProbe(
                re.compile(r"osv-scanner version:\s*v?(\d+\.\d+\.\d+)")
            ),
            exclusion_style=ExclusionStyle.WALK,
            # Exactly the names 2.6.0 accepts through `-L`: one it rejects
            # (`go.sum`, `package.json`, `pyproject.toml`, ...) aborts the
            # whole run, rc 127, no output (measured one by one).
            file_patterns=tuple(
                f"**/{name}" for name in osv_database.LOCKFILE_ECOSYSTEMS
            ),
            # It decides by the exact name: `Requirements.txt` is rejected,
            # and one rejected name loses every lockfile's findings.
            accepts_name=_osv_reads,
            no_files_reason=Reason.NO_LOCKFILE,
            precheck=_osv_databases,
            flag_grammar=FlagGrammar.GO_FLAG,
            # Where and how it writes: `-format table` took 40 findings to 0
            # (measured, 2.6.0). `--output` is `--output-file`'s deprecated
            # name; `--serve` serves the report as HTML instead. The download
            # flag would fetch mid-scan (measured: 207 -> 252 MB).
            reserved_flags=_reserve(
                OUTPUT=("-f", "--format", "--output-file", "--output", "--serve"),
                DOWNLOAD=("--download-offline-databases",),
            ),
            stub={"version": "2.1.0", "runs": []},
        ),
        ToolDescriptor(
            name="zap",
            invocations={"url": _zap_url},
            version_probe=VersionProbe(
                # Not the JVM's version, a four-part version's first three
                # parts, or the jar name zap.bat echoes when it cannot find
                # the jar (#1283).
                re.compile(
                    r"(?<!version )(?<!\d)(?<!\.)(?:(?:OWASP\s+)?(?:ZAP|Zed Attack Proxy)\s+)?"
                    r"v?(\d+\.\d+\.\d+)(?!\d|\.jar|\.\d)",
                    re.IGNORECASE,
                ),
                command={
                    "windows": ["zap.bat", "-version"],
                    "default": ["zap.sh", "-version"],
                },
                timeout=30,  # a JVM starts first
            ),
            exclusion_style=ExclusionStyle.NOT_FILESYSTEM,
            flag_grammar=FlagGrammar.ZAP,
            # Where it writes; the file's extension picks the format.
            reserved_flags=_reserve(OUTPUT=("-quickout",)),
            excluded_vendored=(),
            off_target_reason=Reason.NEEDS_URL,
            timeout_floor=900,
            binary="zap.sh",
            execution_commands=("zap.sh", "java"),
            stub={"site": []},
        ),
        ToolDescriptor(
            name="nuclei",
            invocations={"url": _nuclei_url},
            version_probe=VersionProbe(_VERSION, command=["nuclei", "-version"]),
            exclusion_style=ExclusionStyle.NOT_FILESYSTEM,
            flag_grammar=FlagGrammar.GO_FLAG,
            # `-jsonl=false` wrote text where JMo reads JSONL: 1 finding to 0
            # (measured, 3.11.1). Its other `-o...` and `-j...` flags are
            # names of their own (`-omit-raw`, `-je`), never `-o` chained.
            reserved_flags=_reserve(OUTPUT=("-o", "-output", "-j", "-jsonl")),
            excluded_vendored=(),
            off_target_reason=Reason.NEEDS_URL,
            execution_commands=("nuclei",),
            stub="",  # NDJSON: an empty file
        ),
    )
}


# The seventeen tools v2.0.0 removed (docs/TOOLS.md), and falco's companion.
REMOVED_TOOLS: frozenset[str] = frozenset(
    {
        "kubescape",
        "semgrep-secrets",
        "bandit",
        "trivy-rbac",
        "checkov-cicd",
        "noseyparker",
        "prowler",
        "akto",
        "scancode",
        "cdxgen",
        "dependency-check",
        "horusec",
        "falco",
        "falcoctl",
        "afl++",
        "mobsf",
        "lynis",
        "gosec",
    }
)

_NAME_SEPARATORS = re.compile(r"[,\s]+")


class UnknownToolError(ValueError):
    """A tool name that is not in the matrix. A usage error: exit 2 (#1279)."""


def parse_tool_names(values: Iterable[str]) -> list[str]:
    """Split `--tools a,b c` and `tools: [a, "b,c"]` into names, in order.

    `--tools trivy,syft` used to be one tool named `trivy,syft`, which ran
    nowhere, and e2e tests written that way passed while scanning nothing
    (#1279). Each name must be in the matrix; a removed one says so.
    """
    names: list[str] = []
    for value in values:
        for name in _NAME_SEPARATORS.split(str(value)):
            if name and name not in names:
                names.append(name)
    bad = [n for n in names if n not in DESCRIPTORS]
    if bad:
        removed = [n for n in bad if n in REMOVED_TOOLS]
        unknown = [n for n in bad if n not in REMOVED_TOOLS]
        parts = []
        if removed:
            parts.append(f"{', '.join(removed)}: removed in v2.0.0 (see docs/TOOLS.md)")
        if unknown:
            parts.append(f"unknown tool {', '.join(repr(n) for n in unknown)}")
        raise UnknownToolError(
            "; ".join(parts) + f". The tools are: {', '.join(DESCRIPTORS)}"
        )
    return names
