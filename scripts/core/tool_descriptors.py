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
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import quote

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


class ExclusionStyle(StrEnum):
    """How a tool is told to skip a directory. Measured per tool, never guessed.

    The style cannot be inferred from the flag's name. trivy and checkov both
    take a repeatable `--flag VALUE`, and the value that works is opposite:
    trivy's is a glob anchored at the scan root (`**/vendor` for any depth),
    checkov's a regex matched against the whole path (`**` does not compile
    and is dropped without a word, so `vendor` is right). syft and grype reject
    a bare name outright (rc 1: "must start with one of: './', '*/', or
    '**/'"), and `./results` covers only the root copy (measured 2026-09-25).
    """

    INLINE = "inline"  # one `--flag=NAME` per directory
    # One `--flag=REGEX` per directory, the name escaped and bounded to whole
    # path segments. gosec wraps the value as `([\\/])?VALUE([\\/])?` and
    # matches it against root-relative paths, so a bare `.git` also dropped
    # `.github/x` (measured 2026-09-25, gosec 2.28.0, its `Import directory`
    # log, which it writes with or without a Go toolchain).
    INLINE_REGEX = "inline_regex"
    SEPARATE = "separate"  # one `--flag **/NAME` pair per directory
    REGEX = "regex"  # one `--flag NAME` pair per directory
    PATTERN_FILE = "pattern_file"  # a generated file of regexes, one flag
    # A generated config file, one flag: gitleaks has no exclude flag at all,
    # only a config's `[[allowlists]] paths`.
    CONFIG_FILE = "config_file"
    WALK = "walk"  # JMo walks the tree and hands the tool its files
    NOT_FILESYSTEM = "not_filesystem"  # reads a URL, never a directory


@dataclass(frozen=True)
class ScanContext:
    """What one tool's builder and trigger see for one target."""

    tool: str
    target_type: str
    target: Any  # Path (repo, iac), str (image, url), Mapping (k8s)
    out_dir: Path
    binary: str = ""
    flags: tuple[str, ...] = ()
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


@dataclass(frozen=True)
class VersionProbe:
    """How `jmo tools check` reads the installed version."""

    pattern: re.Pattern[str]
    # None: `<binary> --version`. A mapping is keyed by platform, with "default".
    command: list[str] | dict[str, list[str]] | None = None
    # None: tool_manager's default budget.
    timeout: int | None = None


Builder = Callable[[ScanContext], list[Invocation]]
Trigger = Callable[[ScanContext], Reason | None]


@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    # target type -> the command lines for it. The keys are the tool's target
    # types; a GitLab target runs the repository builders on its clone.
    invocations: Mapping[str, Builder]
    version_probe: VersionProbe
    exclusion_style: ExclusionStyle
    exclusion_flag: str | None = None
    # VENDORED_DIRS entries this tool is told to skip (the results directory
    # is excluded for every filesystem tool regardless).
    excluded_vendored: tuple[str, ...] = VENDORED_DIRS
    # Content the tool needs: walk-fed file patterns, or a predicate.
    file_patterns: tuple[str, ...] = ()
    no_files_reason: Reason | None = None
    trigger: Trigger | None = None
    off_target_reason: Reason = Reason.NOT_FOR_TARGET
    timeout_floor: int = 0
    binary: str | None = None  # executable name, where it differs from `name`
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


# --- content triggers ---------------------------------------------------------


def _is_go(path: Path) -> bool:
    return path.suffix == ".go" or path.name == "go.mod"


def _go_trigger(ctx: ScanContext) -> Reason | None:
    """gosec loads Go packages. `go.mod` alone counts: a module whose sources
    are generated at build time still carries one, and over-triggering costs a
    fast run that finds nothing while under-triggering drops a scanner from a
    real Go repository (#1081)."""
    return None if ctx.any_file(_is_go) else Reason.NO_GO_SOURCES


_CFN_SUFFIXES = frozenset({".yaml", ".yml", ".json", ".template"})
_CFN_MARKERS = (b"AWSTemplateFormatVersion", b"AWS::")
_CFN_HEAD_BYTES = 8192


def _is_iac(path: Path) -> bool:
    """Terraform, CloudFormation, Helm, or a GitHub Actions workflow.

    checkov's trigger (Phase 3 decision): the cut folded checkov-cicd into
    checkov, so `.github/workflows` is checkov's until Phase 4 hands it to
    zizmor. CloudFormation has no file name of its own, so a YAML or JSON file
    counts when its first 8 KB name an `AWS::` type or the template version.
    """
    name = path.name
    if name.endswith((".tf", ".tf.json")) or name == "Chart.yaml":
        return True
    if path.suffix in (".yml", ".yaml") and path.parent.name == "workflows":
        if path.parent.parent.name == ".github":
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


def _gosec_scanned(path: Path) -> int | None:
    """`Stats.files`: 0 whenever gosec cannot load a package, which is every
    run without a Go toolchain (measured on Windows and in the image)."""
    data = _load(path)
    if not isinstance(data, dict):
        return None
    files = (data.get("Stats") or {}).get("files")
    return files if isinstance(files, int) else None


# --- command lines ------------------------------------------------------------


def scan_root(target: Any) -> str:
    """The absolute root trufflehog is given, and its exclude patterns anchor on.

    One function for both, so they cannot disagree. Absolute because Go's
    `filepath.Join` cleans `./sub` to `sub`: a pattern anchored on `.`, which
    is what `--repo .` passes, would never match anything.
    """
    return str(Path(target).resolve())


def _asks_for_verified_results(flags: tuple[str, ...]) -> bool:
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


def _trufflehog_repo(ctx: ScanContext) -> list[Invocation]:
    # Verification sends each candidate secret to its issuer, and git mode
    # multiplies the candidates: off unless `per_tool.trufflehog.verify` is
    # true (decided 2026-09-26), or the user's flags ask for verified results.
    # An unverified finding is graded MEDIUM.
    verify = ctx.tool_config.get("verify") is True or _asks_for_verified_results(
        ctx.flags
    )
    verification = () if verify else ("--no-verification",)
    root = scan_root(ctx.target)
    invocations = [
        Invocation(
            command=(
                ctx.binary,
                "filesystem",
                root,
                "--json",
                "--no-update",
                *verification,
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
                    *verification,
                    *ctx.history_exclusion_args,
                    *ctx.flags,
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
    modes = [("dir", ctx.output)]
    if ctx.history:
        modes.append(("git", ctx.history_output))
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
                *ctx.flags,
            ),
            output_file=output,
            capture_stdout=False,
            ok_return_codes=(0,),
            cwd=Path(scan_root(ctx.target)),
            label=mode,
        )
        for mode, output in modes
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


def _checkov(flag: str, excl: bool) -> Builder:
    def build(ctx: ScanContext) -> list[Invocation]:
        return [
            Invocation(
                command=(
                    ctx.binary,
                    flag,
                    str(ctx.target),
                    "-o",
                    "json",
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


def _gosec_repo(ctx: ScanContext) -> list[Invocation]:
    return [
        Invocation(
            command=(
                ctx.binary,
                "-fmt=json",
                f"-out={ctx.output}",
                *ctx.exclusion_args,
                *ctx.flags,
                str(Path(ctx.target) / "..."),
            ),
            output_file=ctx.output,
            capture_stdout=False,
            ok_return_codes=(0, 1),
        )
    ]


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
            stub={"version": "2.1.0", "runs": []},
            reads_history=True,
        ),
        ToolDescriptor(
            name="semgrep",
            invocations={"repo": _semgrep_repo},
            version_probe=VersionProbe(re.compile(r"^(\d+\.\d+\.\d+)$", re.MULTILINE)),
            exclusion_style=ExclusionStyle.INLINE,
            exclusion_flag="--exclude",
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
            # An SBOM inventories exactly those trees (#1205).
            excluded_vendored=(),
            stub={"artifacts": []},
        ),
        ToolDescriptor(
            name="trivy",
            invocations={
                "repo": _trivy("fs", "--scanners", "vuln,secret,misconfig", excl=True),
                "image": _trivy("image", "--scanners", "vuln,secret,misconfig"),
                "iac": _trivy("config"),
                "k8s": _trivy_k8s,
            },
            version_probe=VersionProbe(_VERSION),
            exclusion_style=ExclusionStyle.SEPARATE,
            exclusion_flag="--skip-dirs",
            stub={"Results": []},
        ),
        ToolDescriptor(
            name="checkov",
            invocations={
                "repo": _checkov("-d", excl=True),
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
            file_patterns=("**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile"),
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
            file_patterns=("**/*.sh", "**/*.bash", "**/*.ksh"),
            no_files_reason=Reason.NO_SHELL_SCRIPTS,
        ),
        ToolDescriptor(
            name="gosec",
            invocations={"repo": _gosec_repo},
            version_probe=VersionProbe(_VERSION),
            exclusion_style=ExclusionStyle.INLINE_REGEX,
            # A regex at any depth; `**/results` exits 2 (measured, 2.29.0).
            exclusion_flag="-exclude-dir",
            trigger=_go_trigger,
            execution_commands=("gosec",),
            scanned_count=_gosec_scanned,
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
        ),
        ToolDescriptor(
            name="grype",
            invocations={"repo": _grype_repo},
            version_probe=VersionProbe(_VERSION, command=["grype", "version"]),
            exclusion_style=ExclusionStyle.SEPARATE,
            exclusion_flag="--exclude",
            # Reads vendored trees (#1205) except a virtualenv: 104 findings on
            # this repository were the dev machine's CPython (decided 2026-09-11).
            excluded_vendored=(".venv", "venv"),
            stub={"matches": []},
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
            excluded_vendored=(),
            off_target_reason=Reason.NEEDS_URL,
            execution_commands=("nuclei",),
            stub="",  # NDJSON: an empty file
        ),
    )
}


# The sixteen tools v2.0.0 removed (docs/TOOLS.md), and falco's companion.
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
