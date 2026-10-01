"""The one loop every scan job runs its tools through (v2.0.0 Phase 3).

Before it, each of the six scan jobs had a hand-written block per tool, eighteen
in all, and a block's branches decided whether a tool was recorded at all:
hadolint and shellcheck collected no files, took the branch with no `else`,
and vanished from the scan (#1227). Here every requested tool leaves with
exactly one `ToolRun`, in this order:

1. **off-target**: the tool does not read this kind of target, so it is
   `skipped` (`needs --url` for zap and nuclei).
2. **binary**: not found is `failed:not installed`, or `skipped:not installed`
   under `--allow-missing-tools` (#825's semantics).
3. **content**: a tool that needs files of a kind the target lacks is
   `skipped` with that reason (no Dockerfiles, no IaC files). A
   tool's `precheck` then fails the row for what of that content it cannot
   read (osv-scanner: a lockfile with no offline database), and it runs on
   the rest, or not at all.
4. **run**: `ToolRunner`'s result becomes `ran` or `failed:<reason>`, and a
   tool whose own output says it examined 0 files is `failed` (G2, #1231).
   An invocation that failed the way its `Fallback` names is replaced by the
   fallback's invocations, run in a second round.

Before any of that, a repository whose pruned walk yields no file at all fails
every tool that would have read it: nothing was there to scan (G2).
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import replace
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from ...core.config import RetryConfig
from ...core.scan_timings import (
    OUTCOME_FAILED_BEFORE_TOOLS,
    Reason,
    State,
    TargetRows,
    ToolRun,
    write_scan_timings,
)
from ...core.tool_descriptors import (
    DESCRIPTORS,
    PART_OUTPUT,
    VENDORED_DIRS,
    ExclusionStyle,
    Fallback,
    Invocation,
    ScanContext,
    Shortfall,
    ToolDescriptor,
    read_history,
    scan_root,
)
from ...core.tool_runner import ToolDefinition, ToolResult
from ..scan_utils import (
    find_tool,
    gitleaks_config_warning,
    report_tool_failure,
    tool_exclusion_flags,
    tool_flags,
    tool_timeout,
    write_gitleaks_config,
    write_stub,
    write_trufflehog_exclude_file,
)

logger = logging.getLogger(__name__)

# Upper bound on file arguments passed to a single per-file tool invocation.
# Windows caps a command line at 32767 characters; a few hundred absolute paths
# stays well inside that while covering every repository we have measured
# (docker-library/postgres, the densest, has 55 shell scripts and 26
# Dockerfiles). Exceeding it is reported, never silently truncated.
MAX_FILE_ARGS = 300

_SKIPPED_DIR_NAMES: frozenset[str] = frozenset(VENDORED_DIRS)


def _same_tree(candidate: Path, target: Path) -> bool:
    """True when ``candidate`` is ``target``, resolving both.

    Returns False on OSError: an unresolvable directory is not a reason to
    abort a scan, and Python 3.12 propagates PermissionError from path
    operations rather than returning False (#1163).
    """
    try:
        return candidate.resolve() == target
    except OSError:
        return False


def iter_repo_files(repo: Path, skip_tree: Path | None = None) -> Iterator[Path]:
    """Yield every file under ``repo``, never descending into a skipped tree.

    ``skip_tree`` is an absolute directory pruned by PATH -- JMo's own results
    directory when it sits inside the repository (#1156) -- so a same-named
    directory elsewhere is kept. ``os.walk`` so pruning happens by assigning
    into ``dirnames`` and a vendored tree is never *entered*; a generator, so a
    caller asking "is there one?" stops at the first.
    """
    for dirpath, dirnames, filenames in os.walk(repo):
        base = Path(dirpath)
        dirnames[:] = [
            d
            for d in dirnames
            if d not in _SKIPPED_DIR_NAMES
            and not (skip_tree is not None and _same_tree(base / d, skip_tree))
        ]
        for filename in filenames:
            yield base / filename


def collect_files(
    repo: Path,
    patterns: tuple[str, ...],
    tool_name: str,
    skip_tree: Path | None = None,
    accepts_name: Callable[[str], bool] | None = None,
) -> list[str]:
    """Collect matching files for a tool that takes file arguments.

    hadolint used to take `dockerfiles[0]`, which on docker-library/postgres
    meant 1 of 26 files scanned, with nothing in the output to say so.

    `accepts_name` is the tool's own test of a file name, for a tool that
    decides by the exact name: on Windows the glob ignores case, so it found
    `Requirements.txt` and `Package-Lock.json` for osv-scanner, which rejects
    both and then read nothing at all. A file it refuses is left out, and
    named when the patterns match it only by ignoring case. One they match as
    spelled is a name the test refuses on purpose (`Dockerfile.md` is no
    Dockerfile), and a WARNING beside every run read as a missed file.
    """
    seen: set[Path] = set()
    for pattern in patterns:
        for path in repo.glob(pattern):
            # Relative to the repository: a repository that itself lives under
            # `vendor/` or `node_modules/` still has content of its own.
            if set(path.relative_to(repo).parts) & _SKIPPED_DIR_NAMES:
                continue
            if skip_tree is not None and any(
                _same_tree(parent, skip_tree) for parent in path.parents
            ):
                continue
            if path.is_file():
                seen.add(path)

    if accepts_name is not None:
        refused = sorted(p for p in seen if not accepts_name(p.name))
        seen.difference_update(refused)
        names = [pattern.rsplit("/", 1)[-1] for pattern in patterns]
        miscased = [
            p for p in refused if not any(fnmatchcase(p.name, n) for n in names)
        ]
        if miscased:
            logger.warning(
                "%s: %d file(s) matched its patterns but not a name it reads "
                "(it reads names exactly, case included) - NOT scanned: %s",
                tool_name,
                len(miscased),
                ", ".join(p.relative_to(repo).as_posix() for p in miscased),
            )

    files = sorted(seen)
    if len(files) > MAX_FILE_ARGS:
        logger.warning(
            "%s: %d matching files in %s, scanning the first %d "
            "(command-line length limit) - %d file(s) NOT scanned",
            tool_name,
            len(files),
            repo.name,
            MAX_FILE_ARGS,
            len(files) - MAX_FILE_ARGS,
        )
        files = files[:MAX_FILE_ARGS]
    return [str(f) for f in files]


def invocation_key(target_type: str) -> str:
    """The descriptor key a target type reads: a GitLab clone is a repository."""
    return "repo" if target_type == "gitlab" else target_type


def _descriptor(tool: str) -> ToolDescriptor:
    try:
        return DESCRIPTORS[tool]
    except KeyError:
        # `parse_tool_names` rejects an unknown name before a scan starts
        # (#1279), so reaching here is a caller's defect, not user input.
        raise ValueError(f"unknown tool {tool!r}") from None


def rows_without_running(
    tools: Iterable[str],
    target_type: str,
    reason: Reason,
    detail: str | None = None,
) -> TargetRows:
    """Rows for a target no tool reached: a failed clone, a scanner that raised.

    A tool that does not read this kind of target is `skipped` as it would have
    been anyway; every other one is `failed` with `reason`.
    """
    key = invocation_key(target_type)
    rows: TargetRows = {}
    for tool in dict.fromkeys(tools):
        d = _descriptor(tool)
        rows[tool] = (
            ToolRun(tool, State.FAILED, reason, detail=detail)
            if key in d.invocations
            else ToolRun(tool, State.SKIPPED, d.off_target_reason)
        )
    return rows


def _resolve(d: ToolDescriptor, find: Callable[[str], str | None]) -> str | None:
    """The tool's executable: its binary name first, then its own name."""
    for name in dict.fromkeys(filter(None, (d.binary, d.name))):
        path = find(name)
        if path:
            return path
    return None


def _history_off(per_tool_config: Mapping[str, Any], tool: str) -> bool:
    """`per_tool.<tool>.history: false`: keep the tree's scan, skip git
    history, for a repository whose history is too large or too noisy
    (#1327)."""
    config = per_tool_config.get(tool)
    return isinstance(config, dict) and config.get("history") is False


def _repository_gitleaks_config(root: Path) -> Path | None:
    """The repository's own `.gitleaks.toml`, which gitleaks reads when run
    alone and JMo's config extends (#1327). Python 3.12 raises from a probe
    where 3.11 returned False (#1163), hence the guard."""
    own = root / ".gitleaks.toml"
    try:
        return own if own.is_file() else None
    except OSError:
        return None


def _announce_own_config(d: ToolDescriptor, root: Path) -> None:
    """Say which of the repository's own files `d` reads as its configuration.

    The repository then decides part of its own audit (zizmor: a
    `.github/zizmor.yml` disabling two audits took a sample from 3 rule ids to
    1, unannounced, #1363), so the scan says so at INFO, as it does for
    gitleaks' `.gitleaks.toml` (#1327). Python 3.12 raises from a probe where
    3.11 returned False (#1163), hence the guard."""
    for name in d.own_config:
        try:
            if not (root / name).is_file():
                continue
        except OSError:
            continue
        logger.info(
            "%s: %s reads its %s (its audit settings apply)", root.name, d.name, name
        )


def _exclusions(
    d: ToolDescriptor, out_dir: Path, results_name: str | None, target: Any
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The exclusion arguments for the working tree, and for git history.

    They differ only for trufflehog: filesystem mode sees absolute paths, so
    its patterns are anchored below the scan root (a repository under
    `vendor/` read nothing otherwise, B5), while git mode sees
    repository-relative ones that an anchored pattern never matches.
    """
    if d.exclusion_style is ExclusionStyle.PATTERN_FILE and d.exclusion_flag:
        tree = write_trufflehog_exclude_file(
            out_dir, results_dir_name=results_name, root=scan_root(target)
        )
        history = write_trufflehog_exclude_file(
            out_dir, results_dir_name=results_name, name=".trufflehog-exclude-git"
        )
        return (d.exclusion_flag, str(tree)), (d.exclusion_flag, str(history))
    if d.exclusion_style is ExclusionStyle.CONFIG_FILE and d.exclusion_flag:
        root = Path(scan_root(target))
        repo_config = _repository_gitleaks_config(root)
        if repo_config is not None:
            # The scanned repository's config now shapes gitleaks' run: its
            # rules and allowlists apply, as when gitleaks runs alone. Said,
            # since the repository decides part of its own audit (#1327).
            logger.info(
                "%s: gitleaks extends its .gitleaks.toml (its rules and "
                "allowlists apply)",
                root.name,
            )
            warning = gitleaks_config_warning(repo_config, root)
            if warning:
                logger.warning("%s: %s", root.name, warning)
        path = write_gitleaks_config(
            out_dir, results_dir_name=results_name, repo_config=repo_config
        )
        args = (d.exclusion_flag, str(path))
        return args, args
    flags = tuple(tool_exclusion_flags(d.name, results_dir_name=results_name))
    return flags, flags


def _failure(
    tool: str,
    result: ToolResult,
    out_dir: Path,
    stub: Callable[[str, Path], None],
    others_ran: bool = False,
) -> tuple[Reason, str]:
    """One failed invocation's reason and words, said on a durable stream.

    The log line matters: the Rich progress glyph is the only other trace, and
    a non-TTY run (CI, cron, a detached scan) never renders one.
    """
    if result.failure == "missing_tool":
        # It resolved, got a command line, and then could not be executed:
        # always a defect (find_tool's old "python:yara" pseudo-path), never
        # something --allow-missing-tools consents to. No stub, either.
        reason, words = (
            Reason.NOT_FOUND_AT_RUN,
            "its executable was not found at run time",
        )
    elif result.timed_out:
        # A stub keeps the report phase's file tree consistent; the row and
        # the log line are what say it timed out.
        tool_out = out_dir / f"{tool}.json"
        if not tool_out.exists():
            stub(tool, tool_out)
        reason, words = Reason.TIMED_OUT, "it timed out"
    elif result.status == "no_output":
        reason, words = (
            Reason.NO_OUTPUT,
            "it exited with an accepted code but wrote no output",
        )
    elif result.failure == "crash":
        reason, words = Reason.EXIT_CODE, "it failed"
    else:
        reason, words = Reason.COULD_NOT_RUN, "it failed"
    report_tool_failure(result, words, others_ran)
    return reason, words


def _row_from_results(
    d: ToolDescriptor,
    results: list[ToolResult],
    invocations: int,
    out_dir: Path,
    stub: Callable[[str, Path], None],
    labels: Mapping[Path, str] | None = None,
    handed: Sequence[str] = (),
) -> ToolRun:
    tool = d.name
    if not results:
        return ToolRun(
            tool,
            State.FAILED,
            Reason.SCANNER_ERROR,
            invocations=invocations,
            detail="no result came back for its invocation",
        )
    seconds = sum(r.duration for r in results)
    attempts = sum(r.attempts for r in results)
    unread: dict[str, str] = {}
    if d.unread_inputs is not None:
        unread = d.unread_inputs("\n".join(r.stderr or "" for r in results), handed)
    nothing = d.nothing_read
    if nothing is not None and all(
        r.status != "success"
        and r.returncode == nothing.returncode
        and nothing.stderr_marker in (r.stderr or "")
        for r in results
    ):
        # Handed files, read none: nothing was there to audit, and the tool's
        # own exit code for it is not a failure of the tool. The files are
        # named, since the row's reason is a closed-set label.
        stub(tool, out_dir / f"{tool}.json")
        named = unread or dict.fromkeys(handed, "it was not read")
        _warn_unread(tool, named)
        return ToolRun(
            tool,
            State.SKIPPED,
            nothing.reason,
            seconds=seconds,
            exit_code=results[0].returncode,
            attempts=attempts,
            invocations=invocations,
            detail=f"it read none of the files handed to it: {', '.join(named)}",
        )
    for r in results:
        # Tools told where to write wrote their own file; the rest printed it.
        # Before any failure is graded: a failed history run must not throw
        # away the tree's findings, which ran fine.
        if r.status == "success" and r.output_file and r.capture_stdout:
            r.output_file.write_text(r.stdout or "", encoding="utf-8")
    labels = labels or {}
    failed = [r for r in results if r.status != "success"]
    if failed:
        # One row covers every invocation (G1: the tree and git history), so
        # each failed one is named, in the order the builder made them: two
        # failures have two causes, and naming only the first hid the other
        # (#1324).
        order = list(labels)
        failed.sort(
            key=lambda r: (
                order.index(r.output_file) if r.output_file in order else len(order)
            )
        )
        others_ran = len(failed) < len(results)
        causes = [_failure(tool, r, out_dir, stub, others_ran) for r in failed]
        parts: list[str] = []
        for r, (_reason, words) in zip(failed, causes, strict=True):
            label = labels.get(r.output_file, "") if r.output_file else ""
            if label:
                parts.append(f"{label}: {r.error_message or words}")
            elif r.error_message:
                parts.append(r.error_message)
        return ToolRun(
            tool,
            State.FAILED,
            causes[0][0],
            seconds=seconds,
            exit_code=None if failed[0].returncode == -1 else failed[0].returncode,
            attempts=attempts,
            invocations=invocations,
            detail="; ".join(parts) or None,
        )
    # The tree's run writes the tool's own `<tool>.json`; history's writes
    # another. The tree's exit code and examined count speak for the row, not
    # whichever run the runner happened to finish first or last (#1324).
    primary = next(
        (r for r in results if r.output_file == out_dir / f"{tool}.json"), results[0]
    )
    exit_code = primary.returncode
    if d.scanned_count is not None:
        examined = d.scanned_count(primary.output_file or out_dir / f"{tool}.json")
        if examined == 0:
            # "Scanned 4 files, found nothing" and "scanned 0 files" were
            # indistinguishable in every artifact (#1231).
            logger.error(
                "%s: examined 0 files - it did NOT contribute findings to this "
                "scan, though the target has files to scan",
                tool,
            )
            return ToolRun(
                tool,
                State.FAILED,
                Reason.EXAMINED_ZERO,
                seconds=seconds,
                exit_code=exit_code,
                attempts=attempts,
                invocations=invocations,
                detail="its output reports 0 files examined",
            )
    # The others were read and the row is `ran`; the log and the record name
    # what was dropped (a file the row implies was audited, and was not).
    _warn_unread(tool, unread)
    return ToolRun(
        tool,
        State.RAN,
        seconds=seconds,
        exit_code=exit_code,
        attempts=attempts,
        invocations=invocations,
        detail=f"not audited: {', '.join(unread)}" if unread else None,
    )


def _kept_findings(d: ToolDescriptor, results: Iterable[ToolResult]) -> int | None:
    """The findings a failed row's runs that worked still wrote, which reach
    the report (#1369), or None when none of them worked. A run worked when
    it succeeded and examined something: one whose output reports 0 files
    examined is the row's `EXAMINED_ZERO`, not a run that worked. This scan's
    runs only: a file an earlier scan left is not a finding of this one."""
    written = [
        r.output_file
        for r in results
        if r.status == "success"
        and r.output_file
        and (d.scanned_count is None or d.scanned_count(r.output_file) != 0)
    ]
    if not written:
        return None
    # Imported here: the report phase's module (compliance mapping, the
    # reporters) is otherwise not loaded by the scan loop, and only a failed
    # row with a run that worked needs it.
    from ...core.normalize_and_report import count_findings

    return sum(count_findings(path) for path in written)


def _warn_unread(tool: str, unread: Mapping[str, str]) -> None:
    for name, why in unread.items():
        logger.warning(
            "%s: %s was NOT audited: %s - its findings, if any, are MISSING "
            "from this scan",
            tool,
            name,
            why,
        )


def _unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("could not remove %s from an earlier scan: %s", path, exc)


def _remove_parts(out_dir: Path, tool: str) -> None:
    """Remove the fallback outputs (`PART_OUTPUT`) an earlier scan left."""
    for stale in out_dir.glob(PART_OUTPUT.format(tool=tool, n="*")):
        _unlink(stale)


def _fallen_back(
    results: list[ToolResult],
    planned: Mapping[str, tuple[ToolDescriptor, list[Invocation]]],
) -> dict[str, list[tuple[ToolResult, Invocation, Fallback]]]:
    """Each failed result whose invocation's `Fallback` names its failure (a
    return code it lists and its marker in stderr), with that invocation."""
    fallen: dict[str, list[tuple[ToolResult, Invocation, Fallback]]] = {}
    for result in results:
        if result.status == "success" or result.tool not in planned:
            continue
        for inv in planned[result.tool][1]:
            fallback = inv.fallback
            if (
                inv.output_file == result.output_file
                and fallback is not None
                and result.returncode in fallback.returncodes
                and fallback.stderr_marker in (result.stderr or "")
            ):
                fallen.setdefault(result.tool, []).append((result, inv, fallback))
                break
    return fallen


def run_tools(
    *,
    tools: Iterable[str],
    target_type: str,
    target: Any,
    target_label: str,
    out_dir: Path,
    timeout: int,
    retries: int | RetryConfig,
    per_tool_config: Mapping[str, Any],
    allow_missing_tools: bool,
    runner_cls: Callable[..., Any],
    find_tool_func: Callable[[str], str | None] | None = None,
    write_stub_func: Callable[[str, Path], None] | None = None,
    progress_callback: Callable[..., None] | None = None,
    repo_root: Path | None = None,
    results_name: str | None = None,
    results_tree: Path | None = None,
) -> TargetRows:
    """Run every requested tool that applies to this target; one row per tool.

    Args:
        tools: The requested tools, all of them: a tool that does not read this
            kind of target still gets its row.
        target_type: 'repo', 'gitlab', 'image', 'iac', 'url' or 'k8s'.
        target: What the builders scan (a path, an image, a URL, k8s info).
        target_label: The name the timings document records.
        out_dir: This target's output directory, already created.
        runner_cls: `ToolRunner`, passed by each job from its own module so a
            test patching `<job>.ToolRunner` still reaches it.
        repo_root: The directory to walk for content triggers and G2; None for
            targets that are not a tree.
        results_name: The in-tree results directory's name, for the flags.
        results_tree: The same directory, resolved, for JMo's own walk.
    """
    find = find_tool_func or find_tool
    stub = write_stub_func or write_stub
    key = invocation_key(target_type)
    ordered = list(dict.fromkeys(tools))
    walk: Callable[[], Iterator[Path]] | None = None
    if repo_root is not None:
        root = repo_root

        def walk() -> Iterator[Path]:
            return iter_repo_files(root, results_tree)

    if walk is not None and next(walk(), None) is None:
        empty = rows_without_running(
            ordered,
            target_type,
            Reason.NO_FILES_TO_SCAN,
            detail="the target has no files outside the excluded directories",
        )
        logger.error(
            "%s: no files to scan once %s are excluded - no tool ran against it",
            target_label,
            ", ".join(VENDORED_DIRS),
        )
        write_scan_timings(
            out_dir,
            empty,
            target=target_label,
            target_type=target_type,
            wall_seconds=0.0,
            outcome=OUTCOME_FAILED_BEFORE_TOOLS,
            error=str(Reason.NO_FILES_TO_SCAN),
        )
        return empty

    # One git probe per repository, for the tools that read its history (G1)
    # and were not told not to (#1327).
    history, history_gap = False, ""
    readers = [
        t
        for t in ordered
        if _descriptor(t).reads_history and not _history_off(per_tool_config, t)
    ]
    if key == "repo" and readers:
        history, history_gap = read_history(Path(scan_root(target)))
        if history_gap:
            logger.warning(
                "%s: git history not read (%s) - a secret committed and later "
                "removed is NOT reported for it",
                target_label,
                history_gap,
            )

    def definition(tool: str, inv: Invocation) -> ToolDefinition:
        return ToolDefinition(
            name=tool,
            command=list(inv.command),
            output_file=inv.output_file,
            timeout=tool_timeout(per_tool_config, tool, timeout),
            retries=retries,
            ok_return_codes=inv.ok_return_codes,
            capture_stdout=inv.capture_stdout,
            cwd=inv.cwd,
            env=inv.env,
        )

    rows: TargetRows = {}
    planned: dict[str, tuple[ToolDescriptor, list[Invocation]]] = {}
    shortfalls: dict[str, Shortfall] = {}
    definitions: list[ToolDefinition] = []
    for tool in ordered:
        d = _descriptor(tool)
        builder = d.invocations.get(key)
        if builder is None:
            rows[tool] = ToolRun(tool, State.SKIPPED, d.off_target_reason)
            continue
        # A fallback writes one file per input, so an earlier scan's may be
        # more than this one writes, and the report reads every file here.
        _remove_parts(out_dir, tool)

        binary = _resolve(d, find)
        if not binary:
            if allow_missing_tools:
                # An explicit, user-requested empty result - not a silent one:
                # the row says it did not run.
                stub(tool, out_dir / f"{tool}.json")
                rows[tool] = ToolRun(tool, State.SKIPPED, Reason.NOT_INSTALLED)
            else:
                logger.error(
                    "%s: requested but its executable could not be found - it "
                    "did NOT run and its findings are MISSING from this scan. "
                    "Run `jmo tools check` to confirm installation, or pass "
                    "--allow-missing-tools to record an explicit empty result.",
                    tool,
                )
                rows[tool] = ToolRun(
                    tool,
                    State.FAILED,
                    Reason.NOT_INSTALLED,
                    detail="its executable could not be found",
                )
            continue

        tool_config = per_tool_config.get(tool)
        files: tuple[str, ...] = ()
        if d.file_patterns and repo_root is not None:
            files = tuple(
                collect_files(
                    repo_root, d.file_patterns, tool, results_tree, d.accepts_name
                )
            )
        tree_excl, history_excl = (
            _exclusions(d, out_dir, results_name, target) if key == "repo" else ((), ())
        )
        ctx = ScanContext(
            tool=tool,
            target_type=key,
            target=target,
            out_dir=out_dir,
            binary=binary,
            # The resolved executable: a `.cmd` launcher's argv is re-parsed.
            flags=tuple(tool_flags(per_tool_config, tool, executable=binary)),
            history_flags=tuple(
                tool_flags(per_tool_config, tool, "history_flags", executable=binary)
            ),
            tool_config=tool_config if isinstance(tool_config, dict) else {},
            exclusion_args=tree_excl,
            history_exclusion_args=history_excl,
            history=history and tool in readers,
            files=files,
            iter_files=walk,
        )
        # Content decides only on a tree. An IaC file target is itself the
        # content checkov reads; walking for it there would find nothing.
        reason: Reason | None = None
        if walk is not None:
            if d.file_patterns:
                reason = None if files else d.no_files_reason
            elif d.trigger is not None:
                reason = d.trigger(ctx)
        if reason is not None:
            stub(tool, ctx.output)
            rows[tool] = ToolRun(tool, State.SKIPPED, reason)
            continue
        if walk is not None and d.precheck is not None:
            shortfall = d.precheck(ctx)
            if shortfall is not None:
                logger.error(
                    "%s: %s - what it cannot read is MISSING from this scan",
                    tool,
                    shortfall.detail,
                )
                if not shortfall.files:
                    rows[tool] = ToolRun(
                        tool, State.FAILED, shortfall.reason, detail=shortfall.detail
                    )
                    continue
                ctx = replace(ctx, files=shortfall.files)
                shortfalls[tool] = shortfall

        if key == "repo":
            _announce_own_config(d, Path(scan_root(target)))
        invocations = builder(ctx)
        planned[tool] = (d, invocations)
        definitions.extend(definition(tool, inv) for inv in invocations)

    runner = runner_cls(tools=definitions, progress_callback=progress_callback)
    started = time.perf_counter()
    results: list[ToolResult] = runner.run_all_parallel()

    # A second round, for the invocations that failed the way their fallback
    # names: each is replaced by the fallback's invocations.
    fallen = _fallen_back(results, planned)
    second: list[ToolDefinition] = []
    for tool, pairs in fallen.items():
        d, invocations = planned[tool]
        instead: list[Invocation] = []
        for _result, inv, fallback in pairs:
            logger.warning(
                "%s: one of the %d inputs of a run could not be read, so it "
                "runs once for each of them",
                tool,
                len(fallback.invocations),
            )
            # It wrote nothing, so a file there is an earlier scan's.
            _unlink(inv.output_file)
            instead.extend(fallback.invocations)
        gone = {id(inv) for _, inv, _ in pairs}
        planned[tool] = (d, [i for i in invocations if id(i) not in gone] + instead)
        second.extend(definition(tool, i) for i in instead)
    if second:
        superseded = {id(r) for pairs in fallen.values() for r, _, _ in pairs}
        results = [r for r in results if id(r) not in superseded]
        runner = runner_cls(tools=second, progress_callback=progress_callback)
        results += runner.run_all_parallel()
    wall = time.perf_counter() - started

    by_tool: dict[str, list[ToolResult]] = {}
    for result in results:
        by_tool.setdefault(result.tool, []).append(result)
    for tool, (d, invocations) in planned.items():
        # Each failed invocation is named by its label, in the builder's order.
        labels = {inv.output_file: inv.label for inv in invocations}
        row = _row_from_results(
            d,
            by_tool.get(tool, []),
            len(invocations),
            out_dir,
            stub,
            labels,
            tuple(f for inv in invocations for f in inv.inputs),
        )
        if tool in fallen:
            # What the replaced run cost is part of what the row cost.
            replaced = [r for r, _, _ in fallen[tool]]
            row = replace(
                row,
                seconds=row.seconds + sum(r.duration for r in replaced),
                attempts=row.attempts + sum(r.attempts for r in replaced),
                invocations=row.invocations + len(replaced),
            )
        if d.reads_history and row.state is State.RAN:
            # The tree ran, so the row is `ran`; the record says history did not.
            if tool not in readers:
                row = replace(
                    row,
                    detail=f"history not read: per_tool.{tool}.history is false",
                )
            elif history_gap:
                row = replace(row, detail=f"history not read: {history_gap}")
        if tool in shortfalls:
            # Decided before the run, so it is the row's reason whatever the
            # run did; what the run itself says follows it.
            shortfall = shortfalls[tool]
            said = row.detail if row.state is State.FAILED and row.detail else ""
            row = replace(
                row,
                state=State.FAILED,
                reason=shortfall.reason,
                detail="; ".join(filter(None, (shortfall.detail, said))),
            )
        if row.state is State.FAILED:
            row = replace(row, kept_findings=_kept_findings(d, by_tool.get(tool, [])))
        rows[tool] = row

    rows = {tool: rows[tool] for tool in ordered}
    write_scan_timings(
        out_dir,
        rows,
        target=target_label,
        target_type=target_type,
        wall_seconds=wall,
        root=str(Path(scan_root(target)).resolve()) if key == "repo" else None,
    )
    return rows
