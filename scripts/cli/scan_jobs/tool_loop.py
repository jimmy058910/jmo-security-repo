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
   `skipped` with that reason (no Dockerfiles, no Go sources, no IaC).
4. **run**: `ToolRunner`'s result becomes `ran` or `failed:<reason>`, and a
   tool whose own output says it examined 0 files is `failed` (G2, #1231).

Before any of that, a repository whose pruned walk yields no file at all fails
every tool that would have read it: nothing was there to scan (G2).
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
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
    VENDORED_DIRS,
    ExclusionStyle,
    ScanContext,
    ToolDescriptor,
    scan_root,
)
from ...core.tool_runner import ToolDefinition, ToolResult
from ..scan_utils import (
    find_tool,
    report_tool_failure,
    tool_exclusion_flags,
    tool_flags,
    tool_timeout,
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
) -> list[str]:
    """Collect matching files for a tool that takes file arguments.

    hadolint used to take `dockerfiles[0]`, which on docker-library/postgres
    meant 1 of 26 files scanned, with nothing in the output to say so.
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


def _exclusions(
    d: ToolDescriptor, out_dir: Path, results_name: str | None, target: Any
) -> list[str]:
    if d.exclusion_style is ExclusionStyle.PATTERN_FILE and d.exclusion_flag:
        path = write_trufflehog_exclude_file(
            out_dir, results_dir_name=results_name, root=scan_root(target)
        )
        return [d.exclusion_flag, str(path)]
    return tool_exclusion_flags(d.name, results_dir_name=results_name)


def _failed_row(
    tool: str,
    result: ToolResult,
    seconds: float,
    attempts: int,
    invocations: int,
    out_dir: Path,
    stub: Callable[[str, Path], None],
) -> ToolRun:
    """Map one failed invocation to a row, and say so on a durable stream.

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
    report_tool_failure(result, words)
    return ToolRun(
        tool,
        State.FAILED,
        reason,
        seconds=seconds,
        exit_code=None if result.returncode == -1 else result.returncode,
        attempts=attempts,
        invocations=invocations,
        detail=result.error_message or None,
    )


def _row_from_results(
    d: ToolDescriptor,
    results: list[ToolResult],
    invocations: int,
    out_dir: Path,
    stub: Callable[[str, Path], None],
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
    failed = [r for r in results if r.status != "success"]
    if failed:
        return _failed_row(
            tool, failed[0], seconds, attempts, invocations, out_dir, stub
        )

    for r in results:
        # Tools told where to write wrote their own file; the rest printed it.
        if r.output_file and r.capture_stdout:
            r.output_file.write_text(r.stdout or "", encoding="utf-8")
    exit_code = results[-1].returncode
    if d.scanned_count is not None:
        examined = d.scanned_count(results[0].output_file or out_dir / f"{tool}.json")
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
    return ToolRun(
        tool,
        State.RAN,
        seconds=seconds,
        exit_code=exit_code,
        attempts=attempts,
        invocations=invocations,
    )


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

    rows: TargetRows = {}
    planned: dict[str, tuple[ToolDescriptor, int]] = {}
    definitions: list[ToolDefinition] = []
    for tool in ordered:
        d = _descriptor(tool)
        builder = d.invocations.get(key)
        if builder is None:
            rows[tool] = ToolRun(tool, State.SKIPPED, d.off_target_reason)
            continue

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
            files = tuple(collect_files(repo_root, d.file_patterns, tool, results_tree))
        ctx = ScanContext(
            tool=tool,
            target_type=key,
            target=target,
            out_dir=out_dir,
            binary=binary,
            flags=tuple(tool_flags(per_tool_config, tool)),
            tool_config=tool_config if isinstance(tool_config, dict) else {},
            exclusion_args=(
                tuple(_exclusions(d, out_dir, results_name, target))
                if key == "repo"
                else ()
            ),
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

        invocations = builder(ctx)
        planned[tool] = (d, len(invocations))
        for inv in invocations:
            definitions.append(
                ToolDefinition(
                    name=tool,
                    command=list(inv.command),
                    output_file=inv.output_file,
                    timeout=tool_timeout(per_tool_config, tool, timeout),
                    retries=retries,
                    ok_return_codes=inv.ok_return_codes,
                    capture_stdout=inv.capture_stdout,
                    cwd=inv.cwd,
                )
            )

    runner = runner_cls(tools=definitions, progress_callback=progress_callback)
    started = time.perf_counter()
    results: list[ToolResult] = runner.run_all_parallel()
    wall = time.perf_counter() - started

    by_tool: dict[str, list[ToolResult]] = {}
    for result in results:
        by_tool.setdefault(result.tool, []).append(result)
    for tool, (d, count) in planned.items():
        rows[tool] = _row_from_results(d, by_tool.get(tool, []), count, out_dir, stub)

    rows = {tool: rows[tool] for tool in ordered}
    write_scan_timings(
        out_dir, rows, target=target_label, target_type=target_type, wall_seconds=wall
    )
    return rows
