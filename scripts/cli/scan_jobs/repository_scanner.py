"""
Repository Scanner

Scans a local repository with every matrix tool that applies to one:
trufflehog (verified secrets), semgrep (SAST), syft (SBOM), trivy
(vulnerabilities, secrets, misconfiguration), checkov (IaC and CI/CD
policy), hadolint (Dockerfiles), shellcheck (shell scripts), gosec (Go),
yara (malware rules) and grype (vulnerabilities).

Content decides what runs. hadolint and shellcheck collect their files first
and produce no invocation without them; gosec runs only on a tree with Go
sources or a go.mod. zap is a DAST tool: handed a directory, it records
'nothing for it to scan' rather than running. nuclei is URL-only and never
reaches this module (tool_registry.TOOL_SCAN_TYPES).

Integrates with ToolRunner for parallel execution and resilient error handling.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path

from ...core.config import RetryConfig
from ...core.paths import get_yara_rules_dir
from ...core.scan_timings import write_scan_timings
from ...core.tool_runner import ToolDefinition, ToolRunner
from ..path_sanitizers import _sanitize_path_component, _validate_output_path
from ..scan_utils import (
    NOT_ATTEMPTED_MISSING,
    NOT_ATTEMPTED_NOTHING_APPLICABLE,
    TOOL_TIMEOUT_DEFAULTS,
    VENDORED_DIRS,
    find_tool,
    in_tree_results_name,
    record_not_attempted,
    report_tool_failure,
    tool_exclusion_flags,
    tool_flags,
    tool_timeout,
    write_stub,
    write_trufflehog_exclude_file,
)

logger = logging.getLogger(__name__)

# TOOL_TIMEOUT_DEFAULTS now lives in scan_utils and is re-exported here for the
# handful of readers that reach for it by this name. It was defined in this
# module, which is exactly why only *repository* scans honoured the floor: the
# other four scanners could not see it and their `get_tool_timeout` copies had
# none. `zap` carries a 900 s floor and also runs on `url` targets, so a
# `balanced` URL scan gave it 600 s -- a third short -- while the same tool on a
# repository target got 900 s.
__all__ = ["TOOL_TIMEOUT_DEFAULTS", "scan_repository"]

# Upper bound on file arguments passed to a single per-file tool invocation.
# Windows caps a command line at 32767 characters; a few hundred absolute paths
# stays well inside that while covering every repository we have measured
# (docker-library/postgres, the densest, has 55 shell scripts and 26
# Dockerfiles). Exceeding it is reported, never silently truncated - a cap that
# does not announce itself reads as "everything was scanned" when it was not.
MAX_FILE_ARGS = 300

# Every directory name this module's own file enumeration skips: the vendored
# dependency trees - the same list the per-tool `--exclude` flags are built
# from, so the walk and the flags cannot drift.
_SKIPPED_DIR_NAMES: frozenset[str] = frozenset(VENDORED_DIRS)


def _same_tree(candidate: Path, target: Path) -> bool:
    """True when ``candidate`` is ``target``, resolving both.

    ``resolve()`` on each side rather than a string compare: the walk yields
    paths built from the caller's ``repo``, which may be relative, contain a
    ``..``, or reach the results directory through a symlink or a different
    drive-letter case. Any of those makes an equal directory compare unequal.

    Returns False on OSError instead of raising -- an unresolvable directory is
    not a reason to abort a scan, and Python 3.12 propagates PermissionError
    from path operations rather than returning False (#1163).
    """
    try:
        return candidate.resolve() == target
    except OSError:
        return False


def _collect_files(
    repo: Path,
    patterns: tuple[str, ...],
    tool_name: str,
    skip_tree: Path | None = None,
) -> list[str]:
    """Collect matching files for a tool that takes file arguments.

    Both shellcheck and hadolint accept many paths per invocation; scanning one
    file and calling it done under-reports without saying so. hadolint used to
    take `dockerfiles[0]`, which on docker-library/postgres meant 1 of 26 files
    (and 1 of 14 on kubernetes-goat) - about 90% of Dockerfiles unexamined,
    with nothing in the output to indicate it.
    """
    seen: set[Path] = set()
    for pattern in patterns:
        for path in repo.glob(pattern):
            # Repositories vendor dependencies; scanning node_modules or a
            # bundled venv buries the repo's own findings in third-party noise.
            #
            # The names come from scan_utils rather than a literal here: this
            # walk and the per-tool `--exclude` flags are two answers to the
            # same question, and #1080 was the two disagreeing (this list had
            # the dependency directories since #1132; the flags never did).
            if set(path.parts) & _SKIPPED_DIR_NAMES:
                continue
            if skip_tree is not None and any(
                _same_tree(parent, skip_tree) for parent in path.parents
            ):
                # JMo's own output: a Dockerfile or shell script copied into a
                # previous scan's results directory is not the user's code.
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


def _iter_repo_files(repo: Path, skip_tree: Path | None = None) -> Iterator[Path]:
    """Yield every file under ``repo``, never descending into a skipped tree.

    ``skip_tree`` is an absolute directory pruned by PATH rather than by name --
    JMo's own results directory when it sits inside the repository (#1156). The
    per-tool `--exclude` flags can only take a name, because that is the one
    spelling all six grammars share; here there is no pattern language, so the
    exact directory is skipped and a same-named directory elsewhere is not.

    ``os.walk`` rather than ``Path.glob`` because pruning is done by assigning
    into ``dirnames`` in place, so a vendored tree is never *entered*.
    ``repo.glob("**/*.go")`` walks ``node_modules`` in full and discards the
    result afterwards, which is the expensive half of the work -- and these
    predicates run on every scan, including the repositories that have nothing
    for the tool and get no value from the walk.

    A generator, so a caller that only needs "is there one?" stops at the first
    match instead of materialising a list.
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


def _repo_has_go_sources(repo: Path, skip_tree: Path | None = None) -> bool:
    """True when gosec has something to load: a ``.go`` file or a ``go.mod``.

    ``go.mod`` alone counts. A module whose sources are generated at build time
    still carries one, and the failure directions here are not symmetric: over-
    triggering costs one fast tool run that reports nothing, while under-
    triggering silently drops a scanner from a real Go repository -- the class
    of bug that let a Windows ``.exe`` omission make trufflehog scan nothing,
    exit 0, and pass the ``zero-secrets`` policy.

    Vendored trees are excluded by ``_iter_repo_files``, which matters more than
    it looks: pre-commit ships ``resources/empty_template_main.go`` inside its
    own package, so counting ``.venv`` would trigger gosec on every Python
    repository with a virtualenv in the tree. gosec's ``./...`` target excludes
    ``vendor/`` in module mode for the same reason.
    """
    for path in _iter_repo_files(repo, skip_tree):
        if path.suffix == ".go" or path.name == "go.mod":
            return True
    return False


def scan_repository(
    repo: Path,
    results_dir: Path,
    tools: list[str],
    timeout: int,
    retries: int | RetryConfig,
    per_tool_config: dict,
    allow_missing_tools: bool,
    tool_exists_func: Callable[[str], bool] | None = None,
    write_stub_func: Callable[[str, Path], None] | None = None,
    find_tool_func: Callable[[str], str | None] | None = None,
    progress_callback: Callable[[str, str, int], None] | None = None,
) -> tuple[str, dict[str, bool]]:
    """
    Scan a Git repository with multiple security tools.

    Args:
        repo: Path to Git repository to scan
        results_dir: Base results directory (individual-repos)
        tools: List of tools to run
        timeout: Default timeout in seconds
        retries: Number of retries for flaky tools
        per_tool_config: Per-tool configuration overrides
        allow_missing_tools: If True, write empty stubs for missing tools
        tool_exists_func: Optional function to check if tool exists (for testing)
        write_stub_func: Optional function to write stub files (for testing)
        find_tool_func: Optional function to find tool path (for testing)
        progress_callback: Optional callback(tool_name, status, findings_count)
                          Called when tools start and complete for progress tracking

    Returns:
        Tuple of (repo_name, statuses_dict)
        statuses_dict contains tool success/failure and __attempts__ metadata
    """
    statuses: dict[str, bool] = {}
    tool_defs = []

    # Use provided functions or defaults
    _write_stub = write_stub_func or write_stub
    _resolve_tool = find_tool_func or find_tool

    # Every tool block below is `if X in tools: path = _find_tool(X)` followed by
    # `if path: ... elif allow_missing_tools: ...`. When neither holds the tool is
    # dropped with no status, no warning and no error -- the scan simply runs
    # without it and still exits 0. That is how checkov vanished from a repo with
    # 47 Terraform files while `jmo tools check` reported it OK.
    #
    # Recording here rather than in every block: they share this one alias.
    unresolved: list[str] = []

    # Tools this scanner actually has a code path for. Only an implemented block
    # reaches `_find_tool`, so membership is recorded rather than inferred.
    # Inferring it from "produced no ToolDefinition" cannot distinguish "no
    # implementation" from "implemented, but this repo has no matching files" -
    # and reporting the wrong reason sends the reader hunting for code that
    # already exists.
    considered: set[str] = set()

    def _find_tool(tool_name: str) -> str | None:
        """Resolve a tool's binary, recording that this scanner considered it.

        Every block resolves the binary named after its own tool, so the name
        recorded in `considered` and `unresolved` is the tool the user asked
        for. (Variant tools that ran another tool's binary, and needed a
        separate owner name, left in v2.0.0.)
        """
        considered.add(tool_name)
        resolved = _resolve_tool(tool_name)
        if resolved is None:
            unresolved.append(tool_name)
        return resolved

    # `_find_any_tool` lived here, resolving the first of several
    # interchangeable binaries. zap was its only caller -- it probed
    # `zap-baseline.py` and then `docker` -- and #1159 removed that probe, so it
    # went with it. The defect it was written for (#1136: one scan reporting zap
    # as never started AND as failed) is now unreachable by construction rather
    # than by careful bookkeeping: nothing resolves a binary for zap on a
    # repository target at all.

    name = _sanitize_path_component(repo.name)
    out_dir = results_dir / name
    _validate_output_path(results_dir, out_dir)
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # `jmo scan . --out ./results` is the ordinary layout, and it puts JMo's
    # output inside the tree the next scan walks -- so every tool reads JMo's
    # own artifacts back. Measured on juice-shop: 90 of 831 findings (10.8%)
    # were horusec and trufflehog reporting a previous scan's `results/`, and
    # they scale with how many times the user has scanned (#1156).
    #
    # Resolved once, here, because it is the same answer for every block and
    # `results_dir` is only in scope in this function. `None` when the results
    # directory lives elsewhere, which is the usual CI shape and needs nothing.
    # `results_dir` is NOT the results root: every scanner is handed
    # `<root>/individual-<type>` (scan_orchestrator.py passes
    # `self.config.results_dir / "individual-repos"`). Excluding that would
    # leave `summaries/` beside it in the walk -- and `summaries/findings.json`,
    # `findings.yaml` and `dashboard.html` each embed every finding verbatim, so
    # they are the richest source of the re-reporting, not the raw tool output.
    # Measured: excluding only `individual-repos` left 5 of 8 findings inside
    # the results tree.
    #
    # Guarded rather than assumed. A scanner that is one day handed the root
    # itself keeps working instead of silently excluding the wrong directory.
    results_root = (
        results_dir.parent
        if results_dir.name.startswith("individual-")
        else results_dir
    )
    results_name = in_tree_results_name(repo, results_root)
    if results_name:
        logger.debug(
            "Results directory %s is inside %s; excluding '%s' from the scan",
            results_root,
            repo.name,
            results_name,
        )
    # The precise form, for this module's own file enumeration. The flags take
    # a NAME because that is the only spelling every tool's grammar shares;
    # here there is no pattern language, so the exact directory is skipped and
    # a same-named directory elsewhere in the tree is not.
    results_tree = results_root.resolve() if results_name else None

    def get_tool_timeout(tool: str, default: int) -> int:
        """Timeout for this tool, honouring the slow-tool floor.

        Priority: an explicit `per_tool.<tool>.timeout` wins outright, else the
        scan default raised to `TOOL_TIMEOUT_DEFAULTS` if the tool has a floor,
        so a low default cannot kill a slow tool early.

        Delegates to the shared implementation. This body was the only one of
        five that applied the floor at all.
        """
        return tool_timeout(per_tool_config, tool, default)

    def get_tool_flags(tool: str) -> list[str]:
        """Extra flags for this tool, minus any JMo must own.

        Delegates to the shared implementation: this was one of five identical
        copies, none of which filtered anything, so a `per_tool` flag could
        override JMo's own `-f`/`-o` and silently destroy the tool's findings
        (#822).
        """
        return tool_flags(per_tool_config, tool)

    # TruffleHog: Verified secrets scanning
    # Uses filesystem mode to scan working directory (not just git history)
    # This catches secrets that may not be committed yet or in non-git directories
    if "trufflehog" in tools:
        trufflehog_out = out_dir / "trufflehog.json"
        trufflehog_path = _find_tool("trufflehog")
        if trufflehog_path:
            trufflehog_flags = get_tool_flags("trufflehog")
            trufflehog_cmd = [
                trufflehog_path,
                "filesystem",
                str(repo),
                "--json",
                "--no-update",
                # Keep VCS internals and JMo's own state out of the walk. A
                # secret at `.git/objects/03/f8eab...` names no commit and no
                # source file, and `.jmo/history.db` holds the raw findings of
                # every previous scan, so scanning it re-reports them all
                # (#1134).
                "--exclude-paths",
                str(
                    write_trufflehog_exclude_file(
                        out_dir, results_dir_name=results_name
                    )
                ),
                *trufflehog_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="trufflehog",
                    command=trufflehog_cmd,
                    output_file=trufflehog_out,
                    timeout=get_tool_timeout("trufflehog", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("trufflehog", trufflehog_out)
            record_not_attempted(statuses, "trufflehog")

    # Semgrep: Static analysis
    if "semgrep" in tools:
        semgrep_out = out_dir / "semgrep.json"
        semgrep_path = _find_tool("semgrep")
        if semgrep_path:
            semgrep_flags = get_tool_flags("semgrep")

            # Get semgrep configs from per_tool_config (allows offline mode)
            # Default: ["auto"] - uses Semgrep Registry auto-detection
            # Custom: ["p/python", "p/javascript"] - specify language packs
            # Note: "p/security" ruleset was deprecated, use "auto" instead
            semgrep_tool_config = per_tool_config.get("semgrep", {})
            if isinstance(semgrep_tool_config, dict):
                semgrep_configs = semgrep_tool_config.get("configs", ["auto"])
            else:
                semgrep_configs = ["auto"]

            # Build config arguments
            config_args = []
            for cfg in semgrep_configs:
                config_args.extend(["--config", cfg])

            semgrep_cmd = [
                semgrep_path,
                *config_args,
                "--json",
                "--output",
                str(semgrep_out),
                # JMo's exclusions go before the user's flags so an explicit
                # per_tool entry still wins; the repeatable forms accumulate
                # either way (#1132).
                *tool_exclusion_flags("semgrep", results_dir_name=results_name),
                *semgrep_flags,
                str(repo),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="semgrep",
                    command=semgrep_cmd,
                    output_file=semgrep_out,
                    timeout=get_tool_timeout("semgrep", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1, 2),  # 0=clean, 1=findings, 2=errors
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("semgrep", semgrep_out)
            record_not_attempted(statuses, "semgrep")

    # Trivy: Vulnerability and secrets scanning
    if "trivy" in tools:
        trivy_out = out_dir / "trivy.json"
        trivy_path = _find_tool("trivy")
        if trivy_path:
            trivy_flags = get_tool_flags("trivy")
            trivy_cmd = [
                trivy_path,
                "fs",
                "-q",
                "-f",
                "json",
                "--scanners",
                "vuln,secret,misconfig",
                *tool_exclusion_flags("trivy", results_dir_name=results_name),
                *trivy_flags,
                str(repo),
                "-o",
                str(trivy_out),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="trivy",
                    command=trivy_cmd,
                    output_file=trivy_out,
                    timeout=get_tool_timeout("trivy", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("trivy", trivy_out)
            record_not_attempted(statuses, "trivy")

    # Syft: SBOM generation
    if "syft" in tools:
        syft_out = out_dir / "syft.json"
        syft_path = _find_tool("syft")
        if syft_path:
            syft_flags = get_tool_flags("syft")
            syft_cmd = [
                syft_path,
                f"dir:{repo}",
                "-o",
                "json",
                *syft_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="syft",
                    command=syft_cmd,
                    output_file=syft_out,
                    timeout=get_tool_timeout("syft", timeout),
                    retries=retries,
                    ok_return_codes=(0,),
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("syft", syft_out)
            record_not_attempted(statuses, "syft")

    # Checkov: IaC policy checks
    if "checkov" in tools:
        checkov_out = out_dir / "checkov.json"
        checkov_path = _find_tool("checkov")
        if checkov_path:
            checkov_flags = get_tool_flags("checkov")
            checkov_cmd = [
                checkov_path,
                "-d",
                str(repo),
                "-o",
                "json",
                # Before the user's flags, so an explicit per_tool entry still
                # wins - --skip-path is repeatable and accumulates (#1080).
                *tool_exclusion_flags("checkov", results_dir_name=results_name),
                *checkov_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="checkov",
                    command=checkov_cmd,
                    output_file=checkov_out,
                    timeout=get_tool_timeout("checkov", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("checkov", checkov_out)
            record_not_attempted(statuses, "checkov")

    # Hadolint: Dockerfile linting
    if "hadolint" in tools:
        hadolint_out = out_dir / "hadolint.json"
        hadolint_path = _find_tool("hadolint")
        if hadolint_path:
            hadolint_flags = get_tool_flags("hadolint")

            # hadolint's usage is `[DOCKERFILE...]` - it takes as many paths as
            # you give it. This previously passed `dockerfiles[0]` only, so
            # docker-library/postgres had 1 of its 26 Dockerfiles scanned and
            # kubernetes-goat 1 of 14 - ~90% unexamined, silently.
            dockerfiles = _collect_files(
                repo,
                ("**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile"),
                "hadolint",
                results_tree,
            )
            if dockerfiles:
                hadolint_cmd = [
                    hadolint_path,
                    "-f",
                    "json",
                    *hadolint_flags,
                    *dockerfiles,
                ]
                tool_defs.append(
                    ToolDefinition(
                        name="hadolint",
                        command=hadolint_cmd,
                        output_file=hadolint_out,
                        timeout=get_tool_timeout("hadolint", timeout),
                        retries=retries,
                        ok_return_codes=(0, 1),
                        capture_stdout=True,
                    )
                )
        elif allow_missing_tools:
            _write_stub("hadolint", hadolint_out)
            record_not_attempted(statuses, "hadolint")

    # ShellCheck: shell script static analysis
    #
    # shellcheck shipped in the smallest profile, installed cleanly and reported OK
    # from `jmo tools check`, but had no repository implementation at all - so it
    # could never run, and `shellcheck_adapter.py` sat waiting for input that was
    # never produced. Measured: docker-library/postgres has 55 shell scripts and
    # kubernetes-goat 7, none of them examined.
    #
    # Shell scripts are a genuine finding source in public repositories:
    # unquoted expansions (SC2086), unquoted command substitution (SC2046) and
    # `cd` without a failure guard (SC2164) are command-injection and
    # data-destruction risks, not merely style.
    if "shellcheck" in tools:
        shellcheck_out = out_dir / "shellcheck.json"
        shellcheck_path = _find_tool("shellcheck")
        if shellcheck_path:
            shellcheck_flags = get_tool_flags("shellcheck")
            shell_scripts = _collect_files(
                repo, ("**/*.sh", "**/*.bash", "**/*.ksh"), "shellcheck", results_tree
            )
            if shell_scripts:
                shellcheck_cmd = [
                    shellcheck_path,
                    "--format=json",
                    *shellcheck_flags,
                    *shell_scripts,
                ]
                tool_defs.append(
                    ToolDefinition(
                        name="shellcheck",
                        command=shellcheck_cmd,
                        output_file=shellcheck_out,
                        timeout=get_tool_timeout("shellcheck", timeout),
                        retries=retries,
                        # 0 = clean, 1 = findings. 2+ are fatal parse/usage
                        # errors and must NOT be graded acceptable.
                        ok_return_codes=(0, 1),
                        capture_stdout=True,
                    )
                )
        elif allow_missing_tools:
            _write_stub("shellcheck", shellcheck_out)
            record_not_attempted(statuses, "shellcheck")

    # ZAP: DAST, and a repository is not a running application.
    #
    # This block used to build a command. It could not work in any
    # configuration, and never had (#1159):
    #
    #   - `zap-baseline.py -t` takes a URL ("target URL including the
    #     protocol"). JMo passed it `web_files[0]` -- the first `.html`, `.js`
    #     or `.php` file in the tree, a filesystem path. Its exit codes are 0
    #     success, 1 FAIL, 2 WARN, **3 any other failure**, and the dogfood
    #     measured exactly that: `Return code 3 not in (0, 1, 2)`,
    #     `retry_exhausted`, no `zap.json` written.
    #   - `zap-baseline.py` is not in the package `jmo tools install zap` lays
    #     down. That package is the ZAP desktop distribution -- `zap.bat` /
    #     `zap.sh` and `zap-2.17.0.jar`. The baseline script ships in the ZAP
    #     *Docker image*. So without Docker the tool never started, and with it
    #     the tool started and exited 3.
    #
    # Scanning one arbitrary file out of a repository was never DAST anyway:
    # ZAP finds vulnerabilities by exercising a live application over HTTP.
    # Serving the tree and pointing `-t` at a local URL would make it real, and
    # turns a file scan into a network service with a lifecycle to manage --
    # deliberately not built here.
    #
    # zap is untouched on **url** targets, where it works: see
    # `url_scanner.py`, which resolves `zap.sh` and matches
    # `TOOL_EXECUTION_COMMANDS["zap"]`. That entry is `["zap.sh", "java"]`, and
    # `jmo tools check` has always verified it -- which is why `tools check`
    # could read `zap OK 2.17.0` on a box where the repository scan could not
    # run it. The two now agree.
    #
    # `NOTHING_APPLICABLE` rather than a new reason: it is the honest one for a
    # DAST tool handed a directory, and it is one of exactly two reasons
    # `not_attempted_tools` is ever queried with, so a third would be recorded
    # and never printed -- a silent skip.
    if "zap" in tools:
        zap_out = out_dir / "zap.json"
        considered.add("zap")
        _write_stub("zap", zap_out)
        record_not_attempted(statuses, "zap", NOT_ATTEMPTED_NOTHING_APPLICABLE)

    # Gosec: Go security analyzer
    # Content-triggered: gosec loads Go packages, so a tree with no Go gives it
    # nothing to do. It exits in ~100 ms with an accepted return code and no
    # output file, which `tool_runner` grades as `no_output` and reports as
    # "its findings are MISSING from this scan" -- on every Node, Python, Java,
    # Ruby or PHP repository, i.e. most of them (#1081).
    if "gosec" in tools:
        gosec_out = out_dir / "gosec.json"
        gosec_path = _find_tool("gosec")
        has_go = _repo_has_go_sources(repo, results_tree) if gosec_path else False
        if gosec_path and has_go:
            gosec_flags = get_tool_flags("gosec")
            gosec_cmd = [
                gosec_path,
                "-fmt=json",
                f"-out={gosec_out}",
                *gosec_flags,
                str(repo / "..."),
            ]
            tool_defs.append(
                ToolDefinition(
                    name="gosec",
                    command=gosec_cmd,
                    output_file=gosec_out,
                    timeout=get_tool_timeout("gosec", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools or not has_go:
            _write_stub("gosec", gosec_out)
            record_not_attempted(
                statuses,
                "gosec",
                (
                    NOT_ATTEMPTED_MISSING
                    if not gosec_path
                    else NOT_ATTEMPTED_NOTHING_APPLICABLE
                ),
            )

    # YARA: Malware detection
    if "yara" in tools:
        yara_out = out_dir / "yara.json"
        yara_path = _find_tool("yara")
        if yara_path:
            yara_flags = get_tool_flags("yara")
            # yara is libyara bindings, not a CLI, so `yara_path` is this
            # interpreter and scripts/core/yara_runner.py supplies the command
            # line. See that module for why the native CLI is not an option:
            # VirusTotal/yara publishes prebuilt binaries for Windows only, and
            # stopped even those at v4.5.6.
            #
            # What was here before could never have run. It built the native C
            # command line (`yara -r -w -s <rules> <repo>`) against a library
            # that has no executable; it pointed at /usr/share/yara/rules, which
            # is absent on Windows and on stock Ubuntu alike; and the adapter it
            # fed parses JSON, which yara's CLI has never emitted - the string
            # "json" does not appear anywhere in cli/yara.c.
            rules_path = per_tool_config.get("yara", {}).get(
                "rules_path", str(get_yara_rules_dir())
            )
            yara_cmd = [
                yara_path,
                "-m",
                "scripts.core.yara_runner",
                "--rules",
                str(rules_path),
                "--target",
                str(repo),
                "--output",
                str(yara_out),
                *yara_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="yara",
                    command=yara_cmd,
                    output_file=yara_out,
                    timeout=get_tool_timeout("yara", timeout),
                    retries=retries,
                    # 0 = clean, 1 = matches. The runner reserves 2 for "did NOT
                    # scan", which must stay a failure rather than an empty result.
                    ok_return_codes=(0, 1),
                    # The runner writes --output itself. Capturing stdout would
                    # overwrite that file with the runner's (empty) stdout.
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("yara", yara_out)
            record_not_attempted(statuses, "yara")

    # Grype: Vulnerability scanner for containers and filesystems
    if "grype" in tools:
        grype_out = out_dir / "grype.json"
        grype_path = _find_tool("grype")
        if grype_path:
            grype_flags = get_tool_flags("grype")
            grype_cmd = [
                grype_path,
                f"dir:{repo}",
                "-o",
                "json",
                *grype_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="grype",
                    command=grype_cmd,
                    output_file=grype_out,
                    timeout=get_tool_timeout("grype", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=True,
                )
            )
        elif allow_missing_tools:
            _write_stub("grype", grype_out)
            record_not_attempted(statuses, "grype")

    # A requested tool that never ran must say so. Silence here is the same
    # failure class as #700 (an accepted return code with no output written):
    # the scan looks complete, exits 0, and the missing tool's findings are
    # simply absent with nothing in the output to indicate it.
    #
    # Only tools that were *dropped*. Under --allow-missing-tools the `elif`
    # branch already wrote a stub and recorded the tool satisfied; that is a
    # deliberate, user-requested empty result, not a silent omission, so it must
    # not be overwritten here. Presence in `statuses` is what distinguishes the
    # two - a dropped tool has no entry at all, which is the whole problem.
    for missing in sorted(set(unresolved)):
        if missing in statuses:
            continue
        statuses[missing] = False
        logger.error(
            "%s: requested but its executable could not be found - it did "
            "NOT run and its findings are MISSING from this scan. "
            "Run `jmo tools check` to confirm installation, or pass "
            "--allow-missing-tools to record an explicit empty result.",
            missing,
        )

    # Requested but never even attempted: this scanner has no code path for
    # them. With the default matrix this is empty - nuclei is URL-only and is
    # filtered out before it reaches a repository, and opa is the report-phase
    # policy engine rather than a scanner - so it fires only for an explicit
    # `--tools` naming something this module cannot run. Kept distinct from
    # `unresolved` so a genuinely missing binary is not lost among tools that
    # were never going to run.
    not_implemented = set(tools) - considered
    if not_implemented:
        logger.warning(
            "Requested but not applicable to repository targets (no repository "
            "implementation): %s",
            ", ".join(sorted(not_implemented)),
        )

    # Implemented and installed, but this repository had nothing for them to
    # look at - shellcheck on a repo with no shell scripts, hadolint with no
    # Dockerfiles. Benign, and reported at debug so it is available when a user
    # asks "why is there no shellcheck output?" without adding noise to a normal
    # run. Distinct from the two cases above: nothing is wrong here.
    idle = considered - set(unresolved) - {td.name for td in tool_defs} - set(statuses)
    if idle:
        logger.debug(
            "No matching files in %s for: %s",
            repo.name,
            ", ".join(sorted(idle)),
        )

    # Execute all tools with ToolRunner
    # Note: Tool progress is reported via progress_callback, not direct stderr prints
    # This prevents overlapping output when Rich progress display is active
    runner = ToolRunner(
        tools=tool_defs,
        progress_callback=progress_callback,  # type: ignore[arg-type]
    )
    tools_started = time.perf_counter()
    results = runner.run_all_parallel()

    # ToolRunner already timed and classified every invocation. Record that
    # before the loop below reduces the results to booleans, which is where it
    # used to be lost (#722).
    write_scan_timings(
        out_dir,
        results,
        target=name,
        target_type="repo",
        wall_seconds=time.perf_counter() - tools_started,
    )

    # Process results
    attempts_map: dict[str, int] = {}

    for result in results:
        if result.status == "success":
            # Write stdout to file ONLY if we captured it (capture_stdout=True)
            # Tools with capture_stdout=False write their own files (semgrep, trivy)
            if result.output_file and result.capture_stdout:
                result.output_file.write_text(result.stdout or "", encoding="utf-8")
            statuses[result.tool] = True
            if result.attempts > 1:
                attempts_map[result.tool] = result.attempts
        elif result.status == "error" and "Tool not found" in result.error_message:
            # Reaching here means the tool RESOLVED in pre-flight - it was given
            # a ToolDefinition and handed to ToolRunner - and then could not be
            # executed. That is always a defect: a resolver returning something
            # that is not a path, or a binary that vanished mid-scan. A tool the
            # user genuinely has not installed never gets this far; it is
            # dropped or stubbed in pre-flight.
            #
            # So --allow-missing-tools must NOT absorb it. That flag means
            # "record an explicit empty result for tools I know I lack", which
            # is not consent to swallow a resolver bug. It used to write a stub
            # and set True here: find_tool("yara") returned the pseudo-path
            # "python:yara", which is truthy and so passed pre-flight, then
            # raised FileNotFoundError at exec. Measured on a machine with HOME
            # and PATH stripped - where yara could not possibly have run - the
            # scan wrote yara.json and reported a clean malware scan.
            #
            # No stub, either: an empty stub is indistinguishable from a genuine
            # empty result once the report phase reads it, which is the precise
            # lie being removed.
            statuses[result.tool] = False
            report_tool_failure(result, "its executable was not found at run time")
        elif result.timed_out:
            # Tool timed out - write stub so report phase has consistent files
            # and mark as failed (timeout is a failure state)
            #
            # `result.timed_out`, not `"Timeout" in result.error_message` (#727).
            # That match made a human-readable message load-bearing: rewording
            # "Timeout after 600s" would have silently routed every timeout to
            # the generic branch below, dropping the stub and the "it timed out"
            # log line, with nothing going red.
            #
            # The stub must not be the only signal: once the report phase reads
            # it, an empty stub is indistinguishable from a tool that genuinely
            # found nothing. The timeout has to be stated here or it is lost.
            tool_out = out_dir / f"{result.tool}.json"
            if not tool_out.exists():
                _write_stub(result.tool, tool_out)
            statuses[result.tool] = False
            if result.attempts > 0:
                attempts_map[result.tool] = result.attempts
            report_tool_failure(result, "it timed out")
        else:
            # Other errors (non-zero exit, etc.)
            statuses[result.tool] = False
            if result.attempts > 0:
                attempts_map[result.tool] = result.attempts
            # `no_output` - an accepted return code with nothing written - is
            # also announced by the progress tracker, but that is a UI surface:
            # bare text rather than the log stream, and overwritten in place on
            # a TTY. It is not a durable record, so this must still log. The
            # #700 class of bug is precisely a tool that returns 0 and produces
            # nothing; that must survive into the log.
            report_tool_failure(
                result,
                (
                    "it exited with an accepted code but wrote no output"
                    if result.status == "no_output"
                    else "it failed"
                ),
            )

    # Include attempts metadata if any retries occurred
    if attempts_map:
        statuses["__attempts__"] = attempts_map  # type: ignore[assignment]  # Store retry metadata alongside bool statuses

    return name, statuses
