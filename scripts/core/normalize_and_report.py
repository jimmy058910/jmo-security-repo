#!/usr/bin/env python3
"""
Normalize and report: load tool outputs from a results directory, convert to CommonFinding,
dedupe by fingerprint, and emit JSON + Markdown summaries.

Expected structure (flexible, supports 6 target types):
results_dir/
  individual-repos/
    <repo>/trufflehog.json
    <repo>/opengrep.json
    <repo>/trivy.json
    <repo>/... (28 active tools total)

Usage:
  python3 scripts/core/normalize_and_report.py <results_dir> [--out <out_dir>]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.core.adapters.common import (
    normalize_finding_path,
    scan_root_pattern,
    strip_scan_roots,
)
from scripts.core.common_finding import fingerprint, package_of, target_id
from scripts.core.compliance_mapper import enrich_findings_with_compliance
from scripts.core.cwe_extraction import backfill_risk_cwe
from scripts.core.exceptions import AdapterParseException

# Plugin system (v0.9.0)
from scripts.core.plugin_loader import get_plugin_loader, get_plugin_registry

# Priority calculation (v0.9.0 Feature #5: EPSS/KEV)
from scripts.core.priority_calculator import PriorityCalculator
from scripts.core.reporters.basic_reporter import write_json, write_markdown
from scripts.core.scan_timings import (
    SCAN_TIMINGS_FILENAME,
    State,
    ToolRun,
    read_scan_root,
)
from scripts.core.tool_diagnostics import (
    ToolDiagnostic,
    extract_tool_diagnostics,
)

# Configure logging
logger = logging.getLogger(__name__)

# When profiling is enabled (env JMO_PROFILE=1), this will be populated with per-job timings
PROFILE_TIMINGS: dict[str, Any] = {
    "jobs": [],  # list of {"tool": str, "path": str, "seconds": float, "count": int}
    "meta": {},  # miscellaneous metadata like max_workers
}

#: Keys whose values are a tool's own output, kept as it wrote them: a finding's
#: `raw` may name the scanning machine's directories (J5, #1007). The dashboard
#: redacts it on its way out; `findings.json` and `findings.yaml` keep it.
_VERBATIM_KEYS = frozenset({"raw"})


def deduplicate_findings_memory_efficient(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deduplicate findings by fingerprint with minimal memory overhead.

    This function uses a set-based approach instead of storing findings twice
    (once in dict, once in list). Memory savings: ~50% for large scans.

    Algorithm:
        1. Uses set to track seen fingerprints (tiny strings, ~32 bytes each)
        2. Builds result list incrementally (no dict → list copy)
        3. Preserves insertion order (first occurrence wins)

    Performance:
        - Time: O(n) where n = number of findings
        - Space: O(k) for fingerprints where k = unique findings
        - Memory savings vs dict approach: ~50% for large finding sets

    Args:
        findings: List of finding dictionaries, each with an 'id' field (fingerprint)

    Returns:
        List of deduplicated findings (first occurrence of each fingerprint)

    Example:
        >>> findings = [
        ...     {"id": "fp1", "message": "Issue A"},
        ...     {"id": "fp2", "message": "Issue B"},
        ...     {"id": "fp1", "message": "Issue A (dup)"},  # Duplicate
        ... ]
        >>> deduplicate_findings_memory_efficient(findings)
        [{"id": "fp1", "message": "Issue A"}, {"id": "fp2", "message": "Issue B"}]
    """
    seen_fingerprints: set[str] = set()
    result: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []

    for finding in findings:
        fingerprint = finding.get("id")
        if not fingerprint:
            # NOT deduplicated - discarded. Before #848 this fell out of the
            # `if fingerprint and ...` test with no log record at any level and
            # no count in the report to compare against, so a finding a tool
            # produced and JMo deleted looked exactly like a finding that never
            # existed. The drop itself is kept: a finding with no id cannot be
            # deduplicated, suppressed, diffed or referenced, and
            # `calculate_priorities_bulk` reads `finding["id"]` unguarded. What
            # changes is that it is now counted and named.
            dropped.append(finding)
            continue
        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            result.append(finding)

    _report_dropped_findings(dropped)
    return result


def _report_dropped_findings(dropped: list[dict[str, Any]]) -> None:
    """Name the tools whose findings were discarded for having no id (#848).

    WARNING because `configure_scan_logging` sets the `scripts` logger to
    WARNING for a normal run - the level below it is invisible in exactly the
    situation this exists to report. Silent on a healthy scan, which every
    corpus measured so far is: #843 found 0 of 264 real findings with an empty
    id, so this must not become the always-fires shape #784 removed.

    The schema does say `minLength: 1` on `id`, but nothing between the
    adapters and this function validates against it - `schema_validator` is
    reached only by `jmo validate` and the YAML reporter. The contract is
    documented, not enforced, so this path is reachable by any adapter that
    ships a falsy id.
    """
    if not dropped:
        return
    by_tool: dict[str, int] = {}
    for finding in dropped:
        tool = (finding.get("tool") or {}).get("name") or "unknown"
        by_tool[tool] = by_tool.get(tool, 0) + 1
    logger.warning(
        "Discarded %d finding(s) with no id - they are MISSING from this "
        "report and were not deduplicated, they were deleted (by tool: %s)",
        len(dropped),
        ", ".join(f"{tool}={n}" for tool, n in sorted(by_tool.items())),
    )


def deduplicate_findings_streaming(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Stream-deduplicate findings for very large datasets.

    This is a generator-based variant that yields deduplicated findings
    one at a time. Useful when processing 10k+ findings to minimize
    peak memory usage.

    Note: Returns a list for API compatibility, but internally uses
    generator for memory efficiency during processing.

    Args:
        findings: List of finding dictionaries

    Returns:
        List of deduplicated findings

    See Also:
        deduplicate_findings_memory_efficient: Faster for moderate-sized datasets
    """
    seen: set[str] = set()
    dropped: list[dict[str, Any]] = []

    def _gen():
        for finding in findings:
            fp = finding.get("id")
            if not fp:
                # Identical shape to `deduplicate_findings_memory_efficient`,
                # and identically silent before #848. Two copies of a data-loss
                # path is how one gets fixed and the other does not.
                dropped.append(finding)
                continue
            if fp not in seen:
                seen.add(fp)
                yield finding

    out = list(_gen())
    _report_dropped_findings(dropped)
    return out


def scan_roots(results_dir: Path) -> tuple[str, ...]:
    """Absolute directories this scan visited, for #861 path normalization.

    Read from ``repo_paths`` in ``.scan_metadata.json``, the same key
    ``history_db._scanned_repo_paths`` uses, and from the ``root`` each
    tree's ``scan-timings.json`` records. ``repo_paths`` holds ``--repo``
    targets only, so a GitLab clone, scanned in a random temporary directory,
    reached no root and its findings kept that path (#1332).

    Empty when neither is readable -- a results directory produced by
    something other than `jmo scan` still normalizes separators and leading
    separators, it just cannot strip a host prefix it was never told about.
    """
    roots: list[str] = []
    try:
        meta = json.loads(
            (results_dir / ".scan_metadata.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        meta = None
    raw = meta.get("repo_paths") if isinstance(meta, dict) else None
    if isinstance(raw, list):
        roots.extend(entry for entry in raw if isinstance(entry, str) and entry)
    for timings in sorted(results_dir.glob(f"individual-*/*/{SCAN_TIMINGS_FILENAME}")):
        root = read_scan_root(timings)
        if root:
            roots.append(root)
    return tuple(dict.fromkeys(roots))


def _normalize_paths_and_ids(
    findings: list[dict[str, Any]], roots: tuple[str, ...]
) -> tuple[int, int]:
    """Normalize ``location.path`` in place, drop the scan root from every other
    string, and re-key the ids derived from either (#861, #1007).

    Returns ``(paths_changed, ids_rekeyed)``.

    The root is dropped from **every string in a finding except** ``raw``, which
    is the tool's own output and stays as the tool wrote it (J5; the dashboard
    redacts it on its way out). A field list would be the next field's leak:
    osv-scanner's ``remediation`` told the reader where to put an ignore rule,
    ``C:\\Users\\...\\osv-scanner.toml``, and that reached ``findings.sarif``
    1,896 times, as ``properties.remediation`` and as every rule's ``help``.

    **The id is only recomputed when the existing one can be shown to have come
    from the old path.** That check is not defensive padding -- it is load
    bearing. Two adapters deliberately fingerprint on something that is *not*
    ``location.path``:

    ==============  =====================================================
    ``zap``         ``f"{uri}:{method}:{param}:{idx}"`` -- one alert on one
                    URI yields several findings that differ only by param
    ``nuclei``      the matched URL
    ==============  =====================================================

    Re-keying those from ``location.path`` would give every instance the same
    id, and `deduplicate_findings_memory_efficient` would then delete all but
    the first -- turning a path cleanup into silent finding loss, which is the
    exact failure class this campaign keeps finding. Deriving the answer from
    the data rather than from a hard-coded allowlist also means a new adapter
    with a custom key is safe on the day it lands, with nothing to remember.

    The same holds for the other inputs of that formula, ``message`` and
    ``ruleId``: an id is recognised from what the adapter hashed, and re-keyed
    from what the finding says now, so it does not depend on which directory
    was scanned. (No golden adapter's message names the root today; a tool's
    would have made the id differ between two checkouts of one repository.)
    """
    paths_changed = 0
    ids_rekeyed = 0
    pattern = scan_root_pattern(roots)

    for finding in findings:
        location = finding.get("location")
        original = location.get("path") if isinstance(location, dict) else None
        rule_id = finding.get("ruleId", "") or ""
        message = finding.get("message", "") or ""

        normalized = original
        if isinstance(location, dict) and isinstance(original, str) and original:
            # The root comes out of the path first. `normalize_finding_path`
            # strips a leading `/`, and the pattern needs it to find a POSIX
            # root, so a path equal to the root would come out as `home/u/app`;
            # it also leaves alone a path equal to a Windows root, and a URL
            # naming the root.
            candidate = strip_scan_roots(original, pattern) if pattern else original
            normalized = normalize_finding_path(candidate, roots)
            location["path"] = normalized
        if pattern:
            # The same objects, so `target_of`, which keys on `id(finding)`,
            # still finds this finding.
            finding.update(strip_scan_roots(finding, pattern, verbatim=_VERBATIM_KEYS))
            location = finding.get("location")
        if normalized != original:
            paths_changed += 1

        if not isinstance(location, dict) or not isinstance(original, str):
            continue
        if not original:
            continue
        new_rule_id = finding.get("ruleId", "") or ""
        new_message = finding.get("message", "") or ""
        if (normalized, new_rule_id, new_message) == (original, rule_id, message):
            continue

        current = finding.get("id")
        if not isinstance(current, str) or not current:
            continue
        tool = (finding.get("tool") or {}).get("name", "")
        start_line = location.get("startLine")

        # Two shapes of the one formula: five components, or six when the
        # adapter keyed on its column (shellcheck, the SARIF bindings; #1242).
        # Try five first and recompute under whichever shape matched, so a
        # finding that carries a column but was keyed without one keeps its
        # shape rather than being silently promoted.
        column = location.get("startColumn")
        columns = (None, column) if column is not None else (None,)
        # A secret scanner's record from git history is keyed on its commit
        # too (G1), and is re-keyed with it.
        context = finding.get("secretContext")
        commit = context.get("commit") if isinstance(context, dict) else None
        commits = (None, commit) if commit else (None,)
        # And a dependency scanner's on its package (#1346): osv-scanner's
        # path arrives absolute, and without this shape its ids kept the
        # scanning machine's directory.
        package = package_of(finding.get("dependency"))
        packages = (None, package) if package else (None,)
        shapes = [(col, c, p) for p in packages for c in commits for col in columns]
        for col, c, p in shapes:
            if current == fingerprint(
                tool,
                rule_id,
                original,
                start_line,
                message,
                start_column=col,
                commit=c,
                package=p,
            ):
                finding["id"] = fingerprint(
                    tool,
                    new_rule_id,
                    normalized,
                    start_line,
                    new_message,
                    start_column=col,
                    commit=c,
                    package=p,
                )
                ids_rekeyed += 1
                break

    return paths_changed, ids_rekeyed


def _scope_ids_to_targets(findings: list[dict[str, Any]]) -> None:
    """Replace each finding's id with `target_id` of it and its target (#1309).

    Every finding, whatever its adapter hashed: the id is derived from the
    adapter's own, so zap's and nuclei's URL-keyed ids are scoped the same as
    a path-keyed one. A finding with no id keeps none, and deduplication says
    so (#848).
    """
    for finding in findings:
        current = finding.get("id")
        target = finding.get("target")
        if isinstance(current, str) and current and isinstance(target, dict):
            finding["id"] = target_id(current, target["type"], target["name"])


def collect_tool_diagnostics(results_dir: Path) -> list[ToolDiagnostic]:
    """Files the tools said they could not analyse (#837).

    Walks the same tree as :func:`gather_results` but answers a different
    question, so it is a separate pass rather than a second return value: the
    adapters' contract stays `list[Finding]`, and only the five tools with a
    known error channel pay an extra parse.

    A file a tool could not read is not "clean" - it was never looked at - and
    before this nothing in the report distinguished the two. Measured: bandit
    named 2 unparseable files, and they appeared 0 times across findings.json,
    SUMMARY.md, dashboard.html, findings.sarif and findings.csv, with 0 log
    records at any level.
    """
    roots = scan_roots(results_dir)
    loader = get_plugin_loader()
    out: list[ToolDiagnostic] = []

    for target_dir in _target_dirs(results_dir):
        if not target_dir.exists():
            continue
        for target in sorted(p for p in target_dir.iterdir() if p.is_dir()):
            # Debug: `gather_results` says what it leaves out, once.
            for tool_output in _outputs_of_this_scan(target, logger.debug):
                adapter_name = loader._tool_to_adapter_name(tool_of_output(tool_output))
                out.extend(extract_tool_diagnostics(adapter_name, tool_output, roots))
    return out


def tool_of_output(path: Path) -> str:
    """The tool a scan output belongs to: its name before the first dot.

    A tool with more than one invocation writes more than one file, and each
    is read by the tool's adapter: `trufflehog.json` from the working tree,
    `trufflehog.git.json` from git history (v2.0.0 Phase 3, G1).
    """
    return path.name.split(".", 1)[0]


def count_findings(path: Path) -> int:
    """How many findings the report reads from one tool output: through the
    adapter `gather_results` gives it, so the scan phase and the report agree
    on what a failed row still contributed (#1369). 0 when no adapter reads
    it, or it does not parse, or the lookup itself fails (Python 3.12 raises
    from the adapter discovery's `Path.exists()` on an unreadable directory):
    it runs inside a target's scan, which it must not end. The report phase
    says why."""
    try:
        name = get_plugin_loader()._tool_to_adapter_name(tool_of_output(path))
        plugin_class = get_plugin_registry().get(name)
        if plugin_class is None:
            return 0
        return len(plugin_class().parse(path))
    except Exception as e:  # Acceptable: as in `_safe_load_plugin`
        logger.debug("count_findings: %s could not be counted: %s", path, e)
        return 0


def _commit_date(finding: dict[str, Any]) -> tuple[datetime, str]:
    """A history record's sort key: its commit's time, then the commit.

    Compared as times, not strings: `2026-01-03T01:00:00+05:00` (20:00 UTC on
    the 2nd) is earlier than `2026-01-02T22:00:00+00:00`. A date with no
    offset is read as UTC, and one that does not parse sorts last.
    """
    context = finding.get("secretContext") or {}
    try:
        when = datetime.fromisoformat(str(context.get("date")))
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
    except ValueError:
        when = datetime.max.replace(tzinfo=UTC)
    return when, str(context.get("commit") or "")


def pair_history_with_tree(
    findings: list[dict[str, Any]], target_of: Mapping[int, str] | None = None
) -> list[dict[str, Any]]:
    """Fold each secret's git-history records into its working-tree finding.

    A secret still in the tree is in history too, and trufflehog and gitleaks
    each report it once per mode. Records are paired **by the secret**, within
    one target, tool, rule and path (decided 2026-09-26). Pairing by location
    cannot work: once a line is inserted above a committed key, the tree says
    line 2 and history line 1 (measured).

    `target_of` maps each finding (by `id()`) to the results folder it was
    read from. Without the target in the key, two repositories in one scan
    paired with each other: one's tree finding took the other's commit, and
    the other's record was dropped (#1323).

    - A tree finding keeps its id and location, and takes the `secretContext`
      of the earliest commit that added its secret. Its history records go.
    - History records with no tree finding are a secret that is gone from the
      tree. One stays per (tool, rule, path, secret): the earliest.
    - A key rotated in place is two secrets, so it stays two findings.

    Every finding leaves without its `secretDigest`: this is the one place it
    is read, and nothing writes it.
    """
    groups: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    for finding in findings:
        digest = finding.pop("secretDigest", None)
        if not digest:
            continue
        tool = finding.get("tool") or {}
        key = (
            (target_of or {}).get(id(finding), ""),
            str(tool.get("name") if isinstance(tool, dict) else tool),
            str(finding.get("ruleId") or ""),
            str((finding.get("location") or {}).get("path") or ""),
            str(digest),
        )
        groups.setdefault(key, []).append(finding)

    dropped: set[int] = set()
    for members in groups.values():
        history = sorted(
            (f for f in members if (f.get("secretContext") or {}).get("commit")),
            key=_commit_date,
        )
        if not history:
            continue
        tree = [f for f in members if not (f.get("secretContext") or {}).get("commit")]
        for finding in tree:
            finding["secretContext"] = dict(history[0]["secretContext"])
        # By identity: two history records can be equal dicts.
        kept = set() if tree else {id(history[0])}
        dropped.update(id(f) for f in history if id(f) not in kept)
    return [f for f in findings if id(f) not in dropped]


# The six kinds of target a scan can have, as `scan_orchestrator` names them,
# and the results folder each one's output lands in.
TARGET_FOLDERS: dict[str, str] = {
    "repo": "individual-repos",
    "image": "individual-images",
    "iac": "individual-iac",
    "url": "individual-web",
    "gitlab": "individual-gitlab",
    "k8s": "individual-k8s",
}
_TARGET_TYPES = {folder: kind for kind, folder in TARGET_FOLDERS.items()}


def _target_dirs(results_dir: Path) -> list[Path]:
    """The six target-type directories a scan can write.

    Defined once because `gather_results` and `collect_tool_diagnostics` must
    walk the same set - a seventh target type added to one and not the other
    would go unreported in exactly the silent way #837 is about.
    """
    return [results_dir / folder for folder in TARGET_FOLDERS.values()]


def _scan_rows(target: Path, warn: Callable[..., None]) -> dict[str, ToolRun] | None:
    """The rows `jmo scan` recorded for one target, by tool.

    None when there are none to go by: the folder has no `scan-timings.json`
    (output `jmo scan` did not write), or it has one that cannot be read, which
    is said, since reading everything on its account is a guess. A row that
    does not parse is left out and said: its tool then has no row. A document
    JMo v1.x wrote (`schema_version` below 3, rows without a `state`) is also
    None, and said once, when it lists any tool.
    """
    timings = target / SCAN_TIMINGS_FILENAME
    try:
        document = json.loads(timings.read_bytes())
    except FileNotFoundError:
        return None
    # `UnicodeDecodeError` is a `ValueError`, not a `JSONDecodeError`.
    except (OSError, ValueError) as e:
        warn(
            "%s/%s cannot be read, so every tool output is reported: %s",
            target.name,
            timings.name,
            e,
        )
        return None
    entries = document.get("tools") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        warn(
            "%s/%s has no list of tool rows, so every tool output is reported",
            target.name,
            timings.name,
        )
        return None
    # v1.1.x wrote `schema_version` 2 (dev builds before v1.1.0 wrote 1; v1.0.x
    # wrote no such file), with rows that name a `status` and no `state`. None
    # of them parses, which would withhold every output as "a tool this scan
    # did not run". Its scan had no accounting of this kind, so it is read
    # whole, as for a folder with no document. No release left the version
    # out; a document without one is read the same way. With no row at all
    # (`failed-before-tools`) there is nothing to read by: that stays withheld.
    # A bool is an int to Python (`True < 3`), and no JMo wrote one.
    version = document.get("schema_version")
    is_v1 = isinstance(version, int) and not isinstance(version, bool) and version < 3
    if entries and (version is None or is_v1):
        warn(
            "%s/%s was written by JMo v1.x (%s); its rows name no state, so "
            "every tool output is reported",
            target.name,
            timings.name,
            "no schema_version" if version is None else f"schema_version {version}",
        )
        return None
    rows: dict[str, ToolRun] = {}
    for entry in entries:
        try:
            row = ToolRun.from_dict(entry)
        except (AttributeError, KeyError, TypeError, ValueError) as e:
            warn(
                "%s/%s: a tool row cannot be read and is ignored: %s",
                target.name,
                timings.name,
                e,
            )
            continue
        rows[row.tool] = row
    return rows


def _outputs_of_this_scan(target: Path, warn: Callable[..., None]) -> list[Path]:
    """The tool outputs in one target's folder that this scan produced (#1371,
    #1432). Shared by `gather_results` and `collect_tool_diagnostics`, which
    must read the same files.

    A folder holds an earlier scan's outputs too (a results directory reused),
    and a failed tool may leave output behind. The scan's own account of what
    it ran is `scan-timings.json`, so a tool's output is read when its row is
    `ran`, or when a run of it worked (`kept_findings` is a count, 0 included,
    #1369), and not when the tool has no row or its row is anything else. A
    folder without rows is read whole, and so is one JMo v1.x wrote.

    `warn` is told of an output left out that the reader would take for this
    scan's: a tool the scan did not run, and a row that failed. A `skipped`
    row's file is a stub the scan itself wrote, which would warn on every
    report (#784).
    """
    rows = _scan_rows(target, warn)
    outputs: list[Path] = []
    for path in target.glob("*.json"):
        # JMo's own scan-phase instrumentation, written by write_scan_timings
        # into the same directory as the tool outputs. It is not a tool result,
        # so no adapter exists for it and the registry lookup in the reader
        # warned about it on *every* report run (#784). A warning that always
        # fires teaches the reader to skip the whole class -- and "no adapter
        # plugin found" is precisely the message that matters when a real
        # adapter goes missing.
        #
        # Compared against the constant rather than the literal string so
        # renaming the artifact cannot quietly resurrect the warning.
        if path.name == SCAN_TIMINGS_FILENAME:
            continue
        if rows is not None:
            tool = tool_of_output(path)
            row = rows.get(tool)
            if row is None:
                warn(
                    "%s/%s is not reported: this scan did not run %s (it has no "
                    "row in %s), so the file is an earlier scan's",
                    target.name,
                    path.name,
                    tool,
                    SCAN_TIMINGS_FILENAME,
                )
                continue
            if row.state is not State.RAN and row.kept_findings is None:
                if row.state is State.FAILED:
                    warn(
                        "%s/%s is not reported: %s's row is %s and no run of it "
                        "worked, so what it wrote is partial",
                        target.name,
                        path.name,
                        tool,
                        row.label,
                    )
                continue
        outputs.append(path)
    return outputs


def gather_results(results_dir: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    # Get lazy-loading registry and loader for tool name normalization
    registry = get_plugin_registry()
    loader = get_plugin_loader()

    # Each load job, and the results folder it reads: the pairing keeps two
    # targets' records apart (#1323), and every finding names its target (#1309).
    jobs: dict[Future[list[dict[str, Any]]], tuple[str, str]] = {}
    target_of: dict[int, str] = {}
    max_workers = 8
    try:
        # Allow override via env, else default to min(8, cpu_count or 4)
        env_thr = os.getenv("JMO_THREADS")
        if env_thr:
            max_workers = max(1, int(env_thr))
        else:
            cpu = os.cpu_count() or 4
            max_workers = min(8, max(2, cpu))
    except ValueError as e:
        # Invalid JMO_THREADS value (e.g., non-numeric string)
        logger.debug(f"Invalid JMO_THREADS value, using default workers: {e}")
        max_workers = 8
    except (OSError, RuntimeError) as e:
        # Environment or CPU inspection failed (cpu_count() can raise RuntimeError)
        logger.debug(f"Failed to determine CPU count, using default workers: {e}")
        max_workers = 8

    profiling = os.getenv("JMO_PROFILE") == "1"
    if profiling:
        try:
            PROFILE_TIMINGS["meta"]["max_workers"] = max_workers
        except (KeyError, TypeError) as e:
            # Profiling metadata update is best-effort; PROFILE_TIMINGS may be modified
            logger.debug(f"Failed to update profiling metadata: {e}")

    # Scan all target type directories: repos, images, IaC, web, gitlab, k8s
    target_dirs = _target_dirs(results_dir)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for target_dir in target_dirs:
            if not target_dir.exists():
                continue

            for target in sorted(p for p in target_dir.iterdir() if p.is_dir()):
                # Discover the tool outputs this scan produced, through the
                # plugin registry
                for tool_output in _outputs_of_this_scan(target, logger.warning):
                    # e.g. "trivy", "osv-scanner"; "trufflehog" for
                    # trufflehog.git.json as well
                    tool_name = tool_of_output(tool_output)

                    # Hyphenated tool names map to underscored adapters
                    adapter_name = loader._tool_to_adapter_name(tool_name)

                    # Get plugin for this tool
                    plugin_class = registry.get(adapter_name)
                    if plugin_class is None:
                        logger.warning(
                            f"No adapter plugin found for: {tool_name} ({tool_output})"
                        )
                        continue

                    # Submit job to load findings using plugin
                    future = ex.submit(
                        _safe_load_plugin, plugin_class, tool_output, profiling
                    )
                    jobs[future] = (target_dir.name, target.name)
        for fut in as_completed(jobs):
            try:
                loaded = fut.result()
                folder, name = jobs[fut]
                for finding in loaded:
                    target_of[id(finding)] = f"{folder}/{name}"
                    # From where `jmo scan` put the output, never from the
                    # adapter or from `scan-timings.json`, which is optional.
                    finding["target"] = {"type": _TARGET_TYPES[folder], "name": name}
                findings.extend(loaded)
            except (
                Exception
            ) as e:  # Acceptable: a broken future must not abort aggregation
                # `_safe_load_plugin` already catches AdapterParseException,
                # FileNotFoundError, OSError and bare Exception, returning `[]`
                # for each -- so this loop used to carry per-type handlers that
                # could never run. Worse, the dead `AdapterParseException` one
                # held the *better* message (it unpacked `.tool`/`.path`/
                # `.reason` where the live one printed only `e`), so the good
                # diagnostic was the unreachable one. Same shape as #808 and the
                # dead `_iter_*` helpers: two copies, and the fix lived in the
                # one nothing calls.
                #
                # They are removed rather than kept "just in case": an except
                # clause that cannot fire is a claim about behaviour that is not
                # true. This generic one stays as a genuine backstop, because a
                # future can fail for reasons unrelated to its callable.
                logger.error(f"Unexpected error loading findings: {e}", exc_info=True)

    # Normalize `location.path` to one repo-relative POSIX spelling **before**
    # dedup (#861). Order matters: dedup keys on `id`, and `id` is derived from
    # the path, so two spellings of one location are two ids and survive dedup
    # as separate findings. Measured on a real scan, `python/vulnerable_app.py`
    # arrived under both `C:\...\repos\fixturecopy\python\vulnerable_app.py`
    # (bandit) and `python\vulnerable_app.py` (horusec).
    paths_changed, ids_rekeyed = _normalize_paths_and_ids(
        findings, scan_roots(results_dir)
    )
    if paths_changed:
        logger.info(
            "Normalized %d finding path(s) to repo-relative POSIX form "
            "(%d finding id(s) re-keyed)",
            paths_changed,
            ids_rekeyed,
        )

    # Scope every id to its target (#1309), once the paths are normalised: the
    # re-keying above recognises an id by recomputing it from the adapter's own
    # inputs, so it has to see the adapter's id. Before dedup, which keys on
    # `id`, so the same finding in two targets is two findings.
    _scope_ids_to_targets(findings)

    # After the paths are normalised, since a tree record's absolute path and
    # a history record's relative one must compare equal; before dedup, which
    # would otherwise keep whichever of a secret's records a thread finished
    # first.
    paired = len(findings)
    findings = pair_history_with_tree(findings, target_of)
    if paired != len(findings):
        logger.info(
            "Folded %d git-history record(s) into the findings for the same secret",
            paired - len(findings),
        )

    # Dedupe by id (fingerprint) - memory-efficient approach
    # Uses set for fingerprints (tiny strings) instead of dict storing full findings
    # This avoids double memory storage (dict + list copy)
    deduped = deduplicate_findings_memory_efficient(findings)

    # The three enrichment stages below are best-effort by design: a failure must
    # not block the report. But each catches every exception around a call that
    # enriches the WHOLE list, so a single failure costs every finding its
    # enrichment -- and at DEBUG that is invisible, because `configure_scan_logging`
    # sets the `scripts` logger to WARNING for a normal run.
    #
    # Measured on a real 244-finding scan: a corrupt `~/.jmo/cache/epss_scores.db`
    # -- an ordinary on-disk file, not a network outage -- took priority
    # enrichment from 244/244 to 0/244 while emitting one DEBUG record and
    # nothing at WARNING or above. The report is written, is the expected length,
    # and silently has no EPSS/KEV data at all. Same shape as #823/#836: the
    # failure is not the problem, the silence is.
    #
    # These report at WARNING and name what was lost. They cannot become the
    # always-fires warning #784 was about, because they fire only on an actual
    # exception -- a healthy run raises none.

    # Enrich Trivy findings with Syft SBOM context when available
    try:
        _enrich_trivy_with_syft(deduped)
    except (
        Exception
    ) as e:  # Acceptable: enrichment is best-effort — must not block report generation
        logger.warning(
            "Trivy/Syft SBOM enrichment failed, so no finding in this report "
            "carries SBOM package context (%d findings affected): %s: %s",
            len(deduped),
            type(e).__name__,
            e,
        )

    # Lift each tool's own CWE into `risk.cwe` BEFORE compliance enrichment
    # (#845). Order is the whole point: `enrich_finding_with_compliance` reads
    # CWEs from `risk.cwe` and nowhere else, so a CWE that arrives after this
    # call reaches no framework. Measured before the fix -- bandit reported a
    # CWE on 17 of 17 findings and 0 reached the mapper, and `cweTop25_2024`
    # was populated on 0 findings in the whole corpus.
    filled = backfill_risk_cwe(deduped)
    if filled:
        logger.info("Lifted a tool-reported CWE into risk.cwe on %d finding(s)", filled)

    # Enrich all findings with compliance framework mappings (v1.2.0)
    try:
        deduped = enrich_findings_with_compliance(deduped)
    except (
        Exception
    ) as e:  # Acceptable: enrichment is best-effort — must not block report generation
        # `deduped` is deliberately left bound to the un-enriched list: the
        # assignment never happens, so the findings themselves survive intact.
        detail = (
            f"mapping data not found: {e.filename}"
            if isinstance(e, FileNotFoundError)
            else f"{type(e).__name__}: {e}"
        )
        logger.warning(
            "Compliance enrichment failed, so no finding in this report carries "
            "OWASP/CWE/CIS/NIST/PCI/MITRE mappings and the compliance reports "
            "will be empty (%d findings affected): %s",
            len(deduped),
            detail,
        )

    # Enrich findings with priority scores (v0.9.0 Feature #5: EPSS/KEV)
    try:
        _enrich_with_priority(deduped)
    except (
        Exception
    ) as e:  # Acceptable: enrichment is best-effort — EPSS/KEV API failures non-fatal
        logger.warning(
            "Priority enrichment failed, so no finding in this report carries an "
            "EPSS score, KEV status or priority ranking (%d findings affected). "
            "Check ~/.jmo/cache for an unreadable epss_scores.db or kev_catalog.json: %s: %s",
            len(deduped),
            type(e).__name__,
            e,
        )

    # Cross-tool deduplication clustering (v1.0.0 Feature #4 - Phase 2)
    # Threshold configurable via JMO_DEDUP_THRESHOLD env var or jmo.yml deduplication section
    try:
        dedup_threshold = 0.65  # Default threshold
        env_threshold = os.getenv("JMO_DEDUP_THRESHOLD")
        if env_threshold:
            try:
                threshold_val = float(env_threshold)
                if 0.5 <= threshold_val <= 1.0:
                    dedup_threshold = threshold_val
                else:
                    logger.debug(
                        f"JMO_DEDUP_THRESHOLD {threshold_val} out of range [0.5-1.0], using default"
                    )
            except ValueError:
                logger.debug(f"Invalid JMO_DEDUP_THRESHOLD value: {env_threshold}")

        deduped = _cluster_cross_tool_duplicates(
            deduped, similarity_threshold=dedup_threshold
        )
    except Exception as e:  # Acceptable: dedup clustering is best-effort — continue with unfiltered results
        logger.warning(
            f"Cross-tool clustering failed, continuing with Phase 1 deduplication: {e}"
        )

    return deduped


def _safe_load_plugin(
    plugin_class, path: Path, profiling: bool = False
) -> list[dict[str, Any]]:
    """Load findings using plugin architecture (v0.9.0+).

    Args:
        plugin_class: AdapterPlugin class (not instance)
        path: Path to tool output file
        profiling: Whether to record timing data

    Returns:
        List of finding dictionaries
    """
    try:
        adapter = plugin_class()  # Instantiate plugin
        tool_name = adapter.metadata.name

        if profiling:
            t0 = time.perf_counter()
            findings = adapter.parse(path)
            dt = time.perf_counter() - t0
            try:
                PROFILE_TIMINGS["jobs"].append(
                    {
                        "tool": tool_name,
                        "path": str(path),
                        "seconds": round(dt, 6),
                        "count": len(findings) if isinstance(findings, list) else 0,
                    }
                )
            except (KeyError, TypeError, AttributeError) as e:
                logger.debug(f"Failed to record profiling timing: {e}")
            # Convert Finding objects to dicts
            return [f.to_dict() for f in findings]
        else:
            findings = adapter.parse(path)
            # Convert Finding objects to dicts
            return [f.to_dict() for f in findings]

    except FileNotFoundError:
        logger.debug(f"Tool output not found: {path}")
        return []
    except AdapterParseException as e:
        # WARNING, not DEBUG. `configure_scan_logging` sets the `scripts` logger
        # to WARNING by default, so at DEBUG this was invisible in every normal
        # run -- and what it hides is a tool that ran, exited acceptably and
        # wrote a file JMo cannot read. Its findings are absent from the report
        # while the scan reports success, which is the #769 / `zero-secrets`
        # class all over again.
        #
        # Measured on #822: a `per_tool` flag making trivy emit a table instead
        # of JSON took a target from 2 findings to 0, with rc=0 and not one line
        # on any stream. Flag collision is only one cause -- a tool changing its
        # output schema between versions does the same thing -- so this is the
        # guard for the whole class rather than for that one bug.
        #
        # Message carries tool, path and reason: `AdapterParseException` already
        # separates them, and "which tool lost its findings" is the first thing
        # a reader needs.
        logger.warning(
            "%s produced output that could not be parsed, so its findings are "
            "MISSING from this report: %s (%s)",
            e.tool,
            e.path,
            e.reason,
        )
        return []
    except (OSError, PermissionError) as e:
        logger.debug(f"Failed to read tool output {path}: {e}")
        return []
    except (
        Exception
    ) as e:  # Acceptable: file scanning safety — skip unreadable tool outputs
        logger.error(f"Unexpected error loading {path}: {e}", exc_info=True)
        return []


def _build_syft_indexes(
    findings: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, str]]], dict[str, list[dict[str, str]]]]:
    """Build indexes of Syft packages by file path and lowercase package name.

    Args:
        findings: All findings from all tools (of one target: the indexes have
            no target in them, and `_enrich_trivy_with_syft` builds one set per
            target)

    Returns:
        Tuple of (by_path, by_name) indexes where:
        - by_path: Dict mapping file paths to list of package dicts
        - by_name: Dict mapping lowercase package names to list of package dicts
    """
    by_path: dict[str, list[dict[str, str]]] = {}
    by_name: dict[str, list[dict[str, str]]] = {}

    for f in findings:
        if not isinstance(f, dict):
            continue
        tool_info = f.get("tool") or {}
        tool = tool_info.get("name") if isinstance(tool_info, dict) else None
        tags = f.get("tags") or []

        if tool == "syft" and ("package" in tags or "sbom" in tags):
            raw = f.get("raw") or {}
            if not isinstance(raw, dict):
                raw = {}
            name = str(raw.get("name") or f.get("title") or "").strip()
            version = str(raw.get("version") or "").strip()
            loc = f.get("location") or {}
            path = str(loc.get("path") if isinstance(loc, dict) else "" or "")

            if path:
                by_path.setdefault(path, []).append(
                    {"name": name, "version": version, "path": path}
                )
            if name:
                by_name.setdefault(name.lower(), []).append(
                    {"name": name, "version": version, "path": path}
                )

    return by_path, by_name


def _find_sbom_match(
    trivy_finding: dict[str, Any],
    by_path: dict[str, list[dict[str, str]]],
    by_name: dict[str, list[dict[str, str]]],
) -> dict[str, str] | None:
    """Find matching SBOM package for a Trivy finding.

    The indexes are one target's (see `_enrich_trivy_with_syft`). The rule:

    - A finding that names its package (`raw.PkgName`) matches the package of
      that name at its path (`location.path`, or `raw.PkgPath`), else the first
      package of that name anywhere in the target. A path alone does not say
      which package a finding is of: a lockfile lists every package of a project
      at one path (#1408). Names compare without case, and trivy's Maven
      `group:artifact` also matches syft's bare artifactId (syft keeps the group
      in the package URL only). The by-name lookup is NOT widened that way: a
      bare artifactId alone names no group.
    - Among several candidates of that name, the one whose version equals the
      finding's `raw.InstalledVersion` wins (compared as text); with no such
      version, or none named, the first. The candidates are those at the path
      (npm lists a nested copy of a package beside the top-level one in one
      lockfile) or, failing a path match, those anywhere in the target (the
      package in two lockfiles). The version never overrides the path: a
      package of that name at the finding's path is taken even when the
      finding's version is listed elsewhere.
    - A finding with no package name matches by path only when exactly one
      package is at that path. With several, any pick is a guess.

    Args:
        trivy_finding: Trivy finding dict
        by_path: Index of packages by file path
        by_name: Index of packages by lowercase name

    Returns:
        Best matching package dict, or None if no match found
    """
    loc = trivy_finding.get("location") or {}
    loc_path = str(loc.get("path") if isinstance(loc, dict) else "" or "")
    raw = trivy_finding.get("raw") or {}
    if not isinstance(raw, dict):
        raw = {}
    pkg_name = str(raw.get("PkgName") or "").strip().lower()
    pkg_path = str(raw.get("PkgPath") or "").strip()
    installed = str(raw.get("InstalledVersion") or "").strip()

    def of_installed_version(candidates: list[dict[str, str]]) -> dict[str, str]:
        """The candidate at the version trivy found, else the first."""
        return next(
            (p for p in candidates if installed and p["version"] == installed),
            candidates[0],
        )

    # `dict.fromkeys`: a finding whose location is its PkgPath asks once.
    at_path = [
        p for path in dict.fromkeys((loc_path, pkg_path)) for p in by_path.get(path, [])
    ]
    if not pkg_name:
        return at_path[0] if len(at_path) == 1 else None

    names = {pkg_name, pkg_name.rsplit(":", 1)[-1]}
    at_path = [p for p in at_path if p["name"].lower() in names]
    if at_path:
        return of_installed_version(at_path)

    named = by_name.get(pkg_name, [])
    return of_installed_version(named) if named else None


def _attach_sbom_context(finding: dict[str, Any], match: dict[str, str]) -> None:
    """Attach SBOM context and package tag to a finding.

    Args:
        finding: Finding dict to enrich (modified in-place)
        match: Matched package dict with name, version, path
    """
    # Attach context
    ctx = finding.setdefault("context", {})
    ctx["sbom"] = {k: v for k, v in match.items() if v}

    # Add package tag
    tags = finding.setdefault("tags", [])
    tag_val = (
        "pkg:"
        + match["name"]
        + ("@" + match["version"] if match.get("version") else "")
    )
    if tag_val not in tags:
        tags.append(tag_val)


def _enrich_trivy_with_syft(findings: list[dict[str, Any]]) -> None:
    """Best-effort enrichment: attach SBOM package context from Syft to Trivy findings.

    Strategy:
    - Group the findings by target: a package belongs to the image or repository
      syft catalogued, and a Trivy finding takes a package from its own target's
      SBOM only. Two images hold an openssl at one path in the apk database, and
      nothing but the target says whose is whose (#1408). Findings that carry no
      `target` are one group of their own.
    - Within a target, build indexes of Syft packages by file path and by
      lowercase package name.
    - For each Trivy finding, try to match by location.path and/or raw.PkgName/PkgPath.
    - When matched, attach context.sbom = {name, version, path} and add a tag 'pkg:name@version'.
    """
    by_target: dict[tuple[Any, Any] | None, list[dict[str, Any]]] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        target = f.get("target")
        key = (
            (target.get("type"), target.get("name"))
            if isinstance(target, dict)
            else None
        )
        by_target.setdefault(key, []).append(f)

    for group in by_target.values():
        by_path, by_name = _build_syft_indexes(group)

        # Enrich Trivy findings
        for f in group:
            tool_info = f.get("tool") or {}
            tool = tool_info.get("name") if isinstance(tool_info, dict) else None
            if tool != "trivy":
                continue

            match = _find_sbom_match(f, by_path, by_name)
            if match:
                _attach_sbom_context(f, match)


def _enrich_with_priority(findings: list[dict[str, Any]]) -> None:
    """Enrich findings with priority scores using EPSS and CISA KEV data.

    Adds a 'priority' field to each finding containing:
    - priority: float (0-100 score)
    - epss: float (0.0-1.0 exploit probability) if available
    - epss_percentile: float (0.0-1.0) if available
    - is_kev: bool (whether CVE is in CISA KEV catalog)
    - kev_due_date: str (remediation deadline for federal agencies) if applicable
    - components: dict (breakdown of score components for transparency)

    Args:
        findings: List of findings to enrich (modified in-place)
    """
    if not findings:
        return

    # Initialize priority calculator
    calculator = PriorityCalculator()

    # Calculate priorities in bulk for better performance
    priority_scores = calculator.calculate_priorities_bulk(findings)

    # Attach priority data to findings
    for finding in findings:
        finding_id = finding.get("id")
        if finding_id and finding_id in priority_scores:
            priority_score = priority_scores[finding_id]

            # Convert PriorityScore dataclass to dict for JSON serialization
            finding["priority"] = {
                "priority": priority_score.priority,
                "epss": priority_score.epss,
                "epss_percentile": priority_score.epss_percentile,
                "is_kev": priority_score.is_kev,
                "kev_due_date": priority_score.kev_due_date,
                "components": priority_score.components,
            }


def _cluster_cross_tool_duplicates(
    findings: list[dict[str, Any]],
    similarity_threshold: float = 0.65,
) -> list[dict[str, Any]]:
    """Apply cross-tool deduplication clustering (Phase 2).

    Groups similar findings from different tools into consensus findings with
    detected_by arrays. Uses multi-dimensional similarity matching on:
    - Location (path + line numbers): 50% weight
    - Message content (fuzzy text matching): 25% weight
    - Metadata (CWE, CVE, rule IDs): 25% weight

    Args:
        findings: List of deduplicated findings from Phase 1 (fingerprint-based)
        similarity_threshold: Minimum similarity score (0.5-1.0) for clustering.
            Configurable via jmo.yml deduplication.similarity_threshold or
            JMO_DEDUP_THRESHOLD environment variable. Default: 0.65

    Returns:
        List of consensus findings with cross-tool duplicates clustered
    """
    # Skip clustering if too few findings
    if len(findings) < 2:
        logger.debug("Skipping cross-tool clustering (< 2 findings)")
        return findings

    from scripts.core.dedup_enhanced import FindingClusterer

    logger.info(f"Clustering {len(findings)} findings for cross-tool duplicates...")

    # Progress callback for user feedback
    def progress(current: int, total: int, message: str):
        if current % 50 == 0 or current == total:
            logger.info(message)

    # Create clusterer with configurable threshold and location-first weights
    # Updated weights: location=0.50, message=0.25, metadata=0.25
    # Lower threshold (0.65 vs 0.75) enables better cross-tool clustering
    # Rule equivalence mapping in metadata_similarity prevents false positives
    # Example: Trivy "DS-0001" + Hadolint "DL3006" on same line → clustered
    # Threshold is configurable via jmo.yml deduplication section or JMO_DEDUP_THRESHOLD env
    logger.debug(f"Using similarity threshold: {similarity_threshold}")
    clusterer = FindingClusterer(similarity_threshold=similarity_threshold)

    # Run clustering algorithm
    clusters = clusterer.cluster(findings, progress_callback=progress)

    # Convert clusters to consensus findings
    consensus_findings = []
    for cluster in clusters:
        if len(cluster.findings) > 1:
            # Multiple findings in cluster -> create consensus
            consensus_findings.append(cluster.to_consensus_finding())
        else:
            # Single finding -> keep as-is
            consensus_findings.append(cluster.representative)

    # Log reduction statistics
    reduction_count = len(findings) - len(consensus_findings)
    reduction_pct = (reduction_count / len(findings) * 100) if len(findings) > 0 else 0
    logger.info(
        f"Cross-tool clustering complete: {len(findings)} → {len(consensus_findings)} findings "
        f"({reduction_count} duplicates removed, {reduction_pct:.1f}% reduction)"
    )

    return consensus_findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "results_dir", help="Directory with tool outputs (individual-repos/*)"
    )
    ap.add_argument(
        "--out",
        default=None,
        help="Output directory (default: <results_dir>/summaries)",
    )
    args = ap.parse_args()

    results_dir = Path(args.results_dir).resolve()
    out_dir = Path(args.out) if args.out else results_dir / "summaries"
    out_dir.mkdir(parents=True, exist_ok=True)

    findings = gather_results(results_dir)
    write_json(findings, out_dir / "findings.json")
    write_markdown(findings, out_dir / "SUMMARY.md")

    print(f"Wrote {len(findings)} findings to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
