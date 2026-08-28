#!/usr/bin/env python3
"""
Normalize and report: load tool outputs from a results directory, convert to CommonFinding,
dedupe by fingerprint, and emit JSON + Markdown summaries.

Expected structure (flexible, supports 6 target types):
results_dir/
  individual-repos/
    <repo>/trufflehog.json
    <repo>/semgrep.json
    <repo>/trivy.json
    <repo>/... (28 active tools total)

Usage:
  python3 scripts/core/normalize_and_report.py <results_dir> [--out <out_dir>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from scripts.core.adapters.common import normalize_finding_path
from scripts.core.common_finding import (
    FINGERPRINT_LENGTH,
    MESSAGE_SNIPPET_LENGTH,
    fingerprint,
)
from scripts.core.compliance_mapper import enrich_findings_with_compliance
from scripts.core.cwe_extraction import backfill_risk_cwe
from scripts.core.exceptions import AdapterParseException

# Plugin system (v0.9.0)
from scripts.core.plugin_loader import get_plugin_loader, get_plugin_registry

# Priority calculation (v0.9.0 Feature #5: EPSS/KEV)
from scripts.core.priority_calculator import PriorityCalculator
from scripts.core.reporters.basic_reporter import write_json, write_markdown
from scripts.core.scan_timings import SCAN_TIMINGS_FILENAME
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
    ``history_db._scanned_repo_paths`` uses. Returns an empty tuple when the
    file is absent or unreadable -- a results directory produced by something
    other than `jmo scan` still normalizes separators and leading separators,
    it just cannot strip a host prefix it was never told about.
    """
    try:
        meta = json.loads(
            (results_dir / ".scan_metadata.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return ()
    if not isinstance(meta, dict):
        return ()
    raw = meta.get("repo_paths")
    if not isinstance(raw, list):
        return ()
    return tuple(entry for entry in raw if isinstance(entry, str) and entry)


def _legacy_plugin_fingerprint(
    tool: str, rule_id: str, path: str, start_line: Any, message: str
) -> str:
    """The formula in ``AdapterPlugin.get_fingerprint``.

    There are **two** fingerprint formulas in this codebase and they disagree:
    :func:`~scripts.core.common_finding.fingerprint` coerces a missing line to
    ``0`` and strips the message, while ``get_fingerprint`` renders a missing
    line as ``""`` and does not strip. trivy, trufflehog and semgrep use the
    second. Reproducing both is what lets
    :func:`_normalize_paths_and_ids` *prove* an id was path-derived instead of
    assuming it.
    """
    parts = [tool, rule_id, path, str(start_line), message[:MESSAGE_SNIPPET_LENGTH]]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:FINGERPRINT_LENGTH]


def _normalize_paths_and_ids(
    findings: list[dict[str, Any]], roots: tuple[str, ...]
) -> tuple[int, int]:
    """Normalize ``location.path`` in place and re-key path-derived ids (#861).

    Returns ``(paths_changed, ids_rekeyed)``.

    **The id is only recomputed when the existing one can be shown to have come
    from the old path.** That check is not defensive padding -- it is load
    bearing. Four adapters deliberately fingerprint on something that is *not*
    ``location.path``:

    ==============  =====================================================
    ``zap``         ``f"{uri}:{method}:{param}:{idx}"`` -- one alert on one
                    URI yields several findings that differ only by param
    ``cdxgen``      ``component_id``
    ``nuclei``      the matched URL
    ``mobsf``       the literal ``"AndroidManifest.xml"`` on one branch
    ==============  =====================================================

    Re-keying those from ``location.path`` would give every instance the same
    id, and `deduplicate_findings_memory_efficient` would then delete all but
    the first -- turning a path cleanup into silent finding loss, which is the
    exact failure class this campaign keeps finding. Deriving the answer from
    the data rather than from a hard-coded allowlist also means a new adapter
    with a custom key is safe on the day it lands, with nothing to remember.
    """
    paths_changed = 0
    ids_rekeyed = 0

    for finding in findings:
        location = finding.get("location")
        if not isinstance(location, dict):
            continue
        original = location.get("path")
        if not isinstance(original, str) or not original:
            continue

        normalized = normalize_finding_path(original, roots)
        if normalized == original:
            continue

        location["path"] = normalized
        paths_changed += 1

        current = finding.get("id")
        if not isinstance(current, str) or not current:
            continue
        tool = (finding.get("tool") or {}).get("name", "")
        rule_id = finding.get("ruleId", "") or ""
        message = finding.get("message", "") or ""
        start_line = location.get("startLine")

        if current == fingerprint(tool, rule_id, original, start_line, message):
            finding["id"] = fingerprint(tool, rule_id, normalized, start_line, message)
            ids_rekeyed += 1
        elif current == _legacy_plugin_fingerprint(
            tool,
            rule_id,
            original,
            start_line if start_line is not None else "",
            message,
        ):
            finding["id"] = _legacy_plugin_fingerprint(
                tool,
                rule_id,
                normalized,
                start_line if start_line is not None else "",
                message,
            )
            ids_rekeyed += 1

    return paths_changed, ids_rekeyed


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
            for tool_output in target.glob("*.json"):
                if tool_output.name == SCAN_TIMINGS_FILENAME:
                    continue
                tool_name = tool_output.stem
                if tool_name == "afl++":
                    tool_name = "aflplusplus"
                adapter_name = loader._tool_to_adapter_name(tool_name)
                out.extend(extract_tool_diagnostics(adapter_name, tool_output, roots))
    return out


def _target_dirs(results_dir: Path) -> list[Path]:
    """The six target-type directories a scan can write.

    Defined once because `gather_results` and `collect_tool_diagnostics` must
    walk the same set - a seventh target type added to one and not the other
    would go unreported in exactly the silent way #837 is about.
    """
    return [
        results_dir / "individual-repos",
        results_dir / "individual-images",
        results_dir / "individual-iac",
        results_dir / "individual-web",
        results_dir / "individual-gitlab",
        results_dir / "individual-k8s",
    ]


def gather_results(results_dir: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    # Get lazy-loading registry and loader for tool name normalization
    registry = get_plugin_registry()
    loader = get_plugin_loader()

    jobs = []
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
                # Discover all tool outputs using plugin registry
                for tool_output in target.glob("*.json"):
                    # JMo's own scan-phase instrumentation, written by
                    # write_scan_timings into the same directory as the tool
                    # outputs. It is not a tool result, so no adapter exists for
                    # it and the registry lookup below warned about it on
                    # *every* report run (#784). A warning that always fires
                    # teaches the reader to skip the whole class -- and "no
                    # adapter plugin found" is precisely the message that
                    # matters when a real adapter goes missing.
                    #
                    # Compared against the constant rather than the literal
                    # string so renaming the artifact cannot quietly resurrect
                    # the warning.
                    if tool_output.name == SCAN_TIMINGS_FILENAME:
                        continue

                    tool_name = tool_output.stem  # e.g., "trivy", "semgrep", "afl++"

                    # Handle special case: afl++.json → tool name is "aflplusplus"
                    if tool_name == "afl++":
                        tool_name = "aflplusplus"

                    # Normalize tool name to adapter name (e.g., "checkov-cicd" → "checkov")
                    # This handles variant filenames from scan profiles
                    adapter_name = loader._tool_to_adapter_name(tool_name)

                    # Get plugin for this tool
                    plugin_class = registry.get(adapter_name)
                    if plugin_class is None:
                        logger.warning(
                            f"No adapter plugin found for: {tool_name} ({tool_output})"
                        )
                        continue

                    # Submit job to load findings using plugin
                    jobs.append(
                        ex.submit(
                            _safe_load_plugin, plugin_class, tool_output, profiling
                        )
                    )
        for fut in as_completed(jobs):
            try:
                findings.extend(fut.result())
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
    except (
        Exception
    ) as e:  # Acceptable: dedup clustering is best-effort — continue with unfiltered results
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
        findings: All findings from all tools

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
    pkg_name = str(raw.get("PkgName") or "").strip()
    pkg_path = str(raw.get("PkgPath") or "").strip()

    # Collect all candidates
    candidates = []
    if loc_path and loc_path in by_path:
        candidates.extend(by_path.get(loc_path, []))
    if pkg_path and pkg_path in by_path:
        candidates.extend(by_path.get(pkg_path, []))
    if pkg_name and pkg_name.lower() in by_name:
        candidates.extend(by_name.get(pkg_name.lower(), []))

    if not candidates:
        return None

    # Prefer exact path match, then first by name
    if loc_path and loc_path in by_path:
        return by_path[loc_path][0]
    elif pkg_path and pkg_path in by_path:
        return by_path[pkg_path][0]
    else:
        return candidates[0]


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
    - Build indexes of Syft packages by file path and by lowercase package name.
    - For each Trivy finding, try to match by location.path and/or raw.PkgName/PkgPath.
    - When matched, attach context.sbom = {name, version, path} and add a tag 'pkg:name@version'.
    """
    # Build indexes from Syft package entries
    by_path, by_name = _build_syft_indexes(findings)

    # Enrich Trivy findings
    for f in findings:
        if not isinstance(f, dict):
            continue
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
    # Example: Trivy ":latest tag used" + Hadolint "DL3006" on same line → clustered
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
