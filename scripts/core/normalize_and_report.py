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
    <repo>/... (11 active tools total)

Usage:
  python3 scripts/core/normalize_and_report.py <results_dir> [--out <out_dir>]
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import os
import time
from typing import Any, Dict, List, Optional

from scripts.core.exceptions import AdapterParseException

# Plugin system (v0.9.0)
from scripts.core.plugin_loader import discover_adapters, get_plugin_registry
from concurrent.futures import ThreadPoolExecutor, as_completed
from scripts.core.reporters.basic_reporter import write_json, write_markdown
from scripts.core.compliance_mapper import enrich_findings_with_compliance

# Priority calculation (v0.9.0 Feature #5: EPSS/KEV)
from scripts.core.priority_calculator import PriorityCalculator

# Configure logging
logger = logging.getLogger(__name__)

# When profiling is enabled (env JMO_PROFILE=1), this will be populated with per-job timings
PROFILE_TIMINGS: Dict[str, Any] = {
    "jobs": [],  # list of {"tool": str, "path": str, "seconds": float, "count": int}
    "meta": {},  # miscellaneous metadata like max_workers
}


def gather_results(results_dir: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # Discover and load all adapter plugins
    plugin_count = discover_adapters()
    logger.info(f"Loaded {plugin_count} adapter plugins")
    registry = get_plugin_registry()

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
    target_dirs = [
        results_dir / "individual-repos",
        results_dir / "individual-images",
        results_dir / "individual-iac",
        results_dir / "individual-web",
        results_dir / "individual-gitlab",
        results_dir / "individual-k8s",
    ]

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for target_dir in target_dirs:
            if not target_dir.exists():
                continue

            for target in sorted(p for p in target_dir.iterdir() if p.is_dir()):
                # Discover all tool outputs using plugin registry
                for tool_output in target.glob("*.json"):
                    tool_name = tool_output.stem  # e.g., "trivy", "semgrep", "afl++"

                    # Handle special case: afl++.json → tool name is "aflplusplus"
                    if tool_name == "afl++":
                        tool_name = "aflplusplus"

                    # Get plugin for this tool
                    plugin_class = registry.get(tool_name)
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
            except AdapterParseException as e:
                # Adapter parsing failed - log but continue with other tools
                logger.debug(f"Adapter parse failed: {e.tool} on {e.path}: {e.reason}")
            except FileNotFoundError as e:
                # Tool output missing (expected when using --allow-missing-tools)
                logger.debug(f"Tool output file not found: {e.filename}")
            except Exception as e:
                # Unexpected error - log with traceback for debugging
                logger.error(f"Unexpected error loading findings: {e}", exc_info=True)
    # Dedupe by id (fingerprint)
    seen = {}
    for f in findings:
        seen[f.get("id")] = f
    deduped = list(seen.values())

    # Enrich Trivy findings with Syft SBOM context when available
    try:
        _enrich_trivy_with_syft(deduped)
    except (KeyError, ValueError, TypeError) as e:
        # Best-effort enrichment - missing SBOM data or malformed findings
        logger.debug(f"Trivy-Syft enrichment skipped: {e}")
    except Exception as e:
        # Unexpected enrichment failure
        logger.debug(f"Unexpected error during Trivy-Syft enrichment: {e}")

    # Enrich all findings with compliance framework mappings (v1.2.0)
    try:
        deduped = enrich_findings_with_compliance(deduped)
    except FileNotFoundError as e:
        # Compliance mapping data files missing
        logger.debug(
            f"Compliance enrichment skipped: mapping data not found: {e.filename}"
        )
    except (KeyError, ValueError, TypeError) as e:
        # Malformed compliance data or findings
        logger.debug(f"Compliance enrichment skipped: {e}")
    except Exception as e:
        # Unexpected enrichment failure
        logger.debug(f"Unexpected error during compliance enrichment: {e}")

    # Enrich findings with priority scores (v0.9.0 Feature #5: EPSS/KEV)
    try:
        _enrich_with_priority(deduped)
    except (KeyError, ValueError, TypeError) as e:
        # Missing priority data or malformed findings
        logger.debug(f"Priority enrichment skipped: {e}")
    except Exception as e:
        # Unexpected enrichment failure (e.g., EPSS/KEV API errors)
        logger.debug(f"Unexpected error during priority enrichment: {e}")

    return deduped


def _safe_load_plugin(
    plugin_class, path: Path, profiling: bool = False
) -> List[Dict[str, Any]]:
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
            return [vars(f) for f in findings]
        else:
            findings = adapter.parse(path)
            # Convert Finding objects to dicts
            return [vars(f) for f in findings]

    except FileNotFoundError:
        logger.debug(f"Tool output not found: {path}")
        return []
    except AdapterParseException as e:
        logger.debug(f"Adapter parse failed: {e}")
        return []
    except (OSError, PermissionError) as e:
        logger.debug(f"Failed to read tool output {path}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error loading {path}: {e}", exc_info=True)
        return []


def _safe_load(loader, path: Path, profiling: bool = False) -> List[Dict[str, Any]]:
    """DEPRECATED: Legacy loader function for backward compatibility.

    This function will be removed in v1.0.0.
    Use _safe_load_plugin instead.
    """
    try:
        if profiling:
            t0 = time.perf_counter()
            res: List[Dict[str, Any]] = loader(path)
            dt = time.perf_counter() - t0
            try:
                PROFILE_TIMINGS["jobs"].append(
                    {
                        "tool": getattr(loader, "__name__", "unknown"),
                        "path": str(path),
                        "seconds": round(dt, 6),
                        "count": len(res) if isinstance(res, list) else 0,
                    }
                )
            except (KeyError, TypeError, AttributeError) as e:
                # Profiling dict mutation or attribute access failed
                logger.debug(f"Failed to record profiling timing: {e}")
            return res
        else:
            result: List[Dict[str, Any]] = loader(path)
            return result
    except FileNotFoundError:
        # Tool output file missing (expected with --allow-missing-tools)
        logger.debug(f"Tool output not found: {path}")
        return []
    except AdapterParseException as e:
        # Adapter explicitly raised parse exception with context
        logger.debug(f"Adapter parse failed: {e}")
        return []
    except (OSError, PermissionError) as e:
        # File system errors (permissions, I/O errors, etc.)
        logger.debug(f"Failed to read tool output {path}: {e}")
        return []
    except Exception as e:
        # Unexpected adapter error - log with traceback
        logger.error(f"Unexpected error loading {path}: {e}", exc_info=True)
        return []


def _build_syft_indexes(
    findings: List[Dict[str, Any]],
) -> tuple[Dict[str, List[Dict[str, str]]], Dict[str, List[Dict[str, str]]]]:
    """Build indexes of Syft packages by file path and lowercase package name.

    Args:
        findings: All findings from all tools

    Returns:
        Tuple of (by_path, by_name) indexes where:
        - by_path: Dict mapping file paths to list of package dicts
        - by_name: Dict mapping lowercase package names to list of package dicts
    """
    by_path: Dict[str, List[Dict[str, str]]] = {}
    by_name: Dict[str, List[Dict[str, str]]] = {}

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
    trivy_finding: Dict[str, Any],
    by_path: Dict[str, List[Dict[str, str]]],
    by_name: Dict[str, List[Dict[str, str]]],
) -> Optional[Dict[str, str]]:
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


def _attach_sbom_context(finding: Dict[str, Any], match: Dict[str, str]) -> None:
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


def _enrich_trivy_with_syft(findings: List[Dict[str, Any]]) -> None:
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


def _enrich_with_priority(findings: List[Dict[str, Any]]) -> None:
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
