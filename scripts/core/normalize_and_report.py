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

# Active tool adapters (12 tools)
from scripts.core.adapters.trufflehog_adapter import load_trufflehog
from scripts.core.adapters.semgrep_adapter import load_semgrep
from scripts.core.adapters.noseyparker_adapter import load_noseyparker
from scripts.core.adapters.syft_adapter import load_syft
from scripts.core.adapters.hadolint_adapter import load_hadolint
from scripts.core.adapters.checkov_adapter import load_checkov
from scripts.core.adapters.trivy_adapter import load_trivy
from scripts.core.adapters.bandit_adapter import load_bandit
from scripts.core.adapters.zap_adapter import load_zap
from scripts.core.adapters.nuclei_adapter import load_nuclei
from scripts.core.adapters.falco_adapter import load_falco
from scripts.core.adapters.aflplusplus_adapter import load_aflplusplus
from concurrent.futures import ThreadPoolExecutor, as_completed
from scripts.core.reporters.basic_reporter import write_json, write_markdown
from scripts.core.compliance_mapper import enrich_findings_with_compliance

# Configure logging
logger = logging.getLogger(__name__)

# When profiling is enabled (env JMO_PROFILE=1), this will be populated with per-job timings
PROFILE_TIMINGS: Dict[str, Any] = {
    "jobs": [],  # list of {"tool": str, "path": str, "seconds": float, "count": int}
    "meta": {},  # miscellaneous metadata like max_workers
}


def gather_results(results_dir: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
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
                # Active tools only (12 tools)
                th = target / "trufflehog.json"
                sg = target / "semgrep.json"
                np = target / "noseyparker.json"
                sy = target / "syft.json"
                hd = target / "hadolint.json"
                ck = target / "checkov.json"
                bd = target / "bandit.json"
                tv = target / "trivy.json"
                zap_file = target / "zap.json"
                nuclei_file = target / "nuclei.json"
                falco_file = target / "falco.json"
                afl_file = target / "afl++.json"
                for path, loader in (
                    (th, load_trufflehog),
                    (sg, load_semgrep),
                    (np, load_noseyparker),
                    (sy, load_syft),
                    (hd, load_hadolint),
                    (ck, load_checkov),
                    (bd, load_bandit),
                    (tv, load_trivy),
                    (zap_file, load_zap),
                    (nuclei_file, load_nuclei),
                    (falco_file, load_falco),
                    (afl_file, load_aflplusplus),
                ):
                    jobs.append(ex.submit(_safe_load, loader, path, profiling))
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

    return deduped


def _safe_load(loader, path: Path, profiling: bool = False) -> List[Dict[str, Any]]:
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
    findings: List[Dict[str, Any]]
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
