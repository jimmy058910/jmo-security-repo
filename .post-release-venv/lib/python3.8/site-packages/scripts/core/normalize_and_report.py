#!/usr/bin/env python3
"""
Normalize and report: load tool outputs from a results directory, convert to CommonFinding,
dedupe by fingerprint, and emit JSON + Markdown summaries.

Expected structure (flexible):
results_dir/
  individual-repos/
    <repo>/gitleaks.json
    <repo>/trufflehog.json
    <repo>/semgrep.json
    <repo>/noseyparker.json

Usage:
  python3 scripts/core/normalize_and_report.py <results_dir> [--out <out_dir>]
"""
from __future__ import annotations

import argparse
from pathlib import Path
import os
import time
from typing import Any, Dict, List

from scripts.core.adapters.gitleaks_adapter import load_gitleaks
from scripts.core.adapters.trufflehog_adapter import load_trufflehog
from scripts.core.adapters.semgrep_adapter import load_semgrep
from scripts.core.adapters.noseyparker_adapter import load_noseyparker
from scripts.core.adapters.syft_adapter import load_syft
from scripts.core.adapters.hadolint_adapter import load_hadolint
from scripts.core.adapters.checkov_adapter import load_checkov
from scripts.core.adapters.tfsec_adapter import load_tfsec
from scripts.core.adapters.trivy_adapter import load_trivy
from scripts.core.adapters.bandit_adapter import load_bandit
from concurrent.futures import ThreadPoolExecutor, as_completed
from scripts.core.reporters.basic_reporter import write_json, write_markdown

# When profiling is enabled (env JMO_PROFILE=1), this will be populated with per-job timings
PROFILE_TIMINGS = {
    "jobs": [],  # list of {"tool": str, "path": str, "seconds": float, "count": int}
    "meta": {},  # miscellaneous metadata like max_workers
}


def gather_results(results_dir: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    indiv = results_dir / "individual-repos"
    if not indiv.exists():
        return findings
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
    except Exception:
        # Fall back to default workers if environment inspection fails
        max_workers = 8

    profiling = os.getenv("JMO_PROFILE") == "1"
    if profiling:
        try:
            PROFILE_TIMINGS["meta"]["max_workers"] = max_workers
        except Exception:
            # profiling metadata update is best-effort
            ...

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for repo in sorted(p for p in indiv.iterdir() if p.is_dir()):
            gl = repo / "gitleaks.json"
            th = repo / "trufflehog.json"
            sg = repo / "semgrep.json"
            np = repo / "noseyparker.json"
            sy = repo / "syft.json"
            hd = repo / "hadolint.json"
            ck = repo / "checkov.json"
            bd = repo / "bandit.json"
            tf = repo / "tfsec.json"
            tv = repo / "trivy.json"
            for path, loader in (
                (gl, load_gitleaks),
                (th, load_trufflehog),
                (sg, load_semgrep),
                (np, load_noseyparker),
                (sy, load_syft),
                (hd, load_hadolint),
                (ck, load_checkov),
                (bd, load_bandit),
                (tf, load_tfsec),
                (tv, load_trivy),
            ):
                jobs.append(ex.submit(_safe_load, loader, path, profiling))
        for fut in as_completed(jobs):
            try:
                findings.extend(fut.result())
            except Exception:
                # Individual loader failures should not break aggregation
                ...
    # Dedupe by id (fingerprint)
    seen = {}
    for f in findings:
        seen[f.get("id")] = f
    deduped = list(seen.values())

    # Enrich Trivy findings with Syft SBOM context when available
    try:
        _enrich_trivy_with_syft(deduped)
    except Exception:
        # best-effort enrichment; ignore failures
        # leave silent to avoid noisy logs at import-time context
        ...
    return deduped


def _safe_load(loader, path: Path, profiling: bool = False) -> List[Dict[str, Any]]:
    try:
        if profiling:
            t0 = time.perf_counter()
            res = loader(path)
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
            except Exception:
                # If profiling dict is mutated concurrently or missing, ignore
                ...
            return res
        else:
            return loader(path)
    except Exception:
        # If any adapter throws, return an empty list for resilience
        return []


def _enrich_trivy_with_syft(findings: List[Dict[str, Any]]) -> None:
    """Best-effort enrichment: attach SBOM package context from Syft to Trivy findings.

    Strategy:
    - Build indexes of Syft packages by file path and by lowercase package name.
    - For each Trivy finding, try to match by location.path and/or raw.PkgName/PkgPath.
    - When matched, attach context.sbom = {name, version, path} and add a tag 'pkg:name@version'.
    """
    # Build indexes from Syft package entries (INFO-level with tags include 'sbom'/'package')
    by_path = {}
    by_name = {}
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
                by_path.setdefault(path, []).append({"name": name, "version": version, "path": path})
            if name:
                by_name.setdefault(name.lower(), []).append({"name": name, "version": version, "path": path})

    # Enrich Trivy findings
    for f in findings:
        if not isinstance(f, dict):
            continue
        tool_info = f.get("tool") or {}
        tool = tool_info.get("name") if isinstance(tool_info, dict) else None
        if tool != "trivy":
            continue
        loc = f.get("location") or {}
        loc_path = str(loc.get("path") if isinstance(loc, dict) else "" or "")
        raw = f.get("raw") or {}
        if not isinstance(raw, dict):
            raw = {}
        pkg_name = str(raw.get("PkgName") or "").strip()
        pkg_path = str(raw.get("PkgPath") or "").strip()

        candidates = []
        if loc_path and loc_path in by_path:
            candidates.extend(by_path.get(loc_path, []))
        if pkg_path and pkg_path in by_path:
            candidates.extend(by_path.get(pkg_path, []))
        if pkg_name and pkg_name.lower() in by_name:
            candidates.extend(by_name.get(pkg_name.lower(), []))
        if not candidates:
            continue
        # Prefer exact path match, then first by name
        if loc_path and loc_path in by_path:
            match = by_path[loc_path][0]
        elif pkg_path and pkg_path in by_path:
            match = by_path[pkg_path][0]
        else:
            match = candidates[0]

        # Attach context and tag
        ctx = f.setdefault("context", {})
        ctx["sbom"] = {k: v for k, v in match.items() if v}
        tags = f.setdefault("tags", [])
        tag_val = "pkg:" + match["name"] + ("@" + match["version"] if match.get("version") else "")
        if tag_val not in tags:
            tags.append(tag_val)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results_dir", help="Directory with tool outputs (individual-repos/*)")
    ap.add_argument("--out", default=None, help="Output directory (default: <results_dir>/summaries)")
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
