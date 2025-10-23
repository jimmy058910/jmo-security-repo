#!/usr/bin/env python3
"""Report orchestration logic for JMo Security."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from scripts.core.config import load_config
from scripts.core.normalize_and_report import gather_results
from scripts.core.reporters.basic_reporter import write_json, write_markdown
from scripts.core.reporters.compliance_reporter import (
    write_attack_navigator_json,
    write_compliance_summary,
    write_pci_dss_report,
)
from scripts.core.reporters.html_reporter import write_html
from scripts.core.reporters.sarif_reporter import write_sarif
from scripts.core.reporters.suppression_reporter import write_suppression_report
from scripts.core.reporters.yaml_reporter import write_yaml
from scripts.core.suppress import filter_suppressed, load_suppressions
from scripts.core.telemetry import send_event, bucket_findings

logger = logging.getLogger(__name__)

# Version (from pyproject.toml)
__version__ = "0.7.0-dev"  # Will be updated to 0.7.0 at release

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def fail_code(threshold: str | None, counts: dict) -> int:
    """Determine exit code based on severity threshold.

    Args:
        threshold: Minimum severity level to fail on (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        counts: Dictionary mapping severity levels to finding counts

    Returns:
        1 if any findings at or above threshold severity, 0 otherwise
    """
    if not threshold:
        return 0
    thr = threshold.upper()
    if thr not in SEV_ORDER:
        return 0
    idx = SEV_ORDER.index(thr)
    severities = SEV_ORDER[: idx + 1]
    return 1 if any(counts.get(s, 0) > 0 for s in severities) else 0


def cmd_report(args, _log_fn) -> int:
    """Run report command: aggregate findings and generate outputs.

    Args:
        args: Parsed CLI arguments with results_dir, config, fail_on, etc.
        _log_fn: Logging function (args, level, message) -> None

    Returns:
        Exit code (0 for success, 1 if threshold exceeded, 2 for errors)
    """
    cfg = load_config(args.config)

    # Normalize results_dir from positional or optional
    rd = (
        getattr(args, "results_dir_opt", None)
        or getattr(args, "results_dir_pos", None)
        or getattr(args, "results_dir", None)
    )
    if not rd:
        _log_fn(
            args,
            "ERROR",
            "results_dir not provided. Use positional 'results_dir' or --results-dir <path>.",
        )
        return 2

    results_dir = Path(rd)
    out_dir = Path(args.out) if args.out else results_dir / "summaries"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Set profiling environment
    prev_profile = os.getenv("JMO_PROFILE")
    if args.profile:
        os.environ["JMO_PROFILE"] = "1"

    prev_threads = os.getenv("JMO_THREADS")
    if args.threads is not None:
        os.environ["JMO_THREADS"] = str(max(1, args.threads))
    elif prev_threads is None and getattr(cfg, "threads", None) is not None:
        os.environ["JMO_THREADS"] = str(max(1, int(getattr(cfg, "threads"))))

    # Gather and process findings
    start = time.perf_counter()
    findings = gather_results(results_dir)
    elapsed = time.perf_counter() - start

    # Apply suppressions
    sup_file = (
        (results_dir / "jmo.suppress.yml")
        if (results_dir / "jmo.suppress.yml").exists()
        else (Path.cwd() / "jmo.suppress.yml")
    )
    suppressions = load_suppressions(str(sup_file) if sup_file.exists() else None)
    suppressed_ids = []
    if suppressions:
        before = {f.get("id") for f in findings}
        findings = filter_suppressed(findings, suppressions)
        after = {f.get("id") for f in findings}
        suppressed_ids = list(before - after)

    # Write reports
    if "json" in cfg.outputs:
        write_json(findings, out_dir / "findings.json")
    if "md" in cfg.outputs:
        write_markdown(findings, out_dir / "SUMMARY.md")
    if "yaml" in cfg.outputs:
        try:
            write_yaml(findings, out_dir / "findings.yaml")
        except RuntimeError as e:
            _log_fn(args, "DEBUG", f"YAML reporter unavailable: {e}")
    if "html" in cfg.outputs:
        write_html(findings, out_dir / "dashboard.html")
    if "sarif" in cfg.outputs:
        write_sarif(findings, out_dir / "findings.sarif")
    if suppressions:
        write_suppression_report(
            [str(x) for x in suppressed_ids], suppressions, out_dir / "SUPPRESSIONS.md"
        )

    # Write compliance framework reports (v1.2.0)
    try:
        write_compliance_summary(findings, out_dir / "COMPLIANCE_SUMMARY.md")
        write_pci_dss_report(findings, out_dir / "PCI_DSS_COMPLIANCE.md")
        write_attack_navigator_json(findings, out_dir / "attack-navigator.json")
    except (OSError, PermissionError) as e:
        _log_fn(args, "DEBUG", f"Failed to write compliance reports: {e}")
        logger.debug(f"Compliance report write failed: {e}")
    except (KeyError, ValueError, TypeError) as e:
        _log_fn(args, "DEBUG", f"Failed to write compliance reports: {e}")
        logger.debug(f"Compliance data formatting error: {e}")

    # Write profiling data
    if args.profile:
        try:
            cpu = os.cpu_count() or cfg.profiling_default_threads
            rec_threads = max(
                cfg.profiling_min_threads, min(cfg.profiling_max_threads, cpu)
            )
        except (OSError, RuntimeError, AttributeError) as e:
            _log_fn(
                args,
                "DEBUG",
                f"Failed to determine CPU count, using default threads: {e}",
            )
            logger.debug(f"CPU count detection error: {e}")
            rec_threads = cfg.profiling_default_threads

        job_timings = []
        meta = {}
        try:
            from scripts.core.normalize_and_report import PROFILE_TIMINGS

            job_timings = PROFILE_TIMINGS.get("jobs", [])
            meta = PROFILE_TIMINGS.get("meta", {})
        except (ImportError, AttributeError, KeyError) as e:
            _log_fn(args, "DEBUG", f"Profiling data unavailable: {e}")
            logger.debug(f"Profiling data access error: {e}")

        timings = {
            "aggregate_seconds": round(elapsed, 3),
            "recommended_threads": rec_threads,
            "jobs": job_timings,
            "meta": meta,
        }
        (out_dir / "timings.json").write_text(
            json.dumps(timings, indent=2), encoding="utf-8"
        )

    # Restore environment
    if prev_profile is not None:
        os.environ["JMO_PROFILE"] = prev_profile
    elif "JMO_PROFILE" in os.environ:
        del os.environ["JMO_PROFILE"]

    if prev_threads is not None:
        os.environ["JMO_THREADS"] = prev_threads
    elif "JMO_THREADS" in os.environ and args.threads is not None:
        del os.environ["JMO_THREADS"]

    # Calculate severity counts
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = f.get("severity")
        if s in counts:
            counts[s] += 1

    # Determine exit code
    threshold = args.fail_on if args.fail_on is not None else cfg.fail_on
    code = fail_code(threshold, counts)

    # Send report.generated telemetry event
    output_formats = []
    if getattr(args, "json", False) or "json" in cfg.outputs:
        output_formats.append("json")
    if getattr(args, "md", False) or "md" in cfg.outputs:
        output_formats.append("md")
    if getattr(args, "html", False) or "html" in cfg.outputs:
        output_formats.append("html")
    if getattr(args, "sarif", False) or "sarif" in cfg.outputs:
        output_formats.append("sarif")
    if getattr(args, "yaml", False) or "yaml" in cfg.outputs:
        output_formats.append("yaml")

    send_event(
        "report.generated",
        {
            "output_formats": output_formats,
            "findings_bucket": bucket_findings(len(findings)),
            "suppressions_used": sup_file is not None and sup_file.exists(),
            "compliance_enabled": True,  # Always enabled in v0.5.1+
        },
        {},
        version=__version__,
    )

    _log_fn(
        args,
        "INFO",
        f"Wrote reports to {out_dir} (threshold={threshold or 'none'}, exit={code})",
    )
    return code
