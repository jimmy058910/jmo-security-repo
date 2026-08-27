#!/usr/bin/env python3
"""Report orchestration logic for JMo Security."""

from __future__ import annotations

import json
import logging
import os
import time
import traceback
from pathlib import Path

from scripts.core.config import load_config_with_env_overrides
from scripts.core.exceptions import OPANotFoundException
from scripts.core.normalize_and_report import collect_tool_diagnostics, gather_results
from scripts.core.reporters.basic_reporter import write_json, write_markdown
from scripts.core.reporters.compliance_reporter import (
    write_attack_navigator_json,
    write_compliance_summary,
    write_pci_dss_report,
)
from scripts.core.reporters.csv_reporter import write_csv
from scripts.core.reporters.html_reporter import write_html
from scripts.core.reporters.sarif_reporter import write_sarif
from scripts.core.reporters.simple_html_reporter import write_simple_html
from scripts.core.reporters.suppression_reporter import write_suppression_report
from scripts.core.reporters.yaml_reporter import write_yaml
from scripts.core.suppress import (
    SuppressionSummary,
    filter_suppressed_with_summary,
    load_suppressions,
)
from scripts.core.tool_diagnostics import summarize

logger = logging.getLogger(__name__)

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Every value `outputs:` accepts. Each one gates exactly one writer below.
#
# A name outside this set used to be discarded in silence: `outputs: [sarrif]`
# or `outputs: [SARIF]` produced no SARIF file and no log record at any level,
# so a typo in jmo.yml looked identical to a working config that happened to
# emit fewer artifacts.
KNOWN_OUTPUTS = (
    "json",
    "md",
    "yaml",
    "html",
    "simple-html",
    "sarif",
    "csv",
    # Added under #867. These artifacts were written unconditionally, outside
    # any gate, so `outputs: []` -- an explicit request for no output formats --
    # still produced four files. Both default to ON, so a config that does not
    # mention them is unchanged.
    "compliance",
    "suppressions",
)


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


def _warn_unknown_outputs(cfg, args, _log_fn) -> list[str]:
    """Report any `outputs:` value that gates no writer.

    Returns the unknown names, in config order, so callers can assert on them.
    """
    outputs = getattr(cfg, "outputs", None) or []
    unknown = [str(o) for o in outputs if str(o) not in KNOWN_OUTPUTS]
    for name in unknown:
        _log_fn(
            args,
            "WARN",
            f"Unknown output format {name!r} in config 'outputs'; "
            f"no such report will be written. Valid formats: "
            f"{', '.join(KNOWN_OUTPUTS)}",
        )
        # `_log_fn` writes straight to stderr and `logger` is separately wired
        # to it, so a WARNING on both paths prints the same line twice. The
        # user-facing record is `_log_fn`; keep the module logger at DEBUG.
        logger.debug("Unknown output format %r in config 'outputs'", name)
    return unknown


def _warn_unknown_threshold(threshold, args, _log_fn) -> str | None:
    """Report a `--fail-on` / `fail_on:` value that gates nothing.

    Returns the unrecognised value, so callers can assert on it.

    `fail_code` returns 0 for any threshold outside SEV_ORDER, which is the
    same exit code as "nothing at or above the threshold". A typo therefore
    turns the CI gate off and looks exactly like a clean run: `--fail-on HIGHH`
    exited 0 on a scan holding HIGH findings, and the only record at any level
    was the summary line reporting `threshold=HIGHH` as though it had applied.
    """
    if not threshold:
        return None
    if str(threshold).upper() in SEV_ORDER:
        return None
    bad = str(threshold)
    _log_fn(
        args,
        "WARN",
        f"Unrecognized severity threshold {bad!r}; no threshold applied and "
        f"the run cannot fail on findings. Valid values: "
        f"{', '.join(SEV_ORDER)}",
    )
    # Same two-systems rule as `_warn_unknown_outputs` above: `_log_fn` carries
    # the user-facing record, the module logger stays at DEBUG so the line is
    # not printed twice.
    logger.debug("Unrecognized severity threshold %r", bad)
    return bad


def cmd_report(args, _log_fn) -> int:
    """Run report command: aggregate findings and generate outputs.

    Args:
        args: Parsed CLI arguments with results_dir, config, fail_on, etc.
        _log_fn: Logging function (args, level, message) -> None

    Returns:
        Exit code (0 for success, 1 if threshold exceeded, 2 for errors)
    """
    cfg = load_config_with_env_overrides(args.config)

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

    _warn_unknown_outputs(cfg, args, _log_fn)

    # Set profiling environment
    prev_profile = os.getenv("JMO_PROFILE")
    if args.profile:
        os.environ["JMO_PROFILE"] = "1"

    prev_threads = os.getenv("JMO_THREADS")
    if args.threads is not None:
        os.environ["JMO_THREADS"] = str(max(1, args.threads))
    elif prev_threads is None and isinstance(cfg.threads, int):
        # cfg.threads is `int | str | None` — the str case is the literal
        # "auto", which means auto-detect. Leaving JMO_THREADS unset is
        # exactly that, and avoids int("auto") raising ValueError.
        os.environ["JMO_THREADS"] = str(max(1, cfg.threads))

    # Gather and process findings
    start = time.perf_counter()
    findings = gather_results(results_dir)
    elapsed = time.perf_counter() - start

    # Files the tools said they could not analyse (#837). WARNING, not INFO:
    # `configure_scan_logging` sets the `scripts` logger to WARNING for a normal
    # run, so anything quieter is invisible exactly when it matters. It cannot
    # become the always-fires warning #784 removed, because a healthy scan
    # produces no diagnostics and this stays silent.
    diagnostics = collect_tool_diagnostics(results_dir)
    if diagnostics:
        logger.warning(
            "%s - they are NOT clean results, and any finding they contain is "
            "absent from this report: %s",
            summarize(diagnostics),
            "; ".join(sorted({d.render() for d in diagnostics})[:10]),
        )

    # Apply suppressions
    sup_file = (
        (results_dir / "jmo.suppress.yml")
        if (results_dir / "jmo.suppress.yml").exists()
        else (Path.cwd() / "jmo.suppress.yml")
    )
    suppressions = load_suppressions(str(sup_file) if sup_file.exists() else None)
    suppressed_ids: list[str] = []
    suppression_summary: SuppressionSummary | None = None
    if suppressions:
        findings, suppression_summary = filter_suppressed_with_summary(
            findings, suppressions
        )
        suppressed_ids = suppression_summary.suppressed_ids
        if suppression_summary.total_suppressed > 0:
            _log_fn(args, "INFO", suppression_summary.debt_label)

    # Generate metadata for v1.0.0 output format
    import uuid

    from scripts.core.reporters.basic_reporter import _generate_metadata

    # Collect scan metadata
    scan_id = str(uuid.uuid4())

    # Read profile from scan metadata if available (Bug #3 fix)
    scan_metadata_path = results_dir / ".scan_metadata.json"
    profile = ""
    tools_from_scan: list[str] = []
    if scan_metadata_path.exists():
        try:
            scan_meta = json.loads(scan_metadata_path.read_text(encoding="utf-8"))
            profile = scan_meta.get("profile", "")
            tools_from_scan = scan_meta.get("tools", [])
        except (json.JSONDecodeError, OSError):
            pass
    if not profile:
        profile = getattr(cfg, "default_profile", "") or ""

    # Use tools from scan metadata if available, else infer from findings (Bug #5 fix)
    tools_used: list[str] = tools_from_scan.copy() if tools_from_scan else []
    if not tools_used:
        # Fallback: infer tools from findings
        for f in findings:
            tool_name = f.get("tool", {}).get("name", "")
            if tool_name and tool_name not in tools_used:
                tools_used.append(tool_name)

    # Count targets scanned
    target_count = 0
    for target_dir_name in [
        "individual-repos",
        "individual-images",
        "individual-iac",
        "individual-web",
        "individual-gitlab",
        "individual-k8s",
    ]:
        target_dir = results_dir / target_dir_name
        if target_dir.exists():
            target_count += sum(1 for p in target_dir.iterdir() if p.is_dir())

    metadata = _generate_metadata(
        findings,
        scan_id=scan_id,
        profile=profile,
        tools=sorted(tools_used),
        target_count=target_count,
    )

    # Write reports (v1.0.0: with metadata wrapper)
    if "json" in cfg.outputs:
        write_json(findings, out_dir / "findings.json", metadata=metadata)
    if "md" in cfg.outputs:
        write_markdown(
            findings,
            out_dir / "SUMMARY.md",
            unanalysed=[(d.tool, d.path, d.reason) for d in diagnostics],
        )
    if "yaml" in cfg.outputs:
        try:
            write_yaml(findings, out_dir / "findings.yaml", metadata=metadata)
        except RuntimeError as e:
            # The config asked for this artifact and it will not exist. At
            # DEBUG that was invisible in a normal run, so findings.yaml simply
            # went missing from a report the user had configured.
            _log_fn(
                args,
                "WARN",
                f"findings.yaml was requested in 'outputs' but was not written: {e}",
            )
            logger.debug("YAML reporter unavailable: %s", e)
    if "html" in cfg.outputs:
        write_html(findings, out_dir / "dashboard.html")
    if "simple-html" in cfg.outputs:
        write_simple_html(findings, out_dir / "simple-report.html")
    if "sarif" in cfg.outputs:
        write_sarif(findings, out_dir / "findings.sarif")
    if "csv" in cfg.outputs:
        # Get CSV configuration from config
        csv_config = getattr(cfg, "csv", None)
        csv_columns = None
        if csv_config and isinstance(csv_config, dict):
            csv_columns = csv_config.get("columns")
        # Pass suppressions for triage status column (Feature #3)
        write_csv(
            findings,
            out_dir / "findings.csv",
            columns=csv_columns,
            suppressions=suppressions,
        )
    # Gated on `outputs` as well as on there being suppression rules at all.
    # Before chunk 8 `load_suppressions()` returned {} for the shipped
    # jmo.suppress.yml (#538), so this never fired; now that the shipped config
    # loads 11 usable rules, every user of it gets a SUPPRESSIONS.md -- often
    # one that says "No suppressions matched any findings." That was a new
    # artifact appearing as a side effect of an unrelated fix, with no key that
    # could turn it off (#867).
    if "suppressions" in cfg.outputs and suppressions:
        write_suppression_report(
            [str(x) for x in suppressed_ids],
            suppressions,
            out_dir / "SUPPRESSIONS.md",
            summary=suppression_summary,
        )

    # Write compliance framework reports (v1.2.0)
    try:
        if "compliance" in cfg.outputs:
            write_compliance_summary(findings, out_dir / "COMPLIANCE_SUMMARY.md")
            write_pci_dss_report(findings, out_dir / "PCI_DSS_COMPLIANCE.md")
            write_attack_navigator_json(findings, out_dir / "attack-navigator.json")
    except (OSError, PermissionError) as e:
        # DEBUG hid this entirely: all three compliance artifacts could vanish
        # from a report with no record at any level a normal run displays.
        _log_fn(args, "WARN", f"Failed to write compliance reports: {e}")
        logger.debug("Compliance report write failed: %s", e)
    except (KeyError, ValueError, TypeError) as e:
        _log_fn(args, "WARN", f"Failed to write compliance reports: {e}")
        logger.debug("Compliance data formatting error: %s", e)

    # Evaluate and write policy reports (v1.0.0 Feature #5: Policy-as-Code)
    # Determine policies to evaluate using configuration precedence:
    # 1. CLI arguments (highest priority)
    # 2. Environment variables (already loaded via load_config_with_env_overrides)
    # 3. Config file (jmo.yml)
    # 4. Skip if disabled
    policy_names = []
    policy_exit_code = 0

    # 1. CLI arguments (highest priority)
    if hasattr(args, "policies") and args.policies:
        policy_names = args.policies
        _log_fn(args, "INFO", f"Using policies from CLI: {', '.join(policy_names)}")
    # 2. Config (includes env vars via load_config_with_env_overrides)
    elif (
        cfg.policy.enabled and cfg.policy.auto_evaluate and cfg.policy.default_policies
    ):
        policy_names = cfg.policy.default_policies
        _log_fn(args, "INFO", f"Using policies from config: {', '.join(policy_names)}")
    # 3. Skip if disabled
    elif not cfg.policy.enabled:
        _log_fn(args, "DEBUG", "Policy evaluation disabled via config")

    if policy_names:
        try:
            from scripts.core.reporters.policy_reporter import (
                evaluate_policies,
                write_policy_json,
                write_policy_report,
                write_policy_summary_md,
            )

            builtin_dir = Path(__file__).parent.parent.parent / "policies" / "builtin"
            user_dir = Path.home() / ".jmo" / "policies"

            _log_fn(
                args,
                "INFO",
                f"Evaluating {len(policy_names)} policies: {', '.join(policy_names)}",
            )

            policy_results = evaluate_policies(
                findings, policy_names, builtin_dir, user_dir
            )

            if policy_results:
                write_policy_report(policy_results, out_dir / "POLICY_REPORT.md")
                write_policy_json(policy_results, out_dir / "policy_results.json")
                write_policy_summary_md(policy_results, out_dir / "POLICY_SUMMARY.md")

                passed = sum(1 for r in policy_results.values() if r.passed)
                failed = len(policy_results) - passed

                _log_fn(
                    args,
                    "INFO",
                    f"Policy evaluation complete: {passed}/{len(policy_results)} passed, {failed} failed",
                )

                # Fail if violations and fail_on_violation=True (check both CLI and config)
                cli_fail_on_violation = getattr(args, "fail_on_policy_violation", False)
                if failed > 0 and (
                    cli_fail_on_violation or cfg.policy.fail_on_violation
                ):
                    _log_fn(
                        args,
                        "ERROR",
                        f"❌ {failed} policies FAILED. Exiting due to fail_on_violation=True",
                    )
                    policy_exit_code = 1

        except ImportError as e:
            _log_fn(args, "DEBUG", f"Policy reporter unavailable: {e}")
            logger.debug(f"Policy reporter import error: {e}")
        except (OSError, PermissionError) as e:
            _log_fn(args, "DEBUG", f"Failed to write policy reports: {e}")
            logger.debug(f"Policy report write failed: {e}")
        except OPANotFoundException as e:
            # OPA not installed - graceful degradation with warning (not error)
            _log_fn(args, "WARN", f"Policy evaluation skipped: {e}")
            logger.warning("Policy evaluation skipped: OPA not installed")
        except Exception as e:
            _log_fn(args, "ERROR", f"Policy evaluation failed: {e}")
            logger.error(f"Policy evaluation error: {e}", exc_info=True)
            cli_fail_on_violation = getattr(args, "fail_on_policy_violation", False)
            if cli_fail_on_violation or cfg.policy.fail_on_violation:
                policy_exit_code = 1

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
    counts = dict.fromkeys(SEV_ORDER, 0)
    for f in findings:
        s = f.get("severity")
        if s in counts:
            counts[s] += 1

    # Determine exit code
    threshold = args.fail_on if args.fail_on is not None else cfg.fail_on
    _warn_unknown_threshold(threshold, args, _log_fn)
    code = fail_code(threshold, counts)

    # The one-line summary is emitted AFTER the storage hook, at the bottom of
    # this function, so it can name the storage outcome and the exit code the
    # run actually returns. It used to be emitted here, which put it *above* the
    # store attempt: the only trace of a failed write was a single ERROR line in
    # a wall of scan output, and the line a user reads to find out how the run
    # went could not mention it (#801).

    # Auto-storage hook: Store scan in history database if requested.
    #
    # `history_db_path` and `store_error` are bound OUTSIDE the try so the
    # handler can name the database even when the failure happened before the
    # assignment, and so the exit-code check below is reachable on the path
    # where no store was attempted at all.
    store_error: Exception | None = None
    stored_ok = False
    _configured_db = getattr(args, "history_db", None)
    history_db_path = (
        Path(_configured_db) if _configured_db else Path(".jmo/history.db")
    )
    if getattr(args, "store_history", False):
        try:
            from scripts.core.history_db import store_scan as db_store_scan

            # Record what the scan actually did, not what the config asks for.
            # `profile` and `tools_used` were resolved above from
            # .scan_metadata.json (written by the scan) with a findings-derived
            # fallback, and `tools_used` is what findings.json's metadata
            # already reports. Reading cfg.tools here instead made every stored
            # row claim jmo.yml's top-level `tools:` list regardless of profile
            # -- 1790 of 1833 rows named the same 8 tools, including one that
            # was not installed and so cannot have run (#787).
            profile_name = getattr(args, "profile_name", None) or profile or "balanced"
            tools = sorted(tools_used)

            # Get security flags (Phase 6 Step 6.1, 6.2, 6.3)
            no_store_raw = getattr(args, "no_store_raw_findings", False)
            encrypt_findings = getattr(args, "encrypt_findings", False)
            collect_metadata = getattr(args, "collect_metadata", False)

            # Store scan in history database
            scan_id = db_store_scan(
                results_dir=results_dir,
                profile=profile_name,
                tools=tools,
                db_path=history_db_path,
                no_store_raw=no_store_raw,
                encrypt_findings=encrypt_findings,
                collect_metadata=collect_metadata,
            )

            stored_ok = True
            _log_fn(args, "INFO", f"Stored scan in history: {scan_id}")
            _log_fn(args, "INFO", f"Database: {history_db_path}")

        except Exception as e:
            # Reported at ERROR, naming the consequence rather than the call
            # that failed. History storage is on unless `--no-store-history`,
            # so this used to be a WARN that scrolled past mid-run followed by
            # a raw traceback -- and the exit code never saw it, so a scan
            # could report success having stored nothing (#903).
            store_error = e
            _log_fn(
                args,
                "ERROR",
                f"Scan results were NOT recorded in the history database "
                f"({history_db_path}): {e}. The scan completed and its reports "
                f"are valid, but `jmo history` will not show this run. "
                f"Re-record it with `jmo history store --results-dir "
                f"{results_dir}`, or pass --fail-on-store-error to make a "
                f"failed history write exit non-zero.",
            )
            # The traceback is a debugging detail, not a user-facing one: this
            # is a recoverable condition, and printing a stack trace into
            # normal scan output makes it read as a crash.
            _log_fn(args, "DEBUG", f"store_scan traceback: {traceback.format_exc()}")

    # Return non-zero if the severity threshold, a policy violation, or -- only
    # when explicitly asked -- a failed history write says so. Storage is on by
    # default, so failing without the flag would redden scans for users who
    # never asked for history and ran the scan for its findings (#903).
    store_exit_code = (
        1
        if store_error is not None and getattr(args, "fail_on_store_error", False)
        else 0
    )
    final_code = max(code, policy_exit_code, store_exit_code)

    # One line carrying every verdict the run produced. `history=` is here
    # because an ERROR scrolls past mid-scan while this line is what a user
    # actually goes looking for, and "the row was not written" is exactly the
    # kind of failure that otherwise reads as success (#801). `exit=` reports
    # what the process returns rather than the severity verdict alone -- with
    # --fail-on-store-error the two differ, and the old line printed the
    # severity code while the function returned something else.
    if not getattr(args, "store_history", False):
        history_state = "off"
    elif stored_ok:
        history_state = "stored"
    else:
        history_state = "NOT STORED"
    _log_fn(
        args,
        "INFO",
        f"Wrote reports to {out_dir} (threshold={threshold or 'none'}, "
        f"exit={final_code}, history={history_state})",
    )

    return final_code
