#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, Tuple
import os
import json
import datetime
import shutil
import subprocess
import time
import signal
import fnmatch
import tempfile

from scripts.core.normalize_and_report import gather_results
from scripts.core.reporters.basic_reporter import write_json, write_markdown
from scripts.core.reporters.yaml_reporter import write_yaml
from scripts.core.reporters.html_reporter import write_html
from scripts.core.reporters.sarif_reporter import write_sarif
from scripts.core.reporters.suppression_reporter import write_suppression_report
from scripts.core.config import load_config
from scripts.core.suppress import load_suppressions, filter_suppressed

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _log(args, level: str, message: str) -> None:
    """Logs messages based on configured log level and output format."""
    level = level.upper()
    cfg_level = None
    try:
        cfg = load_config(getattr(args, "config", None))
        cfg_level = getattr(cfg, "log_level", None)
    except Exception:
        # If config loading fails, default to INFO
        cfg_level = None

    cli_level = getattr(args, "log_level", None)
    effective_log_level = (cli_level or cfg_level or "INFO").upper()

    rank = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
    if rank.get(level, 20) < rank.get(effective_log_level, 20):
        return

    if getattr(args, "human_logs", False):
        color = {
            "DEBUG": "\x1b[36m",  # Cyan
            "INFO": "\x1b[32m",   # Green
            "WARN": "\x1b[33m",   # Yellow
            "ERROR": "\x1b[31m",  # Red
        }.get(level, "")
        reset = "\x1b[0m"
        ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
        sys.stderr.write(f"{color}{level:5}{reset} {ts} {message}\n")
    else:
        rec = {
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "level": level,
            "msg": message,
        }
        sys.stderr.write(json.dumps(rec) + "\n")


def _merge_dict(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Merges two dictionaries, with values from 'b' overriding 'a'."""
    out = dict(a) if a else {}
    if b:
        out.update(b)
    return out


def _effective_scan_settings(args) -> Dict[str, Any]:
    """Compute effective scan settings from CLI, config, and optional profile.

    Returns dict with keys: tools, threads, timeout, include, exclude, retries, per_tool
    """
    cfg = load_config(getattr(args, "config", None))
    profile_name = getattr(args, "profile_name", None) or cfg.default_profile
    profile = {}
    if profile_name and isinstance(cfg.profiles, dict):
        profile = cfg.profiles.get(profile_name, {}) or {}
    tools = getattr(args, "tools", None) or profile.get("tools") or cfg.tools
    threads = getattr(args, "threads", None) or profile.get("threads") or cfg.threads
    timeout = (
        getattr(args, "timeout", None) or profile.get("timeout") or cfg.timeout or 600
    )
    include = profile.get("include", cfg.include) or cfg.include
    exclude = profile.get("exclude", cfg.exclude) or cfg.exclude
    retries = cfg.retries
    if isinstance(profile.get("retries"), int):
        retries = profile["retries"]
    per_tool = _merge_dict(cfg.per_tool, profile.get("per_tool", {}))
    return {
        "tools": tools,
        "threads": threads,
        "timeout": timeout,
        "include": include,
        "exclude": exclude,
        "retries": max(0, int(retries or 0)),
        "per_tool": per_tool,
    }


def parse_args():
    """Parses command line arguments for jmo."""
    ap = argparse.ArgumentParser(prog="jmo")
    sub = ap.add_subparsers(dest="cmd")

    sp = sub.add_parser(
        "scan", help="Run configured tools on repos and write JSON outputs"
    )
    g = sp.add_mutually_exclusive_group(required=False)
    g.add_argument("--repo", help="Path to a single repository to scan")
    g.add_argument(
        "--repos-dir", help="Directory whose immediate subfolders are repos to scan"
    )
    g.add_argument("--targets", help="File listing repo paths (one per line)")
    sp.add_argument(
        "--results-dir",
        default="results",
        help="Base results directory (default: results)",
    )
    sp.add_argument(
        "--config", default="jmo.yml", help="Config file (default: jmo.yml)"
    )
    sp.add_argument("--tools", nargs="*", help="Override tools list from config")
    sp.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Per-tool timeout seconds (default: from config or 600)",
    )
    sp.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Concurrent repos to scan (default: auto)",
    )
    sp.add_argument(
        "--allow-missing-tools",
        action="store_true",
        help="If a tool is missing or fails, create empty JSON instead of failing",
    )
    sp.add_argument(
        "--profile-name",
        default=None,
        help="Optional profile name from config.profiles to apply for scanning",
    )
    sp.add_argument(
        "--log-level",
        default=None,
        help="Log level: DEBUG|INFO|WARN|ERROR (default: from config)",
    )
    sp.add_argument(
        "--human-logs",
        action="store_true",
        help="Emit human-friendly colored logs instead of JSON",
    )

    rp = sub.add_parser("report", help="Aggregate findings and emit reports")
    # Allow both positional and optional for results dir (backward compatible)
    rp.add_argument(
        "results_dir_pos",
        nargs="?",
        default=None,
        help="Directory with individual-repos/* tool outputs",
    )
    rp.add_argument(
        "--results-dir",
        dest="results_dir_opt",
        default=None,
        help="Directory with individual-repos/* tool outputs (optional form)",
    )
    rp.add_argument(
        "--out",
        default=None,
        help="Output directory (default: <results_dir>/summaries)",
    )
    rp.add_argument(
        "--config", default="jmo.yml", help="Config file (default: jmo.yml)"
    )
    rp.add_argument(
        "--fail-on", default=None, help="Severity threshold to exit non-zero"
    )
    rp.add_argument(
        "--profile",
        action="store_true",
        help="Collect per-tool timing and write timings.json",
    )
    rp.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Override worker threads for aggregation (default: auto)",
    )
    rp.add_argument(
        "--log-level", default=None, help="Log level: DEBUG|INFO|WARN|ERROR"
    )
    rp.add_argument(
        "--human-logs",
        action="store_true",
        help="Emit human-friendly colored logs instead of JSON",
    )
    # Accept --allow-missing-tools for symmetry with scan (no-op during report)
    rp.add_argument(
        "--allow-missing-tools",
        action="store_true",
        help="Accepted for compatibility; reporting tolerates missing tool outputs by default",
    )

    cp = sub.add_parser(
        "ci", help="Run scan then report with thresholds; convenient for CI"
    )
    cg = cp.add_mutually_exclusive_group(required=False)
    cg.add_argument("--repo", help="Path to a single repository to scan")
    cg.add_argument(
        "--repos-dir", help="Directory whose immediate subfolders are repos to scan"
    )
    cg.add_argument("--targets", help="File listing repo paths (one per line)")
    cp.add_argument(
        "--results-dir",
        default="results",
        help="Base results directory (default: results)",
    )
    cp.add_argument(
        "--config", default="jmo.yml", help="Config file (default: jmo.yml)"
    )
    cp.add_argument(
        "--tools", nargs="*", help="Override tools list from config (for scan)"
    )
    cp.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Per-tool timeout seconds (default: from config or 600)",
    )
    cp.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Concurrent repos to scan/aggregate (default: auto)",
    )
    cp.add_argument(
        "--allow-missing-tools",
        action="store_true",
        help="If a tool is missing, create empty JSON instead of failing",
    )
    cp.add_argument(
        "--profile-name",
        default=None,
        help="Optional profile name from config.profiles to apply for scanning",
    )
    cp.add_argument(
        "--fail-on",
        default=None,
        help="Severity threshold to exit non-zero (for report)",
    )
    cp.add_argument(
        "--profile", action="store_true", help="Collect timings.json during report"
    )
    cp.add_argument(
        "--log-level", default=None, help="Log level: DEBUG|INFO|WARN|ERROR"
    )
    cp.add_argument(
        "--human-logs",
        action="store_true",
        help="Emit human-friendly colored logs instead of JSON",
    )

    try:
        return ap.parse_args()
    except SystemExit:
        if os.getenv("PYTEST_CURRENT_TEST"):
            return argparse.Namespace()
        raise


def fail_code(threshold: str | None, counts: dict) -> int:
    """Determines exit code based on findings severity and threshold."""
    if not threshold:
        return 0
    thr = threshold.upper()
    if thr not in SEV_ORDER:
        return 0
    idx = SEV_ORDER.index(thr)
    severities = SEV_ORDER[: idx + 1]
    return 1 if any(counts.get(s, 0) > 0 for s in severities) else 0


def cmd_report(args) -> int:
    """Aggregates findings from scan results and emits various reports."""
    cfg = load_config(args.config)
    # Normalize results_dir from positional or optional
    rd = (
        getattr(args, "results_dir_opt", None)
        or getattr(args, "results_dir_pos", None)
        or getattr(args, "results_dir", None)
    )
    if not rd:
        _log(
            args,
            "ERROR",
            "results_dir not provided. Use positional 'results_dir' or --results-dir <path>.",
        )
        return 2
    results_dir = Path(rd)
    out_dir = Path(args.out) if args.out else results_dir / "summaries"
    out_dir.mkdir(parents=True, exist_ok=True)

    prev_profile = os.getenv("JMO_PROFILE")
    if args.profile:
        os.environ["JMO_PROFILE"] = "1"
    prev_threads = os.getenv("JMO_THREADS")
    if args.threads is not None:
        os.environ["JMO_THREADS"] = str(max(1, args.threads))
    elif prev_threads is None and getattr(cfg, "threads", None) is not None:
        os.environ["JMO_THREADS"] = str(max(1, int(getattr(cfg, "threads"))))
    
    start = time.perf_counter()
    findings = gather_results(results_dir)
    elapsed = time.perf_counter() - start
    
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

    if "json" in cfg.outputs:
        write_json(findings, out_dir / "findings.json")
    if "md" in cfg.outputs:
        write_markdown(findings, out_dir / "SUMMARY.md")
    if "yaml" in cfg.outputs:
        try:
            write_yaml(findings, out_dir / "findings.yaml")
        except RuntimeError as e:
            _log(args, "DEBUG", f"YAML reporter unavailable: {e}")
    if "html" in cfg.outputs:
        write_html(findings, out_dir / "dashboard.html")
    if "sarif" in cfg.outputs:
        write_sarif(findings, out_dir / "findings.sarif")
    if suppressions:
        write_suppression_report(
            [str(x) for x in suppressed_ids], suppressions, out_dir / "SUPPRESSIONS.md"
        )

    if args.profile:
        try:
            cpu = os.cpu_count() or cfg.profiling_default_threads
            rec_threads = max(
                cfg.profiling_min_threads, min(cfg.profiling_max_threads, cpu)
            )
        except Exception as e:
            _log(
                args,
                "DEBUG",
                f"Failed to determine CPU count for profiling, using default threads: {e}",
            )
            rec_threads = cfg.profiling_default_threads
        job_timings = []
        meta = {}
        try:
            from scripts.core.normalize_and_report import PROFILE_TIMINGS
            job_timings = PROFILE_TIMINGS.get("jobs", [])
            meta = PROFILE_TIMINGS.get("meta", {})
        except Exception as e:
            _log(args, "DEBUG", f"Profiling data unavailable: {e}")
        timings = {
            "aggregate_seconds": round(elapsed, 3),
            "recommended_threads": rec_threads,
            "jobs": job_timings,
            "meta": meta,
        }
        (out_dir / "timings.json").write_text(
            json.dumps(timings, indent=2), encoding="utf-8"
        )
    
    # Restore environment variables
    if prev_profile is not None:
        os.environ["JMO_PROFILE"] = prev_profile
    elif "JMO_PROFILE" in os.environ:
        del os.environ["JMO_PROFILE"]
    if prev_threads is not None:
        os.environ["JMO_THREADS"] = prev_threads
    elif "JMO_THREADS" in os.environ and args.threads is not None: # Only delete if it was set by this invocation
        del os.environ["JMO_THREADS"]

    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = f.get("severity")
        if s in counts:
            counts[s] += 1

    threshold = args.fail_on if args.fail_on is not None else cfg.fail_on
    code = fail_code(threshold, counts)
    _log(
        args,
        "INFO",
        f"Wrote reports to {out_dir} (threshold={threshold or 'none'}, exit={code})",
    )
    return code


def _iter_repos(args) -> list[Path]:
    """Iterates over repository paths based on CLI arguments."""
    repos: list[Path] = []
    if args.repo:
        p = Path(args.repo)
        if p.exists():
            repos.append(p)
        else:
            _log(args, "WARN", f"Repository path not found: {p}")
    elif args.repos_dir:
        base = Path(args.repos_dir)
        if base.exists():
            repos.extend([p for p in base.iterdir() if p.is_dir()])
        else:
            _log(args, "WARN", f"Repositories directory not found: {base}")
    elif args.targets:
        t = Path(args.targets)
        if t.exists():
            for line in t.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                p = Path(s)
                if p.exists():
                    repos.append(p)
                else:
                    _log(args, "WARN", f"Target repository path not found: {p} (from {t})")
        else:
            _log(args, "WARN", f"Targets file not found: {t}")
    return repos


def _tool_exists(args: Any, cmd: str) -> bool:
    """Checks if a command-line tool exists in the system's PATH."""
    exists = shutil.which(cmd) is not None
    if not exists:
        _log(args, "DEBUG", f"Tool '{cmd}' not found in PATH: {os.environ.get('PATH')}")
    return exists


def _write_stub(tool: str, out_path: Path) -> None:
    """Writes an empty JSON stub for a tool when it's skipped or fails but --allow-missing-tools is set."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stubs = {
        "gitleaks": [],
        "trufflehog": [],
        "semgrep": {"results": []},
        "noseyparker": {"matches": []},
        "syft": {"artifacts": []},
        "trivy": {"Results": []},
        "hadolint": [],
        "checkov": {"results": {"failed_checks": []}},
        "tfsec": {"results": []},
        "bandit": {"results": []},
        "osv-scanner": {"results": []},
    }
    payload = stubs.get(tool, {})
    out_path.write_text(json.dumps(payload), encoding="utf-8")


def _run_cmd(
    cmd: list[str],
    timeout: int,
    retries: int = 0,
    capture_stdout: bool = False,
    ok_rcs: Tuple[int, ...] | None = None,
) -> Tuple[int, str, str, int]:
    """Run a command with timeout and optional retries.

    Returns a tuple: (returncode, stdout, stderr, used_attempts).
    stdout is empty when capture_stdout=False. used_attempts is how many tries were made.
    """
    attempts = max(0, retries) + 1
    used_attempts = 0
    last_exc: Exception | None = None
    rc = 1 # Default return code for failure

    for i in range(attempts):
        used_attempts = i + 1
        try:
            # nosec B603: executing fixed CLI tools, no shell, args vetted
            cp = subprocess.run(
                cmd,
                stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            rc = cp.returncode
            success = (rc == 0) if ok_rcs is None else (rc in ok_rcs)
            if success or i == attempts - 1: # On success, or on last attempt (regardless of success)
                return (
                    rc,
                    (cp.stdout or "") if capture_stdout else "",
                    (cp.stderr or ""),
                    used_attempts,
                )
            time.sleep(min(1.0 * (i + 1), 3.0)) # Exponential backoff up to 3 seconds
            continue
        except subprocess.TimeoutExpired as e:
            last_exc = e
            rc = 124 # Common return code for timeout
        except Exception as e:
            last_exc = e
            rc = 1 # Generic error code
        
        # Only retry if not the last attempt
        if i < attempts - 1:
            time.sleep(min(1.0 * (i + 1), 3.0))
            continue
    
    # If all attempts failed, return the last known status
    return rc, "", str(last_exc or ""), used_attempts or 1


# Helper for noseyparker due to its complex local/docker fallback logic
def _run_noseyparker_logic(
    args: Any, repo: Path, out_path: Path, timeout: int, retries: int, local_tool_exists: bool, tool_flags: list[str]
) -> tuple[bool, int]:
    """Handles running Nosey Parker, including local binary and Docker fallback."""
    np_ok = False
    attempts_total = 0

    def _run_np_local_impl() -> tuple[bool, int]:
        _log(args, "DEBUG", f"Attempting noseyparker local run for {repo.name}")
        attempts = 0
        ds_dir = Path(tempfile.mkdtemp(prefix="np-"))
        ds = ds_dir / "datastore.sqlite"
        try:
            # Scan phase
            # nosec B603: executing fixed CLI tool, no shell, args vetted
            rc1, _, err1, used1 = _run_cmd(
                ["noseyparker", "scan", "--datastore", str(ds), *tool_flags, str(repo)],
                timeout, retries=retries, ok_rcs=(0,),
            )
            attempts += used1 or 0
            if rc1 != 0:
                _log(args, "DEBUG", f"noseyparker local scan failed rc={rc1} repo={repo.name} err={err1.strip()}")
                return False, attempts

            # Report phase
            # nosec B603: executing fixed CLI tool, no shell, args vetted
            rc2, out_s, err2, used2 = _run_cmd(
                ["noseyparker", "report", "--datastore", str(ds), "--format", "json"],
                timeout, retries=retries, capture_stdout=True, ok_rcs=(0,),
            )
            attempts += used2 or 0
            if rc2 == 0:
                try:
                    out_path.write_text(out_s, encoding="utf-8")
                except Exception as e:
                    _log(args, "DEBUG", f"Failed to write noseyparker output for {repo.name}: {e}")
                return True, attempts
            else:
                _log(args, "DEBUG", f"noseyparker local report failed rc={rc2} repo={repo.name} err={err2.strip()}")
            return False, attempts
        except Exception as e:
            _log(args, "DEBUG", f"noseyparker local run error for {repo.name}: {e}")
            return False, attempts or 1
        finally:
            try:
                shutil.rmtree(ds_dir, ignore_errors=True)
            except Exception as cleanup_error:
                _log(args, "DEBUG", f"Failed to clean up Nosey Parker datastore for {repo.name}: {cleanup_error}")

    def _run_np_docker_impl() -> tuple[bool, int]:
        _log(args, "DEBUG", f"Attempting noseyparker docker fallback for {repo.name}")
        try:
            runner = (
                Path(__file__).resolve().parent.parent
                / "core"
                / "run_noseyparker_docker.sh"
            )
            if not runner.exists():
                _log(args, "DEBUG", f"Nosey Parker docker runner not found at {runner}")
                return False, 0
            # Check for 'docker' binary using _tool_exists
            if not _tool_exists(args, "docker"):
                _log(args, "DEBUG", "docker not available in PATH; cannot fallback to container for noseyparker")
                return False, 0
            
            # Note: current run_noseyparker_docker.sh does not support passing tool_flags
            # If it did, 'cmd' would need to be updated.
            cmd = ["bash", str(runner), "--repo", str(repo), "--out", str(out_path)]
            # nosec B603: executing fixed CLI tool, no shell, args vetted
            rc, _, err, used = _run_cmd(cmd, timeout, retries=retries, ok_rcs=(0,))
            if rc != 0:
                _log(args, "DEBUG", f"noseyparker docker fallback failed rc={rc} repo={repo.name} err={err.strip()}")
            return (rc == 0), (used or 0)
        except Exception as e:
            _log(args, "DEBUG", f"noseyparker docker fallback error for {repo.name}: {e}")
            return False, 1

    if local_tool_exists:
        np_ok, attempts_total = _run_np_local_impl()
        if not np_ok:
            _log(args, "DEBUG", f"noseyparker local run failed for {repo.name}; attempting docker fallback…")
            docker_ok, docker_attempts = _run_np_docker_impl()
            attempts_total += docker_attempts
            np_ok = docker_ok
    else:
        _log(args, "DEBUG", f"noseyparker local binary not found for {repo.name}; attempting docker fallback…")
        np_ok, attempts_total = _run_np_docker_impl()
    
    return np_ok, max(1, attempts_total) # Ensure at least 1 attempt is counted if any execution occurred


def cmd_scan(args) -> int:
    """Orchestrates scanning multiple repositories with configured tools."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Effective settings with profile/per-tool
    eff = _effective_scan_settings(args)
    cfg = load_config(args.config)
    tools = eff["tools"]
    results_dir = Path(args.results_dir)
    indiv_base = results_dir / "individual-repos"
    indiv_base.mkdir(parents=True, exist_ok=True)
    repos = _iter_repos(args)
    if eff["include"]:
        repos = [
            r
            for r in repos
            if any(fnmatch.fnmatch(r.name, pat) for pat in eff["include"])
        ]
    if eff["exclude"]:
        repos = [
            r
            for r in repos
            if not any(fnmatch.fnmatch(r.name, pat) for pat in eff["exclude"])
        ]
    if not repos:
        _log(args, "WARN", "No repositories to scan.")
        return 0

    max_workers = None
    if eff["threads"]:
        max_workers = max(1, int(eff["threads"]))
    elif os.getenv("JMO_THREADS"):
        try:
            max_workers = max(1, int(os.getenv("JMO_THREADS") or "0"))
        except ValueError: # Catch cases where JMO_THREADS is not an int
            _log(args, "DEBUG", f"Invalid JMO_THREADS environment variable: {os.getenv('JMO_THREADS')}")
            max_workers = None
    elif cfg.threads:
        max_workers = max(1, int(cfg.threads))

    timeout = int(eff["timeout"] or 600)
    retries = int(eff["retries"] or 0)

    stop_flag = {"stop": False}

    def _handle_stop(signum, frame):
        stop_flag["stop"] = True
        _log(
            args,
            "WARN",
            f"Received signal {signum}; finishing current tasks then stopping...",
        )

    try:
        signal.signal(signal.SIGINT, _handle_stop)
        signal.signal(signal.SIGTERM, _handle_stop)
    except Exception as e:
        _log(args, "DEBUG", f"Unable to set signal handlers: {e}")

    def job(repo: Path) -> tuple[str, dict[str, Any]]:
        """Worker function to scan a single repository with all configured tools."""
        statuses: dict[str, bool] = {}
        attempts_map: dict[str, int] = {}
        name = repo.name
        out_dir = indiv_base / name
        out_dir.mkdir(parents=True, exist_ok=True)
        to = timeout # Base timeout
        pt = eff["per_tool"] if isinstance(eff.get("per_tool"), dict) else {}

        _log(args, "DEBUG", f"Worker for repo {name}: PATH={os.environ.get('PATH')}")

        def t_override(tool: str, default: int) -> int:
            """Gets per-tool timeout override, otherwise uses default."""
            v = (
                pt.get(tool, {}).get("timeout")
                if isinstance(pt.get(tool, {}), dict)
                else None
            )
            if isinstance(v, int) and v > 0:
                return v
            return default

        # Dictionary to hold tool-specific command logic and metadata
        tool_runners = {
            "gitleaks": {
                "cmd_func": lambda repo_path, out_path, flags: [
                    "gitleaks", "detect", "--source", repo_path, "--report-format", "json",
                    "--report-path", out_path, "--verbose", *flags
                ],
                "ok_rcs": (0, 1), "capture_stdout": False,
            },
            "trufflehog": {
                "cmd_func": lambda repo_path, out_path, flags: [
                    "trufflehog", "git", f"file://{repo_path}", "--json", "--no-update", *flags
                ],
                "ok_rcs": (0, 1), "capture_stdout": True,
            },
            "semgrep": {
                "cmd_func": lambda repo_path, out_path, flags: [
                    "semgrep", "--config=auto", "--json", "--output", out_path, *flags, repo_path
                ],
                "ok_rcs": (0, 1, 2), "capture_stdout": False,
            },
            # noseyparker will use _run_noseyparker_logic directly
            "syft": {
                "cmd_func": lambda repo_path, out_path, flags: [
                    "syft", repo_path, "-o", "json", *flags
                ],
                "ok_rcs": (0,), "capture_stdout": True,
            },
            "trivy": {
                "cmd_func": lambda repo_path, out_path, flags: [
                    "trivy", "fs", "-q", "-f", "json", "--scanners", "vuln,secret,misconfig", *flags, repo_path, "-o", out_path
                ],
                "ok_rcs": (0, 1), "capture_stdout": False,
            },
            "hadolint": {
                "cmd_func": lambda repo_path, out_path, flags: [
                    "hadolint", "-f", "json", *flags, str(Path(repo_path) / "Dockerfile")
                ],
                "pre_check": lambda repo_path: Path(repo_path) / "Dockerfile", # Returns Path object to check existence
                "ok_rcs": (0, 1), "capture_stdout": True,
            },
            "checkov": {
                "cmd_func": lambda repo_path, out_path, flags: [
                    "checkov", "-d", repo_path, "-o", "json", *flags
                ],
                "ok_rcs": (0, 1), "capture_stdout": True,
            },
            "bandit": {
                "cmd_func": lambda repo_path, out_path, flags: [
                    "bandit", "-q", "-r", repo_path, "-f", "json", *flags
                ],
                "ok_rcs": (0, 1), "capture_stdout": True,
            },
            "tfsec": {
                "cmd_func": lambda repo_path, out_path, flags: [
                    "tfsec", repo_path, "--format", "json", *flags
                ],
                "ok_rcs": (0, 1), "capture_stdout": True,
            },
            "osv-scanner": {
                "cmd_func": lambda repo_path, out_path, flags: [
                    "osv-scanner", "--format", "json", "--output", out_path, *flags, repo_path
                ],
                "ok_rcs": (0, 1), "capture_stdout": False,
            },
        }

        for tool_name in tools:
            if stop_flag["stop"]:
                break # Stop processing tools for this repo if global stop is requested

            tool_config = tool_runners.get(tool_name)
            if not tool_config:
                _log(args, "WARN", f"Unknown tool '{tool_name}' configured in jmo.yml. Skipping.")
                continue

            out = out_dir / f"{tool_name}.json"
            tool_flags = (
                pt.get(tool_name, {}).get("flags", [])
                if isinstance(pt.get(tool_name, {}), dict)
                else []
            )
            
            current_timeout = t_override(tool_name, to)
            tool_ok = False
            used_attempts = 0
            
            # --- Specific logic for Nosey Parker ---
            if tool_name == "noseyparker":
                tool_ok, used_attempts = _run_noseyparker_logic(
                    args, repo, out, current_timeout, retries, _tool_exists(args, tool_name), tool_flags
                )
            # --- Generic logic for other tools ---
            else:
                # 1. Pre-check for specific tools (e.g., Dockerfile for Hadolint)
                pre_check_met = True
                if "pre_check" in tool_config:
                    pre_check_target_path = tool_config["pre_check"](str(repo))
                    if not pre_check_target_path.exists():
                        _log(
                            args,
                            "WARN",
                            f"Tool '{tool_name}' configured, but required file '{pre_check_target_path.name}' not found for repo {name}. Skipping tool execution.",
                        )
                        pre_check_met = False
                
                if not pre_check_met:
                    tool_ok = False # Tool was not run due to missing dependency
                elif not _tool_exists(args, tool_name):
                    # _tool_exists already logs a DEBUG message if not found
                    _log(
                        args,
                        "WARN",
                        f"Tool '{tool_name}' not found in PATH for repo {name}. Skipping tool execution.",
                    )
                    tool_ok = False
                else:
                    # Execute the tool
                    cmd = tool_config["cmd_func"](str(repo), str(out), tool_flags)
                    rc, out_s, _, used = _run_cmd(
                        cmd,
                        current_timeout,
                        retries=retries,
                        capture_stdout=tool_config["capture_stdout"],
                        ok_rcs=tool_config["ok_rcs"],
                    )
                    used_attempts = used
                    
                    if tool_config["capture_stdout"] and out_s:
                        try:
                            out.write_text(out_s, encoding="utf-8")
                        except Exception as e:
                            _log(args, "DEBUG", f"Failed to write {tool_name} output for {name}: {e}")

                    # Determine success: RC must be OK, AND the output file must exist
                    is_rc_ok = (rc in tool_config["ok_rcs"])
                    output_file_exists = out.exists()
                    
                    tool_ok = is_rc_ok and output_file_exists
                    
                    if not tool_ok: # If execution failed (non-OK RC, or output file missing)
                        _log(
                            args,
                            "WARN",
                            f"Tool '{tool_name}' execution failed for repo {name} (RC={rc}, output_exists={output_file_exists}). Attempts: {used_attempts}.",
                        )
            
            # --- Universal handling after execution or skip attempt ---
            if tool_ok:
                statuses[tool_name] = True
                if used_attempts: attempts_map[tool_name] = used_attempts
            else:
                if args.allow_missing_tools:
                    _write_stub(tool_name, out)
                    statuses[tool_name] = True
                    log_msg = f"Tool '{tool_name}' skipped/failed for repo {name}, but --allow-missing-tools is set. Stub created."
                    if used_attempts: log_msg += f" Attempts: {used_attempts}."
                    _log(args, "WARN", log_msg)
                    if used_attempts: attempts_map[tool_name] = used_attempts
                else:
                    statuses[tool_name] = False
                    log_msg = f"Tool '{tool_name}' skipped/failed for repo {name} and --allow-missing-tools is not set. Skipping."
                    if used_attempts: log_msg += f" Attempts: {used_attempts}."
                    _log(args, "WARN", log_msg)
                    if used_attempts: attempts_map[tool_name] = used_attempts

        if attempts_map:
            statuses["__attempts__"] = attempts_map  # type: ignore
        return name, statuses

    futures = []
    with ThreadPoolExecutor(max_workers=max_workers or None) as ex:
        for repo in repos:
            if stop_flag["stop"]:
                _log(args, "INFO", "Stopping repository scanning due to interrupt signal.")
                break
            futures.append(ex.submit(job, repo))
        
        # This loop waits for all futures to complete or for an interrupt.
        # It also handles logging of results.
        for fut in as_completed(futures):
            try:
                name, statuses = fut.result()
                attempts_map: dict[str, int] = {}
                if isinstance(statuses, dict) and "__attempts__" in statuses:
                    popped_value = statuses.pop("__attempts__")
                    if isinstance(popped_value, dict):
                        attempts_map = popped_value
                ok = all(v for k, v in statuses.items()) if statuses else True
                extra = (
                    f" attempts={attempts_map}"
                    if any(
                        (attempts_map or {}).get(t, 1) > 1 for t in (attempts_map or {})
                    )
                    else ""
                )
                _log(
                    args,
                    "INFO" if ok else "WARN",
                    f"scanned {name}: {'ok' if ok else 'issues'} {statuses}{extra}",
                )
            except Exception as e:
                _log(args, "ERROR", f"scan error processing a repository: {e}")
    return 0


def cmd_ci(args) -> int:
    """Convenience command to run scan then report, suitable for CI pipelines."""
    # Create a Namespace-like object for cmd_scan
    class ScanArgs:
        def __init__(self, a):
            self.repo = getattr(a, "repo", None)
            self.repos_dir = getattr(a, "repos_dir", None)
            self.targets = getattr(a, "targets", None)
            self.results_dir = getattr(a, "results_dir", "results")
            self.config = getattr(a, "config", "jmo.yml")
            self.tools = getattr(a, "tools", None)
            self.timeout = getattr(a, "timeout", 600)
            self.threads = getattr(a, "threads", None)
            self.allow_missing_tools = getattr(a, "allow_missing_tools", False)
            self.profile_name = getattr(a, "profile_name", None)
            self.log_level = getattr(a, "log_level", None)
            self.human_logs = getattr(a, "human_logs", False)

    scan_rc = cmd_scan(ScanArgs(args))
    if scan_rc != 0:
        _log(args, "ERROR", f"Scan command failed with exit code {scan_rc}. Aborting CI command.")
        return scan_rc

    # Create a Namespace-like object for cmd_report
    class ReportArgs:
        def __init__(self, a):
            rd = str(Path(getattr(a, "results_dir", "results")))
            # Set all possible fields that cmd_report normalizes
            self.results_dir = rd
            self.results_dir_pos = rd
            self.results_dir_opt = rd
            self.out = None
            self.config = getattr(a, "config", "jmo.yml")
            self.fail_on = getattr(a, "fail_on", None)
            self.profile = getattr(a, "profile", False)
            self.threads = getattr(a, "threads", None)
            self.log_level = getattr(a, "log_level", None)
            self.human_logs = getattr(a, "human_logs", False)
            self.allow_missing_tools = getattr(a, "allow_missing_tools", False) # For symmetry, though no-op

    rc_report = cmd_report(ReportArgs(args))
    return rc_report


def main():
    """Main entry point for the jmo CLI."""
    args = parse_args()
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "ci":
        return cmd_ci(args)
    
    _log(args, "ERROR", "No command specified. Use 'scan', 'report', or 'ci'.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())