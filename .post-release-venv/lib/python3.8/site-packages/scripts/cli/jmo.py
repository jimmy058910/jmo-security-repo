#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

from scripts.core.normalize_and_report import gather_results
from scripts.core.reporters.basic_reporter import write_json, write_markdown
from scripts.core.reporters.yaml_reporter import write_yaml
from scripts.core.reporters.html_reporter import write_html
from scripts.core.reporters.sarif_reporter import write_sarif
from scripts.core.reporters.suppression_reporter import write_suppression_report
from scripts.core.config import load_config
from scripts.core.suppress import load_suppressions, filter_suppressed

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _merge_dict(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(a) if a else {}
    if b:
        out.update(b)
    return out


def _effective_scan_settings(args) -> Dict[str, Any]:
    """Compute effective scan settings from CLI, config, and optional profile.

    Returns dict with keys: tools, threads, timeout, include, exclude, retries, per_tool
    """
    cfg = load_config(getattr(args, 'config', None))
    profile_name = getattr(args, 'profile_name', None) or cfg.default_profile
    profile = {}
    if profile_name and isinstance(cfg.profiles, dict):
        profile = cfg.profiles.get(profile_name, {}) or {}
    tools = getattr(args, 'tools', None) or profile.get('tools') or cfg.tools
    threads = getattr(args, 'threads', None) or profile.get('threads') or cfg.threads
    timeout = getattr(args, 'timeout', None) or profile.get('timeout') or cfg.timeout or 600
    include = profile.get('include', cfg.include) or cfg.include
    exclude = profile.get('exclude', cfg.exclude) or cfg.exclude
    retries = cfg.retries
    if isinstance(profile.get('retries'), int):
        retries = profile['retries']
    per_tool = _merge_dict(cfg.per_tool, profile.get('per_tool', {}))
    return {
        'tools': tools,
        'threads': threads,
        'timeout': timeout,
        'include': include,
        'exclude': exclude,
        'retries': max(0, int(retries or 0)),
        'per_tool': per_tool,
    }


def parse_args():
    ap = argparse.ArgumentParser(prog="jmo")
    sub = ap.add_subparsers(dest="cmd")

    sp = sub.add_parser("scan", help="Run configured tools on repos and write JSON outputs")
    g = sp.add_mutually_exclusive_group(required=False)
    g.add_argument("--repo", help="Path to a single repository to scan")
    g.add_argument("--repos-dir", help="Directory whose immediate subfolders are repos to scan")
    g.add_argument("--targets", help="File listing repo paths (one per line)")
    sp.add_argument("--results-dir", default="results", help="Base results directory (default: results)")
    sp.add_argument("--config", default="jmo.yml", help="Config file (default: jmo.yml)")
    sp.add_argument("--tools", nargs="*", help="Override tools list from config")
    sp.add_argument("--timeout", type=int, default=None, help="Per-tool timeout seconds (default: from config or 600)")
    sp.add_argument("--threads", type=int, default=None, help="Concurrent repos to scan (default: auto)")
    sp.add_argument("--allow-missing-tools", action="store_true", help="If a tool is missing, create empty JSON instead of failing")
    sp.add_argument("--profile-name", default=None, help="Optional profile name from config.profiles to apply for scanning")
    sp.add_argument("--log-level", default=None, help="Log level: DEBUG|INFO|WARN|ERROR (default: from config)")
    sp.add_argument("--human-logs", action="store_true", help="Emit human-friendly colored logs instead of JSON")

    rp = sub.add_parser("report", help="Aggregate findings and emit reports")
    # Allow both positional and optional for results dir (backward compatible)
    rp.add_argument("results_dir_pos", nargs="?", default=None, help="Directory with individual-repos/* tool outputs")
    rp.add_argument("--results-dir", dest="results_dir_opt", default=None, help="Directory with individual-repos/* tool outputs (optional form)")
    rp.add_argument("--out", default=None, help="Output directory (default: <results_dir>/summaries)")
    rp.add_argument("--config", default="jmo.yml", help="Config file (default: jmo.yml)")
    rp.add_argument("--fail-on", default=None, help="Severity threshold to exit non-zero")
    rp.add_argument("--profile", action="store_true", help="Collect per-tool timing and write timings.json")
    rp.add_argument("--threads", type=int, default=None, help="Override worker threads for aggregation (default: auto)")
    rp.add_argument("--log-level", default=None, help="Log level: DEBUG|INFO|WARN|ERROR")
    rp.add_argument("--human-logs", action="store_true", help="Emit human-friendly colored logs instead of JSON")
    # Accept --allow-missing-tools for symmetry with scan (no-op during report)
    rp.add_argument("--allow-missing-tools", action="store_true", help="Accepted for compatibility; reporting tolerates missing tool outputs by default")

    cp = sub.add_parser("ci", help="Run scan then report with thresholds; convenient for CI")
    cg = cp.add_mutually_exclusive_group(required=False)
    cg.add_argument("--repo", help="Path to a single repository to scan")
    cg.add_argument("--repos-dir", help="Directory whose immediate subfolders are repos to scan")
    cg.add_argument("--targets", help="File listing repo paths (one per line)")
    cp.add_argument("--results-dir", default="results", help="Base results directory (default: results)")
    cp.add_argument("--config", default="jmo.yml", help="Config file (default: jmo.yml)")
    cp.add_argument("--tools", nargs="*", help="Override tools list from config (for scan)")
    cp.add_argument("--timeout", type=int, default=None, help="Per-tool timeout seconds (default: from config or 600)")
    cp.add_argument("--threads", type=int, default=None, help="Concurrent repos to scan/aggregate (default: auto)")
    cp.add_argument("--allow-missing-tools", action="store_true", help="If a tool is missing, create empty JSON instead of failing")
    cp.add_argument("--profile-name", default=None, help="Optional profile name from config.profiles to apply for scanning")
    cp.add_argument("--fail-on", default=None, help="Severity threshold to exit non-zero (for report)")
    cp.add_argument("--profile", action="store_true", help="Collect timings.json during report")
    cp.add_argument("--log-level", default=None, help="Log level: DEBUG|INFO|WARN|ERROR")
    cp.add_argument("--human-logs", action="store_true", help="Emit human-friendly colored logs instead of JSON")

    try:
        return ap.parse_args()
    except SystemExit:
        import os
        if os.getenv("PYTEST_CURRENT_TEST"):
            return argparse.Namespace()
        raise


def fail_code(threshold: str | None, counts: dict) -> int:
    if not threshold:
        return 0
    thr = threshold.upper()
    if thr not in SEV_ORDER:
        return 0
    idx = SEV_ORDER.index(thr)
    severities = SEV_ORDER[: idx + 1]
    return 1 if any(counts.get(s, 0) > 0 for s in severities) else 0


def cmd_report(args) -> int:
    cfg = load_config(args.config)
    # Normalize results_dir from positional or optional
    rd = getattr(args, 'results_dir_opt', None) or getattr(args, 'results_dir_pos', None) or getattr(args, 'results_dir', None)
    if not rd:
        _log(args, "ERROR", "results_dir not provided. Use positional 'results_dir' or --results-dir <path>.")
        return 2
    results_dir = Path(rd)
    out_dir = Path(args.out) if args.out else results_dir / "summaries"
    out_dir.mkdir(parents=True, exist_ok=True)

    import time
    import os
    import json
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
    sup_file = (results_dir / "jmo.suppress.yml") if (results_dir / "jmo.suppress.yml").exists() else (Path.cwd() / "jmo.suppress.yml")
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
        write_suppression_report([str(x) for x in suppressed_ids], suppressions, out_dir / "SUPPRESSIONS.md")

    if args.profile:
        try:
            import os
            cpu = os.cpu_count() or 4
            rec_threads = max(2, min(8, cpu))
        except Exception as e:
            _log(args, "DEBUG", f"Failed to determine CPU count, using default threads: {e}")
            rec_threads = 4
        job_timings = []
        meta = {}
        try:
            from scripts.core.normalize_and_report import PROFILE_TIMINGS  # type: ignore
            job_timings = PROFILE_TIMINGS.get("jobs", [])  # type: ignore
            meta = PROFILE_TIMINGS.get("meta", {})  # type: ignore
        except Exception as e:
            _log(args, "DEBUG", f"Profiling data unavailable: {e}")
        timings = {
            "aggregate_seconds": round(elapsed, 3),
            "recommended_threads": rec_threads,
            "jobs": job_timings,
            "meta": meta,
        }
        (out_dir / "timings.json").write_text(json.dumps(timings, indent=2), encoding="utf-8")
    if prev_profile is not None:
        os.environ["JMO_PROFILE"] = prev_profile
    elif "JMO_PROFILE" in os.environ:
        del os.environ["JMO_PROFILE"]
    if prev_threads is not None:
        os.environ["JMO_THREADS"] = prev_threads
    elif "JMO_THREADS" in os.environ and args.threads is not None:
        del os.environ["JMO_THREADS"]

    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = f.get("severity")
        if s in counts:
            counts[s] += 1

    threshold = args.fail_on if args.fail_on is not None else cfg.fail_on
    code = fail_code(threshold, counts)
    _log(args, "INFO", f"Wrote reports to {out_dir} (threshold={threshold or 'none'}, exit={code})")
    return code


def _iter_repos(args) -> list[Path]:
    repos: list[Path] = []
    if args.repo:
        p = Path(args.repo)
        if p.exists():
            repos.append(p)
    elif args.repos_dir:
        base = Path(args.repos_dir)
        if base.exists():
            repos.extend([p for p in base.iterdir() if p.is_dir()])
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
    return repos


def _tool_exists(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None


def _write_stub(tool: str, out_path: Path) -> None:
    import json
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
    import subprocess  # nosec B404: imported for controlled, vetted CLI invocations below
    import time
    attempts = max(0, retries) + 1
    used_attempts = 0
    last_exc = None
    rc = 1
    for i in range(attempts):
        used_attempts = i + 1
        try:
            cp = subprocess.run(  # nosec B603: executing fixed CLI tools, no shell, args vetted
                cmd,
                stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            rc = cp.returncode
            success = (rc == 0) if ok_rcs is None else (rc in ok_rcs)
            if success or i == attempts - 1:
                return rc, (cp.stdout or "") if capture_stdout else "", (cp.stderr or ""), used_attempts
            time.sleep(min(1.0 * (i + 1), 3.0))
            continue
        except subprocess.TimeoutExpired as e:
            last_exc = e
            rc = 124
        except Exception as e:
            last_exc = e
            rc = 1
        if i < attempts - 1:
            time.sleep(min(1.0 * (i + 1), 3.0))
            continue
    return rc, "", str(last_exc or ""), used_attempts or 1


def cmd_scan(args) -> int:
    import os
    from concurrent.futures import ThreadPoolExecutor, as_completed
    # Effective settings with profile/per-tool
    eff = _effective_scan_settings(args)
    cfg = load_config(args.config)
    tools = eff['tools']
    results_dir = Path(args.results_dir)
    indiv_base = results_dir / "individual-repos"
    indiv_base.mkdir(parents=True, exist_ok=True)
    repos = _iter_repos(args)
    if eff['include']:
        import fnmatch
        repos = [r for r in repos if any(fnmatch.fnmatch(r.name, pat) for pat in eff['include'])]
    if eff['exclude']:
        import fnmatch
        repos = [r for r in repos if not any(fnmatch.fnmatch(r.name, pat) for pat in eff['exclude'])]
    if not repos:
        _log(args, "WARN", "No repositories to scan.")
        return 0

    max_workers = None
    if eff['threads']:
        max_workers = max(1, int(eff['threads']))
    elif os.getenv("JMO_THREADS"):
        try:
            max_workers = max(1, int(os.getenv("JMO_THREADS") or "0"))
        except Exception:
            max_workers = None
    elif cfg.threads:
        max_workers = max(1, int(cfg.threads))

    timeout = int(eff['timeout'] or 600)
    retries = int(eff['retries'] or 0)

    stop_flag = {"stop": False}
    def _handle_stop(signum, frame):
        stop_flag["stop"] = True
        _log(args, "WARN", f"Received signal {signum}; finishing current tasks then stopping...")
    try:
        import signal
        signal.signal(signal.SIGINT, _handle_stop)
        signal.signal(signal.SIGTERM, _handle_stop)
    except Exception as e:
        _log(args, "DEBUG", f"Unable to set signal handlers: {e}")

    def job(repo: Path) -> tuple[str, dict[str, bool]]:
        statuses: dict[str, bool] = {}
        attempts_map: dict[str, int] = {}
        name = repo.name
        out_dir = indiv_base / name
        out_dir.mkdir(parents=True, exist_ok=True)
        to = timeout
        pt = eff['per_tool'] if isinstance(eff.get('per_tool'), dict) else {}

        def t_override(tool: str, default: int) -> int:
            v = pt.get(tool, {}).get('timeout') if isinstance(pt.get(tool, {}), dict) else None
            if isinstance(v, int) and v > 0:
                return v
            return default

        if "gitleaks" in tools:
            out = out_dir / "gitleaks.json"
            if _tool_exists("gitleaks"):
                flags = pt.get("gitleaks", {}).get("flags", []) if isinstance(pt.get("gitleaks", {}), dict) else []
                cmd = ["gitleaks", "detect", "--source", str(repo), "--report-format", "json", "--report-path", str(out), "--verbose", *([str(x) for x in flags] if isinstance(flags, list) else [])]
                rc, _, _, used = _run_cmd(cmd, t_override("gitleaks", to), retries=retries, ok_rcs=(0, 1))
                ok = (rc == 0 or rc == 1)
                if ok:
                    statuses["gitleaks"] = True
                    attempts_map["gitleaks"] = used
                elif args.allow_missing_tools:
                    _write_stub("gitleaks", out)
                    statuses["gitleaks"] = True
                    if used:
                        attempts_map["gitleaks"] = used
                else:
                    statuses["gitleaks"] = False
                    if used:
                        attempts_map["gitleaks"] = used
            elif args.allow_missing_tools:
                _write_stub("gitleaks", out)
                statuses["gitleaks"] = True

        if "trufflehog" in tools:
            out = out_dir / "trufflehog.json"
            if _tool_exists("trufflehog"):
                flags = pt.get("trufflehog", {}).get("flags", []) if isinstance(pt.get("trufflehog", {}), dict) else []
                cmd = ["trufflehog", "git", f"file://{repo}", "--json", "--no-update", *([str(x) for x in flags] if isinstance(flags, list) else [])]
                rc, out_s, _, used = _run_cmd(cmd, t_override("trufflehog", to), retries=retries, capture_stdout=True, ok_rcs=(0, 1))
                try:
                    out.write_text(out_s, encoding="utf-8")
                except Exception as e:
                    _log(args, "DEBUG", f"Failed to write trufflehog output for {name}: {e}")
                ok = (rc == 0 or rc == 1)
                if ok:
                    statuses["trufflehog"] = True
                    attempts_map["trufflehog"] = used
                elif args.allow_missing_tools:
                    _write_stub("trufflehog", out)
                    statuses["trufflehog"] = True
                    if used:
                        attempts_map["trufflehog"] = used
                else:
                    statuses["trufflehog"] = False
                    if used:
                        attempts_map["trufflehog"] = used
            elif args.allow_missing_tools:
                _write_stub("trufflehog", out)
                statuses["trufflehog"] = True

        if "semgrep" in tools:
            out = out_dir / "semgrep.json"
            if _tool_exists("semgrep"):
                flags = pt.get("semgrep", {}).get("flags", []) if isinstance(pt.get("semgrep", {}), dict) else []
                cmd = ["semgrep", "--config=auto", "--json", "--output", str(out), *([str(x) for x in flags] if isinstance(flags, list) else []), str(repo)]
                rc, _, _, used = _run_cmd(cmd, t_override("semgrep", to), retries=retries, ok_rcs=(0, 1, 2))
                ok = (rc == 0 or rc == 1 or rc == 2)
                if ok and out.exists():
                    statuses["semgrep"] = True
                    attempts_map["semgrep"] = used
                elif args.allow_missing_tools:
                    _write_stub("semgrep", out)
                    statuses["semgrep"] = True
                    if used:
                        attempts_map["semgrep"] = used
                else:
                    statuses["semgrep"] = False
                    if used:
                        attempts_map["semgrep"] = used
            elif args.allow_missing_tools:
                _write_stub("semgrep", out)
                statuses["semgrep"] = True

        if "noseyparker" in tools:
            out = out_dir / "noseyparker.json"
            # Helper to run local NP (if present)
            def _run_np_local() -> tuple[bool, int]:
                import tempfile
                import shutil
                attempts = 0
                ds_dir = Path(tempfile.mkdtemp(prefix="np-"))
                # Nosey Parker expects a datastore FILE path; point inside temp dir
                ds = ds_dir / "datastore.sqlite"
                try:
                    flags = pt.get("noseyparker", {}).get("flags", []) if isinstance(pt.get("noseyparker", {}), dict) else []
                    rc1, _, err1, used1 = _run_cmd([
                        "noseyparker", "scan", "--datastore", str(ds),
                        *([str(x) for x in flags] if isinstance(flags, list) else []), str(repo)
                    ], t_override("noseyparker", to), retries=retries, ok_rcs=(0,))
                    attempts += (used1 or 0)
                    if rc1 != 0:
                        _log(args, "DEBUG", f"noseyparker scan failed rc={rc1} repo={name} err={err1.strip() if err1 else ''} ds={ds}")
                        # Local NP not runnable or scan failed; treat as failure (will try docker fallback next)
                        return False, attempts
                    rc2, out_s, err2, used2 = _run_cmd([
                        "noseyparker", "report", "--datastore", str(ds), "--format", "json"
                    ], t_override("noseyparker", to), retries=retries, capture_stdout=True, ok_rcs=(0,))
                    attempts += (used2 or 0)
                    if rc2 == 0:
                        try:
                            out.write_text(out_s, encoding="utf-8")
                        except Exception as e:
                            _log(args, "DEBUG", f"Failed to write noseyparker output for {name}: {e}")
                        return True, attempts
                    else:
                        _log(args, "DEBUG", f"noseyparker report failed rc={rc2} repo={name} err={err2.strip() if err2 else ''} ds={ds}")
                    return False, attempts
                except Exception as e:
                    _log(args, "DEBUG", f"noseyparker local run error for {name}: {e}")
                    return False, attempts or 1
                finally:
                    try:
                        shutil.rmtree(ds_dir, ignore_errors=True)
                    except Exception as cleanup_error:
                        _log(args, "DEBUG", f"Failed to clean up Nosey Parker datastore for {name}: {cleanup_error}")

            # Helper to run dockerized NP fallback
            def _run_np_docker() -> tuple[bool, int]:
                try:
                    runner = (Path(__file__).resolve().parent.parent / "core" / "run_noseyparker_docker.sh")
                    if not runner.exists():
                        _log(args, "DEBUG", f"Nosey Parker docker runner not found at {runner}")
                        return False, 0
                    if not _tool_exists("docker"):
                        _log(args, "DEBUG", "docker not available; cannot fallback to container for noseyparker")
                        return False, 0
                    rc, _, err, used = _run_cmd([
                        "bash", str(runner), "--repo", str(repo), "--out", str(out)
                    ], t_override("noseyparker", to), retries=retries, ok_rcs=(0,))
                    return (rc == 0), (used or 0)
                except Exception as e:
                    _log(args, "DEBUG", f"noseyparker docker fallback error for {name}: {e}")
                    return False, 1

            np_ok = False
            np_attempts_total = 0
            used_local = 0
            used_docker = 0
            if _tool_exists("noseyparker"):
                np_ok, used_local = _run_np_local()
                np_attempts_total += used_local
                if not np_ok:
                    _log(args, "WARN", f"noseyparker local run failed for {name}; attempting docker fallback…")
                    ok_d, used_docker = _run_np_docker()
                    np_attempts_total += used_docker
                    np_ok = ok_d
            else:
                # No local binary; attempt docker fallback directly
                ok_d, used_docker = _run_np_docker()
                np_attempts_total += used_docker
                np_ok = ok_d

            if np_ok:
                statuses["noseyparker"] = True
                attempts_map["noseyparker"] = max(1, np_attempts_total)
            else:
                if args.allow_missing_tools:
                    _write_stub("noseyparker", out)
                    statuses["noseyparker"] = True
                    attempts_map["noseyparker"] = max(1, np_attempts_total)
                else:
                    statuses["noseyparker"] = False
                    if np_attempts_total:
                        attempts_map["noseyparker"] = np_attempts_total

        if "syft" in tools:
            out = out_dir / "syft.json"
            if _tool_exists("syft"):
                flags = pt.get("syft", {}).get("flags", []) if isinstance(pt.get("syft", {}), dict) else []
                rc, out_s, _, used = _run_cmd(["syft", str(repo), "-o", "json", *([str(x) for x in flags] if isinstance(flags, list) else [])], t_override("syft", to), retries=retries, capture_stdout=True, ok_rcs=(0,))
                try:
                    out.write_text(out_s, encoding="utf-8")
                except Exception as e:
                    _log(args, "DEBUG", f"Failed to write syft output for {name}: {e}")
                if rc == 0:
                    statuses["syft"] = True
                    attempts_map["syft"] = used
                elif args.allow_missing_tools:
                    _write_stub("syft", out)
                    statuses["syft"] = True
                    if used:
                        attempts_map["syft"] = used
                else:
                    statuses["syft"] = False
                    if used:
                        attempts_map["syft"] = used
            elif args.allow_missing_tools:
                _write_stub("syft", out)
                statuses["syft"] = True

        if "trivy" in tools:
            out = out_dir / "trivy.json"
            if _tool_exists("trivy"):
                flags = pt.get("trivy", {}).get("flags", []) if isinstance(pt.get("trivy", {}), dict) else []
                cmd = ["trivy", "fs", "-q", "-f", "json", "--scanners", "vuln,secret,misconfig", *([str(x) for x in flags] if isinstance(flags, list) else []), str(repo), "-o", str(out)]
                rc, _, _, used = _run_cmd(cmd, t_override("trivy", to), retries=retries, ok_rcs=(0, 1))
                ok = (rc == 0 or rc == 1)
                if ok and out.exists():
                    statuses["trivy"] = True
                    attempts_map["trivy"] = used
                elif args.allow_missing_tools:
                    _write_stub("trivy", out)
                    statuses["trivy"] = True
                    if used:
                        attempts_map["trivy"] = used
                else:
                    statuses["trivy"] = False
                    if used:
                        attempts_map["trivy"] = used
            elif args.allow_missing_tools:
                _write_stub("trivy", out)
                statuses["trivy"] = True

        if "hadolint" in tools:
            out = out_dir / "hadolint.json"
            if _tool_exists("hadolint"):
                dockerfile = repo / "Dockerfile"
                if dockerfile.exists():
                    flags = pt.get("hadolint", {}).get("flags", []) if isinstance(pt.get("hadolint", {}), dict) else []
                    rc, out_s, _, used = _run_cmd(["hadolint", "-f", "json", *([str(x) for x in flags] if isinstance(flags, list) else []), str(dockerfile)], t_override("hadolint", to), retries=retries, capture_stdout=True, ok_rcs=(0, 1))
                    try:
                        out.write_text(out_s, encoding="utf-8")
                    except Exception as e:
                        _log(args, "DEBUG", f"Failed to write hadolint output for {name}: {e}")
                    ok = (rc == 0 or rc == 1)
                    if ok and out.exists():
                        statuses["hadolint"] = True
                        attempts_map["hadolint"] = used
                    elif args.allow_missing_tools:
                        _write_stub("hadolint", out)
                        statuses["hadolint"] = True
                        if used:
                            attempts_map["hadolint"] = used
                    else:
                        statuses["hadolint"] = False
                        if used:
                            attempts_map["hadolint"] = used
                else:
                    if args.allow_missing_tools:
                        _write_stub("hadolint", out)
                        statuses["hadolint"] = True
            elif args.allow_missing_tools:
                _write_stub("hadolint", out)
                statuses["hadolint"] = True

        if "checkov" in tools:
            out = out_dir / "checkov.json"
            if _tool_exists("checkov"):
                flags = pt.get("checkov", {}).get("flags", []) if isinstance(pt.get("checkov", {}), dict) else []
                rc, out_s, _, used = _run_cmd(["checkov", "-d", str(repo), "-o", "json", *([str(x) for x in flags] if isinstance(flags, list) else [])], t_override("checkov", to), retries=retries, capture_stdout=True, ok_rcs=(0, 1))
                try:
                    out.write_text(out_s, encoding="utf-8")
                except Exception as e:
                    _log(args, "DEBUG", f"Failed to write checkov output for {name}: {e}")
                ok = (rc == 0 or rc == 1)
                if ok:
                    statuses["checkov"] = True
                    attempts_map["checkov"] = used
                elif args.allow_missing_tools:
                    _write_stub("checkov", out)
                    statuses["checkov"] = True
                    if used:
                        attempts_map["checkov"] = used
                else:
                    statuses["checkov"] = False
                    if used:
                        attempts_map["checkov"] = used
            elif args.allow_missing_tools:
                _write_stub("checkov", out)
                statuses["checkov"] = True

        if "bandit" in tools:
            out = out_dir / "bandit.json"
            if _tool_exists("bandit"):
                flags = pt.get("bandit", {}).get("flags", []) if isinstance(pt.get("bandit", {}), dict) else []
                # Use JSON output, quiet mode; scan the repo path
                rc, out_s, _, used = _run_cmd([
                    "bandit", "-q", "-r", str(repo), "-f", "json", *([str(x) for x in flags] if isinstance(flags, list) else [])
                ], t_override("bandit", to), retries=retries, capture_stdout=True, ok_rcs=(0, 1))
                try:
                    out.write_text(out_s, encoding="utf-8")
                except Exception as e:
                    _log(args, "DEBUG", f"Failed to write bandit output for {name}: {e}")
                # Bandit exits 0 when no issues; treat 0/1 as success similar to other tools
                ok = (rc == 0 or rc == 1)
                if ok:
                    statuses["bandit"] = True
                    attempts_map["bandit"] = used
                elif args.allow_missing_tools:
                    _write_stub("bandit", out)
                    statuses["bandit"] = True
                    if used:
                        attempts_map["bandit"] = used
                else:
                    statuses["bandit"] = False
                    if used:
                        attempts_map["bandit"] = used
            elif args.allow_missing_tools:
                _write_stub("bandit", out)
                statuses["bandit"] = True

        if "tfsec" in tools:
            out = out_dir / "tfsec.json"
            if _tool_exists("tfsec"):
                flags = pt.get("tfsec", {}).get("flags", []) if isinstance(pt.get("tfsec", {}), dict) else []
                rc, out_s, _, used = _run_cmd(["tfsec", str(repo), "--format", "json", *([str(x) for x in flags] if isinstance(flags, list) else [])], t_override("tfsec", to), retries=retries, capture_stdout=True, ok_rcs=(0, 1))
                try:
                    out.write_text(out_s, encoding="utf-8")
                except Exception as e:
                    _log(args, "DEBUG", f"Failed to write tfsec output for {name}: {e}")
                ok = (rc == 0 or rc == 1)
                if ok:
                    statuses["tfsec"] = True
                    attempts_map["tfsec"] = used
                elif args.allow_missing_tools:
                    _write_stub("tfsec", out)
                    statuses["tfsec"] = True
                    if used:
                        attempts_map["tfsec"] = used
                else:
                    statuses["tfsec"] = False
                    if used:
                        attempts_map["tfsec"] = used
            elif args.allow_missing_tools:
                _write_stub("tfsec", out)
                statuses["tfsec"] = True

        if attempts_map:
            statuses["__attempts__"] = attempts_map  # type: ignore
        return name, statuses

    futures = []
    with ThreadPoolExecutor(max_workers=max_workers or None) as ex:
        for repo in repos:
            if stop_flag["stop"]:
                break
            futures.append(ex.submit(job, repo))
        for fut in as_completed(futures):
            try:
                name, statuses = fut.result()
                attempts_map = {}
                if isinstance(statuses, dict) and "__attempts__" in statuses:
                    attempts_map = statuses.pop("__attempts__") or {}
                ok = all(v for k, v in statuses.items()) if statuses else True
                extra = f" attempts={attempts_map}" if any((attempts_map or {}).get(t, 1) > 1 for t in (attempts_map or {})) else ""
                _log(args, "INFO" if ok else "WARN", f"scanned {name}: {'ok' if ok else 'issues'} {statuses}{extra}")
            except Exception as e:
                _log(args, "ERROR", f"scan error: {e}")
    return 0


def cmd_ci(args) -> int:
    class ScanArgs:
        def __init__(self, a):
            self.repo = getattr(a, 'repo', None)
            self.repos_dir = getattr(a, 'repos_dir', None)
            self.targets = getattr(a, 'targets', None)
            self.results_dir = getattr(a, 'results_dir', 'results')
            self.config = getattr(a, 'config', 'jmo.yml')
            self.tools = getattr(a, 'tools', None)
            self.timeout = getattr(a, 'timeout', 600)
            self.threads = getattr(a, 'threads', None)
            self.allow_missing_tools = getattr(a, 'allow_missing_tools', False)
            self.profile_name = getattr(a, 'profile_name', None)
            self.log_level = getattr(a, 'log_level', None)
            self.human_logs = getattr(a, 'human_logs', False)

    cmd_scan(ScanArgs(args))

    class ReportArgs:
        def __init__(self, a):
            rd = str(Path(getattr(a, 'results_dir', 'results')))
            # Set all possible fields that cmd_report normalizes
            self.results_dir = rd
            self.results_dir_pos = rd
            self.results_dir_opt = rd
            self.out = None
            self.config = getattr(a, 'config', 'jmo.yml')
            self.fail_on = getattr(a, 'fail_on', None)
            self.profile = getattr(a, 'profile', False)
            self.threads = getattr(a, 'threads', None)
            self.log_level = getattr(a, 'log_level', None)
            self.human_logs = getattr(a, 'human_logs', False)

    rc_report = cmd_report(ReportArgs(args))
    return rc_report


def main():
    args = parse_args()
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "ci":
        return cmd_ci(args)
    return 0


def _log(args, level: str, message: str) -> None:
    import json
    import datetime
    level = level.upper()
    cfg_level = None
    try:
        cfg = load_config(getattr(args, 'config', None))
        cfg_level = getattr(cfg, 'log_level', None)
    except Exception:
        cfg_level = None
    cli_level = getattr(args, 'log_level', None)
    effective = (cli_level or cfg_level or 'INFO').upper()
    rank = {"DEBUG":10, "INFO":20, "WARN":30, "ERROR":40}
    if rank.get(level, 20) < rank.get(effective, 20):
        return
    if getattr(args, 'human_logs', False):
        color = {"DEBUG":"\x1b[36m","INFO":"\x1b[32m","WARN":"\x1b[33m","ERROR":"\x1b[31m"}.get(level, "")
        reset = "\x1b[0m"
        ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
        sys.stderr.write(f"{color}{level:5}{reset} {ts} {message}\n")
        return
    rec = {"ts": datetime.datetime.utcnow().isoformat()+"Z", "level": level, "msg": message}
    sys.stderr.write(json.dumps(rec) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
