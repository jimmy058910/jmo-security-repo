#!/usr/bin/env python3
"""
Beginner-friendly wrapper around the jmo CLI.

Examples:
  jmotools fast       # quick scan (fast profile)
  jmotools balanced   # balanced default profile
  jmotools full       # deep/full scan

Steps performed:
  1) Print OS info
  2) Verify tools (non-fatal when --allow-missing-tools)
  3) Optionally clone from TSV into a repos folder and emit targets file
  4) Run jmo ci with appropriate profile
  5) Open dashboard and summary when done
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess  # nosec B404 - CLI needs subprocess to orchestrate external tools
import sys
from pathlib import Path
from typing import List, Optional


DEFAULT_RESULTS = "results"


def _print_os_info() -> None:
    sys.stderr.write("\x1b[36m[INFO]\x1b[0m Environment\n")
    sys.stderr.write(f"  System: {platform.system()} {platform.release()}\n")
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/version", "r", encoding="utf-8") as f:
                v = f.read().strip()
            if "microsoft" in v.lower() or "wsl" in v.lower():
                sys.stderr.write("  Detected: WSL\n")
        except Exception as e:
            # Non-fatal, informational only
            sys.stderr.write(f"\x1b[36m[DEBUG]\x1b[0m WSL detection failed: {e}\n")


def _run(cmd: List[str], cwd: Optional[Path] = None, ok_rcs=(0,)) -> int:
    cp = subprocess.run(  # nosec B603 - cmd is a list built by this tool; shell is not used
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if cp.returncode not in ok_rcs:
        sys.stderr.write(
            f"\x1b[33m[WARN]\x1b[0m Command failed ({cp.returncode}): {' '.join(cmd)}\n"
        )
        if cp.stderr:
            sys.stderr.write(cp.stderr + "\n")
    return cp.returncode


def _check_tools(allow_missing: bool) -> None:
    script = (
        Path(__file__).resolve().parent.parent / "core" / "check_and_install_tools.sh"
    )
    if not script.exists():
        sys.stderr.write(
            "\x1b[33m[WARN]\x1b[0m Tool checker script not found; skipping verification.\n"
        )
        return
    sys.stderr.write("\x1b[36m[INFO]\x1b[0m Verifying tools…\n")
    rc = _run(["bash", str(script), "--check"])  # prints a friendly table
    if rc != 0 and not allow_missing:
        sys.stderr.write(
            "\x1b[31m[ERROR]\x1b[0m Missing tools detected. Re-run with '--allow-missing-tools' to proceed with stubs, or install required tools.\n"
        )
        raise SystemExit(1)


def _maybe_clone_from_tsv(
    tsv: Optional[str], dest: str, targets_out: str
) -> Optional[Path]:
    if not tsv:
        return None
    clone_script = Path(__file__).resolve().parent / "clone_from_tsv.py"
    if not Path(tsv).expanduser().exists():
        sys.stderr.write(f"\x1b[31m[ERROR]\x1b[0m TSV not found: {tsv}\n")
        raise SystemExit(2)
    sys.stderr.write("\x1b[36m[INFO]\x1b[0m Cloning repositories from TSV…\n")
    rc = _run(
        [
            sys.executable,
            str(clone_script),
            "--tsv",
            str(Path(tsv).expanduser()),
            "--dest",
            dest,
            "--targets-out",
            targets_out,
            "--human-logs",
        ]
    )
    if rc != 0:
        raise SystemExit(rc)
    return Path(targets_out)


def _open_outputs(out_dir: Path) -> None:
    html = out_dir / "dashboard.html"
    md = out_dir / "SUMMARY.md"
    yaml = out_dir / "findings.yaml"
    opener = None
    if sys.platform.startswith("linux"):
        opener = shutil.which("xdg-open")
    elif sys.platform == "darwin":
        opener = shutil.which("open")
    elif os.name == "nt":
        opener = "start"
    paths = [p for p in [html, md, yaml] if p.exists()]
    if not paths:
        sys.stderr.write(
            f"\x1b[33m[WARN]\x1b[0m No output files found yet in {out_dir}\n"
        )
        return
    # Constrain opener to an allowlist for safety
    allowed_openers = {"xdg-open", "open", "start"}
    opener_name = None
    if opener:
        opener_name = os.path.basename(opener) if os.path.isabs(opener) else opener

    if opener and opener_name in allowed_openers:
        for p in paths:
            try:
                if opener == "start":
                    os.startfile(str(p))  # type: ignore[attr-defined]  # nosec B606 - expected on Windows; guarded by allowlist
                else:
                    subprocess.Popen(  # nosec B603 - opener is from allowlist; shell=False; args are fixed
                        [opener, str(p)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
            except Exception as e:
                sys.stderr.write(f"\x1b[36m[DEBUG]\x1b[0m Failed to open {p}: {e}\n")
    elif opener:
        sys.stderr.write(
            f"\x1b[33m[WARN]\x1b[0m Opener '{opener}' is not in allowlist; not launching files.\n"
        )
    sys.stderr.write("\x1b[36m[INFO]\x1b[0m Results:\n")
    for p in paths:
        sys.stderr.write(f"  {p}\n")


def _profile_for(cmd_name: str) -> str:
    m = {
        "fast": "fast",
        "balanced": "balanced",
        "full": "deep",
        "deep": "deep",
    }
    return m.get(cmd_name, "balanced")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="jmotools", description="Beginner-friendly wrapper for jmo security scans"
    )
    sub = ap.add_subparsers(dest="mode", required=True)

    def _add_common(sp: argparse.ArgumentParser) -> None:
        g = sp.add_mutually_exclusive_group(required=False)
        g.add_argument("--repo", help="Path to a single repository to scan")
        g.add_argument(
            "--repos-dir", help="Directory whose immediate subfolders are repos to scan"
        )
        g.add_argument("--targets", help="File listing repo paths (one per line)")
        sp.add_argument(
            "--tsv", help="Optional TSV to clone from (with url or full_name headers)"
        )
        sp.add_argument(
            "--dest",
            default="repos-tsv",
            help="Where to clone TSV repos (default: repos-tsv)",
        )
        sp.add_argument(
            "--results-dir",
            default=DEFAULT_RESULTS,
            help="Results directory (default: results)",
        )
        sp.add_argument("--threads", type=int, default=None, help="Override threads")
        sp.add_argument(
            "--timeout",
            type=int,
            default=None,
            help="Override per-tool timeout seconds",
        )
        sp.add_argument(
            "--fail-on",
            default=None,
            help="Optional severity threshold to fail the run",
        )
        sp.add_argument(
            "--no-open", action="store_true", help="Do not open results after run"
        )
        sp.add_argument(
            "--strict",
            action="store_true",
            help="Fail if tools are missing (disable stubs)",
        )
        sp.add_argument("--human-logs", action="store_true", help="Human-friendly logs")
        sp.add_argument(
            "--config", default="jmo.yml", help="Config file (default: jmo.yml)"
        )

    for name in ("fast", "balanced", "full", "deep"):
        sp = sub.add_parser(name, help=f"Run the {name} profile")
        _add_common(sp)

    # Setup subcommand: bootstrap tools
    sp_setup = sub.add_parser(
        "setup", help="Verify and optionally auto-install security tools"
    )
    sp_setup.add_argument(
        "--auto-install",
        action="store_true",
        help="Attempt to auto-install missing tools",
    )
    sp_setup.add_argument(
        "--print-commands",
        action="store_true",
        help="Print installation commands without executing",
    )
    sp_setup.add_argument(
        "--force-reinstall",
        action="store_true",
        help="Force reinstallation of all tools",
    )
    sp_setup.add_argument(
        "--human-logs", action="store_true", help="Human-friendly logs"
    )
    sp_setup.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if tools are missing and not auto-installed",
    )

    # Wizard subcommand: interactive guided setup
    sp_wizard = sub.add_parser(
        "wizard", help="Interactive wizard for guided security scanning"
    )
    sp_wizard.add_argument(
        "--yes", "-y", action="store_true", help="Non-interactive mode (use defaults)"
    )
    sp_wizard.add_argument(
        "--docker", action="store_true", help="Force Docker execution mode"
    )
    sp_wizard.add_argument(
        "--emit-make-target", metavar="FILE", help="Generate Makefile target"
    )
    sp_wizard.add_argument(
        "--emit-script", metavar="FILE", help="Generate shell script"
    )
    sp_wizard.add_argument(
        "--emit-gha", metavar="FILE", help="Generate GitHub Actions workflow"
    )

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _print_os_info()

    # Handle wizard early
    if args.mode == "wizard":
        wizard_script = Path(__file__).resolve().parent / "wizard.py"
        if not wizard_script.exists():
            sys.stderr.write("\x1b[31m[ERROR]\x1b[0m Wizard script not found.\n")
            return 2

        # Import and run wizard
        sys.path.insert(0, str(wizard_script.parent))
        from wizard import run_wizard

        exit_code: int = run_wizard(
            yes=getattr(args, "yes", False),
            force_docker=getattr(args, "docker", False),
            emit_make=getattr(args, "emit_make_target", None),
            emit_script=getattr(args, "emit_script", None),
            emit_gha=getattr(args, "emit_gha", None),
        )
        return exit_code

    # Handle setup early
    if args.mode == "setup":
        script = (
            Path(__file__).resolve().parent.parent
            / "core"
            / "check_and_install_tools.sh"
        )
        if not script.exists():
            sys.stderr.write(
                "\x1b[31m[ERROR]\x1b[0m Tool bootstrap script not found.\n"
            )
            return 2
        cmd = ["bash", str(script)]
        if args.force_reinstall:
            cmd.append("--force-reinstall")
        elif args.auto_install:
            cmd.append("--auto-install")
        elif args.print_commands:
            cmd.append("--print-commands")
        else:
            cmd.append("--check")
        rc = _run(cmd)
        if rc != 0 and args.strict:
            return rc
        return 0 if rc == 0 else rc

    allow_missing = not args.strict
    _check_tools(allow_missing)

    results_dir = Path(args.results_dir).expanduser().resolve()
    results_dir.mkdir(parents=True, exist_ok=True)
    out_dir = results_dir / "summaries"

    targets_file: Optional[Path] = None
    if getattr(args, "tsv", None):
        targets_file = _maybe_clone_from_tsv(
            args.tsv, args.dest, str(results_dir / "targets.tsv.txt")
        )

    # Prefer command-line selection order: explicit targets/repo(s) override TSV
    ci_args: List[str] = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "ci",
        "--results-dir",
        str(results_dir),
        "--config",
        str(args.config),
        "--profile-name",
        _profile_for(args.mode),
        "--human-logs",
    ]
    if allow_missing:
        ci_args.append("--allow-missing-tools")
    if args.threads is not None:
        ci_args += ["--threads", str(max(1, args.threads))]
    if args.timeout is not None:
        ci_args += ["--timeout", str(max(60, args.timeout))]
    if args.fail_on:
        ci_args += ["--fail-on", str(args.fail_on)]

    # Sources: explicit > repos-dir > targets from TSV
    if args.repo:
        ci_args += ["--repo", str(Path(args.repo).expanduser().resolve())]
    elif args.repos_dir:
        ci_args += ["--repos-dir", str(Path(args.repos_dir).expanduser().resolve())]
    elif args.targets:
        ci_args += ["--targets", str(Path(args.targets).expanduser().resolve())]
    elif targets_file:
        ci_args += ["--targets", str(targets_file)]

    sys.stderr.write("\x1b[36m[INFO]\x1b[0m Running security scan…\n")
    rc = _run(ci_args)
    if rc != 0:
        sys.stderr.write(
            f"\x1b[33m[WARN]\x1b[0m Scan completed with non-zero exit: {rc}\n"
        )

    if not args.no_open:
        _open_outputs(out_dir)

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
