#!/usr/bin/env python3
"""CI orchestration logic for JMo Security."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

# Attributes the downstream phases read as a bare ``args.X`` -- no ``getattr``
# default -- so their absence is an AttributeError rather than a fallback.
# `jmo ci`'s own parser supplies all of them except ``out``, which only
# `jmo report` defines. The list exists for callers that build a namespace by
# hand: `cmd_profile` routes `jmo fast|balanced|full` through here with 11
# dests against `jmo ci`'s 40.
#
# This is deliberately NOT a mirror of the parser, and the distinction is the
# whole point of the rewrite below. Two hand-written mirror classes used to live
# here, listing 29 and 20 fields by name, and they had drifted from
# `_add_ci_args` by nine: `--skip-tools`, `--resume`, `--no-resume`,
# `--no-store-raw-findings`, `--encrypt-findings` and `--collect-metadata` were
# parsed, advertised in `--help`, and then silently discarded. Because every
# read was ``getattr(a, "<literal>", <default>)``, a renamed or added flag
# produced no type error -- the same getattr-masks-mypy class as the
# `threads: auto` crash. Anything reached through ``getattr`` with a default is
# forwarded automatically by copying the namespace, so it must not be listed.
_SCAN_REQUIRED: dict[str, object] = {
    "config": "jmo.yml",
    "results_dir": "results",
}
_REPORT_REQUIRED: dict[str, object] = {
    "config": "jmo.yml",
    "fail_on": None,
    "out": None,
    "policies": None,
    "profile": False,
    "threads": None,
}


def _phase_args(a, required: dict[str, object], **overrides):
    """Return the caller's namespace, adapted for one phase.

    ``copy.copy`` rather than ``argparse.Namespace(**vars(a))``: the test suite
    and `cmd_profile` both pass objects whose attributes live on the *class*,
    where ``vars(instance)`` is ``{}`` and every field would be dropped.

    The copy also means the phase cannot mutate the caller's namespace --
    `cmd_scan` adds ``results_dir_pos``/``out``/``fail_on`` to whatever it is
    given, which used to land on a throwaway object and now would otherwise
    land on `jmo ci`'s own arguments.
    """
    ns = copy.copy(a)
    for key, value in required.items():
        if not hasattr(ns, key):
            setattr(ns, key, value)
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def cmd_ci(args, cmd_scan_fn, cmd_report_fn) -> int:
    """Run CI command: scan + report in one step.

    Args:
        args: Parsed CLI arguments
        cmd_scan_fn: Function to run scan command (args) -> int
        cmd_report_fn: Function to run report command (args, _log_fn) -> int

    Returns:
        Exit code: the report's threshold verdict when it fails, otherwise the
        scan's own code.
    """
    # v1.0.0: Strict version check for reproducible CI builds
    if getattr(args, "strict_versions", False):
        from scripts.cli.tool_manager import ToolManager

        profile = getattr(args, "profile_name", None) or "balanced"
        manager = ToolManager()
        drift = manager.get_version_drift(profile)

        if drift:
            # Categorize by direction
            ahead = [d for d in drift if d.get("direction") == "ahead"]
            behind = [d for d in drift if d.get("direction") == "behind"]
            unknown = [d for d in drift if d.get("direction") == "unknown"]

            # Only fail on behind or unknown (ahead is generally OK)
            problematic = behind + unknown
            if problematic:
                sys.stderr.write(
                    f"ERROR: --strict-versions: {len(problematic)} tool(s) require attention\n"
                )
                if behind:
                    sys.stderr.write(f"\n{len(behind)} tool(s) BEHIND expected:\n")
                    for d in behind:
                        marker = " [CRITICAL]" if d["critical"] else ""
                        sys.stderr.write(
                            f"  {d['tool']}: {d['installed']} < {d['expected']}{marker}\n"
                        )
                if unknown:
                    sys.stderr.write(
                        f"\n{len(unknown)} tool(s) with unknown version:\n"
                    )
                    for d in unknown:
                        marker = " [CRITICAL]" if d["critical"] else ""
                        sys.stderr.write(
                            f"  {d['tool']}: installed={d['installed']} "
                            f"expected={d['expected']}{marker}\n"
                        )
                sys.stderr.write("\nRun 'jmo tools update' to synchronize versions.\n")
                return 1
            elif ahead:
                # Only ahead - info message, don't fail
                sys.stderr.write(
                    f"INFO: {len(ahead)} tool(s) ahead of versions.yaml (OK)\n"
                )

    # Run scan phase.
    #
    # `cmd_scan` runs the report phase itself, so that `--no-store-history`
    # works for a bare `jmo scan`. Suppress that here: `jmo ci` runs its own
    # report below with the threshold and policy flags the scan namespace does
    # not carry, and without this a single `jmo ci` parsed, enriched and wrote
    # all 14 artifacts twice -- and stored *two* history rows plus a doubled
    # findings table for one scan (measured: 2 rows / 34 findings where
    # `jmo scan` produced 1 / 17).
    scan_rc = int(cmd_scan_fn(_phase_args(args, _SCAN_REQUIRED, skip_auto_report=True)))

    # Import _log here to avoid circular dependency
    from scripts.cli.jmo import _log

    rd = str(Path(getattr(args, "results_dir", "results")))
    report_args = _phase_args(
        args,
        _REPORT_REQUIRED,
        results_dir=rd,
        results_dir_pos=rd,
        results_dir_opt=rd,
        out=None,
    )
    rc_report: int = int(cmd_report_fn(report_args, _log))

    # Same precedence `cmd_scan` applies to its own two codes: the threshold
    # verdict wins when it fails, because it is the more specific answer.
    # Otherwise a scan that could not complete is itself a failure. `jmo ci`
    # previously discarded `cmd_scan`'s return value outright, so a target that
    # never scanned exited 0 whenever the findings that *were* collected sat
    # under the threshold.
    if rc_report != 0:
        return rc_report
    return scan_rc
