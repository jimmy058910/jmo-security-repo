"""`jmo ci` must forward every argument its own parser accepts.

`cmd_ci` used to re-marshal its arguments through two hand-written classes,
`ScanArgs` and `ReportArgs`, each naming its fields one at a time as
``getattr(a, "<literal>", <default>)``. That is a second source of truth for
`_add_ci_args`, and it had drifted: six flags reached the scan phase as their
getattr default and three reached the report phase the same way, while
``jmo ci --help`` advertised all nine. A string literal is invisible to the type
checker, so nothing failed -- the same getattr-masks-mypy class as the
``threads: auto`` crash.

Measured consequences before the fix, on a real scan of the e2e fixture tree:

* ``jmo ci --skip-tools semgrep`` ran semgrep anyway (121,398 B, 43 results),
  where ``jmo scan`` with the same flag produced no semgrep output at all.
* ``jmo ci --no-store-raw-findings`` stored raw finding text for 34 of 34 rows.
* ``jmo ci --encrypt-findings`` stored plaintext where ``jmo scan`` stored a
  Fernet token.
* ``jmo ci --collect-metadata`` left ``hostname``/``username`` NULL.

Every expectation below is DERIVED from the parser, so a flag added to
`_add_scan_config_args` tomorrow is covered without editing this file. That is
also why the extractor needs its own meta-guard: an extractor that silently
finds nothing passes every assertion built on top of it.
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.cli import jmo, report_orchestrator
from scripts.cli.ci_orchestrator import (
    _REPORT_REQUIRED,
    _SCAN_REQUIRED,
    cmd_ci,
)
from scripts.cli.jmo import _add_ci_args

# The nine dests that actually drifted. Naming them is the meta-guard: it is the
# one thing in this file that is NOT derived, and it exists so a broken
# extractor cannot pass by returning an empty set.
KNOWN_DRIFTED_DESTS = frozenset(
    {
        "skip_tools",
        "resume",
        "no_resume",
        "no_store_raw_findings",
        "encrypt_findings",
        "collect_metadata",
    }
)

# The report phase legitimately rewrites these: `results_dir` is normalized
# through `Path` and mirrored onto the positional/optional dests `jmo report`
# reads, and `out` is forced to None so reports land in `<results>/summaries`.
# Nothing else may differ.
REPORT_PHASE_OVERRIDES = frozenset({"results_dir", "out"})


def ci_parser_dests() -> set[str]:
    """Every dest `jmo ci` accepts, read off the real parser."""
    ap = argparse.ArgumentParser(prog="jmo")
    sub = ap.add_subparsers(dest="cmd")
    parser = _add_ci_args(sub)
    return {a.dest for a in parser._actions if a.dest != "help"}


def sentineled_namespace() -> argparse.Namespace:
    """A namespace holding every ci dest, each with a value unique to it.

    Values rather than mere presence: a forwarder that set every field to None
    would satisfy a presence-only check while discarding what the user typed.
    Sentinels also sidestep the parser's mutually exclusive groups, which no
    single command line can populate at once.
    """
    return argparse.Namespace(**{d: f"<sentinel:{d}>" for d in ci_parser_dests()})


def run_ci(args):
    """Invoke cmd_ci with capturing phases; return (scan_args, report_args, rc)."""
    captured: dict[str, object] = {}

    def fake_scan(a):
        captured["scan"] = a
        return 0

    def fake_report(a, _log_fn):
        captured["report"] = a
        return 0

    with patch("scripts.cli.jmo._log"):
        rc = cmd_ci(args, fake_scan, fake_report)
    return captured["scan"], captured["report"], rc


# ---------------------------------------------------------------------------
# Meta-guard: the extractor itself
# ---------------------------------------------------------------------------


def test_ci_parser_dest_extractor_finds_a_real_parser():
    """The derivation must not silently come back empty.

    Every assertion below is built on `ci_parser_dests()`. If `_add_ci_args`
    were renamed, or the private `_actions` traversal stopped working, an empty
    set would make each of those assertions vacuously true.
    """
    dests = ci_parser_dests()
    assert (
        len(dests) >= 35
    ), f"expected the full ci surface, got {len(dests)}: {sorted(dests)}"
    missing = KNOWN_DRIFTED_DESTS - dests
    assert (
        not missing
    ), f"extractor lost dests that are known to exist: {sorted(missing)}"
    # Spot-check the three shared helpers `_add_ci_args` composes, so a change
    # that drops one of them entirely is caught rather than shrinking silently.
    assert "repo" in dests, "target args missing (_add_target_args)"
    assert "timeout" in dests, "scan config args missing (_add_scan_config_args)"
    assert "log_level" in dests, "logging args missing (_add_logging_args)"
    assert "fail_on" in dests, "ci's own args missing"


# ---------------------------------------------------------------------------
# The acceptance criterion: a flag the parser accepts must reach both phases
# ---------------------------------------------------------------------------


def test_scan_phase_receives_every_ci_parser_dest():
    """This is the test that fails when a scan flag exists and is not forwarded."""
    args = sentineled_namespace()
    scan_args, _report_args, _rc = run_ci(args)

    dropped = sorted(d for d in ci_parser_dests() if not hasattr(scan_args, d))
    assert (
        not dropped
    ), f"`jmo ci` accepts these flags and never hands them to the scan phase: {dropped}"

    altered = sorted(
        d for d in ci_parser_dests() if getattr(scan_args, d) != f"<sentinel:{d}>"
    )
    assert (
        not altered
    ), f"scan phase received a value the user did not supply: {altered}"


def test_report_phase_receives_every_ci_parser_dest():
    args = sentineled_namespace()
    _scan_args, report_args, _rc = run_ci(args)

    dropped = sorted(d for d in ci_parser_dests() if not hasattr(report_args, d))
    assert (
        not dropped
    ), f"`jmo ci` accepts these flags and never hands them to the report phase: {dropped}"

    altered = sorted(
        d
        for d in ci_parser_dests() - REPORT_PHASE_OVERRIDES
        if getattr(report_args, d) != f"<sentinel:{d}>"
    )
    assert (
        not altered
    ), f"report phase received a value the user did not supply: {altered}"


@pytest.mark.parametrize("dest", sorted(KNOWN_DRIFTED_DESTS))
def test_each_previously_dropped_flag_now_reaches_its_consumer(dest):
    """Named individually so a regression says which flag came back."""
    args = sentineled_namespace()
    scan_args, report_args, _rc = run_ci(args)
    assert getattr(scan_args, dest) == f"<sentinel:{dest}>"
    assert getattr(report_args, dest) == f"<sentinel:{dest}>"


def test_required_report_attributes_are_supplied_when_the_caller_lacks_them():
    """`cmd_profile` routes `jmo fast|balanced|full` here with 11 dests, not 40.

    `cmd_report` reads `config`, `fail_on`, `out`, `policies`, `profile` and
    `threads` as a bare ``args.X``, so their absence is an AttributeError rather
    than a fallback.
    """

    class SparseArgs:
        repo = "/repo"
        results_dir = "results"

    _scan_args, report_args, _rc = run_ci(SparseArgs())
    for attr in ("config", "fail_on", "out", "policies", "profile", "threads"):
        assert hasattr(report_args, attr), f"report phase would raise on args.{attr}"


def test_class_attribute_namespaces_are_forwarded():
    """The forwarder must copy the object, not `vars()` it.

    Callers in this suite define their fields on the *class*, where
    ``vars(instance)`` is ``{}``. A `vars`-based forwarder drops every one of
    them while still returning a plausible-looking namespace.
    """

    class ClassAttrArgs:
        repo = "/some/repo"
        skip_tools = ["semgrep"]
        results_dir = "results"
        config = "jmo.yml"

    scan_args, _report_args, _rc = run_ci(ClassAttrArgs())
    assert scan_args.repo == "/some/repo"
    assert scan_args.skip_tools == ["semgrep"]


# ---------------------------------------------------------------------------
# The scan phase must not run the report a second time
# ---------------------------------------------------------------------------


def test_scan_phase_is_told_to_skip_its_own_report():
    """`cmd_scan` runs the report itself; `jmo ci` runs it again afterwards.

    Both firing wrote all 14 artifacts twice and stored two history rows plus a
    doubled findings table for one scan (measured: 2 scans / 34 findings, where
    `jmo scan` produced 1 / 17).
    """
    args = sentineled_namespace()
    scan_args, _report_args, _rc = run_ci(args)
    assert getattr(scan_args, "skip_auto_report", False) is True


def test_the_callers_namespace_is_not_mutated():
    """`cmd_scan` adds attributes to whatever namespace it is handed.

    Those must land on the forwarded copy, not on `jmo ci`'s own arguments --
    otherwise the scan phase silently rewrites the values the report phase is
    about to read.
    """
    args = sentineled_namespace()
    before = dict(vars(args))
    run_ci(args)
    assert "skip_auto_report" not in vars(args)
    assert dict(vars(args)) == before


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scan_rc", "report_rc", "expected"),
    [
        (0, 0, 0),
        (0, 1, 1),  # threshold exceeded
        (0, 2, 2),  # report error
        (1, 0, 1),  # scan failed a target; findings were under threshold
        (1, 1, 1),
        (2, 0, 2),
        (1, 2, 2),  # the report's more specific verdict wins
    ],
)
def test_ci_exit_code_combines_both_phases(scan_rc, report_rc, expected):
    """`cmd_ci` used to discard `cmd_scan`'s return value entirely.

    A target that never scanned therefore exited 0 whenever the findings that
    *were* collected sat under the threshold. The precedence here is the one
    `cmd_scan` already applies to its own two codes.
    """

    class Args:
        repo = "/repo"
        results_dir = "results"
        config = "jmo.yml"

    with patch("scripts.cli.jmo._log"):
        rc = cmd_ci(Args(), lambda a: scan_rc, lambda a, log: report_rc)
    assert rc == expected


# ---------------------------------------------------------------------------
# The required-attribute lists must match what the consumers actually demand
# ---------------------------------------------------------------------------


def unguarded_arg_reads(module_path: Path, func_name: str) -> set[str]:
    """Attributes a function reads as a bare ``args.X`` and never assigns first.

    Anything reached through ``getattr(args, "x", default)`` tolerates absence;
    anything the function assigns before reading supplies its own value. What is
    left is the set whose absence is an AttributeError -- exactly the set
    `_phase_args` has to fill in.
    """
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != func_name:
            continue
        param = node.args.args[0].arg
        loaded: set[str] = set()
        stored: set[str] = set()
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Attribute)
                and isinstance(child.value, ast.Name)
                and child.value.id == param
            ):
                (stored if isinstance(child.ctx, ast.Store) else loaded).add(child.attr)
        return loaded - stored
    raise AssertionError(f"{func_name} not found in {module_path}")


def test_phase_required_lists_match_what_the_consumers_demand():
    """`_SCAN_REQUIRED` / `_REPORT_REQUIRED` are not a taste judgement.

    Each entry exists because its consumer reads it without a default. If a new
    bare `args.X` appears in `cmd_scan` or `cmd_report`, `jmo fast` -- which
    reaches `cmd_ci` with 11 dests, not 40 -- starts raising AttributeError, and
    this is the test that says so before a user finds it.
    """
    scan_needs = unguarded_arg_reads(Path(jmo.__file__), "cmd_scan")
    report_needs = unguarded_arg_reads(Path(report_orchestrator.__file__), "cmd_report")

    # meta-guard: an extractor that finds nothing satisfies every subset check
    assert scan_needs, "AST scan found no unguarded reads in cmd_scan; extractor broken"
    assert (
        len(report_needs) >= 5
    ), f"AST scan found only {report_needs} in cmd_report; extractor broken"
    assert "config" in scan_needs and "config" in report_needs

    missing_scan = scan_needs - set(_SCAN_REQUIRED)
    assert not missing_scan, (
        f"cmd_scan reads args.{sorted(missing_scan)} with no default; "
        "add them to _SCAN_REQUIRED in ci_orchestrator.py"
    )
    missing_report = report_needs - set(_REPORT_REQUIRED)
    assert not missing_report, (
        f"cmd_report reads args.{sorted(missing_report)} with no default; "
        "add them to _REPORT_REQUIRED in ci_orchestrator.py"
    )


def test_phase_required_lists_carry_nothing_extra():
    """Kept minimal deliberately.

    The lists this replaced were 29 and 20 names long and drifted. Every entry
    here has to earn its place by being unguarded in its consumer, or the list
    starts becoming a mirror again.
    """
    scan_needs = unguarded_arg_reads(Path(jmo.__file__), "cmd_scan")
    report_needs = unguarded_arg_reads(Path(report_orchestrator.__file__), "cmd_report")
    # `out` is the exception: `cmd_report` reads it unguarded, and no `jmo ci`
    # flag supplies it, so `_phase_args` always overrides it to None.
    assert set(_SCAN_REQUIRED) == scan_needs
    assert set(_REPORT_REQUIRED) == report_needs


# ---------------------------------------------------------------------------
# #870: the profile shortcuts route through cmd_ci, so they inherit this
# contract. They used to satisfy none of it.
# ---------------------------------------------------------------------------

# Dests `jmo ci` defines that a shortcut deliberately does not, each verified
# to be tolerated by its consumer rather than assumed to be:
#   policies, profile  -- supplied by _REPORT_REQUIRED when absent
#   fail_on_policy_violation, strict_versions -- read via getattr(..., False)
# `--profile` is excluded for a second reason: on a command named after a
# profile, a boolean timing flag spelled `--profile` is a trap, and profile
# selection is `--profile-name` anyway.
SHORTCUT_OMITTED_DESTS = frozenset(
    {"policies", "profile", "fail_on_policy_violation", "strict_versions"}
)


def profile_parser_dests(name: str = "fast") -> set[str]:
    """Every dest a profile shortcut accepts, read off the real parser."""
    ap = argparse.ArgumentParser(prog="jmo")
    sub = ap.add_subparsers(dest="cmd")
    parser = jmo._add_profile_args(sub, name, "help text")
    return {a.dest for a in parser._actions if a.dest != "help"}


def profile_parser_defaults(name: str = "fast") -> dict[str, object]:
    ap = argparse.ArgumentParser(prog="jmo")
    sub = ap.add_subparsers(dest="cmd")
    parser = jmo._add_profile_args(sub, name, "help text")
    return {a.dest: a.default for a in parser._actions if a.dest != "help"}


def ci_parser_defaults() -> dict[str, object]:
    ap = argparse.ArgumentParser(prog="jmo")
    sub = ap.add_subparsers(dest="cmd")
    parser = _add_ci_args(sub)
    return {a.dest: a.default for a in parser._actions if a.dest != "help"}


def test_profile_dest_extractor_finds_a_real_parser():
    """Meta-guard, same reason as the ci one: empty passes everything."""
    dests = profile_parser_dests()
    assert len(dests) >= 35, f"expected the full surface, got {sorted(dests)}"
    assert "repo" in dests, "target args missing (_add_target_args)"
    assert "timeout" in dests, "scan config args missing (_add_scan_config_args)"
    assert "log_level" in dests, "logging args missing (_add_logging_args)"
    assert "no_open" in dests, "the shortcut's own args missing"


@pytest.mark.parametrize("name", ["fast", "balanced", "full"])
def test_shortcut_parsers_define_every_ci_dest(name):
    """The defect itself.

    `cmd_profile` builds its ci namespace by copying the *profile* parser's,
    so any dest that parser does not define arrives absent. `store_history`
    was one: `report_orchestrator` gates storage on
    `getattr(args, "store_history", False)`, so absent meant OFF while the
    parser that defines it defaults it ON. `jmo fast` silently stored nothing
    and had no flag to turn it on either (#870).

    Derived from both parsers, so the next flag added to `_add_scan_config_args`
    is covered without editing this file.
    """
    missing = ci_parser_dests() - profile_parser_dests(name) - SHORTCUT_OMITTED_DESTS
    assert not missing, (
        f"`jmo {name}` does not define {sorted(missing)}, which `jmo ci` does. "
        "An absent dest reads as its consumer's getattr default, which is not "
        "necessarily the parser default -- that is exactly #870."
    )


@pytest.mark.parametrize("name", ["fast", "balanced", "full"])
def test_shared_dests_carry_the_same_default(name):
    """A dest both define but default differently is the same bug, quieter.

    `store_history` would have been caught by the presence check above; a flag
    that exists on both with opposite defaults would not.
    """
    ci = ci_parser_defaults()
    prof = profile_parser_defaults(name)
    disagree = {
        d: (prof[d], ci[d])
        for d in set(ci) & set(prof)
        # `cmd` is the subcommand's own name and is meant to differ.
        if d != "cmd" and prof[d] != ci[d]
    }
    assert not disagree, (
        f"`jmo {name}` and `jmo ci` disagree on defaults " f"(shortcut, ci): {disagree}"
    )


def test_omitted_dests_are_actually_omitted():
    """Negative control for SHORTCUT_OMITTED_DESTS.

    Without it the exception list could name dests the shortcut *does* define,
    silently widening what the guard above forgives.
    """
    defined = profile_parser_dests() & SHORTCUT_OMITTED_DESTS
    assert not defined, (
        f"{sorted(defined)} are in the omitted list but the parser defines "
        "them; remove them from SHORTCUT_OMITTED_DESTS"
    )
