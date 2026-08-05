#!/usr/bin/env python3
"""Guard the scan-accounting reconciler: every declared tool, exactly one state.

`scripts/dev/reconcile_scan_accounting.py` is the acceptance instrument for the
silent-data-loss class this repo has repeatedly shipped: a scan that exits 0
while producing less than it found. Its verdict is derived from the scan's own
artifacts, never from the exit code.

These tests cover the *verdict logic* with fabricated inputs, so they can assert
the cases a healthy scanner never produces - a tool in zero states, a tool in
two, a name reported that is not in the profile. A reconciler that cannot fail
is worth nothing, and the only way to know it can is to hand it a broken scan.

The end-to-end half - that the reconciler's patterns still match what the
scanner actually emits - is `tests/integration/test_scan_accounting.py`, which
reconciles a real scan rather than a frozen fixture. That split is deliberate:
replaying a captured log would pin yesterday's message wording and stay green
while live scans went unaccounted.
"""

from __future__ import annotations

import pytest

from scripts.dev.reconcile_scan_accounting import (
    ACCOUNTED_STATES,
    Diagnostics,
    parse_log,
    reconcile,
)

# ---------------------------------------------------------------------------
# Verbatim diagnostics, copied from real scan logs rather than written to match
# the regexes. Paraphrasing these would make the parser tests circular: they
# would prove the patterns match text this file invented, which is exactly the
# property that does not matter.
# ---------------------------------------------------------------------------

LOG_PREFLIGHT_SKIP = (
    '{"ts": "2026-08-01T06:45:14.624359Z", "level": "WARN", "msg": '
    '"Skipping 6 missing tool(s): noseyparker, akto, scancode, falco, afl++, mobsf"}'
)
LOG_DEPENDENCY_MISSING = (
    '{"ts": "2026-08-01T10:38:46.608735Z", "level": "ERROR", "msg": '
    '"zap: requested but its dependency `docker` could not be found - it did NOT '
    "run and its findings are MISSING from this scan. Run `jmo tools check` to "
    "confirm installation, or pass --allow-missing-tools to record an explicit "
    'empty result."}'
)
LOG_EXECUTABLE_MISSING = (
    '{"ts": "2026-08-01T10:38:46.608735Z", "level": "ERROR", "msg": '
    '"trivy: requested but its executable could not be found - it did NOT '
    "run and its findings are MISSING from this scan. Run `jmo tools check` to "
    "confirm installation, or pass --allow-missing-tools to record an explicit "
    'empty result."}'
)
LOG_RUNTIME_NOT_FOUND = (
    '{"ts": "2026-08-01T10:39:30.258849Z", "level": "ERROR", "msg": '
    '"yara: its executable was not found at run time - it did NOT contribute '
    'findings to this scan (Tool not found: python:yara)"}'
)
LOG_RUNTIME_FAILURE = (
    '{"ts": "2026-08-01T10:39:30.279507Z", "level": "ERROR", "msg": '
    '"prowler: it failed - it did NOT contribute findings to this scan '
    '(Return code 2 not in (0, 1, 3))"}'
)
LOG_NO_OUTPUT = (
    '{"ts": "2026-08-02T01:27:32.866687Z", "level": "ERROR", "msg": '
    '"checkov-cicd: it exited with an accepted code but wrote no output - it did '
    "NOT contribute findings to this scan (Exited 0 (an accepted code) but wrote "
    'no output)"}'
)
LOG_UNROUTED = (
    '{"ts": "2026-08-01T10:38:46.497567Z", "level": "WARN", "msg": '
    '"Requested but applicable to no target type in this scan, so not run and '
    'contributing no findings: lynis, nuclei"}'
)
LOG_NOT_IMPLEMENTED = (
    '{"ts": "2026-08-01T10:38:46.608735Z", "level": "WARN", "msg": '
    '"Requested but not applicable to repository targets (no repository '
    'implementation): opa"}'
)
LOG_IDLE = (
    '{"ts": "2026-08-01T10:44:13.639063Z", "level": "DEBUG", "msg": '
    '"No matching files in terragoat for: noseyparker"}'
)


# ---------------------------------------------------------------------------
# The verdict: every declared tool in exactly one state
# ---------------------------------------------------------------------------


def test_tool_in_no_state_is_unaccounted() -> None:
    """A declared tool absent from every stream and artifact must fail the run.

    This is the whole point. Four of the seven defects fixed on this branch
    presented exactly this way: the tool was declared, never ran, and left no
    trace anywhere - while the scan exited 0.
    """
    result = reconcile(declared=["trivy"], diags=Diagnostics(), output_counts={})

    assert result.unaccounted == ["trivy"]
    assert result.never_mentioned == ["trivy"]
    assert not result.ok


def test_tool_in_two_states_is_contradictory() -> None:
    """A tool that both produced output and was called unimplemented is a bug.

    Measured on this repo: `_find_tool` recorded the *binary* rather than the
    tool, so checkov-cicd / semgrep-secrets / trivy-rbac were each reported as
    having "no repository implementation" in the same run that wrote all three
    of their output files.
    """
    result = reconcile(
        declared=["checkov-cicd"],
        diags=Diagnostics(not_impl=frozenset({"checkov-cicd"})),
        output_counts={"checkov-cicd": 12},
    )

    assert result.contradictory == ["checkov-cicd"]
    assert not result.ok


def test_manual_tool_that_is_also_unresolved_is_not_contradictory() -> None:
    """manual + unresolved is the correct pairing, not a disagreement.

    The four MANUAL_INSTALL_TOOLS are manual-by-design and therefore also
    absent. Counting that as a contradiction would make every deep scan fail
    forever, which is how a guard gets disabled instead of fixed.
    """
    result = reconcile(
        declared=["falco"],
        diags=Diagnostics(unresolved=frozenset({"falco"})),
        output_counts={},
        manual=frozenset({"falco"}),
    )

    assert result.contradictory == []
    assert result.ok


@pytest.mark.parametrize("state", ACCOUNTED_STATES)
def test_any_single_state_accounts_for_a_tool(state: str) -> None:
    """Each state alone is a complete account. None is second-class."""
    if state == "output":
        result = reconcile(["trivy"], Diagnostics(), {"trivy": 3})
    else:
        result = reconcile(["trivy"], Diagnostics(**{state: frozenset({"trivy"})}), {})

    assert result.states["trivy"] == [state]
    assert result.ok


def test_reported_tool_outside_the_profile_is_a_failure() -> None:
    """The scanner must name tools, not the binaries they happen to invoke.

    `docker` and `zap-baseline.py` were once reported as tools with missing
    findings. Neither is in any profile; both are implementation details of zap.
    """
    result = reconcile(
        declared=["zap"],
        diags=Diagnostics(unresolved=frozenset({"zap", "docker", "zap-baseline.py"})),
        output_counts={},
    )

    assert result.stray_reported == ["docker", "zap-baseline.py"]
    assert not result.ok


def test_output_file_for_a_name_outside_the_profile_is_a_failure() -> None:
    """An output file nothing declared is an unexplained artifact."""
    result = reconcile(
        declared=["trivy"],
        diags=Diagnostics(),
        output_counts={"trivy": 1, "mystery-tool": 4},
    )

    assert result.stray_output == ["mystery-tool"]
    assert not result.ok


def test_unparseable_output_is_a_failure() -> None:
    """A file that exists but does not parse is data loss, not success."""
    result = reconcile(
        declared=["trivy"],
        diags=Diagnostics(),
        output_counts={"trivy": 0},
        unparseable=frozenset({"trivy"}),
    )

    assert result.unparseable == ["trivy"]
    assert not result.ok


def test_failure_with_only_a_progress_glyph_is_reported_as_silent() -> None:
    """A tool whose only trace is a transient glyph is worse than unmentioned.

    The Rich progress display draws a red cross and then overwrites it; a
    non-TTY run (CI, cron, a detached scan) never renders it at all. Separating
    this from `never_mentioned` is what tells you whether the tool ran and its
    failure was discarded, or was dropped before it ever ran - different bugs
    with different fixes.
    """
    result = reconcile(
        declared=["prowler"],
        diags=Diagnostics(tick_fail=frozenset({"prowler"})),
        output_counts={},
    )

    assert result.silent_fail == ["prowler"]
    assert result.never_mentioned == []
    assert not result.ok


def test_fully_accounted_scan_passes() -> None:
    """The healthy case: every tool in exactly one state, verdict PASS."""
    result = reconcile(
        declared=["trivy", "opa", "lynis", "falco", "prowler"],
        diags=Diagnostics(
            not_impl=frozenset({"opa"}),
            unrouted=frozenset({"lynis"}),
            unresolved=frozenset({"falco"}),
            failed=frozenset({"prowler"}),
        ),
        output_counts={"trivy": 7},
        manual=frozenset({"falco"}),
    )

    assert result.unaccounted == []
    assert result.contradictory == []
    assert result.ok


# ---------------------------------------------------------------------------
# The parser: the scanner's own diagnostics, verbatim
# ---------------------------------------------------------------------------


def test_parses_preflight_skip_list() -> None:
    """Pre-flight drops every missing tool in one message, comma-separated."""
    diags = parse_log(LOG_PREFLIGHT_SKIP)

    assert diags.unresolved == frozenset(
        {"noseyparker", "akto", "scancode", "falco", "afl++", "mobsf"}
    )


def test_parses_missing_dependency_as_unresolved() -> None:
    """zap is unresolved when docker is absent, and zap is the tool named."""
    diags = parse_log(LOG_DEPENDENCY_MISSING)

    assert diags.unresolved == frozenset({"zap"})


def test_parses_missing_executable_as_unresolved() -> None:
    diags = parse_log(LOG_EXECUTABLE_MISSING)

    assert diags.unresolved == frozenset({"trivy"})


def test_parses_runtime_resolution_failure_as_unresolved() -> None:
    """Resolved at pre-flight, unfindable at run time - still unresolved."""
    diags = parse_log(LOG_RUNTIME_NOT_FOUND)

    assert diags.unresolved == frozenset({"yara"})


def test_parses_runtime_failure() -> None:
    diags = parse_log(LOG_RUNTIME_FAILURE)

    assert diags.failed == frozenset({"prowler"})


def test_parses_accepted_exit_code_with_no_output() -> None:
    """Exit 0 and nothing written is the #700 class - it must not read as success."""
    diags = parse_log(LOG_NO_OUTPUT)

    assert diags.no_output == frozenset({"checkov-cicd"})
    assert diags.failed == frozenset()


def test_parses_unrouted_list() -> None:
    diags = parse_log(LOG_UNROUTED)

    assert diags.unrouted == frozenset({"lynis", "nuclei"})


def test_parses_not_implemented_list() -> None:
    diags = parse_log(LOG_NOT_IMPLEMENTED)

    assert diags.not_impl == frozenset({"opa"})


def test_parses_idle() -> None:
    """Emitted at DEBUG, and unreachable at any flag setting until this branch."""
    diags = parse_log(LOG_IDLE)

    assert diags.idle == frozenset({"noseyparker"})


def test_diagnostic_is_found_when_a_progress_spinner_shares_its_line() -> None:
    """Rich writes progress frames to stderr with no newline.

    A real run puts hundreds of in-place spinner frames and then a JSON
    diagnostic on one physical line. Parsing the log as line-delimited JSON
    therefore drops that diagnostic entirely and reports its tool as
    unaccounted. The parser must scan the whole text.
    """
    spinner = "".join(
        f"[16/22] ⠳ semgrep ({n}s) [72%]" + " " * 8 for n in range(20, 44)
    )
    log = f"{spinner}{LOG_RUNTIME_FAILURE}\n"

    diags = parse_log(log)

    assert diags.failed == frozenset({"prowler"})


def test_progress_glyphs_are_not_mistaken_for_durable_accounts() -> None:
    """A green tick is a UI artifact; it must not satisfy the invariant.

    If `[3/9] ✓ trivy` counted as an account, a tool that ticked green and then
    wrote nothing would pass - which is the exact failure the reconciler exists
    to catch.
    """
    diags = parse_log("[3/9] ✓ trivy [33%]\n")

    assert diags.tick_ok == frozenset({"trivy"})
    result = reconcile(declared=["trivy"], diags=diags, output_counts={})
    assert result.unaccounted == ["trivy"]
    assert not result.ok
