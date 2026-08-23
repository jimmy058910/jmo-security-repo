#!/usr/bin/env python3
"""A real scan must account for every tool its profile declares.

This is the acceptance criterion the scan core lacked. "It exited 0" is not
one: on a deliberately-vulnerable repository, a run once reported
``Policy evaluation complete: 2/2 passed`` and exit 0 while prowler, yara and
dependency-check had each failed and written nothing, leaving no record on any
stream. Five tools were unaccounted for and three were reported in two
contradictory states at once.

So this test runs a real ``jmo scan`` and reconciles the scan against its own
artifacts: every tool declared by the profile must land in exactly one state
(see ``scripts/dev/reconcile_scan_accounting.py``). Zero states is a silent
omission; two is the diagnostics disagreeing with themselves.

**Why this is not marked ``requires_tools``.** The invariant is
environment-independent - it holds with no tools installed (everything
``unresolved``), with a full local install (mixed), and inside a Docker image
(mostly ``output``). Only the *distribution* moves. Measured on this fixture:
28/28 accounted in 90s with 22 tools installed, and 28/28 accounted in 17s with
``HOME`` and ``PATH`` stripped. Marking it ``requires_tools`` would exclude it
from every CI job and forfeit the protection entirely; ``slow`` keeps it in the
PR shards (``-m "not smoke and not requires_tools and not docker"``) while
excusing it from the quick coverage gate, which adds ``not slow``.

**Never assert which state a tool is in.** The distribution is not portable:
``opa`` is ``not_impl`` locally but ``unresolved`` in CI, because a missing
binary is dropped in pre-flight before routing is ever consulted. A test
pinning that would pass here and fail in CI.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.core.tool_registry import MANUAL_INSTALL_TOOLS, PROFILE_TOOLS
from scripts.dev.reconcile_scan_accounting import parse_log, parse_outputs, reconcile

REPO_ROOT = Path(__file__).resolve().parents[2]

# Deliberately vulnerable, and deliberately narrow: Terraform, a Dockerfile,
# Python and a JS manifest, with no shell or Go sources at all. The omissions
# matter as much as the contents - a tool with nothing to look at must report
# itself idle rather than vanish.
FIXTURE_FILES = {
    "main.tf": (
        'resource "aws_s3_bucket" "b" {\n'
        '  bucket = "accounting-fixture"\n'
        '  acl    = "public-read"\n'
        "}\n"
    ),
    "Dockerfile": "FROM ubuntu:latest\nRUN apt-get update\nUSER root\n",
    "app.py": (
        "import subprocess\n"
        "password = 'hardcoded123'\n"
        "subprocess.call('ls', shell=True)\n"
    ),
    "package.json": (
        '{"name": "fixture", "version": "1.0.0", '
        '"dependencies": {"lodash": "4.17.11"}}\n'
    ),
}


def _write_fixture_repo(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, body in FIXTURE_FILES.items():
        # write_bytes, not write_text: write_text opens with newline=None and
        # translates \n to \r\n on Windows, which changes what the tools parse.
        (root / name).write_bytes(body.encode("utf-8"))
    return root


# The scan must bound itself *below* the budget this test gives it, or the test
# measures the runner's tool inventory instead of the scan's accounting.
#
# `deep`'s default tool timeout is 600s and `get_tool_timeout()` returns
# `max(default, tool_minimum)` with minimums up to 1200s (dependency-check,
# scancode) - so a single long-running tool is allowed 600-1200s. The original
# 280s budget here was calibrated to observed wall clock (17s with HOME/PATH
# stripped, 90s with 22 tools installed) rather than to that worst case, and
# duly timed out on the ubuntu and macos shards, where the mix of installed
# tools differs from any developer box. A timeout is not a reconciliation
# failure - it reports nothing at all about accounting.
#
# `--timeout` alone is not enough, and the reason is worth recording:
# `get_tool_timeout()` returns `max(default, tool_minimum)`, so for the six
# tools carrying a TOOL_TIMEOUT_DEFAULTS floor (cdxgen 600, prowler 600, zap
# 900, horusec 900, dependency-check 1200, scancode 1200) the flag cannot lower
# anything. Measured with `--timeout 30`: dependency-check was still running
# its first-time NVD sync at **5m30s**, which is what actually blew the old
# budget. A `per_tool` entry *does* take priority over the floor - measured, the
# same tool finished in 19s under a 15s cap - so the config below is the only
# lever that bounds all 28.
#
# The cap must clear the tools that are merely slow, or it manufactures
# failures. Measured at 30s: semgrep (natural runtime 47s on this fixture) and
# dependency-check were both killed mid-run, and each had already written its
# output file - so the reconciler correctly reported them **contradictory**,
# in `output` and `failed` at once. A cap that kills a healthy tool does not
# test accounting, it fabricates a defect. 120s clears every tool measured
# here; the whole 22-tool scan is ~90s.
#
# Worst case becomes roughly ceil(27 tools / 4 workers) * PER_TOOL_TIMEOUT_S
# plus startup; measured runtime is ~2 min, well inside SCAN_BUDGET_S.
PER_TOOL_TIMEOUT_S = 120
SCAN_BUDGET_S = 420

# dependency-check is excluded rather than capped. Its first run performs a
# full NVD database sync - measured at 5m30s and still going - so *any*
# workable cap kills it mid-write and produces the contradiction described
# above. Skipping lands it in `skipped`, which is an accounted state and keeps
# the invariant total at 28; §11e's reference PASS run was configured the same
# way for the same reason. The unbounded first sync is a known open issue
# (it likely wants an NVD API key), not something this test should absorb.
SKIP_TOOLS = ("dependency-check",)

# A capped-out tool is still *accounted* - `failed` is a state like any other,
# and this test asserts the invariant, never the distribution. That is what
# makes capping safe where shortening the budget was not: a timeout kills the
# scan and reports nothing, while a cap still produces a full reconciliation.


@pytest.mark.slow
@pytest.mark.timeout(600)  # > SCAN_BUDGET_S, so TimeoutExpired fires first and
# its diagnostics get printed; pytest-timeout would kill the test with none.
def test_deep_scan_accounts_for_every_declared_tool(tmp_path: Path) -> None:
    """Every tool in the deep profile lands in exactly one state.

    ``deep`` is the strongest case: 28 declared tools, the most opportunities
    for one to be dropped without a trace.
    """
    repo = _write_fixture_repo(tmp_path / "accounting-fixture")
    results_dir = tmp_path / "results"

    # Cap every declared tool. Listing all 28 rather than just the six with
    # floors keeps this correct if a floor is added to another tool later.
    cap_config = tmp_path / "jmo.yml"
    cap_config.write_bytes(
        (
            "per_tool:\n"
            + "".join(
                f"  {tool}:\n    timeout: {PER_TOOL_TIMEOUT_S}\n"
                for tool in PROFILE_TOOLS["deep"]
            )
        ).encode("utf-8")
    )

    log_path = tmp_path / "scan.err"
    cmd = [
        sys.executable,
        "-u",
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(repo),
        "--results-dir",
        str(results_dir),
        "--profile-name",
        "deep",
        # Keep the scan's own bound under this test's budget - see the
        # PER_TOOL_TIMEOUT_S comment above. Both levers: --timeout caps the
        # profile default, the config caps the six tools it cannot reach.
        "--timeout",
        str(PER_TOOL_TIMEOUT_S),
        "--config",
        str(cap_config),
        "--skip-tools",
        *SKIP_TOOLS,
        # The `idle` diagnostic is emitted at DEBUG. Without this, a tool
        # with no matching files is genuinely unaccounted for.
        "--log-level",
        "DEBUG",
        # Point history at tmp_path. The suite defaulting to the
        # repo-relative .jmo/history.db is why 67% of the rows ever stored
        # there came from tests; a test that runs a real scan must not add
        # to that.
        "--history-db",
        str(tmp_path / "history.db"),
    ]

    try:
        proc = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            capture_output=True,
            # Not text=True: that decodes with the parent's locale codec, which
            # on Windows loses captured output inside a subprocess reader
            # thread. The diagnostics are ASCII, so replace-on-error is
            # lossless for them.
            encoding="utf-8",
            errors="replace",
            # The pre-flight prompts guard on sys.stdin.isatty(), which returns
            # True at EOF under Git Bash. A scan reading a closed stdin used to
            # take the Cancel branch and produce no results directory at all.
            stdin=subprocess.DEVNULL,
            timeout=SCAN_BUDGET_S,
            # `--history-db` above redirects the scan's DB write, but
            # `cmd_scan` also unconditionally calls `_show_kofi_reminder()`
            # (#933), which resolves `Path.home()` with no injection point
            # at all. Redirect it via the env var Path.home() actually reads
            # on Windows (ntpath.expanduser -> USERPROFILE).
            env={**os.environ, "USERPROFILE": str(tmp_path)},
        )
    except subprocess.TimeoutExpired as exc:
        # `capture_output=True` means the only copy of what the scan managed to
        # say lives on this exception. Letting it propagate discards that and
        # reports the command line instead - which is what the ubuntu and macos
        # shards did, leaving a timeout with no indication of which tool was
        # still running. Same failure mode as the tool stderr that ToolRunner
        # captured and nothing read.
        partial = exc.stderr or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        log_path.write_bytes(partial.encode("utf-8", errors="replace"))
        pytest.fail(
            f"The scan did not finish within {SCAN_BUDGET_S}s, so it reported "
            f"nothing about its own accounting.\n"
            f"Per-tool cap was {PER_TOOL_TIMEOUT_S}s, so a tool exceeding it "
            f"has a minimum in TOOL_TIMEOUT_DEFAULTS that --timeout cannot "
            f"lower.\n"
            f"Full log: {log_path}\n"
            f"Last 3000 chars of the scan's stderr:\n{partial[-3000:]}",
            pytrace=False,
        )

    # Keep the evidence next to the results so a CI artifact carries it.
    log_path.write_bytes(proc.stderr.encode("utf-8", errors="replace"))

    assert results_dir.exists(), (
        f"Scan produced no results directory (exit {proc.returncode}). "
        f"stderr: {proc.stderr[-2000:]}"
    )

    declared = list(PROFILE_TOOLS["deep"])
    counts, unparseable = parse_outputs(results_dir)
    result = reconcile(
        declared=declared,
        diags=parse_log(proc.stderr),
        output_counts=counts,
        unparseable=unparseable,
        manual=frozenset(MANUAL_INSTALL_TOOLS),
    )

    assert result.never_mentioned == [], (
        f"{len(result.never_mentioned)} declared tool(s) appear in no stream and "
        f"no artifact: {result.never_mentioned}. The scan omitted them silently. "
        f"Full log: {log_path}"
    )
    assert result.silent_fail == [], (
        f"{len(result.silent_fail)} tool(s) failed leaving only a transient "
        f"progress glyph: {result.silent_fail}. A non-TTY run records nothing at "
        f"all. Full log: {log_path}"
    )
    assert result.contradictory == [], (
        f"{len(result.contradictory)} tool(s) were reported in two states at "
        f"once: {result.contradictory}. The scan's own diagnostics disagree. "
        f"Full log: {log_path}"
    )
    assert result.stray_reported == [], (
        f"The scan reported on names that are not tools in the profile: "
        f"{result.stray_reported}. Report the tool, not the binary it invokes. "
        f"Full log: {log_path}"
    )
    assert result.stray_output == [], (
        f"Output files exist for names nothing declared: {result.stray_output}. "
        f"Full log: {log_path}"
    )
    assert result.unparseable == [], (
        f"Output files exist but do not parse: {result.unparseable}. An "
        f"unreadable file is data loss, not a successful tool run."
    )

    # Belt and braces: the invariant restated as a whole, so a state added to
    # the reconciler without a matching assertion above still fails here.
    assert result.ok, f"Scan did not fully account for itself. Full log: {log_path}"
    assert len(result.states) == len(declared)
