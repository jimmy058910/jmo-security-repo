#!/usr/bin/env python3
"""A real scan must account for every tool the matrix declares.

This is the acceptance criterion the scan core lacked. "It exited 0" is not
one: on a deliberately-vulnerable repository, a run once reported
``Policy evaluation complete: 2/2 passed`` and exit 0 while prowler, yara and
dependency-check had each failed and written nothing, leaving no record on any
stream. Five tools were unaccounted for and three were reported in two
contradictory states at once.

So this test runs a real ``jmo scan`` and reconciles the scan against its own
artifacts: every tool in ``TOOL_MATRIX`` - the default when nothing narrows the
list - must land in exactly one state (see
``scripts/dev/reconcile_scan_accounting.py``). Zero states is a silent
omission; two is the diagnostics disagreeing with themselves.

**Why this is not marked ``requires_tools``.** The invariant is
environment-independent - it holds with no tools installed (everything
``unresolved``), with a full local install (mixed), and inside a Docker image
(mostly ``output``). Only the *distribution* moves. Marking it
``requires_tools`` would exclude it from every CI job and forfeit the
protection entirely; ``slow`` keeps it in the PR shards
(``-m "not smoke and not requires_tools and not docker"``) while excusing it
from the quick coverage gate, which adds ``not slow``.

**Why the child runs in container mode.** Before v2.0.0 the host pre-flight
never emptied the scan: bandit, a dev dependency, resolved from the venv on
every machine, so at least one declared tool always reached the scanners. No
v2.0.0 matrix tool is present that way, and with none installed the host
pre-flight exits 1 before any target is scanned - this test would reconcile
nothing on a runner without scanners. So the child runs with
``DOCKER_CONTAINER=1``: pre-flight is skipped and every tool reaches the scan
core, installed or not, which is the path a Docker user takes. Container mode
also rejects a ``C:\\...`` ``--repo`` as MSYS-mangled
(``scan_orchestrator._detect_msys_path_mangling``), so the child runs from
``tmp_path`` with relative paths.

The host pre-flight this skips is covered elsewhere: dropping the missing tools
and continuing by ``tests/cli/test_jmo.py::TestScanPreflightAtEOF``
(``test_non_tty_proceeds_with_available_tools``), and the reconciler's reading
of its "Skipping N missing tool(s)" line by
``tests/unit/test_scan_accounting.py::test_parses_preflight_skip_list``.

**Never assert which state a tool is in.** The distribution is not portable:
a tool that runs here is ``unresolved`` on a runner without it. A test pinning
a state would pass on one machine and fail on another.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.core.tool_registry import TOOL_MATRIX
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
# The default tool timeout is 600s and `get_tool_timeout()` returns
# `max(default, tool_minimum)` - so a single long-running tool is allowed 600s
# or its TOOL_TIMEOUT_DEFAULTS floor. The original 280s budget here was
# calibrated to observed wall clock (17s with HOME/PATH stripped, 90s with 22
# tools installed) rather than to that worst case, and duly timed out on the
# ubuntu and macos shards, where the mix of installed tools differs from any
# developer box. A timeout is not a reconciliation failure - it reports nothing
# at all about accounting.
#
# `--timeout` alone is not enough, and the reason is worth recording:
# `get_tool_timeout()` returns `max(default, tool_minimum)`, so for a tool
# carrying a TOOL_TIMEOUT_DEFAULTS floor the flag cannot lower anything.
# Measured with `--timeout 30` on the pre-v2 matrix: a floored tool was still
# running at **5m30s**, which is what actually blew the old budget. A
# `per_tool` entry *does* take priority over the floor - measured, the same
# tool finished in 19s under a 15s cap - so the config below is the only lever
# that bounds every tool.
#
# The cap must clear the tools that are merely slow, or it manufactures
# failures. Measured at 30s: semgrep (natural runtime 47s on this fixture) was
# killed mid-run after writing its output file - so the reconciler correctly
# reported it **contradictory**, in `output` and `failed` at once. A cap that
# kills a healthy tool does not test accounting, it fabricates a defect. 120s
# cleared every tool measured here.
#
# Worst case becomes roughly ceil(matrix tools / 4 workers) * PER_TOOL_TIMEOUT_S
# plus startup, inside SCAN_BUDGET_S.
PER_TOOL_TIMEOUT_S = 120
SCAN_BUDGET_S = 420

# semgrep is excluded rather than capped (#907): its production default
# (`--config auto`) fetches its ruleset from semgrep.dev, so on a machine where
# semgrep is genuinely on PATH this test spawned a real, unmarked,
# network-blocking scan of its own -- and PER_TOOL_TIMEOUT_S caps it mid-fetch,
# producing the exact output-vs-failed contradiction described above. Skipping
# lands it in `skipped`, which is an accounted state, without this test
# depending on network access to pass.
SKIP_TOOLS = ("semgrep",)

# A capped-out tool is still *accounted* - `failed` is a state like any other,
# and this test asserts the invariant, never the distribution. That is what
# makes capping safe where shortening the budget was not: a timeout kills the
# scan and reports nothing, while a cap still produces a full reconciliation.


@pytest.mark.slow
@pytest.mark.timeout(600)  # > SCAN_BUDGET_S, so TimeoutExpired fires first and
# its diagnostics get printed; pytest-timeout would kill the test with none.
def test_default_scan_accounts_for_every_matrix_tool(tmp_path: Path) -> None:
    """Every tool in TOOL_MATRIX lands in exactly one state.

    The unnarrowed scan is the strongest case: every tool the product ships,
    the most opportunities for one to be dropped without a trace.
    """
    repo = _write_fixture_repo(tmp_path / "accounting-fixture")
    results_dir = tmp_path / "results"

    # Cap every declared tool. Listing all of them rather than just those with
    # floors keeps this correct if a floor is added to another tool later. The
    # file names no `tools:`, so the scan resolves to TOOL_MATRIX.
    cap_config = tmp_path / "jmo.yml"
    cap_config.write_bytes(
        (
            "per_tool:\n"
            + "".join(
                f"  {tool}:\n    timeout: {PER_TOOL_TIMEOUT_S}\n"
                for tool in TOOL_MATRIX
            )
        ).encode("utf-8")
    )

    log_path = tmp_path / "scan.err"
    # Every path is relative to the child's cwd, `tmp_path`: container mode
    # rejects a drive-letter `--repo` (see the module docstring).
    cmd = [
        sys.executable,
        "-u",
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        repo.name,
        "--results-dir",
        results_dir.name,
        # Keep the scan's own bound under this test's budget - see the
        # PER_TOOL_TIMEOUT_S comment above. Both levers: --timeout caps the
        # default, the config caps the floored tools it cannot reach.
        "--timeout",
        str(PER_TOOL_TIMEOUT_S),
        "--config",
        cap_config.name,
        "--skip-tools",
        *SKIP_TOOLS,
        # The `idle` diagnostic is emitted at DEBUG. Without this, a tool
        # with no matching files is genuinely unaccounted for.
        "--log-level",
        "DEBUG",
        # Point history at tmp_path. The suite defaulting to the
        # repo-relative .jmo/history.db is why 67% of the rows ever stored
        # there came from tests; a test that runs a real scan must not add
        # to that. Named even though the cwd already puts the default there.
        "--history-db",
        "history.db",
    ]

    try:
        proc = subprocess.run(
            cmd,
            cwd=tmp_path,
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
            # at all. Redirect it via the env vars Path.home() actually
            # reads: USERPROFILE on Windows (ntpath.expanduser), HOME on
            # Linux/macOS (posixpath.expanduser) -- each platform consults
            # only its own var and ignores the other, so setting just one
            # leaves the other platform's real config.yml exposed. This
            # test previously set USERPROFILE alone, which protected the
            # Windows box this fix was measured on and missed Linux CI
            # entirely, where it wrote to the real /home/runner/.jmo/
            # config.yml (#978 CI follow-up).
            #
            # DOCKER_CONTAINER skips the host pre-flight, so a runner with no
            # scanners installed still reaches the scan core (module
            # docstring).
            #
            # PYTHONPATH: with cwd = tmp_path, `-m scripts.cli.jmo` no longer
            # finds the package through the cwd, so without it the child
            # imports only where the project is pip-installed (CI is; WSL's
            # system python is not: "No module named 'scripts'").
            env={
                **os.environ,
                "PYTHONPATH": str(REPO_ROOT),
                "USERPROFILE": str(tmp_path),
                "HOME": str(tmp_path),
                "DOCKER_CONTAINER": "1",
            },
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

    declared = list(TOOL_MATRIX)
    counts, unparseable = parse_outputs(results_dir)
    result = reconcile(
        declared=declared,
        diags=parse_log(proc.stderr),
        output_counts=counts,
        unparseable=unparseable,
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
        f"The scan reported on names that are not tools in the matrix: "
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
