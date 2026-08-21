"""The exit-code contract in docs/CLI_REFERENCE.md, exercised against real runs.

Chunk 1 of the v1.1.0 audit noted there was no central exit-code contract to
validate against, and chunk 16 declined to change `jmo policy test` for that
reason (#925): it returned **1** both when a policy legitimately failed and when
the policy name was a typo, so a CI script could not tell a blocked release from
a run that proved nothing -- and the second is the dangerous one, because it
looks like a working gate.

The contract is now written down, and this exercises it:

    0  success
    1  ran, and the answer is negative (or a runtime error)
    2  usage error - the command was invoked incorrectly and did not run

Subcommands are taken from the parser, not restated: `MAIN_SUBCOMMANDS` was a
restated list and had drifted to 13 of 20 (#783).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.cli.jmo import build_parser

REPO = Path(__file__).resolve().parents[2]
CLI_REFERENCE = REPO / "docs" / "CLI_REFERENCE.md"

SUBCOMMANDS = sorted(build_parser()._subparsers._group_actions[0].choices)


def _run(*args: str, timeout: int = 25) -> subprocess.CompletedProcess:
    """Run the CLI in a subprocess.

    The timeout is deliberately below pytest-timeout's 60s Windows budget. If
    pytest's timer wins, its thread method kills the *test* thread but not the
    child, which becomes an orphan and multiplies across the parametrised cases
    -- see "CRITICAL: Windows Test Hang Prevention" in
    .claude/rules/testing.cross-platform.rules.md. Measured, each of these
    invocations takes well under a second.

    `errors="replace"` because bare `text=True` decodes with the parent's
    locale codec inside subprocess's reader thread, where the failure is
    swallowed and the captured output silently truncates.
    """
    env = dict(os.environ, JMO_NON_INTERACTIVE="1")
    return subprocess.run(
        [sys.executable, "-m", "scripts.cli.jmo", *args],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        cwd=str(REPO),
        env=env,
    )


def test_contract_table_exists():
    """The table this file exercises must be in the docs.

    Its absence is the reason #925 sat open: there was nothing to make
    `jmo policy test` consistent *with*.
    """
    text = CLI_REFERENCE.read_text(encoding="utf-8")
    assert "## Exit Codes" in text
    section = text[text.index("## Exit Codes") :]
    section = section[: section.index("## Commands")]
    for code in ("`0`", "`1`", "`2`"):
        assert code in section, f"contract table does not document {code}"
    # And no fourth code, which is what makes the table a contract.
    documented = set(re.findall(r"^\|\s*`?(\d+)`?\s*\|", section, re.MULTILINE))
    assert documented == {"0", "1", "2"}, documented


def test_subcommands_derived_not_restated():
    """Meta-guard for the parametrisation below."""
    assert len(SUBCOMMANDS) >= 20, SUBCOMMANDS
    for known in ("scan", "adapters", "attest", "verify", "setup", "validate"):
        assert known in SUBCOMMANDS


@pytest.mark.parametrize("subcommand", SUBCOMMANDS)
def test_help_exits_zero(subcommand):
    assert _run(subcommand, "--help").returncode == 0


@pytest.mark.parametrize("subcommand", SUBCOMMANDS)
def test_unknown_flag_is_a_usage_error(subcommand):
    assert _run(subcommand, "--definitely-not-a-flag-xyz").returncode == 2


def test_top_level_contract():
    assert _run("--help").returncode == 0
    assert _run("--version").returncode == 0
    assert _run().returncode == 2
    assert _run("no-such-subcommand-xyz").returncode == 2


@pytest.mark.parametrize(
    "args",
    [
        ("policy", "validate", "no-such-policy-xyz"),
        ("policy", "show", "no-such-policy-xyz"),
        ("policy", "install", "no-such-policy-xyz"),
        ("policy", "test", "no-such-policy-xyz", "--findings-file", "pyproject.toml"),
    ],
)
def test_policy_unknown_name_is_a_usage_error(args):
    """#925. These all returned 1, indistinguishable from a policy that failed."""
    assert _run(*args).returncode == 2


def test_policy_test_missing_findings_file_is_a_usage_error():
    result = _run(
        "policy", "test", "zero-secrets", "--findings-file", "no-such-file-xyz.json"
    )
    assert result.returncode == 2


@pytest.mark.parametrize("group", ["history", "trends"])
def test_group_command_without_a_subcommand_is_a_usage_error(group):
    """These printed "Error: Unknown <group> subcommand" and then exited 1.

    Printing a usage line and returning 1 claims the command ran and found a
    problem. Nothing ran. `policy`, `adapters` and `schedule` already exited 2.
    """
    result = _run(group)
    assert result.returncode == 2
    assert "Unknown" in (result.stdout + result.stderr)


def test_validate_unknown_category_is_a_usage_error():
    """`--category bogus` printed `0/0 PASS`, `Verdict: GO`, and exited 0."""
    result = _run("validate", "--category", "definitely-not-a-category")
    assert result.returncode == 2
    assert "Unknown category" in (result.stdout + result.stderr)


@pytest.mark.parametrize(
    "args",
    [
        ("attest", "no-such-file-xyz.json"),
        ("verify", "no-such-file-xyz.json"),
        ("verify", "pyproject.toml", "--attestation", "no-such-file-xyz.att.json"),
    ],
)
def test_attest_and_verify_absent_paths_are_usage_errors(args):
    """These returned 1, which is the code for "the check ran and said no".

    Nothing ran: there was no file to attest, or no attestation to check. A CI
    gate reading 1 as "this artifact failed verification" was being handed the
    same number for "you typed the filename wrong".
    """
    assert _run(*args).returncode == 2


def test_verify_signature_flags_without_a_signer_are_usage_errors():
    """A signature check needs a bundle *and* an expected signer.

    Half of one is not a weaker check, it is a different claim, so the partial
    invocations must not run and report a pass.
    """
    assert _run("verify", "pyproject.toml", "--rekor-check").returncode == 2
    assert _run("verify", "pyproject.toml", "--cert-identity", "x").returncode == 2


def test_attest_rekor_without_sign_is_a_usage_error():
    """It warned and exited 0, so a CI step asking for a transparency-log entry
    reported success without producing one."""
    assert _run("attest", "pyproject.toml", "--rekor").returncode == 2
