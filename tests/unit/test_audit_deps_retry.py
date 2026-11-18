"""The dependency audit retries an audit that did not finish, never a finding (#1642).

Dev's push CI 43664484350 (2026-11-14) failed quick-checks on one
`ReadTimeout ... (read timeout=15)` from pypi.org: no advisory was found or
missed, and a rerun passed unchanged. pip-audit exits 1 for that and for a real
finding alike, so `scripts/dev/audit_deps.sh` tells them apart by the summary a
finished audit prints, and the audit step runs last in quick-checks, so a
network failure no longer skips the nine local checks that came after it.

These run the real script, as CI does, against stand-ins for `uv` and
`pip-audit` on PATH.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "dev" / "audit_deps.sh"
CI = ROOT / ".github" / "workflows" / "ci.yml"
AUDIT_STEP = "Audit Python dependencies for vulnerabilities"

needs_bash = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None,
    reason="the audit runs on ubuntu-latest and in the pre-commit hook, as bash",
)

# What pip-audit 2.10.1 prints in each case (its _cli.py; the timeout line is
# the one in 43664484350's log).
OUTCOMES = {
    "timeout": (
        1,
        "",
        "requests.exceptions.ReadTimeout: HTTPSConnectionPool(host='pypi.org', "
        "port=443): Read timed out. (read timeout=15)",
    ),
    "finding": (
        1,
        "Name    Version ID             Fix Versions\njinja2 3.1.0   GHSA-xxxx 3.1.6",
        "Found 1 known vulnerability in 1 package",
    ),
    "clean": (0, "", "No known vulnerabilities found, 1 ignored"),
}


def _fake(path: Path, body: str) -> None:
    path.write_bytes(("#!/usr/bin/env bash\n" + body).encode())
    path.chmod(0o755)


def _audit(
    tmp_path: Path, outcomes: list[str]
) -> tuple[subprocess.CompletedProcess, list[str]]:
    """Run audit_deps.sh with pip-audit answering `outcomes`, one per call;
    return the run and the argv of each pip-audit call."""
    # A copy read through universal newlines, as a CRLF checkout must be: bash
    # reads a `\r` as part of each command.
    repo = tmp_path / "repo"
    (repo / "scripts" / "dev").mkdir(parents=True)
    script = repo / "scripts" / "dev" / "audit_deps.sh"
    script.write_bytes(SCRIPT.read_text(encoding="utf-8").encode())

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # `uv export ... --output-file F` writes the requirements file.
    _fake(
        bin_dir / "uv",
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--output-file" ]; then echo "jinja2==3.1.0" > "$2"; fi\n'
        "  shift\n"
        "done\n",
    )
    state = tmp_path / "state"
    for i, name in enumerate(outcomes, start=1):
        rc, out, err = OUTCOMES[name]
        (state / str(i)).mkdir(parents=True)
        (state / str(i) / "rc").write_bytes(f"{rc}\n".encode())
        (state / str(i) / "out").write_bytes(out.encode())
        (state / str(i) / "err").write_bytes(err.encode())
    calls = tmp_path / "calls"
    _fake(
        bin_dir / "pip-audit",
        f'n=$(( $(ls "{calls}" 2>/dev/null | wc -l) + 1 ))\n'
        f'mkdir -p "{calls}"; echo "$*" > "{calls}/$n"\n'
        f'd="{state}/$n"\n'
        'cat "$d/out"; cat "$d/err" >&2\n'
        'exit "$(cat "$d/rc")"\n',
    )
    run = subprocess.run(
        ["bash", str(script)],
        env={
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "JMO_AUDIT_RETRY_DELAY_S": "0",
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    argv = (
        [
            (calls / str(i)).read_text(encoding="utf-8").strip()
            for i in range(1, len(list(calls.iterdir())) + 1)
        ]
        if calls.is_dir()
        else []
    )
    return run, argv


@needs_bash
def test_a_timed_out_audit_is_retried_and_its_pass_is_a_pass(tmp_path) -> None:
    run, argv = _audit(tmp_path, ["timeout", "clean"])
    assert run.returncode == 0, run.stdout + run.stderr
    assert len(argv) == 2
    assert "retrying" in run.stderr
    # The socket timeout is raised from pip-audit's 15 s, and the one ignore
    # with no fix version survives the rewrite (test_dep_audit_drift.py).
    assert all(
        "--timeout 60" in a and "--ignore-vuln PYSEC-2025-183" in a for a in argv
    )


@needs_bash
def test_a_finding_fails_at_once_and_is_not_retried(tmp_path) -> None:
    run, argv = _audit(tmp_path, ["finding", "clean"])
    assert run.returncode == 1
    assert len(argv) == 1, "a finding was retried, so a second try could hide it"
    assert "Found 1 known vulnerability" in run.stdout


@needs_bash
def test_a_finding_after_a_timeout_still_fails(tmp_path) -> None:
    run, argv = _audit(tmp_path, ["timeout", "finding"])
    assert run.returncode == 1
    assert len(argv) == 2


@needs_bash
def test_an_audit_that_never_finishes_fails_after_three_tries(tmp_path) -> None:
    run, argv = _audit(tmp_path, ["timeout", "timeout", "timeout", "clean"])
    assert run.returncode == 1
    assert len(argv) == 3
    assert "did not finish in 3 attempts" in run.stderr


@needs_bash
def test_a_clean_audit_runs_once(tmp_path) -> None:
    run, argv = _audit(tmp_path, ["clean"])
    assert run.returncode == 0, run.stdout + run.stderr
    assert len(argv) == 1


def test_the_audit_runs_last_in_quick_checks_whatever_failed_before_it() -> None:
    steps = yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]["quick-checks"][
        "steps"
    ]
    names = [s.get("name") for s in steps]
    assert names[-1] == AUDIT_STEP, names
    # !cancelled(), not always(): a cancelled run stops here too. Without it, a
    # failed step before the audit (the badge check is red on purpose on a
    # release commit) would skip the audit instead.
    assert steps[-1]["if"] == "${{ !cancelled() }}"
    assert "scripts/dev/audit_deps.sh" in steps[-1]["run"]
