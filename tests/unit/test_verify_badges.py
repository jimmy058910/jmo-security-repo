"""verify_badges.sh reaches its own fallbacks when a service answers with no version (#1417).

The script runs under `set -euo pipefail` and read each version with
`x=$(curl ... | grep/jq ...)`. When shields.io (or PyPI) answered without one, an
outage page say, the pipeline's last command exited non-zero, pipefail carried it
out of the substitution, and `set -e` ended the script on the assignment: its
"Could not parse badge version" warning never ran, and `quick-checks` went red on
a shields.io 503 (CI run 36806756044). A stub `curl` on PATH stands in for both
services here.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "dev" / "verify_badges.sh"
OUTAGE = "<html><body><h1>503 Service Unavailable</h1></body></html>"

pytestmark = [
    # `grep -oP` is GNU grep's; BSD grep (macOS) has no -P.
    pytest.mark.skipif(sys.platform != "linux", reason="GNU grep and bash"),
    pytest.mark.skipif(
        not all(shutil.which(tool) for tool in ("bash", "jq", "git")),
        reason="needs bash, jq and git",
    ),
]


def _local_version() -> str:
    for line in (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version = "):
            return line.split('"')[1]
    raise AssertionError("pyproject.toml has no version line")


def _run(tmp_path: Path, pypi_body: str, shields_body: str) -> tuple[int, str]:
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "pypi.body").write_bytes(pypi_body.encode())
    (stub / "shields.body").write_bytes(shields_body.encode())
    curl = stub / "curl"
    curl.write_bytes(
        b"#!/usr/bin/env bash\n"
        b'here="$(dirname "$0")"\n'
        b'for arg in "$@"; do\n'
        b'  case "$arg" in\n'
        b'    *pypi.org*) cat "$here/pypi.body"; exit 0 ;;\n'
        b'    *shields.io*) cat "$here/shields.body"; exit 0 ;;\n'
        b"  esac\n"
        b"done\n"
        b"exit 0\n"
    )
    curl.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{stub}{os.pathsep}{os.environ.get('PATH', '')}",
        # A feature branch: a version mismatch is not this test's subject.
        "GITHUB_HEAD_REF": "feature/badge-test",
    }
    env.pop("GITHUB_EVENT_PATH", None)
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    return result.returncode, result.stdout + result.stderr


def test_a_badge_with_no_version_warns_and_passes(tmp_path: Path) -> None:
    version = _local_version()
    rc, output = _run(tmp_path, f'{{"info": {{"version": "{version}"}}}}', OUTAGE)

    assert "Could not parse badge version" in output, output
    assert "PyPI matches local version" in output, output
    assert rc == 0, output


def test_a_badge_that_answers_still_passes(tmp_path: Path) -> None:
    """Control: the stub reaches the script, and a good badge reads as one."""
    version = _local_version()
    badge = f'<svg><text x="1">pypi</text><text x="2">v{version}</text></svg>'
    rc, output = _run(tmp_path, f'{{"info": {{"version": "{version}"}}}}', badge)

    assert "Badge matches PyPI version" in output, output
    assert rc == 0, output


def test_pypi_with_no_version_fails_saying_so(tmp_path: Path) -> None:
    """PyPI's version is the check itself, so missing it still fails, but on the
    script's own line rather than mid-assignment with nothing said."""
    rc, output = _run(tmp_path, OUTAGE, OUTAGE)

    assert "Failed to fetch PyPI version" in output, output
    assert rc == 1, output
