"""`make tools` installs every scanner through `jmo tools install` (#1562).

scripts/dev/install_tools.sh installed the scanners itself, from `latest`,
unpinned and unchecked, three of them by piping an install.sh from `main`,
and ZAP on Linux as a snap that jmo never looks for (`/snap/bin/zaproxy`).
Decided 2026-11-05: the script keeps only the developer prerequisites and
hands the scanners to `jmo tools install`, the one install path jmo reads,
which pins each one and checks its sha256.

The script runs for real, with every command it could install or download
through (sudo, apt-get, snap, brew, curl, jmo...) replaced by a stub that
records its arguments, so nothing is installed.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "dev" / "install_tools.sh"
STUBBED = (
    "sudo",
    "apt-get",
    "dpkg",
    "snap",
    "brew",
    "curl",
    "wget",
    "go",
    "pipx",
    "pip3",
    "jmo",
)

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("bash") is None,
    reason="the script's Linux branch, run under bash",
)


def _run(
    tmp_path: Path, *args: str
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    log = tmp_path / "calls.log"
    for name in STUBBED:
        stub = stubs / name
        stub.write_bytes(f'#!/bin/sh\necho "{name} $*" >> "{log}"\nexit 0\n'.encode())
        stub.chmod(0o755)
    # Present already, so the script has no prerequisite to fetch.
    for present in ("shfmt", "jq", "git"):
        stub = stubs / present
        stub.write_bytes(b"#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
    env = {
        "PATH": f"{stubs}:/usr/bin:/bin",
        "HOME": str(tmp_path / "home"),
        "JMO": str(stubs / "jmo"),
    }
    proc = subprocess.run(
        ["bash", str(SCRIPT), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return proc, calls


def test_the_scanners_are_installed_by_jmo_tools_install(tmp_path: Path) -> None:
    proc, calls = _run(tmp_path)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "jmo tools install --yes" in calls
    # Nothing else installs or downloads a scanner: no snap (ZAP was
    # `snap install zaproxy`), no curl or wget, no pip or pipx.
    assert not [
        c for c in calls if c.split()[0] in ("snap", "curl", "wget", "pipx", "pip3")
    ], calls
    assert not [c for c in calls if "zaproxy" in c or "checkov" in c], calls


def test_upgrade_updates_the_scanners_through_jmo(tmp_path: Path) -> None:
    proc, calls = _run(tmp_path, "--upgrade")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "jmo tools update --yes" in calls
    assert "jmo tools install --yes" not in calls
