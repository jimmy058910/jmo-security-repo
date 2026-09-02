"""The MCP import guard must name the installed mcp version and the real floor.

Measured 2026-09-01 with mcp 1.29.0 in the venv (semgrep's pin, dragged in by
#1101): `import scripts.jmo_mcp.jmo_server` raised

    MCP SDK not installed. Install with: pip install 'mcp[cli]>=1.0.0'

which is wrong twice -- the SDK *was* installed, and 1.29.0 already satisfies
>=1.0.0, so following the advice changes nothing. mcp 2.0 renamed FastMCP to
MCPServer with no shim; the floor JMo needs is 2.0.0 and the message has to
say what is installed so the reader can see the gap.

Run in a subprocess because the guard fires at import time and the module
builds its server on import; poisoning `sys.modules` in-process would have to
be unwound around every other MCP test.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_TOO_OLD = """
import sys, importlib.metadata as md
sys.modules["mcp.server"] = None
md.version = lambda name: "1.29.0" if name == "mcp" else None
"""

_ABSENT = """
import sys, importlib.metadata as md
sys.modules["mcp.server"] = None
def _absent(name):
    raise md.PackageNotFoundError(name)
md.version = _absent
"""


def _import_jmo_server_after(prelude: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-c", prelude + "\nimport scripts.jmo_mcp.jmo_server\n"],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert proc.returncode != 0, "the import should have raised"
    return proc.stderr


def test_a_too_old_sdk_reports_the_installed_version_and_the_floor():
    err = _import_jmo_server_after(_TOO_OLD)
    assert "1.29.0" in err
    assert ">=2.0.0" in err
    assert "not installed" not in err


def test_an_absent_sdk_still_says_not_installed_with_the_real_floor():
    err = _import_jmo_server_after(_ABSENT)
    assert "not installed" in err
    assert ">=2.0.0" in err
    assert ">=1.0.0" not in err
