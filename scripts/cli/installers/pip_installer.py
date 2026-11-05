"""The pip command `jmo tools install` runs for a Python-packaged tool.

checkov, the one such scanner, installs into its own venv
(ToolInstaller._isolated_pip_install); this builds the command for the
interpreter it is given.
"""

from __future__ import annotations

import shutil
import subprocess
import sys


def pip_install_command(packages: list[str]) -> list[str]:
    """Build an install command that works in a uv-created virtualenv.

    `uv venv` does **not** install pip, so `sys.executable -m pip install ...`
    fails outright with

        No module named pip

    That has been the case for every pip-backed tool since the uv.lock migration
    (#683/#687) made `.venv` the project's standard environment: measured,
    `jmo tools install bandit yara prowler` failed with exactly that message
    while the tools themselves were perfectly installable.

    Prefer pip when it is genuinely present -- an isolated venv built by
    `python -m venv` does ship it, and pip is the more widely understood path --
    and fall back to `uv pip install --python <interpreter>`, which targets the
    same interpreter without needing pip inside it.
    """
    if _interpreter_has_pip(sys.executable):
        return [sys.executable, "-m", "pip", "install", "--quiet", *packages]

    uv = shutil.which("uv")
    if uv:
        return [uv, "pip", "install", "--python", sys.executable, "--quiet", *packages]

    # Neither available: return the pip form so the failure names the real
    # problem rather than "uv not found", which would send the reader the
    # wrong way.
    return [sys.executable, "-m", "pip", "install", "--quiet", *packages]


def _interpreter_has_pip(interpreter: str) -> bool:
    """Whether `interpreter -m pip` is importable. Cached per interpreter."""
    cached = _PIP_AVAILABLE.get(interpreter)
    if cached is not None:
        return cached

    try:
        probe = subprocess.run(
            [interpreter, "-c", "import pip"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        available = probe.returncode == 0
    except (OSError, subprocess.SubprocessError):
        available = False

    _PIP_AVAILABLE[interpreter] = available
    return available


_PIP_AVAILABLE: dict[str, bool] = {}
