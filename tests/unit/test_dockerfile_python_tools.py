"""The image installs checkov into a virtual environment of its own (#1436).

On an Ubuntu 26.04 base, `pip install --break-system-packages checkov` failed
the build: checkov needs a `packaging` other than the one Debian installed, and
pip cannot uninstall a distribution's package ("no RECORD file"). Dependabot's
base-image bump (#1268) was closed for it. A venv never has to uninstall one,
and it is the shape `jmo tools install` gives checkov (ISOLATED_TOOLS).

A Dockerfile line is not a build: docker-smoke builds this one, and the 26.04
build is measured by hand. This guards the shape between those runs.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_instructions() -> list[str]:
    """Each RUN instruction of the Dockerfile, its continuation lines joined."""
    text = (REPO_ROOT / "Dockerfile").read_bytes().decode("utf-8")
    joined = re.sub(r"\\\n", " ", text)
    return [
        line.strip() for line in joined.splitlines() if line.strip().startswith("RUN ")
    ]


def test_checkov_is_installed_by_a_venvs_own_pip() -> None:
    (install,) = [r for r in _run_instructions() if "checkov==" in r]

    assert "--break-system-packages" not in install
    venv = re.search(r"python3 -m venv (\S+)", install)
    assert venv, install
    assert f"{venv.group(1)}/bin/pip install" in install
    assert re.search(
        rf"ln -s {re.escape(venv.group(1))}/bin/checkov /usr/local/bin/checkov", install
    )


def test_the_runtime_installs_the_venv_module() -> None:
    # Ubuntu's python3 has no ensurepip without python3-venv, so
    # `python3 -m venv` fails without it.
    assert any(
        "apt-get install" in r and "python3-venv" in r for r in _run_instructions()
    )
