"""What the wheel carries, and what a JMo installed from it can do.

The wheel is the documented install (`uv tool install jmo-security`), and it is
the one artifact no other test exercises: a source checkout, the editable dev
install and the Docker image all read files from a repository tree that a
wheel install does not have. That is how every `jmo tools` command from a
wheel raised FileNotFoundError on `versions.yaml` (#1511).

The wheel is built from a fresh copy of the packaging inputs, never in the
working tree: setuptools' `build/` and `*.egg-info/` caches there make a wheel
check pass vacuously (tests/unit/test_dist_build_cleans_first.py).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

# What setuptools reads to build the wheel, besides scripts/.
PACKAGING_INPUTS = (
    "pyproject.toml",
    "setup.py",
    "MANIFEST.in",
    "README.md",
    "LICENSE",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "THIRD_PARTY_LICENSES.md",
    "versions.yaml",
)

pytestmark = pytest.mark.slow


def _uv() -> str:
    uv = shutil.which("uv")
    assert uv, "uv builds this repository's wheel (CONTRIBUTING.md); put it on PATH"
    return uv


@pytest.fixture(scope="module")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    src = tmp_path_factory.mktemp("src")
    for name in PACKAGING_INPUTS:
        if (REPO_ROOT / name).is_file():
            shutil.copy2(REPO_ROOT / name, src / name)
    shutil.copytree(
        REPO_ROOT / "scripts",
        src / "scripts",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "node_modules"),
    )
    out = tmp_path_factory.mktemp("dist")
    # sdist first, then the wheel from the unpacked sdist: the release's route
    # (`python -m build`), and the one that needs MANIFEST.in.
    build = subprocess.run(
        [_uv(), "build", "--out-dir", str(out), str(src)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    assert build.returncode == 0, build.stderr[-3000:]
    (built,) = out.glob("*.whl")
    return built


@pytest.fixture(scope="module")
def installed_jmo(wheel: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The `jmo` console script of a venv holding only the wheel and its deps."""
    venv = tmp_path_factory.mktemp("venv")
    uv = _uv()
    subprocess.run(
        [uv, "venv", "--quiet", "--python", sys.executable, str(venv)],
        check=True,
        timeout=300,
    )
    bindir = venv / ("Scripts" if os.name == "nt" else "bin")
    python = bindir / ("python.exe" if os.name == "nt" else "python")
    subprocess.run(
        [uv, "pip", "install", "--quiet", "--python", str(python), str(wheel)],
        check=True,
        timeout=600,
    )
    return bindir / ("jmo.exe" if os.name == "nt" else "jmo")


def _run_jmo(jmo: Path, home: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the installed `jmo` where no repository is: a scratch HOME as cwd."""
    home.mkdir(exist_ok=True)
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    return subprocess.run(
        [str(jmo), *args],
        cwd=home,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )


def test_the_wheel_carries_the_tool_pins(wheel: Path) -> None:
    """`versions.yaml` ships as package data, byte for byte the root file."""
    with zipfile.ZipFile(wheel) as zf:
        assert "scripts/core/versions.yaml" in zf.namelist()
        packaged = zf.read("scripts/core/versions.yaml")
    assert packaged == (REPO_ROOT / "versions.yaml").read_bytes()


def test_an_installed_wheel_resolves_a_tool_pin(
    installed_jmo: Path, tmp_path: Path
) -> None:
    """`jmo tools check` and `tools install --dry-run` work from a wheel install,
    and the version they expect is the one versions.yaml pins."""
    pins = yaml.safe_load((REPO_ROOT / "versions.yaml").read_text(encoding="utf-8"))
    pinned = str(pins["binary_tools"]["opengrep"]["version"])
    home = tmp_path / "home"

    check = _run_jmo(installed_jmo, home, "tools", "check", "opengrep", "--json")
    assert "Traceback" not in check.stderr, check.stderr
    expected = json.loads(check.stdout)["tools"]["opengrep"]["expected_version"]
    assert expected == pinned

    dry = _run_jmo(installed_jmo, home, "tools", "install", "--dry-run", "opengrep")
    assert dry.returncode == 0, dry.stderr
    assert "Would install" in dry.stdout and "opengrep" in dry.stdout
