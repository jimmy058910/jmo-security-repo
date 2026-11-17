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
    "docs/schemas/common_finding.v1.json",
)
# setup.py's SHIPPED_GLOBS: copied by pattern, so a new policy needs no edit here.
PACKAGING_GLOBS = ("policies/builtin/*.rego",)

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
            (src / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / name, src / name)
    for pattern in PACKAGING_GLOBS:
        for path in REPO_ROOT.glob(pattern):
            rel = path.relative_to(REPO_ROOT)
            (src / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, src / rel)
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


def test_the_wheel_carries_the_findings_schema(wheel: Path) -> None:
    """The CommonFinding schema ships as package data, byte for byte (#1350)."""
    member = "scripts/core/schemas/common_finding.v1.json"
    with zipfile.ZipFile(wheel) as zf:
        assert member in zf.namelist()
        packaged = zf.read(member)
    schema = REPO_ROOT / "docs" / "schemas" / "common_finding.v1.json"
    assert packaged == schema.read_bytes()


def test_an_installed_wheel_loads_the_findings_schema(
    installed_jmo: Path, tmp_path: Path
) -> None:
    """Before #1350 every installed JMo skipped schema validation: the
    validator looked for the schema at a docs/ path only a checkout has."""
    python = installed_jmo.with_name("python.exe" if os.name == "nt" else "python")
    probe = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "from scripts.core.schema_validator import load_schema; "
            "print(load_schema()['$id'])",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert probe.returncode == 0, probe.stderr
    assert "common_finding" in probe.stdout


def test_a_bare_install_validates_findings_against_the_schema(
    installed_jmo: Path, tmp_path: Path
) -> None:
    """jsonschema is a dependency, not the `reporting` extra (#1350, decided
    2026-11-05): without it the report skipped validation silently, logging
    nothing, on every install made the documented way."""
    python = installed_jmo.with_name("python.exe" if os.name == "nt" else "python")
    probe = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "from scripts.core.schema_validator import validate_finding; "
            "print(len(validate_finding({'schemaVersion': '1.2.0'})))",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert probe.returncode == 0, probe.stderr
    assert int(probe.stdout) > 0, "an empty finding passed validation"


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


def test_a_bare_install_runs_and_names_the_extra_yara_x_needs(
    installed_jmo: Path, tmp_path: Path
) -> None:
    """yara-x is the yara extra (#1577), so the bare wheel installs without it,
    as it must on platforms yara-x has no wheel for, and says how to add it."""
    home = tmp_path / "home"

    check = _run_jmo(installed_jmo, home, "tools", "check", "yara-x")
    assert "Traceback" not in check.stderr, check.stderr
    assert "MISSING" in check.stdout
    assert 'install "jmo-security[yara]"' in check.stdout

    # A default install leaves out what it cannot add (decided 2026-11-05), so
    # `jmo tools install && jmo scan` does not stop where the extra has no wheel.
    default = _run_jmo(installed_jmo, home, "tools", "install", "--dry-run")
    assert default.returncode == 0, default.stderr
    assert "yara-x" not in default.stdout

    # Named, it still fails and says why.
    install = _run_jmo(installed_jmo, home, "tools", "install", "yara-x")
    assert install.returncode != 0
    assert "Traceback" not in install.stderr, install.stderr
    assert 'install "jmo-security[yara]"' in install.stdout + install.stderr
    assert not (home / ".jmo" / "yara-rules").exists(), "rules fetched with no engine"


def _tracked_policies() -> dict[str, bytes]:
    policies = {
        p.name: p.read_bytes()
        for p in sorted((REPO_ROOT / "policies" / "builtin").glob("*.rego"))
    }
    assert "zero-secrets.rego" in policies, sorted(policies)
    return policies


def test_the_wheel_carries_every_builtin_policy(wheel: Path) -> None:
    """Every tracked policies/builtin/*.rego ships, byte for byte. v1.1.1 and
    dev at a4445b52 shipped none, so an installed jmo enforced no policy."""
    prefix = "scripts/core/policies/builtin/"
    with zipfile.ZipFile(wheel) as zf:
        packaged = {
            n[len(prefix) :]: zf.read(n)
            for n in zf.namelist()
            if n.startswith(prefix) and n.endswith(".rego")
        }
    tracked = _tracked_policies()
    assert sorted(packaged) == sorted(tracked)
    differing = sorted(n for n in tracked if packaged[n] != tracked[n])
    assert not differing, f"packaged policies differ from the tracked ones: {differing}"


def test_an_installed_wheel_resolves_its_builtin_policies(
    installed_jmo: Path, tmp_path: Path
) -> None:
    """The resolver finds the packaged copy, not a checkout: the probe runs
    isolated (-I) from a directory outside any repository."""
    python = installed_jmo.with_name("python.exe" if os.name == "nt" else "python")
    probe = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "from scripts.core.policy_engine import builtin_policies_dir as d; "
            "print(d()); print(*sorted(p.name for p in d().glob('*.rego')))",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert probe.returncode == 0, probe.stderr
    where, names = probe.stdout.splitlines()
    assert "site-packages" in where, where
    assert names.split() == sorted(_tracked_policies())


def _report_one_verified_secret(
    jmo: Path, root: Path, *, opa: str | None
) -> subprocess.CompletedProcess[str]:
    """`jmo report --policy zero-secrets` with enforcement on, over one
    verified trufflehog secret, run where no repository is. OPA is found only
    where this puts it: a scratch HOME's .jmo/bin, and PATH is the venv's."""
    home = root / "home"
    (home / ".jmo" / "bin").mkdir(parents=True)
    if opa:
        shutil.copy2(opa, home / ".jmo" / "bin" / Path(opa).name)
    results = root / "results"
    (results / "individual-repos" / "demo").mkdir(parents=True)
    (results / "individual-repos" / "demo" / "trufflehog.json").write_text(
        json.dumps(
            [
                {
                    "DetectorName": "Example",
                    "Verified": True,
                    "SourceMetadata": {
                        "Data": {"Filesystem": {"file": "demo.txt", "line": 1}}
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    cfg = root / "jmo.yml"
    cfg.write_text(
        "outputs: [json]\npolicy:\n  enabled: true\n  fail_on_violation: true\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "PATH": str(jmo.parent),
    }
    return subprocess.run(
        [str(jmo), "report", str(results), "--config", str(cfg)]
        + ["--policy", "zero-secrets"],
        cwd=home,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )


def test_an_installed_wheel_fails_closed_without_opa(
    installed_jmo: Path, tmp_path: Path
) -> None:
    """Enforcement on and no OPA: the policy was not evaluated, so exit 2 and
    say which policy and why, instead of a warning and exit 0."""
    run = _report_one_verified_secret(installed_jmo, tmp_path, opa=None)
    assert run.returncode == 2, run.stdout + run.stderr
    out = run.stdout + run.stderr
    assert "'zero-secrets' could not be evaluated" in out, out
    assert "OPA not installed" in out, out


@pytest.mark.requires_tools
def test_an_installed_wheel_enforces_zero_secrets(
    installed_jmo: Path, tmp_path: Path
) -> None:
    """The measurement the defect was found with: OPA present, enforcement on,
    one verified secret. The source checkout exited 1; the wheel exited 0."""
    from scripts.core.tool_utils import find_tool

    opa = find_tool("opa")
    if opa is None:
        pytest.skip("opa is not installed (jmo tools install opa)")
    run = _report_one_verified_secret(installed_jmo, tmp_path, opa=opa)
    assert run.returncode == 1, run.stdout + run.stderr
    verdict = json.loads(
        (tmp_path / "results" / "summaries" / "policy_results.json").read_text(
            encoding="utf-8"
        )
    )
    assert [(p["name"], p["passed"]) for p in verdict["policies"]] == [
        ("zero-secrets", False)
    ], verdict
