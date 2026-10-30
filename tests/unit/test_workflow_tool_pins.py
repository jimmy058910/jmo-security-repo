"""The workflows read their tool versions from versions.yaml; none carries a copy.

`maintenance.yml`'s weekly tool update bumps versions.yaml and the Dockerfile,
then opens a PR. Its token may not push `.github/workflows/`, so a pin copied
into a workflow was one that PR could never move: every bump of a
workflow-pinned tool left it out of sync until someone pushed the edit by hand
(#1470; `e31bc870` on #1469 was one). Before that, `--sync` had not seen one
copy at all: `ci.yml`'s quick-checks held trufflehog as `v="3.94.3"` while
versions.yaml said 3.99.4.

So the workflows read their pins at run time through `scripts/dev/tool_pins.py`,
and `update_versions.py --sync` refuses a copy. These tests, and `--sync
--dry-run` in ci.yml's quick-checks, are the checks every pull request gets.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts.dev import tool_pins, update_versions

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PINS_OUTPUT = re.compile(r"steps\.pins\.outputs\.([A-Za-z0-9_]+)")


def _registry() -> dict[str, dict]:
    data = yaml.safe_load((REPO_ROOT / "versions.yaml").read_text(encoding="utf-8"))
    return {
        tool: info
        for section in tool_pins.PINNED_SECTIONS
        for tool, info in (data.get(section) or {}).items()
    }


def _copies_in(tmp_path: Path, name: str, text: str) -> list[str]:
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8"))
    return update_versions.find_workflow_literal_pins(
        update_versions.load_versions(), [path]
    )


# --- the reader the workflows run ----------------------------------------------


def test_tool_pins_prints_one_line_per_registry_entry(tmp_path: Path):
    """The contract a workflow relies on: every pin, as `NAME_VERSION=x.y.z`.

    Run as the workflows run it, from another directory, so a dependency on the
    working directory or on the project venv's import path would show here.
    """
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "dev" / "tool_pins.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    for line in lines:
        assert re.fullmatch(r"[A-Z][A-Z0-9_]*_VERSION=[0-9]+(\.[0-9]+)*", line), line

    printed = dict(line.split("=", 1) for line in lines)
    registry = _registry()
    expected = {
        f"{tool_pins.VERSION_VAR_ALIASES.get(tool, tool.upper())}_VERSION": info[
            "version"
        ]
        for tool, info in registry.items()
    }
    assert printed == expected
    # Two entries sharing a name would collapse into one line.
    assert len(lines) == len(registry)


@pytest.mark.parametrize(
    ("entry", "why"),
    [
        ('trivy:\n    version: "0.74.0\\nEVIL=1"', "a newline"),
        ("trivy:\n    version: 2.15", "a float"),
        ("trivy:\n    version: latest", "not a version"),
        ("new-tool:\n    version: 1.0.0", "no shell name"),
    ],
)
def test_an_unusable_entry_prints_nothing_and_fails(
    tmp_path: Path, monkeypatch, capsys, entry: str, why: str
):
    """A value written into $GITHUB_OUTPUT must not be able to add a line to it.

    And a failure must print nothing at all, so the step fails without leaving
    a half-written set of outputs behind.
    """
    bad = tmp_path / "versions.yaml"
    bad.write_bytes(
        f"binary_tools:\n  syft:\n    version: 1.55.0\n  {entry}\n".encode()
    )
    monkeypatch.setattr(tool_pins, "VERSIONS_YAML", bad)

    assert tool_pins.main() == 1, why
    assert capsys.readouterr().out == ""


# --- no copy in any workflow -----------------------------------------------------


def test_the_checked_files_include_every_workflow_and_local_action():
    """An empty glob would make the next test pass without looking at anything."""
    # Relative to the module's own root, which is not resolve()d: through a
    # junction or symlink the two roots differ.
    root = update_versions.REPO_ROOT
    checked = {
        p.relative_to(root).as_posix() for p in update_versions._workflow_files()
    }
    on_disk = {
        p.relative_to(root).as_posix()
        for p in (root / ".github" / "workflows").glob("*.y*ml")
    }
    assert on_disk <= checked
    assert {
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
        ".github/workflows/scheduled.yml",
        ".github/actions/setup-python-jmo/action.yml",
    } <= checked


def test_no_workflow_or_action_carries_a_copy_of_a_pin():
    copies = update_versions.find_workflow_literal_pins(update_versions.load_versions())
    assert not copies, (
        "Tool versions hard-coded under .github/. The weekly tool-update PR "
        "cannot change these files, so read them from versions.yaml with a "
        '`python3 scripts/dev/tool_pins.py >> "$GITHUB_OUTPUT"` step '
        "(id: pins) and `${{ steps.pins.outputs.NAME }}` (#1470):\n  "
        + "\n  ".join(copies)
    )


# Each form a copy has taken or could take, put back into the real file. If the
# guard misses one, the parametrized case says which.
MUTATIONS = [
    pytest.param(
        "ci.yml",
        "TRIVY_VERSION: ${{ steps.pins.outputs.TRIVY_VERSION }}",
        'TRIVY_VERSION: "0.74.0"',
        "TRIVY_VERSION: 0.74.0",
        id="env-mapping",
    ),
    pytest.param(
        "ci.yml",
        'v="$TRUFFLEHOG_VERSION"',
        'v="3.94.3"',
        "3.94.3",
        id="short-alias-the-form-sync-never-saw",
    ),
    pytest.param(
        "release.yml",
        "download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux",
        "download/v1.55.0/syft_1.55.0_linux",
        "v1.55.0",
        id="inline-url",
    ),
    pytest.param(
        "ci.yml",
        'pip install "checkov==${CHECKOV_VERSION}"',
        'pip install "checkov==3.3.30"',
        "checkov==3.3.30",
        id="pip-pin",
    ),
    pytest.param(
        "scheduled.yml",
        "OSV_SCANNER_VERSION: ${{ steps.pins.outputs.OSV_SCANNER_VERSION }}",
        "OSV_SCANNER_VERSION: 2.7.0",
        "OSV_SCANNER_VERSION: 2.7.0",
        id="aliased-name-unquoted",
    ),
]


@pytest.mark.parametrize(("workflow", "now", "copy", "reported"), MUTATIONS)
def test_a_copy_put_back_is_caught(
    tmp_path: Path, workflow: str, now: str, copy: str, reported: str
):
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    assert now in text, f"{workflow} no longer has {now!r}; update this case"

    copies = _copies_in(tmp_path, workflow, text.replace(now, copy, 1))

    assert any(c.endswith(f": {reported}") for c in copies), copies


def test_shell_assignment_and_job_env_are_caught(tmp_path: Path):
    copies = _copies_in(
        tmp_path,
        "synthetic.yml",
        """
name: Synthetic
env:
  OPA_VERSION: "1.21.3"
jobs:
  scan:
    env:
      GRYPE_VERSION: 0.118.0
    steps:
      - run: GITLEAKS_VERSION=8.30.1 make thing
""",
    )
    assert copies == [
        "synthetic.yml: top level: OPA_VERSION: 1.21.3",
        "synthetic.yml: jobs.scan: GRYPE_VERSION: 0.118.0",
        "synthetic.yml: jobs.scan.steps[0]: GITLEAKS_VERSION=8.30.1",
    ]


def test_what_is_not_a_copy(tmp_path: Path):
    """The boundary: references, comments, and tools versions.yaml does not pin."""
    copies = _copies_in(
        tmp_path,
        "synthetic.yml",
        """
jobs:
  build:
    steps:
      - env:
          TRUFFLEHOG_VERSION: ${{ steps.pins.outputs.TRUFFLEHOG_VERSION }}
          NEW_VERSION: ${{ steps.bump.outputs.new_version }}
        run: |
          # Was v="3.94.3" here until #1470.
          v="$TRUFFLEHOG_VERSION"
          curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${v}/x.tar.gz"
          uv pip install "checkov==${CHECKOV_VERSION}"
      - run: |
          # crane is not in versions.yaml, so its pin is not this guard's business.
          VERSION="0.20.3"
          curl -sL "https://github.com/google/go-containerregistry/releases/download/v$VERSION/x.tar.gz"
""",
    )
    assert copies == []


# --- no registry tool installed unpinned ----------------------------------------


def _unpinned_installs(text: str) -> list[str]:
    """Registry Python tools a `pip install` line names with no `==` pin."""
    packages = {
        info["pypi_package"]
        for info in _registry().values()
        if isinstance(info.get("pypi_package"), str)
    }
    return [
        name
        for args in re.findall(r"\bpip install\b([^\n]*)", text)
        for name in (token.strip("\"'") for token in args.split())
        if name in packages
    ]


def test_no_workflow_installs_a_registry_python_tool_unpinned():
    """An unpinned install tests whatever PyPI released last, not the pin.

    versions.yaml pins semgrep and checkov, and the image ships those versions,
    but seven install steps ran a bare `pip install semgrep checkov` (#1479).
    They resolved to the pins only because nothing newer had been released, so
    the first release ahead of the weekly bump would have been tested in CI
    before the version JMo ships.
    """
    found = [
        f"{path.name}: {name}"
        for path in sorted(WORKFLOWS.glob("*.yml"))
        for name in _unpinned_installs(path.read_text(encoding="utf-8"))
    ]
    assert not found, (
        "Registry Python tools installed without their versions.yaml pin; use "
        '`pip install "tool==${TOOL_VERSION}"` with TOOL_VERSION read from the '
        "job's `id: pins` step:\n  " + "\n  ".join(found)
    )


def test_an_unpinned_install_put_back_is_caught():
    """The guard above can fail: the original line, put back, is reported."""
    text = (WORKFLOWS / "scheduled.yml").read_text(encoding="utf-8")
    pinned = 'pip install "checkov==${CHECKOV_VERSION}"'
    assert pinned in text, "scheduled.yml changed; update this case"

    assert _unpinned_installs(text.replace(pinned, "pip install checkov", 1)) == [
        "checkov"
    ]
    # `uv pip install` is the same install, and a pinned line is not a hit.
    assert _unpinned_installs("uv pip install checkov pyyaml\n") == ["checkov"]
    assert _unpinned_installs('pip install "checkov==3.3.30"\n') == []


# --- every pin a step reads is one tool_pins.py writes --------------------------


def _consumers() -> list[tuple[str, str, int, dict, list[str]]]:
    """(workflow, job, index, step, names) for every step reading a pins output."""
    found = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        jobs = yaml.safe_load(path.read_text(encoding="utf-8")).get("jobs") or {}
        for job_id, job in jobs.items():
            for i, step in enumerate(job.get("steps") or []):
                names = PINS_OUTPUT.findall(repr(step))
                if names:
                    found.append((path.name, job_id, i, step, names))
    return found


def test_the_pins_steps_are_found():
    """Every converted workflow has readers, so the next test is not vacuous."""
    assert {wf for wf, *_ in _consumers()} == {"ci.yml", "release.yml", "scheduled.yml"}


@pytest.mark.parametrize(
    "consumer", _consumers(), ids=lambda c: f"{c[0]}:{c[1]}:{c[2]}"
)
def test_each_reader_has_a_pins_step_before_it_in_its_job(consumer):
    """A missing or misspelt read gives an empty version, so a broken URL.

    That fails loudly, but only on the runner, and scheduled.yml and release.yml
    never run on a pull request. Caught here, it fails on the PR that makes it.
    """
    workflow, job_id, index, step, names = consumer
    jobs = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))["jobs"]
    earlier = jobs[job_id]["steps"][:index]
    readers = [s for s in earlier if s.get("id") == "pins"]
    assert readers, f"{workflow}:{job_id}: no `id: pins` step before step {index}"
    reader = readers[-1]
    assert "scripts/dev/tool_pins.py" in reader.get("run", "")
    assert "$GITHUB_OUTPUT" in reader.get("run", "")
    # The read must run whenever the install does, or the install gets nothing.
    assert reader.get("if") in (None, step.get("if"))

    known = tool_pins.read_pins(REPO_ROOT / "versions.yaml")
    assert set(names) <= set(known), set(names) - set(known)


# --- --sync no longer writes workflows -------------------------------------------


@pytest.mark.parametrize("dry_run", [False, True])
def test_sync_fails_on_a_copy_and_leaves_the_workflow_alone(
    tmp_path: Path, monkeypatch, dry_run: bool
):
    """It used to rewrite the copy, into a file the weekly job could not push."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_bytes(b'ENV TRIVY_VERSION="0.74.0"\n')
    workflows = tmp_path / "workflows"
    workflows.mkdir()
    workflow = workflows / "ci.yml"
    original = (
        b'jobs:\n  x:\n    steps:\n      - env:\n          TRIVY_VERSION: "0.70.0"\n'
    )
    workflow.write_bytes(original)
    monkeypatch.setattr(update_versions, "DOCKERFILE", dockerfile)
    monkeypatch.setattr(update_versions, "WORKFLOWS_DIR", workflows)
    monkeypatch.setattr(update_versions, "ACTIONS_DIR", tmp_path / "actions")
    monkeypatch.setattr(
        update_versions,
        "load_versions",
        lambda: {"binary_tools": {"trivy": {"version": "0.74.0"}}},
    )

    assert update_versions.sync_dockerfiles(dry_run=dry_run) is False
    assert workflow.read_bytes() == original

    # The same tree without the copy passes, so the copy is what failed it.
    workflow.write_bytes(b"jobs: {}\n")
    assert update_versions.sync_dockerfiles(dry_run=dry_run) is True
