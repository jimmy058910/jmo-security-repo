"""`--sync` fails while the Dockerfile still installs a tool versions.yaml dropped (#1563).

`sync_dockerfiles` rewrote the pin of each tool versions.yaml lists and looked at
nothing else, so a tool removed from versions.yaml and left in the Dockerfile read
"already in sync" (measured with grype's block, 2026-11-02). Removing a tool from
the image was a hand edit with no guard, and a leftover would ship a binary
nothing runs. Three shapes a leftover takes, each named here: a `<TOOL>_VERSION`
download, a pip `package==X` pin, and a removed tool installed by name (apt's
`yara`, which no pin names).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.dev import update_versions

REGISTRY = {
    "python_tools": {"checkov": {"version": "3.3.30", "pypi_package": "checkov"}},
    "binary_tools": {"trufflehog": {"version": "3.99.7"}},
}

IN_SYNC = """\
FROM ubuntu:24.04
# yara was replaced by yara-x; grype left in Phase 6. Comments may name them.
RUN TRUFFLEHOG_VERSION="3.99.7" && \\
    curl -fsSL "https://example.invalid/trufflehog_${TRUFFLEHOG_VERSION}.tar.gz"
RUN apt-get update && apt-get install -y --no-install-recommends \\
    git \\
    jq
RUN python3 -m pip install --no-cache-dir checkov==3.3.30
RUN HOME=/tmp/h jmo tools install yara-x && mv /tmp/h/.jmo/yara-rules /opt/jmo/yara-rules
"""


@pytest.fixture
def sync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    """Run `sync_dockerfiles` over a Dockerfile of the test's own; return its
    result and what it printed to stderr."""
    monkeypatch.setattr(update_versions, "load_versions", lambda: REGISTRY)
    monkeypatch.setattr(update_versions, "WORKFLOWS_DIR", tmp_path / "workflows")
    monkeypatch.setattr(update_versions, "ACTIONS_DIR", tmp_path / "actions")
    dockerfile = tmp_path / "Dockerfile"
    monkeypatch.setattr(update_versions, "DOCKERFILE", dockerfile)

    def run(text: str, dry_run: bool = True) -> tuple[bool, str]:
        dockerfile.write_bytes(text.encode())
        capsys.readouterr()
        ok = update_versions.sync_dockerfiles(dry_run=dry_run)
        return ok, capsys.readouterr().err

    return run


def test_a_dockerfile_matching_the_registry_passes(sync) -> None:
    """Control: comments naming removed tools, yara-x and yara-rules are not leftovers."""
    ok, errors = sync(IN_SYNC)
    assert ok, errors
    assert errors == ""


@pytest.mark.parametrize("dry_run", [True, False])
@pytest.mark.parametrize(
    ("leftover", "named"),
    [
        ('RUN GRYPE_VERSION="0.87.0" && curl -fsSL "x/${GRYPE_VERSION}"\n', "GRYPE"),
        ("RUN python3 -m pip install yara-python==4.5.4\n", "yara-python"),
        ("RUN apt-get update && apt-get install -y yara && rm -rf /x\n", "yara"),
    ],
)
def test_a_tool_versions_yaml_does_not_list_fails_sync(
    sync, leftover: str, named: str, dry_run: bool
) -> None:
    ok, errors = sync(IN_SYNC + leftover, dry_run=dry_run)
    assert not ok
    assert named in errors, errors


def test_the_real_dockerfile_installs_nothing_versions_yaml_dropped(capsys) -> None:
    """The check passes on the tree as it is, so no leftover ships today."""
    assert update_versions.sync_dockerfiles(dry_run=True), capsys.readouterr().err
