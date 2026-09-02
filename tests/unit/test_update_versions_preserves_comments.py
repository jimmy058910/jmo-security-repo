"""`update_versions.py` must not delete the comments in versions.yaml (#1052).

`save_versions` round-tripped the file through `yaml.safe_load` / `yaml.dump`,
which has no comment model, so every `--tool` and `--update-all` run deleted
all 12 comment lines -- the block recording why cdxgen lives in python_tools
(#935) and the block recording why yara must not track `github_repo` (it once
pinned 4.5.5, a version that never existed on PyPI). Restored by hand three
times during Phases 9 and 11. Worse than ordinary comment loss because the
file's own contract is "never hand-edit this": the only sanctioned path ate
the reasoning, invisibly, in a diff that also carried the intended bump.

The second finding in the same issue: `save_versions` prepended a
content-free "Automated version update" history row (`tools_updated: []`) on
top of the real row `update_tool_version` had just written, one per call.

The fix patches the file text -- only the changed `version:` lines and the
new history entries -- and falls back to a full dump, loudly, when the data
changed in a way the patcher does not model. `yaml.safe_load` of the patched
text must equal the data that was asked for; that check is what makes the
patcher safe to trust.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_module():
    script = REPO_ROOT / "scripts" / "dev" / "update_versions.py"
    spec = importlib.util.spec_from_file_location("update_versions", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


update_versions = _load_module()

# Both comment shapes the real file carries: a block INSIDE a tool's mapping
# (cdxgen, between two keys) and a block BEFORE a tool's first key (yara).
FIXTURE = """\
schema_version: '1.0'
python_tools:
  cdxgen:
    version: 12.0.0
    # npm, not PyPI. PyPI has no scoped names, so `pypi_package:
    # '@cyclonedx/cdxgen'` could never validate -- see #935.
    npm_package: '@cyclonedx/cdxgen'
    critical: false
  yara:
    # Tracks the PyPI package, which is what JMo installs. It previously
    # tracked github_repo VirusTotal/yara as well and came to pin 4.5.5,
    # which has never existed on PyPI.
    version: 4.5.4
    pypi_package: yara-python
binary_tools:
  trivy:
    version: 0.74.0
    github_repo: aquasecurity/trivy
    critical: true
version_history:
- date: '2026-09-01'
  action: Updated trivy
  tools_updated:
  - tool: trivy
    old_version: 0.70.0
    new_version: 0.74.0
  updated_by: update_versions.py
  notes: Manual update via --tool flag
"""

COMMENT_LINES = [line for line in FIXTURE.splitlines() if line.lstrip().startswith("#")]


@pytest.fixture
def versions_file(tmp_path, monkeypatch) -> Path:
    target = tmp_path / "versions.yaml"
    target.write_bytes(FIXTURE.encode("utf-8"))
    monkeypatch.setattr(update_versions, "VERSIONS_YAML", target)
    return target


def test_the_fixture_carries_both_comment_shapes():
    assert len(COMMENT_LINES) == 5


def test_tool_update_keeps_every_comment_and_changes_only_the_version(versions_file):
    assert update_versions.update_tool_version("cdxgen", "12.1.0") is True

    text = versions_file.read_text(encoding="utf-8")
    for line in COMMENT_LINES:
        assert line in text.splitlines(), f"comment lost: {line!r}"

    data = yaml.safe_load(text)
    assert data["python_tools"]["cdxgen"]["version"] == "12.1.0"
    assert data["python_tools"]["yara"]["version"] == "4.5.4"
    assert data["binary_tools"]["trivy"]["version"] == "0.74.0"
    assert data["python_tools"]["cdxgen"]["npm_package"] == "@cyclonedx/cdxgen"


def test_tool_update_writes_one_real_history_row_and_no_empty_one(versions_file):
    update_versions.update_tool_version("cdxgen", "12.1.0")

    history = yaml.safe_load(versions_file.read_text(encoding="utf-8"))[
        "version_history"
    ]
    assert len(history) == 2, history
    newest = history[0]
    assert newest["tools_updated"] == [
        {"tool": "cdxgen", "old_version": "12.0.0", "new_version": "12.1.0"}
    ]
    assert not any(row["tools_updated"] == [] for row in history)
    assert history[1]["action"] == "Updated trivy"


def test_two_updates_in_a_row_keep_the_comments_twice(versions_file):
    update_versions.update_tool_version("cdxgen", "12.1.0")
    update_versions.update_tool_version("yara", "4.5.5")

    text = versions_file.read_text(encoding="utf-8")
    for line in COMMENT_LINES:
        assert line in text.splitlines(), f"comment lost on the second write: {line!r}"
    data = yaml.safe_load(text)
    assert data["python_tools"]["yara"]["version"] == "4.5.5"
    assert len(data["version_history"]) == 3


def test_writing_the_data_back_unchanged_is_byte_identical(versions_file):
    before = versions_file.read_bytes()
    update_versions.save_versions(update_versions.load_versions())
    assert versions_file.read_bytes() == before


def test_the_real_versions_yaml_round_trips_byte_identical(tmp_path, monkeypatch):
    """The repo's own file, comments and all: 12 comment lines today.

    Compared LF-to-LF. The writer emits LF on every platform by design (#555),
    and `read_text()` normalises CRLF on the way in, so on a checkout that
    `core.autocrlf` has converted (GitHub's Windows runners) the round trip
    is the LF form of the file, not its on-disk bytes. Measured on #1110's
    `Windows native console encoding` job: `b'...0.58.1)\\n' == b'...0.58.1)\\r\\n'`.
    """
    real = REPO_ROOT / "versions.yaml"
    copy = tmp_path / "versions.yaml"
    copy.write_bytes(real.read_bytes())
    monkeypatch.setattr(update_versions, "VERSIONS_YAML", copy)
    comment_count = sum(
        1
        for line in copy.read_text(encoding="utf-8").splitlines()
        if line.lstrip().startswith("#")
    )
    assert comment_count >= 12, "the guard needs a file that actually has comments"

    update_versions.save_versions(update_versions.load_versions())

    written = copy.read_bytes()
    assert b"\r\n" not in written, "versions.yaml is written LF-only (#555)"
    assert written == real.read_bytes().replace(b"\r\n", b"\n")


def test_a_structural_change_falls_back_to_a_full_dump_and_says_so(
    versions_file, capsys
):
    data = update_versions.load_versions()
    data["python_tools"]["newtool"] = {"version": "1.0.0", "pypi_package": "newtool"}

    update_versions.save_versions(data)

    text = versions_file.read_text(encoding="utf-8")
    assert yaml.safe_load(text)["python_tools"]["newtool"]["version"] == "1.0.0"
    out = capsys.readouterr()
    assert "comment" in (out.out + out.err).lower()
    assert "5" in (out.out + out.err)
