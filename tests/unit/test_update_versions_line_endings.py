"""Regression tests: update_versions.py must write LF line endings, not CRLF.

`update_versions.py` writes three file families — `versions.yaml`
(`save_versions`), the `Dockerfile.*` set and the `.github/workflows/*.yml`
`env:` blocks (`sync_dockerfiles`). All three used Python text-mode writes
(`open(path, "w")` / `Path.write_text(content)`) with no `newline=` argument.

On **Windows**, text-mode writes apply universal-newline translation and emit
`\r\n` for every `\n`. The repo stores LF and does not auto-normalize
(`.gitattributes` is empty, `core.autocrlf=false`), so a single tool-version
bump on a Windows checkout produced a ~7700-line full-file CRLF-flip diff that
buried the ~175 real lines. See issue #555.

These tests assert the produced bytes contain no `\r\n`. The assertion is
correct on every platform, but it only has *teeth on Windows* — on Linux/macOS
the buggy text-mode write already produces LF, so nothing to catch. That is
intrinsic to an OS-newline-translation bug; the value here is guarding the
`windows-2022` CI shard against regression (and the bug is watchable locally on
Windows). We deliberately do NOT simulate Windows on Linux via mocks.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    script = (
        Path(__file__).resolve().parents[2] / "scripts" / "dev" / "update_versions.py"
    )
    spec = importlib.util.spec_from_file_location("update_versions", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


update_versions = _load_module()


def test_save_versions_writes_lf_not_crlf(tmp_path, monkeypatch):
    """save_versions() must write versions.yaml with LF, not CRLF (#555)."""
    target = tmp_path / "versions.yaml"
    monkeypatch.setattr(update_versions, "VERSIONS_YAML", target)

    update_versions.save_versions({"python_tools": {"ruff": {"version": "0.15.15"}}})

    raw = target.read_bytes()
    # Guard: confirm the write actually produced the expected content, so a
    # silently-empty file can't make the CRLF assertion pass hollowly.
    assert b"ruff" in raw, "save_versions did not write the expected content"
    assert b"\r\n" not in raw, "versions.yaml must be written with LF, not CRLF (#555)"


def test_sync_dockerfiles_writes_lf_not_crlf(tmp_path, monkeypatch):
    """sync_dockerfiles() must write Dockerfiles + workflows with LF (#555)."""
    # Stub load_versions so version_map maps TRIVY -> 0.70.0 without a tmp YAML.
    monkeypatch.setattr(
        update_versions,
        "load_versions",
        lambda: {"binary_tools": {"trivy": {"version": "0.70.0"}}},
    )

    # Dockerfile pinned to a STALE version so the regex actually replaces and a
    # write fires (sync_dockerfiles only writes when content changes).
    dockerfile = tmp_path / "Dockerfile.test"
    dockerfile.write_text('ENV TRIVY_VERSION="0.69.0"\n', newline="\n")
    monkeypatch.setattr(update_versions, "DOCKERFILE", dockerfile)
    # Point the other Dockerfile globals at non-existent paths -> skipped.
    for attr in ("DOCKERFILE_BALANCED", "DOCKERFILE_SLIM", "DOCKERFILE_FAST"):
        monkeypatch.setattr(update_versions, attr, tmp_path / f"absent_{attr}")

    # Workflow env: block, likewise stale, to exercise the second write site.
    wf_dir = tmp_path / "workflows"
    wf_dir.mkdir()
    workflow = wf_dir / "test.yml"
    workflow.write_text('  TRIVY_VERSION: "0.69.0"\n', newline="\n")
    monkeypatch.setattr(update_versions, "WORKFLOWS_DIR", wf_dir)

    update_versions.sync_dockerfiles(dry_run=False)

    df_raw = dockerfile.read_bytes()
    wf_raw = workflow.read_bytes()
    # Rewrite-fired guards: without a real replacement, the files keep the LF we
    # wrote above and the CRLF assertion would pass even pre-fix (false GREEN).
    assert b'TRIVY_VERSION="0.70.0"' in df_raw, "Dockerfile rewrite did not fire"
    assert b'TRIVY_VERSION: "0.70.0"' in wf_raw, "workflow rewrite did not fire"
    # The actual regression assertions:
    assert b"\r\n" not in df_raw, "Dockerfile must be written with LF, not CRLF (#555)"
    assert b"\r\n" not in wf_raw, "workflow must be written with LF, not CRLF (#555)"
