"""Integration tests for scan filters and retries.

Each runs the real CLI in a subprocess through `jmo_runner` (a home and a
working directory of the test's own, the developer's scanners linked in), with
a jmo.yml config.

These were selected by no CI job until 2026-11 and had rotted: three scanned an
empty directory, which a scan now refuses ("no files to scan"), one named
semgrep, removed in v2.0.0, and one was a non-strict xfail that could not fail.
They ran from the checkout with the real home, too, so a scan that ran would
have written the checkout's `.jmo/history.db`.

Note: These tests require external security tools (trufflehog, opengrep,
trivy). They are marked requires_tools; the scheduled e2e-ubuntu job runs them.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import scanner_states

# Mark all tests in this module as requiring external tools
pytestmark = pytest.mark.requires_tools

NATIVE_SAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "samples" / "native"


def _repo(tmp_path: Path, name: str) -> Path:
    """Create a test repository holding one file: a scan refuses an empty one."""
    r = tmp_path / "repos" / name
    r.mkdir(parents=True, exist_ok=True)
    (r / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return r


def _config(tmp_path: Path, text: str) -> Path:
    config_file = tmp_path / "jmo.yml"
    config_file.write_text(text, encoding="utf-8")
    return config_file


def test_include_exclude_filters(tmp_path: Path, jmo_runner):
    """Test include/exclude patterns filter repositories correctly."""
    # Create two repos: app-1 (should be included) and test-1 (should be excluded)
    _repo(tmp_path, "app-1")
    _repo(tmp_path, "test-1")
    out_base = tmp_path / "results"
    config_file = _config(
        tmp_path,
        """
tools: [trufflehog]
include: ["app-*"]
exclude: ["test-*"]
""",
    )

    result = jmo_runner(
        [
            "scan",
            "--repos-dir",
            str(tmp_path / "repos"),
            "--results-dir",
            str(out_base),
            "--config",
            str(config_file),
        ],
        timeout=60,
    )
    assert result.returncode == 0, f"Scan failed: {result.stderr}"
    assert scanner_states(out_base) == {"trufflehog": "ran"}

    # app-1 should be scanned (included by pattern)
    assert (out_base / "individual-repos" / "app-1" / "trufflehog.json").exists()

    # test-1 should NOT be scanned (excluded by pattern)
    assert not (out_base / "individual-repos" / "test-1").exists()


def test_retries_attempts_logging(tmp_path: Path, jmo_runner):
    """Test the retry configuration is accepted.

    This checks that `retries: 2` does not break a scan. Whether a failing
    tool is retried needs a tool that fails, which a real scan does not give;
    `tests/integration/test_cli_per_tool_config.py` covers that with a fake.
    """
    repo = _repo(tmp_path, "retry-repo")
    out_base = tmp_path / "results"
    config_file = _config(
        tmp_path,
        """
tools: [trufflehog]
retries: 2
""",
    )

    result = jmo_runner(
        [
            "scan",
            "--repo",
            str(repo),
            "--results-dir",
            str(out_base),
            "--config",
            str(config_file),
        ],
        timeout=60,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert scanner_states(out_base) == {"trufflehog": "ran"}
    assert (out_base / "individual-repos" / repo.name / "trufflehog.json").exists()


def test_nonzero_tool_exit_codes_are_accepted(tmp_path: Path, jmo_runner):
    """A tool that exits non-zero because it found something still ran.

    checkov exits 1 when a check fails, which is how it reports a finding (this
    test named semgrep, whose rc 2 meant the same, until v2.0.0 removed it).
    The scan reads its output, records the row as ran and exits 0; trivy,
    which exits 0 with findings, runs beside it.
    """
    repo = _repo(tmp_path, "exitcode-repo")
    (repo / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl    = "public-read"\n}\n',
        encoding="utf-8",
    )
    out_base = tmp_path / "results"
    config_file = _config(tmp_path, "tools: [checkov, trivy]\n")

    result = jmo_runner(
        [
            "scan",
            "--repo",
            str(repo),
            "--results-dir",
            str(out_base),
            "--config",
            str(config_file),
        ],
        timeout=300,
    )
    assert result.returncode == 0, f"Scan failed unexpectedly: {result.stderr}"
    assert scanner_states(out_base) == {"checkov": "ran", "trivy": "ran"}
    metadata = json.loads((out_base / ".scan_metadata.json").read_bytes())
    checkov = next(r for r in metadata["tool_runs"] if r["tool"] == "checkov")
    assert checkov["exit_code"] == 1, checkov  # the case this test is about
    assert (out_base / "individual-repos" / repo.name / "checkov.json").exists()
    assert (out_base / "individual-repos" / repo.name / "trivy.json").exists()


def _without_scanners(tmp_path: Path) -> dict[str, str]:
    """An environment where only the interpreter is on PATH and the home holds
    no ~/.jmo/bin, so every external scanner is missing."""
    home = tmp_path / "bare-home"
    home.mkdir()
    env = {
        "PATH": str(Path(sys.executable).parent),
        "HOME": str(home),
        "USERPROFILE": str(home),
    }
    # Windows needs these to load its DLLs and find a temporary directory.
    for var in ("SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP"):
        if var in os.environ:
            env[var] = os.environ[var]
    return env


def _scan_without_scanners(tmp_path: Path, repo: Path, tools: list[str]):
    out_base = tmp_path / "results"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "scan",
            "--repo",
            str(repo),
            "--tools",
            *tools,
            "--results-dir",
            str(out_base),
            "--history-db",
            str(tmp_path / "history.db"),
            "--allow-missing-tools",
        ],
        timeout=120,
        capture_output=True,
        text=True,
        env=_without_scanners(tmp_path),
        cwd=str(tmp_path),
    )
    return result, out_base


def test_a_missing_tool_gets_a_stub_beside_one_that_ran(tmp_path: Path):
    """With --allow-missing-tools a missing tool is written as an empty stub
    and recorded as skipped, while a tool that is there runs.

    jmo-native is built in, so it is the one that runs with every scanner off
    PATH; its sample gives it something to read.
    """
    repo = tmp_path / "app"
    shutil.copytree(NATIVE_SAMPLE, repo)
    result, out_base = _scan_without_scanners(
        tmp_path, repo, ["trufflehog", "jmo-native"]
    )

    assert result.returncode == 0, result.stderr[-2000:]
    metadata = json.loads((out_base / ".scan_metadata.json").read_bytes())
    rows = {r["tool"]: (r["state"], r["reason"]) for r in metadata["tool_runs"]}
    assert rows == {
        "trufflehog": ("skipped", "not installed"),
        "jmo-native": ("ran", None),
    }, rows
    stub = out_base / "individual-repos" / repo.name / "trufflehog.json"
    assert json.loads(stub.read_bytes()) == []


def test_with_every_requested_tool_missing_nothing_is_scanned(tmp_path: Path):
    """--allow-missing-tools does not turn a scan that can run nothing into a
    clean one: it exits 1, names the tools, and writes no results."""
    repo = _repo(tmp_path, "stub-repo")
    result, out_base = _scan_without_scanners(tmp_path, repo, ["trufflehog", "trivy"])

    assert result.returncode == 1, result.stderr[-2000:]
    assert "none of the requested tool(s)" in result.stderr
    assert "trufflehog, trivy" in result.stderr
    assert not out_base.exists()


def test_bad_jmo_threads_fallback(tmp_path: Path, jmo_runner, monkeypatch):
    """Test that invalid JMO_THREADS environment variable falls back to default (1).

    When JMO_THREADS is set to a non-integer value, the scanner should
    gracefully fall back to threads=1 instead of crashing.
    """
    repo = _repo(tmp_path, "threads-repo")
    out_base = tmp_path / "results"
    config_file = _config(tmp_path, "tools: [trufflehog]\n")
    monkeypatch.setenv("JMO_THREADS", "not-an-int")

    result = jmo_runner(
        [
            "scan",
            "--repo",
            str(repo),
            "--results-dir",
            str(out_base),
            "--config",
            str(config_file),
        ],
        timeout=60,
    )

    # Should succeed (fall back to default threads=1)
    assert result.returncode == 0, (
        f"Scan failed to handle bad JMO_THREADS: {result.stderr}"
    )
    assert scanner_states(out_base) == {"trufflehog": "ran"}
    assert (out_base / "individual-repos" / repo.name / "trufflehog.json").exists()
