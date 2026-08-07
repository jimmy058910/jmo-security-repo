"""Every scan job must persist the timings its ToolRunner produced.

`ToolRunner` measures each invocation and hands back a `ToolResult` carrying
`duration`, `status`, `returncode` and `attempts`. Each scan job then iterated
those results, kept `.tool` and `.status`, and dropped the rest -- so "which
tool made my scan slow?" had no answer in JMo's own output even though JMo had
measured it (#722).

Five jobs share that loop, and the shape of this bug is *omission*: a job that
simply never calls the writer looks completely normal. So these tests are
parameterized across all five, and a separate test asserts the parameterization
still covers every job that runs tools -- otherwise a sixth scanner added later
would silently opt out of instrumentation and nothing would go red.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.scan_jobs.iac_scanner import scan_iac_file
from scripts.cli.scan_jobs.image_scanner import scan_image
from scripts.cli.scan_jobs.k8s_scanner import scan_k8s_resource
from scripts.cli.scan_jobs.repository_scanner import scan_repository
from scripts.cli.scan_jobs.url_scanner import scan_url
from scripts.core.scan_timings import SCAN_TIMINGS_FILENAME
from scripts.core.tool_runner import ToolResult

SCAN_JOBS_DIR = Path(__file__).resolve().parents[2] / "scripts" / "cli" / "scan_jobs"


def _repo_target(tmp_path: Path) -> dict:
    repo = tmp_path / "test-repo"
    repo.mkdir()
    return {"repo": repo}


def _iac_target(tmp_path: Path) -> dict:
    # write_bytes, not write_text: Path.write_text translates LF to CRLF on
    # Windows (newline=None -> os.linesep).
    tf = tmp_path / "main.tf"
    tf.write_bytes(b'resource "aws_s3_bucket" "b" {}\n')
    return {"iac_type": "terraform", "iac_path": tf}


# (module under scripts.cli.scan_jobs, entry point, target kwargs, tool, target_type)
SCANNERS = [
    pytest.param(
        "repository_scanner",
        scan_repository,
        _repo_target,
        "trivy",
        "repo",
        id="repository",
    ),
    pytest.param("iac_scanner", scan_iac_file, _iac_target, "checkov", "iac", id="iac"),
    pytest.param(
        "k8s_scanner",
        scan_k8s_resource,
        lambda _: {
            "k8s_info": {"context": "ctx", "namespace": "ns", "all_namespaces": ""}
        },
        "trivy",
        "k8s",
        id="k8s",
    ),
    pytest.param(
        "image_scanner",
        scan_image,
        lambda _: {"image": "nginx:latest"},
        "trivy",
        "image",
        id="image",
    ),
    pytest.param(
        "url_scanner",
        scan_url,
        lambda _: {"url": "https://example.com"},
        "zap",
        "url",
        id="url",
    ),
]

PARAMETERIZED_MODULES = {p.values[0] for p in SCANNERS}


def _run(module: str, scan_func, target_kwargs: dict, tool: str, tmp_path: Path):
    """Run a scan job whose single tool succeeds, with ToolRunner mocked out."""
    with patch(f"scripts.cli.scan_jobs.{module}.ToolRunner") as MockRunner:
        mock_runner = MagicMock()
        MockRunner.return_value = mock_runner
        mock_runner.run_all_parallel.return_value = [
            ToolResult(
                tool=tool,
                status="success",
                returncode=0,
                attempts=1,
                duration=12.5,
            )
        ]
        return scan_func(
            **target_kwargs,
            results_dir=tmp_path,
            tools=[tool],
            timeout=600,
            retries=0,
            per_tool_config={},
            allow_missing_tools=True,
            find_tool_func=lambda t: f"/usr/bin/{t}",
            write_stub_func=lambda name, path: None,
        )


def _read_timings(tmp_path: Path) -> dict:
    """Find and parse the one scan-timings.json written under tmp_path."""
    written = list(tmp_path.rglob(SCAN_TIMINGS_FILENAME))
    assert written, (
        f"no {SCAN_TIMINGS_FILENAME} was written. The scan job ran its tools, "
        f"received their durations from ToolRunner, and discarded them -- which "
        f"is the #722 defect this test exists to prevent."
    )
    assert len(written) == 1, f"expected exactly one timings file, got {written}"
    return json.loads(written[0].read_text(encoding="utf-8"))


@pytest.mark.parametrize("module,scan_func,target,tool,target_type", SCANNERS)
def test_scan_job_persists_its_tool_durations(
    module, scan_func, target, tool, target_type, tmp_path
):
    """The duration ToolRunner measured reaches disk instead of being dropped."""
    _run(module, scan_func, target(tmp_path), tool, tmp_path)

    doc = _read_timings(tmp_path)
    entries = {t["tool"]: t for t in doc["tools"]}

    assert tool in entries, f"{module}: {tool} ran but is absent from the timings"
    assert (
        entries[tool]["duration"] == 12.5
    ), f"{module}: the measured duration did not survive to disk"
    assert entries[tool]["status"] == "success"


@pytest.mark.parametrize("module,scan_func,target,tool,target_type", SCANNERS)
def test_scan_job_records_its_own_target_type(
    module, scan_func, target, tool, target_type, tmp_path
):
    """Each job labels its output, so timings can be grouped across a mixed scan.

    A single `jmo scan` can cover repositories, images and URLs at once. Without
    the type, per-tool numbers from a container scan and a repo scan are
    indistinguishable once collected -- and trivy runs in both.
    """
    _run(module, scan_func, target(tmp_path), tool, tmp_path)

    assert _read_timings(tmp_path)["target_type"] == target_type


def test_every_tool_running_scan_job_is_covered_here():
    """The parameterization must not fall behind the scan_jobs package.

    This bug's shape is omission: a job that never calls the writer looks
    entirely normal and no assertion fires. Discovering the jobs from the source
    instead of a hand-kept list means a sixth scanner cannot quietly opt out of
    instrumentation -- adding one turns this test red until it is wired up.
    """
    runs_tools = set()
    for path in SCAN_JOBS_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "run_all_parallel":
                runs_tools.add(path.stem)

    assert runs_tools == PARAMETERIZED_MODULES, (
        "scan jobs that invoke tools are no longer the same set this file "
        "covers.\n"
        f"  not covered here: {sorted(runs_tools - PARAMETERIZED_MODULES)}\n"
        f"  no longer run tools: {sorted(PARAMETERIZED_MODULES - runs_tools)}"
    )
