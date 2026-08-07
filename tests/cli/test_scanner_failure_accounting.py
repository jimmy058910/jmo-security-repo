"""A tool that resolved and then failed to execute must never be recorded clean.

Every scan job shares one results-processing loop, and every copy of it used to
carry this branch::

    elif result.status == "error" and "Tool not found" in result.error_message:
        if allow_missing_tools:
            _write_stub(result.tool, tool_out)
            statuses[result.tool] = True          # <- a defect, recorded clean

Reaching that branch means the tool *resolved during pre-flight* - it was given
a ToolDefinition and handed to ToolRunner - and then could not be executed. A
genuinely absent tool never gets that far: it is dropped or stubbed in
pre-flight. So arriving here is always a defect, never the user's choice, and
``--allow-missing-tools`` ("record an explicit empty result" for tools you know
you have not installed) is the wrong consent to read into it.

What it cost, measured: ``find_tool("yara")`` returned the pseudo-path
``"python:yara"``, which is truthy, so yara passed pre-flight. ``subprocess``
then raised ``FileNotFoundError`` on it, producing ``Tool not found:
python:yara``, which matched here. On a machine with ``HOME`` and ``PATH``
stripped - where yara could not possibly have run - the scan wrote ``yara.json``
and recorded a clean malware scan.

Which tools land in this branch is platform-dependent, so a single-platform run
"confirms" the honest path for a different subset each time. These tests pin the
contract across every scan job at once instead.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.scan_jobs.iac_scanner import scan_iac_file
from scripts.cli.scan_jobs.image_scanner import scan_image
from scripts.cli.scan_jobs.k8s_scanner import scan_k8s_resource
from scripts.cli.scan_jobs.repository_scanner import scan_repository
from scripts.cli.scan_jobs.url_scanner import scan_url
from scripts.core.tool_runner import ToolResult


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


# (module under scripts.cli.scan_jobs, entry point, target kwargs, a tool it runs)
SCANNERS = [
    pytest.param(
        "repository_scanner", scan_repository, _repo_target, "yara", id="repository"
    ),
    pytest.param("iac_scanner", scan_iac_file, _iac_target, "checkov", id="iac"),
    pytest.param(
        "k8s_scanner",
        scan_k8s_resource,
        lambda _: {
            "k8s_info": {"context": "ctx", "namespace": "ns", "all_namespaces": ""}
        },
        "trivy",
        id="k8s",
    ),
    pytest.param(
        "image_scanner",
        scan_image,
        lambda _: {"image": "nginx:latest"},
        "trivy",
        id="image",
    ),
    pytest.param(
        "url_scanner",
        scan_url,
        lambda _: {"url": "https://example.com"},
        "zap",
        id="url",
    ),
]


def _run(
    module: str,
    scan_func,
    target_kwargs: dict,
    tool: str,
    tmp_path: Path,
    stubbed: list[str],
):
    """Run a scan job whose only tool resolves in pre-flight, then fails to exec.

    find_tool_func must succeed for every name: an unresolvable tool takes the
    pre-flight branch, which is a different (and already honest) path. Letting
    that happen would make these tests pass without the fix under test.
    """
    with patch(f"scripts.cli.scan_jobs.{module}.ToolRunner") as MockRunner:
        mock_runner = MagicMock()
        MockRunner.return_value = mock_runner
        mock_runner.run_all_parallel.return_value = [
            ToolResult(
                tool=tool,
                status="error",
                returncode=-1,
                attempts=1,
                error_message=f"Tool not found: python:{tool}",
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
            write_stub_func=lambda name, path: stubbed.append(name),
        )


@pytest.mark.parametrize("module,scan_func,target,tool", SCANNERS)
def test_resolve_then_vanish_is_not_recorded_as_success(
    module, scan_func, target, tool, tmp_path, caplog
):
    """--allow-missing-tools must not launder an exec failure into a clean run."""
    stubbed: list[str] = []
    with caplog.at_level(logging.ERROR):
        _, statuses = _run(module, scan_func, target(tmp_path), tool, tmp_path, stubbed)

    assert statuses[tool] is False, (
        f"{module}: {tool} resolved in pre-flight and then failed to execute, "
        f"but the scan recorded it as having run successfully. This is the "
        f"branch that made a starved machine report a clean yara malware scan."
    )


@pytest.mark.parametrize("module,scan_func,target,tool", SCANNERS)
def test_resolve_then_vanish_names_itself_on_a_durable_stream(
    module, scan_func, target, tool, tmp_path, caplog
):
    """The failure must reach the log, not just the progress glyph.

    A non-TTY run - CI, cron, a detached scan - renders no progress display at
    all, so a `x` in the Rich tracker is not a record of anything.
    """
    stubbed: list[str] = []
    with caplog.at_level(logging.ERROR):
        _run(module, scan_func, target(tmp_path), tool, tmp_path, stubbed)

    assert tool in caplog.text, (
        f"{module}: {tool} failed to execute and said so on no stream. "
        f"caplog was: {caplog.text!r}"
    )


def test_failure_report_carries_the_tool_stderr(tmp_path, caplog):
    """error_message says what happened; stderr says why. Log both.

    For a non-zero exit `error_message` is only "exited with return code 2".
    ToolRunner captures the tool's stderr onto the result and nothing read it,
    so the diagnosis was collected and dropped one line short of the log. yara
    exiting 2 writes "0 of 310 rule file(s) compiled - nothing was scanned"
    there, which is the difference between an operator knowing the rule set is
    broken and seeing only a bare return code.
    """
    from scripts.cli.scan_utils import report_tool_failure

    with caplog.at_level(logging.ERROR):
        report_tool_failure(
            ToolResult(
                tool="yara",
                status="error",
                returncode=2,
                error_message="Return code 2 not in (0, 1)",
                stderr="yara: 0 of 310 rule file(s) compiled - nothing was scanned.",
            ),
            "it failed",
        )

    assert "0 of 310" in caplog.text, caplog.text
    assert "Return code 2" in caplog.text


def test_failure_report_bounds_a_chatty_tool(caplog):
    """Keep the tail, where the fatal message is - not the whole stream."""
    from scripts.cli.scan_utils import STDERR_TAIL_CHARS, report_tool_failure

    with caplog.at_level(logging.ERROR):
        report_tool_failure(
            ToolResult(
                tool="semgrep",
                status="error",
                stderr=("banner\n" * 5000) + "FATAL: the actual cause",
                error_message="exited 2",
            ),
            "it failed",
        )

    assert "FATAL: the actual cause" in caplog.text
    assert len(caplog.text) < STDERR_TAIL_CHARS * 4


def test_resolve_then_vanish_writes_no_stub(tmp_path, caplog):
    """No fabricated empty result for a tool that never ran.

    A stub is an empty findings array, which the report phase cannot tell apart
    from "this tool ran and found nothing". That is the precise lie being
    removed, so the fix must not keep writing one. Asserted on the repository
    scanner, whose pre-flight resolves yara cleanly and so writes no stub of its
    own to confuse the signal.
    """
    stubbed: list[str] = []
    with caplog.at_level(logging.ERROR):
        _, statuses = _run(
            "repository_scanner",
            scan_repository,
            _repo_target(tmp_path),
            "yara",
            tmp_path,
            stubbed,
        )

    assert stubbed == [], (
        f"a stub was fabricated for a tool that never executed: {stubbed}. "
        f"An empty stub is indistinguishable from a genuine empty result once "
        f"the report phase reads it."
    )
    assert statuses["yara"] is False


def test_timeout_handling_does_not_depend_on_the_message_wording(tmp_path, caplog):
    """A timeout is routed by `result.timed_out`, not by prose (#727).

    This branch writes a stub and logs "it timed out". It used to be selected by
    `"Timeout" in result.error_message`, which made a human-readable string
    load-bearing: rewording it would silently route every timeout to the generic
    failure branch, dropping both signals, with no test going red.

    So this passes a deliberately reworded message. The branch must still fire.
    """
    stubbed: list[str] = []
    with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
        mock_runner = MagicMock()
        MockRunner.return_value = mock_runner
        mock_runner.run_all_parallel.return_value = [
            ToolResult(
                tool="semgrep",
                status="retry_exhausted",
                returncode=-1,
                attempts=3,
                timed_out=True,
                error_message="exceeded its 600s budget",  # deliberately NOT "Timeout"
            )
        ]
        with caplog.at_level(logging.ERROR):
            _, statuses = scan_repository(
                repo=_repo_target(tmp_path)["repo"],
                results_dir=tmp_path,
                tools=["semgrep"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                find_tool_func=lambda t: f"/usr/bin/{t}",
                write_stub_func=lambda name, path: stubbed.append(name),
            )

    assert statuses["semgrep"] is False
    assert stubbed == ["semgrep"], (
        "no stub was written for a timed-out tool, so the report phase will "
        f"have no file for it at all. stubbed={stubbed}"
    )
    assert (
        "timed out" in caplog.text
    ), f"the timeout was not announced as a timeout. caplog was: {caplog.text!r}"


def _run_timeout(
    module: str, scan_func, target_kwargs: dict, tool: str, tmp_path: Path
):
    """Run a scan job whose only tool times out, with ToolRunner mocked."""
    stubbed: list[str] = []
    with patch(f"scripts.cli.scan_jobs.{module}.ToolRunner") as MockRunner:
        mock_runner = MagicMock()
        MockRunner.return_value = mock_runner
        mock_runner.run_all_parallel.return_value = [
            ToolResult(
                tool=tool,
                status="retry_exhausted",
                returncode=-1,
                attempts=3,
                timed_out=True,
                error_message="Timeout after 600s",
            )
        ]
        _, statuses = scan_func(
            **target_kwargs,
            results_dir=tmp_path,
            tools=[tool],
            timeout=600,
            retries=0,
            per_tool_config={},
            allow_missing_tools=True,
            find_tool_func=lambda t: f"/usr/bin/{t}",
            write_stub_func=lambda name, path: stubbed.append(name),
        )
    return statuses, stubbed


@pytest.mark.parametrize("module,scan_func,target,tool", SCANNERS)
def test_a_timeout_names_itself_on_a_durable_stream(
    module, scan_func, target, tool, tmp_path, caplog
):
    """Every scan job must say a tool timed out, not just record False.

    `repository_scanner` writes a stub and logs "it timed out"; the other four
    dropped a timeout into an `else` branch that recorded `False` and returned
    -- no stub, and **no log call at all**. Measured: `report_tool_failure` was
    called once per scanner (the tool-not-found path) against three times in
    `repository_scanner`.

    So a `deep` scan where checkov timed out on an IaC target produced a scan
    that exited 0 with no output for checkov and nothing anywhere saying why.
    That is the silent-failure class this suite exists to close.
    """
    with caplog.at_level(logging.ERROR):
        statuses, _ = _run_timeout(module, scan_func, target(tmp_path), tool, tmp_path)

    assert statuses[tool] is False
    assert tool in caplog.text, (
        f"{module}: {tool} timed out and said so on no stream. A non-TTY run "
        f"renders no progress display, so this is the only durable record. "
        f"caplog was: {caplog.text!r}"
    )
    assert "timed out" in caplog.text, (
        f"{module}: the failure was logged but not identified as a timeout, so "
        f"an operator cannot tell it from a crash. caplog was: {caplog.text!r}"
    )


@pytest.mark.parametrize("module,scan_func,target,tool", SCANNERS)
def test_a_timeout_leaves_a_stub_so_the_report_phase_has_a_file(
    module, scan_func, target, tool, tmp_path
):
    """A timed-out tool gets a stub, so the report phase sees a consistent tree.

    Paired with the log assertion above, never alone: an empty stub on its own
    is indistinguishable from a tool that ran and found nothing, which is the
    lie #7 in the scan-core work removed. The stub is for file-shape
    consistency; the log is what carries the meaning.
    """
    _, stubbed = _run_timeout(module, scan_func, target(tmp_path), tool, tmp_path)

    assert tool in stubbed, (
        f"{module}: no stub written for a timed-out {tool}, so the report phase "
        f"has no file for it at all. stubbed={stubbed}"
    )
