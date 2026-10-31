#!/usr/bin/env python3
"""A target whose scanner raised reports none of an earlier scan's findings (#1518).

The report reads a target's `<tool>.json` only when that target's
`scan-timings.json` says this scan ran the tool, and a folder with no timings
file is read whole (output `jmo scan` did not write). A scanner that raised
before `run_tools` wrote nothing, so a results directory reused from an earlier
scan kept that scan's timings, `ran` row and output together, and the report
took the earlier findings for this scan's.

The orchestrator's `except` knows a target's type and id, and the id is not the
folder for an image (the reference against `nginx_latest`), IaC (`terraform:
main.tf` against `main`), a URL, a GitLab project or a cluster. So each case
below seeds the folder the real scanner writes to and patches that scanner to
raise: an id-named folder would leave the seeded one untouched and fail.

These run `jmo scan` and `jmo report` in-process. No tool is run: the raising
scanner is the only job, and the earlier scan is a timings document written by
`write_scan_timings` and the output its row vouches for.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.cli import jmo
from scripts.cli.scan_jobs.gitlab_scanner import DiscoveredImages
from scripts.cli.scan_orchestrator import ScanConfig, ScanOrchestrator, ScanTargets
from scripts.cli.scan_session import ScanSession
from scripts.core.normalize_and_report import gather_results
from scripts.core.scan_timings import (
    OUTCOME_COMPLETED,
    OUTCOME_FAILED_BEFORE_TOOLS,
    SCAN_TIMINGS_FILENAME,
    Reason,
    State,
    ToolRun,
    write_scan_timings,
)

EARLIER_FINDINGS = 4

# Four findings the report would read from each of these, if it read them.
TRIVY_OUTPUT = json.dumps(
    {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {"VulnerabilityID": f"CVE-2026-000{i}", "Severity": "HIGH"}
                    for i in range(EARLIER_FINDINGS)
                ],
            }
        ]
    }
).encode()
ZAP_OUTPUT = json.dumps(
    {
        "site": [
            {
                "alerts": [
                    {
                        "alert": f"Earlier alert {i}",
                        "riskcode": "3",
                        "instances": [{"uri": f"http://staging.example.com/{i}"}],
                    }
                    for i in range(EARLIER_FINDINGS)
                ]
            }
        ]
    }
).encode()
OUTPUTS = {"trivy": TRIVY_OUTPUT, "zap": ZAP_OUTPUT}

GITLAB_FLAGS = (
    "--gitlab-repo",
    "group/app",
    "--gitlab-token",
    "t",
    "--gitlab-url",
    "https://gitlab.example.com",
)

# (flags, the scan job `jmo scan` runs, the folder that job writes, the target's
# type and id, the tool the earlier scan ran). Only the repository's id is also
# its folder.
TARGETS = [
    pytest.param(
        ("--repo", "proj"),
        "scan_repository",
        "individual-repos/proj",
        ("repo", "proj"),
        "trivy",
        id="repository",
    ),
    pytest.param(
        ("--image", "nginx:latest"),
        "scan_image",
        "individual-images/nginx_latest",
        ("image", "nginx:latest"),
        "trivy",
        id="image",
    ),
    pytest.param(
        ("--terraform-state", "proj/main.tf"),
        "scan_iac_file",
        "individual-iac/main",
        ("iac", "terraform:main.tf"),
        "trivy",
        id="iac",
    ),
    pytest.param(
        ("--url", "http://staging.example.com/app1"),
        "scan_url",
        "individual-web/staging.example.com",
        ("url", "http://staging.example.com/app1"),
        "zap",
        id="url",
    ),
    pytest.param(
        GITLAB_FLAGS,
        "scan_gitlab_repo",
        "individual-gitlab/group_app",
        ("gitlab", "group/app"),
        "trivy",
        id="gitlab",
    ),
    pytest.param(
        ("--k8s-context", "eks/prod", "--k8s-all-namespaces"),
        "scan_k8s_resource",
        "individual-k8s/eks_prod_all",
        ("k8s", "eks/prod:*"),
        "trivy",
        id="k8s",
    ),
]


def explode(*args, **kwargs):
    raise RuntimeError("scanner exploded")


def earlier_scan(folder: Path, target: tuple[str, str], tool: str) -> None:
    """What an earlier scan left in the target's folder: its timings, saying
    `tool` ran, and the output that row vouches for."""
    folder.mkdir(parents=True)
    target_type, name = target
    write_scan_timings(
        folder,
        {tool: ToolRun(tool, State.RAN, seconds=1.0, exit_code=0)},
        target=name,
        target_type=target_type,
        wall_seconds=1.0,
    )
    (folder / f"{tool}.json").write_bytes(OUTPUTS[tool])


@pytest.fixture
def scan(tmp_path: Path, monkeypatch):
    """`jmo scan` and `jmo report` in `tmp_path`, which holds a directory
    `proj` with a `main.tf`. The pre-flight and the tool lookup are pinned as
    `test_scan_target_names.env` pins them; `Path.home()` is redirected too."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "main.tf").write_bytes(b"{}\n")
    (tmp_path / "jmo.yml").write_bytes(b"outputs: [json]\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    monkeypatch.setattr(
        "scripts.cli.tool_manager.ToolManager._find_binary", lambda *a, **k: None
    )
    monkeypatch.setattr(
        "scripts.cli.scan_jobs.tool_loop.find_tool",
        lambda name, *a, **k: "/usr/bin/" + name,
    )
    monkeypatch.setenv("CI", "true")
    results = tmp_path / "results"

    def run(*argv: str) -> int:
        full = [
            "jmo",
            "scan",
            *argv,
            "--results-dir",
            str(results),
            "--config",
            str(tmp_path / "jmo.yml"),
            "--history-db",
            str(tmp_path / "history.db"),
        ]
        with patch.object(sys, "argv", full):
            args = jmo.parse_args()
        return jmo.cmd_scan(args)

    def report() -> list[dict]:
        """`jmo report` on the results directory, from a clean `summaries/`."""
        shutil.rmtree(results / "summaries", ignore_errors=True)
        with patch.object(sys, "argv", ["jmo", "report", str(results)]):
            args = jmo.parse_args()
        jmo.cmd_report(args)
        document = json.loads((results / "summaries" / "findings.json").read_bytes())
        return document["findings"]

    return types.SimpleNamespace(run=run, report=report, results=results)


def _timings(folder: Path) -> dict:
    return json.loads((folder / SCAN_TIMINGS_FILENAME).read_bytes())


@pytest.mark.parametrize(("flags", "scanner", "folder", "target", "tool"), TARGETS)
def test_a_scanner_that_raised_reports_none_of_an_earlier_scans_findings(
    scan, monkeypatch, flags, scanner, folder, target, tool
):
    out = scan.results / folder
    earlier_scan(out, target, tool)
    assert len(gather_results(scan.results)) == EARLIER_FINDINGS, (
        "the earlier scan's output must be findings the report would read"
    )
    monkeypatch.setattr(f"scripts.cli.scan_jobs.{scanner}", explode)

    scan.run(*flags, "--tools", tool)
    findings = scan.report()

    assert findings == []
    timings = _timings(out)
    assert (timings["target_type"], timings["target"]) == target
    assert timings["outcome"] == OUTCOME_FAILED_BEFORE_TOOLS
    assert timings["error"] == "RuntimeError: scanner exploded"
    [row] = timings["tools"]
    assert (row["tool"], row["state"], row["reason"]) == (
        tool,
        State.FAILED,
        Reason.SCANNER_ERROR,
    )
    assert row["detail"] == "RuntimeError: scanner exploded"
    assert row["kept_findings"] is None


def test_a_failed_scan_leaves_a_target_that_scanned_alone(scan, monkeypatch):
    """The fix is per target: the image whose scanner raised reports nothing
    old, and the repository beside it keeps the findings of its own scan."""
    image_out = scan.results / "individual-images" / "nginx_latest"
    earlier_scan(image_out, ("image", "nginx:latest"), "trivy")
    repo_out = scan.results / "individual-repos" / "proj"
    earlier_scan(repo_out, ("repo", "proj"), "trivy")
    repo_timings = (repo_out / SCAN_TIMINGS_FILENAME).read_bytes()

    def scan_proj(repo, results_dir, *args, result_name, **kwargs):
        # A scan of its own would rewrite both; this one only has to leave the
        # target a raising sibling cannot reach as it found it.
        return result_name, {"trivy": ToolRun("trivy", State.RAN, exit_code=0)}

    monkeypatch.setattr("scripts.cli.scan_jobs.scan_image", explode)
    monkeypatch.setattr("scripts.cli.scan_jobs.scan_repository", scan_proj)

    scan.run("--repo", "proj", "--image", "nginx:latest", "--tools", "trivy")
    findings = scan.report()

    assert len(findings) == EARLIER_FINDINGS
    assert (repo_out / SCAN_TIMINGS_FILENAME).read_bytes() == repo_timings
    assert _timings(image_out)["outcome"] == OUTCOME_FAILED_BEFORE_TOOLS


def _orchestrator(results: Path) -> ScanOrchestrator:
    return ScanOrchestrator(ScanConfig(results_dir=results, tools=["trivy"]))


def test_a_resumed_target_is_not_touched(tmp_path, monkeypatch):
    """`alpha` completed in the session being resumed, so it is not submitted:
    it has no future for the failure path to write to. Its earlier timings and
    output stand and the report still reads them; `beta`, scanned and raising
    in the same pass, gets the failed rows."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    results = tmp_path / "results"
    alpha, beta = tmp_path / "alpha", tmp_path / "beta"
    for repo in (alpha, beta):
        repo.mkdir()
    alpha_out = results / "individual-repos" / "alpha"
    earlier_scan(alpha_out, ("repo", "alpha"), "trivy")
    before = {p.name: p.read_bytes() for p in alpha_out.iterdir()}
    session = ScanSession(session_id="s", config_hash="h", started_at=0.0, pid=1)
    for name in ("alpha", "beta"):
        session.register_target("repo", name, ["trivy"])
    done = ToolRun("trivy", State.RAN, seconds=1.0, exit_code=0)
    session.mark_target_complete("alpha", {"trivy": done})
    scanned: list[str] = []

    def scan_repository(repo, results_dir, *args, result_name, **kwargs):
        scanned.append(result_name)
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr("scripts.cli.scan_jobs.scan_repository", scan_repository)

    got = _orchestrator(results).scan_all(
        ScanTargets(repos=[alpha, beta]),
        {},
        session=session,
        session_path=tmp_path / "session.json",
    )

    assert scanned == ["beta"]
    assert {name: rows["trivy"].state for _, name, rows in got} == {
        "alpha": State.RAN,
        "beta": State.FAILED,
    }
    assert {p.name: p.read_bytes() for p in alpha_out.iterdir()} == before
    assert _timings(alpha_out)["outcome"] == OUTCOME_COMPLETED
    assert _timings(results / "individual-repos" / "beta")["outcome"] == (
        OUTCOME_FAILED_BEFORE_TOOLS
    )
    assert len(gather_results(results)) == EARLIER_FINDINGS


def _progress_display_fails(*args, **kwargs):
    raise OSError("the display is gone")


def _checkpoint_fails(*args, **kwargs):
    raise OSError("the session file is gone")


@pytest.mark.parametrize("fails", ["progress", "checkpoint"])
def test_a_scan_that_succeeded_keeps_its_timings_when_what_follows_it_fails(
    tmp_path, monkeypatch, fails
):
    """The `except` around `future.result()` also covers what runs after a good
    scan: the checkpoint and the progress display. If either raises, the scan
    did not: its own timings (`ran`, outcome `completed`) and output stand, and
    the report still reads its findings. Only a scan that raised is recorded as
    failed (ruling 1 of #1518: a `ran` row is never overwritten)."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    results = tmp_path / "results"
    alpha = tmp_path / "alpha"
    alpha.mkdir()
    out = results / "individual-repos" / "alpha"

    def scan_repository(repo, results_dir, *args, result_name, **kwargs):
        # What a scan that worked leaves, as `run_tools` writes it.
        earlier_scan(results_dir / result_name, ("repo", result_name), "trivy")
        return result_name, {"trivy": ToolRun("trivy", State.RAN, exit_code=0)}

    monkeypatch.setattr("scripts.cli.scan_jobs.scan_repository", scan_repository)
    session = ScanSession(session_id="s", config_hash="h", started_at=0.0, pid=1)
    session.register_target("repo", "alpha", ["trivy"])
    callbacks = {}
    if fails == "progress":
        callbacks["progress_callback"] = _progress_display_fails
    else:
        monkeypatch.setattr(ScanSession, "mark_target_complete", _checkpoint_fails)

    _orchestrator(results).scan_all(
        ScanTargets(repos=[alpha]),
        {},
        session=session,
        session_path=tmp_path / "session.json",
        **callbacks,
    )

    timings = _timings(out)
    assert (timings["outcome"], timings["error"]) == (OUTCOME_COMPLETED, None)
    assert [(r["tool"], r["state"]) for r in timings["tools"]] == [("trivy", "ran")]
    assert len(gather_results(results)) == EARLIER_FINDINGS


def test_a_timings_write_that_fails_does_not_replace_the_targets_failure(
    tmp_path, monkeypatch, caplog
):
    """A file where the target's folder belongs: the folder cannot be made, so
    nothing can be written. The target is still reported as failed with the
    scanner's own error, the sibling still scans, and the WARNING names the
    folder."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    results = tmp_path / "results"
    bad, good = tmp_path / "bad", tmp_path / "good"
    for repo in (bad, good):
        repo.mkdir()
    (results / "individual-repos").mkdir(parents=True)
    (results / "individual-repos" / "bad").write_bytes(b"in the way")

    def scan_repository(repo, results_dir, *args, result_name, **kwargs):
        if result_name == "bad":
            raise RuntimeError("scanner exploded")
        return result_name, {"trivy": ToolRun("trivy", State.RAN, exit_code=0)}

    monkeypatch.setattr("scripts.cli.scan_jobs.scan_repository", scan_repository)

    with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_orchestrator"):
        got = _orchestrator(results).scan_all(ScanTargets(repos=[bad, good]), {})

    by_name = {name: rows["trivy"] for _, name, rows in got}
    assert (by_name["bad"].state, by_name["bad"].reason) == (
        State.FAILED,
        Reason.SCANNER_ERROR,
    )
    assert by_name["bad"].detail == "RuntimeError: scanner exploded"
    assert by_name["good"].state is State.RAN
    assert any(
        r.levelno == logging.WARNING
        and r.name == "scripts.cli.scan_orchestrator"
        and "individual-repos" in r.getMessage()
        and "bad" in r.getMessage()
        for r in caplog.records
    ), [r.getMessage() for r in caplog.records]


GITLAB_SCANNER = "scripts.cli.scan_jobs.gitlab_scanner"


@pytest.mark.parametrize("fails", ["the image step", "its record of an image"])
def test_a_gitlab_repository_keeps_its_findings_when_its_image_step_fails(
    scan, monkeypatch, caplog, fails
):
    """`scan_repository` returned, so the repository's rows and output are
    final, and whatever the image step raises past that is the images' own.
    The generic `except` used to rewrite the repository's `ran` rows as
    `failed:target not scanned`, and the report then withheld the findings of a
    scan that worked. Two ways in: the step raising outright (what the
    docstring of `_record_abandoned_target` promises cannot reach it), and the
    one measured way out of the real step, its own handler failing to record
    an image it had claimed."""
    out = scan.results / "individual-gitlab" / "group_app"
    real_run = subprocess.run

    def run(cmd, *args, **kwargs):
        if isinstance(cmd, list) and cmd[:2] == ["git", "clone"]:
            return types.SimpleNamespace(returncode=0, stderr=b"")
        return real_run(cmd, *args, **kwargs)

    def scan_repository(*, results_dir, result_name, label, **kwargs):
        # What a scan that worked leaves, as `run_tools` writes it.
        earlier_scan(results_dir / result_name, ("gitlab", label), "trivy")
        return result_name, {"trivy": ToolRun("trivy", State.RAN, exit_code=0)}

    monkeypatch.setattr(f"{GITLAB_SCANNER}.subprocess.run", run)
    monkeypatch.setattr(f"{GITLAB_SCANNER}.scan_repository", scan_repository)
    if fails == "the image step":
        monkeypatch.setattr(f"{GITLAB_SCANNER}._scan_named_images", explode)
    else:
        monkeypatch.setattr(
            f"{GITLAB_SCANNER}._discover_container_images",
            lambda *args, **kwargs: {"alpine:3.19"},
        )
        monkeypatch.setattr(
            f"{GITLAB_SCANNER}.scan_image",
            lambda **kw: (kw["image"], {"trivy": ToolRun("trivy", State.RAN)}),
        )
        monkeypatch.setattr(DiscoveredImages, "add", explode)

    with caplog.at_level(logging.WARNING, logger=GITLAB_SCANNER):
        scan.run(*GITLAB_FLAGS, "--tools", "trivy")
    findings = scan.report()

    assert len(findings) == EARLIER_FINDINGS
    timings = _timings(out)
    assert (timings["outcome"], timings["error"]) == (OUTCOME_COMPLETED, None)
    assert [(r["tool"], r["state"]) for r in timings["tools"]] == [("trivy", "ran")]
    logged = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and r.name == GITLAB_SCANNER
    ]
    assert any("group/app" in m and "scanner exploded" in m for m in logged), logged
