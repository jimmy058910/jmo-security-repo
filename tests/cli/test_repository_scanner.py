"""
Tests for Repository Scanner

Tests `scan_repository` and the tool loop it runs through. Each test resolves
its tools explicitly (the loop only reads a result for a tool it planned), and
each repository fixture holds at least one file: an empty tree fails every row
before any tool runs (G2), which has its own tests below.
"""

import json
import logging
import os
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.repository_scanner import scan_repository
from scripts.cli.scan_jobs.tool_loop import collect_files, iter_repo_files
from scripts.cli.scan_utils import tool_exclusion_flags
from scripts.core.scan_timings import Reason, State
from scripts.core.tool_descriptors import DESCRIPTORS, ExclusionStyle
from scripts.core.tool_registry import TOOL_MATRIX, TOOL_SCAN_TYPES
from scripts.core.tool_runner import ToolResult

REPO_TOOLS = [t for t in TOOL_MATRIX if t in TOOL_SCAN_TYPES["repo"]]


def _found(tool_name):
    return f"/usr/bin/{tool_name}"


def _repo(tmp_path, name="repo", files=None):
    """A repository holding `files` ({relative path: text}), or one README."""
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    for rel, text in (files or {"README.md": "# repo\n"}).items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return repo


def _scan(repo, results_dir, tools, results=None, find=_found, **kw):
    """Run `scan_repository` with ToolRunner patched.

    `results` is a list of ToolResult, or None to succeed exactly the
    definitions the loop built. Returns (name, rows, commands by tool, runner).
    """
    runner_calls = []

    def runner_for(tools, **_kwargs):
        runner_calls.append(tools)
        runner = MagicMock()
        runner.run_all_parallel.return_value = (
            results
            if results is not None
            else [ToolResult(tool=d.name, status="success", attempts=1) for d in tools]
        )
        return runner

    with patch(
        "scripts.cli.scan_jobs.repository_scanner.ToolRunner", side_effect=runner_for
    ):
        name, rows = scan_repository(
            repo=repo,
            results_dir=results_dir,
            tools=tools,
            timeout=kw.pop("timeout", 600),
            retries=kw.pop("retries", 0),
            per_tool_config=kw.pop("per_tool_config", {}),
            allow_missing_tools=kw.pop("allow_missing_tools", False),
            find_tool_func=find,
            **kw,
        )
    defs = runner_calls[0] if runner_calls else []
    return name, rows, {d.name: d for d in defs}


class TestRepositoryScanner:
    """Test repository scanner functionality"""

    def test_scan_repository_basic(self, tmp_path):
        repo = _repo(tmp_path, "test-repo")

        name, rows, _ = _scan(repo, tmp_path / "out", ["trufflehog", "semgrep"])

        assert name == "test-repo"
        assert rows["trufflehog"].state is State.RAN
        assert rows["semgrep"].state is State.RAN

    def test_scan_repository_with_timeout_override(self, tmp_path):
        repo = _repo(tmp_path, "my-app")

        _, _, defs = _scan(
            repo,
            tmp_path / "out",
            ["trivy"],
            find=lambda t: "/usr/bin/trivy" if t == "trivy" else None,
            per_tool_config={
                "trivy": {"timeout": 1200, "flags": ["--severity", "HIGH,CRITICAL"]}
            },
        )

        assert defs["trivy"].timeout == 1200
        assert "--severity" in defs["trivy"].command

    def test_scan_repository_multiple_tools(self, tmp_path):
        repo = _repo(tmp_path, "multi-tool-repo")
        tools = ["trufflehog", "semgrep", "trivy", "syft"]

        _, rows, _ = _scan(repo, tmp_path / "out", tools)

        assert list(rows) == tools
        assert all(rows[t].state is State.RAN for t in tools)

    def test_scan_repository_with_retries(self, tmp_path):
        repo = _repo(tmp_path, "retry-repo")

        _, rows, _ = _scan(
            repo,
            tmp_path / "out",
            ["semgrep"],
            results=[ToolResult(tool="semgrep", status="success", attempts=3)],
            retries=2,
        )

        assert rows["semgrep"].state is State.RAN
        assert rows["semgrep"].attempts == 3

    def test_scan_repository_creates_output_directory(self, tmp_path):
        repo = _repo(tmp_path, "output-test")

        _scan(repo, tmp_path, ["trufflehog"])

        assert (tmp_path / "output-test").exists()

    def test_a_unique_result_name_is_the_folder(self, tmp_path):
        """#1303: the orchestrator names each repository's folder uniquely."""
        repo = _repo(tmp_path / "alice", "app")

        name, _, _ = _scan(repo, tmp_path / "out", ["trivy"], result_name="alice__app")

        assert name == "alice__app"
        assert (tmp_path / "out" / "alice__app" / "scan-timings.json").is_file()
        assert not (tmp_path / "out" / "app").exists()

    def test_every_repo_tool_in_the_matrix_runs(self, tmp_path):
        """With content for every trigger, every repository tool runs; zap and
        nuclei are `skipped:needs --url` (they read URLs)."""
        repo = _repo(
            tmp_path,
            "matrix-repo",
            {
                "Dockerfile": "FROM ubuntu\n",
                "build.sh": "#!/bin/sh\necho hi\n",
                "main.go": "package main\n",
                "main.tf": 'resource "aws_s3_bucket" "b" {}\n',
            },
        )

        name, rows, defs = _scan(repo, tmp_path / "out", list(TOOL_MATRIX), timeout=900)

        assert name == "matrix-repo"
        assert list(rows) == list(TOOL_MATRIX)
        for tool in REPO_TOOLS:
            assert rows[tool].state is State.RAN, f"{tool}: {rows[tool].label}"
        assert rows["zap"].label == "skipped:needs --url"
        assert rows["nuclei"].label == "skipped:needs --url"
        assert set(defs) == set(REPO_TOOLS)

    def test_allow_missing_tools_writes_stubs(self, tmp_path):
        repo = _repo(tmp_path, "missing-tools-repo")
        stub_calls = []

        def mock_write_stub(tool_name, output_path):
            stub_calls.append((tool_name, output_path))
            output_path.write_text('{"results": []}')

        _, rows, _ = _scan(
            repo,
            tmp_path / "out",
            ["trufflehog", "semgrep", "trivy"],
            find=lambda t: None,
            allow_missing_tools=True,
            write_stub_func=mock_write_stub,
        )

        assert sorted(t for t, _ in stub_calls) == ["semgrep", "trivy", "trufflehog"]
        for tool in ("trufflehog", "semgrep", "trivy"):
            assert rows[tool].label == "skipped:not installed", tool

    def test_allow_missing_tools_all_scanners(self, tmp_path):
        """Every repository tool is stubbed; the URL tools get no file at all."""
        repo = _repo(tmp_path, "all-missing-repo")
        stub_calls = []

        def mock_write_stub(tool_name, output_path):
            stub_calls.append(tool_name)
            output_path.write_text("{}")

        _, rows, _ = _scan(
            repo,
            tmp_path / "out",
            list(TOOL_MATRIX),
            find=lambda t: None,
            allow_missing_tools=True,
            write_stub_func=mock_write_stub,
        )

        assert sorted(stub_calls) == sorted(REPO_TOOLS)
        for tool in REPO_TOOLS:
            assert rows[tool].label == "skipped:not installed", tool
        assert rows["zap"].label == "skipped:needs --url"

    def test_missing_without_the_flag_is_a_failed_row_and_says_so(
        self, tmp_path, caplog
    ):
        """A dropped tool used to have no status at all and the scan exited 0."""
        repo = _repo(tmp_path)

        with caplog.at_level(logging.ERROR):
            _, rows, _ = _scan(repo, tmp_path / "out", ["semgrep"], find=lambda t: None)

        assert rows["semgrep"].state is State.FAILED
        assert rows["semgrep"].reason is Reason.NOT_INSTALLED
        assert "semgrep: requested but its executable could not be found" in caplog.text

    def test_per_tool_flags_applied(self, tmp_path):
        repo = _repo(tmp_path, "flags-test-repo")

        _, _, defs = _scan(
            repo,
            tmp_path / "out",
            ["semgrep", "trivy"],
            per_tool_config={
                "semgrep": {"flags": ["--exclude", "node_modules"]},
                "trivy": {"flags": ["--severity", "HIGH,CRITICAL"]},
            },
        )

        assert "node_modules" in defs["semgrep"].command
        assert "HIGH,CRITICAL" in defs["trivy"].command

    def test_per_tool_timeout_overrides(self, tmp_path):
        repo = _repo(tmp_path, "timeout-override-repo")

        _, _, defs = _scan(
            repo,
            tmp_path / "out",
            ["trufflehog", "semgrep", "trivy"],
            per_tool_config={
                "trufflehog": {"timeout": 300},
                "semgrep": {"timeout": 900},
                "trivy": {"timeout": 1200},
            },
        )

        assert defs["trufflehog"].timeout == 300
        assert defs["semgrep"].timeout == 900
        assert defs["trivy"].timeout == 1200

    def test_mixed_available_and_missing_tools(self, tmp_path):
        """trufflehog and trivy really ran, so their `ran` and the others'
        `skipped` cannot both come from a constant (#825)."""
        repo = _repo(tmp_path, "mixed-tools-repo", {"main.tf": "x = 1\n"})
        stub_calls = []

        _, rows, _ = _scan(
            repo,
            tmp_path / "out",
            ["trufflehog", "semgrep", "trivy", "checkov"],
            find=lambda t: f"/usr/bin/{t}" if t in ("trufflehog", "trivy") else None,
            allow_missing_tools=True,
            write_stub_func=lambda tool, path: stub_calls.append(tool),
        )

        assert rows["trufflehog"].state is State.RAN
        assert rows["trivy"].state is State.RAN
        assert rows["semgrep"].label == "skipped:not installed"
        assert rows["checkov"].label == "skipped:not installed"
        assert sorted(stub_calls) == ["checkov", "semgrep"]

    def test_timeout_writes_stub_file(self, tmp_path):
        repo = _repo(tmp_path, "timeout-repo")
        stub_calls = []

        def mock_write_stub(tool_name, output_path):
            stub_calls.append(tool_name)
            output_path.write_text("{}")

        _, rows, _ = _scan(
            repo,
            tmp_path / "out",
            ["semgrep", "trivy"],
            results=[
                ToolResult(tool="semgrep", status="success", attempts=1),
                ToolResult(
                    tool="trivy",
                    status="error",
                    attempts=2,
                    timed_out=True,
                    error_message="Timeout after 900s",
                    failure="timeout",
                ),
            ],
            timeout=900,
            retries=1,
            write_stub_func=mock_write_stub,
        )

        assert rows["semgrep"].state is State.RAN
        assert rows["trivy"].label == "failed:timed out"
        assert rows["trivy"].attempts == 2
        assert stub_calls == ["trivy"]

    def test_scan_repository_custom_write_stub_func(self, tmp_path):
        repo = _repo(tmp_path, "test-repo")
        stub_calls = []

        _scan(
            repo,
            tmp_path / "out",
            ["trivy", "semgrep"],
            find=lambda t: None,
            allow_missing_tools=True,
            write_stub_func=lambda tool, path: stub_calls.append((tool, path)),
        )

        assert len(stub_calls) == 2
        assert any("trivy" in str(p) for _, p in stub_calls)
        assert any("semgrep" in str(p) for _, p in stub_calls)

    def test_the_timings_document_carries_every_row(self, tmp_path):
        """#722: every requested tool has a row in scan-timings.json, including
        the ones that did not run. v2 had rows only for tools that ran."""
        repo = _repo(tmp_path, "rows-repo")

        _scan(repo, tmp_path / "out", list(TOOL_MATRIX))
        doc = json.loads(
            (tmp_path / "out" / "rows-repo" / "scan-timings.json").read_bytes()
        )

        assert doc["schema_version"] == 3
        assert [r["tool"] for r in doc["tools"]] == list(TOOL_MATRIX)
        by_tool = {r["tool"]: r for r in doc["tools"]}
        assert by_tool["hadolint"]["state"] == "skipped"
        assert by_tool["hadolint"]["reason"] == "no Dockerfiles"
        assert by_tool["trivy"]["state"] == "ran"
        assert by_tool["trivy"]["reason"] is None


class TestContentDecidesWhoRuns:
    """#1227: hadolint and shellcheck with nothing to read vanished from the
    scan: no stub, no record, no log line. Every content skip is now a row."""

    @pytest.mark.parametrize(
        ("tool", "reason", "content"),
        [
            ("hadolint", Reason.NO_DOCKERFILES, {"Dockerfile": "FROM alpine\n"}),
            ("shellcheck", Reason.NO_SHELL_SCRIPTS, {"run.sh": "#!/bin/sh\n"}),
            ("gosec", Reason.NO_GO_SOURCES, {"main.go": "package main\n"}),
            # A module whose sources are generated at build time (#1081).
            ("gosec", Reason.NO_GO_SOURCES, {"go.mod": "module example.com/x\n"}),
            ("checkov", Reason.NO_IAC, {"main.tf": 'resource "x" "y" {}\n'}),
        ],
    )
    def test_skipped_without_content_and_run_with_it(
        self, tmp_path, tool, reason, content
    ):
        stub_calls = []
        without = _repo(tmp_path, "without", {"lib.py": "x = 1\n"})
        _, rows, defs = _scan(
            without,
            tmp_path / "out",
            [tool],
            write_stub_func=lambda t, p: stub_calls.append(t),
        )

        assert rows[tool].state is State.SKIPPED
        assert rows[tool].reason is reason
        assert tool not in defs, f"{tool} must not run with nothing to read"
        assert stub_calls == [tool]

        with_content = _repo(tmp_path, "with", content)
        _, rows, defs = _scan(with_content, tmp_path / "out2", [tool])

        assert rows[tool].state is State.RAN
        assert tool in defs

    @pytest.mark.parametrize(
        "files",
        [
            {".github/workflows/ci.yml": "on: push\n"},
            {"charts/app/Chart.yaml": "name: app\n"},
            {"stack.yaml": "AWSTemplateFormatVersion: 2010-09-09\n"},
            {"infra/net.json": '{"Resources": {"V": {"Type": "AWS::EC2::VPC"}}}'},
            {"main.tf.json": "{}"},
        ],
    )
    def test_checkov_reads_every_kind_of_iac_it_is_triggered_by(self, tmp_path, files):
        """The Phase 3 decision: Terraform, CloudFormation, Helm, and the
        workflows checkov-cicd used to cover."""
        _, rows, _ = _scan(_repo(tmp_path, files=files), tmp_path / "out", ["checkov"])

        assert rows["checkov"].state is State.RAN

    @pytest.mark.parametrize(
        "files",
        [
            {"workflows/ci.yml": "on: push\n"},  # not under .github
            {"config.yaml": "resources: {}\n"},  # no AWS marker
            {"Dockerfile": "FROM alpine\n", "k8s/pod.yaml": "kind: Pod\n"},
        ],
    )
    def test_checkov_is_not_triggered_by_other_yaml(self, tmp_path, files):
        _, rows, _ = _scan(_repo(tmp_path, files=files), tmp_path / "out", ["checkov"])

        assert rows["checkov"].label == "skipped:no IaC or workflow files"

    def test_a_missing_binary_is_reported_before_content_is_looked_at(self, tmp_path):
        """A repository with Go and no gosec is an environment gap, not a
        content skip: the reasons must stay distinct (#1081)."""
        repo = _repo(tmp_path, files={"main.go": "package main\n"})

        _, rows, _ = _scan(
            repo,
            tmp_path / "out",
            ["gosec"],
            find=lambda t: None,
            allow_missing_tools=True,
        )

        assert rows["gosec"].label == "skipped:not installed"

    def test_go_inside_a_vendored_tree_does_not_trigger_gosec(self, tmp_path):
        """pre-commit ships `resources/empty_template_main.go`; counting .venv
        would trigger gosec on every Python repository with a virtualenv."""
        repo = _repo(
            tmp_path,
            files={"node_modules/pkg/helper.go": "package main\n", "index.js": "1\n"},
        )

        _, rows, _ = _scan(repo, tmp_path / "out", ["gosec"])

        assert rows["gosec"].label == "skipped:no Go sources"

    def test_zap_and_nuclei_read_urls_not_repositories(self, tmp_path, caplog):
        """#1159: zap's repository mode never worked (`-t` takes a URL). Both
        URL tools are off-target here: no command, no stub, no "did NOT run"
        line even with nothing resolvable (#1136 stays unreachable)."""
        repo = _repo(tmp_path, files={"index.html": "<html></html>"})

        with caplog.at_level(logging.INFO):
            _, rows, defs = _scan(
                repo, tmp_path / "out", ["zap", "nuclei"], find=lambda t: None
            )

        assert rows["zap"].label == "skipped:needs --url"
        assert rows["nuclei"].label == "skipped:needs --url"
        assert defs == {}
        assert not (tmp_path / "out" / "repo" / "zap.json").exists()
        assert "did NOT run" not in caplog.text


class TestNothingExaminedIsFailed:
    """G2 (#1231): a scan of zero files is `failed`, at both levels."""

    def test_a_tree_with_no_files_fails_every_tool_that_reads_it(self, tmp_path):
        repo = tmp_path / "empty"
        (repo / "node_modules" / "pkg").mkdir(parents=True)
        (repo / "node_modules" / "pkg" / "index.js").write_bytes(b"1\n")

        _, rows, defs = _scan(repo, tmp_path / "out", ["trivy", "semgrep", "zap"])

        assert rows["trivy"].label == "failed:no files to scan"
        assert rows["semgrep"].label == "failed:no files to scan"
        assert rows["zap"].label == "skipped:needs --url"
        assert defs == {}, "no tool may run against an empty tree"
        doc = json.loads(
            (tmp_path / "out" / "empty" / "scan-timings.json").read_bytes()
        )
        assert doc["outcome"] == "failed-before-tools"

    @pytest.mark.parametrize(
        ("scanned", "label"), [(0, "failed:examined 0 files"), (4, "ran")]
    )
    def test_semgrep_reporting_zero_paths_scanned_is_failed(
        self, tmp_path, scanned, label
    ):
        """#1231's case: semgrep ran 2930 rules on 0 files, exited 0, and was
        recorded as success. Its own `paths.scanned` says so."""
        repo = _repo(tmp_path)
        out = tmp_path / "out" / "repo" / "semgrep.json"

        def runner_writes(tools, **_kwargs):
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps({"results": [], "paths": {"scanned": ["a.py"] * scanned}}),
                encoding="utf-8",
            )
            runner = MagicMock()
            runner.run_all_parallel.return_value = [
                ToolResult(
                    tool="semgrep", status="success", returncode=0, output_file=out
                )
            ]
            return runner

        with patch(
            "scripts.cli.scan_jobs.repository_scanner.ToolRunner",
            side_effect=runner_writes,
        ):
            _, rows = scan_repository(
                repo,
                tmp_path / "out",
                ["semgrep"],
                600,
                0,
                {},
                False,
                find_tool_func=_found,
            )

        assert rows["semgrep"].label == label

    def test_gosec_without_a_go_toolchain_is_failed(self, tmp_path):
        """Measured on Windows and in the image: without `go`, gosec cannot
        load a package, reports `Stats.files` 0, exits 1, and was graded
        success on every Go repository."""
        repo = _repo(tmp_path, files={"main.go": "package main\n"})
        out = tmp_path / "out" / "repo" / "gosec.json"

        def runner_writes(tools, **_kwargs):
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps(
                    {"Issues": [], "Stats": {"files": 0}, "Golang errors": {"x": []}}
                ),
                encoding="utf-8",
            )
            runner = MagicMock()
            runner.run_all_parallel.return_value = [
                ToolResult(
                    tool="gosec", status="success", returncode=1, output_file=out
                )
            ]
            return runner

        with patch(
            "scripts.cli.scan_jobs.repository_scanner.ToolRunner",
            side_effect=runner_writes,
        ):
            _, rows = scan_repository(
                repo,
                tmp_path / "out",
                ["gosec"],
                600,
                0,
                {},
                False,
                find_tool_func=_found,
            )

        assert rows["gosec"].label == "failed:examined 0 files"
        assert rows["gosec"].exit_code == 1

    def test_an_unreadable_count_is_not_a_zero(self, tmp_path):
        """No output to read: the count is unknown, not 0, so the row is
        decided by the run alone."""
        repo = _repo(tmp_path)

        _, rows, _ = _scan(repo, tmp_path / "out", ["semgrep"])

        assert rows["semgrep"].state is State.RAN


class TestFailedToolsAreReported:
    """A tool that does not deliver findings must say so on a durable stream.

    Measured against bridgecrewio/terragoat: tools that failed ended as a
    transient `✗` glyph and nothing else, and a non-TTY run renders none, so
    the failure left no trace. These pin the contract: every non-success names
    itself and its reason, in the log and in its row.
    """

    def _run(self, tmp_path, results, tools):
        repo = _repo(
            tmp_path, "test-repo", {"main.tf": "x\n", "main.go": "package m\n"}
        )
        return _scan(repo, tmp_path / "out", tools, results=results)[1]

    def test_non_zero_exit_reports_tool_and_reason(self, tmp_path, caplog):
        with caplog.at_level(logging.ERROR):
            rows = self._run(
                tmp_path,
                [
                    ToolResult(
                        tool="semgrep",
                        status="error",
                        returncode=3,
                        error_message="Return code 3 not in (0, 1, 2)",
                        failure="crash",
                    )
                ],
                ["semgrep"],
            )

        assert rows["semgrep"].label == "failed:unaccepted exit code"
        assert rows["semgrep"].exit_code == 3
        assert "semgrep" in caplog.text
        assert "Return code 3" in caplog.text

    def test_timeout_reports_tool_and_reason(self, tmp_path, caplog):
        """A stub is indistinguishable from an empty result once read, so the
        timeout has to be stated at scan time."""
        with caplog.at_level(logging.ERROR):
            rows = self._run(
                tmp_path,
                [
                    ToolResult(
                        tool="checkov",
                        status="error",
                        returncode=-1,
                        timed_out=True,
                        error_message="Timeout after 1200s",
                        failure="timeout",
                    )
                ],
                ["checkov"],
            )

        assert rows["checkov"].label == "failed:timed out"
        # A killed process has no exit code. -1 is ToolRunner's placeholder,
        # and history would read it as one (#1318).
        assert rows["checkov"].exit_code is None
        assert "checkov: it timed out" in caplog.text
        assert "1200" in caplog.text

    def test_missing_binary_at_run_time_is_its_own_reason(self, tmp_path, caplog):
        """It resolved, then could not be executed: a defect, never something
        --allow-missing-tools consents to."""
        with caplog.at_level(logging.ERROR):
            rows = self._run(
                tmp_path,
                [
                    ToolResult(
                        tool="yara",
                        status="error",
                        error_message="Tool not found: yara",
                        failure="missing_tool",
                    )
                ],
                ["yara"],
            )

        assert rows["yara"].label == "failed:not found at run time"
        assert "yara: its executable was not found at run time" in caplog.text

    def test_no_output_is_reported_durably(self, tmp_path, caplog):
        """The #700 class (an accepted code, nothing written) must reach the
        log: the progress tracker's line is a UI surface, overwritten on a TTY."""
        with caplog.at_level(logging.ERROR):
            rows = self._run(
                tmp_path,
                [
                    ToolResult(
                        tool="trivy",
                        status="no_output",
                        returncode=1,
                        error_message="Exited 1 (an accepted code) but wrote no output",
                    )
                ],
                ["trivy"],
            )

        assert rows["trivy"].label == "failed:no output"
        assert "wrote no output" in caplog.text

    def test_successful_tool_is_not_reported_as_failed(self, tmp_path, caplog):
        with caplog.at_level(logging.ERROR):
            rows = self._run(
                tmp_path, [ToolResult(tool="trivy", status="success")], ["trivy"]
            )

        assert rows["trivy"].state is State.RAN
        assert "trivy" not in caplog.text

    def test_a_planned_tool_with_no_result_is_not_silently_clean(self, tmp_path):
        rows = self._run(tmp_path, [], ["trivy"])

        assert rows["trivy"].label == "failed:scanner error"


class TestExclusions:
    """#1080, #1132, #1235: each tool is told to skip what it should not read,
    in its own spelling. The spellings are pinned in tests/unit/test_scan_utils.py;
    these assert they reach the argv."""

    def test_semgrep_is_told_to_skip_vendored_trees(self, tmp_path):
        _, _, defs = _scan(_repo(tmp_path), tmp_path / "out", ["semgrep"])

        assert "--exclude=node_modules" in defs["semgrep"].command

    def test_trivy_is_told_to_skip_them_at_any_depth(self, tmp_path):
        _, _, defs = _scan(_repo(tmp_path), tmp_path / "out", ["trivy"])
        command = defs["trivy"].command

        assert "**/node_modules" in [
            command[i + 1] for i, tok in enumerate(command) if tok == "--skip-dirs"
        ]

    def test_checkov_gets_bare_names(self, tmp_path):
        """`--skip-path` is a regex and checkov drops an unparseable one in
        silence, so `**/node_modules` would exclude nothing."""
        _, _, defs = _scan(
            _repo(tmp_path, files={"main.tf": "x\n"}), tmp_path / "out", ["checkov"]
        )
        command = defs["checkov"].command
        values = [
            command[i + 1] for i, tok in enumerate(command) if tok == "--skip-path"
        ]

        assert "node_modules" in values
        assert ".venv" in values
        assert not any(v.startswith("**") for v in values), values

    def test_exclusions_precede_the_users_flags(self, tmp_path):
        _, _, defs = _scan(
            _repo(tmp_path, files={"main.tf": "x\n"}),
            tmp_path / "out",
            ["checkov"],
            per_tool_config={"checkov": {"flags": ["--compact"]}},
        )
        command = defs["checkov"].command

        assert command.index("--skip-path") < command.index("--compact")

    def test_syft_reads_vendored_trees_and_grype_reads_all_but_a_virtualenv(
        self, tmp_path
    ):
        """#1205: a vendored tree is syft's subject. grype's .venv/venv was
        decided 2026-09-11 (104 findings were the dev machine's CPython)."""
        _, _, defs = _scan(_repo(tmp_path), tmp_path / "out", ["syft", "grype"])

        assert "--exclude" not in defs["syft"].command
        grype = defs["grype"].command
        excluded = [grype[i + 1] for i, tok in enumerate(grype) if tok == "--exclude"]
        assert excluded == ["**/.venv", "**/venv"]

    def test_every_descriptor_keeps_an_in_tree_results_directory_out(self, tmp_path):
        """B5 (#1235): the rendered command for every repository tool excludes
        an in-tree `results/`, syft included; the walk-fed tools do it in the
        walk. syft, grype and yara got nothing at all before Phase 3."""
        repo = _repo(
            tmp_path,
            files={
                "Dockerfile": "FROM alpine\n",
                "run.sh": "#!/bin/sh\n",
                "main.go": "package main\n",
                "main.tf": "x\n",
                "results/individual-repos/old/Dockerfile": "FROM alpine\n",
                "results/individual-repos/old/old.sh": "#!/bin/sh\n",
            },
        )

        _, _, defs = _scan(repo, repo / "results" / "individual-repos", REPO_TOOLS)

        for tool in REPO_TOOLS:
            d = DESCRIPTORS[tool]
            command = defs[tool].command
            if d.exclusion_style is ExclusionStyle.WALK:
                # By location, not substring: macOS's temp root is
                # /private/var/folders/..., and "folders" contains "old".
                files = [Path(arg) for arg in command if Path(arg).is_relative_to(repo)]
                assert files, (tool, command)
                assert not [f for f in files if f.is_relative_to(repo / "results")], (
                    tool,
                    command,
                )
            elif d.exclusion_style is ExclusionStyle.PATTERN_FILE:
                lines = Path(command[command.index("--exclude-paths") + 1])
                patterns = lines.read_bytes().decode("utf-8").splitlines()
                inside = os.sep.join([command[2], "results", "individual-repos", "x"])
                assert any(re.search(p, inside) for p in patterns), patterns
            else:
                # A bare name, a `**/` glob, or gosec's segment regex.
                assert any("results" in arg for arg in command), (tool, command)

    def test_yara_is_told_to_skip_the_results_directory(self, tmp_path):
        repo = _repo(tmp_path, files={"a.py": "x\n"})

        _, _, defs = _scan(repo, repo / "results" / "individual-repos", ["yara"])

        assert "--exclude-dir=results" in defs["yara"].command

    def test_jmos_own_file_walk_skips_a_vendored_tree(self, tmp_path):
        repo = _repo(
            tmp_path,
            files={
                "docker/Dockerfile": "FROM alpine\n",
                "node_modules/some-pkg/docker/Dockerfile": "FROM alpine\n",
            },
        )

        found = collect_files(repo, ("**/Dockerfile",), "hadolint")

        assert len(found) == 1, f"the vendored copy was collected too: {found}"
        assert "node_modules" not in found[0]


class TestTruffleHogExcludeFile:
    """#1134, #1235: trufflehog's --exclude-paths file."""

    @staticmethod
    def _command(tmp_path, per_tool_config=None):
        _, _, defs = _scan(
            _repo(tmp_path),
            tmp_path / "out",
            ["trufflehog"],
            per_tool_config=per_tool_config or {},
        )
        return defs["trufflehog"].command

    def test_the_command_carries_an_exclude_paths_file(self, tmp_path):
        command = self._command(tmp_path)

        exclude_file = Path(command[command.index("--exclude-paths") + 1])
        assert exclude_file.is_file(), "the flag names a file that was not written"

    def test_the_file_excludes_git_jmo_and_the_vendored_trees(self, tmp_path):
        """Each anchored below the absolute root trufflehog is given: it matches
        the root's own path too, so an unanchored `vendor` excluded a whole
        repository living under a `vendor/` (measured 2026-09-25)."""
        from scripts.cli.scan_utils import re2_escape

        command = self._command(tmp_path)
        exclude_file = Path(command[command.index("--exclude-paths") + 1])

        patterns = exclude_file.read_bytes().decode("utf-8").splitlines()

        root = command[2]
        assert Path(root).is_absolute()
        assert patterns == [
            rf"^{re2_escape(root)}[\\/](.*[\\/])?{name}[\\/]"
            for name in (
                r"\.git",
                r"\.jmo",
                "node_modules",
                "vendor",
                r"\.venv",
                "venv",
            )
        ]

    def test_user_flags_still_come_last(self, tmp_path):
        command = self._command(
            tmp_path, {"trufflehog": {"flags": ["--results", "verified"]}}
        )

        assert command.index("--exclude-paths") < command.index("--results")


class TestTheInTreeResultsDirectoryIsKeptOutOfTheScan:
    """#1156, at the scanner. The scanners are handed
    `<results_root>/individual-<type>`, NOT the root: excluding what the
    function receives left `summaries/` (each file embedding every finding)
    in the walk."""

    def test_the_results_ROOT_is_excluded_not_the_per_type_subdirectory(self, tmp_path):
        repo = _repo(tmp_path, files={"main.tf": "x\n"})

        _, _, defs = _scan(repo, repo / "results" / "individual-repos", ["checkov"])
        cmd = " ".join(defs["checkov"].command)

        assert "--skip-path results" in cmd, cmd
        assert "individual-repos" not in cmd.split("--skip-path")[-1]

    def test_a_results_dir_outside_the_repo_adds_no_exclusion(self, tmp_path):
        repo = _repo(tmp_path, files={"main.tf": "x\n"})

        _, _, defs = _scan(repo, tmp_path / "outside" / "individual-repos", ["checkov"])
        command = defs["checkov"].command

        skipped = [
            command[i + 1] for i, tok in enumerate(command) if tok == "--skip-path"
        ]
        assert "results" not in skipped, skipped

    def test_the_content_walk_ignores_a_previous_scans_output(self, tmp_path):
        """A `.go` file inside `results/` is not the repository's code."""
        repo = _repo(
            tmp_path,
            files={
                "results/individual-repos/vendored.go": "package main\n",
                "app.js": "1\n",
            },
        )

        found = {p.name for p in iter_repo_files(repo)}
        pruned = {p.name for p in iter_repo_files(repo, (repo / "results").resolve())}

        assert "vendored.go" in found, "control: found without the skip"
        assert "vendored.go" not in pruned
        _, rows, _ = _scan(repo, repo / "results" / "individual-repos", ["gosec"])
        assert rows["gosec"].label == "skipped:no Go sources"

    def test_the_file_walk_skips_by_PATH_not_by_name(self, tmp_path):
        """A user directory that merely shares the results directory's name
        must still be scanned."""
        repo = _repo(
            tmp_path,
            files={
                "results/own.sh": "#!/bin/sh\n",
                "src/results/theirs.sh": "#!/bin/sh\n",
            },
        )

        found = collect_files(
            repo, ("**/*.sh",), "shellcheck", (repo / "results").resolve()
        )

        assert any("theirs.sh" in f for f in found), (
            "the user's src/results/ was skipped"
        )
        assert not any("own.sh" in f for f in found), "JMo's output was scanned"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestARepositorysOwnPathIsNeverExcluded:
    r"""Exclusions name directories INSIDE the scanned tree. A repository that
    itself lives under `vendor/`, `node_modules/` or `.venv/` (`--repos-dir
    node_modules`, `--tsv --dest vendor`) must still be read. Measured with
    trufflehog 3.97.1 (review of PR B, Important #3): the planted secret was
    found with no pattern and not at all with `(^|[\\/])vendor[\\/]`, because
    trufflehog matches the scan root's own path too."""

    @staticmethod
    def _trufflehog(tmp_path, repo):
        _, _, defs = _scan(repo, tmp_path / "out", ["trufflehog"])
        command = defs["trufflehog"].command
        exclude_file = Path(command[command.index("--exclude-paths") + 1])
        lines = exclude_file.read_bytes().decode("utf-8").splitlines()
        return command[2], [re.compile(line) for line in lines]

    @pytest.mark.parametrize("parent", ["vendor", "node_modules", ".venv"])
    def test_trufflehog_reads_a_repository_under_a_vendored_name(
        self, tmp_path, parent
    ):
        repo = _repo(tmp_path / parent, "app")
        target, patterns = self._trufflehog(tmp_path, repo)

        def excluded(*parts):
            path = os.sep.join([target, *parts])  # trufflehog joins root + entry
            return [p.pattern for p in patterns if p.search(path)]

        assert not excluded("config.txt"), "the repository's own files are excluded"
        assert not excluded("src", "app.py")
        assert excluded("node_modules", "pkg", "a.js"), "a vendored tree is read"
        assert excluded("sub", "vendor", "lib", "b.go")
        assert excluded(".git", "config")

    def test_gosec_names_are_whole_segments_not_regex_substrings(self):
        r"""gosec wraps each -exclude-dir value as `([\\/])?VALUE([\\/])?` and
        matches paths relative to the scan root (measured 2026-09-25, 2.28.0,
        from its `Import directory` log): `-exclude-dir=.git` also dropped
        `.github/x`, the dot being a regex wildcard."""
        flags = tool_exclusion_flags("gosec", results_dir_name="results")
        wrapped = [re.compile(rf"([\\/])?{f.split('=', 1)[1]}([\\/])?") for f in flags]

        def excluded(*parts):
            return any(w.search(os.sep.join(parts)) for w in wrapped)

        for parts in (
            (".git",),
            ("results",),
            ("sub", "results"),
            ("a", "vendor", "b"),
        ):
            assert excluded(*parts), parts
        for parts in ((".github", "x"), ("resultsets",), ("vendorclient",), ("sub",)):
            assert not excluded(*parts), parts

    def test_file_fed_tools_find_content_in_a_repository_under_vendor(self, tmp_path):
        repo = _repo(tmp_path / "vendor", "app", {"Dockerfile": "FROM alpine\n"})

        _, rows, defs = _scan(repo, tmp_path / "out", ["hadolint"])

        assert rows["hadolint"].state is State.RAN, rows["hadolint"].label
        assert any(arg.endswith("Dockerfile") for arg in defs["hadolint"].command)


def test_trufflehog_anchors_on_the_absolute_root_for_a_relative_target(
    tmp_path, monkeypatch
):
    """`--repo .` hands the job a relative path. Go's `filepath.Join` cleans
    `./sub` to `sub`, so a pattern anchored on `.` would match nothing: the
    target trufflehog is given and the anchor are one resolved path."""
    repo = _repo(tmp_path, "app")
    monkeypatch.chdir(tmp_path)

    _, _, defs = _scan(Path("app"), tmp_path / "out", ["trufflehog"])

    command = defs["trufflehog"].command
    assert command[2] == str(repo.resolve())
    lines = Path(command[command.index("--exclude-paths") + 1]).read_bytes()
    nested = os.sep.join([command[2], "node_modules", "p", "a.js"])
    assert any(re.search(p, nested) for p in lines.decode("utf-8").splitlines())
