"""Regression tests for #837 - the tool's own error channel must reach the report.

Measured reproduction, through `jmo report`. Two Python files with genuine
syntax errors, scanned with bandit 1.9.4:

- bandit's `errors` array named both, "syntax error while parsing AST from file"
- the report carried 17 findings, all from the one file that parsed
- the two unanalysed files appeared **0** times in findings.json, SUMMARY.md,
  dashboard.html, findings.sarif and findings.csv
- **0** log records named them, at any level
- `jmo report` exited **0**

The properties asserted here are "a tool that says it could not read a file is
believed" and, just as important, "a healthy run says nothing" - an
always-fires notice is the shape #784 removed, and it trains readers to skip
the section on the one run that matters.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.core import normalize_and_report as nr
from scripts.core.reporters.basic_reporter import write_markdown
from scripts.core.tool_diagnostics import (
    DIAGNOSTIC_EXTRACTORS,
    ToolDiagnostic,
    extract_tool_diagnostics,
    summarize,
)

BS = chr(92)


def _write(path: Path, obj) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def test_bandit_unparseable_files_are_extracted(tmp_path: Path):
    """The exact shape bandit emitted in the measured reproduction."""
    out = _write(
        tmp_path / "bandit.json",
        {
            "errors": [
                {"filename": "/r/broken/a.py", "reason": "syntax error while parsing"},
                {"filename": "/r/broken/b.py", "reason": "syntax error while parsing"},
            ],
            "results": [],
        },
    )

    found = extract_tool_diagnostics("bandit", out)

    assert [d.path for d in found] == ["r/broken/a.py", "r/broken/b.py"]
    assert all("syntax error" in d.reason for d in found)
    assert {d.tool for d in found} == {"bandit"}


def test_paths_are_normalized_like_location_path(tmp_path: Path):
    """An unanalysed file and a finding on its neighbour must be comparable.

    Without this the report says `iac/x.tf` for a finding and
    `C:\\...\\iac\\y.tf` for the file next to it that could not be read (#861).
    """
    root = "C:" + BS + "work" + BS + "repo"
    out = _write(
        tmp_path / "bandit.json",
        {"errors": [{"filename": root + BS + "pkg" + BS + "a.py", "reason": "bad"}]},
    )

    found = extract_tool_diagnostics("bandit", out, (root,))

    assert [d.path for d in found] == ["pkg/a.py"]


def test_horusec_errors_is_a_string_not_a_list(tmp_path: Path):
    """Measured: horusec writes `errors` as a **string**.

    Iterating it as a list yields one diagnostic per character. The extractor
    inspects the value's type rather than trusting the key's name.
    """
    out = _write(tmp_path / "horusec.json", {"errors": "failed to run analysis"})

    found = extract_tool_diagnostics("horusec", out)

    assert len(found) == 1, f"a string must not be iterated as a list: {found}"
    assert found[0].reason == "failed to run analysis"
    assert found[0].path == ""


def test_scancode_reports_run_level_and_per_file(tmp_path: Path):
    out = _write(
        tmp_path / "scancode.json",
        {
            "headers": [{"errors": ["license db unavailable"], "warnings": ["slow"]}],
            "files": [{"path": "a/b.txt", "scan_errors": ["unreadable"]}],
        },
    )

    found = extract_tool_diagnostics("scancode", out)

    assert {(d.path, d.reason) for d in found} == {
        ("", "license db unavailable"),
        ("", "slow"),
        ("a/b.txt", "unreadable"),
    }


@pytest.mark.parametrize("tool", ["trivy", "grype", "syft", "zap", "cdxgen"])
def test_tools_without_a_channel_cost_nothing(tool: str, tmp_path: Path):
    """Only the tools that have a channel pay the extra parse.

    Pins the design decision: reading centrally is cheap precisely because it
    is not done for all 29 adapters.
    """
    assert tool not in DIAGNOSTIC_EXTRACTORS
    out = _write(tmp_path / f"{tool}.json", {"errors": [{"reason": "ignored"}]})
    assert extract_tool_diagnostics(tool, out) == []


def test_a_healthy_run_produces_no_diagnostics(tmp_path: Path):
    """The negative control. Verified on a real 152-finding scan: 0 and 0."""
    out = _write(tmp_path / "bandit.json", {"errors": [], "results": [{"x": 1}]})
    assert extract_tool_diagnostics("bandit", out) == []
    assert summarize([]) == "", "a healthy run must render nothing at all"


@pytest.mark.parametrize(
    "payload", ["", "{not json", json.dumps([1, 2]), json.dumps({"errors": 7})]
)
def test_unreadable_or_odd_output_never_raises(tmp_path: Path, payload: str):
    """`safe_load_json_file` already warns about these; a second one would only
    teach the reader to skip both."""
    out = tmp_path / "bandit.json"
    out.write_text(payload, encoding="utf-8")
    assert extract_tool_diagnostics("bandit", out) == []


def test_summarize_names_the_tools_and_counts_files():
    found = [
        ToolDiagnostic("bandit", "syntax error", "a.py"),
        ToolDiagnostic("bandit", "syntax error", "b.py"),
        ToolDiagnostic("semgrep", "timeout", "a.py"),
    ]
    text = summarize(found)
    assert "2 file(s)" in text, text
    assert "bandit" in text and "semgrep" in text, text


# ---------------------------------------------------------------------------
# Reaching the report
# ---------------------------------------------------------------------------


def test_collect_tool_diagnostics_walks_the_results_tree(tmp_path: Path):
    results = tmp_path / "results"
    _write(
        results / "individual-repos" / "r1" / "bandit.json",
        {"errors": [{"filename": "x/a.py", "reason": "syntax error"}]},
    )
    _write(results / "individual-repos" / "r1" / "trivy.json", {"Results": []})

    found = nr.collect_tool_diagnostics(results)

    assert [(d.tool, d.path) for d in found] == [("bandit", "x/a.py")]


def test_every_target_type_is_walked_for_diagnostics(tmp_path: Path):
    """`gather_results` and `collect_tool_diagnostics` must cover the same set.

    A seventh target type added to one and not the other would go unreported in
    exactly the silent way #837 is about, so both read `_target_dirs`.
    """
    results = tmp_path / "results"
    kinds = ["repos", "images", "iac", "web", "gitlab", "k8s"]
    for kind in kinds:
        _write(
            results / f"individual-{kind}" / "t" / "bandit.json",
            {"errors": [{"filename": f"{kind}/a.py", "reason": "syntax error"}]},
        )

    found = nr.collect_tool_diagnostics(results)

    assert sorted(d.path for d in found) == sorted(f"{k}/a.py" for k in kinds)
    assert {p.name for p in nr._target_dirs(results)} == {
        f"individual-{k}" for k in kinds
    }


def test_summary_markdown_lists_the_unanalysed_files(tmp_path: Path):
    out = tmp_path / "SUMMARY.md"

    write_markdown(
        [],
        out,
        unanalysed=[("bandit", "broken/a.py", "syntax error while parsing AST")],
    )

    body = out.read_text(encoding="utf-8")
    assert "could not be analysed" in body
    assert "broken/a.py" in body
    assert "syntax error while parsing AST" in body
    assert "not** clean results" in body, "must say what a missing file means"


def test_summary_markdown_says_nothing_when_everything_was_analysed(tmp_path: Path):
    """The property that keeps the section meaningful.

    A "0 files could not be analysed" line on every run is the always-fires
    shape #784 removed.
    """
    quiet = tmp_path / "quiet.md"
    write_markdown([], quiet, unanalysed=[])
    assert "could not be analysed" not in quiet.read_text(encoding="utf-8")

    default = tmp_path / "default.md"
    write_markdown([], default)
    assert quiet.read_text(encoding="utf-8") == default.read_text(encoding="utf-8")


def test_a_pipe_in_a_reason_cannot_break_the_markdown_table(tmp_path: Path):
    out = tmp_path / "SUMMARY.md"
    write_markdown([], out, unanalysed=[("t", "a.py", "failed | badly")])
    row = [
        ln
        for ln in out.read_text(encoding="utf-8").splitlines()
        if ln.startswith("| t |")
    ]
    assert len(row) == 1
    # Count *delimiters*, so drop the escaped pipes first - `\|` still contains
    # a `|` character, and counting raw pipes measures the wrong thing.
    delimiters = row[0].replace(BS + "|", "").count("|")
    assert delimiters == 4, f"an unescaped pipe adds a column: {row[0]}"
    assert BS + "|" in row[0], "the pipe in the reason must be escaped"
