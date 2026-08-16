"""Tests for HTML diff reporter."""

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.core.diff_engine import DiffResult, DiffSource, ModifiedFinding
from scripts.core.reporters.diff_html_reporter import (
    INLINE_THRESHOLD,
    _write_html_diff_vanilla,
    write_html_diff,
)


@pytest.fixture
def sample_diff_result():
    """Create sample DiffResult for testing."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline-results/",
        timestamp="2025-11-04T10:00:00Z",
        profile="balanced",
        total_findings=150,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current-results/",
        timestamp="2025-11-05T10:00:00Z",
        profile="balanced",
        total_findings=142,
    )

    new_findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "abc123",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret detected",
        },
        {
            "schemaVersion": "1.2.0",
            "id": "xyz789",
            "severity": "CRITICAL",
            "ruleId": "CWE-89",
            "tool": {"name": "trivy", "version": "0.68.0"},
            "location": {"path": "src/db.py", "startLine": 89},
            "message": "SQL injection vulnerability",
        },
    ]

    resolved_findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "old123",
            "severity": "MEDIUM",
            "ruleId": "CWE-79",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/views.py", "startLine": 120},
            "message": "XSS vulnerability",
        }
    ]

    modified_findings = [
        ModifiedFinding(
            fingerprint="mod456",
            changes={"severity": ["MEDIUM", "HIGH"], "priority": [45.2, 78.9]},
            baseline={
                "schemaVersion": "1.2.0",
                "id": "mod456",
                "severity": "MEDIUM",
                "ruleId": "G101",
                "message": "Hardcoded password",
                "location": {"path": "src/config.py", "startLine": 15},
            },
            current={
                "schemaVersion": "1.2.0",
                "id": "mod456",
                "severity": "HIGH",
                "ruleId": "G101",
                "message": "Hardcoded password",
                "location": {"path": "src/config.py", "startLine": 15},
            },
            risk_delta="worsened",
        )
    ]

    statistics = {
        "total_new": 2,
        "total_resolved": 1,
        "total_unchanged": 139,
        "total_modified": 1,
        "net_change": 1,
        "trend": "worsening",
        "new_by_severity": {"CRITICAL": 1, "HIGH": 1},
        "resolved_by_severity": {"MEDIUM": 1},
        "modifications_by_type": {"severity": 1, "priority": 1},
    }

    return DiffResult(
        new=new_findings,
        resolved=resolved_findings,
        unchanged=[],
        modified=modified_findings,
        baseline_source=baseline_source,
        current_source=current_source,
        statistics=statistics,
    )


def test_html_diff_has_one_renderer(tmp_path, sample_diff_result, caplog):
    """There is one HTML diff renderer, and it never mentions React.

    `write_html_diff` used to choose between a React path and this one. The
    React branch could not complete -- no template JMo ships contains
    `window.__DIFF_DATA__` -- so it logged "Using React dashboard for diff
    visualization" at INFO and then "React template missing placeholder" at
    WARNING on every run where a build existed, and produced this page anyway.
    Both the branch and its log records are gone (#863). The presence of a
    built dashboard must make no difference to the output.
    """
    caplog.set_level(logging.DEBUG)
    out_path = tmp_path / "diff.html"

    write_html_diff(sample_diff_result, out_path)

    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")

    assert "Security Diff Report" in content
    assert "window.DIFF_DATA" in content
    assert "renderDiff()" in content

    # No React record at any level, and nothing telling the user to run a
    # build that would change nothing.
    assert "React" not in caplog.text
    assert "npm run build" not in caplog.text


@pytest.mark.parametrize("dashboard_built", [True, False])
def test_html_diff_output_ignores_dashboard_build(
    tmp_path, sample_diff_result, dashboard_built
):
    """The rendered page is identical whether or not dist/index.html exists."""
    out_path = tmp_path / f"diff-{dashboard_built}.html"
    with patch.object(Path, "exists", return_value=dashboard_built):
        write_html_diff(sample_diff_result, out_path)
    content = out_path.read_text(encoding="utf-8")
    assert "renderDiff()" in content
    assert "__DIFF_DATA__" not in content


def test_html_diff_escapes_uppercase_script_breakout(tmp_path):
    """Finding text cannot break out of the embedded-data <script> block.

    HTML end tags match case-insensitively, so `</SCRIPT>` closes a script
    element exactly as `</script>` does -- the stored XSS chunk 9 fixed. That
    uppercase case was only ever asserted against the React branch, which
    could not run; the reachable renderer was covered for the lowercase form
    alone. Asserting it here keeps the guard on the path that executes.
    """
    out_path = tmp_path / "diff.html"
    payload = "</SCRIPT><img src=x onerror=alert(document.domain)>"
    diff = DiffResult(
        new=[
            {
                "id": "xss",
                "severity": "HIGH",
                "ruleId": "XSS",
                "message": payload,
                "location": {"path": "test.js", "startLine": 1},
            }
        ],
        resolved=[],
        unchanged=[],
        modified=[],
        baseline_source=DiffSource("directory", "baseline/", "", "fast", 0),
        current_source=DiffSource("directory", "current/", "", "fast", 1),
        statistics={
            "total_new": 1,
            "total_resolved": 0,
            "total_unchanged": 0,
            "total_modified": 0,
            "net_change": 1,
            "trend": "worsening",
            "new_by_severity": {"HIGH": 1},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    write_html_diff(diff, out_path)
    content = out_path.read_text(encoding="utf-8")

    # Meta-guard: the payload must actually be in the document, escaped. A
    # renderer that silently dropped the message would satisfy every negative
    # assertion below without escaping anything.
    assert "\\u003c/SCRIPT" in content, "payload never reached the document"

    # Nothing broke out: no live element anywhere in the page. The handler
    # text itself survives inside the JSON string literal and is inert there --
    # what matters is that no `<` did, so it can never start an element.
    assert "<img" not in content.lower(), "payload broke out as a live element"

    # And no raw `<` inside the embedded data itself. The assignment is a
    # single line; the rest of the <script> block is the page's own JS, which
    # legitimately contains `<` in its template literals.
    prefix = "window.DIFF_DATA = "
    start = content.index(prefix) + len(prefix)
    embedded = content[start : content.index("\n", start)]
    assert json.loads(embedded.rstrip(";"))["new"][0]["message"] == payload
    assert "<" not in embedded, f"raw '<' reached the payload: {embedded[:200]}"


def test_html_inline_mode(tmp_path, sample_diff_result):
    """Test inline mode (<1000 findings)."""
    out_path = tmp_path / "diff.html"

    # Ensure total findings < INLINE_THRESHOLD
    assert (
        len(sample_diff_result.new)
        + len(sample_diff_result.resolved)
        + len(sample_diff_result.modified)
        < INLINE_THRESHOLD
    )

    _write_html_diff_vanilla(sample_diff_result, out_path)

    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")

    # Verify inline mode
    assert "window.DIFF_DATA = {" in content
    assert "Hardcoded secret detected" in content  # Finding inlined
    assert "diff-data.json" not in content  # No external JSON reference


def test_html_external_mode(tmp_path):
    """Test external mode (>1000 findings)."""
    out_path = tmp_path / "diff.html"

    # Create diff with >1000 findings
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="fast",
        total_findings=1500,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="fast",
        total_findings=1500,
    )

    # Generate 1001 new findings
    new_findings = [
        {
            "id": f"finding{i}",
            "severity": "HIGH",
            "ruleId": "TEST",
            "message": f"Finding {i}",
            "location": {"path": f"file{i}.py", "startLine": i},
        }
        for i in range(1001)
    ]

    diff = DiffResult(
        new=new_findings,
        resolved=[],
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 1001,
            "total_resolved": 0,
            "total_unchanged": 0,
            "total_modified": 0,
            "net_change": 1001,
            "trend": "worsening",
            "new_by_severity": {"HIGH": 1001},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    _write_html_diff_vanilla(diff, out_path)

    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")

    # Verify external mode
    assert 'fetch("diff-data.json")' in content
    assert "Finding 0" not in content  # Findings NOT inlined

    # Verify external JSON file created
    json_path = tmp_path / "diff-data.json"
    assert json_path.exists()

    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
    assert len(data["new"]) == 1001


def test_html_dark_mode(tmp_path, sample_diff_result):
    """Ensure dark mode styles present."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify dark mode styles
    assert "body.dark-mode" in content
    assert "toggleDarkMode()" in content
    assert "localStorage.getItem('darkMode')" in content


def test_html_metadata_section(tmp_path, sample_diff_result):
    """Test metadata section rendering."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify metadata present
    assert "baseline-results/" in content
    assert "current-results/" in content
    assert "2025-11-04" in content
    assert "2025-11-05" in content
    assert "balanced" in content


def test_html_summary_statistics(tmp_path, sample_diff_result):
    """Test summary statistics rendering."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify statistics rendering logic
    assert "renderSummary" in content
    assert "total_new" in content
    assert "total_resolved" in content
    assert "total_modified" in content


def test_html_new_findings_section(tmp_path, sample_diff_result):
    """Test new findings section."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify new findings rendering
    assert "renderNewFindings" in content
    assert "Hardcoded secret detected" in content
    assert "SQL injection vulnerability" in content


def test_html_resolved_findings_section(tmp_path, sample_diff_result):
    """Test resolved findings section."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify resolved findings rendering
    assert "renderResolvedFindings" in content
    assert "XSS vulnerability" in content


def test_html_modified_findings_section(tmp_path, sample_diff_result):
    """Test modified findings section."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify modified findings rendering
    assert "renderModifiedFindings" in content
    assert "renderModificationCard" in content
    assert "Hardcoded password" in content


def test_html_severity_badges(tmp_path, sample_diff_result):
    """Test severity badge rendering."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify severity styles
    assert ".sev-CRITICAL" in content
    assert ".sev-HIGH" in content
    assert ".sev-MEDIUM" in content
    assert ".sev-LOW" in content
    assert ".sev-INFO" in content


def test_html_filters(tmp_path, sample_diff_result):
    """Test filter UI elements."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify filters
    assert "renderFilters" in content
    assert "filterFindings()" in content
    assert "search-input" in content
    assert "severity-filter" in content


def test_html_responsive_design(tmp_path, sample_diff_result):
    """Test responsive design media queries."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify responsive styles
    assert "@media (max-width: 768px)" in content
    assert "grid-template-columns" in content


def test_html_security_headers(tmp_path, sample_diff_result):
    """Test security headers present."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify security meta tags
    assert "Content-Security-Policy" in content
    assert "X-Frame-Options" in content
    assert "X-Content-Type-Options" in content
    assert "noindex, nofollow" in content


def test_html_self_contained(tmp_path, sample_diff_result):
    """Verify HTML is self-contained (no CDN dependencies)."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify no external dependencies
    assert "https://cdn" not in content
    assert "http://" not in content.replace("http-equiv", "")
    assert "//cdn" not in content


def test_html_json_escaping(tmp_path):
    """Test dangerous characters are escaped in inline JSON."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="fast",
        total_findings=1,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="fast",
        total_findings=1,
    )

    # Finding with dangerous characters
    new_findings = [
        {
            "id": "xss123",
            "severity": "HIGH",
            "ruleId": "XSS",
            "message": "XSS: </script><script>alert('XSS')</script>",
            "location": {"path": "test.js", "startLine": 10},
        }
    ]

    diff = DiffResult(
        new=new_findings,
        resolved=[],
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 1,
            "total_resolved": 0,
            "total_unchanged": 0,
            "total_modified": 0,
            "net_change": 1,
            "trend": "worsening",
            "new_by_severity": {"HIGH": 1},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    out_path = tmp_path / "xss-test.html"
    _write_html_diff_vanilla(diff, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify dangerous characters escaped in JSON data.
    # These assertions used to pin the escaper's *spelling* (`<\/script>`,
    # `<\/script><\script`), which meant they passed while `</SCRIPT>`,
    # `</ScRiPt>` and `</script >` all still broke out -- the HTML tokenizer
    # matches an end tag case-insensitively. Assert the property instead.
    assert "\\u003c" in content  # escaped form present

    # Verify HTML is well-formed (only one script tag at the end)
    assert content.count("</script>") == 1  # Only template's closing tag
    assert content.count("<script>") == 1  # Only one script tag

    # The payload text survives intact -- only the characters that can *start*
    # markup are neutered -- and the result is still valid JSON.
    prefix = "window.DIFF_DATA = "
    start = content.index(prefix) + len(prefix)
    payload = content[start : content.index(";", start)]
    assert "<" not in payload, f"raw '<' reached the payload: {payload[:200]}"
    assert json.loads(payload)["new"][0]["message"] == (
        "XSS: </script><script>alert('XSS')</script>"
    )


def test_html_creates_parent_directory(tmp_path, sample_diff_result):
    """Test that parent directories are created if they don't exist."""
    out_path = tmp_path / "nested" / "dir" / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    assert out_path.exists()
    assert out_path.parent.exists()


def test_html_empty_diff(tmp_path):
    """Test HTML output for empty diff result."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="fast",
        total_findings=0,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="fast",
        total_findings=0,
    )

    diff = DiffResult(
        new=[],
        resolved=[],
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 0,
            "total_resolved": 0,
            "total_unchanged": 0,
            "total_modified": 0,
            "net_change": 0,
            "trend": "stable",
            "new_by_severity": {},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    out_path = tmp_path / "empty-diff.html"
    _write_html_diff_vanilla(diff, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify empty state handling
    assert "0" in content  # Statistics should show zeros
    assert "stable" in content
