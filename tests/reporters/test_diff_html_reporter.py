"""Tests for HTML diff reporter."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.core.diff_engine import DiffResult, DiffSource, ModifiedFinding
from scripts.core.reporters.diff_html_reporter import (
    INLINE_THRESHOLD,
    write_html_diff,
    _write_html_diff_vanilla,
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


def test_html_react_path(tmp_path, sample_diff_result):
    """Test React dashboard path (if built)."""
    out_path = tmp_path / "diff.html"

    # Mock React dashboard exists (path defined but not used in current implementation)
    # Future enhancement: use this path for React integration
    # react_template_path = (
    #     Path(__file__).parent / "../../scripts/dashboard/dist/index.html"
    # )
    mock_template = """<!DOCTYPE html>
<html>
<head><title>React Dashboard</title></head>
<body>
<div id="root"></div>
<script>window.__DIFF_DATA__ = null</script>
</body>
</html>"""

    with (
        patch.object(Path, "exists", return_value=True),
        patch.object(Path, "read_text", return_value=mock_template),
    ):
        write_html_diff(sample_diff_result, out_path)

    assert out_path.exists()
    content = out_path.read_text()

    # Verify React template used
    assert "React Dashboard" in content
    assert "window.__DIFF_DATA__" in content
    assert "window.__DIFF_DATA__ = null" not in content  # Should be replaced


def test_html_vanilla_fallback(tmp_path, sample_diff_result, caplog):
    """Test vanilla fallback (React not built)."""
    out_path = tmp_path / "diff.html"

    # Mock React dashboard missing
    with patch.object(Path, "exists", return_value=False):
        write_html_diff(sample_diff_result, out_path)

    assert out_path.exists()
    content = out_path.read_text()

    # Verify vanilla template used
    assert "Security Diff Report" in content
    assert "window.DIFF_DATA" in content
    assert "renderDiff()" in content

    # Verify warning logged
    assert "React dashboard not built" in caplog.text
    assert "vanilla JS fallback" in caplog.text


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
    content = out_path.read_text()

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
    content = out_path.read_text()

    # Verify external mode
    assert 'fetch("diff-data.json")' in content
    assert "Finding 0" not in content  # Findings NOT inlined

    # Verify external JSON file created
    json_path = tmp_path / "diff-data.json"
    assert json_path.exists()

    with open(json_path) as f:
        data = json.load(f)
    assert len(data["new"]) == 1001


def test_html_dark_mode(tmp_path, sample_diff_result):
    """Ensure dark mode styles present."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text()

    # Verify dark mode styles
    assert "body.dark-mode" in content
    assert "toggleDarkMode()" in content
    assert "localStorage.getItem('darkMode')" in content


def test_html_metadata_section(tmp_path, sample_diff_result):
    """Test metadata section rendering."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text()

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

    content = out_path.read_text()

    # Verify statistics rendering logic
    assert "renderSummary" in content
    assert "total_new" in content
    assert "total_resolved" in content
    assert "total_modified" in content


def test_html_new_findings_section(tmp_path, sample_diff_result):
    """Test new findings section."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text()

    # Verify new findings rendering
    assert "renderNewFindings" in content
    assert "Hardcoded secret detected" in content
    assert "SQL injection vulnerability" in content


def test_html_resolved_findings_section(tmp_path, sample_diff_result):
    """Test resolved findings section."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text()

    # Verify resolved findings rendering
    assert "renderResolvedFindings" in content
    assert "XSS vulnerability" in content


def test_html_modified_findings_section(tmp_path, sample_diff_result):
    """Test modified findings section."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text()

    # Verify modified findings rendering
    assert "renderModifiedFindings" in content
    assert "renderModificationCard" in content
    assert "Hardcoded password" in content


def test_html_severity_badges(tmp_path, sample_diff_result):
    """Test severity badge rendering."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text()

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

    content = out_path.read_text()

    # Verify filters
    assert "renderFilters" in content
    assert "filterFindings()" in content
    assert "search-input" in content
    assert "severity-filter" in content


def test_html_responsive_design(tmp_path, sample_diff_result):
    """Test responsive design media queries."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text()

    # Verify responsive styles
    assert "@media (max-width: 768px)" in content
    assert "grid-template-columns" in content


def test_html_security_headers(tmp_path, sample_diff_result):
    """Test security headers present."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text()

    # Verify security meta tags
    assert "Content-Security-Policy" in content
    assert "X-Frame-Options" in content
    assert "X-Content-Type-Options" in content
    assert "noindex, nofollow" in content


def test_html_self_contained(tmp_path, sample_diff_result):
    """Verify HTML is self-contained (no CDN dependencies)."""
    out_path = tmp_path / "diff.html"

    _write_html_diff_vanilla(sample_diff_result, out_path)

    content = out_path.read_text()

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

    content = out_path.read_text()

    # Verify dangerous characters escaped in JSON data
    assert "<\\/script>" in content  # Escaped in JSON data
    assert (
        "alert('XSS')" in content or "alert(\\'XSS\\')" in content
    )  # Payload preserved

    # Verify HTML is well-formed (only one script tag at the end)
    assert content.count("</script>") == 1  # Only template's closing tag

    # Most importantly: XSS payload should be safely embedded in JSON
    # and NOT break out of the script context
    assert content.count("<script>") == 1  # Only one script tag
    assert "<\\/script><\\script" in content  # Dangerous sequences escaped


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

    content = out_path.read_text()

    # Verify empty state handling
    assert "0" in content  # Statistics should show zeros
    assert "stable" in content
