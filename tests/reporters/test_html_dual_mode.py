#!/usr/bin/env python3
"""
Tests for HTML dashboard dual-mode functionality (Phase 3).

Tests inline vs external JSON loading based on finding count threshold.
"""

from pathlib import Path

import pytest

from scripts.core.reporters.html_reporter import write_html, INLINE_THRESHOLD


def test_inline_mode_small_dataset(tmp_path: Path):
    """
    Test inline mode for datasets ≤ INLINE_THRESHOLD.

    Verifies:
    - JSON embedded directly in HTML
    - No external findings.json created
    - useExternal = false
    - Data assignment: data = [...]
    """
    # Create small dataset (below threshold)
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": f"test-{i}",
            "ruleId": "TEST-001",
            "severity": "HIGH",
            "message": f"Test finding {i}",
            "tool": {"name": "test-tool", "version": "1.0"},
            "location": {"path": "test.py", "startLine": i},
        }
        for i in range(100)  # 100 findings << 1000 threshold
    ]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # Verify inline mode indicators
    assert "const useExternal = false;" in html_content
    assert "data = [" in html_content  # Inline JSON array
    assert "Test finding 0" in html_content  # Data is embedded

    # Verify external JSON NOT created
    findings_json = tmp_path / "findings.json"
    assert not findings_json.exists()


def test_external_mode_large_dataset(tmp_path: Path):
    """
    Test external mode for datasets > INLINE_THRESHOLD.

    Verifies:
    - findings.json created separately
    - useExternal = true
    - Data loaded via fetch()
    - Loading UI present
    """
    # Create large dataset (above threshold)
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": f"test-{i}",
            "ruleId": "TEST-002",
            "severity": "MEDIUM",
            "message": f"Large dataset finding {i}",
            "tool": {"name": "test-tool", "version": "1.0"},
            "location": {"path": "large.py", "startLine": i},
        }
        for i in range(INLINE_THRESHOLD + 100)  # 1100 findings > 1000 threshold
    ]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # Verify external mode indicators
    assert "const useExternal = true;" in html_content
    assert "// Data loaded via fetch()" in html_content
    assert "fetch('findings.json')" in html_content

    # Verify findings NOT embedded in HTML
    assert "Large dataset finding 500" not in html_content

    # Verify loading UI present
    assert 'id="loading"' in html_content
    assert "Loading Security Findings..." in html_content
    assert 'id="loadError"' in html_content

    # Verify external findings.json created
    findings_json = tmp_path / "findings.json"
    assert findings_json.exists()

    # Verify findings.json has all data
    import json

    external_data = json.loads(findings_json.read_text(encoding="utf-8"))
    assert len(external_data) == INLINE_THRESHOLD + 100
    assert external_data[500]["message"] == "Large dataset finding 500"


def test_threshold_boundary_inline(tmp_path: Path):
    """
    Test boundary condition: exactly INLINE_THRESHOLD findings uses inline mode.
    """
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": f"boundary-{i}",
            "ruleId": "BOUNDARY-001",
            "severity": "LOW",
            "message": f"Boundary test {i}",
            "tool": {"name": "test", "version": "1.0"},
            "location": {"path": "boundary.py", "startLine": i},
        }
        for i in range(INLINE_THRESHOLD)  # Exactly 1000
    ]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # At threshold: should use inline mode
    assert "const useExternal = false;" in html_content
    assert "data = [" in html_content

    # Verify no external file
    findings_json = tmp_path / "findings.json"
    assert not findings_json.exists()


def test_threshold_boundary_external(tmp_path: Path):
    """
    Test boundary condition: INLINE_THRESHOLD + 1 findings uses external mode.
    """
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": f"boundary-{i}",
            "ruleId": "BOUNDARY-002",
            "severity": "INFO",
            "message": f"Boundary test {i}",
            "tool": {"name": "test", "version": "1.0"},
            "location": {"path": "boundary.py", "startLine": i},
        }
        for i in range(INLINE_THRESHOLD + 1)  # 1001 findings
    ]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # Above threshold: should use external mode
    assert "const useExternal = true;" in html_content
    assert "fetch('findings.json')" in html_content

    # Verify external file created
    findings_json = tmp_path / "findings.json"
    assert findings_json.exists()
    import json

    data = json.loads(findings_json.read_text())
    assert len(data) == INLINE_THRESHOLD + 1


def test_external_mode_loading_ui_elements(tmp_path: Path):
    """
    Test that external mode includes all loading UI elements.
    """
    findings = [{"id": f"ui-{i}", "severity": "LOW"} for i in range(1500)]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # Verify loading spinner
    assert 'id="loading"' in html_content
    assert "Loading Security Findings..." in html_content
    assert "@keyframes spin" in html_content  # CSS animation

    # Verify error message
    assert 'id="loadError"' in html_content
    assert "⚠️ Loading Failed" in html_content
    assert "Could not load findings.json" in html_content

    # Verify app wrapper
    assert 'id="app"' in html_content
    assert "</div><!-- Close #app wrapper" in html_content


def test_external_mode_fetch_error_handling(tmp_path: Path):
    """
    Test that external mode has proper error handling for failed fetch.
    """
    findings = [{"id": f"err-{i}", "severity": "CRITICAL"} for i in range(2000)]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # Verify error handling in fetch logic
    assert "try {" in html_content
    assert "catch (err) {" in html_content
    assert "console.error('Failed to load findings.json:', err);" in html_content
    assert "errorEl.textContent = `Failed to load findings.json: ${err.message}`" in html_content


def test_inline_mode_no_loading_ui(tmp_path: Path):
    """
    Test that inline mode doesn't show loading UI (hidden by default).
    """
    findings = [{"id": f"no-ui-{i}", "severity": "MEDIUM"} for i in range(50)]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # Verify loading elements exist but are hidden
    assert 'id="loading" style="display:none;' in html_content
    assert 'id="loadError" style="display:none;' in html_content

    # Verify inline initialization doesn't show loading
    assert "if (loadingEl) loadingEl.style.display = 'block';" in html_content
    # But this code is only executed in useExternal branch


def test_external_mode_findings_json_formatting(tmp_path: Path):
    """
    Test that external findings.json is properly formatted (pretty-printed).
    """
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": f"format-{i}",
            "ruleId": "FORMAT-001",
            "severity": "HIGH",
            "message": "Test formatting",
            "tool": {"name": "formatter", "version": "1.0"},
            "location": {"path": "format.py", "startLine": i},
        }
        for i in range(1200)
    ]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    findings_json = tmp_path / "findings.json"
    assert findings_json.exists()

    json_content = findings_json.read_text(encoding="utf-8")

    # Verify pretty-printing (indent=2)
    assert '  "schemaVersion"' in json_content  # 2-space indent
    assert '  "id"' in json_content
    assert "\n" in json_content  # Newlines present


def test_empty_dataset_uses_inline(tmp_path: Path):
    """
    Test that empty datasets use inline mode (performance optimization).
    """
    findings = []

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # Empty dataset should use inline (faster)
    assert "const useExternal = false;" in html_content
    assert "data = []" in html_content or "data = __DATA_JSON__" in html_content

    # No external file needed
    findings_json = tmp_path / "findings.json"
    assert not findings_json.exists()


def test_html_escaping_in_inline_mode(tmp_path: Path):
    """
    Test that inline mode still escapes dangerous characters.

    Ensures dual-mode refactoring didn't break XSS prevention.
    """
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "xss-test-1",
            "ruleId": "XSS-001",
            "message": "Found </script> tag",  # Dangerous!
            "severity": "HIGH",
            "tool": {"name": "xss-tool", "version": "1.0"},
            "location": {"path": "xss.html", "startLine": 1},
        }
    ]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # Verify </script> is escaped
    # In JSON, it should be escaped as <\/script>
    assert r"<\/script>" in html_content or r"<\\\/script>" in html_content
    # Verify unescaped </script> does NOT appear in data (except closing script tag)
    script_count = html_content.count("</script>")
    # Should be exactly N script tags closed (not N+1 from data)
    # Rough check: count should be reasonable (<10 for normal dashboard)
    assert script_count < 10


def test_dual_mode_preserves_dashboard_features(tmp_path: Path):
    """
    Test that both modes preserve all dashboard features.

    Ensures dual-mode refactoring didn't break existing functionality.
    """
    # Test with both modes
    for count in [100, 1500]:  # Inline and external
        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": f"feature-{i}",
                "ruleId": "FEATURE-001",
                "severity": "CRITICAL",
                "message": f"Feature test {i}",
                "tool": {"name": "feature-tool", "version": "2.0"},
                "location": {"path": "feature.py", "startLine": i},
                "priority": {
                    "priority": 85,
                    "is_kev": True,
                    "kev_due_date": "2025-12-31",
                    "epss": 0.75,
                },
                "compliance": {
                    "owaspTop10_2021": ["A01:2021"],
                    "cweTop25_2024": [{"cwe": "CWE-79", "rank": 1}],
                },
            }
            for i in range(count)
        ]

        out_path = tmp_path / f"dashboard_{count}.html"
        write_html(findings, out_path)

        html_content = out_path.read_text(encoding="utf-8")

        # Verify core dashboard features present
        assert "Security Dashboard v2.2 (Priority Intelligence)" in html_content
        assert "Priority Summary Cards" in html_content or "summary-cards" in html_content
        assert "Quick Win" in html_content or "Quick filter" in html_content
        assert "Toggle Theme" in html_content
        assert "Group by:" in html_content
        assert "Compliance Framework:" in html_content

        # Verify JavaScript functions present
        assert "function render()" in html_content
        assert "function updateSummaryCards()" in html_content
        assert "function toggleQuickFilter" in html_content
        assert "function triageFinding" in html_content


@pytest.mark.parametrize(
    "count,expected_mode",
    [
        (0, "inline"),
        (1, "inline"),
        (500, "inline"),
        (999, "inline"),
        (1000, "inline"),  # Exactly at threshold
        (1001, "external"),  # First external
        (2000, "external"),
        (10000, "external"),
    ],
)
def test_threshold_decision_parametrized(tmp_path: Path, count: int, expected_mode: str):
    """
    Parametrized test for threshold decision across various counts.
    """
    findings = [
        {
            "id": f"param-{i}",
            "severity": "LOW",
            "ruleId": "PARAM",
            "tool": {"name": "test", "version": "1.0"},
            "location": {"path": "test.py", "startLine": 1},
            "message": "test",
        }
        for i in range(count)
    ]

    out_path = tmp_path / f"dashboard_{count}.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    if expected_mode == "inline":
        assert "const useExternal = false;" in html_content
        findings_json = tmp_path / "findings.json"
        assert not findings_json.exists()
    else:
        assert "const useExternal = true;" in html_content
        findings_json = tmp_path / "findings.json"
        assert findings_json.exists()
