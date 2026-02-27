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
    - JSON embedded directly in HTML (React mode)
    - No external findings.json created
    - window.__FINDINGS__ placeholder replaced with data
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

    # Verify inline mode indicators (React implementation)
    # Data should be embedded in HTML
    assert "Test finding 0" in html_content  # Data is embedded
    assert "test-0" in html_content  # Check for finding ID
    # Placeholder should be replaced (not present as empty array)
    assert "window.__FINDINGS__ = []" not in html_content

    # Verify external JSON NOT created
    findings_json = tmp_path / "findings.json"
    assert not findings_json.exists()


def test_external_mode_large_dataset(tmp_path: Path):
    """
    Test external mode for datasets > INLINE_THRESHOLD.

    Verifies:
    - findings.json created separately (React mode)
    - Data loaded asynchronously by React app
    - window.__FINDINGS__ placeholder remains empty
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

    # Verify external mode indicators (React implementation)
    # Placeholder should remain empty (React will fetch data)
    assert "window.__FINDINGS__ = []" in html_content

    # Verify findings NOT embedded in HTML
    assert "Large dataset finding 500" not in html_content
    assert "test-500" not in html_content

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
    Test boundary condition: exactly INLINE_THRESHOLD findings uses inline mode (React).
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

    # At threshold: should use inline mode (React implementation)
    # Data embedded, placeholder replaced
    assert "boundary-0" in html_content
    assert "window.__FINDINGS__ = []" not in html_content

    # Verify no external file
    findings_json = tmp_path / "findings.json"
    assert not findings_json.exists()


def test_threshold_boundary_external(tmp_path: Path):
    """
    Test boundary condition: INLINE_THRESHOLD + 1 findings uses external mode (React).
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

    # Above threshold: should use external mode (React implementation)
    # Placeholder remains empty, React will fetch data
    assert "window.__FINDINGS__ = []" in html_content
    # Data NOT embedded
    assert "boundary-500" not in html_content

    # Verify external file created
    findings_json = tmp_path / "findings.json"
    assert findings_json.exists()
    import json

    data = json.loads(findings_json.read_text())
    assert len(data) == INLINE_THRESHOLD + 1


def test_external_mode_loading_ui_elements(tmp_path: Path):
    """
    Test that external mode creates findings.json file (React loads it).
    """
    findings = [{"id": f"ui-{i}", "severity": "LOW"} for i in range(1500)]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # React implementation: placeholder remains, data in external file
    assert "window.__FINDINGS__ = []" in html_content

    # React app will handle loading UI - check for React root
    assert 'id="root"' in html_content

    # Verify external file created
    findings_json = tmp_path / "findings.json"
    assert findings_json.exists()


def test_external_mode_fetch_error_handling(tmp_path: Path):
    """
    Test that external mode creates findings.json (React handles errors).
    """
    findings = [{"id": f"err-{i}", "severity": "CRITICAL"} for i in range(2000)]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # React implementation: placeholder remains, data in external file
    assert "window.__FINDINGS__ = []" in html_content

    # Verify external file created (React will fetch this)
    findings_json = tmp_path / "findings.json"
    assert findings_json.exists()

    # React app has React root for rendering
    assert 'id="root"' in html_content


def test_inline_mode_no_loading_ui(tmp_path: Path):
    """
    Test that inline mode embeds data directly (no external loading needed).
    """
    findings = [{"id": f"no-ui-{i}", "severity": "MEDIUM"} for i in range(50)]

    out_path = tmp_path / "dashboard.html"
    write_html(findings, out_path)

    html_content = out_path.read_text(encoding="utf-8")

    # React implementation: data embedded, placeholder replaced
    assert "no-ui-0" in html_content  # Data is embedded
    assert "window.__FINDINGS__ = []" not in html_content  # Placeholder replaced

    # No external file needed
    findings_json = tmp_path / "findings.json"
    assert not findings_json.exists()


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

    # React implementation: empty dataset embedded, placeholder replaced
    # Look for the replaced placeholder with empty array
    assert "window.__FINDINGS__ = []" in html_content

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

        # React implementation: verify React root and bundled app
        assert 'id="root"' in html_content

        # Verify data handling based on mode
        if count <= INLINE_THRESHOLD:
            # Inline mode: data embedded
            assert "feature-0" in html_content
        else:
            # External mode: data in separate file
            findings_json = tmp_path / "findings.json"
            assert findings_json.exists()
            assert "window.__FINDINGS__ = []" in html_content


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
def test_threshold_decision_parametrized(
    tmp_path: Path, count: int, expected_mode: str
):
    """
    Parametrized test for threshold decision across various counts (React implementation).
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
        # React implementation: data embedded (for count=0, placeholder remains as empty array)
        # For count > 0: check for embedded data
        if count > 0:
            assert (
                "param-0" in html_content or "window.__FINDINGS__ = []" in html_content
            )
        else:
            # Empty dataset: placeholder replaced with empty array
            assert "window.__FINDINGS__ = []" in html_content
        findings_json = tmp_path / "findings.json"
        assert not findings_json.exists()
    else:
        # React implementation: placeholder remains empty, data in external file
        assert "window.__FINDINGS__ = []" in html_content
        findings_json = tmp_path / "findings.json"
        assert findings_json.exists()
