"""Tests for simple HTML reporter (email-compatible static HTML table)."""

from scripts.core.reporters.simple_html_reporter import (
    write_simple_html,
    _escape_html,
    _truncate_text,
)


def test_escape_html():
    """Test HTML escaping for security."""
    assert (
        _escape_html("<script>alert('XSS')</script>")
        == "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"
    )
    assert _escape_html("A & B") == "A &amp; B"
    assert _escape_html('Test "quoted"') == "Test &quot;quoted&quot;"
    assert _escape_html("Normal text") == "Normal text"


def test_truncate_text():
    """Test text truncation."""
    short = "Short text"
    long = "A" * 100

    assert _truncate_text(short, 50) == short
    assert len(_truncate_text(long, 50)) == 50
    assert _truncate_text(long, 50).endswith("...")


def test_write_simple_html_basic(tmp_path):
    """Test basic simple HTML generation."""
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "test-1",
            "ruleId": "CWE-79",
            "severity": "HIGH",
            "tool": {"name": "semgrep", "version": "1.0.0"},
            "location": {"path": "index.js", "startLine": 42},
            "message": "Cross-site scripting vulnerability detected",
        }
    ]

    out_path = tmp_path / "simple-report.html"
    write_simple_html(findings, out_path)

    assert out_path.exists()
    html = out_path.read_text(encoding="utf-8")

    # Check essential HTML structure
    assert "<!DOCTYPE html>" in html
    assert '<html lang="en">' in html
    assert "<title>Security Findings Report</title>" in html

    # Check inline CSS (no external stylesheets)
    assert '<link rel="stylesheet"' not in html  # No external CSS
    assert 'style="' in html  # Inline styles present

    # Check JavaScript-free (email compatibility)
    assert "<script>" not in html
    assert "onclick=" not in html
    assert "addEventListener" not in html

    # Check finding data
    assert "HIGH" in html
    assert "CWE-79" in html
    assert "index.js:42" in html
    assert "Cross-site scripting" in html
    assert "semgrep" in html


def test_write_simple_html_severity_colors(tmp_path):
    """Test severity color-coding."""
    findings = [
        {
            "severity": "CRITICAL",
            "ruleId": "R1",
            "tool": {"name": "tool1"},
            "location": {"path": "a.js", "startLine": 1},
            "message": "Critical issue",
        },
        {
            "severity": "HIGH",
            "ruleId": "R2",
            "tool": {"name": "tool2"},
            "location": {"path": "b.js", "startLine": 2},
            "message": "High issue",
        },
        {
            "severity": "MEDIUM",
            "ruleId": "R3",
            "tool": {"name": "tool3"},
            "location": {"path": "c.js", "startLine": 3},
            "message": "Medium issue",
        },
        {
            "severity": "LOW",
            "ruleId": "R4",
            "tool": {"name": "tool4"},
            "location": {"path": "d.js", "startLine": 4},
            "message": "Low issue",
        },
        {
            "severity": "INFO",
            "ruleId": "R5",
            "tool": {"name": "tool5"},
            "location": {"path": "e.js", "startLine": 5},
            "message": "Info issue",
        },
    ]

    out_path = tmp_path / "simple-report.html"
    write_simple_html(findings, out_path)

    html = out_path.read_text(encoding="utf-8")

    # Check severity colors (inline CSS)
    assert "#b71c1c" in html  # CRITICAL red
    assert "#e65100" in html  # HIGH orange
    assert "#f57f17" in html  # MEDIUM yellow
    assert "#558b2f" in html  # LOW green
    assert "#616161" in html  # INFO gray


def test_write_simple_html_summary_stats(tmp_path):
    """Test summary statistics generation."""
    findings = [
        {
            "severity": "CRITICAL",
            "ruleId": "R1",
            "tool": {"name": "tool1"},
            "location": {"path": "a.js"},
            "message": "Issue 1",
        },
        {
            "severity": "CRITICAL",
            "ruleId": "R2",
            "tool": {"name": "tool2"},
            "location": {"path": "b.js"},
            "message": "Issue 2",
        },
        {
            "severity": "HIGH",
            "ruleId": "R3",
            "tool": {"name": "tool3"},
            "location": {"path": "c.js"},
            "message": "Issue 3",
        },
    ]

    out_path = tmp_path / "simple-report.html"
    write_simple_html(findings, out_path)

    html = out_path.read_text(encoding="utf-8")

    # Check total count
    assert "Total Findings: 3" in html or "Total Findings:</strong> 3" in html

    # Check severity breakdown in summary
    assert "CRITICAL: 2" in html
    assert "HIGH: 1" in html


def test_write_simple_html_consensus_findings(tmp_path):
    """Test handling of consensus findings (detected by multiple tools)."""
    findings = [
        {
            "severity": "HIGH",
            "ruleId": "CWE-79",
            "location": {"path": "app.js", "startLine": 10},
            "message": "XSS vulnerability",
            "detected_by": [
                {"name": "semgrep", "version": "1.0.0"},
                {"name": "bandit", "version": "2.0.0"},
                {"name": "eslint", "version": "3.0.0"},
            ],
        }
    ]

    out_path = tmp_path / "simple-report.html"
    write_simple_html(findings, out_path)

    html = out_path.read_text(encoding="utf-8")

    # Should show multiple tools
    assert "semgrep, bandit, eslint" in html


def test_write_simple_html_long_message_truncation(tmp_path):
    """Test long message truncation."""
    long_message = "A" * 200
    findings = [
        {
            "severity": "MEDIUM",
            "ruleId": "LONG-RULE",
            "tool": {"name": "test-tool"},
            "location": {"path": "test.js", "startLine": 1},
            "message": long_message,
        }
    ]

    out_path = tmp_path / "simple-report.html"
    write_simple_html(findings, out_path)

    html = out_path.read_text(encoding="utf-8")

    # Message should be truncated to 100 chars
    assert long_message[:97] + "..." in html or long_message[:80] in html


def test_write_simple_html_xss_protection(tmp_path):
    """Test XSS protection via HTML escaping."""
    malicious_findings = [
        {
            "severity": "HIGH",
            "ruleId": "<script>alert('XSS')</script>",
            "tool": {"name": "<img src=x onerror=alert('XSS')>"},
            "location": {"path": "test<>.js", "startLine": 1},
            "message": "Test message with <script>alert('pwned')</script>",
        }
    ]

    out_path = tmp_path / "simple-report.html"
    write_simple_html(malicious_findings, out_path)

    html = out_path.read_text(encoding="utf-8")

    # Check that dangerous characters are escaped
    assert "&lt;script&gt;" in html
    assert "<script>alert" not in html  # Raw script tag should not appear
    assert "&lt;img src" in html


def test_write_simple_html_email_client_compatibility(tmp_path):
    """Test email client compatibility features."""
    findings = [
        {
            "severity": "HIGH",
            "ruleId": "R1",
            "tool": {"name": "tool1"},
            "location": {"path": "a.js"},
            "message": "Test",
        }
    ]

    out_path = tmp_path / "simple-report.html"
    write_simple_html(findings, out_path)

    html = out_path.read_text(encoding="utf-8")

    # Check MSO (Microsoft Outlook) compatibility comments
    assert "<!--[if mso]>" in html

    # Check table-based layout (email clients prefer tables over divs)
    assert '<table role="presentation"' in html
    assert 'cellspacing="0"' in html
    assert 'cellpadding="0"' in html

    # Check viewport meta tag for mobile
    assert '<meta name="viewport"' in html

    # Check no external dependencies
    assert (
        'href="http' not in html or 'href="https://jmotools.com"' in html
    )  # Only footer link allowed
    assert '<link rel="stylesheet"' not in html


def test_write_simple_html_responsive_design(tmp_path):
    """Test responsive design elements."""
    findings = [
        {
            "severity": "HIGH",
            "ruleId": "R1",
            "tool": {"name": "tool1"},
            "location": {"path": "a.js"},
            "message": "Test",
        }
    ]

    out_path = tmp_path / "simple-report.html"
    write_simple_html(findings, out_path)

    html = out_path.read_text(encoding="utf-8")

    # Check media queries for dark mode
    assert "@media (prefers-color-scheme: dark)" in html

    # Check mobile responsiveness
    assert "@media screen and (max-width: 600px)" in html


def test_write_simple_html_sorting_by_severity(tmp_path):
    """Test findings are sorted by severity (CRITICAL → INFO)."""
    findings = [
        {
            "severity": "INFO",
            "ruleId": "R5",
            "tool": {"name": "t1"},
            "location": {"path": "e.js"},
            "message": "Info",
        },
        {
            "severity": "CRITICAL",
            "ruleId": "R1",
            "tool": {"name": "t2"},
            "location": {"path": "a.js"},
            "message": "Critical",
        },
        {
            "severity": "MEDIUM",
            "ruleId": "R3",
            "tool": {"name": "t3"},
            "location": {"path": "c.js"},
            "message": "Medium",
        },
        {
            "severity": "HIGH",
            "ruleId": "R2",
            "tool": {"name": "t4"},
            "location": {"path": "b.js"},
            "message": "High",
        },
        {
            "severity": "LOW",
            "ruleId": "R4",
            "tool": {"name": "t5"},
            "location": {"path": "d.js"},
            "message": "Low",
        },
    ]

    out_path = tmp_path / "simple-report.html"
    write_simple_html(findings, out_path)

    html = out_path.read_text(encoding="utf-8")

    # Check severity order in HTML (CRITICAL should appear before HIGH, etc.)
    crit_idx = html.find("CRITICAL")
    high_idx = html.find("HIGH")
    med_idx = html.find("MEDIUM")
    low_idx = html.find("LOW")
    info_idx = html.find("INFO")

    assert crit_idx < high_idx < med_idx < low_idx < info_idx


def test_write_simple_html_empty_findings(tmp_path):
    """Test handling of empty findings list."""
    findings = []

    out_path = tmp_path / "simple-report.html"
    write_simple_html(findings, out_path)

    assert out_path.exists()
    html = out_path.read_text(encoding="utf-8")

    # Should still generate valid HTML
    assert "<!DOCTYPE html>" in html
    assert "Total Findings: 0" in html or "Total Findings:</strong> 0" in html


def test_write_simple_html_tools_list(tmp_path):
    """Test tools used summary."""
    findings = [
        {
            "severity": "HIGH",
            "ruleId": "R1",
            "tool": {"name": "semgrep"},
            "location": {"path": "a.js"},
            "message": "Test 1",
        },
        {
            "severity": "HIGH",
            "ruleId": "R2",
            "tool": {"name": "trivy"},
            "location": {"path": "b.js"},
            "message": "Test 2",
        },
        {
            "severity": "HIGH",
            "ruleId": "R3",
            "tool": {"name": "bandit"},
            "location": {"path": "c.js"},
            "message": "Test 3",
        },
    ]

    out_path = tmp_path / "simple-report.html"
    write_simple_html(findings, out_path)

    html = out_path.read_text(encoding="utf-8")

    # Check tools list in summary
    assert "Tools Used:" in html or "Tools Used</strong>" in html
    assert "semgrep" in html
    assert "trivy" in html
    assert "bandit" in html
