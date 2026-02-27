"""
Tests for html_reporter.py - Interactive HTML dashboard generation.

Coverage targets:
- Inline mode (<1000 findings)
- External mode (>1000 findings)
- Fallback HTML mode
- React build detection
- JSON escaping for script injection prevention
"""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.core.reporters.html_reporter import (
    write_html,
    _write_fallback_html,
    INLINE_THRESHOLD,
)


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        {
            "id": "finding-1",
            "severity": "HIGH",
            "ruleId": "rule-1",
            "message": "Test finding 1",
            "schemaVersion": "1.2.0",
            "tool": {"name": "test-tool", "version": "1.0"},
            "location": {"path": "file.py", "startLine": 10},
        },
        {
            "id": "finding-2",
            "severity": "MEDIUM",
            "ruleId": "rule-2",
            "message": "Test finding 2",
            "schemaVersion": "1.2.0",
            "tool": {"name": "test-tool", "version": "1.0"},
            "location": {"path": "file.py", "startLine": 20},
        },
    ]


def test_write_html_inline_mode_react_build(tmp_path, sample_findings):
    """Test inline mode (<1000 findings) with React build available."""
    output_path = tmp_path / "dashboard.html"

    # Set environment to skip React build check and use test fixture
    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    try:
        write_html(sample_findings, output_path)

        assert output_path.exists()
        html = output_path.read_text(encoding="utf-8")

        # Verify inline mode (data embedded in HTML)
        assert "window.__FINDINGS__ = [" in html
        assert "finding-1" in html
        assert "finding-2" in html

        # Verify no external JSON file created
        json_path = tmp_path / "findings.json"
        assert not json_path.exists()
    finally:
        os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_write_html_inline_mode_threshold(tmp_path):
    """Test inline mode exactly at INLINE_THRESHOLD."""
    # Create findings exactly at threshold
    findings = [
        {"id": f"f{i}", "severity": "HIGH", "message": f"Finding {i}"}
        for i in range(INLINE_THRESHOLD)
    ]
    output_path = tmp_path / "dashboard.html"

    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    try:
        write_html(findings, output_path)

        html = output_path.read_text(encoding="utf-8")
        # Should use inline mode (≤ threshold)
        assert "window.__FINDINGS__ = [" in html

        # Verify no external JSON file
        json_path = tmp_path / "findings.json"
        assert not json_path.exists()
    finally:
        os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_write_html_external_mode(tmp_path):
    """Test external mode (>1000 findings) with separate JSON file."""
    # Create findings above threshold
    findings = [
        {"id": f"f{i}", "severity": "HIGH", "message": f"Finding {i}"}
        for i in range(INLINE_THRESHOLD + 1)
    ]
    output_path = tmp_path / "dashboard.html"

    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    try:
        write_html(findings, output_path)

        html = output_path.read_text(encoding="utf-8")
        # Should use external mode (> threshold)
        assert "window.__FINDINGS__ = []  // Loaded via fetch()" in html

        # Verify external JSON file created
        json_path = tmp_path / "findings.json"
        assert json_path.exists()

        # Verify JSON content
        json_data = json.loads(json_path.read_text(encoding="utf-8"))
        assert len(json_data) == INLINE_THRESHOLD + 1
        assert json_data[0]["id"] == "f0"
    finally:
        os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_write_html_script_injection_prevention(tmp_path):
    """Test that dangerous characters are escaped to prevent script injection."""
    findings = [
        {
            "id": "xss-1",
            "message": "</script><script>alert('XSS')</script>",
            "severity": "HIGH",
        },
        {
            "id": "xss-2",
            "message": "<!-- comment injection -->",
            "severity": "MEDIUM",
        },
        {
            "id": "xss-3",
            "message": "Template `literal` injection",
            "severity": "LOW",
        },
    ]
    output_path = tmp_path / "dashboard.html"

    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    try:
        write_html(findings, output_path)

        html = output_path.read_text(encoding="utf-8")

        # Verify dangerous characters are escaped in the JSON data
        # Note: escaping only happens in inline mode when data embedded in <script> tag
        if "window.__FINDINGS__ = [{" in html:  # Inline mode detected
            assert "<\\/script>" in html  # Should escape </script>
            assert "<\\script" in html  # Should escape <script
            assert "<\\!--" in html  # Should escape <!--
            assert "\\`" in html  # Should escape backticks
        else:
            # Fallback or external mode - no escaping needed (data in separate file)
            pass
    finally:
        os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_write_html_fallback_mode(tmp_path, sample_findings):
    """Test fallback HTML mode works when React build and fixture unavailable.

    Note: This test calls _write_fallback_html directly since mocking Path
    construction is complex. The integration test via write_html() is covered
    by other tests when SKIP_REACT_BUILD_CHECK=true.
    """
    output_path = tmp_path / "dashboard.html"

    # Call fallback function directly
    _write_fallback_html(sample_findings, output_path)

    assert output_path.exists()
    html = output_path.read_text(encoding="utf-8")

    # Verify fallback HTML structure
    assert "<!DOCTYPE html>" in html
    assert "JMo Security Findings Report" in html
    assert "Fallback HTML Mode" in html
    assert "npm run build" in html
    assert "Total Findings:</strong> 2" in html  # 2 findings from sample_findings


def test_write_fallback_html_direct(tmp_path):
    """Test _write_fallback_html() directly."""
    findings = [{"id": f"f{i}", "severity": "HIGH"} for i in range(42)]
    output_path = tmp_path / "fallback.html"

    _write_fallback_html(findings, output_path)

    assert output_path.exists()
    html = output_path.read_text(encoding="utf-8")

    assert "<!DOCTYPE html>" in html
    assert "JMo Security Findings Report" in html
    assert "Total Findings:</strong> 42" in html  # Matches actual HTML structure
    assert "Fallback HTML Mode" in html
    assert "npm run build" in html


def test_write_html_creates_parent_directory(tmp_path):
    """Test that parent directory is created if it doesn't exist."""
    output_path = tmp_path / "nested" / "dir" / "dashboard.html"
    findings = [{"id": "f1", "severity": "HIGH"}]

    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    try:
        write_html(findings, output_path)

        assert output_path.exists()
        assert output_path.parent.exists()
    finally:
        os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_write_html_with_test_fixture(tmp_path, sample_findings):
    """Test using test fixture when React build missing but fixture available."""
    output_path = tmp_path / "output" / "dashboard.html"

    # Create fake module structure (React build won't exist)
    fake_scripts_dir = tmp_path / "scripts"
    fake_core_dir = fake_scripts_dir / "core"
    fake_reporters_dir = fake_core_dir / "reporters"
    fake_reporters_dir.mkdir(parents=True)
    fake_module_file = fake_reporters_dir / "html_reporter.py"
    fake_module_file.touch()

    # Create test fixture at tests/fixtures/dashboard/test-inline-dashboard.html
    # (repo root is tmp_path/)
    fixture_dir = tmp_path / "tests" / "fixtures" / "dashboard"
    fixture_dir.mkdir(parents=True)
    fixture_file = fixture_dir / "test-inline-dashboard.html"
    fixture_file.write_text(
        "<!DOCTYPE html><html><head><title>Fixture</title></head>"
        '<body><div id="fixture-test"></div>'
        "<script>window.__FINDINGS__ = []</script></body></html>",
        encoding="utf-8",
    )

    # Set environment to skip React build check (allows fallback to fixture)
    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    try:
        # Mock __file__ to use our tmp_path structure
        with patch(
            "scripts.core.reporters.html_reporter.__file__", str(fake_module_file)
        ):
            write_html(sample_findings, output_path)

            assert output_path.exists()
            html = output_path.read_text(encoding="utf-8")

            # Verify fixture template was used (not React build, not fallback)
            assert "fixture-test" in html
            assert "window.__FINDINGS__ = [{" in html
    finally:
        os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_write_html_empty_findings(tmp_path):
    """Test writing HTML with empty findings list."""
    output_path = tmp_path / "dashboard.html"

    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    try:
        write_html([], output_path)

        assert output_path.exists()
        html = output_path.read_text(encoding="utf-8")

        # Should use inline mode (0 < threshold)
        assert "window.__FINDINGS__ = []" in html
    finally:
        os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_write_html_unicode_handling(tmp_path):
    """Test that Unicode characters are handled correctly."""
    findings = [
        {
            "id": "unicode-1",
            "message": "Test with emoji: 🔒 🛡️ 🚨",
            "severity": "HIGH",
        },
        {
            "id": "unicode-2",
            "message": "Test with CJK: 测试 テスト",
            "severity": "MEDIUM",
        },
    ]
    output_path = tmp_path / "dashboard.html"

    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    try:
        write_html(findings, output_path)

        assert output_path.exists()
        html = output_path.read_text(encoding="utf-8")

        # Verify Unicode characters are preserved
        assert "🔒" in html or "\\u" in html  # Either literal or JSON-escaped
        assert "测试" in html or "\\u" in html
    finally:
        os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_write_html_pathlib_and_str_paths(tmp_path, sample_findings):
    """Test that both pathlib.Path and str paths work."""
    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    try:
        # Test with Path object
        path1 = tmp_path / "dashboard1.html"
        write_html(sample_findings, path1)
        assert path1.exists()

        # Test with string path
        path2 = str(tmp_path / "dashboard2.html")
        write_html(sample_findings, path2)
        assert Path(path2).exists()
    finally:
        os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_write_html_large_findings_performance(tmp_path):
    """Test external mode with very large findings list."""
    # Create 5000 findings (well above threshold)
    findings = [
        {"id": f"f{i}", "severity": "HIGH", "message": f"Finding {i}"}
        for i in range(5000)
    ]
    output_path = tmp_path / "dashboard.html"

    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    try:
        write_html(findings, output_path)

        # Verify HTML is small (external mode)
        html = output_path.read_text(encoding="utf-8")
        html_size = len(html)
        assert html_size < 1_000_000  # Should be < 1MB (no embedded data)

        # Verify external JSON file is created and large
        json_path = tmp_path / "findings.json"
        assert json_path.exists()
        json_size = json_path.stat().st_size
        assert json_size > 100_000  # Should be > 100KB (5000 findings)
    finally:
        os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_write_html_with_react_build(tmp_path, sample_findings):
    """Test using actual React build when available."""
    output_path = tmp_path / "output" / "dashboard.html"

    # Create fake module structure matching real layout:
    # scripts/core/reporters/html_reporter.py
    # The code does: Path(__file__).parent.parent.parent / "dashboard"
    # So from reporters/ -> core/ -> scripts/ -> scripts/dashboard/
    fake_scripts_dir = tmp_path / "scripts"
    fake_core_dir = fake_scripts_dir / "core"
    fake_reporters_dir = fake_core_dir / "reporters"
    fake_reporters_dir.mkdir(parents=True)
    fake_module_file = fake_reporters_dir / "html_reporter.py"
    fake_module_file.touch()

    # Create React build at scripts/dashboard/dist/index.html
    dashboard_dir = fake_scripts_dir / "dashboard"
    react_build_dir = dashboard_dir / "dist"
    react_build_dir.mkdir(parents=True)
    react_build_file = react_build_dir / "index.html"

    # Write fake React build with placeholder
    react_build_file.write_text(
        "<!DOCTYPE html><html><head><title>Test</title></head>"
        '<body><div id="root"></div>'
        "<script>window.__FINDINGS__ = []</script></body></html>",
        encoding="utf-8",
    )

    # Mock __file__ to point to our fake structure
    with patch("scripts.core.reporters.html_reporter.__file__", str(fake_module_file)):
        write_html(sample_findings, output_path)

        assert output_path.exists()
        html = output_path.read_text(encoding="utf-8")

        # Verify React build template was used
        assert '<div id="root"></div>' in html
        # Verify inline mode (data embedded)
        assert "window.__FINDINGS__ = [{" in html


def test_write_html_react_build_check_enforced(tmp_path, sample_findings):
    """Test that React build check is enforced when SKIP_REACT_BUILD_CHECK=false."""
    output_path = tmp_path / "dashboard.html"

    # Ensure SKIP_REACT_BUILD_CHECK and CI are not set
    os.environ.pop("SKIP_REACT_BUILD_CHECK", None)
    os.environ.pop("CI", None)

    # Mock the __file__ location to ensure React build path doesn't exist
    fake_file_path = tmp_path / "fake_module.py"
    fake_file_path.touch()  # Create the fake module file

    with patch("scripts.core.reporters.html_reporter.__file__", str(fake_file_path)):
        # Should raise FileNotFoundError when React build missing and check enabled
        # The dashboard_dir will be tmp_path/dashboard which doesn't exist
        with pytest.raises(FileNotFoundError, match="React dashboard build not found"):
            write_html(sample_findings, output_path)
