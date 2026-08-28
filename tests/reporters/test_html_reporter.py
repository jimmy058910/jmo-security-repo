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
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.core.reporters.html_reporter import (
    INLINE_THRESHOLD,
    PROVENANCE_META_NAME,
    _write_fallback_html,
    write_html,
)

#: A minimal stand-in for a `npm run build` artifact: everything write_html
#: needs from a React build, and nothing else.
MINIMAL_REACT_BUILD = (
    "<!DOCTYPE html><html><head><title>JMo Security Dashboard</title>"
    "<script>window.__FINDINGS__ = []</script></head>"
    '<body><div id="root"></div></body></html>'
)


@pytest.fixture(autouse=True)
def pinned_react_build(tmp_path_factory, monkeypatch):
    """Render every test in this file from a known React build.

    These tests used to wrap ``write_html`` in ``SKIP_REACT_BUILD_CHECK``
    try/finally blocks, which nothing had read since ``df55c8f`` removed the
    ``FileNotFoundError`` that variable gated. They therefore exercised
    whichever template the machine happened to have -- a real ``dist/`` build
    locally, the vendored ``tests/fixtures/dashboard`` build in CI -- so the
    same test covered different code on different machines.

    Tests that need a *different* template still patch ``__file__`` themselves;
    that takes effect inside this one and is restored after.
    """
    root = tmp_path_factory.mktemp("pinned-build")
    reporters = root / "scripts" / "core" / "reporters"
    reporters.mkdir(parents=True)
    module = reporters / "html_reporter.py"
    module.touch()
    dist = root / "scripts" / "dashboard" / "dist"
    dist.mkdir(parents=True)
    (dist / "index.html").write_text(MINIMAL_REACT_BUILD, encoding="utf-8")
    monkeypatch.setattr(
        "scripts.core.reporters.html_reporter.__file__", str(module), raising=False
    )
    return dist / "index.html"


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

    write_html(sample_findings, output_path)

    assert output_path.exists()
    html = output_path.read_text(encoding="utf-8")

    # Verify inline mode (data embedded in HTML)
    assert "window.__FINDINGS__ = [" in html
    assert "finding-1" in html
    assert "finding-2" in html

    # Verify no external JSON file created
    json_path = tmp_path / "dashboard-data.json"
    assert not json_path.exists()


def test_write_html_inline_mode_threshold(tmp_path):
    """Test inline mode exactly at INLINE_THRESHOLD."""
    # Create findings exactly at threshold
    findings = [
        {"id": f"f{i}", "severity": "HIGH", "message": f"Finding {i}"}
        for i in range(INLINE_THRESHOLD)
    ]
    output_path = tmp_path / "dashboard.html"

    write_html(findings, output_path)

    html = output_path.read_text(encoding="utf-8")
    # Should use inline mode (≤ threshold)
    assert "window.__FINDINGS__ = [" in html

    # Verify no external JSON file
    json_path = tmp_path / "dashboard-data.json"
    assert not json_path.exists()


def test_write_html_external_mode(tmp_path):
    """Test external mode (>1000 findings) with separate JSON file."""
    # Create findings above threshold
    findings = [
        {"id": f"f{i}", "severity": "HIGH", "message": f"Finding {i}"}
        for i in range(INLINE_THRESHOLD + 1)
    ]
    output_path = tmp_path / "dashboard.html"

    write_html(findings, output_path)

    html = output_path.read_text(encoding="utf-8")
    # Should use external mode (> threshold)
    assert "window.__FINDINGS__ = []  // Loaded via fetch()" in html

    # Verify external JSON file created
    json_path = tmp_path / "dashboard-data.json"
    assert json_path.exists()

    # Verify JSON content
    json_data = json.loads(json_path.read_text(encoding="utf-8"))
    assert len(json_data) == INLINE_THRESHOLD + 1
    assert json_data[0]["id"] == "f0"


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

    write_html(findings, output_path)

    html = output_path.read_text(encoding="utf-8")

    # The template is pinned to a React build, so inline mode is guaranteed --
    # this assertion used to sit behind `if inline mode:` with a bare `pass`
    # else-branch, so on a machine that took a different branch the whole
    # injection check silently asserted nothing.
    assert "window.__FINDINGS__ = [{" in html

    # `<` cannot survive into the script block in any form, so no end tag,
    # comment open or entity can be spelled there regardless of case.
    prefix = "window.__FINDINGS__ = "
    payload_start = html.index(prefix) + len(prefix)
    payload = html[payload_start : html.index("</script>", payload_start)]
    assert "<" not in payload, f"raw '<' reached the embedded payload: {payload[:200]}"
    assert "\\u003c" in payload  # the escaped form is what is there instead

    # Escaping must not corrupt the data: \uXXXX is valid JSON, `<\script` was not.
    decoded = json.loads(payload)
    assert decoded[0]["message"] == "</script><script>alert('XSS')</script>"
    assert decoded[1]["message"] == "<!-- comment injection -->"
    assert decoded[2]["message"] == "Template `literal` injection"


def test_write_html_fallback_mode(tmp_path, sample_findings):
    """Test fallback HTML mode works when React build and fixture unavailable.

    Note: This test calls _write_fallback_html directly. The integration path
    through write_html() is covered by
    tests/reporters/test_html_template_provenance.py, which pins each template
    by patching html_reporter.__file__.
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

    write_html(findings, output_path)

    assert output_path.exists()
    assert output_path.parent.exists()


def test_write_html_without_a_bundle_uses_the_static_fallback(
    tmp_path, sample_findings
):
    """A tree with no built bundle degrades to the static page, and says so.

    This replaced ``test_write_html_with_test_fixture``, which exercised a rung
    that no longer exists: ``write_html`` used to fall from the React build to a
    build vendored under ``tests/fixtures/dashboard/``, because
    ``scripts/dashboard/dist/`` was gitignored and no real tree had one. The
    bundle is tracked now (#862), so the fixture branch was unreachable and was
    deleted along with its 697 KB 2025-11-17 artifact (#864). What matters here
    is that a missing bundle degrades *loudly* rather than to a stale build.
    """
    output_path = tmp_path / "output" / "dashboard.html"

    # Fake module structure with no scripts/dashboard/dist/index.html in it.
    fake_reporters_dir = tmp_path / "scripts" / "core" / "reporters"
    fake_reporters_dir.mkdir(parents=True)
    fake_module_file = fake_reporters_dir / "html_reporter.py"
    fake_module_file.touch()

    # A fixture at the old location must NOT be picked up any more.
    fixture_dir = tmp_path / "tests" / "fixtures" / "dashboard"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "test-inline-dashboard.html").write_text(
        "<!DOCTYPE html><html><head><title>Fixture</title></head>"
        '<body><div id="fixture-test"></div>'
        "<script>window.__FINDINGS__ = []</script></body></html>",
        encoding="utf-8",
    )

    with patch("scripts.core.reporters.html_reporter.__file__", str(fake_module_file)):
        write_html(sample_findings, output_path)

    assert output_path.exists()
    html = output_path.read_text(encoding="utf-8")

    assert "fixture-test" not in html, "the deleted fixture rung was resurrected"
    assert 'content="fallback"' in html
    assert "Fallback HTML Mode" in html


def test_write_html_empty_findings(tmp_path):
    """Test writing HTML with empty findings list."""
    output_path = tmp_path / "dashboard.html"

    write_html([], output_path)

    assert output_path.exists()
    html = output_path.read_text(encoding="utf-8")

    # Should use inline mode (0 < threshold)
    assert "window.__FINDINGS__ = []" in html


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

    write_html(findings, output_path)

    assert output_path.exists()
    html = output_path.read_text(encoding="utf-8")

    # Verify Unicode characters are preserved
    assert "🔒" in html or "\\u" in html  # Either literal or JSON-escaped
    assert "测试" in html or "\\u" in html


def test_write_html_pathlib_and_str_paths(tmp_path, sample_findings):
    """Test that both pathlib.Path and str paths work."""
    # Test with Path object
    path1 = tmp_path / "dashboard1.html"
    write_html(sample_findings, path1)
    assert path1.exists()

    # Test with string path
    path2 = str(tmp_path / "dashboard2.html")
    write_html(sample_findings, path2)
    assert Path(path2).exists()


def test_write_html_large_findings_performance(tmp_path):
    """Test external mode with very large findings list."""
    # Create 5000 findings (well above threshold)
    findings = [
        {"id": f"f{i}", "severity": "HIGH", "message": f"Finding {i}"}
        for i in range(5000)
    ]
    output_path = tmp_path / "dashboard.html"

    write_html(findings, output_path)

    # Verify HTML is small (external mode)
    html = output_path.read_text(encoding="utf-8")
    html_size = len(html)
    assert html_size < 1_000_000  # Should be < 1MB (no embedded data)

    # Verify external JSON file is created and large
    json_path = tmp_path / "dashboard-data.json"
    assert json_path.exists()
    json_size = json_path.stat().st_size
    assert json_size > 100_000  # Should be > 100KB (5000 findings)


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


def test_write_html_fallback_when_react_build_missing(tmp_path, sample_findings):
    """Test that fallback HTML is produced when React build is missing."""
    output_path = tmp_path / "dashboard.html"

    # Mock the __file__ location to ensure React build path doesn't exist
    fake_file_path = tmp_path / "fake_module.py"
    fake_file_path.touch()  # Create the fake module file

    with patch("scripts.core.reporters.html_reporter.__file__", str(fake_file_path)):
        # Should produce fallback HTML instead of raising
        write_html(sample_findings, output_path)

    assert output_path.exists(), "Fallback dashboard.html should be created"
    html = output_path.read_text(encoding="utf-8")
    # This used to read `"Fallback HTML Mode" in html or "JMo Security" in html`,
    # which no template in the chain can fail: all three carry "JMo Security" in
    # their <title>. Assert the thing that actually distinguishes them.
    assert "Fallback HTML Mode" in html
    assert f'<meta name="{PROVENANCE_META_NAME}" content="fallback"' in html
    assert "JMo Security Dashboard" not in html, "React template was used, not fallback"
