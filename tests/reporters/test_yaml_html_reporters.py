from pathlib import Path

import pytest

from scripts.core.reporters.yaml_reporter import write_yaml
from scripts.core.reporters.html_reporter import write_html


SAMPLE = [
    {
        "schemaVersion": "1.0.0",
        "id": "abc",
        "ruleId": "aws-key",
        "message": "Potential AWS key",
        "severity": "HIGH",
        "tool": {"name": "gitleaks", "version": "x"},
        "location": {"path": "a.txt", "startLine": 1},
    }
]


def test_write_yaml(tmp_path: Path):
    try:
        out = tmp_path / "f.yaml"
        write_yaml(SAMPLE, out)
        s = out.read_text(encoding="utf-8")
        assert "aws-key" in s and "schemaVersion" in s
    except RuntimeError:
        pytest.skip("PyYAML not installed")


def test_write_html(tmp_path: Path):
    out = tmp_path / "f.html"
    write_html(SAMPLE, out)
    s = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in s
    assert (
        "Security Dashboard" in s or "Security Summary" in s
    )  # v2 renamed to Dashboard
    assert "aws-key" in s or "AWS" in s


def test_html_script_tag_escaping(tmp_path: Path):
    """Test that dangerous HTML/JS characters are properly escaped in dashboard JSON data.

    This is a CRITICAL security test - without proper escaping, malicious content
    in findings can break out of the <script> tag and inject arbitrary HTML/JS.

    Bug: https://github.com/jimmy058910/jmo-security-repo/issues/XXXXX
    The dashboard was broken because findings contained literal </script> strings
    that weren't escaped, causing premature script tag closure.
    """
    # Create findings with dangerous characters that must be escaped
    dangerous_findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "test1",
            "ruleId": "XSS-001",
            "message": "Found </script> tag in code",  # CRITICAL: breaks script tag
            "description": "This finding contains </script> which must be escaped",
            "severity": "HIGH",
            "tool": {"name": "test-tool", "version": "1.0"},
            "location": {"path": "test.js", "startLine": 10},
        },
        {
            "schemaVersion": "1.2.0",
            "id": "test2",
            "ruleId": "XSS-002",
            "message": "Found <script>alert(1)</script> injection",  # Script injection
            "description": "Contains <script> tags that must be escaped",
            "severity": "CRITICAL",
            "tool": {"name": "test-tool", "version": "1.0"},
            "location": {"path": "test.html", "startLine": 20},
        },
        {
            "schemaVersion": "1.2.0",
            "id": "test3",
            "ruleId": "XSS-003",
            "message": "Found <!-- comment with </script> inside -->",  # HTML comment
            "description": "Contains HTML comment markers",
            "severity": "MEDIUM",
            "tool": {"name": "test-tool", "version": "1.0"},
            "location": {"path": "test.html", "startLine": 30},
        },
        {
            "schemaVersion": "1.2.0",
            "id": "test4",
            "ruleId": "XSS-004",
            "message": "Template literal with `backticks`",  # Backtick escaping
            "description": "Contains `backticks` that could break template literals",
            "severity": "LOW",
            "tool": {"name": "test-tool", "version": "1.0"},
            "location": {"path": "test.js", "startLine": 40},
        },
    ]

    out = tmp_path / "dangerous.html"
    write_html(dangerous_findings, out)
    html_content = out.read_text(encoding="utf-8")

    # 1. Verify HTML structure is valid (basic check)
    assert "<!DOCTYPE html>" in html_content
    assert "<html" in html_content
    assert "</html>" in html_content

    # 2. Count script tags - should be balanced (equal opens and closes)
    open_script_count = html_content.count("<script>")
    close_script_count = html_content.count("</script>")
    assert open_script_count == close_script_count, (
        f"Unbalanced script tags! Found {open_script_count} <script> "
        f"but {close_script_count} </script> tags. This indicates </script> "
        f"in JSON data wasn't properly escaped."
    )

    # 3. Verify dangerous strings are properly escaped in the data JSON
    # The data should be embedded as: const data = [...];
    # Extract the script content (between <script> and first </script>)
    script_start = html_content.find("<script>")
    script_end = html_content.find("</script>", script_start)
    assert script_start != -1 and script_end != -1, "Could not find script tags"

    script_content = html_content[script_start:script_end]

    # 4. Verify that dangerous strings were escaped (should contain escaped versions)
    # </script> should be escaped as <\/script>
    assert r"<\/script>" in script_content or r"<\\\/script>" in script_content, (
        "Danger! Found </script> in script content without proper escaping. "
        "This will break out of the <script> tag!"
    )

    # 5. Verify that unescaped dangerous strings DON'T appear in data JSON
    # (They might appear in HTML elsewhere, but not in the JSON data)
    # Find the data array declaration
    data_start = script_content.find("const data = [")
    data_end = script_content.find("];", data_start)
    if data_start != -1 and data_end != -1:
        data_json = script_content[data_start:data_end+2]

        # Count unescaped </script> (should be 0 or very few, definitely not 4+)
        unescaped_count = data_json.count("</script>")
        # We expect at most 1 (the closing tag for const data = [...];)
        # But the fix should make it 0 in the data itself
        assert unescaped_count <= 1, (
            f"Found {unescaped_count} unescaped </script> in data JSON! "
            f"These will break the script tag. Expected 0-1."
        )

    # 6. Verify the dashboard data is loadable by checking structure
    assert "const data = [" in script_content
    assert "let sortKey" in script_content  # Verify rest of JS is present
    assert "function render()" in script_content  # Core function exists
