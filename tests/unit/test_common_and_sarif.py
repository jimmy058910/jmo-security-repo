from scripts.core.common_finding import (
    Severity,
    normalize_severity,
    fingerprint,
    extract_code_snippet,
)
from scripts.core.reporters.sarif_reporter import _severity_to_level


def test_normalize_severity_variants():
    assert normalize_severity("error") == "HIGH"
    assert normalize_severity("warn") == "MEDIUM"
    assert normalize_severity(None) == "INFO"
    assert normalize_severity("CRIT") == "CRITICAL"


def test_fingerprint_stability_changes_with_inputs():
    a = fingerprint("t", "R1", "p", 10, "msg")
    b = fingerprint("t", "R1", "p", 11, "msg")
    assert a != b


def test_sarif_level_mapping():
    assert _severity_to_level("CRITICAL") == "error"
    assert _severity_to_level("HIGH") == "error"
    assert _severity_to_level("MEDIUM") == "warning"
    assert _severity_to_level("LOW") == "note"
    assert _severity_to_level(None) == "note"


# Comprehensive Severity enum tests
def test_severity_from_string_direct_match():
    """Test direct severity string matches."""
    assert Severity.from_string("CRITICAL") == Severity.CRITICAL
    assert Severity.from_string("HIGH") == Severity.HIGH
    assert Severity.from_string("MEDIUM") == Severity.MEDIUM
    assert Severity.from_string("LOW") == Severity.LOW
    assert Severity.from_string("INFO") == Severity.INFO


def test_severity_from_string_case_insensitive():
    """Test case-insensitive severity parsing."""
    assert Severity.from_string("critical") == Severity.CRITICAL
    assert Severity.from_string("High") == Severity.HIGH
    assert Severity.from_string("MeDiUm") == Severity.MEDIUM


def test_severity_from_string_mapping():
    """Test severity variant mapping."""
    assert Severity.from_string("ERROR") == Severity.HIGH
    assert Severity.from_string("WARN") == Severity.MEDIUM
    assert Severity.from_string("WARNING") == Severity.MEDIUM
    assert Severity.from_string("CRIT") == Severity.CRITICAL
    assert Severity.from_string("MED") == Severity.MEDIUM


def test_severity_from_string_unknown():
    """Test unknown severity defaults to INFO."""
    assert Severity.from_string("UNKNOWN") == Severity.INFO
    assert Severity.from_string("invalid") == Severity.INFO
    assert Severity.from_string("") == Severity.INFO
    assert Severity.from_string(None) == Severity.INFO


def test_severity_comparison_less_than():
    """Test severity < comparison."""
    assert Severity.INFO < Severity.LOW
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.HIGH < Severity.CRITICAL
    assert not (Severity.CRITICAL < Severity.HIGH)


def test_severity_comparison_less_equal():
    """Test severity <= comparison."""
    assert Severity.INFO <= Severity.INFO
    assert Severity.INFO <= Severity.LOW
    assert Severity.MEDIUM <= Severity.HIGH
    assert not (Severity.CRITICAL <= Severity.HIGH)


def test_severity_comparison_greater_than():
    """Test severity > comparison."""
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO
    assert not (Severity.INFO > Severity.LOW)


def test_severity_comparison_greater_equal():
    """Test severity >= comparison."""
    assert Severity.CRITICAL >= Severity.CRITICAL
    assert Severity.CRITICAL >= Severity.HIGH
    assert Severity.MEDIUM >= Severity.LOW
    assert not (Severity.LOW >= Severity.MEDIUM)


def test_severity_comparison_invalid_type():
    """Test severity comparison with invalid type returns NotImplemented."""
    # Comparison with invalid type should return NotImplemented, not raise
    # Python comparison operators handle NotImplemented by falling back to reflection
    result = Severity.HIGH.__lt__("HIGH")
    assert result is NotImplemented
    result = Severity.HIGH.__gt__(5)
    assert result is NotImplemented


def test_severity_string_representation():
    """Test severity string value."""
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Severity.HIGH.value == "HIGH"  # Use .value for string representation


# Comprehensive extract_code_snippet tests
def test_extract_code_snippet_basic(tmp_path):
    """Test basic code snippet extraction."""
    test_file = tmp_path / "test.py"
    test_file.write_text(
        """line 1
line 2
line 3 - target
line 4
line 5"""
    )

    result = extract_code_snippet(str(test_file), start_line=3, context_lines=1)
    assert result is not None
    assert "line 2" in result["snippet"]
    assert "line 3 - target" in result["snippet"]
    assert "line 4" in result["snippet"]
    assert result["startLine"] == 2  # 1-indexed
    assert result["endLine"] == 4
    assert result["language"] == "python"


def test_extract_code_snippet_file_not_exists():
    """Test snippet extraction for non-existent file."""
    result = extract_code_snippet("/nonexistent/file.py", start_line=1)
    assert result is None


def test_extract_code_snippet_not_a_file(tmp_path):
    """Test snippet extraction for directory."""
    test_dir = tmp_path / "testdir"
    test_dir.mkdir()

    result = extract_code_snippet(str(test_dir), start_line=1)
    assert result is None


def test_extract_code_snippet_empty_file(tmp_path):
    """Test snippet extraction from empty file."""
    test_file = tmp_path / "empty.py"
    test_file.write_text("")

    result = extract_code_snippet(str(test_file), start_line=1)
    assert result is None


def test_extract_code_snippet_first_line(tmp_path):
    """Test snippet extraction at first line."""
    test_file = tmp_path / "test.js"
    test_file.write_text("line 1\nline 2\nline 3")

    result = extract_code_snippet(str(test_file), start_line=1, context_lines=2)
    assert result is not None
    assert "1: line 1" in result["snippet"]
    assert result["startLine"] == 1
    assert result["language"] == "javascript"


def test_extract_code_snippet_last_line(tmp_path):
    """Test snippet extraction at last line."""
    test_file = tmp_path / "test.go"
    test_file.write_text("line 1\nline 2\nline 3")

    result = extract_code_snippet(str(test_file), start_line=3, context_lines=2)
    assert result is not None
    assert "3: line 3" in result["snippet"]
    assert result["endLine"] == 3
    assert result["language"] == "go"


def test_extract_code_snippet_beyond_bounds(tmp_path):
    """Test snippet extraction with line beyond file bounds."""
    test_file = tmp_path / "test.rs"
    test_file.write_text("line 1\nline 2")

    result = extract_code_snippet(str(test_file), start_line=10, context_lines=2)
    assert result is not None
    # Should clamp to available lines
    assert result["language"] == "rust"


def test_extract_code_snippet_language_detection(tmp_path):
    """Test language detection from file extensions."""
    test_cases = [
        ("test.py", "python"),
        ("test.js", "javascript"),
        ("test.ts", "typescript"),
        ("test.go", "go"),
        ("test.rs", "rust"),
        ("test.java", "java"),
        ("test.c", "c"),
        ("test.cpp", "cpp"),
        ("test.rb", "ruby"),
        ("test.php", "php"),
        ("test.sh", "bash"),
        ("test.yaml", "yaml"),
        ("test.yml", "yaml"),
        ("test.json", "json"),
        ("test.xml", "xml"),
        ("test.html", "html"),
        ("test.css", "css"),
        ("test.sql", "sql"),
        ("test.tf", "terraform"),
        ("test.unknown", "text"),
    ]

    for filename, expected_lang in test_cases:
        test_file = tmp_path / filename
        test_file.write_text("test content")
        result = extract_code_snippet(str(test_file), start_line=1)
        assert result is not None
        assert result["language"] == expected_lang, f"Failed for {filename}"


def test_extract_code_snippet_dockerfile_detection(tmp_path):
    """Test Dockerfile detection by name."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM ubuntu:22.04")

    result = extract_code_snippet(str(dockerfile), start_line=1)
    assert result is not None
    assert result["language"] == "dockerfile"

    # Test with .dockerfile extension
    dockerfile_ext = tmp_path / "test.dockerfile"
    dockerfile_ext.write_text("FROM alpine")

    result_ext = extract_code_snippet(str(dockerfile_ext), start_line=1)
    assert result_ext is not None
    assert result_ext["language"] == "dockerfile"


def test_extract_code_snippet_line_numbering(tmp_path):
    """Test snippet line numbering format."""
    test_file = tmp_path / "test.py"
    test_file.write_text("line 1\nline 2\nline 3\nline 4\nline 5")

    result = extract_code_snippet(str(test_file), start_line=3, context_lines=1)
    assert result is not None

    # Check line numbering format
    lines = result["snippet"].split("\n")
    assert any("2: line 2" in line for line in lines)
    assert any("3: line 3" in line for line in lines)
    assert any("4: line 4" in line for line in lines)


def test_extract_code_snippet_large_context(tmp_path):
    """Test snippet with large context lines."""
    test_file = tmp_path / "test.py"
    content = "\n".join(f"line {i}" for i in range(1, 101))
    test_file.write_text(content)

    result = extract_code_snippet(str(test_file), start_line=50, context_lines=10)
    assert result is not None
    assert result["startLine"] == 40  # 50 - 10
    assert result["endLine"] == 60  # 50 + 10


def test_extract_code_snippet_unicode_content(tmp_path):
    """Test snippet extraction with unicode content."""
    test_file = tmp_path / "test.py"
    test_file.write_text(
        "# -*- coding: utf-8 -*-\nprint('Hello 世界')\n# Comment 日本語"
    )

    result = extract_code_snippet(str(test_file), start_line=2, context_lines=1)
    assert result is not None
    assert "世界" in result["snippet"]
    assert "utf-8" in result["snippet"]


def test_extract_code_snippet_zero_context(tmp_path):
    """Test snippet with zero context lines."""
    test_file = tmp_path / "test.py"
    test_file.write_text("line 1\nline 2\nline 3")

    result = extract_code_snippet(str(test_file), start_line=2, context_lines=0)
    assert result is not None
    assert "2: line 2" in result["snippet"]
    assert "line 1" not in result["snippet"]
    assert "line 3" not in result["snippet"]


def test_extract_code_snippet_exception_handling(tmp_path):
    """Test snippet extraction handles exceptions gracefully."""
    # Create a file and then make it unreadable
    test_file = tmp_path / "test.py"
    test_file.write_text("content")

    # Patch to simulate read error
    from unittest.mock import patch

    with patch("pathlib.Path.read_text", side_effect=Exception("Read error")):
        result = extract_code_snippet(str(test_file), start_line=1)
        assert result is None


def test_fingerprint_stability_same_inputs():
    """Test fingerprint generates same ID for same inputs."""
    fp1 = fingerprint("semgrep", "rule123", "file.py", 42, "test message")
    fp2 = fingerprint("semgrep", "rule123", "file.py", 42, "test message")
    assert fp1 == fp2


def test_fingerprint_different_tool():
    """Test fingerprint changes with different tool."""
    fp1 = fingerprint("semgrep", "rule1", "file.py", 1, "msg")
    fp2 = fingerprint("gitleaks", "rule1", "file.py", 1, "msg")
    assert fp1 != fp2


def test_fingerprint_different_rule():
    """Test fingerprint changes with different rule."""
    fp1 = fingerprint("semgrep", "rule1", "file.py", 1, "msg")
    fp2 = fingerprint("semgrep", "rule2", "file.py", 1, "msg")
    assert fp1 != fp2


def test_fingerprint_different_path():
    """Test fingerprint changes with different path."""
    fp1 = fingerprint("semgrep", "rule1", "file1.py", 1, "msg")
    fp2 = fingerprint("semgrep", "rule1", "file2.py", 1, "msg")
    assert fp1 != fp2


def test_fingerprint_different_message():
    """Test fingerprint changes with different message."""
    fp1 = fingerprint("semgrep", "rule1", "file.py", 1, "message 1")
    fp2 = fingerprint("semgrep", "rule1", "file.py", 1, "message 2")
    assert fp1 != fp2


def test_fingerprint_none_values():
    """Test fingerprint with None values."""
    fp = fingerprint("tool", None, None, None, None)
    assert isinstance(fp, str)
    assert len(fp) == 16  # FINGERPRINT_LENGTH


def test_fingerprint_long_message_truncation():
    """Test fingerprint truncates long messages."""
    long_msg = "x" * 200
    fp1 = fingerprint("tool", "rule", "path", 1, long_msg)
    fp2 = fingerprint("tool", "rule", "path", 1, long_msg + "extra")
    # Both should use first 120 chars, so fingerprints should be same
    assert fp1 == fp2


def test_fingerprint_hex_format():
    """Test fingerprint returns valid hex string."""
    fp = fingerprint("tool", "rule", "path", 1, "msg")
    assert isinstance(fp, str)
    assert len(fp) == 16
    # Should be valid hex
    int(fp, 16)  # Will raise if not valid hex
