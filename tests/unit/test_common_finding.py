#!/usr/bin/env python3
"""
Comprehensive tests for scripts/core/common_finding.py

Tests cover:
- Severity enum and comparison operators
- normalize_severity() function
- fingerprint() function for stable ID generation
- extract_code_snippet() function with language detection

Target: ≥85% coverage for scripts/core/common_finding.py
"""

from __future__ import annotations

import hashlib
from pathlib import Path


from scripts.core.common_finding import (
    FINGERPRINT_LENGTH,
    MESSAGE_SNIPPET_LENGTH,
    SEVERITY_ORDER,
    TOOL_SEVERITY_MAPPINGS,
    Severity,
    extract_code_snippet,
    fingerprint,
    map_tool_severity,
    normalize_severity,
)


# ============================================================================
# 1. Severity Enum Tests
# ============================================================================


class TestSeverityEnum:
    """Tests for Severity enum basic functionality."""

    def test_severity_values(self):
        """Test that all severity levels exist with correct values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_severity_is_string(self):
        """Test that Severity inherits from str."""
        assert isinstance(Severity.HIGH, str)
        assert isinstance(Severity.MEDIUM, str)

    def test_severity_order_list(self):
        """Test that SEVERITY_ORDER contains all severity strings."""
        assert SEVERITY_ORDER == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class TestSeverityFromString:
    """Tests for Severity.from_string() method."""

    def test_from_string_exact_match(self):
        """Test exact string matches."""
        assert Severity.from_string("CRITICAL") == Severity.CRITICAL
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("MEDIUM") == Severity.MEDIUM
        assert Severity.from_string("LOW") == Severity.LOW
        assert Severity.from_string("INFO") == Severity.INFO

    def test_from_string_case_insensitive(self):
        """Test case-insensitive parsing."""
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("High") == Severity.HIGH
        assert Severity.from_string("mEdIuM") == Severity.MEDIUM
        assert Severity.from_string("low") == Severity.LOW
        assert Severity.from_string("info") == Severity.INFO

    def test_from_string_with_whitespace(self):
        """Test parsing with leading/trailing whitespace."""
        assert Severity.from_string("  CRITICAL  ") == Severity.CRITICAL
        assert Severity.from_string("\tHIGH\n") == Severity.HIGH

    def test_from_string_common_variants(self):
        """Test mapping of common severity variants."""
        # ERROR → HIGH
        assert Severity.from_string("ERROR") == Severity.HIGH
        assert Severity.from_string("error") == Severity.HIGH

        # WARN/WARNING → MEDIUM
        assert Severity.from_string("WARN") == Severity.MEDIUM
        assert Severity.from_string("WARNING") == Severity.MEDIUM
        assert Severity.from_string("warning") == Severity.MEDIUM

        # CRIT → CRITICAL
        assert Severity.from_string("CRIT") == Severity.CRITICAL
        assert Severity.from_string("crit") == Severity.CRITICAL

        # MED → MEDIUM
        assert Severity.from_string("MED") == Severity.MEDIUM
        assert Severity.from_string("med") == Severity.MEDIUM

        # INFORMATIONAL/INFORMATION → INFO
        assert Severity.from_string("INFORMATIONAL") == Severity.INFO
        assert Severity.from_string("INFORMATION") == Severity.INFO
        assert Severity.from_string("informational") == Severity.INFO

        # NOTE → LOW
        assert Severity.from_string("NOTE") == Severity.LOW
        assert Severity.from_string("note") == Severity.LOW

        # STYLE → INFO
        assert Severity.from_string("STYLE") == Severity.INFO
        assert Severity.from_string("style") == Severity.INFO

    def test_from_string_none(self):
        """Test that None returns INFO."""
        assert Severity.from_string(None) == Severity.INFO

    def test_from_string_empty(self):
        """Test that empty string returns INFO."""
        assert Severity.from_string("") == Severity.INFO
        assert Severity.from_string("   ") == Severity.INFO

    def test_from_string_unknown(self):
        """Test that unknown strings return INFO."""
        assert Severity.from_string("UNKNOWN") == Severity.INFO
        assert Severity.from_string("invalid") == Severity.INFO
        assert Severity.from_string("123") == Severity.INFO


class TestSeverityComparisons:
    """Tests for Severity comparison operators."""

    def test_less_than(self):
        """Test __lt__ operator (CRITICAL > HIGH > MEDIUM > LOW > INFO)."""
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

        # Test non-adjacent levels
        assert Severity.INFO < Severity.CRITICAL
        assert Severity.LOW < Severity.HIGH

    def test_less_than_equal(self):
        """Test __le__ operator."""
        # Less than
        assert Severity.INFO <= Severity.LOW
        assert Severity.LOW <= Severity.MEDIUM

        # Equal
        assert Severity.HIGH <= Severity.HIGH
        assert Severity.CRITICAL <= Severity.CRITICAL

    def test_greater_than(self):
        """Test __gt__ operator."""
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

        # Test non-adjacent levels
        assert Severity.CRITICAL > Severity.INFO
        assert Severity.HIGH > Severity.LOW

    def test_greater_than_equal(self):
        """Test __ge__ operator."""
        # Greater than
        assert Severity.CRITICAL >= Severity.HIGH
        assert Severity.MEDIUM >= Severity.LOW

        # Equal
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.INFO >= Severity.INFO

    def test_equality(self):
        """Test equality comparisons."""
        assert Severity.CRITICAL == Severity.CRITICAL
        assert Severity.HIGH == Severity.HIGH
        assert not (Severity.HIGH == Severity.MEDIUM)

    def test_string_inheritance(self):
        """Test that Severity inherits from str for JSON serialization."""
        # Severity should be usable as a string
        assert isinstance(Severity.HIGH, str)

        # Value is the actual severity string
        assert Severity.HIGH.value == "HIGH"

        # Can be compared directly with strings (due to str inheritance)
        # This is intentional for JSON compatibility
        assert Severity.HIGH == "HIGH"


# ============================================================================
# 2. normalize_severity() Tests
# ============================================================================


class TestNormalizeSeverity:
    """Tests for normalize_severity() function."""

    def test_normalize_severity_exact_match(self):
        """Test normalization of exact severity strings."""
        assert normalize_severity("CRITICAL") == "CRITICAL"
        assert normalize_severity("HIGH") == "HIGH"
        assert normalize_severity("MEDIUM") == "MEDIUM"
        assert normalize_severity("LOW") == "LOW"
        assert normalize_severity("INFO") == "INFO"

    def test_normalize_severity_case_insensitive(self):
        """Test case-insensitive normalization."""
        assert normalize_severity("critical") == "CRITICAL"
        assert normalize_severity("High") == "HIGH"
        assert normalize_severity("mEdIuM") == "MEDIUM"

    def test_normalize_severity_variants(self):
        """Test normalization of common variants."""
        assert normalize_severity("ERROR") == "HIGH"
        assert normalize_severity("WARN") == "MEDIUM"
        assert normalize_severity("WARNING") == "MEDIUM"
        assert normalize_severity("CRIT") == "CRITICAL"
        assert normalize_severity("MED") == "MEDIUM"

    def test_normalize_severity_none(self):
        """Test that None returns INFO."""
        assert normalize_severity(None) == "INFO"

    def test_normalize_severity_unknown(self):
        """Test that unknown strings return INFO."""
        assert normalize_severity("UNKNOWN") == "INFO"
        assert normalize_severity("invalid") == "INFO"

    def test_normalize_severity_returns_string(self):
        """Test that function returns string value, not enum."""
        result = normalize_severity("HIGH")
        assert isinstance(result, str)
        assert result == "HIGH"


# ============================================================================
# 3. fingerprint() Tests
# ============================================================================


class TestFingerprint:
    """Tests for fingerprint() function."""

    def test_fingerprint_basic(self):
        """Test basic fingerprint generation."""
        fp = fingerprint(
            tool="semgrep",
            rule_id="python.lang.security.audit.dangerous-spawn.dangerous-spawn",
            path="src/main.py",
            start_line=42,
            message="Detected dangerous subprocess call",
        )

        # Should be hex string of FINGERPRINT_LENGTH
        assert isinstance(fp, str)
        assert len(fp) == FINGERPRINT_LENGTH
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_stability(self):
        """Test that same inputs produce same fingerprint."""
        fp1 = fingerprint(
            tool="trivy",
            rule_id="CVE-2024-1234",
            path="package.json",
            start_line=10,
            message="Known vulnerability in package",
        )
        fp2 = fingerprint(
            tool="trivy",
            rule_id="CVE-2024-1234",
            path="package.json",
            start_line=10,
            message="Known vulnerability in package",
        )

        assert fp1 == fp2

    def test_fingerprint_different_tools(self):
        """Test that different tools produce different fingerprints."""
        fp1 = fingerprint(
            tool="semgrep",
            rule_id="rule1",
            path="file.py",
            start_line=1,
            message="Issue found",
        )
        fp2 = fingerprint(
            tool="bandit",
            rule_id="rule1",
            path="file.py",
            start_line=1,
            message="Issue found",
        )

        assert fp1 != fp2

    def test_fingerprint_different_rule_ids(self):
        """Test that different rule IDs produce different fingerprints."""
        fp1 = fingerprint(
            tool="semgrep",
            rule_id="rule1",
            path="file.py",
            start_line=1,
            message="Issue",
        )
        fp2 = fingerprint(
            tool="semgrep",
            rule_id="rule2",
            path="file.py",
            start_line=1,
            message="Issue",
        )

        assert fp1 != fp2

    def test_fingerprint_different_paths(self):
        """Test that different paths produce different fingerprints."""
        fp1 = fingerprint(
            tool="semgrep",
            rule_id="rule1",
            path="file1.py",
            start_line=1,
            message="Issue",
        )
        fp2 = fingerprint(
            tool="semgrep",
            rule_id="rule1",
            path="file2.py",
            start_line=1,
            message="Issue",
        )

        assert fp1 != fp2

    def test_fingerprint_different_lines(self):
        """Test that different line numbers produce different fingerprints."""
        fp1 = fingerprint(
            tool="semgrep",
            rule_id="rule1",
            path="file.py",
            start_line=10,
            message="Issue",
        )
        fp2 = fingerprint(
            tool="semgrep",
            rule_id="rule1",
            path="file.py",
            start_line=20,
            message="Issue",
        )

        assert fp1 != fp2

    def test_fingerprint_different_messages(self):
        """Test that different messages produce different fingerprints."""
        fp1 = fingerprint(
            tool="semgrep",
            rule_id="rule1",
            path="file.py",
            start_line=1,
            message="Issue 1",
        )
        fp2 = fingerprint(
            tool="semgrep",
            rule_id="rule1",
            path="file.py",
            start_line=1,
            message="Issue 2",
        )

        assert fp1 != fp2

    def test_fingerprint_none_rule_id(self):
        """Test fingerprint with None rule_id."""
        fp = fingerprint(
            tool="custom",
            rule_id=None,
            path="file.py",
            start_line=1,
            message="Issue",
        )

        assert isinstance(fp, str)
        assert len(fp) == FINGERPRINT_LENGTH

    def test_fingerprint_none_path(self):
        """Test fingerprint with None path."""
        fp = fingerprint(
            tool="custom",
            rule_id="rule1",
            path=None,
            start_line=1,
            message="Issue",
        )

        assert isinstance(fp, str)
        assert len(fp) == FINGERPRINT_LENGTH

    def test_fingerprint_none_line(self):
        """Test fingerprint with None start_line."""
        fp = fingerprint(
            tool="custom",
            rule_id="rule1",
            path="file.py",
            start_line=None,
            message="Issue",
        )

        assert isinstance(fp, str)
        assert len(fp) == FINGERPRINT_LENGTH

    def test_fingerprint_none_message(self):
        """Test fingerprint with None message."""
        fp = fingerprint(
            tool="custom",
            rule_id="rule1",
            path="file.py",
            start_line=1,
            message=None,
        )

        assert isinstance(fp, str)
        assert len(fp) == FINGERPRINT_LENGTH

    def test_fingerprint_message_truncation(self):
        """Test that long messages are truncated to MESSAGE_SNIPPET_LENGTH."""
        long_message = "x" * (MESSAGE_SNIPPET_LENGTH + 100)
        short_message = "x" * MESSAGE_SNIPPET_LENGTH

        fp_long = fingerprint(
            tool="tool",
            rule_id="rule",
            path="file.py",
            start_line=1,
            message=long_message,
        )
        fp_short = fingerprint(
            tool="tool",
            rule_id="rule",
            path="file.py",
            start_line=1,
            message=short_message,
        )

        # Should be same because message truncated to same length
        assert fp_long == fp_short

    def test_fingerprint_message_whitespace_stripped(self):
        """Test that message whitespace is stripped."""
        fp1 = fingerprint(
            tool="tool",
            rule_id="rule",
            path="file.py",
            start_line=1,
            message="  Issue  ",
        )
        fp2 = fingerprint(
            tool="tool",
            rule_id="rule",
            path="file.py",
            start_line=1,
            message="Issue",
        )

        assert fp1 == fp2

    def test_fingerprint_algorithm(self):
        """Test that fingerprint uses SHA256 and truncates to FINGERPRINT_LENGTH."""
        tool = "semgrep"
        rule_id = "rule1"
        path = "file.py"
        start_line = 42
        message = "Test message"

        # Manually compute expected fingerprint
        snippet = message.strip()[:MESSAGE_SNIPPET_LENGTH]
        base = f"{tool}|{rule_id}|{path}|{start_line}|{snippet}"
        expected = hashlib.sha256(base.encode("utf-8")).hexdigest()[:FINGERPRINT_LENGTH]

        actual = fingerprint(tool, rule_id, path, start_line, message)

        assert actual == expected


# ============================================================================
# 4. extract_code_snippet() Tests
# ============================================================================


class TestExtractCodeSnippet:
    """Tests for extract_code_snippet() function."""

    def test_extract_code_snippet_basic(self, tmp_path: Path):
        """Test basic code snippet extraction."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """line 1
line 2
line 3
line 4
line 5
line 6
line 7
"""
        )

        result = extract_code_snippet(str(test_file), start_line=4, context_lines=2)

        assert result is not None
        assert result["startLine"] == 2  # 4 - 2 = 2 (1-indexed)
        assert result["endLine"] == 6  # Exclusive upper bound (1-indexed)
        assert result["language"] == "python"
        assert "2: line 2" in result["snippet"]
        assert "3: line 3" in result["snippet"]
        assert "4: line 4" in result["snippet"]
        assert "5: line 5" in result["snippet"]
        assert "6: line 6" in result["snippet"]

    def test_extract_code_snippet_no_context(self, tmp_path: Path):
        """Test snippet extraction with zero context lines."""
        test_file = tmp_path / "test.py"
        test_file.write_text("line 1\nline 2\nline 3\n")

        result = extract_code_snippet(str(test_file), start_line=2, context_lines=0)

        assert result is not None
        assert "2: line 2" in result["snippet"]
        # Should only contain the target line
        assert "line 1" not in result["snippet"]
        assert "line 3" not in result["snippet"]

    def test_extract_code_snippet_first_line(self, tmp_path: Path):
        """Test snippet extraction at first line with context."""
        test_file = tmp_path / "test.py"
        test_file.write_text("line 1\nline 2\nline 3\nline 4\n")

        result = extract_code_snippet(str(test_file), start_line=1, context_lines=2)

        assert result is not None
        assert result["startLine"] == 1  # Can't go below 1
        assert "1: line 1" in result["snippet"]
        assert "2: line 2" in result["snippet"]
        assert "3: line 3" in result["snippet"]

    def test_extract_code_snippet_last_line(self, tmp_path: Path):
        """Test snippet extraction at last line with context."""
        test_file = tmp_path / "test.py"
        test_file.write_text("line 1\nline 2\nline 3\nline 4\n")

        result = extract_code_snippet(str(test_file), start_line=4, context_lines=2)

        assert result is not None
        assert result["endLine"] == 4  # Can't go beyond file end
        assert "2: line 2" in result["snippet"]
        assert "3: line 3" in result["snippet"]
        assert "4: line 4" in result["snippet"]

    def test_extract_code_snippet_file_not_exists(self):
        """Test that non-existent file returns None."""
        result = extract_code_snippet("/nonexistent/file.py", start_line=1)
        assert result is None

    def test_extract_code_snippet_empty_file(self, tmp_path: Path):
        """Test that empty file returns None."""
        test_file = tmp_path / "empty.py"
        test_file.write_text("")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result is None

    def test_extract_code_snippet_language_detection_python(self, tmp_path: Path):
        """Test language detection for Python files."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')\n")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "python"

    def test_extract_code_snippet_language_detection_javascript(self, tmp_path: Path):
        """Test language detection for JavaScript files."""
        test_file = tmp_path / "test.js"
        test_file.write_text("console.log('hello');\n")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "javascript"

    def test_extract_code_snippet_language_detection_typescript(self, tmp_path: Path):
        """Test language detection for TypeScript files."""
        test_file = tmp_path / "test.ts"
        test_file.write_text("const x: string = 'hello';\n")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "typescript"

    def test_extract_code_snippet_language_detection_go(self, tmp_path: Path):
        """Test language detection for Go files."""
        test_file = tmp_path / "test.go"
        test_file.write_text("package main\n")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "go"

    def test_extract_code_snippet_language_detection_rust(self, tmp_path: Path):
        """Test language detection for Rust files."""
        test_file = tmp_path / "test.rs"
        test_file.write_text("fn main() {}\n")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "rust"

    def test_extract_code_snippet_language_detection_java(self, tmp_path: Path):
        """Test language detection for Java files."""
        test_file = tmp_path / "Test.java"
        test_file.write_text("public class Test {}\n")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "java"

    def test_extract_code_snippet_language_detection_yaml(self, tmp_path: Path):
        """Test language detection for YAML files."""
        test_file = tmp_path / "config.yaml"
        test_file.write_text("key: value\n")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "yaml"

    def test_extract_code_snippet_language_detection_yml(self, tmp_path: Path):
        """Test language detection for .yml files."""
        test_file = tmp_path / "config.yml"
        test_file.write_text("key: value\n")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "yaml"

    def test_extract_code_snippet_language_detection_json(self, tmp_path: Path):
        """Test language detection for JSON files."""
        test_file = tmp_path / "data.json"
        test_file.write_text('{"key": "value"}\n')

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "json"

    def test_extract_code_snippet_language_detection_dockerfile(self, tmp_path: Path):
        """Test language detection for Dockerfile."""
        test_file = tmp_path / "Dockerfile"
        test_file.write_text("FROM ubuntu:latest\n")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "dockerfile"

    def test_extract_code_snippet_language_detection_dockerfile_extension(
        self, tmp_path: Path
    ):
        """Test language detection for .dockerfile extension."""
        test_file = tmp_path / "app.dockerfile"
        test_file.write_text("FROM node:18\n")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "dockerfile"

    def test_extract_code_snippet_language_detection_terraform(self, tmp_path: Path):
        """Test language detection for Terraform files."""
        test_file = tmp_path / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}\n')

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "terraform"

    def test_extract_code_snippet_language_detection_unknown(self, tmp_path: Path):
        """Test language detection for unknown extensions."""
        test_file = tmp_path / "file.unknown"
        test_file.write_text("some content\n")

        result = extract_code_snippet(str(test_file), start_line=1)
        assert result["language"] == "text"

    def test_extract_code_snippet_line_numbering(self, tmp_path: Path):
        """Test that line numbers are correctly formatted."""
        test_file = tmp_path / "test.py"
        test_file.write_text("line 1\nline 2\nline 3\n")

        result = extract_code_snippet(str(test_file), start_line=2, context_lines=1)

        # Check format: "line_num: content"
        assert "1: line 1" in result["snippet"]
        assert "2: line 2" in result["snippet"]
        assert "3: line 3" in result["snippet"]

    def test_extract_code_snippet_unicode_content(self, tmp_path: Path):
        """Test snippet extraction with unicode content."""
        test_file = tmp_path / "test.py"
        test_file.write_text("# 日本語コメント\nprint('hello')\n", encoding="utf-8")

        result = extract_code_snippet(str(test_file), start_line=2, context_lines=1)

        assert result is not None
        assert "日本語コメント" in result["snippet"]
        assert "print('hello')" in result["snippet"]

    def test_extract_code_snippet_bounds_checking(self, tmp_path: Path):
        """Test that bounds are correctly checked."""
        test_file = tmp_path / "test.py"
        test_file.write_text("line 1\nline 2\nline 3\n")

        # Request beyond file bounds
        result = extract_code_snippet(str(test_file), start_line=10, context_lines=2)

        # Should handle gracefully and return None or bounded result
        # Based on implementation, line_idx will be clamped
        assert result is None or result["startLine"] >= 1

    def test_extract_code_snippet_default_context_lines(self, tmp_path: Path):
        """Test default context_lines parameter."""
        test_file = tmp_path / "test.py"
        test_file.write_text("line 1\nline 2\nline 3\nline 4\nline 5\n")

        # Default context_lines is 2
        result = extract_code_snippet(str(test_file), start_line=3)

        assert result is not None
        # Should include 2 lines before and after line 3
        assert "1: line 1" in result["snippet"]
        assert "2: line 2" in result["snippet"]
        assert "3: line 3" in result["snippet"]
        assert "4: line 4" in result["snippet"]
        assert "5: line 5" in result["snippet"]


# ============================================================================
# 5. Constants Tests
# ============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_fingerprint_length_constant(self):
        """Test FINGERPRINT_LENGTH is set correctly."""
        assert FINGERPRINT_LENGTH == 16

    def test_message_snippet_length_constant(self):
        """Test MESSAGE_SNIPPET_LENGTH is set correctly."""
        assert MESSAGE_SNIPPET_LENGTH == 120

    def test_tool_severity_mappings_structure(self):
        """Test TOOL_SEVERITY_MAPPINGS has expected structure."""
        assert isinstance(TOOL_SEVERITY_MAPPINGS, dict)
        # Should have mappings for known tools
        assert "zap" in TOOL_SEVERITY_MAPPINGS
        assert "semgrep" in TOOL_SEVERITY_MAPPINGS
        assert "nuclei" in TOOL_SEVERITY_MAPPINGS
        assert "falco" in TOOL_SEVERITY_MAPPINGS

    def test_tool_severity_mappings_values_are_valid(self):
        """Test all mapped severity values are valid CommonFinding severities."""
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for tool_name, mapping in TOOL_SEVERITY_MAPPINGS.items():
            for tool_sev, common_sev in mapping.items():
                assert (
                    common_sev in valid_severities
                ), f"Invalid severity '{common_sev}' in {tool_name} mapping"


# ============================================================================
# 6. map_tool_severity() Tests
# ============================================================================


class TestMapToolSeverity:
    """Tests for map_tool_severity() function."""

    # ------------------------------------
    # ZAP severity mapping tests
    # ------------------------------------
    def test_zap_informational(self):
        """Test ZAP informational maps to INFO."""
        assert map_tool_severity("zap", "informational") == "INFO"
        assert map_tool_severity("ZAP", "Informational") == "INFO"

    def test_zap_low(self):
        """Test ZAP low maps to LOW."""
        assert map_tool_severity("zap", "low") == "LOW"
        assert map_tool_severity("zap", "Low") == "LOW"

    def test_zap_medium(self):
        """Test ZAP medium maps to MEDIUM."""
        assert map_tool_severity("zap", "medium") == "MEDIUM"
        assert map_tool_severity("zap", "Medium") == "MEDIUM"

    def test_zap_high(self):
        """Test ZAP high maps to HIGH."""
        assert map_tool_severity("zap", "high") == "HIGH"
        assert map_tool_severity("zap", "High") == "HIGH"

    def test_zap_critical(self):
        """Test ZAP critical maps to CRITICAL."""
        assert map_tool_severity("zap", "critical") == "CRITICAL"
        assert map_tool_severity("zap", "CRITICAL") == "CRITICAL"

    # ------------------------------------
    # Semgrep severity mapping tests
    # ------------------------------------
    def test_semgrep_error(self):
        """Test Semgrep ERROR maps to HIGH."""
        assert map_tool_severity("semgrep", "error") == "HIGH"
        assert map_tool_severity("semgrep", "ERROR") == "HIGH"

    def test_semgrep_warning(self):
        """Test Semgrep WARNING maps to MEDIUM."""
        assert map_tool_severity("semgrep", "warning") == "MEDIUM"
        assert map_tool_severity("semgrep", "WARNING") == "MEDIUM"

    def test_semgrep_info(self):
        """Test Semgrep INFO maps to LOW."""
        assert map_tool_severity("semgrep", "info") == "LOW"
        assert map_tool_severity("semgrep", "INFO") == "LOW"

    # ------------------------------------
    # Nuclei severity mapping tests
    # ------------------------------------
    def test_nuclei_info(self):
        """Test Nuclei info maps to INFO."""
        assert map_tool_severity("nuclei", "info") == "INFO"

    def test_nuclei_low(self):
        """Test Nuclei low maps to LOW."""
        assert map_tool_severity("nuclei", "low") == "LOW"

    def test_nuclei_medium(self):
        """Test Nuclei medium maps to MEDIUM."""
        assert map_tool_severity("nuclei", "medium") == "MEDIUM"

    def test_nuclei_high(self):
        """Test Nuclei high maps to HIGH."""
        assert map_tool_severity("nuclei", "high") == "HIGH"

    def test_nuclei_critical(self):
        """Test Nuclei critical maps to CRITICAL."""
        assert map_tool_severity("nuclei", "critical") == "CRITICAL"

    def test_nuclei_unknown(self):
        """Test Nuclei unknown maps to INFO."""
        assert map_tool_severity("nuclei", "unknown") == "INFO"

    # ------------------------------------
    # Falco priority mapping tests
    # ------------------------------------
    def test_falco_emergency(self):
        """Test Falco emergency maps to CRITICAL."""
        assert map_tool_severity("falco", "emergency") == "CRITICAL"

    def test_falco_alert(self):
        """Test Falco alert maps to CRITICAL."""
        assert map_tool_severity("falco", "alert") == "CRITICAL"

    def test_falco_critical(self):
        """Test Falco critical maps to CRITICAL."""
        assert map_tool_severity("falco", "critical") == "CRITICAL"

    def test_falco_error(self):
        """Test Falco error maps to HIGH."""
        assert map_tool_severity("falco", "error") == "HIGH"

    def test_falco_warning(self):
        """Test Falco warning maps to MEDIUM."""
        assert map_tool_severity("falco", "warning") == "MEDIUM"

    def test_falco_notice(self):
        """Test Falco notice maps to LOW."""
        assert map_tool_severity("falco", "notice") == "LOW"

    def test_falco_informational(self):
        """Test Falco informational maps to INFO."""
        assert map_tool_severity("falco", "informational") == "INFO"

    def test_falco_debug(self):
        """Test Falco debug maps to INFO."""
        assert map_tool_severity("falco", "debug") == "INFO"

    # ------------------------------------
    # ShellCheck tests
    # ------------------------------------
    def test_shellcheck_error(self):
        """Test ShellCheck error maps to HIGH."""
        assert map_tool_severity("shellcheck", "error") == "HIGH"

    def test_shellcheck_warning(self):
        """Test ShellCheck warning maps to MEDIUM."""
        assert map_tool_severity("shellcheck", "warning") == "MEDIUM"

    def test_shellcheck_info(self):
        """Test ShellCheck info maps to LOW."""
        assert map_tool_severity("shellcheck", "info") == "LOW"

    def test_shellcheck_style(self):
        """Test ShellCheck style maps to INFO."""
        assert map_tool_severity("shellcheck", "style") == "INFO"

    def test_shellcheck_case_insensitive(self):
        """Test ShellCheck mappings are case insensitive."""
        assert map_tool_severity("shellcheck", "ERROR") == "HIGH"
        assert map_tool_severity("shellcheck", "WARNING") == "MEDIUM"
        assert map_tool_severity("shellcheck", "INFO") == "LOW"
        assert map_tool_severity("shellcheck", "STYLE") == "INFO"
        assert map_tool_severity("SHELLCHECK", "error") == "HIGH"

    # ------------------------------------
    # Fallback behavior tests
    # ------------------------------------
    def test_unknown_tool_uses_generic_normalization(self):
        """Test unknown tools fall back to generic normalize_severity."""
        # Generic normalize_severity should handle standard severities
        assert map_tool_severity("unknown_tool", "HIGH") == "HIGH"
        assert map_tool_severity("unknown_tool", "MEDIUM") == "MEDIUM"
        assert map_tool_severity("unknown_tool", "CRITICAL") == "CRITICAL"
        assert map_tool_severity("unknown_tool", "LOW") == "LOW"
        assert map_tool_severity("unknown_tool", "INFO") == "INFO"

    def test_unknown_tool_common_variants(self):
        """Test unknown tools handle common severity variants."""
        # ERROR -> HIGH via normalize_severity fallback
        assert map_tool_severity("unknown_tool", "ERROR") == "HIGH"
        # WARNING -> MEDIUM via normalize_severity fallback
        assert map_tool_severity("unknown_tool", "WARNING") == "MEDIUM"

    def test_empty_severity_returns_info(self):
        """Test empty severity returns INFO."""
        assert map_tool_severity("zap", "") == "INFO"
        assert map_tool_severity("unknown", "") == "INFO"

    def test_none_like_severity_handling(self):
        """Test None-like values return INFO."""
        # The function handles empty strings, actual None would need type guard
        assert map_tool_severity("zap", "   ") == "INFO"

    def test_case_insensitive_tool_name(self):
        """Test tool name matching is case insensitive."""
        assert map_tool_severity("ZAP", "high") == "HIGH"
        assert map_tool_severity("Zap", "low") == "LOW"
        assert map_tool_severity("SEMGREP", "error") == "HIGH"
        assert map_tool_severity("Semgrep", "warning") == "MEDIUM"

    def test_case_insensitive_severity(self):
        """Test severity matching is case insensitive."""
        assert map_tool_severity("zap", "HIGH") == "HIGH"
        assert map_tool_severity("zap", "High") == "HIGH"
        assert map_tool_severity("zap", "high") == "HIGH"
        assert map_tool_severity("nuclei", "CRITICAL") == "CRITICAL"

    def test_whitespace_handling(self):
        """Test whitespace is stripped from severity values."""
        assert map_tool_severity("zap", "  high  ") == "HIGH"
        assert map_tool_severity("semgrep", "\terror\n") == "HIGH"

    def test_unmapped_value_for_known_tool(self):
        """Test unmapped severity values fall back to normalize_severity."""
        # ZAP doesn't have a mapping for "ultra_critical"
        # Should fall back to generic normalization (returns INFO for unknown)
        result = map_tool_severity("zap", "ultra_critical")
        assert result == "INFO"  # Unknown value defaults to INFO

    def test_consistency_with_original_implementations(self):
        """Test that mapping matches original adapter implementations."""
        # Original _zap_risk_to_severity returned "MEDIUM" for unknown
        # Our centralized version falls back to normalize_severity which returns INFO
        # This is an intentional change for consistency

        # Test known mappings match exactly
        assert map_tool_severity("zap", "informational") == "INFO"
        assert map_tool_severity("zap", "low") == "LOW"
        assert map_tool_severity("zap", "medium") == "MEDIUM"
        assert map_tool_severity("zap", "high") == "HIGH"
        assert map_tool_severity("zap", "critical") == "CRITICAL"
