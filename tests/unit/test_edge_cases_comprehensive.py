#!/usr/bin/env python3
"""
Comprehensive edge case tests for JMo Security core functionality.

This file tests critical edge cases that are often untested, potentially
causing silent failures in production:

1. Encoding Edge Cases - UTF-8, BOM, invalid sequences, null bytes
2. Fingerprint Edge Cases - Collisions, special characters, path normalization
3. Scale Edge Cases - Large inputs, deep nesting, memory limits
4. Format Edge Cases - CWE/CVE variations, severity casing, field presence
5. Path Edge Cases - Absolute/relative, symlinks, special characters
6. Tool Failure Edge Cases - Empty vs failure, missing files, invalid JSON

Target: 30+ test functions across 6+ categories
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.core.adapters.common import safe_load_json_file, safe_load_ndjson_file
from scripts.core.common_finding import (
    fingerprint,
    normalize_severity,
    Severity,
    FINGERPRINT_LENGTH,
)

# ============================================================================
# 1. Encoding Edge Cases (Tests 1-6)
# ============================================================================


class TestEncodingEdgeCases:
    """Tests for encoding-related edge cases in JSON processing."""

    def test_utf8_bom_handling_json(self, tmp_path: Path) -> None:
        """Test UTF-8 BOM (Byte Order Mark) is handled correctly.

        Some editors and tools prepend UTF-8 files with a BOM (0xEF 0xBB 0xBF).
        This should be stripped transparently without affecting parsing.
        """
        bom_file = tmp_path / "bom_test.json"
        # UTF-8 BOM followed by valid JSON
        bom_file.write_bytes(b'\xef\xbb\xbf{"key": "value", "unicode": "\xe2\x9c\x93"}')

        result = safe_load_json_file(bom_file)
        assert result is not None
        assert result["key"] == "value"
        assert result["unicode"] == "✓"

    def test_invalid_utf8_replacement(self, tmp_path: Path) -> None:
        """Test that invalid UTF-8 sequences don't crash, but degrade gracefully.

        Invalid byte sequences should be replaced (errors='ignore' behavior),
        allowing partial data recovery rather than complete failure.
        """
        invalid_file = tmp_path / "invalid_utf8.json"
        # Valid JSON structure with invalid UTF-8 bytes embedded in a string
        # \x80 is not a valid UTF-8 start byte
        invalid_file.write_bytes(b'{"message": "test\x80value"}')

        result = safe_load_json_file(invalid_file)
        assert result is not None
        # The invalid byte should be ignored/replaced
        assert "test" in result.get("message", "")

    def test_mixed_encoding_recovery(self, tmp_path: Path) -> None:
        """Test recovery from files with mixed valid/invalid encoding.

        Real-world files often have a mix of valid UTF-8 and legacy encodings.
        The loader should extract as much valid data as possible.
        """
        mixed_file = tmp_path / "mixed_encoding.json"
        # Mix of valid UTF-8 and Latin-1 encoded content
        content = b'{"text": "valid", "data": "\xe9\xe8\xe0"}'  # Latin-1 accents
        mixed_file.write_bytes(content)

        result = safe_load_json_file(mixed_file)
        assert result is not None
        assert result["text"] == "valid"

    def test_null_bytes_in_json_strings(self, tmp_path: Path) -> None:
        """Test handling of null bytes within JSON string values.

        Null bytes in strings can cause issues with C-based parsers.
        Python's json module should handle this gracefully.
        """
        null_file = tmp_path / "null_bytes.json"
        # JSON with embedded null characters (valid in JSON strings)
        null_file.write_text('{"data": "before\\u0000after"}', encoding="utf-8")

        result = safe_load_json_file(null_file)
        assert result is not None
        # JSON \u0000 should be decoded to actual null character
        assert "\x00" in result["data"]

    def test_very_long_strings(self, tmp_path: Path) -> None:
        """Test handling of very long strings (>64KB) in JSON.

        Large strings should be processed without memory issues or truncation.
        """
        long_string = "x" * 100_000  # 100KB string
        long_file = tmp_path / "long_string.json"
        long_file.write_text(json.dumps({"long": long_string}), encoding="utf-8")

        result = safe_load_json_file(long_file)
        assert result is not None
        assert len(result["long"]) == 100_000

    def test_unicode_in_ndjson(self, tmp_path: Path) -> None:
        """Test Unicode handling across multiple NDJSON lines.

        Each line may have different Unicode content that must be preserved.
        """
        ndjson_file = tmp_path / "unicode.ndjson"
        lines = [
            json.dumps({"text": "日本語"}),  # Japanese
            json.dumps({"text": "العربية"}),  # Arabic
            json.dumps({"text": "🔒🛡️🚨"}),  # Emojis
            json.dumps({"text": "Ñoño"}),  # Spanish
        ]
        ndjson_file.write_text("\n".join(lines), encoding="utf-8")

        results = list(safe_load_ndjson_file(ndjson_file))
        assert len(results) == 4
        assert results[0]["text"] == "日本語"
        assert results[2]["text"] == "🔒🛡️🚨"


# ============================================================================
# 2. Fingerprint Edge Cases (Tests 7-12)
# ============================================================================


class TestFingerprintEdgeCases:
    """Tests for fingerprint generation edge cases."""

    def test_fingerprint_collision_different_inputs(self) -> None:
        """Test that different inputs produce different fingerprints.

        Even slight differences should produce different fingerprints
        to prevent false deduplication.
        """
        fp1 = fingerprint("semgrep", "rule-123", "app.py", 42, "SQL injection")
        fp2 = fingerprint(
            "semgrep", "rule-123", "app.py", 43, "SQL injection"
        )  # line+1
        fp3 = fingerprint("semgrep", "rule-123", "app.py", 42, "SQL Injection")  # case
        fp4 = fingerprint("bandit", "rule-123", "app.py", 42, "SQL injection")  # tool

        # All should be unique
        fps = {fp1, fp2, fp3, fp4}
        assert len(fps) == 4, "Different inputs should produce different fingerprints"

    def test_fingerprint_stability(self) -> None:
        """Test that same inputs always produce same fingerprint.

        Fingerprints must be deterministic for reliable deduplication.
        """
        inputs = (
            "semgrep",
            "rule-xss-001",
            "components/Form.tsx",
            100,
            "XSS vulnerability",
        )

        fp1 = fingerprint(*inputs)
        fp2 = fingerprint(*inputs)
        fp3 = fingerprint(*inputs)

        assert fp1 == fp2 == fp3, "Same inputs must produce identical fingerprints"

    def test_fingerprint_empty_message_handling(self) -> None:
        """Test fingerprint with empty or None message.

        Empty messages should not cause crashes or unexpected behavior.
        """
        fp_none = fingerprint("tool", "rule", "path", 1, None)
        fp_empty = fingerprint("tool", "rule", "path", 1, "")
        fp_whitespace = fingerprint("tool", "rule", "path", 1, "   ")

        # All should be valid hex strings
        assert len(fp_none) == FINGERPRINT_LENGTH
        assert len(fp_empty) == FINGERPRINT_LENGTH
        assert len(fp_whitespace) == FINGERPRINT_LENGTH

        # Empty and None should be treated similarly
        assert fp_none == fp_empty

    def test_fingerprint_special_characters_in_rule_id(self) -> None:
        """Test fingerprint with special characters in rule IDs.

        Rule IDs from various tools may contain unicode, quotes, slashes.
        """
        special_ids = [
            "CWE-79",  # Standard
            "CWE_79",  # Underscore variant
            "rule/with/slashes",
            'rule"with"quotes',
            "rule'with'apostrophes",
            "rule:with:colons",
            "日本語ルール",  # Japanese
            "🔒secure🔒",  # Emojis
        ]

        fingerprints = []
        for rule_id in special_ids:
            fp = fingerprint("tool", rule_id, "file.py", 1, "message")
            assert len(fp) == FINGERPRINT_LENGTH
            assert all(c in "0123456789abcdef" for c in fp), "Must be hex"
            fingerprints.append(fp)

        # All should be unique
        assert len(set(fingerprints)) == len(fingerprints)

    def test_fingerprint_path_normalization(self) -> None:
        """Test that path variations don't cause false collisions.

        Windows vs Unix paths, relative vs absolute should all be handled.
        """
        # These represent "different" paths and should not collide
        fp1 = fingerprint("tool", "rule", "src/app.py", 1, "msg")
        fp2 = fingerprint("tool", "rule", "src\\app.py", 1, "msg")  # Windows
        fp3 = fingerprint("tool", "rule", "./src/app.py", 1, "msg")  # Relative
        fp4 = fingerprint("tool", "rule", "/abs/src/app.py", 1, "msg")  # Absolute

        # Note: Current implementation does NOT normalize paths - they're treated literally
        # This test documents the current behavior
        assert fp1 != fp2  # Unix vs Windows path separators should differ
        assert fp1 != fp3  # With vs without ./ prefix should differ
        assert fp1 != fp4  # Relative vs absolute should differ

    def test_fingerprint_line_number_zero_vs_none(self) -> None:
        """Test fingerprint behavior with line=0 vs line=None.

        Both should be treated as "no line info" for consistent fingerprinting.
        """
        fp_zero = fingerprint("tool", "rule", "file.py", 0, "message")
        fp_none = fingerprint("tool", "rule", "file.py", None, "message")

        # Both should produce valid fingerprints
        assert len(fp_zero) == FINGERPRINT_LENGTH
        assert len(fp_none) == FINGERPRINT_LENGTH

        # Current implementation treats both as 0
        assert fp_zero == fp_none


# ============================================================================
# 3. Scale Edge Cases (Tests 13-18)
# ============================================================================


class TestScaleEdgeCases:
    """Tests for handling large inputs and scale limits."""

    def test_1000_findings_processing(self, tmp_path: Path) -> None:
        """Test processing 1,000 findings without issues.

        This is a common production workload that must complete quickly.
        """
        findings = [
            {"id": i, "severity": "MEDIUM", "rule": f"rule-{i}"} for i in range(1000)
        ]
        json_file = tmp_path / "1000_findings.json"
        json_file.write_text(json.dumps(findings), encoding="utf-8")

        result = safe_load_json_file(json_file)
        assert result is not None
        assert len(result) == 1000

    def test_10000_findings_processing(self, tmp_path: Path) -> None:
        """Test processing 10,000 findings without memory issues.

        Large compliance audits may produce this many findings.
        """
        findings = [
            {"id": i, "msg": f"Finding {i}" * 10}  # ~100 chars per finding
            for i in range(10000)
        ]
        json_file = tmp_path / "10000_findings.json"
        json_file.write_text(json.dumps(findings), encoding="utf-8")

        result = safe_load_json_file(json_file)
        assert result is not None
        assert len(result) == 10000

    def test_very_large_single_finding(self, tmp_path: Path) -> None:
        """Test handling of a single finding with very large message (1MB).

        Some tools may include full stack traces or code snippets.
        """
        large_message = "x" * 1_000_000  # 1MB message
        finding = {
            "id": "large-finding",
            "severity": "HIGH",
            "message": large_message,
        }
        json_file = tmp_path / "large_finding.json"
        json_file.write_text(json.dumps(finding), encoding="utf-8")

        result = safe_load_json_file(json_file)
        assert result is not None
        assert len(result["message"]) == 1_000_000

    def test_deep_nesting(self, tmp_path: Path) -> None:
        """Test handling of deeply nested structures (10+ levels).

        Some tool outputs have deeply nested context/metadata.
        """
        # Build 15-level deep structure
        deep = {"level": 15, "data": "deepest"}
        for i in range(14, 0, -1):
            deep = {"level": i, "child": deep}

        json_file = tmp_path / "deep_nesting.json"
        json_file.write_text(json.dumps(deep), encoding="utf-8")

        result = safe_load_json_file(json_file)
        assert result is not None
        assert result["level"] == 1

        # Navigate to deepest level
        current = result
        for _ in range(14):
            current = current["child"]
        assert current["level"] == 15
        assert current["data"] == "deepest"

    def test_wide_object_many_keys(self, tmp_path: Path) -> None:
        """Test handling of objects with many keys (1000+).

        Findings may have extensive metadata with many fields.
        """
        wide_object = {f"key_{i}": f"value_{i}" for i in range(1000)}
        json_file = tmp_path / "wide_object.json"
        json_file.write_text(json.dumps(wide_object), encoding="utf-8")

        result = safe_load_json_file(json_file)
        assert result is not None
        assert len(result) == 1000
        assert result["key_500"] == "value_500"

    def test_large_ndjson_file(self, tmp_path: Path) -> None:
        """Test streaming large NDJSON file (5000 lines).

        NDJSON loader should handle large files without loading all into memory.
        """
        ndjson_file = tmp_path / "large.ndjson"
        lines = [json.dumps({"id": i, "data": "x" * 100}) for i in range(5000)]
        ndjson_file.write_text("\n".join(lines), encoding="utf-8")

        results = list(safe_load_ndjson_file(ndjson_file))
        assert len(results) == 5000


# ============================================================================
# 4. Format Edge Cases (Tests 19-24)
# ============================================================================


class TestFormatEdgeCases:
    """Tests for format variations in input data."""

    def test_cwe_id_variations(self) -> None:
        """Test that various CWE ID formats are handled.

        Different tools report CWE IDs in various formats.
        """
        # Test that fingerprint handles all CWE formats
        cwe_formats = [
            "CWE-79",
            "CWE_79",
            "79",
            "cwe-79",
            "CWE79",
        ]

        # All should produce valid fingerprints
        for cwe in cwe_formats:
            fp = fingerprint("tool", cwe, "file.py", 1, "XSS vulnerability")
            assert len(fp) == FINGERPRINT_LENGTH

    def test_cve_id_variations(self) -> None:
        """Test that various CVE ID formats are handled.

        CVE IDs come in different case formats.
        """
        cve_formats = [
            "CVE-2024-1234",
            "cve-2024-1234",
            "CVE-2024-12345",  # 5-digit
            "CVE-2024-123456",  # 6-digit (future-proofing)
        ]

        fingerprints = []
        for cve in cve_formats:
            fp = fingerprint("trivy", cve, "package.json", 1, "Vulnerability")
            assert len(fp) == FINGERPRINT_LENGTH
            fingerprints.append(fp)

        # Case variations of same CVE should produce different fingerprints
        # (we don't normalize case - that's a design choice to document)
        assert fingerprints[0] != fingerprints[1]

    def test_severity_case_insensitivity(self) -> None:
        """Test that severity normalization is case-insensitive.

        Different tools use different casing for severity levels.
        """
        cases = [
            ("HIGH", "HIGH"),
            ("high", "HIGH"),
            ("High", "HIGH"),
            ("hIgH", "HIGH"),
            ("CRITICAL", "CRITICAL"),
            ("critical", "CRITICAL"),
            ("Critical", "CRITICAL"),
            ("CrItIcAl", "CRITICAL"),
            ("MEDIUM", "MEDIUM"),
            ("medium", "MEDIUM"),
            ("LOW", "LOW"),
            ("low", "LOW"),
            ("INFO", "INFO"),
            ("info", "INFO"),
        ]

        for input_val, expected in cases:
            assert normalize_severity(input_val) == expected

    def test_empty_arrays_vs_null_vs_missing(self, tmp_path: Path) -> None:
        """Test handling of empty arrays vs null vs missing fields.

        These are semantically different and should be handled appropriately.
        """
        # Test various empty/missing states
        test_cases = [
            ({"findings": []}, "empty_array"),
            ({"findings": None}, "null"),
            ({}, "missing"),
            ({"findings": [{}]}, "array_with_empty_obj"),
        ]

        for data, desc in test_cases:
            json_file = tmp_path / f"{desc}.json"
            json_file.write_text(json.dumps(data), encoding="utf-8")

            result = safe_load_json_file(json_file)
            assert result is not None, f"Failed for {desc}"
            assert isinstance(result, dict), f"Wrong type for {desc}"

    def test_ndjson_with_blank_lines_and_whitespace(self, tmp_path: Path) -> None:
        """Test NDJSON with various blank/whitespace lines.

        Real NDJSON files often have trailing newlines and blank lines.
        """
        ndjson_file = tmp_path / "blanks.ndjson"
        content = """{"id": 1}

{"id": 2}

{"id": 3}


"""
        ndjson_file.write_text(content, encoding="utf-8")

        results = list(safe_load_ndjson_file(ndjson_file))
        assert len(results) == 3
        assert results[0]["id"] == 1
        assert results[1]["id"] == 2
        assert results[2]["id"] == 3

    def test_severity_enum_comparison(self) -> None:
        """Test that Severity enum comparisons work correctly.

        CRITICAL > HIGH > MEDIUM > LOW > INFO
        """
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

        # Also test <= and >=
        assert Severity.HIGH <= Severity.CRITICAL
        assert Severity.HIGH >= Severity.MEDIUM
        assert Severity.INFO <= Severity.INFO


# ============================================================================
# 5. Path Edge Cases (Tests 25-30)
# ============================================================================


class TestPathEdgeCases:
    """Tests for file path handling edge cases."""

    def test_absolute_vs_relative_paths(self, tmp_path: Path) -> None:
        """Test that both absolute and relative paths work.

        Users may provide either form depending on context.
        """
        # Create file
        json_file = tmp_path / "path_test.json"
        json_file.write_text('{"test": true}', encoding="utf-8")

        # Test absolute path
        abs_result = safe_load_json_file(json_file.absolute())
        assert abs_result == {"test": True}

        # Test relative path (from current directory perspective)
        # We can't easily test true relative path, but we can test str vs Path
        str_result = safe_load_json_file(str(json_file))
        assert str_result == {"test": True}

    def test_paths_with_spaces(self, tmp_path: Path) -> None:
        """Test handling of paths with spaces in them.

        Common on Windows and in user directories.
        """
        space_dir = tmp_path / "path with spaces"
        space_dir.mkdir()
        json_file = space_dir / "test file.json"
        json_file.write_text('{"spaces": "work"}', encoding="utf-8")

        result = safe_load_json_file(json_file)
        assert result == {"spaces": "work"}

    def test_paths_with_special_characters(self, tmp_path: Path) -> None:
        """Test handling of paths with special characters.

        Filenames may contain various special characters.
        """
        # Test safe special characters (avoiding OS-restricted ones)
        special_chars = [
            ("file-with-dashes.json", {"dashes": True}),
            ("file_with_underscores.json", {"underscores": True}),
            ("file.multiple.dots.json", {"dots": True}),
        ]

        for filename, data in special_chars:
            json_file = tmp_path / filename
            json_file.write_text(json.dumps(data), encoding="utf-8")

            result = safe_load_json_file(json_file)
            assert result == data, f"Failed for {filename}"

    def test_symlink_resolution(self, tmp_path: Path) -> None:
        """Test that symlinks are followed correctly.

        Build systems often use symlinks for artifacts.
        """
        # Create original file
        original = tmp_path / "original.json"
        original.write_text('{"symlink": "test"}', encoding="utf-8")

        # Create symlink (may not work on Windows without admin)
        symlink = tmp_path / "link.json"
        try:
            symlink.symlink_to(original)
        except OSError:
            pytest.skip("Symlinks not supported on this platform")

        result = safe_load_json_file(symlink)
        assert result == {"symlink": "test"}

    def test_non_existent_parent_directory(self) -> None:
        """Test handling of paths where parent directory doesn't exist.

        Should return default gracefully, not crash.
        """
        non_existent = Path("/nonexistent/path/to/file.json")

        result = safe_load_json_file(non_existent)
        assert result is None

        result_with_default = safe_load_json_file(non_existent, default={})
        assert result_with_default == {}

    def test_path_in_fingerprint(self) -> None:
        """Test fingerprint with various path formats.

        Paths from different tools may have different formats.
        """
        path_formats = [
            "src/app.py",
            "./src/app.py",
            "src\\app.py",  # Windows
            "/absolute/src/app.py",
            "C:\\Users\\test\\app.py",  # Windows absolute
        ]

        # All should produce valid, different fingerprints
        fingerprints = []
        for path in path_formats:
            fp = fingerprint("tool", "rule", path, 1, "message")
            assert len(fp) == FINGERPRINT_LENGTH
            fingerprints.append(fp)

        # Different paths should produce different fingerprints
        assert len(set(fingerprints)) == len(fingerprints)


# ============================================================================
# Additional Edge Cases (Bonus tests for >25)
# ============================================================================


class TestAdditionalEdgeCases:
    """Additional edge cases for comprehensive coverage."""

    def test_fingerprint_very_long_message_truncation(self) -> None:
        """Test that very long messages are truncated for fingerprinting.

        The fingerprint should be consistent regardless of message length beyond limit.
        """
        short_msg = "x" * 120
        long_msg = "x" * 1000  # Much longer than MESSAGE_SNIPPET_LENGTH (120)

        fp_short = fingerprint("tool", "rule", "file.py", 1, short_msg)
        fp_long = fingerprint("tool", "rule", "file.py", 1, long_msg)

        # Both should be valid
        assert len(fp_short) == FINGERPRINT_LENGTH
        assert len(fp_long) == FINGERPRINT_LENGTH

        # They should be the same since long msg is truncated to same prefix
        assert fp_short == fp_long

    def test_json_with_numeric_keys(self, tmp_path: Path) -> None:
        """Test JSON with numeric string keys.

        Some tools output data with numeric-looking keys.
        """
        json_file = tmp_path / "numeric_keys.json"
        data = {"123": "value", "456": {"nested": True}}
        json_file.write_text(json.dumps(data), encoding="utf-8")

        result = safe_load_json_file(json_file)
        assert result == data
        assert result["123"] == "value"

    def test_json_with_boolean_values(self, tmp_path: Path) -> None:
        """Test JSON with boolean and null values preserved correctly."""
        json_file = tmp_path / "booleans.json"
        data = {"active": True, "deleted": False, "modified": None}
        json_file.write_text(json.dumps(data), encoding="utf-8")

        result = safe_load_json_file(json_file)
        assert result["active"] is True
        assert result["deleted"] is False
        assert result["modified"] is None

    def test_severity_from_string_edge_cases(self) -> None:
        """Test Severity.from_string with edge case inputs."""
        # None should return INFO
        assert Severity.from_string(None) == Severity.INFO

        # Empty string should return INFO
        assert Severity.from_string("") == Severity.INFO

        # Unknown values should return INFO
        assert Severity.from_string("UNKNOWN") == Severity.INFO
        assert Severity.from_string("not-a-severity") == Severity.INFO

        # Whitespace-only should return INFO
        assert Severity.from_string("   ") == Severity.INFO


# ============================================================================
# 6. Missing Required Tests from Scenario 4
# ============================================================================


class TestMissingRequiredEdgeCases:
    """Tests for edge cases specifically required by Scenario 4 that were missed."""

    def test_circular_reference_protection(self, tmp_path: Path) -> None:
        """Test that circular references in data don't cause infinite loops.

        Security findings with self-referential metadata should not crash.
        This is a REQUIRED test from Scenario 4.
        """
        # Python's json module doesn't support circular references in encoding,
        # so we test the closest analog: very deep self-similar structures
        # that might cause stack issues

        # Build a structure that looks circular but isn't (JSON can't represent true circles)
        data = {"id": "root", "refs": []}
        for i in range(100):
            data["refs"].append({"id": f"ref-{i}", "back_ref_id": "root"})

        json_file = tmp_path / "pseudo_circular.json"
        json_file.write_text(json.dumps(data), encoding="utf-8")

        result = safe_load_json_file(json_file)
        assert result is not None
        assert result["id"] == "root"
        assert len(result["refs"]) == 100

        # Also test that deeply recursive structures don't overflow
        # (Python default recursion limit protection)
        deep = {"level": 0}
        for i in range(1, 50):
            deep = {"level": i, "child": deep}

        deep_file = tmp_path / "deep_recursive.json"
        deep_file.write_text(json.dumps(deep), encoding="utf-8")

        result = safe_load_json_file(deep_file)
        assert result is not None
        assert result["level"] == 49

    def test_very_long_path_windows_limit(self, tmp_path: Path) -> None:
        """Test handling of very long paths (>260 chars for Windows MAX_PATH).

        Windows traditionally has a 260 character path limit.
        This is a REQUIRED test from Scenario 4.
        """
        # Create a deeply nested directory structure to exceed 260 chars
        # Each segment is ~20 chars, need ~15 levels to exceed 260
        long_path = tmp_path
        segment = "a" * 20  # 20-char segments

        try:
            for i in range(15):
                long_path = long_path / f"{segment}_{i:02d}"
                long_path.mkdir(exist_ok=True)

            # Verify path length
            total_length = len(str(long_path))

            # Create file in deep path
            json_file = long_path / "deep_file.json"
            json_file.write_text('{"deep": true}', encoding="utf-8")

            result = safe_load_json_file(json_file)
            assert result == {"deep": True}, f"Failed with path length {total_length}"

        except OSError as e:
            # On Windows without long path support, this may fail
            # That's okay - we're testing the behavior either way
            # Common Windows errors for long paths:
            # - "path too long" / "filename too long" (generic)
            # - WinError 3: "cannot find the path specified" (path limit exceeded)
            # - WinError 206: "filename or extension is too long"
            err_msg = str(e).lower()
            is_path_limit_error = (
                "path too long" in err_msg
                or "filename" in err_msg
                or "cannot find the path" in err_msg
                or "winerror 3" in err_msg
                or "winerror 206" in err_msg
            )
            if is_path_limit_error:
                pytest.skip(f"Platform doesn't support long paths: {e}")
            raise

    def test_ndjson_with_comment_lines(self, tmp_path: Path) -> None:
        """Test NDJSON handling of lines that look like comments.

        Some NDJSON files have # or // comment-like lines that should be skipped.
        This is a REQUIRED test from Scenario 4.
        """
        ndjson_file = tmp_path / "with_comments.ndjson"
        content = """{"id": 1}
# This looks like a comment
{"id": 2}
// This also looks like a comment
{"id": 3}
; semicolon comment style
{"id": 4}"""
        ndjson_file.write_text(content, encoding="utf-8")

        results = list(safe_load_ndjson_file(ndjson_file))

        # Current behavior: malformed lines (comments) are skipped
        # Valid JSON objects should still be extracted
        valid_ids = [r["id"] for r in results if "id" in r]
        assert 1 in valid_ids
        assert 2 in valid_ids
        assert 3 in valid_ids
        assert 4 in valid_ids

    def test_fingerprint_line_number_variations(self) -> None:
        """Test fingerprint with line numbers 0, 1, and None.

        Line 1 is the first line, line 0 often means "unknown".
        This is a REQUIRED test from Scenario 4.
        """
        fp_zero = fingerprint("tool", "rule", "file.py", 0, "message")
        fp_one = fingerprint("tool", "rule", "file.py", 1, "message")
        fp_none = fingerprint("tool", "rule", "file.py", None, "message")
        fp_negative = fingerprint("tool", "rule", "file.py", -1, "message")

        # All should be valid
        assert len(fp_zero) == FINGERPRINT_LENGTH
        assert len(fp_one) == FINGERPRINT_LENGTH
        assert len(fp_none) == FINGERPRINT_LENGTH
        assert len(fp_negative) == FINGERPRINT_LENGTH

        # Line 1 should differ from line 0/None
        assert fp_one != fp_zero, "Line 1 should differ from line 0"

        # 0 and None should be equivalent (both mean "no line info")
        assert fp_zero == fp_none, "Line 0 and None should be equivalent"

    def test_clusterer_with_large_finding_set(self) -> None:
        """Test FindingClusterer with 1000+ findings for performance.

        Clustering should complete in reasonable time without memory issues.
        This tests integration with dedup_enhanced as mentioned in scenario.
        """
        from scripts.core.dedup_enhanced import FindingClusterer

        # Generate 500 findings (faster than 1000 for unit test, still tests scale)
        findings = []
        for i in range(500):
            findings.append(
                {
                    "id": f"finding-{i}",
                    "fingerprint": f"fp-{i}",
                    "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"][i % 5],
                    "message": f"Security finding number {i} with some description",
                    "location": {"path": f"src/file_{i % 50}.py", "startLine": i % 100},
                    "tool": {"name": ["semgrep", "bandit", "trivy"][i % 3]},
                    "ruleId": f"RULE-{i % 20}",
                }
            )

        clusterer = FindingClusterer(similarity_threshold=0.65)
        clusters = clusterer.cluster(findings)

        # Should complete and produce clusters
        assert len(clusters) > 0
        assert len(clusters) <= len(findings)  # Can't have more clusters than findings

        # Each cluster should have at least one finding
        for cluster in clusters:
            assert len(cluster.findings) >= 1

    def test_fingerprint_collision_resistance_high_volume(self) -> None:
        """Test that 1000 unique findings produce 1000 unique fingerprints.

        This tests the hash quality for collision resistance at scale.
        """
        fingerprints = set()

        for i in range(1000):
            fp = fingerprint(
                tool=f"tool-{i % 10}",
                rule_id=f"rule-{i}",
                path=f"src/module_{i % 100}/file_{i}.py",
                start_line=i,
                message=f"Unique message for finding {i}",
            )
            fingerprints.add(fp)

        # All 1000 should be unique (no collisions)
        assert (
            len(fingerprints) == 1000
        ), f"Found {1000 - len(fingerprints)} collisions!"

    def test_similarity_calculator_edge_cases(self) -> None:
        """Test SimilarityCalculator with edge case inputs.

        Empty findings, None fields, and extreme values should not crash.
        """
        from scripts.core.dedup_enhanced import SimilarityCalculator

        calc = SimilarityCalculator()

        # Empty findings
        sim = calc.calculate_similarity({}, {})
        assert 0.0 <= sim <= 1.0

        # One empty, one populated
        populated = {
            "message": "SQL injection vulnerability",
            "location": {"path": "app.py", "startLine": 42},
            "ruleId": "CWE-89",
            "tool": {"name": "semgrep"},
        }
        sim = calc.calculate_similarity({}, populated)
        assert 0.0 <= sim <= 1.0

        # Same finding should have similarity 1.0
        sim = calc.calculate_similarity(populated, populated)
        assert sim == 1.0

        # Completely different findings
        different = {
            "message": "Hardcoded password detected",
            "location": {"path": "config.py", "startLine": 100},
            "ruleId": "CWE-798",
            "tool": {"name": "bandit"},
        }
        sim = calc.calculate_similarity(populated, different)
        assert 0.0 <= sim < 0.65  # Should be below threshold


# ============================================================================
# 6. Tool Failure Edge Cases (Category 6)
# ============================================================================


class TestToolFailureEdgeCases:
    """Tests for tool failure vs. empty results distinction.

    Security tools can fail in various ways - these tests ensure we handle:
    1. Empty results (success with no findings) vs. tool failures
    2. Missing/truncated/invalid JSON files
    3. Various edge cases in JSON loading that represent different outcomes
    """

    def test_empty_results_array_is_success(self, tmp_path: Path) -> None:
        """Test that an empty array [] is a valid success (no findings).

        An empty array means the tool ran successfully but found no issues.
        This is DIFFERENT from a tool failure.
        """
        empty_array_file = tmp_path / "empty_array.json"
        empty_array_file.write_text("[]", encoding="utf-8")

        result = safe_load_json_file(empty_array_file)

        # Empty array should load successfully
        assert result is not None
        assert result == []
        assert isinstance(result, list)
        assert len(result) == 0

    def test_missing_file_returns_empty_not_crashes(self, tmp_path: Path) -> None:
        """Test that a missing file returns None/default gracefully.

        Missing files should not crash - they indicate the tool didn't run
        or output wasn't captured.
        """
        missing_file = tmp_path / "does_not_exist.json"

        # Without default, should return None
        result = safe_load_json_file(missing_file)
        assert result is None

        # With default, should return the default
        result_with_default = safe_load_json_file(missing_file, default=[])
        assert result_with_default == []

        result_with_dict_default = safe_load_json_file(missing_file, default={})
        assert result_with_dict_default == {}

    def test_truncated_json_handled_gracefully(self, tmp_path: Path) -> None:
        """Test that truncated/partial JSON does not crash.

        Truncated files occur when tools are killed mid-write or disk is full.
        """
        truncated_file = tmp_path / "truncated.json"
        # Valid JSON start, but truncated mid-way
        truncated_file.write_text('{"findings": [{"id": 1}, {"id":', encoding="utf-8")

        # Should not crash, should return None (invalid JSON)
        result = safe_load_json_file(truncated_file)
        assert result is None

        # With default, should return the default
        result_with_default = safe_load_json_file(truncated_file, default=[])
        assert result_with_default == []

    def test_invalid_json_not_treated_as_empty(self, tmp_path: Path) -> None:
        """Test that invalid JSON returns None, not an empty result.

        Invalid JSON indicates a problem (tool failure, encoding issue),
        not a successful scan with no findings.
        """
        invalid_files = [
            ("not_json.json", "This is not JSON at all"),
            ("malformed.json", "{key: value}"),  # Missing quotes
            ("trailing_comma.json", '{"a": 1,}'),  # Invalid trailing comma
            ("single_quote.json", "{'key': 'value'}"),  # Python dict, not JSON
        ]

        for filename, content in invalid_files:
            json_file = tmp_path / filename
            json_file.write_text(content, encoding="utf-8")

            result = safe_load_json_file(json_file)
            # Invalid JSON should return None (indicating failure),
            # NOT an empty list/dict (which would indicate success with no findings)
            assert result is None, f"Expected None for invalid JSON: {filename}"

    def test_empty_object_vs_empty_array(self, tmp_path: Path) -> None:
        """Test that {} and [] are handled distinctly.

        {} means "object with no properties" - often used for metadata
        [] means "array with no items" - often used for findings list
        Both are valid JSON and should be distinguished.
        """
        empty_object_file = tmp_path / "empty_object.json"
        empty_object_file.write_text("{}", encoding="utf-8")

        empty_array_file = tmp_path / "empty_array.json"
        empty_array_file.write_text("[]", encoding="utf-8")

        obj_result = safe_load_json_file(empty_object_file)
        arr_result = safe_load_json_file(empty_array_file)

        # Both should load successfully
        assert obj_result is not None
        assert arr_result is not None

        # They should be different types
        assert isinstance(obj_result, dict)
        assert isinstance(arr_result, list)

        # They should not be equal
        assert obj_result != arr_result

        # Both should be "empty"
        assert len(obj_result) == 0
        assert len(arr_result) == 0

    def test_null_json_value(self, tmp_path: Path) -> None:
        """Test that JSON null is handled gracefully.

        A file containing just "null" is valid JSON but represents no data.
        Some tools output null when there are no findings.
        """
        null_file = tmp_path / "null_value.json"
        null_file.write_text("null", encoding="utf-8")

        result = safe_load_json_file(null_file)

        # JSON null should parse to Python None
        assert result is None

        # With a default, should still return None (since null is a valid JSON value)
        # The behavior here depends on implementation - null IS valid JSON
        result_with_default = safe_load_json_file(null_file, default=[])
        # safe_load_json_file returns parsed value (None) for valid JSON
        # The default is only used when JSON is invalid or file missing
        assert result_with_default is None

    def test_empty_file_vs_empty_json(self, tmp_path: Path) -> None:
        """Test distinction between truly empty file and empty JSON.

        A 0-byte file is NOT valid JSON and should fail.
        An empty array/object IS valid JSON and should succeed.
        """
        # Truly empty file (0 bytes)
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("", encoding="utf-8")

        result_empty = safe_load_json_file(empty_file)
        assert result_empty is None, "Empty file is not valid JSON"

        # Whitespace-only file
        whitespace_file = tmp_path / "whitespace.json"
        whitespace_file.write_text("   \n\t\n   ", encoding="utf-8")

        result_whitespace = safe_load_json_file(whitespace_file)
        assert result_whitespace is None, "Whitespace-only is not valid JSON"

    def test_ndjson_with_tool_errors(self, tmp_path: Path) -> None:
        """Test NDJSON where some lines are errors mixed with valid findings.

        Tools sometimes output error messages as non-JSON lines in NDJSON streams.
        """
        ndjson_file = tmp_path / "mixed_errors.ndjson"
        content = """{"id": 1, "severity": "HIGH"}
ERROR: Failed to scan file xyz.py
{"id": 2, "severity": "MEDIUM"}
Warning: Timeout exceeded
{"id": 3, "severity": "LOW"}"""
        ndjson_file.write_text(content, encoding="utf-8")

        results = list(safe_load_ndjson_file(ndjson_file))

        # Should extract valid JSON lines, skip error lines
        valid_results = [r for r in results if isinstance(r, dict) and "id" in r]
        assert len(valid_results) == 3
        assert valid_results[0]["id"] == 1
        assert valid_results[1]["id"] == 2
        assert valid_results[2]["id"] == 3
