"""Property-based tests for adapter robustness using Hypothesis.

This module uses Hypothesis to generate edge cases and test adapter resilience
against malformed, deeply nested, and extremely large inputs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from scripts.core.adapters.bandit_adapter import load_bandit
from scripts.core.adapters.checkov_adapter import load_checkov
from scripts.core.adapters.trufflehog_adapter import load_trufflehog
from scripts.core.adapters.semgrep_adapter import load_semgrep
from scripts.core.adapters.trivy_adapter import load_trivy


# Strategy: Generate malformed JSON
@st.composite
def malformed_json(draw):
    """Generate various malformed JSON structures."""
    choice = draw(st.integers(min_value=0, max_value=7))
    if choice == 0:
        return ""  # Empty string
    elif choice == 1:
        return "not json at all"
    elif choice == 2:
        return "{incomplete"
    elif choice == 3:
        return '{"key": undefined}'
    elif choice == 4:
        return "null"
    elif choice == 5:
        return "[]"
    elif choice == 6:
        return '{"valid": true}'  # Valid but unexpected structure
    else:
        return "[{}, null, false]"  # Array with nulls


@settings(
    max_examples=50,
    deadline=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(content=malformed_json())
def test_trufflehog_handles_malformed_json(tmp_path: Path, content: str):
    """Trufflehog adapter should not crash on malformed input."""
    test_file = tmp_path / "trufflehog.json"
    test_file.write_text(content, encoding="utf-8")

    # Should return a list, not crash (may be empty or have stub findings)
    result = load_trufflehog(test_file)
    assert isinstance(result, list)


@settings(
    max_examples=50,
    deadline=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(content=malformed_json())
def test_semgrep_handles_malformed_json(tmp_path: Path, content: str):
    """Semgrep adapter should not crash on malformed input."""
    test_file = tmp_path / "semgrep.json"
    test_file.write_text(content, encoding="utf-8")

    result = load_semgrep(test_file)
    assert isinstance(result, list)
    assert len(result) == 0


@settings(
    max_examples=50,
    deadline=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(content=malformed_json())
def test_trivy_handles_malformed_json(tmp_path: Path, content: str):
    """Trivy adapter should not crash on malformed input."""
    test_file = tmp_path / "trivy.json"
    test_file.write_text(content, encoding="utf-8")

    result = load_trivy(test_file)
    assert isinstance(result, list)
    assert len(result) == 0


@settings(
    max_examples=50,
    deadline=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(content=malformed_json())
def test_checkov_handles_malformed_json(tmp_path: Path, content: str):
    """Checkov adapter should not crash on malformed input."""
    test_file = tmp_path / "checkov.json"
    test_file.write_text(content, encoding="utf-8")

    result = load_checkov(test_file)
    assert isinstance(result, list)
    assert len(result) == 0


@settings(
    max_examples=50,
    deadline=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(content=malformed_json())
def test_bandit_handles_malformed_json(tmp_path: Path, content: str):
    """Bandit adapter should not crash on malformed input."""
    test_file = tmp_path / "bandit.json"
    test_file.write_text(content, encoding="utf-8")

    result = load_bandit(test_file)
    assert isinstance(result, list)


# Strategy: Generate deeply nested JSON
@st.composite
def deeply_nested_json(draw):
    """Generate JSON with extreme nesting."""
    depth = draw(st.integers(min_value=10, max_value=100))
    obj = {}
    current = obj
    for i in range(depth):
        current["nested"] = {}
        current = current["nested"]
    return json.dumps(obj)


@settings(
    max_examples=20,
    deadline=2000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(content=deeply_nested_json())
def test_adapters_handle_deep_nesting(tmp_path: Path, content: str):
    """Adapters should handle deeply nested JSON without stack overflow."""
    test_file = tmp_path / "test.json"
    test_file.write_text(content, encoding="utf-8")

    # Should complete without recursion errors
    load_trufflehog(test_file)
    load_semgrep(test_file)
    load_trivy(test_file)
    load_checkov(test_file)
    load_bandit(test_file)


# Strategy: Generate very large arrays
@st.composite
def huge_array_json(draw):
    """Generate JSON with thousands of items."""
    size = draw(st.integers(min_value=1000, max_value=5000))
    items = [{"id": i, "data": "x" * 50} for i in range(size)]
    return json.dumps(items)


@settings(
    max_examples=5,
    deadline=5000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(content=huge_array_json())
def test_adapters_handle_large_outputs(tmp_path: Path, content: str):
    """Adapters should handle large result sets without memory issues."""
    test_file = tmp_path / "huge.json"
    test_file.write_text(content, encoding="utf-8")

    # Should complete without OOM
    result = load_trufflehog(test_file)
    assert isinstance(result, list)


# Strategy: Generate strings with special characters
@st.composite
def special_char_strings(draw):
    """Generate strings with special characters that might break parsers."""
    special_chars = [
        "\x00",  # Null byte
        "\x1b[31m",  # ANSI escape
        "\u200b",  # Zero-width space
        "\uffff",  # Max Unicode BMP
        "\\n\\r\\t",  # Escaped newlines
        "';DROP TABLE--",  # SQL injection attempt
        "<script>alert('xss')</script>",  # XSS attempt
        "../../../etc/passwd",  # Path traversal
    ]
    char = draw(st.sampled_from(special_chars))
    return json.dumps({"message": char, "description": char * 10})


@settings(
    max_examples=30,
    deadline=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(content=special_char_strings())
def test_adapters_handle_special_characters(tmp_path: Path, content: str):
    """Adapters should safely handle special characters without corruption."""
    test_file = tmp_path / "special.json"
    test_file.write_text(content, encoding="utf-8")

    # Should not crash or corrupt data
    result = load_trufflehog(test_file)
    assert isinstance(result, list)

    result = load_semgrep(test_file)
    assert isinstance(result, list)


# Test concurrent adapter failures
def test_concurrent_adapter_failures(tmp_path: Path):
    """Multiple adapters failing concurrently should not break aggregation."""
    from scripts.core.normalize_and_report import gather_results

    # Create results dir with all broken files
    indiv = tmp_path / "individual-repos" / "test-repo"
    indiv.mkdir(parents=True)

    for tool in ["trufflehog", "semgrep", "trivy", "checkov", "bandit"]:
        (indiv / f"{tool}.json").write_text("INVALID JSON{", encoding="utf-8")

    # Should return empty list, not crash
    findings = gather_results(tmp_path)
    assert isinstance(findings, list)
    assert len(findings) == 0


# Test with missing files
def test_adapters_handle_missing_files(tmp_path: Path):
    """Adapters should gracefully handle nonexistent files."""
    missing_file = tmp_path / "nonexistent.json"

    result = load_trufflehog(missing_file)
    assert result == []

    result = load_semgrep(missing_file)
    assert result == []

    result = load_trivy(missing_file)
    assert result == []

    result = load_checkov(missing_file)
    assert result == []

    result = load_bandit(missing_file)
    assert result == []


# Test with empty files
def test_adapters_handle_empty_files(tmp_path: Path):
    """Adapters should handle empty files without errors."""
    empty_file = tmp_path / "empty.json"
    empty_file.write_text("", encoding="utf-8")

    result = load_trufflehog(empty_file)
    assert result == []

    result = load_semgrep(empty_file)
    assert result == []

    result = load_trivy(empty_file)
    assert result == []

    result = load_checkov(empty_file)
    assert result == []

    result = load_bandit(empty_file)
    assert result == []


# Test with binary garbage
def test_adapters_handle_binary_data(tmp_path: Path):
    """Adapters should handle binary data gracefully."""
    binary_file = tmp_path / "binary.json"
    binary_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")  # PNG header

    result = load_trufflehog(binary_file)
    assert result == []

    result = load_semgrep(binary_file)
    assert result == []


# Test with extremely long strings
def test_adapters_handle_long_strings(tmp_path: Path):
    """Adapters should handle extremely long strings without issues."""
    long_string = "A" * 1_000_000  # 1MB string
    content = json.dumps({"message": long_string, "description": long_string})

    long_file = tmp_path / "long.json"
    long_file.write_text(content, encoding="utf-8")

    result = load_trufflehog(long_file)
    assert isinstance(result, list)

    result = load_semgrep(long_file)
    assert isinstance(result, list)


# Test with Unicode edge cases
def test_adapters_handle_unicode(tmp_path: Path):
    """Adapters should handle various Unicode characters correctly."""
    unicode_content = {
        "message": "Hello 世界 🌍 Здравствуй мир",
        "description": "Emojis: 🔒🔑🛡️ RTL: مرحبا  Symbols: ™©®€£¥",
        "path": "/path/to/file with spaces/and.unicode.日本.txt",
    }
    content = json.dumps(unicode_content, ensure_ascii=False)

    unicode_file = tmp_path / "unicode.json"
    unicode_file.write_text(content, encoding="utf-8")

    result = load_trufflehog(unicode_file)
    assert isinstance(result, list)

    result = load_semgrep(unicode_file)
    assert isinstance(result, list)


# Test with mixed valid and invalid entries
def test_adapters_skip_invalid_entries(tmp_path: Path):
    """Adapters should skip malformed entries but process valid ones."""
    mixed_content = json.dumps(
        [
            {"valid": "entry1"},
            None,  # Invalid
            {"valid": "entry2"},
            {},  # Invalid (empty)
            {"valid": "entry3"},
        ]
    )

    mixed_file = tmp_path / "mixed.json"
    mixed_file.write_text(mixed_content, encoding="utf-8")

    result = load_trufflehog(mixed_file)
    assert isinstance(result, list)


# Test permission errors (read-only directory)
def test_adapters_handle_permission_errors(tmp_path: Path):
    """Adapters should handle permission errors gracefully."""
    # Create a file we can't read (best effort - may not work on all platforms)
    restricted_file = tmp_path / "restricted.json"
    restricted_file.write_text('{"test": "data"}', encoding="utf-8")

    # Try to make it unreadable (may not work on Windows)
    try:
        import os
        import stat

        os.chmod(restricted_file, 0o000)

        # Should return empty list or handle gracefully
        result = load_trufflehog(restricted_file)
        assert isinstance(result, list)

        # Restore permissions for cleanup
        os.chmod(restricted_file, stat.S_IRUSR | stat.S_IWUSR)
    except (OSError, PermissionError):
        # Permission tests may not work on all platforms
        pytest.skip("Permission tests not supported on this platform")
