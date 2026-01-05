#!/usr/bin/env python3
"""Tests for common adapter utilities."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from scripts.core.adapters.common import (
    safe_load_json_file,
    safe_load_ndjson_file,
    _flatten_to_dicts,
)


class TestSafeLoadJsonFile:
    """Tests for safe_load_json_file function."""

    def test_load_valid_json_dict(self, tmp_path: Path) -> None:
        """Test loading a valid JSON object."""
        json_file = tmp_path / "valid.json"
        data = {"key": "value", "number": 42}
        json_file.write_text(json.dumps(data), encoding="utf-8")

        result = safe_load_json_file(json_file)
        assert result == data

    def test_load_valid_json_array(self, tmp_path: Path) -> None:
        """Test loading a valid JSON array."""
        json_file = tmp_path / "array.json"
        data = [{"id": 1}, {"id": 2}]
        json_file.write_text(json.dumps(data), encoding="utf-8")

        result = safe_load_json_file(json_file)
        assert result == data

    def test_load_missing_file_returns_default(self, tmp_path: Path) -> None:
        """Test that missing file returns default value."""
        missing = tmp_path / "missing.json"

        assert safe_load_json_file(missing) is None
        assert safe_load_json_file(missing, default={}) == {}
        assert safe_load_json_file(missing, default=[]) == []

    def test_load_empty_file_returns_default(self, tmp_path: Path) -> None:
        """Test that empty file returns default value."""
        empty = tmp_path / "empty.json"
        empty.write_text("", encoding="utf-8")

        assert safe_load_json_file(empty) is None
        assert safe_load_json_file(empty, default={"empty": True}) == {"empty": True}

    def test_load_whitespace_only_file_returns_default(self, tmp_path: Path) -> None:
        """Test that whitespace-only file returns default value."""
        whitespace = tmp_path / "whitespace.json"
        whitespace.write_text("   \n\t  \n  ", encoding="utf-8")

        assert safe_load_json_file(whitespace) is None

    def test_load_invalid_json_returns_default(self, tmp_path: Path) -> None:
        """Test that invalid JSON returns default value."""
        invalid = tmp_path / "invalid.json"
        invalid.write_text("{not valid json", encoding="utf-8")

        assert safe_load_json_file(invalid) is None
        assert safe_load_json_file(invalid, default=[]) == []

    def test_load_with_logging_disabled(self, tmp_path: Path) -> None:
        """Test that log_errors=False suppresses logging."""
        missing = tmp_path / "missing.json"

        with patch("scripts.core.adapters.common.logger") as mock_logger:
            safe_load_json_file(missing, log_errors=False)
            mock_logger.debug.assert_not_called()

    def test_load_with_logging_enabled(self, tmp_path: Path) -> None:
        """Test that log_errors=True logs debug messages."""
        missing = tmp_path / "missing.json"

        with patch("scripts.core.adapters.common.logger") as mock_logger:
            safe_load_json_file(missing, log_errors=True)
            mock_logger.debug.assert_called()

    def test_handles_utf8_with_bom(self, tmp_path: Path) -> None:
        """Test handling of UTF-8 files with BOM."""
        bom_file = tmp_path / "bom.json"
        # Write with UTF-8 BOM
        bom_file.write_bytes(b'\xef\xbb\xbf{"key": "value"}')

        result = safe_load_json_file(bom_file)
        assert result == {"key": "value"}

    def test_handles_string_path(self, tmp_path: Path) -> None:
        """Test that string paths work as well as Path objects."""
        json_file = tmp_path / "string_path.json"
        json_file.write_text('{"test": true}', encoding="utf-8")

        result = safe_load_json_file(str(json_file))
        assert result == {"test": True}


class TestSafeLoadNdjsonFile:
    """Tests for safe_load_ndjson_file function."""

    def test_load_valid_ndjson(self, tmp_path: Path) -> None:
        """Test loading a valid NDJSON file."""
        ndjson_file = tmp_path / "valid.ndjson"
        lines = ['{"id": 1}', '{"id": 2}', '{"id": 3}']
        ndjson_file.write_text("\n".join(lines), encoding="utf-8")

        result = list(safe_load_ndjson_file(ndjson_file))
        assert len(result) == 3
        assert result[0] == {"id": 1}
        assert result[1] == {"id": 2}
        assert result[2] == {"id": 3}

    def test_load_regular_json_array(self, tmp_path: Path) -> None:
        """Test that regular JSON arrays are also supported."""
        json_file = tmp_path / "array.json"
        data = [{"id": 1}, {"id": 2}]
        json_file.write_text(json.dumps(data), encoding="utf-8")

        result = list(safe_load_ndjson_file(json_file))
        assert len(result) == 2
        assert result[0] == {"id": 1}

    def test_load_single_json_object(self, tmp_path: Path) -> None:
        """Test loading a file with single JSON object."""
        json_file = tmp_path / "single.json"
        json_file.write_text('{"single": true}', encoding="utf-8")

        result = list(safe_load_ndjson_file(json_file))
        assert len(result) == 1
        assert result[0] == {"single": True}

    def test_load_nested_arrays(self, tmp_path: Path) -> None:
        """Test flattening of nested arrays [[{...}]]."""
        json_file = tmp_path / "nested.json"
        data = [[{"id": 1}], [{"id": 2}, {"id": 3}]]
        json_file.write_text(json.dumps(data), encoding="utf-8")

        result = list(safe_load_ndjson_file(json_file))
        assert len(result) == 3

    def test_load_missing_file_returns_empty(self, tmp_path: Path) -> None:
        """Test that missing file yields nothing."""
        missing = tmp_path / "missing.ndjson"

        result = list(safe_load_ndjson_file(missing))
        assert result == []

    def test_load_empty_file_returns_empty(self, tmp_path: Path) -> None:
        """Test that empty file yields nothing."""
        empty = tmp_path / "empty.ndjson"
        empty.write_text("", encoding="utf-8")

        result = list(safe_load_ndjson_file(empty))
        assert result == []

    def test_skips_malformed_lines(self, tmp_path: Path) -> None:
        """Test that malformed lines are skipped."""
        ndjson_file = tmp_path / "mixed.ndjson"
        content = '{"id": 1}\n{invalid json}\n{"id": 2}'
        ndjson_file.write_text(content, encoding="utf-8")

        result = list(safe_load_ndjson_file(ndjson_file))
        assert len(result) == 2
        assert result[0] == {"id": 1}
        assert result[1] == {"id": 2}

    def test_skips_empty_lines(self, tmp_path: Path) -> None:
        """Test that empty lines are skipped."""
        ndjson_file = tmp_path / "with_blanks.ndjson"
        content = '{"id": 1}\n\n\n{"id": 2}\n   \n{"id": 3}'
        ndjson_file.write_text(content, encoding="utf-8")

        result = list(safe_load_ndjson_file(ndjson_file))
        assert len(result) == 3

    def test_load_with_logging_disabled(self, tmp_path: Path) -> None:
        """Test that log_errors=False suppresses logging."""
        missing = tmp_path / "missing.ndjson"

        with patch("scripts.core.adapters.common.logger") as mock_logger:
            list(safe_load_ndjson_file(missing, log_errors=False))
            mock_logger.debug.assert_not_called()


class TestFlattenToDicts:
    """Tests for _flatten_to_dicts helper function."""

    def test_flatten_single_dict(self) -> None:
        """Test flattening a single dict."""
        result = list(_flatten_to_dicts({"key": "value"}))
        assert result == [{"key": "value"}]

    def test_flatten_list_of_dicts(self) -> None:
        """Test flattening a list of dicts."""
        result = list(_flatten_to_dicts([{"a": 1}, {"b": 2}]))
        assert result == [{"a": 1}, {"b": 2}]

    def test_flatten_nested_lists(self) -> None:
        """Test flattening nested lists."""
        result = list(_flatten_to_dicts([[{"a": 1}], [[{"b": 2}]]]))
        assert result == [{"a": 1}, {"b": 2}]

    def test_flatten_none(self) -> None:
        """Test flattening None."""
        result = list(_flatten_to_dicts(None))
        assert result == []

    def test_flatten_primitives_ignored(self) -> None:
        """Test that primitives are ignored."""
        result = list(_flatten_to_dicts([1, "string", True, {"valid": True}]))
        assert result == [{"valid": True}]

    def test_flatten_mixed_structure(self) -> None:
        """Test flattening a mixed structure."""
        data = [
            {"id": 1},
            [{"id": 2}, {"id": 3}],
            "ignore",
            None,
            [[{"id": 4}]],
        ]
        result = list(_flatten_to_dicts(data))
        assert len(result) == 4
        assert all(isinstance(r, dict) for r in result)
