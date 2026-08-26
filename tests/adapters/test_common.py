#!/usr/bin/env python3
"""Tests for common adapter utilities."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch

from scripts.core.adapters.common import (
    _flatten_to_dicts,
    safe_load_json_file,
    safe_load_ndjson_file,
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
            # Whole-mock assertion, not `.debug` -- the missing-file branch
            # logs at `warning`, not `debug`, so asserting only `.debug` was
            # never called holds regardless of whether `log_errors` is
            # honoured.
            #
            # NOTE: `mock_logger.assert_not_called()` does NOT do this --
            # measured directly. `Mock.assert_not_called()` only checks
            # whether the mock *itself* was invoked as `mock_logger(...)`;
            # `logger.warning(...)` calls the child mock `mock_logger.warning`,
            # which leaves `mock_logger.called` False regardless. Asserting
            # `mock_calls == []` is what actually inspects every child
            # attribute call (`.debug`, `.warning`, `.info`, `.error`, ...).
            assert mock_logger.mock_calls == [], (
                f"Expected no logger calls with log_errors=False, got: "
                f"{mock_logger.mock_calls}"
            )

    def test_load_with_logging_enabled(self, tmp_path: Path) -> None:
        """Test that log_errors=True logs warning messages for missing files."""
        missing = tmp_path / "missing.json"

        with patch("scripts.core.adapters.common.logger") as mock_logger:
            safe_load_json_file(missing, log_errors=True)
            mock_logger.warning.assert_called()

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
            # Whole-mock assertion, not `.debug` -- same defect as the JSON
            # sibling above (#834): the missing-file branch here also logs
            # at `warning`, not `debug`, so `.debug.assert_not_called()` held
            # whether or not `log_errors` was honoured. See the JSON sibling
            # for why this is `mock_calls == []` and not
            # `mock_logger.assert_not_called()`.
            assert mock_logger.mock_calls == [], (
                f"Expected no logger calls with log_errors=False, got: "
                f"{mock_logger.mock_calls}"
            )


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


class TestUnparseableOutputIsAnnounced:
    """#823/#822: a tool output that cannot be parsed must not vanish quietly."""

    def test_malformed_json_warns_and_names_the_file(
        self, tmp_path: Path, caplog
    ) -> None:
        """This branch used to be DEBUG while its two siblings warned.

        `safe_load_json_file` was inconsistent with itself: a file that is
        *absent* or *empty* logged at WARNING, while a file that is present and
        unreadable logged at DEBUG -- and `configure_scan_logging` sets the
        `scripts` logger to WARNING, so that branch was invisible in every
        normal run.

        Malformed is the most alarming of the three: the tool ran, exited
        acceptably and wrote something JMo cannot read, so its findings are
        absent while the scan reports success. Measured on #822 -- a `per_tool`
        flag making trivy emit a table instead of JSON took a target from 2
        findings to 0, rc=0, nothing on any stream.

        This is the layer that matters because **no adapter raises
        AdapterParseException** (0 of 27); they all route through here.
        """
        bad = tmp_path / "trivy.json"
        bad.write_text("\nReport Summary\n+----+\n", encoding="utf-8")

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            result = safe_load_json_file(bad, default=None)

        assert result is None
        visible = [
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        ]
        assert visible, "an unreadable tool output was not reported at all"
        assert any("trivy.json" in m for m in visible), visible
        assert any("MISSING" in m for m in visible), visible

    def test_valid_json_stays_quiet(self, tmp_path: Path, caplog) -> None:
        """The control. Without it an always-warn bug would pass the test above."""
        good = tmp_path / "trivy.json"
        good.write_text('{"Results": []}', encoding="utf-8")

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            result = safe_load_json_file(good, default=None)

        assert result == {"Results": []}
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_speculative_callers_can_opt_out(self, tmp_path: Path, caplog) -> None:
        """`log_errors=False` is how a format-probing caller stays quiet.

        `prowler_adapter._load` tries NDJSON and then JSON. A genuine multi-line
        NDJSON file is not valid JSON, so without this escape hatch the warning
        above would fire on every prowler scan of that shape -- which is exactly
        the always-fires warning #784 was about.
        """
        ndjson = tmp_path / "prowler.json"
        ndjson.write_text('{"a": 1}\n{"a": 2}\n', encoding="utf-8")

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            result = safe_load_json_file(ndjson, default=None, log_errors=False)

        assert result is None
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_prowler_ndjson_does_not_warn_through_the_real_adapter(
        self, tmp_path: Path, caplog
    ) -> None:
        """The end-to-end version: the real probe must not warn on valid NDJSON."""
        from scripts.core.adapters.prowler_adapter import _iter_prowler_records

        ndjson = tmp_path / "prowler.json"
        ndjson.write_text(
            '{"class_uid": 2001, "finding_info": {"uid": "a"}}\n'
            '{"class_uid": 2001, "finding_info": {"uid": "b"}}\n',
            encoding="utf-8",
        )

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            _iter_prowler_records(ndjson)

        noisy = [
            r.getMessage()
            for r in caplog.records
            if r.levelno >= logging.WARNING and "Could not parse" in r.getMessage()
        ]
        assert not noisy, f"prowler's speculative JSON probe warned: {noisy}"


class TestNdjsonFailuresAreAnnounced:
    """Chunk 5: `safe_load_ndjson_file` reported every failure at DEBUG.

    #830 made `safe_load_json_file` warn on unreadable output, which covered
    the 23 adapters that use it. Its NDJSON sibling -- used by `falco`,
    `nuclei`, `prowler` and `trufflehog` -- kept logging *every* failure mode
    at DEBUG, and `configure_scan_logging` sets the `scripts` logger to
    WARNING, so all four were blind to a missing, empty or corrupt file.

    Measured before the fix, across the whole degenerate matrix: those four
    adapters were the only ones invisible on all six file-level failure modes
    (23 warned, 4 did not).
    """

    def _warnings(self, caplog) -> list[str]:
        return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]

    def test_missing_file_warns(self, tmp_path: Path, caplog) -> None:
        missing = tmp_path / "absent.ndjson"

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            assert list(safe_load_ndjson_file(missing)) == []

        assert any("does not exist" in m for m in self._warnings(caplog))

    def test_empty_file_warns(self, tmp_path: Path, caplog) -> None:
        """trufflehog writes a genuinely 0-byte file when it finds nothing.

        Measured on a real scan: `trufflehog.json` was 0 bytes and the adapter
        reported it at DEBUG, so an empty result and a failed run looked
        identical at default verbosity.
        """
        empty = tmp_path / "empty.ndjson"
        empty.write_bytes(b"")

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            assert list(safe_load_ndjson_file(empty)) == []

        assert any("is empty" in m for m in self._warnings(caplog))

    def test_partial_line_loss_is_reported_with_both_counts(
        self, tmp_path: Path, caplog
    ) -> None:
        """The worst case, because the loss is PARTIAL.

        A total failure yields an empty report, which is at least suspicious.
        This yields a *populated* report that is quietly short. Measured on a
        10-line trufflehog stream with 4 truncated lines: 6 verified-secret
        findings returned, 4 dropped, nothing at WARNING or above.
        """
        lines = [json.dumps({"DetectorName": "AWS", "Raw": f"K{i}"}) for i in range(10)]
        for i in (2, 4, 6, 8):
            lines[i] = lines[i][: len(lines[i]) // 2]
        ndjson = tmp_path / "trufflehog.json"
        ndjson.write_bytes(("\n".join(lines) + "\n").encode())

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            got = list(safe_load_ndjson_file(ndjson))

        assert len(got) == 6
        warnings = self._warnings(caplog)
        # Assert the positive shape -- the counts -- not merely that something
        # was logged. A guard that only checks "a warning happened" cannot tell
        # a useful message from an empty one.
        assert any(
            "4 line(s)" in m and "6 parsed successfully" in m for m in warnings
        ), f"expected a summary naming both counts, got: {warnings}"

    def test_one_summary_not_one_warning_per_bad_line(
        self, tmp_path: Path, caplog
    ) -> None:
        """Flooding hides a signal as thoroughly as silence does."""
        ndjson = tmp_path / "many_bad.ndjson"
        ndjson.write_bytes(b"\n".join([b'{"bad"'] * 50) + b"\n")

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            list(safe_load_ndjson_file(ndjson))

        assert len(self._warnings(caplog)) == 1

    def test_clean_ndjson_stays_quiet(self, tmp_path: Path, caplog) -> None:
        """A healthy NDJSON stream must not warn -- it fails the whole-file
        JSON parse by definition, and promoting that would fire every run."""
        ndjson = tmp_path / "clean.ndjson"
        ndjson.write_bytes(
            b'{"DetectorName": "AWS", "Raw": "a"}\n{"DetectorName": "GH", "Raw": "b"}\n'
        )

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            assert len(list(safe_load_ndjson_file(ndjson))) == 2

        assert not self._warnings(caplog)

    def test_valid_json_array_stays_quiet(self, tmp_path: Path, caplog) -> None:
        arr = tmp_path / "array.json"
        arr.write_bytes(b'[{"id": 1}, {"id": 2}]')

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            assert len(list(safe_load_ndjson_file(arr))) == 2

        assert not self._warnings(caplog)

    def test_line_loss_reports_even_for_speculative_callers(
        self, tmp_path: Path, caplog
    ) -> None:
        """`log_errors=False` must not re-hide destroyed data.

        prowler passes it to probe whether a file is NDJSON at all. That is
        legitimate for "this isn't NDJSON", but line loss cannot happen on a
        healthy file of *either* accepted format -- a valid JSON array returns
        from the whole-file parse without entering the loop, and valid NDJSON
        loses no lines. So losing lines is always real, and always reported.
        """
        ndjson = tmp_path / "partial.ndjson"
        ndjson.write_bytes(b'{"CheckID": "a"}\n{"CheckI\n')

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            list(safe_load_ndjson_file(ndjson, log_errors=False))

        assert any("1 line(s)" in m for m in self._warnings(caplog))


class TestStructurallyValidButImpossibleJson:
    """Chunk 5: JSON that parses but is not a shape any tool emits.

    `null`, a bare string and a bare number all decode cleanly, so the
    malformed branch cannot see them -- and every adapter then fails its
    `isinstance(data, dict)` guard and returns `[]`, which is
    indistinguishable from "the tool found nothing". Measured across all 27
    adapters before the fix: 0 findings and **0 log records at any level**.
    """

    def _warnings(self, caplog) -> list[str]:
        return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]

    def test_literal_null_warns(self, tmp_path: Path, caplog) -> None:
        f = tmp_path / "null.json"
        f.write_bytes(b"null")

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            safe_load_json_file(f)

        assert any("not an object or array" in m for m in self._warnings(caplog))

    def test_bare_scalar_warns_and_names_the_type(self, tmp_path: Path, caplog) -> None:
        f = tmp_path / "scalar.json"
        f.write_bytes(b'"a string"')

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            safe_load_json_file(f)

        assert any("contained str" in m for m in self._warnings(caplog))

    def test_empty_object_and_array_stay_quiet(self, tmp_path: Path, caplog) -> None:
        """`{}` and `[]` are how a tool says "no findings" -- the single most
        common healthy outcome. Warning on them would fire on most scans."""
        for name, payload in (("obj.json", b"{}"), ("arr.json", b"[]")):
            caplog.clear()
            f = tmp_path / name
            f.write_bytes(payload)

            with caplog.at_level(
                logging.WARNING, logger="scripts.core.adapters.common"
            ):
                safe_load_json_file(f)

            assert not self._warnings(caplog), f"{name} warned"

    def test_speculative_callers_can_still_opt_out(
        self, tmp_path: Path, caplog
    ) -> None:
        f = tmp_path / "null.json"
        f.write_bytes(b"null")

        with caplog.at_level(logging.WARNING, logger="scripts.core.adapters.common"):
            safe_load_json_file(f, log_errors=False)

        assert not self._warnings(caplog)

    def test_value_is_still_returned_unchanged(self, tmp_path: Path) -> None:
        """Pure diagnostic: every adapter already rejects a non-dict/list, so
        replacing the return value would be a behaviour change this does not
        need to make."""
        f = tmp_path / "scalar.json"
        f.write_bytes(b"123")

        assert safe_load_json_file(f) == 123
