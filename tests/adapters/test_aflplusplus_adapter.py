import json
from pathlib import Path

from scripts.core.adapters.aflplusplus_adapter import AFLPlusPlusAdapter


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_aflplusplus_basic_crash(tmp_path: Path):
    """Test basic AFL++ crash parsing."""
    sample = {
        "fuzzer": "afl++",
        "version": "4.0",
        "target": "my_program",
        "crashes": [
            {
                "id": "crash-001",
                "type": "SEGV",
                "signal": "SIGSEGV",
                "target": "my_program",
                "input_file": "crashes/id:000000,sig:06,src:000000",
                "timestamp": "2024-01-01T12:00:00Z",
                "classification": "exploitable",
            }
        ],
    }
    path = write_tmp(tmp_path, "afl.json", json.dumps(sample))
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    item = findings[0]
    assert item.severity == "CRITICAL"
    assert item.title.startswith("Fuzzing crash: SEGV")
    assert "exploitable" in item.title
    assert item.context["crash_type"] == "SEGV"
    assert item.context["classification"] == "exploitable"
    assert "memory-safety" in item.tags


def test_aflplusplus_multiple_crashes(tmp_path: Path):
    """Test multiple crashes."""
    sample = {
        "fuzzer": "afl++",
        "crashes": [
            {
                "id": "crash-001",
                "type": "SEGV",
                "signal": "SIGSEGV",
                "target": "parser",
                "input_file": "crashes/crash1",
                "classification": "exploitable",
            },
            {
                "id": "crash-002",
                "type": "ABORT",
                "signal": "SIGABRT",
                "target": "parser",
                "input_file": "crashes/crash2",
                "classification": "unknown",
            },
            {
                "id": "hang-001",
                "type": "HANG",
                "target": "parser",
                "input_file": "hangs/hang1",
            },
        ],
    }
    path = write_tmp(tmp_path, "afl.json", json.dumps(sample))
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 3
    # Check severity mapping
    segv = [f for f in findings if f.context["crash_type"] == "SEGV"][0]
    abort = [f for f in findings if f.context["crash_type"] == "ABORT"][0]
    hang = [f for f in findings if f.context["crash_type"] == "HANG"][0]
    assert segv.severity == "CRITICAL"
    assert abort.severity == "CRITICAL"
    assert hang.severity == "MEDIUM"


def test_aflplusplus_crash_type_severity(tmp_path: Path):
    """Test crash type to severity mapping."""
    crash_types = [
        ("SEGV", "CRITICAL"),
        ("segfault", "CRITICAL"),
        ("ABORT", "CRITICAL"),
        ("overflow", "CRITICAL"),
        ("heap-buffer-overflow", "CRITICAL"),
        ("HANG", "MEDIUM"),
        ("timeout", "MEDIUM"),
        ("CRASH", "HIGH"),
        ("ERROR", "HIGH"),
    ]
    for crash_type, expected_severity in crash_types:
        sample = {
            "crashes": [
                {
                    "id": f"test-{crash_type}",
                    "type": crash_type,
                    "target": "test_program",
                    "input_file": f"crashes/{crash_type}",
                }
            ]
        }
        path = write_tmp(tmp_path, f"afl_{crash_type}.json", json.dumps(sample))
        adapter = AFLPlusPlusAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].severity == expected_severity


def test_aflplusplus_empty_and_nonexistent(tmp_path: Path):
    """Test empty file and nonexistent file."""
    empty = write_tmp(tmp_path, "empty.json", "")
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    assert adapter.parse(empty) == []
    nonexistent = tmp_path / "nonexistent.json"
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    assert adapter.parse(nonexistent) == []


def test_aflplusplus_alternative_structure(tmp_path: Path):
    """Test alternative JSON structure with 'findings' key."""
    sample = {
        "fuzzer": "afl++",
        "findings": [
            {
                "crash_id": "001",
                "crash_type": "SEGV",
                "testcase": "input/crash1",
                "classification": "exploitable",
            }
        ],
    }
    path = write_tmp(tmp_path, "afl_alt.json", json.dumps(sample))
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert findings[0].context["crash_id"] == "001"


def test_aflplusplus_stack_trace_truncation(tmp_path: Path):
    """Test that long stack traces are truncated."""
    long_trace = "\n".join([f"Frame {i}: function_{i}()" for i in range(100)])
    sample = {
        "crashes": [
            {
                "id": "trace-test",
                "type": "SEGV",
                "target": "test",
                "input_file": "crash",
                "stack_trace": long_trace,
            }
        ]
    }
    path = write_tmp(tmp_path, "afl_trace.json", json.dumps(sample))
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    # Stack trace in context should be truncated to 500 chars
    assert len(findings[0].context["stack_trace"]) <= 500


def test_aflplusplus_malformed_json(tmp_path: Path):
    """Test handling of malformed JSON."""
    path = write_tmp(tmp_path, "bad.json", "{not valid json}")
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    assert adapter.parse(path) == []


def test_aflplusplus_non_dict_root(tmp_path: Path):
    """Test handling non-dict root JSON."""
    path = write_tmp(tmp_path, "array.json", json.dumps(["not", "a", "dict"]))
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    assert adapter.parse(path) == []


def test_aflplusplus_non_dict_crashes(tmp_path: Path):
    """Test handling non-dict items in crashes array."""
    sample = {
        "crashes": [
            "not a dict",  # Invalid
            123,  # Invalid
            {
                "id": "valid",
                "type": "SEGV",
                "target": "test",
                "input_file": "crash",
            },  # Valid
        ]
    }

    path = write_tmp(tmp_path, "afl_mixed.json", json.dumps(sample))
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    findings = adapter.parse(path)

    # Should skip invalid items and process valid one
    assert len(findings) == 1
    assert findings[0].context["crash_id"] == "valid"


def test_aflplusplus_missing_optional_fields(tmp_path: Path):
    """Test handling missing optional fields."""
    sample = {
        "crashes": [
            {
                "id": "minimal",
                "type": "SEGV",
                # Missing: target, input_file, timestamp, stack_trace, classification
            }
        ]
    }

    path = write_tmp(tmp_path, "afl_minimal.json", json.dumps(sample))
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    findings = adapter.parse(path)

    assert len(findings) == 1
    item = findings[0]

    # Should have defaults
    assert item.tool["version"] == "unknown"
    assert item.context["timestamp"] == ""
    assert item.context["stack_trace"] == ""
    assert item.context["classification"] == "unknown"


def test_aflplusplus_raw_payload_preserved(tmp_path: Path):
    """Test that raw AFL++ crash data is preserved."""
    sample = {
        "crashes": [
            {
                "id": "test",
                "type": "SEGV",
                "target": "test",
                "input_file": "crash",
                "custom_field": "custom_value",
                "custom_metadata": {"key": "value"},
            }
        ]
    }

    path = write_tmp(tmp_path, "afl_raw.json", json.dumps(sample))
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    findings = adapter.parse(path)

    assert len(findings) == 1
    item = findings[0]

    # Verify raw payload is fully preserved
    assert hasattr(item, "raw") and item.raw
    assert item.raw["custom_field"] == "custom_value"
    assert item.raw["custom_metadata"]["key"] == "value"


def test_aflplusplus_tags_based_on_crash_type(tmp_path: Path):
    """Test tags are correctly generated based on crash type."""
    sample = {
        "crashes": [
            {
                "id": "overflow",
                "type": "heap-buffer-overflow",
                "target": "test",
                "input_file": "crash",
                "classification": "exploitable",
            }
        ]
    }

    path = write_tmp(tmp_path, "afl_tags.json", json.dumps(sample))
    adapter = AFLPlusPlusAdapter()
    adapter = AFLPlusPlusAdapter()
    findings = adapter.parse(path)

    assert len(findings) == 1
    item = findings[0]

    # Check tags
    tags = item.tags
    assert "fuzzing" in tags
    assert "afl++" in tags
    assert "heap-buffer-overflow" in tags
    assert "classification:exploitable" in tags
    assert "memory-safety" in tags  # Because of 'overflow' in crash type
