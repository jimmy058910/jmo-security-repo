import json
from pathlib import Path

from scripts.core.adapters.falco_adapter import load_falco


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_falco_basic_event(tmp_path: Path):
    """Test basic Falco event parsing."""
    event = {
        "output": "Sensitive file opened for reading by non-trusted program",
        "priority": "Warning",
        "rule": "Read sensitive file untrusted",
        "time": "2024-01-01T12:00:00.000Z",
        "output_fields": {
            "container.id": "abc123",
            "container.name": "my-container",
            "fd.name": "/etc/shadow",
            "proc.name": "cat",
            "user.name": "root",
        },
        "source": "syscall",
        "tags": ["filesystem", "mitre_credential_access"],
        "hostname": "host1",
    }
    path = write_tmp(tmp_path, "falco.json", json.dumps(event))
    out = load_falco(path)
    assert len(out) == 1
    item = out[0]
    assert item["severity"] == "MEDIUM"
    assert item["title"] == "Read sensitive file untrusted"
    assert item["context"]["container_name"] == "my-container"
    assert item["context"]["file"] == "/etc/shadow"
    assert "filesystem" in item["tags"]


def test_falco_ndjson_multiple_events(tmp_path: Path):
    """Test NDJSON format with multiple events."""
    events = [
        {
            "rule": "Terminal shell in container",
            "priority": "Critical",
            "output": "A shell was spawned in a container",
            "output_fields": {"container.name": "web-app", "proc.name": "/bin/bash"},
        },
        {
            "rule": "Unexpected network connection",
            "priority": "Error",
            "output": "Unexpected outbound connection attempt",
            "output_fields": {"fd.name": "192.168.1.100:443"},
        },
    ]
    ndjson = "\n".join([json.dumps(e) for e in events])
    path = write_tmp(tmp_path, "falco.ndjson", ndjson)
    out = load_falco(path)
    assert len(out) == 2
    assert out[0]["severity"] == "CRITICAL"
    assert out[1]["severity"] == "HIGH"
    assert "runtime-security" in out[0]["tags"]


def test_falco_priority_mapping(tmp_path: Path):
    """Test priority to severity mapping."""
    priorities = [
        ("Emergency", "CRITICAL"),
        ("Alert", "CRITICAL"),
        ("Critical", "CRITICAL"),
        ("Error", "HIGH"),
        ("Warning", "MEDIUM"),
        ("Notice", "LOW"),
        ("Informational", "INFO"),
    ]
    for priority, expected_severity in priorities:
        event = {
            "rule": f"{priority} Rule",
            "priority": priority,
            "output": f"Event with {priority} priority",
        }
        path = write_tmp(tmp_path, f"falco_{priority}.json", json.dumps(event))
        out = load_falco(path)
        assert len(out) == 1
        assert out[0]["severity"] == expected_severity


def test_falco_empty_and_nonexistent(tmp_path: Path):
    """Test empty file and nonexistent file."""
    empty = write_tmp(tmp_path, "empty.json", "")
    assert load_falco(empty) == []
    nonexistent = tmp_path / "nonexistent.json"
    assert load_falco(nonexistent) == []


def test_falco_blank_lines_ignored(tmp_path: Path):
    """Test that blank lines in NDJSON are ignored."""
    event = {"rule": "Test Rule", "priority": "Warning", "output": "Test output"}
    ndjson = f"\n{json.dumps(event)}\n\n"
    path = write_tmp(tmp_path, "falco_blanks.json", ndjson)
    out = load_falco(path)
    assert len(out) == 1


def test_falco_malformed_json(tmp_path: Path):
    """Test handling of malformed JSON."""
    path = write_tmp(tmp_path, "bad.json", "{not valid json}")
    assert load_falco(path) == []


def test_falco_non_dict_event(tmp_path: Path):
    """Test handling non-dict events in NDJSON."""
    ndjson = "\n".join(
        [
            "not a dict",  # Invalid
            json.dumps(
                {
                    "output": "Valid event",
                    "priority": "Warning",
                    "rule": "test-rule",
                    "time": "2025-01-01T00:00:00.000Z",
                    "output_fields": {},
                }
            ),
        ]
    )

    path = write_tmp(tmp_path, "falco_mixed.ndjson", ndjson)
    out = load_falco(path)

    # Should skip invalid line and process valid one
    assert len(out) == 1
    assert out[0]["ruleId"] == "FALCO-test-rule"


def test_falco_container_context(tmp_path: Path):
    """Test container context extraction."""
    sample = {
        "output": "Container exec detected",
        "priority": "Error",
        "rule": "Terminal shell in container",
        "time": "2025-10-19T12:00:00.000Z",
        "output_fields": {
            "container.id": "abc123",
            "container.name": "nginx-prod",
            "proc.name": "/bin/bash",
            "user.name": "root",
        },
    }

    path = write_tmp(tmp_path, "falco_container.json", json.dumps(sample))

    out = load_falco(path)

    assert len(out) == 1
    item = out[0]

    # Check context field includes container info
    assert "context" in item
    assert item["context"]["container_id"] == "abc123"
    assert item["context"]["container_name"] == "nginx-prod"
    assert item["context"]["process"] == "/bin/bash"
    assert item["context"]["user"] == "root"


def test_falco_file_access_context(tmp_path: Path):
    """Test file access context extraction."""
    sample = {
        "output": "Sensitive file read",
        "priority": "Warning",
        "rule": "Read sensitive file",
        "time": "2025-10-19T12:00:00.000Z",
        "output_fields": {
            "fd.name": "/etc/passwd",
            "proc.name": "cat",
            "user.name": "attacker",
        },
        "hostname": "prod-server-01",
    }

    path = write_tmp(tmp_path, "falco_file.json", json.dumps(sample))

    out = load_falco(path)

    assert len(out) == 1
    item = out[0]

    # Check context includes file and hostname
    assert item["context"]["file"] == "/etc/passwd"
    assert item["context"]["hostname"] == "prod-server-01"
    assert item["location"]["path"] == "/etc/passwd"


def test_falco_tags_extraction(tmp_path: Path):
    """Test falco extracts tags from event."""
    sample = {
        "output": "Test event with tags",
        "priority": "Warning",
        "rule": "tagged-rule",
        "time": "2025-10-19T12:00:00.000Z",
        "output_fields": {},
        "tags": ["filesystem", "mitre_credential_access", "custom_tag"],
        "source": "k8s_audit",
    }

    path = write_tmp(tmp_path, "falco_tags.json", json.dumps(sample))

    out = load_falco(path)

    assert len(out) == 1
    item = out[0]

    # Check tags are present
    assert "tags" in item
    tags = item["tags"]
    assert "runtime-security" in tags  # Default tag
    assert "falco" in tags  # Default tag
    assert "k8s_audit" in tags  # Source tag
    assert "filesystem" in tags  # Custom tag from event
    assert "mitre_credential_access" in tags  # Custom tag from event


def test_falco_missing_optional_fields(tmp_path: Path):
    """Test falco handles missing optional fields gracefully."""
    sample = {
        "output": "Minimal event",
        "priority": "Warning",
        "rule": "minimal-rule",
        # Missing: time, output_fields, source, tags, hostname, falco_version
    }

    path = write_tmp(tmp_path, "falco_minimal.json", json.dumps(sample))

    out = load_falco(path)

    assert len(out) == 1
    item = out[0]

    # Should have defaults
    assert item["tool"]["version"] == "unknown"
    assert item["context"]["timestamp"] == ""
    assert item["context"]["hostname"] == ""
    assert item["context"]["source"] == "syscall"  # Default source


def test_falco_raw_payload_preserved(tmp_path: Path):
    """Test that raw falco output is preserved."""
    sample = {
        "output": "Test event",
        "priority": "Warning",
        "rule": "test-rule",
        "time": "2025-10-19T12:00:00.000Z",
        "output_fields": {"custom_field": "custom_value"},
        "custom_metadata": {"key": "value"},
    }

    path = write_tmp(tmp_path, "falco_raw.json", json.dumps(sample))

    out = load_falco(path)

    assert len(out) == 1
    item = out[0]

    # Verify raw payload is fully preserved
    assert "raw" in item
    assert item["raw"]["custom_metadata"]["key"] == "value"
    assert item["raw"]["output_fields"]["custom_field"] == "custom_value"
