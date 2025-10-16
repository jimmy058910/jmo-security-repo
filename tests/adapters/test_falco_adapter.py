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
