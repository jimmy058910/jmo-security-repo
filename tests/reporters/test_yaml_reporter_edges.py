from pathlib import Path
import sys

import pytest

from scripts.core.reporters.yaml_reporter import write_yaml


def test_yaml_reporter_writes_empty_list(tmp_path: Path):
    """Test write_yaml() with empty findings list produces v1.0.0 metadata wrapper."""
    out = tmp_path / "empty.yaml"
    write_yaml([], out, validate=False)
    text = out.read_text(encoding="utf-8")

    # v1.0.0: YAML now has metadata wrapper even for empty findings
    assert "meta:" in text
    assert "findings: []" in text
    assert "output_version: 1.0.0" in text or "output_version: '1.0.0'" in text
    assert "finding_count: 0" in text


def test_yaml_reporter_preserves_fields(tmp_path: Path):
    """Test write_yaml() preserves all finding fields within metadata wrapper."""
    sample = [
        {
            "schemaVersion": "1.0.0",
            "id": "abc",
            "ruleId": "R1",
            "message": "m",
            "title": "t",
            "severity": "LOW",
            "tool": {"name": "x", "version": "1"},
            "location": {"path": "a.txt", "startLine": 1},
            "context": {"foo": "bar"},
            "tags": ["one", "two"],
        }
    ]
    out = tmp_path / "out.yaml"
    write_yaml(sample, out, validate=False)
    s = out.read_text(encoding="utf-8")

    # v1.0.0: Verify metadata wrapper present
    assert "meta:" in s
    assert "findings:" in s

    # Ensure key finding fields are preserved
    for key in ("schemaVersion", "ruleId", "severity", "location", "message"):
        assert key in s


def test_yaml_reporter_raises_without_pyyaml(monkeypatch, tmp_path: Path):
    import scripts.core.reporters.yaml_reporter as ymod

    monkeypatch.setattr(ymod, "yaml", None, raising=False)
    with pytest.raises(RuntimeError):
        ymod.write_yaml([], tmp_path / "x.yaml")


def test_yaml_import_error_handling():
    """Test that ImportError during yaml import is handled gracefully."""
    # This test covers lines 13-15 (ImportError exception handler)
    # Save original yaml module
    original_yaml = sys.modules.get("yaml")

    # Remove yaml from sys.modules to force ImportError
    if "yaml" in sys.modules:
        del sys.modules["yaml"]

    # Mock yaml import to raise ImportError
    import builtins

    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("No module named 'yaml'")
        return original_import(name, *args, **kwargs)

    builtins.__import__ = mock_import

    try:
        # Force reimport of yaml_reporter to trigger ImportError handler
        import scripts.core.reporters.yaml_reporter as ymod
        import importlib

        importlib.reload(ymod)

        # Verify that yaml is None after ImportError
        assert ymod.yaml is None
    finally:
        # Restore original import and yaml module
        builtins.__import__ = original_import
        if original_yaml is not None:
            sys.modules["yaml"] = original_yaml
