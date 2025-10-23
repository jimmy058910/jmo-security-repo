from pathlib import Path
import json
import os

from scripts.core import normalize_and_report as nr
from scripts.core.exceptions import AdapterParseException


def _write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_safe_load_adapter_failure_isolated(tmp_path: Path, monkeypatch):
    # Create minimal results dir with a repo and one tool JSON
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"
    _write(repo / "trufflehog.json", [])

    # Monkeypatch one loader to raise
    def boom(_path):
        raise RuntimeError("boom")

    monkeypatch.setattr(nr, "load_trufflehog", boom)

    out = nr.gather_results(root)
    # Should still return a list (adapter failure ignored)
    assert isinstance(out, list)


def test_invalid_jmo_threads_env(tmp_path: Path, monkeypatch):
    """Test ValueError handler when JMO_THREADS is invalid (lines 70-71)."""
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"
    _write(repo / "trufflehog.json", [{"schemaVersion": "1.0.0", "id": "x", "ruleId": "R1",
                                        "message": "m", "severity": "LOW",
                                        "tool": {"name": "trufflehog", "version": "1"},
                                        "location": {"path": "a.txt", "startLine": 1}}])

    # Set invalid JMO_THREADS value
    monkeypatch.setenv("JMO_THREADS", "invalid_number")

    out = nr.gather_results(root)
    # Should fall back to default and still work
    assert isinstance(out, list)
    assert len(out) == 1


def test_adapter_parse_exception_in_gather(tmp_path: Path, monkeypatch):
    """Test AdapterParseException handler in gather_results (line 134)."""
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"
    _write(repo / "semgrep.json", [])

    # Monkeypatch loader to raise AdapterParseException
    def raise_adapter_error(path):
        raise AdapterParseException(tool="semgrep", path=str(path), reason="malformed JSON")

    monkeypatch.setattr(nr, "load_semgrep", raise_adapter_error)

    out = nr.gather_results(root)
    # Should handle exception gracefully and return empty list
    assert isinstance(out, list)
    assert len(out) == 0


def test_file_not_found_in_gather(tmp_path: Path, monkeypatch):
    """Test FileNotFoundError handler in gather_results (line 137)."""
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"
    _write(repo / "trivy.json", [])

    # Monkeypatch loader to raise FileNotFoundError
    def raise_file_not_found(path):
        raise FileNotFoundError(f"File not found: {path}")

    monkeypatch.setattr(nr, "load_trivy", raise_file_not_found)

    out = nr.gather_results(root)
    # Should handle exception gracefully
    assert isinstance(out, list)
    assert len(out) == 0


def test_trivy_syft_enrichment_error(tmp_path: Path, monkeypatch):
    """Test exception handlers in Trivy-Syft enrichment (lines 150-155)."""
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"

    # Create valid trivy findings
    trivy_findings = [
        {"schemaVersion": "1.0.0", "id": "t1", "ruleId": "CVE-2021-1234",
         "message": "vuln", "severity": "HIGH",
         "tool": {"name": "trivy", "version": "1"},
         "location": {"path": "package.json", "startLine": 1},
         "raw": {"PkgName": "lodash", "PkgPath": "package.json"}}
    ]

    # Mock load_trivy to return findings
    def mock_load_trivy(path):
        return trivy_findings

    monkeypatch.setattr(nr, "load_trivy", mock_load_trivy)

    # Monkeypatch _enrich_trivy_with_syft to raise KeyError
    def raise_key_error(findings_list):
        raise KeyError("missing SBOM data")

    monkeypatch.setattr(nr, "_enrich_trivy_with_syft", raise_key_error)

    # Need to create the file for gather_results to iterate
    _write(repo / "trivy.json", trivy_findings)

    out = nr.gather_results(root)
    # Should handle enrichment failure gracefully
    assert isinstance(out, list)
    assert len(out) == 1

    # Restore and test ValueError
    def raise_value_error(findings_list):
        raise ValueError("malformed findings")

    monkeypatch.setattr(nr, "_enrich_trivy_with_syft", raise_value_error)
    out = nr.gather_results(root)
    assert isinstance(out, list)


def test_compliance_enrichment_error(tmp_path: Path, monkeypatch):
    """Test exception handlers in compliance enrichment (lines 160-170)."""
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"

    semgrep_findings = [
        {"schemaVersion": "1.0.0", "id": "f1", "ruleId": "R1",
         "message": "m", "severity": "LOW",
         "tool": {"name": "semgrep", "version": "1"},
         "location": {"path": "a.py", "startLine": 1}}
    ]

    # Mock load_semgrep to return findings
    def mock_load_semgrep(path):
        return semgrep_findings

    monkeypatch.setattr(nr, "load_semgrep", mock_load_semgrep)

    # Monkeypatch enrich_findings_with_compliance to raise FileNotFoundError
    from scripts.core import compliance_mapper

    def raise_file_not_found(findings_list):
        raise FileNotFoundError("mapping_data.json")

    monkeypatch.setattr(compliance_mapper, "enrich_findings_with_compliance", raise_file_not_found)

    # Need to create the file for gather_results to iterate
    _write(repo / "semgrep.json", semgrep_findings)

    out = nr.gather_results(root)
    # Should handle enrichment failure gracefully
    assert isinstance(out, list)
    assert len(out) == 1

    # Test KeyError
    def raise_key_error(findings_list):
        raise KeyError("missing compliance field")

    monkeypatch.setattr(compliance_mapper, "enrich_findings_with_compliance", raise_key_error)
    out = nr.gather_results(root)
    assert isinstance(out, list)


def test_safe_load_file_not_found(tmp_path: Path):
    """Test FileNotFoundError handler in _safe_load (lines 199-200)."""
    from scripts.core.adapters.trufflehog_adapter import load_trufflehog

    # Call _safe_load with non-existent file
    result = nr._safe_load(load_trufflehog, tmp_path / "nonexistent.json")

    # Should return empty list
    assert result == []


def test_safe_load_adapter_parse_exception(tmp_path: Path, monkeypatch):
    """Test AdapterParseException handler in _safe_load (lines 203-204)."""
    fake_file = tmp_path / "bad.json"
    fake_file.write_text("{}", encoding="utf-8")

    def raise_adapter_error(path):
        raise AdapterParseException(tool="test", path=str(path), reason="bad format")

    result = nr._safe_load(raise_adapter_error, fake_file)

    # Should return empty list
    assert result == []


def test_safe_load_permission_error(tmp_path: Path):
    """Test OSError/PermissionError handler in _safe_load (lines 207-208)."""
    from scripts.core.adapters.trufflehog_adapter import load_trufflehog

    # Create a file we can't read (Unix permissions)
    restricted_file = tmp_path / "restricted.json"
    restricted_file.write_text("[]", encoding="utf-8")

    # Make file unreadable
    os.chmod(restricted_file, 0o000)

    try:
        result = nr._safe_load(load_trufflehog, restricted_file)
        # Should return empty list
        assert result == []
    finally:
        # Restore permissions for cleanup
        os.chmod(restricted_file, 0o644)
