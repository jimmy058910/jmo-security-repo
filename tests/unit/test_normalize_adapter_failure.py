import json
import logging
from pathlib import Path

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

    # Monkeypatch _safe_load_plugin to raise (v0.9.0 plugin architecture)
    def boom(_plugin_class, _path, _profiling=False):
        raise RuntimeError("boom")

    monkeypatch.setattr(nr, "_safe_load_plugin", boom)

    out = nr.gather_results(root)
    # Should still return a list (adapter failure ignored)
    assert isinstance(out, list)


def test_invalid_jmo_threads_env(tmp_path: Path, monkeypatch):
    """Test ValueError handler when JMO_THREADS is invalid (lines 70-71)."""
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"
    _write(
        repo / "trufflehog.json",
        [
            {
                "schemaVersion": "1.0.0",
                "id": "x",
                "ruleId": "R1",
                "message": "m",
                "severity": "LOW",
                "tool": {"name": "trufflehog", "version": "1"},
                "location": {"path": "a.txt", "startLine": 1},
            }
        ],
    )

    # Set invalid JMO_THREADS value
    monkeypatch.setenv("JMO_THREADS", "invalid_number")

    out = nr.gather_results(root)
    # Should fall back to default and still work
    assert isinstance(out, list)
    assert len(out) == 1


def test_adapter_parse_exception_in_gather(tmp_path: Path, monkeypatch):
    """Aggregation survives a `_safe_load_plugin` that raises.

    Note what this does and does not prove. It patches `_safe_load_plugin`
    itself to raise, which the real one never does -- it catches
    AdapterParseException, FileNotFoundError, OSError and bare Exception and
    returns `[]` for each. So this exercises `gather_results`' generic backstop,
    not any per-exception handler, and it cannot see the WARNING that the real
    `_safe_load_plugin` now emits (that is covered below).

    The docstring used to claim it tested "the AdapterParseException handler in
    gather_results (line 134)". That handler was unreachable in production and
    has been removed; only this monkeypatch made it look live.
    """
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"
    _write(repo / "semgrep.json", [])

    # Monkeypatch _safe_load_plugin to raise AdapterParseException
    def raise_adapter_error(_plugin_class, path, _profiling=False):
        raise AdapterParseException(
            tool="semgrep", path=str(path), reason="malformed JSON"
        )

    monkeypatch.setattr(nr, "_safe_load_plugin", raise_adapter_error)

    out = nr.gather_results(root)
    # Should handle exception gracefully and return empty list
    assert isinstance(out, list)
    assert len(out) == 0


def test_file_not_found_in_gather(tmp_path: Path, monkeypatch):
    """Aggregation survives a `_safe_load_plugin` that raises FileNotFoundError.

    Same caveat as the test above: the real `_safe_load_plugin` swallows this
    and returns `[]`, so what runs here is `gather_results`' generic backstop.
    """
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"
    _write(repo / "trivy.json", [])

    # Monkeypatch _safe_load_plugin to raise FileNotFoundError
    def raise_file_not_found(_plugin_class, path, _profiling=False):
        raise FileNotFoundError(f"File not found: {path}")

    monkeypatch.setattr(nr, "_safe_load_plugin", raise_file_not_found)

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
        {
            "schemaVersion": "1.0.0",
            "id": "t1",
            "ruleId": "CVE-2021-1234",
            "message": "vuln",
            "severity": "HIGH",
            "tool": {"name": "trivy", "version": "1"},
            "location": {"path": "package.json", "startLine": 1},
            "raw": {"PkgName": "lodash", "PkgPath": "package.json"},
        }
    ]

    # Mock _safe_load_plugin to return findings (v0.9.0 plugin architecture)
    def mock_load_plugin(_plugin_class, _path, _profiling=False):
        # Return list of dicts (plugin.parse returns Finding objects, _safe_load_plugin converts to dicts)
        return trivy_findings

    monkeypatch.setattr(nr, "_safe_load_plugin", mock_load_plugin)

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
        {
            "schemaVersion": "1.0.0",
            "id": "f1",
            "ruleId": "R1",
            "message": "m",
            "severity": "LOW",
            "tool": {"name": "semgrep", "version": "1"},
            "location": {"path": "a.py", "startLine": 1},
        }
    ]

    # Mock _safe_load_plugin to return findings (v0.9.0 plugin architecture)
    def mock_load_plugin(_plugin_class, _path, _profiling=False):
        return semgrep_findings

    monkeypatch.setattr(nr, "_safe_load_plugin", mock_load_plugin)

    # Monkeypatch enrich_findings_with_compliance to raise FileNotFoundError
    from scripts.core import compliance_mapper

    def raise_file_not_found(findings_list):
        raise FileNotFoundError("mapping_data.json")

    monkeypatch.setattr(
        compliance_mapper, "enrich_findings_with_compliance", raise_file_not_found
    )

    # Need to create the file for gather_results to iterate
    _write(repo / "semgrep.json", semgrep_findings)

    out = nr.gather_results(root)
    # Should handle enrichment failure gracefully
    assert isinstance(out, list)
    assert len(out) == 1

    # Test KeyError
    def raise_key_error(findings_list):
        raise KeyError("missing compliance field")

    monkeypatch.setattr(
        compliance_mapper, "enrich_findings_with_compliance", raise_key_error
    )
    out = nr.gather_results(root)
    assert isinstance(out, list)


class _Meta:
    def __init__(self, name: str) -> None:
        self.name = name


class _ExplodingAdapter:
    """An adapter whose parse() fails the way a real one does on bad output."""

    metadata = _Meta("semgrep")

    def parse(self, path):
        raise AdapterParseException(
            tool="semgrep", path=Path(path), reason="Invalid JSON: line 1 column 2"
        )


class _WorkingAdapter:
    metadata = _Meta("semgrep")

    def parse(self, path):
        return []


def test_unparseable_tool_output_is_reported_at_default_verbosity(tmp_path, caplog):
    """#823: a tool whose output cannot be parsed must not fail silently.

    This was `logger.debug`, and `configure_scan_logging` sets the `scripts`
    logger to WARNING by default -- so a tool that ran, exited acceptably and
    wrote a file JMo could not read contributed nothing to the report, and said
    so on no stream. Measured on #822: a `per_tool` flag making trivy emit a
    table instead of JSON took a target from 2 findings to 0, with rc=0 and not
    one line logged.

    Asserted as "at least WARNING" rather than "exactly WARNING", because the
    property that matters is *visible at the default level*, not the specific
    level chosen.
    """
    out_path = tmp_path / "semgrep.json"
    out_path.write_text("{ not json", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="scripts.core.normalize_and_report"):
        result = nr._safe_load_plugin(_ExplodingAdapter, out_path)

    # The findings are still dropped rather than crashing the report...
    assert result == []

    # ...but the reader is told which tool lost them, and why.
    visible = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert visible, "the parse failure was invisible at the default log level"
    assert any("semgrep" in m for m in visible), visible
    assert any("MISSING" in m for m in visible), visible
    assert any("Invalid JSON" in m for m in visible), visible


def test_successful_parse_stays_quiet(tmp_path, caplog):
    """The control. Without it, any always-warn bug would pass the test above."""
    out_path = tmp_path / "semgrep.json"
    out_path.write_text("[]", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="scripts.core.normalize_and_report"):
        result = nr._safe_load_plugin(_WorkingAdapter, out_path)

    assert result == []
    visible = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert not visible, f"a clean parse should log nothing at WARNING: {visible}"
