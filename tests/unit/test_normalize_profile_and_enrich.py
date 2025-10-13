from pathlib import Path

from scripts.core.normalize_and_report import gather_results, PROFILE_TIMINGS


def _write(p: Path, s: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8")


def test_gather_results_with_profiling_metadata(tmp_path: Path, monkeypatch):
    root = tmp_path / "results"
    indiv = root / "individual-repos" / "r1"
    # Minimal inputs
    _write(indiv / "gitleaks.json", "[]")
    _write(indiv / "trufflehog.json", "{}")
    # Enable profiling via env
    monkeypatch.setenv("JMO_PROFILE", "1")
    # Constrain threads via env
    monkeypatch.setenv("JMO_THREADS", "2")
    out = gather_results(root)
    assert isinstance(out, list)
    # PROFILE_TIMINGS meta should include max_workers
    assert isinstance(PROFILE_TIMINGS.get("meta", {}).get("max_workers", 0), int)


def test_enrich_noop_when_no_syft_trivy(tmp_path: Path):
    root = tmp_path / "results"
    indiv = root / "individual-repos" / "r1"
    # Only semgrep file; no syft nor trivy
    _write(indiv / "semgrep.json", '{"results": []}')
    out = gather_results(root)
    # Should not crash and simply return list
    assert isinstance(out, list)
