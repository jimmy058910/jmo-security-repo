import json
import sys
from pathlib import Path

import types

import scripts.core.normalize_and_report as nr


# ===== Memory-Efficient Deduplication Tests =====


class TestDedupMemoryEfficient:
    """Tests for memory-efficient deduplication (F2 optimization)."""

    def test_basic_deduplication(self):
        """Test basic deduplication preserves unique findings."""
        findings = [
            {"id": "fp1", "message": "Issue A"},
            {"id": "fp2", "message": "Issue B"},
            {"id": "fp3", "message": "Issue C"},
        ]
        result = nr.deduplicate_findings_memory_efficient(findings)
        assert len(result) == 3
        assert [f["id"] for f in result] == ["fp1", "fp2", "fp3"]

    def test_removes_duplicates(self):
        """Test that duplicates are removed."""
        findings = [
            {"id": "fp1", "message": "Issue A"},
            {"id": "fp2", "message": "Issue B"},
            {"id": "fp1", "message": "Issue A (dup)"},  # Duplicate
            {"id": "fp3", "message": "Issue C"},
            {"id": "fp2", "message": "Issue B (dup)"},  # Duplicate
        ]
        result = nr.deduplicate_findings_memory_efficient(findings)
        assert len(result) == 3
        assert [f["id"] for f in result] == ["fp1", "fp2", "fp3"]

    def test_preserves_first_occurrence(self):
        """Test that first occurrence is preserved."""
        findings = [
            {"id": "fp1", "message": "First", "extra": "data1"},
            {"id": "fp1", "message": "Second", "extra": "data2"},  # Duplicate
        ]
        result = nr.deduplicate_findings_memory_efficient(findings)
        assert len(result) == 1
        assert result[0]["message"] == "First"
        assert result[0]["extra"] == "data1"

    def test_empty_findings(self):
        """Test with empty input."""
        result = nr.deduplicate_findings_memory_efficient([])
        assert result == []

    def test_none_fingerprint_excluded(self):
        """Test that findings without id are excluded."""
        findings = [
            {"id": "fp1", "message": "Issue A"},
            {"message": "No ID"},  # Missing id
            {"id": None, "message": "None ID"},  # None id
            {"id": "fp2", "message": "Issue B"},
        ]
        result = nr.deduplicate_findings_memory_efficient(findings)
        assert len(result) == 2
        assert [f["id"] for f in result] == ["fp1", "fp2"]

    def test_large_dataset_performance(self):
        """Test deduplication of 10k+ findings performs well."""
        import time

        # Create 10k findings with 50% duplicates
        findings = []
        for i in range(10000):
            findings.append(
                {"id": f"fp{i % 5000}", "message": f"Issue {i}", "severity": "HIGH"}
            )

        start = time.perf_counter()
        result = nr.deduplicate_findings_memory_efficient(findings)
        elapsed = time.perf_counter() - start

        assert len(result) == 5000  # 50% unique
        assert elapsed < 1.0  # Should complete in <1 second

    def test_same_results_as_dict_approach(self):
        """Verify same results as original dict approach."""
        findings = [
            {"id": "fp1", "message": "A", "tool": "trivy"},
            {"id": "fp2", "message": "B", "tool": "semgrep"},
            {"id": "fp1", "message": "A dup", "tool": "bandit"},
            {"id": "fp3", "message": "C", "tool": "trivy"},
            {"id": "fp2", "message": "B dup", "tool": "trivy"},
        ]

        # Original dict approach
        seen = {}
        for f in findings:
            seen[f.get("id")] = f
        dict_result = list(seen.values())

        # Memory-efficient approach
        efficient_result = nr.deduplicate_findings_memory_efficient(findings)

        # New approach keeps first occurrence (better for traceability)
        # Dict approach keeps last occurrence (Python dict behavior)
        # Verify same unique IDs returned
        assert set(f["id"] for f in efficient_result) == set(
            f["id"] for f in dict_result
        )
        assert len(efficient_result) == len(dict_result)


class TestDedupStreaming:
    """Tests for streaming deduplication variant."""

    def test_basic_deduplication(self):
        """Test streaming approach produces same results."""
        findings = [
            {"id": "fp1", "message": "Issue A"},
            {"id": "fp2", "message": "Issue B"},
            {"id": "fp1", "message": "Issue A (dup)"},
        ]
        result = nr.deduplicate_findings_streaming(findings)
        assert len(result) == 2
        assert [f["id"] for f in result] == ["fp1", "fp2"]

    def test_empty_input(self):
        """Test with empty input."""
        result = nr.deduplicate_findings_streaming([])
        assert result == []

    def test_matches_memory_efficient(self):
        """Test streaming matches memory-efficient approach."""
        findings = [{"id": f"fp{i % 100}", "message": f"Issue {i}"} for i in range(500)]

        efficient = nr.deduplicate_findings_memory_efficient(findings)
        streaming = nr.deduplicate_findings_streaming(findings)

        assert len(efficient) == len(streaming)
        assert [f["id"] for f in efficient] == [f["id"] for f in streaming]


def _write(p: Path, s: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8")


def test_gather_no_individual_repos(tmp_path: Path):
    root = tmp_path / "results"
    root.mkdir(parents=True, exist_ok=True)
    out = nr.gather_results(root)
    assert out == []


def test_cpu_threads_path_without_env(tmp_path: Path, monkeypatch):
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r"
    repo.mkdir(parents=True, exist_ok=True)
    # minimal files so jobs exist
    _write(repo / "gitleaks.json", "[]")
    # Ensure no env override and predictable cpu_count
    monkeypatch.delenv("JMO_THREADS", raising=False)
    monkeypatch.setenv("JMO_PROFILE", "1")
    monkeypatch.setattr(nr.os, "cpu_count", lambda: 5)
    nr.PROFILE_TIMINGS["jobs"].clear()
    nr.PROFILE_TIMINGS["meta"].clear()
    out = nr.gather_results(root)
    assert isinstance(out, list)
    # max_workers should be min(8, max(2, cpu)) -> 5
    assert nr.PROFILE_TIMINGS.get("meta", {}).get("max_workers") == 5


def test_threads_exception_path(tmp_path: Path, monkeypatch):
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r"
    repo.mkdir(parents=True, exist_ok=True)
    _write(repo / "gitleaks.json", "[]")
    monkeypatch.delenv("JMO_THREADS", raising=False)
    monkeypatch.setenv("JMO_PROFILE", "1")

    def boom():
        raise RuntimeError("cpu fail")

    monkeypatch.setattr(nr.os, "cpu_count", boom)
    nr.PROFILE_TIMINGS["jobs"].clear()
    nr.PROFILE_TIMINGS["meta"].clear()
    out = nr.gather_results(root)
    assert isinstance(out, list)
    # Fallback to default workers on exception: 8
    assert nr.PROFILE_TIMINGS.get("meta", {}).get("max_workers") == 8


def test_as_completed_exception_is_caught(tmp_path: Path, monkeypatch):
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r"
    repo.mkdir(parents=True, exist_ok=True)
    _write(repo / "gitleaks.json", "[]")

    calls = {"n": 0}

    def flaky(loader, path, profiling=False):  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return []

    monkeypatch.setattr(nr, "_safe_load", flaky)
    out = nr.gather_results(root)
    assert isinstance(out, list)


def test_env_threads_override(tmp_path: Path, monkeypatch):
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r"
    repo.mkdir(parents=True, exist_ok=True)
    _write(repo / "gitleaks.json", "[]")
    # Override via env should be used
    monkeypatch.setenv("JMO_THREADS", "3")
    monkeypatch.setenv("JMO_PROFILE", "1")
    nr.PROFILE_TIMINGS["jobs"].clear()
    nr.PROFILE_TIMINGS["meta"].clear()
    out = nr.gather_results(root)
    assert isinstance(out, list)
    assert nr.PROFILE_TIMINGS.get("meta", {}).get("max_workers") == 3


def test_profiling_meta_update_failure(tmp_path: Path, monkeypatch):
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r"
    repo.mkdir(parents=True, exist_ok=True)
    _write(repo / "gitleaks.json", "[]")
    # Make meta mapping immutable to force exception on assignment
    monkeypatch.setenv("JMO_PROFILE", "1")
    nr.PROFILE_TIMINGS["jobs"].clear()
    nr.PROFILE_TIMINGS["meta"] = types.MappingProxyType({})
    # Should not raise despite inability to set meta
    out = nr.gather_results(root)
    assert isinstance(out, list)
    # restore meta dict for subsequent tests
    nr.PROFILE_TIMINGS["meta"] = {}


def test_safe_load_exception_paths(monkeypatch):
    # loader that raises
    def raiser(_):
        raise ValueError("nope")

    # profiling False path
    assert nr._safe_load(raiser, Path("/dev/null"), profiling=False) == []

    # profiling True path with append failure
    def empty_ok(_):
        return []

    # make jobs non-appendable
    orig_jobs = nr.PROFILE_TIMINGS["jobs"]
    nr.PROFILE_TIMINGS["jobs"] = tuple()
    try:
        out = nr._safe_load(empty_ok, Path("/dev/null"), profiling=True)
        assert out == []
    finally:
        nr.PROFILE_TIMINGS["jobs"] = orig_jobs


def test_enrich_no_syft_noop():
    trivy = {
        "schemaVersion": "1.0.0",
        "id": "t4",
        "tool": {"name": "trivy"},
        "tags": ["vuln"],
        "raw": {"PkgName": "", "PkgPath": ""},
        "location": {"path": "", "startLine": 0},
    }
    before = json.dumps(trivy, sort_keys=True)
    items = [trivy]
    nr._enrich_trivy_with_syft(items)
    after = json.dumps(items[0], sort_keys=True)
    assert before == after


def test_dedupe_keeps_single(tmp_path: Path, monkeypatch):
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r"
    repo.mkdir(parents=True, exist_ok=True)
    # Use trufflehog.json (gitleaks removed in v0.5.0)
    _write(repo / "trufflehog.json", "[]")

    def dup(_plugin_class, _path, profiling=False):  # noqa: ARG001
        return [
            {"id": "DUP", "schemaVersion": "1.0.0"},
            {"id": "DUP", "schemaVersion": "1.0.0"},
        ]

    # v0.9.0 uses _safe_load_plugin
    monkeypatch.setattr(nr, "_safe_load_plugin", dup)
    out = nr.gather_results(root)
    # Deduped to a single element
    assert len([f for f in out if f.get("id") == "DUP"]) == 1


def test_enrich_trivy_with_syft_paths():
    # Build synthetic findings for enrichment
    syft_pkg = {
        "schemaVersion": "1.0.0",
        "id": "p1",
        "tool": {"name": "syft"},
        "tags": ["package"],
        "title": "Flask 2.0",
        "raw": {"name": "Flask", "version": "2.0"},
        "location": {"path": "/app/requirements.txt", "startLine": 0},
    }
    trivy_by_loc = {
        "schemaVersion": "1.0.0",
        "id": "t1",
        "tool": {"name": "trivy"},
        "tags": [],
        "raw": {"PkgName": "", "PkgPath": ""},
        "location": {"path": "/app/requirements.txt", "startLine": 0},
    }
    trivy_by_pkgpath = {
        "schemaVersion": "1.0.0",
        "id": "t2",
        "tool": {"name": "trivy"},
        "tags": [],
        "raw": {"PkgName": "", "PkgPath": "/app/requirements.txt"},
        "location": {"path": "", "startLine": 0},
    }
    trivy_by_name = {
        "schemaVersion": "1.0.0",
        "id": "t3",
        "tool": {"name": "trivy"},
        "tags": ["pkg:Flask@2.0"],  # already present to test no-duplicate
        "raw": {"PkgName": "flask", "PkgPath": ""},
        "location": {"path": "", "startLine": 0},
    }
    items = [syft_pkg, trivy_by_loc, trivy_by_pkgpath, trivy_by_name]
    nr._enrich_trivy_with_syft(items)
    # loc match
    assert items[1].get("context", {}).get("sbom", {}).get("name") == "Flask"
    assert "pkg:Flask@2.0" in items[1].get("tags", [])
    # pkg path match
    assert (
        items[2].get("context", {}).get("sbom", {}).get("path")
        == "/app/requirements.txt"
    )
    # name match (case-insensitive) but tag not duplicated
    assert items[3].get("context", {}).get("sbom", {}).get("name") == "Flask"
    assert items[3]["tags"].count("pkg:Flask@2.0") == 1


def test_normalize_and_report_main_cli(tmp_path: Path, monkeypatch):
    # Build a small result dir with one tool output
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r"
    _write(
        repo / "gitleaks.json",
        json.dumps([{"RuleID": "R", "File": "a", "StartLine": 1}]),
    )

    # Simulate argv and run main (writes JSON/MD)
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8")
    argv = ["normalize_and_report.py", str(root), "--out", str(root / "summaries")]
    monkeypatch.setattr(sys, "argv", argv)
    # Call main directly; it should write outputs under --out
    nr.main()
    out_dir = root / "summaries"
    assert (out_dir / "findings.json").exists()
    assert (out_dir / "SUMMARY.md").exists()
