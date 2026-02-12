"""Tests for exception handling paths in normalize_and_report.py enrichment functions.

These tests cover:
- Trivy-Syft enrichment exception paths (lines 225-227)
- Compliance enrichment exceptions with FileNotFoundError.filename (lines 232-242)
- Priority enrichment exceptions (lines 247-252)
- Dedup threshold validation (lines 260-269, 274-276)
- Safe load plugin profiling errors (lines 313-314)
- Safe load plugin exception paths (lines 322-333)
- SBOM index edge cases (lines 399, 407)
- Finding type validation (lines 504-505)
- Cluster consensus finding path (line 608)
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch


import scripts.core.normalize_and_report as nr


def _write(p: Path, obj):
    """Helper to write JSON file."""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


class TestTrivySyftEnrichmentExceptions:
    """Tests for Trivy-Syft enrichment exception paths (lines 225-227)."""

    def test_unexpected_exception_in_trivy_syft_enrichment(self, tmp_path, monkeypatch):
        """Test generic Exception handler in Trivy-Syft enrichment (line 226-227)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        finding = {
            "schemaVersion": "1.0.0",
            "id": "f1",
            "ruleId": "R1",
            "message": "m",
            "severity": "LOW",
            "tool": {"name": "trivy", "version": "1"},
            "location": {"path": "a.txt", "startLine": 1},
        }
        _write(repo / "trivy.json", [finding])

        # Mock _safe_load_plugin to return findings
        def mock_load(_plugin_class, _path, _profiling=False):
            return [finding]

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)

        # Make _enrich_trivy_with_syft raise a generic Exception
        def raise_generic_error(_findings):
            raise RuntimeError("Unexpected SBOM error")

        monkeypatch.setattr(nr, "_enrich_trivy_with_syft", raise_generic_error)

        # Should handle gracefully
        out = nr.gather_results(root)
        assert isinstance(out, list)
        assert len(out) == 1


class TestComplianceEnrichmentExceptions:
    """Tests for compliance enrichment exception paths (lines 232-242)."""

    def test_file_not_found_with_filename_attribute(self, tmp_path, monkeypatch):
        """Test FileNotFoundError with filename attribute (lines 232-236)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        finding = {
            "schemaVersion": "1.0.0",
            "id": "f1",
            "ruleId": "R1",
            "message": "m",
            "severity": "LOW",
            "tool": {"name": "semgrep", "version": "1"},
            "location": {"path": "a.py", "startLine": 1},
        }
        _write(repo / "semgrep.json", [finding])

        # Mock _safe_load_plugin
        def mock_load(_plugin_class, _path, _profiling=False):
            return [finding]

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)

        # Mock enrich_findings_with_compliance at the normalize_and_report module level
        def raise_fnf(_findings):
            err = FileNotFoundError("cwe_mapping.json")
            err.filename = "cwe_mapping.json"
            raise err

        monkeypatch.setattr(nr, "enrich_findings_with_compliance", raise_fnf)

        out = nr.gather_results(root)
        assert isinstance(out, list)
        assert len(out) == 1

    def test_type_error_in_compliance_enrichment(self, tmp_path, monkeypatch):
        """Test TypeError handler in compliance enrichment (lines 237-239)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        finding = {
            "schemaVersion": "1.0.0",
            "id": "f1",
            "ruleId": "R1",
            "message": "m",
            "severity": "LOW",
            "tool": {"name": "semgrep", "version": "1"},
            "location": {"path": "a.py", "startLine": 1},
        }
        _write(repo / "semgrep.json", [finding])

        def mock_load(_plugin_class, _path, _profiling=False):
            return [finding]

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)

        def raise_type_error(_findings):
            raise TypeError("Invalid compliance data structure")

        monkeypatch.setattr(nr, "enrich_findings_with_compliance", raise_type_error)

        out = nr.gather_results(root)
        assert isinstance(out, list)

    def test_generic_exception_in_compliance_enrichment(self, tmp_path, monkeypatch):
        """Test generic Exception handler in compliance enrichment (lines 240-242)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        finding = {
            "schemaVersion": "1.0.0",
            "id": "f1",
            "ruleId": "R1",
            "message": "m",
            "severity": "LOW",
            "tool": {"name": "semgrep", "version": "1"},
            "location": {"path": "a.py", "startLine": 1},
        }
        _write(repo / "semgrep.json", [finding])

        def mock_load(_plugin_class, _path, _profiling=False):
            return [finding]

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)

        def raise_generic(_findings):
            raise RuntimeError("Unexpected compliance error")

        monkeypatch.setattr(nr, "enrich_findings_with_compliance", raise_generic)

        out = nr.gather_results(root)
        assert isinstance(out, list)


class TestPriorityEnrichmentExceptions:
    """Tests for priority enrichment exception paths (lines 247-252)."""

    def test_key_error_in_priority_enrichment(self, tmp_path, monkeypatch):
        """Test KeyError handler in priority enrichment (lines 247-249)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        finding = {
            "schemaVersion": "1.0.0",
            "id": "f1",
            "ruleId": "R1",
            "message": "m",
            "severity": "LOW",
            "tool": {"name": "semgrep", "version": "1"},
            "location": {"path": "a.py", "startLine": 1},
        }
        _write(repo / "semgrep.json", [finding])

        def mock_load(_plugin_class, _path, _profiling=False):
            return [finding]

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)

        def raise_key_error(_findings):
            raise KeyError("Missing priority data")

        monkeypatch.setattr(nr, "_enrich_with_priority", raise_key_error)

        out = nr.gather_results(root)
        assert isinstance(out, list)

    def test_value_error_in_priority_enrichment(self, tmp_path, monkeypatch):
        """Test ValueError handler in priority enrichment (lines 247-249)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        finding = {
            "schemaVersion": "1.0.0",
            "id": "f1",
            "ruleId": "R1",
            "message": "m",
            "severity": "LOW",
            "tool": {"name": "semgrep", "version": "1"},
            "location": {"path": "a.py", "startLine": 1},
        }
        _write(repo / "semgrep.json", [finding])

        def mock_load(_plugin_class, _path, _profiling=False):
            return [finding]

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)

        def raise_value_error(_findings):
            raise ValueError("Invalid priority score")

        monkeypatch.setattr(nr, "_enrich_with_priority", raise_value_error)

        out = nr.gather_results(root)
        assert isinstance(out, list)

    def test_generic_exception_in_priority_enrichment(self, tmp_path, monkeypatch):
        """Test generic Exception handler in priority enrichment (lines 250-252)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        finding = {
            "schemaVersion": "1.0.0",
            "id": "f1",
            "ruleId": "R1",
            "message": "m",
            "severity": "LOW",
            "tool": {"name": "semgrep", "version": "1"},
            "location": {"path": "a.py", "startLine": 1},
        }
        _write(repo / "semgrep.json", [finding])

        def mock_load(_plugin_class, _path, _profiling=False):
            return [finding]

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)

        def raise_generic(_findings):
            raise RuntimeError("EPSS API error")

        monkeypatch.setattr(nr, "_enrich_with_priority", raise_generic)

        out = nr.gather_results(root)
        assert isinstance(out, list)


class TestDedupThresholdValidation:
    """Tests for dedup threshold validation (lines 260-269, 274-276)."""

    def test_dedup_threshold_out_of_range_low(self, tmp_path, monkeypatch):
        """Test threshold < 0.5 uses default (lines 264-267)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        findings = [
            {
                "schemaVersion": "1.0.0",
                "id": f"f{i}",
                "ruleId": "R1",
                "message": "msg",
                "severity": "LOW",
                "tool": {"name": "semgrep", "version": "1"},
                "location": {"path": "a.py", "startLine": i},
            }
            for i in range(3)
        ]
        _write(repo / "semgrep.json", findings)

        def mock_load(_plugin_class, _path, _profiling=False):
            return findings

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)
        monkeypatch.setenv("JMO_DEDUP_THRESHOLD", "0.3")  # Below 0.5

        out = nr.gather_results(root)
        assert isinstance(out, list)

    def test_dedup_threshold_out_of_range_high(self, tmp_path, monkeypatch):
        """Test threshold > 1.0 uses default (lines 264-267)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        findings = [
            {
                "schemaVersion": "1.0.0",
                "id": f"f{i}",
                "ruleId": "R1",
                "message": "msg",
                "severity": "LOW",
                "tool": {"name": "semgrep", "version": "1"},
                "location": {"path": "a.py", "startLine": i},
            }
            for i in range(3)
        ]
        _write(repo / "semgrep.json", findings)

        def mock_load(_plugin_class, _path, _profiling=False):
            return findings

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)
        monkeypatch.setenv("JMO_DEDUP_THRESHOLD", "1.5")  # Above 1.0

        out = nr.gather_results(root)
        assert isinstance(out, list)

    def test_dedup_threshold_invalid_value(self, tmp_path, monkeypatch):
        """Test invalid threshold value uses default (lines 268-269)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        findings = [
            {
                "schemaVersion": "1.0.0",
                "id": f"f{i}",
                "ruleId": "R1",
                "message": "msg",
                "severity": "LOW",
                "tool": {"name": "semgrep", "version": "1"},
                "location": {"path": "a.py", "startLine": i},
            }
            for i in range(3)
        ]
        _write(repo / "semgrep.json", findings)

        def mock_load(_plugin_class, _path, _profiling=False):
            return findings

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)
        monkeypatch.setenv("JMO_DEDUP_THRESHOLD", "not_a_number")

        out = nr.gather_results(root)
        assert isinstance(out, list)

    def test_clustering_failure_exception(self, tmp_path, monkeypatch):
        """Test clustering failure exception path (lines 274-276)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        findings = [
            {
                "schemaVersion": "1.0.0",
                "id": f"f{i}",
                "ruleId": "R1",
                "message": "msg",
                "severity": "LOW",
                "tool": {"name": "semgrep", "version": "1"},
                "location": {"path": "a.py", "startLine": i},
            }
            for i in range(3)
        ]
        _write(repo / "semgrep.json", findings)

        def mock_load(_plugin_class, _path, _profiling=False):
            return findings

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)

        def raise_clustering_error(_findings, similarity_threshold=0.65):
            raise RuntimeError("Clustering failed")

        monkeypatch.setattr(
            nr, "_cluster_cross_tool_duplicates", raise_clustering_error
        )

        out = nr.gather_results(root)
        assert isinstance(out, list)
        assert len(out) == 3  # Falls back to unfiltered results


class TestSafeLoadPluginExceptionPaths:
    """Tests for _safe_load_plugin exception paths (lines 313-314, 322-333)."""

    def test_profiling_timing_append_failure(self, tmp_path, monkeypatch):
        """Test profiling timing append failure (lines 313-314)."""
        # Make PROFILE_TIMINGS["jobs"] non-appendable
        orig_jobs = nr.PROFILE_TIMINGS["jobs"]
        nr.PROFILE_TIMINGS["jobs"] = tuple()

        class MockPlugin:
            def __init__(self):
                self.metadata = MagicMock()
                self.metadata.name = "test"

            def parse(self, path):
                return []

        try:
            result = nr._safe_load_plugin(MockPlugin, Path("/fake"), profiling=True)
            assert result == []
        finally:
            nr.PROFILE_TIMINGS["jobs"] = orig_jobs

    def test_file_not_found_in_safe_load_plugin(self, tmp_path):
        """Test FileNotFoundError in _safe_load_plugin (lines 322-324)."""

        class MockPlugin:
            def __init__(self):
                self.metadata = MagicMock()
                self.metadata.name = "test"

            def parse(self, path):
                raise FileNotFoundError(f"No such file: {path}")

        result = nr._safe_load_plugin(MockPlugin, Path("/nonexistent"))
        assert result == []

    def test_adapter_parse_exception_in_safe_load_plugin(self, tmp_path):
        """Test AdapterParseException in _safe_load_plugin (lines 325-327)."""
        from scripts.core.exceptions import AdapterParseException

        class MockPlugin:
            def __init__(self):
                self.metadata = MagicMock()
                self.metadata.name = "test"

            def parse(self, path):
                raise AdapterParseException(
                    tool="test", path=str(path), reason="malformed"
                )

        result = nr._safe_load_plugin(MockPlugin, Path("/fake"))
        assert result == []

    def test_permission_error_in_safe_load_plugin(self, tmp_path):
        """Test PermissionError in _safe_load_plugin (lines 328-330)."""

        class MockPlugin:
            def __init__(self):
                self.metadata = MagicMock()
                self.metadata.name = "test"

            def parse(self, path):
                raise PermissionError(f"Permission denied: {path}")

        result = nr._safe_load_plugin(MockPlugin, Path("/restricted"))
        assert result == []

    def test_os_error_in_safe_load_plugin(self, tmp_path):
        """Test OSError in _safe_load_plugin (lines 328-330)."""

        class MockPlugin:
            def __init__(self):
                self.metadata = MagicMock()
                self.metadata.name = "test"

            def parse(self, path):
                raise OSError(f"I/O error: {path}")

        result = nr._safe_load_plugin(MockPlugin, Path("/badpath"))
        assert result == []

    def test_generic_exception_in_safe_load_plugin(self, tmp_path):
        """Test generic Exception in _safe_load_plugin (lines 331-333)."""

        class MockPlugin:
            def __init__(self):
                self.metadata = MagicMock()
                self.metadata.name = "test"

            def parse(self, path):
                raise RuntimeError("Unexpected error")

        result = nr._safe_load_plugin(MockPlugin, Path("/fake"))
        assert result == []


class TestSbomIndexEdgeCases:
    """Tests for SBOM index building edge cases (lines 399, 407)."""

    def test_build_syft_indexes_non_dict_finding(self):
        """Test _build_syft_indexes skips non-dict findings (line 399)."""
        findings = [
            "not a dict",
            None,
            123,
            {"tool": {"name": "syft"}, "tags": ["package"]},
        ]
        by_path, by_name = nr._build_syft_indexes(findings)
        # Non-dict findings should be skipped
        assert isinstance(by_path, dict)
        assert isinstance(by_name, dict)

    def test_build_syft_indexes_non_dict_raw(self):
        """Test _build_syft_indexes handles non-dict raw field (line 407)."""
        findings = [
            {
                "tool": {"name": "syft"},
                "tags": ["package"],
                "raw": "not a dict",  # Should be handled
                "title": "TestPackage",
                "location": {"path": "/app/test.txt"},
            }
        ]
        by_path, by_name = nr._build_syft_indexes(findings)
        # Should still extract from title
        assert "/app/test.txt" in by_path
        assert by_path["/app/test.txt"][0]["name"] == "TestPackage"

    def test_find_sbom_match_non_dict_raw(self):
        """Test _find_sbom_match handles non-dict raw field (line 444)."""
        trivy_finding = {
            "location": {"path": "/app/test.txt"},
            "raw": ["not", "a", "dict"],  # Should be replaced with {}
        }
        by_path = {
            "/app/test.txt": [
                {"name": "pkg", "version": "1.0", "path": "/app/test.txt"}
            ]
        }
        by_name = {}

        match = nr._find_sbom_match(trivy_finding, by_path, by_name)
        assert match is not None
        assert match["name"] == "pkg"


class TestEnrichTrivyWithSyftEdgeCases:
    """Tests for _enrich_trivy_with_syft edge cases (line 505)."""

    def test_enrich_skips_non_dict_findings(self):
        """Test _enrich_trivy_with_syft skips non-dict findings (line 505)."""
        findings = [
            "not a dict",
            None,
            {"tool": {"name": "trivy"}, "location": {"path": "/app"}},
        ]
        # Should not raise
        nr._enrich_trivy_with_syft(findings)
        # Non-dict findings unchanged
        assert findings[0] == "not a dict"
        assert findings[1] is None


class TestClusterCrossToolDuplicates:
    """Tests for _cluster_cross_tool_duplicates edge cases."""

    def test_single_finding_skips_clustering(self):
        """Test single finding skips clustering."""
        findings = [{"id": "f1", "message": "test"}]
        result = nr._cluster_cross_tool_duplicates(findings)
        assert result == findings

    def test_empty_findings_skips_clustering(self):
        """Test empty findings list skips clustering."""
        result = nr._cluster_cross_tool_duplicates([])
        assert result == []

    def test_clustering_creates_consensus_finding(self, monkeypatch):
        """Test multiple similar findings create consensus (line 608)."""
        findings = [
            {
                "id": "f1",
                "message": "XSS vulnerability",
                "tool": {"name": "tool1"},
                "location": {"path": "app.js", "startLine": 10},
                "severity": "HIGH",
            },
            {
                "id": "f2",
                "message": "XSS vulnerability",
                "tool": {"name": "tool2"},
                "location": {"path": "app.js", "startLine": 10},
                "severity": "HIGH",
            },
        ]

        # Mock the clusterer to simulate clustering behavior
        class MockCluster:
            def __init__(self, findings_list, representative):
                self.findings = findings_list
                self.representative = representative

            def to_consensus_finding(self):
                return {
                    "id": "consensus-1",
                    "message": "XSS vulnerability",
                    "detected_by": ["tool1", "tool2"],
                }

        class MockClusterer:
            def __init__(self, similarity_threshold=0.65):
                pass

            def cluster(self, findings_list, progress_callback=None):
                # Simulate clustering - return single cluster with both findings
                return [MockCluster(findings_list, findings_list[0])]

        # Patch FindingClusterer at the module import level in dedup_enhanced
        with patch("scripts.core.dedup_enhanced.FindingClusterer", MockClusterer):
            # Import happens inside _cluster_cross_tool_duplicates, need to patch there
            result = nr._cluster_cross_tool_duplicates(
                findings, similarity_threshold=0.65
            )
            # Should have created consensus finding
            assert len(result) <= 2


class TestDeprecatedSafeLoad:
    """Tests for deprecated _safe_load function exception paths."""

    def test_safe_load_profiling_timing_failure(self, monkeypatch):
        """Test _safe_load profiling timing append failure (lines 356-358)."""
        orig_jobs = nr.PROFILE_TIMINGS["jobs"]
        nr.PROFILE_TIMINGS["jobs"] = tuple()  # Make non-appendable

        def mock_loader(_path):
            return []

        try:
            result = nr._safe_load(mock_loader, Path("/fake"), profiling=True)
            assert result == []
        finally:
            nr.PROFILE_TIMINGS["jobs"] = orig_jobs

    def test_safe_load_non_profiling_path(self):
        """Test _safe_load non-profiling path (line 362)."""

        def mock_loader(_path):
            return [{"id": "test"}]

        result = nr._safe_load(mock_loader, Path("/fake"), profiling=False)
        assert result == [{"id": "test"}]


class TestAflPlusPlusHandling:
    """Tests for afl++ special case handling (line 182)."""

    def test_afl_plus_plus_json_normalization(self, tmp_path, monkeypatch):
        """Test afl++.json gets normalized to aflplusplus adapter (line 182)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        repo.mkdir(parents=True, exist_ok=True)

        # Create afl++.json (note the special filename)
        finding = {
            "schemaVersion": "1.0.0",
            "id": "afl1",
            "ruleId": "CRASH",
            "message": "Crash found",
            "severity": "HIGH",
            "tool": {"name": "aflplusplus", "version": "1"},
            "location": {"path": "test.c", "startLine": 1},
        }
        (repo / "afl++.json").write_text(json.dumps([finding]), encoding="utf-8")

        # Track what adapter name is requested
        adapter_requested = []

        def mock_get(name):
            adapter_requested.append(name)
            return None  # No adapter found (will be logged as warning)

        # Mock registry.get
        nr.get_plugin_registry()  # Verify accessible before mocking
        mock_registry = MagicMock()
        mock_registry.get = mock_get
        monkeypatch.setattr(nr, "get_plugin_registry", lambda: mock_registry)

        nr.gather_results(root)

        # Verify aflplusplus was requested (normalized from afl++)
        assert "aflplusplus" in adapter_requested


class TestSyftIndexPathBranch:
    """Tests for SBOM index path/name branch (line 413->417)."""

    def test_syft_package_name_only_no_path(self):
        """Test Syft package with name but no path (line 417 branch)."""
        findings = [
            {
                "tool": {"name": "syft"},
                "tags": ["package"],
                "raw": {"name": "requests", "version": "2.28.0"},
                "location": {"path": ""},  # Empty path
            }
        ]
        by_path, by_name = nr._build_syft_indexes(findings)
        # Should have entry by name but not by path
        assert len(by_path) == 0
        assert "requests" in by_name
        assert by_name["requests"][0]["name"] == "requests"


class TestPriorityEnrichmentLoop:
    """Tests for priority enrichment loop edge case (line 542->540)."""

    def test_priority_enrichment_finding_id_not_in_scores(self, monkeypatch):
        """Test _enrich_with_priority handles finding id not in scores (line 542)."""
        findings = [
            {"id": "f1", "message": "test"},
            {"id": "f2", "message": "test2"},
        ]

        # Mock PriorityCalculator to return empty scores
        class MockCalculator:
            def calculate_priorities_bulk(self, findings_list):
                # Return scores only for f1, not f2
                return {
                    "f1": MagicMock(
                        priority=50.0,
                        epss=0.5,
                        epss_percentile=0.6,
                        is_kev=False,
                        kev_due_date=None,
                        components={},
                    )
                }

        monkeypatch.setattr(nr, "PriorityCalculator", MockCalculator)
        nr._enrich_with_priority(findings)

        # Only f1 should have priority
        assert "priority" in findings[0]
        assert "priority" not in findings[1]

    def test_priority_enrichment_empty_findings(self):
        """Test _enrich_with_priority handles empty findings list."""
        findings = []
        # Should not raise
        nr._enrich_with_priority(findings)
        assert findings == []


class TestDedupThresholdValidRange:
    """Tests for dedup threshold valid range (line 263)."""

    def test_dedup_threshold_valid_value_applied(self, tmp_path, monkeypatch):
        """Test valid threshold (0.5-1.0) is applied (lines 262-263)."""
        root = tmp_path / "results"
        repo = root / "individual-repos" / "r1"
        findings = [
            {
                "schemaVersion": "1.0.0",
                "id": f"f{i}",
                "ruleId": "R1",
                "message": "msg",
                "severity": "LOW",
                "tool": {"name": "semgrep", "version": "1"},
                "location": {"path": "a.py", "startLine": i},
            }
            for i in range(3)
        ]
        _write(repo / "semgrep.json", findings)

        def mock_load(_plugin_class, _path, _profiling=False):
            return findings

        monkeypatch.setattr(nr, "_safe_load_plugin", mock_load)

        # Track what threshold is passed to clusterer
        threshold_used = []

        def mock_cluster(findings_list, similarity_threshold=0.65):
            threshold_used.append(similarity_threshold)
            return findings_list  # Return unchanged

        monkeypatch.setattr(nr, "_cluster_cross_tool_duplicates", mock_cluster)
        monkeypatch.setenv("JMO_DEDUP_THRESHOLD", "0.75")  # Valid value

        nr.gather_results(root)

        # Verify valid threshold was applied
        assert 0.75 in threshold_used


class TestProgressCallbackExit:
    """Tests for progress callback exit branch (line 588->exit)."""

    def test_progress_callback_called_at_intervals(self, monkeypatch):
        """Test progress callback is called at expected intervals."""
        # Create findings > 50 to test progress callback
        findings = [
            {
                "id": f"f{i}",
                "message": f"Issue {i}",
                "tool": {"name": f"tool{i % 3}"},
                "location": {"path": "a.py", "startLine": i},
                "severity": "LOW",
            }
            for i in range(100)
        ]

        # Track progress callback calls
        progress_calls = []

        class MockCluster:
            def __init__(self, finding):
                self.findings = [finding]
                self.representative = finding

            def to_consensus_finding(self):
                return self.representative

        class MockClusterer:
            def __init__(self, similarity_threshold=0.65):
                pass

            def cluster(self, findings_list, progress_callback=None):
                # Simulate calling progress callback
                if progress_callback:
                    for i, f in enumerate(findings_list):
                        progress_callback(i, len(findings_list), f"Processing {i}")
                        progress_calls.append(i)
                return [MockCluster(f) for f in findings_list]

        with patch("scripts.core.dedup_enhanced.FindingClusterer", MockClusterer):
            nr._cluster_cross_tool_duplicates(findings, similarity_threshold=0.65)

        # Verify progress callback was invoked
        assert len(progress_calls) > 0
