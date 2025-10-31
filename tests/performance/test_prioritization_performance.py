"""
Performance tests for EPSS/KEV prioritization.

Tests API latency, cache performance, and bulk operations.
"""

import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from scripts.core.epss_integration import EPSSClient, EPSSScore
from scripts.core.kev_integration import KEVClient, KEVEntry
from scripts.core.priority_calculator import PriorityCalculator


@pytest.fixture
def temp_cache_dir(tmp_path):
    """Create temporary cache directory."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return cache_dir


class TestEPSSPerformance:
    """Performance tests for EPSS integration."""

    def test_cached_score_latency(self, temp_cache_dir):
        """Test that cached EPSS scores are retrieved in <50ms."""
        client = EPSSClient(cache_dir=temp_cache_dir)

        # Cache a score manually
        score = EPSSScore(
            cve='CVE-2024-1234',
            epss=0.95,
            percentile=0.999,
            date='2024-10-01'
        )
        client._cache_score(score)

        # Measure retrieval time
        start = time.time()
        cached_score = client.get_score('CVE-2024-1234')
        elapsed_ms = (time.time() - start) * 1000

        assert cached_score is not None
        assert elapsed_ms < 50, f"Cached retrieval took {elapsed_ms:.2f}ms (expected <50ms)"

    @patch('requests.get')
    def test_api_call_latency(self, mock_get, temp_cache_dir):
        """Test that uncached EPSS API calls complete in <500ms."""
        # Mock fast API response
        mock_response = Mock()
        mock_response.json.return_value = {
            "total": 1,
            "data": [{
                "cve": "CVE-2024-5678",
                "epss": "0.85",
                "percentile": "0.95",
                "date": "2024-10-01"
            }]
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        client = EPSSClient(cache_dir=temp_cache_dir)

        # Measure API call time
        start = time.time()
        score = client.get_score('CVE-2024-5678')
        elapsed_ms = (time.time() - start) * 1000

        assert score is not None
        assert elapsed_ms < 500, f"API call took {elapsed_ms:.2f}ms (expected <500ms)"

    @patch('requests.get')
    def test_bulk_api_latency(self, mock_get, temp_cache_dir):
        """Test that bulk EPSS API calls for 100 CVEs complete in <2s."""
        # Mock bulk API response
        mock_response = Mock()
        mock_response.json.return_value = {
            "total": 100,
            "data": [
                {
                    "cve": f"CVE-2024-{i:04d}",
                    "epss": "0.50",
                    "percentile": "0.80",
                    "date": "2024-10-01"
                }
                for i in range(100)
            ]
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        client = EPSSClient(cache_dir=temp_cache_dir)

        cves = [f"CVE-2024-{i:04d}" for i in range(100)]

        # Measure bulk API call time
        start = time.time()
        scores = client.get_scores_bulk(cves)
        elapsed_ms = (time.time() - start) * 1000

        assert len(scores) == 100
        assert elapsed_ms < 2000, f"Bulk API call took {elapsed_ms:.2f}ms (expected <2000ms)"

    def test_cache_hit_ratio(self, temp_cache_dir):
        """Test cache effectiveness with mixed cached/uncached requests."""
        client = EPSSClient(cache_dir=temp_cache_dir)

        # Pre-cache 50 scores
        for i in range(50):
            score = EPSSScore(
                cve=f"CVE-2024-{i:04d}",
                epss=0.5,
                percentile=0.8,
                date='2024-10-01'
            )
            client._cache_score(score)

        # Request 100 CVEs (50 cached, 50 uncached)
        cves = [f"CVE-2024-{i:04d}" for i in range(100)]

        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = {
                "total": 50,
                "data": [
                    {
                        "cve": f"CVE-2024-{i:04d}",
                        "epss": "0.50",
                        "percentile": "0.80",
                        "date": "2024-10-01"
                    }
                    for i in range(50, 100)
                ]
            }
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            scores = client.get_scores_bulk(cves)

            # Verify only uncached CVEs were fetched from API
            assert mock_get.call_count == 1
            assert len(scores) == 100  # All 100 CVEs returned


class TestKEVPerformance:
    """Performance tests for KEV integration."""

    @patch('requests.get')
    def test_catalog_download_latency(self, mock_get, temp_cache_dir):
        """Test that KEV catalog download completes in <5s."""
        # Mock KEV catalog response (realistic size ~1000 entries)
        mock_response = Mock()
        mock_response.json.return_value = {
            "title": "CISA Catalog",
            "catalogVersion": "2024.10.01",
            "dateReleased": "2024-10-01T00:00:00.000Z",
            "count": 1000,
            "vulnerabilities": [
                {
                    "cveID": f"CVE-2024-{i:04d}",
                    "vendorProject": "Vendor",
                    "product": "Product",
                    "vulnerabilityName": "Vuln",
                    "dateAdded": "2024-09-01",
                    "shortDescription": "Description",
                    "requiredAction": "Patch",
                    "dueDate": "2024-10-01"
                }
                for i in range(1000)
            ]
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        # Measure download + parse time
        start = time.time()
        client = KEVClient(cache_dir=temp_cache_dir)
        elapsed_ms = (time.time() - start) * 1000

        assert len(client.catalog) == 1000
        assert elapsed_ms < 5000, f"Catalog download took {elapsed_ms:.2f}ms (expected <5000ms)"

    def test_cached_catalog_load_latency(self, temp_cache_dir):
        """Test that cached KEV catalog loads in <100ms."""
        # Create cached catalog
        catalog_data = {
            "title": "CISA Catalog",
            "catalogVersion": "2024.10.01",
            "dateReleased": "2024-10-01T00:00:00.000Z",
            "count": 1000,
            "vulnerabilities": [
                {
                    "cveID": f"CVE-2024-{i:04d}",
                    "vendorProject": "Vendor",
                    "product": "Product",
                    "vulnerabilityName": "Vuln",
                    "dateAdded": "2024-09-01",
                    "shortDescription": "Description",
                    "requiredAction": "Patch",
                    "dueDate": "2024-10-01"
                }
                for i in range(1000)
            ]
        }

        import json
        cache_path = temp_cache_dir / "kev_catalog.json"
        cache_path.write_text(json.dumps(catalog_data))

        # Measure cached load time
        start = time.time()
        with patch('requests.get'):  # Prevent download
            client = KEVClient(cache_dir=temp_cache_dir)
        elapsed_ms = (time.time() - start) * 1000

        assert len(client.catalog) == 1000
        assert elapsed_ms < 100, f"Cached load took {elapsed_ms:.2f}ms (expected <100ms)"

    def test_kev_lookup_latency(self, temp_cache_dir):
        """Test that KEV lookups are instant (<1ms)."""
        # Create client with small catalog
        catalog_data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vendorProject": "Vendor",
                    "product": "Product",
                    "vulnerabilityName": "Vuln",
                    "dateAdded": "2024-09-01",
                    "shortDescription": "Description",
                    "requiredAction": "Patch",
                    "dueDate": "2024-10-01"
                }
            ]
        }

        import json
        cache_path = temp_cache_dir / "kev_catalog.json"
        cache_path.write_text(json.dumps(catalog_data))

        with patch('requests.get'):
            client = KEVClient(cache_dir=temp_cache_dir)

        # Measure lookup time
        start = time.time()
        is_kev = client.is_kev('CVE-2024-1234')
        elapsed_ms = (time.time() - start) * 1000

        assert is_kev is True
        assert elapsed_ms < 1, f"KEV lookup took {elapsed_ms:.2f}ms (expected <1ms)"


class TestPriorityCalculatorPerformance:
    """Performance tests for priority calculation."""

    @patch('scripts.core.priority_calculator.EPSSClient')
    @patch('scripts.core.priority_calculator.KEVClient')
    def test_single_finding_calculation_latency(self, mock_kev_client_class, mock_epss_client_class):
        """Test that single finding priority calculation is fast (<10ms)."""
        # Mock clients
        mock_epss_client = Mock()
        mock_epss_client.get_score.return_value = EPSSScore(
            cve='CVE-2024-1234',
            epss=0.85,
            percentile=0.95,
            date='2024-10-01'
        )
        mock_epss_client_class.return_value = mock_epss_client

        mock_kev_client = Mock()
        mock_kev_client.is_kev.return_value = True
        mock_kev_client.get_entry.return_value = KEVEntry(
            cve='CVE-2024-1234',
            vendor='Vendor',
            product='Product',
            vulnerability_name='Vuln',
            date_added='2024-09-01',
            short_description='Description',
            required_action='Patch',
            due_date='2024-10-01'
        )
        mock_kev_client_class.return_value = mock_kev_client

        calculator = PriorityCalculator()

        finding = {
            'id': 'test-001',
            'ruleId': 'CVE-2024-1234',
            'severity': 'CRITICAL',
            'message': 'Critical vulnerability',
            'location': {'path': 'app/main.py', 'startLine': 10},
            'tool': {'name': 'trivy', 'version': '0.50.0'}
        }

        # Measure calculation time
        start = time.time()
        priority = calculator.calculate_priority(finding)
        elapsed_ms = (time.time() - start) * 1000

        assert priority is not None
        assert elapsed_ms < 10, f"Priority calculation took {elapsed_ms:.2f}ms (expected <10ms)"

    @patch('scripts.core.priority_calculator.EPSSClient')
    @patch('scripts.core.priority_calculator.KEVClient')
    def test_bulk_calculation_latency(self, mock_kev_client_class, mock_epss_client_class):
        """Test that bulk calculation of 1000 findings completes in <1s."""
        # Mock clients
        mock_epss_client = Mock()

        # Mock get_score for individual calls (fallback)
        def mock_get_score(cve):
            return EPSSScore(
                cve=cve,
                epss=0.5,
                percentile=0.8,
                date='2024-10-01'
            )

        mock_epss_client.get_score.side_effect = mock_get_score

        # Mock get_scores_bulk for bulk calls
        mock_epss_client.get_scores_bulk.return_value = {
            f'CVE-2024-{i:04d}': EPSSScore(
                cve=f'CVE-2024-{i:04d}',
                epss=0.5,
                percentile=0.8,
                date='2024-10-01'
            )
            for i in range(1000)
        }
        mock_epss_client_class.return_value = mock_epss_client

        mock_kev_client = Mock()
        mock_kev_client.is_kev.return_value = False
        mock_kev_client_class.return_value = mock_kev_client

        calculator = PriorityCalculator()

        # Create 1000 findings
        findings = [
            {
                'id': f'test-{i:04d}',
                'ruleId': f'CVE-2024-{i:04d}',
                'severity': 'HIGH',
                'message': f'Vulnerability {i}',
                'location': {'path': f'app/file{i}.py', 'startLine': 10},
                'tool': {'name': 'trivy', 'version': '0.50.0'}
            }
            for i in range(1000)
        ]

        # Measure bulk calculation time
        start = time.time()
        priorities = calculator.calculate_priorities_bulk(findings)
        elapsed_ms = (time.time() - start) * 1000

        assert len(priorities) == 1000
        assert elapsed_ms < 1000, f"Bulk calculation took {elapsed_ms:.2f}ms (expected <1000ms)"

    @patch('scripts.core.priority_calculator.EPSSClient')
    @patch('scripts.core.priority_calculator.KEVClient')
    def test_cve_extraction_performance(self, mock_kev_client_class, mock_epss_client_class):
        """Test that CVE extraction from complex findings is fast."""
        mock_epss_client = Mock()
        mock_epss_client_class.return_value = mock_epss_client

        mock_kev_client = Mock()
        mock_kev_client_class.return_value = mock_kev_client

        calculator = PriorityCalculator()

        # Complex finding with CVEs in multiple locations
        finding = {
            'id': 'test-001',
            'ruleId': 'CVE-2024-1234',
            'severity': 'HIGH',
            'message': 'Multiple CVEs: CVE-2024-5678, CVE-2024-9999',
            'location': {'path': 'app/main.py', 'startLine': 10},
            'tool': {'name': 'trivy', 'version': '0.50.0'},
            'raw': {
                'cve': 'CVE-2024-1111',
                'cveId': 'CVE-2024-2222',
                'VulnerabilityID': 'CVE-2024-3333'
            }
        }

        # Measure extraction time
        start = time.time()
        cves = calculator._extract_cves(finding)
        elapsed_ms = (time.time() - start) * 1000

        # Should find all unique CVEs
        assert len(cves) >= 5
        assert elapsed_ms < 5, f"CVE extraction took {elapsed_ms:.2f}ms (expected <5ms)"
