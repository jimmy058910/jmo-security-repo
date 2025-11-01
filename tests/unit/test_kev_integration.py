"""
Unit tests for CISA KEV integration.

Tests KEVClient functionality including:
- Catalog downloading and parsing
- JSON caching
- Cache TTL validation
- KEV lookup operations
- Error handling
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests

from scripts.core.kev_integration import KEVClient, KEVEntry


@pytest.fixture
def temp_cache_dir(tmp_path):
    """Create temporary cache directory for testing."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return cache_dir


@pytest.fixture
def kev_client(temp_cache_dir):
    """Create KEVClient with temporary cache."""
    with patch("requests.get"):
        # Prevent automatic download during init
        client = KEVClient.__new__(KEVClient)
        client.cache_path = temp_cache_dir / "kev_catalog.json"
        client.catalog = {}
        return client


@pytest.fixture
def mock_kev_catalog():
    """Mock CISA KEV catalog data."""
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2024.10.01",
        "dateReleased": "2024-10-01T00:00:00.000Z",
        "count": 3,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "Example Vendor",
                "product": "Example Product",
                "vulnerabilityName": "Example Vulnerability",
                "dateAdded": "2024-09-15",
                "shortDescription": "Example vulnerability actively exploited",
                "requiredAction": "Apply patches",
                "dueDate": "2024-10-15",
            },
            {
                "cveID": "CVE-2024-5678",
                "vendorProject": "Test Corp",
                "product": "Test App",
                "vulnerabilityName": "Critical RCE",
                "dateAdded": "2024-09-20",
                "shortDescription": "Remote code execution vulnerability",
                "requiredAction": "Update to latest version",
                "dueDate": "2024-10-20",
            },
            {
                "cveID": "CVE-2024-9999",
                "vendorProject": "Security Inc",
                "product": "Secure System",
                "vulnerabilityName": "SQL Injection",
                "dateAdded": "2024-09-25",
                "shortDescription": "SQL injection in authentication",
                "requiredAction": "Migrate to fixed version",
                "dueDate": "2024-10-25",
            },
        ],
    }


class TestKEVEntry:
    """Tests for KEVEntry dataclass."""

    def test_create_kev_entry(self):
        """Test creating KEVEntry object."""
        entry = KEVEntry(
            cve="CVE-2024-1234",
            vendor="Example Vendor",
            product="Example Product",
            vulnerability_name="Example Vulnerability",
            date_added="2024-09-15",
            short_description="Example vulnerability",
            required_action="Apply patches",
            due_date="2024-10-15",
        )

        assert entry.cve == "CVE-2024-1234"
        assert entry.vendor == "Example Vendor"
        assert entry.product == "Example Product"
        assert entry.vulnerability_name == "Example Vulnerability"
        assert entry.date_added == "2024-09-15"
        assert entry.short_description == "Example vulnerability"
        assert entry.required_action == "Apply patches"
        assert entry.due_date == "2024-10-15"

    def test_kev_entry_equality(self):
        """Test KEVEntry equality comparison."""
        entry1 = KEVEntry(
            cve="CVE-2024-1234",
            vendor="Example Vendor",
            product="Example Product",
            vulnerability_name="Example Vulnerability",
            date_added="2024-09-15",
            short_description="Example vulnerability",
            required_action="Apply patches",
            due_date="2024-10-15",
        )
        entry2 = KEVEntry(
            cve="CVE-2024-1234",
            vendor="Example Vendor",
            product="Example Product",
            vulnerability_name="Example Vulnerability",
            date_added="2024-09-15",
            short_description="Example vulnerability",
            required_action="Apply patches",
            due_date="2024-10-15",
        )

        assert entry1 == entry2


class TestKEVClient:
    """Tests for KEVClient."""

    @patch("requests.get")
    def test_download_catalog(self, mock_get, kev_client, mock_kev_catalog):
        """Test downloading KEV catalog from CISA."""
        mock_response = Mock()
        mock_response.json.return_value = mock_kev_catalog
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        kev_client._download_catalog()

        assert len(kev_client.catalog) == 3
        assert "CVE-2024-1234" in kev_client.catalog
        assert "CVE-2024-5678" in kev_client.catalog
        assert "CVE-2024-9999" in kev_client.catalog

        # Verify cache file created
        assert kev_client.cache_path.exists()

    def test_parse_catalog(self, kev_client, mock_kev_catalog):
        """Test parsing KEV catalog JSON."""
        catalog = kev_client._parse_catalog(mock_kev_catalog)

        assert len(catalog) == 3
        assert "CVE-2024-1234" in catalog
        assert catalog["CVE-2024-1234"].vendor == "Example Vendor"
        assert catalog["CVE-2024-1234"].product == "Example Product"
        assert catalog["CVE-2024-1234"].vulnerability_name == "Example Vulnerability"

    def test_load_catalog_from_cache(self, temp_cache_dir, mock_kev_catalog):
        """Test loading catalog from cache instead of downloading."""
        # Create cache file
        cache_path = temp_cache_dir / "kev_catalog.json"
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(mock_kev_catalog, f)

        with patch("requests.get") as mock_get:
            # Should not call API if cache is valid
            client = KEVClient(cache_dir=temp_cache_dir)

            assert len(client.catalog) == 3
            mock_get.assert_not_called()

    @patch("requests.get")
    def test_load_catalog_cache_expired(
        self, mock_get, temp_cache_dir, mock_kev_catalog
    ):
        """Test that expired cache triggers download."""
        # Create cache file with old timestamp
        cache_path = temp_cache_dir / "kev_catalog.json"
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(mock_kev_catalog, f)

        # Set file modification time to 2 days ago (cache TTL is 1 day)
        old_time = (datetime.now() - timedelta(days=2)).timestamp()
        cache_path.touch()
        import os

        os.utime(cache_path, (old_time, old_time))

        mock_response = Mock()
        mock_response.json.return_value = mock_kev_catalog
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        # Should trigger download due to expired cache
        _ = KEVClient(cache_dir=temp_cache_dir)

        mock_get.assert_called_once()

    def test_is_kev_true(self, kev_client, mock_kev_catalog):
        """Test is_kev returns True for CVE in catalog."""
        kev_client.catalog = kev_client._parse_catalog(mock_kev_catalog)

        assert kev_client.is_kev("CVE-2024-1234") is True
        assert kev_client.is_kev("CVE-2024-5678") is True
        assert kev_client.is_kev("CVE-2024-9999") is True

    def test_is_kev_false(self, kev_client, mock_kev_catalog):
        """Test is_kev returns False for CVE not in catalog."""
        kev_client.catalog = kev_client._parse_catalog(mock_kev_catalog)

        assert kev_client.is_kev("CVE-9999-9999") is False
        assert kev_client.is_kev("CVE-2023-0000") is False

    def test_get_entry_exists(self, kev_client, mock_kev_catalog):
        """Test getting KEV entry for CVE in catalog."""
        kev_client.catalog = kev_client._parse_catalog(mock_kev_catalog)

        entry = kev_client.get_entry("CVE-2024-1234")

        assert entry is not None
        assert entry.cve == "CVE-2024-1234"
        assert entry.vendor == "Example Vendor"
        assert entry.product == "Example Product"
        assert entry.required_action == "Apply patches"
        assert entry.due_date == "2024-10-15"

    def test_get_entry_not_exists(self, kev_client, mock_kev_catalog):
        """Test getting KEV entry for CVE not in catalog."""
        kev_client.catalog = kev_client._parse_catalog(mock_kev_catalog)

        entry = kev_client.get_entry("CVE-9999-9999")

        assert entry is None

    def test_get_all_cves(self, kev_client, mock_kev_catalog):
        """Test getting all CVEs in catalog."""
        kev_client.catalog = kev_client._parse_catalog(mock_kev_catalog)

        cves = kev_client.get_all_cves()

        assert len(cves) == 3
        assert "CVE-2024-1234" in cves
        assert "CVE-2024-5678" in cves
        assert "CVE-2024-9999" in cves

    def test_get_catalog_metadata(self, kev_client, mock_kev_catalog):
        """Test getting catalog metadata."""
        # Write cache file
        with open(kev_client.cache_path, "w", encoding="utf-8") as f:
            json.dump(mock_kev_catalog, f)

        kev_client.catalog = kev_client._parse_catalog(mock_kev_catalog)
        metadata = kev_client.get_catalog_metadata()

        assert metadata["title"] == "CISA Catalog of Known Exploited Vulnerabilities"
        assert metadata["catalog_version"] == "2024.10.01"
        assert metadata["date_released"] == "2024-10-01T00:00:00.000Z"
        assert metadata["count"] == 3
        assert metadata["total_cves"] == 3

    def test_get_catalog_metadata_no_cache(self, kev_client):
        """Test getting metadata when cache doesn't exist."""
        metadata = kev_client.get_catalog_metadata()

        assert metadata == {}

    @patch("requests.get")
    def test_refresh_catalog(self, mock_get, kev_client, mock_kev_catalog):
        """Test forcing catalog refresh."""
        mock_response = Mock()
        mock_response.json.return_value = mock_kev_catalog
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        kev_client.refresh_catalog()

        assert len(kev_client.catalog) == 3
        mock_get.assert_called_once()

    @patch("requests.get")
    def test_download_catalog_api_error(self, mock_get, kev_client):
        """Test handling of API errors during download."""
        mock_get.side_effect = requests.exceptions.RequestException("API Error")

        # _download_catalog raises exception, _load_catalog catches it
        with pytest.raises(requests.exceptions.RequestException):
            kev_client._download_catalog()

    def test_load_catalog_invalid_json(self, temp_cache_dir, capsys):
        """Test handling of invalid JSON in cache file."""
        # Create cache file with invalid JSON
        cache_path = temp_cache_dir / "kev_catalog.json"
        with open(cache_path, "w", encoding="utf-8") as f:
            f.write("invalid json {]}")

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = {"vulnerabilities": []}
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            # Should fall back to downloading
            _ = KEVClient(cache_dir=temp_cache_dir)

            # Warning should be printed
            captured = capsys.readouterr()
            assert "Warning: Failed to load KEV cache" in captured.out

            # Should have attempted download
            mock_get.assert_called_once()

    def test_cache_persistence(self, temp_cache_dir, mock_kev_catalog):
        """Test that cache persists across client instances."""
        # Create cache file
        cache_path = temp_cache_dir / "kev_catalog.json"
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(mock_kev_catalog, f)

        with patch("requests.get") as mock_get:
            # First client instance
            client1 = KEVClient(cache_dir=temp_cache_dir)
            assert len(client1.catalog) == 3

            # Second client instance (should use cache)
            client2 = KEVClient(cache_dir=temp_cache_dir)
            assert len(client2.catalog) == 3

            # API should not be called (cache used)
            mock_get.assert_not_called()

    def test_default_cache_dir(self):
        """Test that default cache directory is ~/.jmo/cache."""
        with patch("requests.get"):
            client = KEVClient.__new__(KEVClient)
            client.cache_path = Path.home() / ".jmo" / "cache" / "kev_catalog.json"
            client.catalog = {}

            expected_cache_dir = Path.home() / ".jmo" / "cache"
            assert client.cache_path.parent == expected_cache_dir
            assert client.cache_path.name == "kev_catalog.json"

    def test_empty_catalog(self, kev_client):
        """Test behavior with empty catalog."""
        kev_client.catalog = kev_client._parse_catalog({"vulnerabilities": []})

        assert len(kev_client.catalog) == 0
        assert kev_client.is_kev("CVE-2024-1234") is False
        assert kev_client.get_entry("CVE-2024-1234") is None
        assert kev_client.get_all_cves() == []
