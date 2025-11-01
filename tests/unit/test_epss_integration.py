"""
Unit tests for EPSS integration.

Tests EPSSClient functionality including:
- API fetching (single and bulk)
- SQLite caching
- Cache TTL validation
- Error handling
"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests

from scripts.core.epss_integration import EPSSClient, EPSSScore


@pytest.fixture
def temp_cache_dir(tmp_path):
    """Create temporary cache directory for testing."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return cache_dir


@pytest.fixture
def epss_client(temp_cache_dir):
    """Create EPSSClient with temporary cache."""
    return EPSSClient(cache_dir=temp_cache_dir)


@pytest.fixture
def mock_epss_response():
    """Mock EPSS API response for a single CVE."""
    return {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "total": 1,
        "data": [
            {
                "cve": "CVE-2024-1234",
                "epss": "0.12345",
                "percentile": "0.85432",
                "date": "2024-10-01",
            }
        ],
    }


@pytest.fixture
def mock_epss_bulk_response():
    """Mock EPSS API response for multiple CVEs."""
    return {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "total": 3,
        "data": [
            {
                "cve": "CVE-2024-1234",
                "epss": "0.12345",
                "percentile": "0.85432",
                "date": "2024-10-01",
            },
            {
                "cve": "CVE-2024-5678",
                "epss": "0.95000",
                "percentile": "0.99999",
                "date": "2024-10-01",
            },
            {
                "cve": "CVE-2024-9999",
                "epss": "0.00100",
                "percentile": "0.10000",
                "date": "2024-10-01",
            },
        ],
    }


class TestEPSSScore:
    """Tests for EPSSScore dataclass."""

    def test_create_epss_score(self):
        """Test creating EPSSScore object."""
        score = EPSSScore(
            cve="CVE-2024-1234", epss=0.12345, percentile=0.85432, date="2024-10-01"
        )

        assert score.cve == "CVE-2024-1234"
        assert score.epss == 0.12345
        assert score.percentile == 0.85432
        assert score.date == "2024-10-01"

    def test_epss_score_equality(self):
        """Test EPSSScore equality comparison."""
        score1 = EPSSScore(
            cve="CVE-2024-1234", epss=0.12345, percentile=0.85432, date="2024-10-01"
        )
        score2 = EPSSScore(
            cve="CVE-2024-1234", epss=0.12345, percentile=0.85432, date="2024-10-01"
        )

        assert score1 == score2


class TestEPSSClient:
    """Tests for EPSSClient."""

    def test_init_creates_cache_directory(self, temp_cache_dir):
        """Test that client creates cache directory if it doesn't exist."""
        cache_dir = temp_cache_dir / "new_cache"
        client = EPSSClient(cache_dir=cache_dir)

        assert cache_dir.exists()
        assert client.cache_path.exists()

    def test_init_creates_database_table(self, epss_client):
        """Test that client creates SQLite table on initialization."""
        conn = sqlite3.connect(epss_client.cache_path)
        cursor = conn.cursor()

        # Check table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='epss_scores'"
        )
        result = cursor.fetchone()
        conn.close()

        assert result is not None

    @patch("requests.get")
    def test_get_score_from_api(self, mock_get, epss_client, mock_epss_response):
        """Test fetching score from API when not cached."""
        mock_response = Mock()
        mock_response.json.return_value = mock_epss_response
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        score = epss_client.get_score("CVE-2024-1234")

        assert score is not None
        assert score.cve == "CVE-2024-1234"
        assert score.epss == 0.12345
        assert score.percentile == 0.85432
        assert score.date == "2024-10-01"

        # Verify API was called
        mock_get.assert_called_once()
        assert "CVE-2024-1234" in mock_get.call_args[0][0]

    @patch("requests.get")
    def test_get_score_from_cache(self, mock_get, epss_client, mock_epss_response):
        """Test retrieving score from cache on second call."""
        mock_response = Mock()
        mock_response.json.return_value = mock_epss_response
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        # First call: fetch from API
        score1 = epss_client.get_score("CVE-2024-1234")

        # Second call: should use cache
        score2 = epss_client.get_score("CVE-2024-1234")

        assert score1 == score2

        # API should only be called once
        assert mock_get.call_count == 1

    @patch("requests.get")
    def test_get_score_not_found(self, mock_get, epss_client):
        """Test handling of CVE not found in API."""
        mock_response = Mock()
        mock_response.json.return_value = {"total": 0, "data": []}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        score = epss_client.get_score("CVE-9999-9999")

        assert score is None

    @patch("requests.get")
    def test_get_score_api_error(self, mock_get, epss_client, capsys):
        """Test handling of API errors."""
        mock_get.side_effect = requests.exceptions.RequestException("API Error")

        score = epss_client.get_score("CVE-2024-1234")

        assert score is None

        # Verify warning printed
        captured = capsys.readouterr()
        assert "Warning: Failed to fetch EPSS score" in captured.out

    @patch("requests.get")
    def test_get_scores_bulk(self, mock_get, epss_client, mock_epss_bulk_response):
        """Test bulk fetching of multiple scores."""
        mock_response = Mock()
        mock_response.json.return_value = mock_epss_bulk_response
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        cves = ["CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"]
        scores = epss_client.get_scores_bulk(cves)

        assert len(scores) == 3
        assert "CVE-2024-1234" in scores
        assert "CVE-2024-5678" in scores
        assert "CVE-2024-9999" in scores

        assert scores["CVE-2024-1234"].epss == 0.12345
        assert scores["CVE-2024-5678"].epss == 0.95000
        assert scores["CVE-2024-9999"].epss == 0.00100

        # Verify bulk API was called once
        mock_get.assert_called_once()

    @patch("requests.get")
    def test_get_scores_bulk_mixed_cache(
        self, mock_get, epss_client, mock_epss_response
    ):
        """Test bulk fetching with some scores already cached."""
        # Cache one score manually
        cached_score = EPSSScore(
            cve="CVE-2024-1234", epss=0.12345, percentile=0.85432, date="2024-10-01"
        )
        epss_client._cache_score(cached_score)

        # Mock API response for uncached scores
        mock_response = Mock()
        mock_response.json.return_value = {
            "total": 1,
            "data": [
                {
                    "cve": "CVE-2024-5678",
                    "epss": "0.95000",
                    "percentile": "0.99999",
                    "date": "2024-10-01",
                }
            ],
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        # Request both CVEs (one cached, one not)
        cves = ["CVE-2024-1234", "CVE-2024-5678"]
        scores = epss_client.get_scores_bulk(cves)

        assert len(scores) == 2
        assert "CVE-2024-1234" in scores
        assert "CVE-2024-5678" in scores

        # Only uncached CVE should be fetched from API
        mock_get.assert_called_once()
        assert "CVE-2024-5678" in mock_get.call_args[0][0]

    def test_cache_ttl_validation(self, epss_client):
        """Test cache TTL expiration."""
        score = EPSSScore(
            cve="CVE-2024-1234", epss=0.12345, percentile=0.85432, date="2024-10-01"
        )

        # Cache score
        epss_client._cache_score(score)

        # Should be valid immediately
        assert epss_client._is_cache_valid(score)

        # Manually expire cache by updating cached_at timestamp
        conn = sqlite3.connect(epss_client.cache_path)
        cursor = conn.cursor()

        expired_time = datetime.now() - timedelta(days=8)  # 8 days ago (TTL is 7 days)
        cursor.execute(
            "UPDATE epss_scores SET cached_at = ? WHERE cve = ?",
            (expired_time.isoformat(), score.cve),
        )
        conn.commit()
        conn.close()

        # Should be invalid after expiration
        assert not epss_client._is_cache_valid(score)

    @patch("requests.get")
    def test_cache_ttl_triggers_refresh(
        self, mock_get, epss_client, mock_epss_response
    ):
        """Test that expired cache triggers API refresh."""
        # Cache score with expired timestamp
        score = EPSSScore(
            cve="CVE-2024-1234", epss=0.12345, percentile=0.85432, date="2024-10-01"
        )
        epss_client._cache_score(score)

        # Manually expire cache
        conn = sqlite3.connect(epss_client.cache_path)
        cursor = conn.cursor()
        expired_time = datetime.now() - timedelta(days=8)
        cursor.execute(
            "UPDATE epss_scores SET cached_at = ? WHERE cve = ?",
            (expired_time.isoformat(), score.cve),
        )
        conn.commit()
        conn.close()

        # Mock API response
        mock_response = Mock()
        mock_response.json.return_value = mock_epss_response
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        # Get score (should trigger API call due to expired cache)
        refreshed_score = epss_client.get_score("CVE-2024-1234")

        assert refreshed_score is not None
        mock_get.assert_called_once()

    def test_cache_persistence(self, temp_cache_dir, mock_epss_response):
        """Test that cache persists across client instances."""
        # Create first client and cache a score
        client1 = EPSSClient(cache_dir=temp_cache_dir)

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = mock_epss_response
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            score1 = client1.get_score("CVE-2024-1234")

        # Create second client (new instance, same cache)
        client2 = EPSSClient(cache_dir=temp_cache_dir)

        with patch("requests.get") as mock_get2:
            score2 = client2.get_score("CVE-2024-1234")

            # Should use cache, not call API
            mock_get2.assert_not_called()

        assert score1 == score2

    @patch("requests.get")
    def test_get_scores_bulk_api_error(self, mock_get, epss_client, capsys):
        """Test handling of bulk API errors."""
        mock_get.side_effect = requests.exceptions.RequestException("Bulk API Error")

        cves = ["CVE-2024-1234", "CVE-2024-5678"]
        scores = epss_client.get_scores_bulk(cves)

        assert len(scores) == 0

        # Verify warning printed
        captured = capsys.readouterr()
        assert "Warning: Failed to fetch bulk EPSS scores" in captured.out

    def test_default_cache_dir(self):
        """Test that default cache directory is ~/.jmo/cache."""
        client = EPSSClient()

        expected_cache_dir = Path.home() / ".jmo" / "cache"
        assert client.cache_path.parent == expected_cache_dir
        assert client.cache_path.name == "epss_scores.db"
