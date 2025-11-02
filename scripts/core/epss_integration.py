"""
EPSS (Exploit Prediction Scoring System) Integration.

Integrates with FIRST.org EPSS API to provide exploit probability data for CVEs.
Uses SQLite caching with 7-day TTL to reduce API calls and improve performance.

API Documentation: https://www.first.org/epss/api
"""

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import requests


@dataclass
class EPSSScore:
    """EPSS score for a CVE.

    Attributes:
        cve: CVE identifier (e.g., "CVE-2024-1234")
        epss: Probability of exploit in next 30 days (0.0-1.0)
        percentile: Percentile among all CVEs (0.0-1.0)
        date: Score date in YYYY-MM-DD format
    """

    cve: str
    epss: float  # 0.0 - 1.0 (probability of exploit in next 30 days)
    percentile: float  # 0.0 - 1.0 (percentile among all CVEs)
    date: str  # Score date (YYYY-MM-DD)


class EPSSClient:
    """Client for EPSS API with SQLite caching.

    Provides access to EPSS exploit probability scores with automatic caching
    to reduce API calls. Cache has 7-day TTL and is stored in SQLite database.

    Example:
        >>> client = EPSSClient()
        >>> score = client.get_score("CVE-2024-1234")
        >>> if score and score.epss > 0.5:
        ...     print(f"High exploit probability: {score.epss:.2%}")
    """

    API_URL = "https://api.first.org/data/v1/epss"
    CACHE_TTL_DAYS = 7

    def __init__(self, cache_dir: Path | None = None):
        """Initialize EPSS client.

        Args:
            cache_dir: Directory for SQLite cache. Defaults to ~/.jmo/cache
        """
        if cache_dir is None:
            cache_dir = Path.home() / ".jmo" / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)

        self.cache_path = cache_dir / "epss_scores.db"
        self._init_cache()

    def _init_cache(self):
        """Initialize SQLite cache database."""
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS epss_scores (
                cve TEXT PRIMARY KEY,
                epss REAL,
                percentile REAL,
                date TEXT,
                cached_at TEXT
            )
        """
        )

        conn.commit()
        conn.close()

    def get_score(self, cve: str) -> EPSSScore | None:
        """Get EPSS score for a CVE (cache first, then API).

        Args:
            cve: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            EPSSScore object or None if not found
        """
        # Check cache first
        cached = self._get_cached_score(cve)
        if cached and self._is_cache_valid(cached):
            return cached

        # Fetch from API
        try:
            score = self._fetch_from_api(cve)
            if score:
                self._cache_score(score)
                return score
        except Exception as e:
            print(f"Warning: Failed to fetch EPSS score for {cve}: {e}")

        return None

    def get_scores_bulk(self, cves: list[str]) -> dict[str, EPSSScore]:
        """Get EPSS scores for multiple CVEs (bulk API call).

        Uses bulk API endpoint to fetch scores for multiple CVEs in a single
        request, reducing API calls and improving performance.

        Args:
            cves: List of CVE identifiers

        Returns:
            Dictionary mapping CVE IDs to EPSSScore objects
        """
        scores = {}

        # Check cache first
        uncached_cves = []
        for cve in cves:
            cached = self._get_cached_score(cve)
            if cached and self._is_cache_valid(cached):
                scores[cve] = cached
            else:
                uncached_cves.append(cve)

        # Fetch uncached from API (bulk request)
        if uncached_cves:
            try:
                bulk_scores = self._fetch_bulk_from_api(uncached_cves)
                for cve, score in bulk_scores.items():
                    self._cache_score(score)
                    scores[cve] = score
            except Exception as e:
                print(f"Warning: Failed to fetch bulk EPSS scores: {e}")

        return scores

    def _fetch_from_api(self, cve: str) -> EPSSScore | None:
        """Fetch EPSS score from API.

        Args:
            cve: CVE identifier

        Returns:
            EPSSScore object or None if not found
        """
        response = requests.get(f"{self.API_URL}?cve={cve}", timeout=10)
        response.raise_for_status()

        data = response.json()
        if data.get("total", 0) == 0:
            return None

        entry = data["data"][0]
        return EPSSScore(
            cve=entry["cve"],
            epss=float(entry["epss"]),
            percentile=float(entry["percentile"]),
            date=entry["date"],
        )

    def _fetch_bulk_from_api(self, cves: list[str]) -> dict[str, EPSSScore]:
        """Fetch multiple EPSS scores from API.

        EPSS API supports bulk queries by passing comma-separated CVE list.

        Args:
            cves: List of CVE identifiers

        Returns:
            Dictionary mapping CVE IDs to EPSSScore objects
        """
        # EPSS API accepts comma-separated CVE list in GET request
        cve_list = ",".join(cves)
        response = requests.get(f"{self.API_URL}?cve={cve_list}", timeout=30)
        response.raise_for_status()

        data = response.json()
        scores = {}

        for entry in data.get("data", []):
            score = EPSSScore(
                cve=entry["cve"],
                epss=float(entry["epss"]),
                percentile=float(entry["percentile"]),
                date=entry["date"],
            )
            scores[score.cve] = score

        return scores

    def _get_cached_score(self, cve: str) -> EPSSScore | None:
        """Get score from SQLite cache.

        Args:
            cve: CVE identifier

        Returns:
            EPSSScore object or None if not cached
        """
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT epss, percentile, date, cached_at FROM epss_scores WHERE cve = ?",
            (cve,),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return EPSSScore(cve=cve, epss=row[0], percentile=row[1], date=row[2])

    def _cache_score(self, score: EPSSScore):
        """Cache score in SQLite.

        Args:
            score: EPSSScore object to cache
        """
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO epss_scores (cve, epss, percentile, date, cached_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                score.cve,
                score.epss,
                score.percentile,
                score.date,
                datetime.now().isoformat(),
            ),
        )

        conn.commit()
        conn.close()

    def _is_cache_valid(self, score: EPSSScore) -> bool:
        """Check if cached score is still valid (within TTL).

        Args:
            score: EPSSScore object to validate

        Returns:
            True if cache is valid, False otherwise
        """
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.cursor()

        cursor.execute("SELECT cached_at FROM epss_scores WHERE cve = ?", (score.cve,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return False

        cached_at = datetime.fromisoformat(row[0])
        ttl = timedelta(days=self.CACHE_TTL_DAYS)

        return datetime.now() - cached_at < ttl
