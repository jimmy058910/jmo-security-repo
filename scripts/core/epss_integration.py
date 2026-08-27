"""
EPSS (Exploit Prediction Scoring System) Integration.

Integrates with FIRST.org EPSS API to provide exploit probability data for CVEs.
Uses SQLite caching with 7-day TTL to reduce API calls and improve performance.

API Documentation: https://www.first.org/epss/api
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


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

    # A CVE EPSS has no score for is remembered too, on its own shorter TTL
    # (#849). Without this, `_fetch_from_api` returned None on `total == 0` and
    # `_cache_score` was only reached on a hit, so every unknown CVE produced a
    # fresh HTTP request on every report run, forever. Measured with EPSS
    # answering "I know none of these": 2000 distinct CVEs produced 2000
    # sequential individual GETs at timeout=10 each, after the bulk call.
    #
    # Shorter than the positive TTL because "not scored yet" is a temporary
    # state -- EPSS publishes new CVEs daily, so a negative answer should be
    # rechecked sooner than a positive one is refreshed.
    NEGATIVE_CACHE_TTL_DAYS = 1

    # Keeps the bulk query string under the ~2000-char practical limit (common
    # server limits are 4-8 KB, and 2048 is the conservative bound). At 2000
    # CVEs the unchunked URL measured **28,038 characters**. Past the limit the
    # bulk call fails, `except Exception` logs a warning, and every finding
    # falls through to the individual path -- so the failure mode of an
    # unbounded URL is the request storm above, at full scale.
    BULK_CHUNK_SIZE = 100

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

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS epss_scores (
                cve TEXT PRIMARY KEY,
                epss REAL,
                percentile REAL,
                date TEXT,
                cached_at TEXT
            )
        """)

        # Added for negative caching (#849). Existing caches on disk predate
        # it, so the column is added in place rather than by recreating the
        # table -- a user's warm cache is not worth discarding for this.
        cursor.execute("PRAGMA table_info(epss_scores)")
        if "found" not in {row[1] for row in cursor.fetchall()}:
            cursor.execute(
                "ALTER TABLE epss_scores ADD COLUMN found INTEGER NOT NULL DEFAULT 1"
            )

        conn.commit()
        conn.close()

    def _lookup(self, cve: str) -> tuple[bool, EPSSScore | None]:
        """One query, one connection: `(cache_answered, score)`.

        Replaces the `_get_cached_score` + `_is_cache_valid` pair, which each
        opened their own `sqlite3.connect` and each re-read the same row -- two
        connections per lookup, measured at 100 for 50 CVEs (#849).

        `cache_answered` is True for a valid **negative** entry too, where
        `score` is None. That distinction is the whole point: "we asked and EPSS
        does not know" and "we have not asked" are different states, and
        collapsing them is what produced one HTTP request per finding per run.
        """
        conn = sqlite3.connect(self.cache_path)
        try:
            row = conn.execute(
                "SELECT epss, percentile, date, cached_at, found "
                "FROM epss_scores WHERE cve = ?",
                (cve,),
            ).fetchone()
        finally:
            conn.close()

        if not row:
            return (False, None)

        epss, percentile, date, cached_at, found = row
        try:
            age = datetime.now() - datetime.fromisoformat(cached_at)
        except (TypeError, ValueError):
            return (False, None)

        ttl_days = self.CACHE_TTL_DAYS if found else self.NEGATIVE_CACHE_TTL_DAYS
        if age >= timedelta(days=ttl_days):
            return (False, None)

        if not found:
            return (True, None)
        return (True, EPSSScore(cve=cve, epss=epss, percentile=percentile, date=date))

    def get_score(self, cve: str) -> EPSSScore | None:
        """Get EPSS score for a CVE (cache first, then API).

        Args:
            cve: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            EPSSScore object or None if not found
        """
        answered, cached = self._lookup(cve)
        if answered:
            return cached

        # Fetch from API
        try:
            score = self._fetch_from_api(cve)
            if score:
                self._cache_score(score)
                return score
            # Remember the miss, so an unknown CVE is asked about once per TTL
            # rather than once per finding per run (#849).
            self._cache_miss(cve)
        except (
            Exception
        ) as e:  # Acceptable: EPSS API is optional enrichment — graceful degradation
            # Deliberately NOT cached: a network failure is not evidence that
            # EPSS lacks a score, and remembering it as one would suppress the
            # real answer for a whole TTL.
            logger.warning("Failed to fetch EPSS score for %s: %s", cve, e)

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
            answered, cached = self._lookup(cve)
            if answered:
                if cached:
                    scores[cve] = cached
                # A valid negative entry answers the question without a
                # request, and without occupying a slot in `scores`.
                continue
            uncached_cves.append(cve)

        # Fetch uncached from API (bulk request)
        if uncached_cves:
            try:
                bulk_scores = self._fetch_bulk_from_api(uncached_cves)
                for cve, score in bulk_scores.items():
                    self._cache_score(score)
                    scores[cve] = score
                # Every CVE we asked about and did not get back is one EPSS
                # does not score. Recording that is what stops the per-finding
                # request storm on the next pass (#849). Written in one
                # transaction rather than one connection each -- at 2000
                # unknown CVEs that is 1 connection instead of 2000.
                self._cache_misses(
                    [cve for cve in uncached_cves if cve not in bulk_scores]
                )
            except (
                Exception
            ) as e:  # Acceptable: bulk EPSS fetch is optional enrichment — graceful degradation
                logger.warning("Failed to fetch bulk EPSS scores: %s", e)

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
        # EPSS API accepts a comma-separated CVE list in a GET request, but the
        # query string is not unbounded. Joining every CVE into one URL measured
        # **28,038 characters at 2000 CVEs** against a conservative practical
        # limit of 2048 (#849), and past the limit the whole bulk call fails --
        # dropping every finding onto the one-request-each path.
        scores = {}
        for start in range(0, len(cves), self.BULK_CHUNK_SIZE):
            chunk = cves[start : start + self.BULK_CHUNK_SIZE]
            response = requests.get(f"{self.API_URL}?cve={','.join(chunk)}", timeout=30)
            response.raise_for_status()

            for entry in response.json().get("data", []):
                score = EPSSScore(
                    cve=entry["cve"],
                    epss=float(entry["epss"]),
                    percentile=float(entry["percentile"]),
                    date=entry["date"],
                )
                scores[score.cve] = score

        return scores

    def _cache_miss(self, cve: str) -> None:
        """Remember that EPSS has no score for this CVE (#849).

        Stored as a row with `found = 0`, so `_lookup` can tell "asked, no
        score" from "never asked" and only re-ask once its shorter TTL expires.
        """
        self._cache_misses([cve])

    def _cache_misses(self, cves: list[str]) -> None:
        """Record several misses in one connection and one transaction."""
        if not cves:
            return
        now = datetime.now().isoformat()
        conn = sqlite3.connect(self.cache_path)
        try:
            conn.executemany(
                "INSERT OR REPLACE INTO epss_scores "
                "(cve, epss, percentile, date, cached_at, found) "
                "VALUES (?, NULL, NULL, NULL, ?, 0)",
                [(cve, now) for cve in cves],
            )
            conn.commit()
        finally:
            conn.close()

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
            INSERT OR REPLACE INTO epss_scores
                (cve, epss, percentile, date, cached_at, found)
            VALUES (?, ?, ?, ?, ?, 1)
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
