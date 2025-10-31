"""
CISA KEV (Known Exploited Vulnerabilities) Integration.

Integrates with CISA's KEV catalog to identify CVEs that are actively exploited
in the wild. Uses JSON caching with daily refresh to stay current.

KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import requests


@dataclass
class KEVEntry:
    """CISA KEV catalog entry.

    Attributes:
        cve: CVE identifier (e.g., "CVE-2024-1234")
        vendor: Vendor/project name
        product: Product name
        vulnerability_name: Short descriptive name
        date_added: Date added to KEV catalog (YYYY-MM-DD)
        short_description: Brief description of vulnerability
        required_action: Required action for federal agencies
        due_date: Remediation due date for federal agencies (YYYY-MM-DD)
    """
    cve: str
    vendor: str
    product: str
    vulnerability_name: str
    date_added: str  # YYYY-MM-DD
    short_description: str
    required_action: str
    due_date: str  # YYYY-MM-DD (for federal agencies)


class KEVClient:
    """Client for CISA KEV catalog with daily caching.

    Provides access to CISA's Known Exploited Vulnerabilities catalog with
    automatic daily refresh. Cache is stored as JSON file.

    Example:
        >>> client = KEVClient()
        >>> if client.is_kev("CVE-2024-1234"):
        ...     entry = client.get_entry("CVE-2024-1234")
        ...     print(f"Active exploit! Required action: {entry.required_action}")
    """

    CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_TTL_DAYS = 1  # Refresh daily

    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize KEV client.

        Args:
            cache_dir: Directory for JSON cache. Defaults to ~/.jmo/cache
        """
        if cache_dir is None:
            cache_dir = Path.home() / ".jmo" / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)

        self.cache_path = cache_dir / "kev_catalog.json"
        self.catalog: Dict[str, KEVEntry] = {}
        self._load_catalog()

    def _load_catalog(self):
        """Load KEV catalog (cache first, then download)."""
        # Check cache
        if self.cache_path.exists() and self._is_cache_valid():
            try:
                with open(self.cache_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.catalog = self._parse_catalog(data)
                    return
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Failed to load KEV cache: {e}")
                # Fall through to download fresh catalog

        # Download fresh catalog
        try:
            self._download_catalog()
        except Exception as e:
            print(f"Warning: Failed to download KEV catalog: {e}")

    def _download_catalog(self):
        """Download KEV catalog from CISA."""
        response = requests.get(self.CATALOG_URL, timeout=30)
        response.raise_for_status()

        data = response.json()

        # Cache catalog
        with open(self.cache_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        self.catalog = self._parse_catalog(data)

    def _parse_catalog(self, data: dict) -> Dict[str, KEVEntry]:
        """Parse KEV catalog JSON.

        Args:
            data: KEV catalog JSON data

        Returns:
            Dictionary mapping CVE IDs to KEVEntry objects
        """
        catalog = {}

        for vuln in data.get('vulnerabilities', []):
            entry = KEVEntry(
                cve=vuln['cveID'],
                vendor=vuln['vendorProject'],
                product=vuln['product'],
                vulnerability_name=vuln['vulnerabilityName'],
                date_added=vuln['dateAdded'],
                short_description=vuln['shortDescription'],
                required_action=vuln['requiredAction'],
                due_date=vuln.get('dueDate', '')
            )
            catalog[entry.cve] = entry

        return catalog

    def is_kev(self, cve: str) -> bool:
        """Check if CVE is in KEV catalog.

        Args:
            cve: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            True if CVE is in KEV catalog (actively exploited), False otherwise
        """
        return cve in self.catalog

    def get_entry(self, cve: str) -> Optional[KEVEntry]:
        """Get KEV entry for CVE.

        Args:
            cve: CVE identifier

        Returns:
            KEVEntry object or None if not in catalog
        """
        return self.catalog.get(cve)

    def get_all_cves(self) -> List[str]:
        """Get all CVEs in KEV catalog.

        Returns:
            List of CVE identifiers
        """
        return list(self.catalog.keys())

    def get_catalog_metadata(self) -> dict:
        """Get KEV catalog metadata.

        Returns:
            Dictionary with catalog metadata (title, version, count, etc.)
        """
        if not self.cache_path.exists():
            return {}

        try:
            with open(self.cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return {
                    'title': data.get('title', ''),
                    'catalog_version': data.get('catalogVersion', ''),
                    'date_released': data.get('dateReleased', ''),
                    'count': data.get('count', 0),
                    'total_cves': len(self.catalog)
                }
        except (json.JSONDecodeError, IOError):
            return {}

    def refresh_catalog(self):
        """Force refresh of KEV catalog regardless of cache TTL.

        Useful for ensuring catalog is up-to-date before important operations.
        """
        try:
            self._download_catalog()
        except Exception as e:
            print(f"Warning: Failed to refresh KEV catalog: {e}")

    def _is_cache_valid(self) -> bool:
        """Check if cached catalog is still valid (within TTL).

        Returns:
            True if cache is valid, False otherwise
        """
        if not self.cache_path.exists():
            return False

        cached_at = datetime.fromtimestamp(self.cache_path.stat().st_mtime)
        ttl = timedelta(days=self.CACHE_TTL_DAYS)

        return datetime.now() - cached_at < ttl
