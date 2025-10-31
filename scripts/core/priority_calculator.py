"""
Priority Calculator for Security Findings.

Calculates priority scores for findings based on:
- Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- EPSS (Exploit Prediction Scoring System) probability
- CISA KEV (Known Exploited Vulnerabilities) status
- Future: Code reachability analysis

Priority formula combines real-world exploit data with severity to focus
on actual threats instead of theoretical vulnerabilities.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from scripts.core.epss_integration import EPSSClient
from scripts.core.kev_integration import KEVClient


@dataclass
class PriorityScore:
    """Calculated priority score for a finding.

    Attributes:
        finding_id: Unique finding identifier
        priority: Priority score (0-100, higher = more urgent)
        severity: Original severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        epss: EPSS exploit probability (0.0-1.0) if available
        epss_percentile: EPSS percentile (0.0-1.0) if available
        is_kev: Whether CVE is in CISA KEV catalog
        kev_due_date: Remediation due date if in KEV catalog
        components: Breakdown of score components for transparency
    """
    finding_id: str
    priority: float  # 0-100
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    epss: Optional[float] = None  # 0.0-1.0
    epss_percentile: Optional[float] = None
    is_kev: bool = False
    kev_due_date: Optional[str] = None
    components: Dict[str, float] = field(default_factory=dict)  # Breakdown of score components


class PriorityCalculator:
    """Calculate priority scores for findings.

    Uses EPSS and KEV data to enhance traditional severity-based prioritization
    with real-world exploit intelligence.

    Example:
        >>> calculator = PriorityCalculator()
        >>> finding = {"id": "f1", "severity": "HIGH", "ruleId": "CVE-2024-1234"}
        >>> priority = calculator.calculate_priority(finding)
        >>> if priority.is_kev:
        ...     print(f"URGENT: KEV exploit! Priority: {priority.priority:.1f}/100")
    """

    def __init__(self, cache_dir: Optional[str] = None):
        """Initialize priority calculator.

        Args:
            cache_dir: Optional cache directory for EPSS/KEV data
        """
        from pathlib import Path
        cache_path = Path(cache_dir) if cache_dir else None

        self.epss_client = EPSSClient(cache_dir=cache_path)
        self.kev_client = KEVClient(cache_dir=cache_path)

    def calculate_priority(self, finding: Dict) -> PriorityScore:
        """Calculate priority score for a finding.

        Formula:
          severity_score = {CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 2, INFO: 1}
          epss_multiplier = 1.0 + (epss_score * 4.0)  # Scale 0.0-1.0 → 1.0-5.0
          kev_multiplier = 3.0 if is_kev else 1.0
          reachability_multiplier = 1.0  # Placeholder for future

          priority = (severity_score × epss_multiplier × kev_multiplier × reachability_multiplier) / 1.5
          # Normalized to 0-100 scale

        Args:
            finding: Finding dictionary with 'id', 'severity', and optional CVE data

        Returns:
            PriorityScore object with calculated priority and components
        """
        # Base severity score
        severity_scores = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2,
            'INFO': 1
        }
        severity_score = severity_scores.get(finding.get('severity', 'MEDIUM'), 4)

        # Extract CVE IDs
        cves = self._extract_cves(finding)

        # Get EPSS scores
        epss_score = None
        epss_percentile = None
        if cves:
            epss_data = self.epss_client.get_score(cves[0])  # Use first CVE
            if epss_data:
                epss_score = epss_data.epss
                epss_percentile = epss_data.percentile

        # Check KEV
        is_kev = False
        kev_due_date = None
        if cves:
            for cve in cves:
                if self.kev_client.is_kev(cve):
                    is_kev = True
                    kev_entry = self.kev_client.get_entry(cve)
                    kev_due_date = kev_entry.due_date if kev_entry else None
                    break

        # Calculate multipliers
        epss_multiplier = 1.0 + (epss_score * 4.0) if epss_score else 1.0
        kev_multiplier = 3.0 if is_kev else 1.0
        reachability_multiplier = 1.0  # Future: code reachability analysis

        # Calculate priority
        raw_priority = (
            severity_score *
            epss_multiplier *
            kev_multiplier *
            reachability_multiplier
        ) / 1.5

        # Normalize to 0-100 scale
        priority = min(100.0, raw_priority * 5.0)

        return PriorityScore(
            finding_id=finding['id'],
            priority=priority,
            severity=finding.get('severity', 'MEDIUM'),
            epss=epss_score,
            epss_percentile=epss_percentile,
            is_kev=is_kev,
            kev_due_date=kev_due_date,
            components={
                'severity_score': severity_score,
                'epss_multiplier': epss_multiplier,
                'kev_multiplier': kev_multiplier,
                'reachability_multiplier': reachability_multiplier,
            }
        )

    def calculate_priorities_bulk(self, findings: List[Dict]) -> Dict[str, PriorityScore]:
        """Calculate priorities for multiple findings (bulk).

        Uses bulk EPSS API to reduce API calls when processing many findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary mapping finding IDs to PriorityScore objects
        """
        # Extract all CVEs from findings
        all_cves = []
        finding_cves = {}
        for finding in findings:
            cves = self._extract_cves(finding)
            all_cves.extend(cves)
            finding_cves[finding['id']] = cves

        # Bulk fetch EPSS scores (reduces API calls)
        epss_scores = self.epss_client.get_scores_bulk(list(set(all_cves)))

        # Calculate priorities
        priorities = {}
        for finding in findings:
            priority = self.calculate_priority(finding)
            priorities[finding['id']] = priority

        return priorities

    def _extract_cves(self, finding: Dict) -> List[str]:
        """Extract CVE IDs from finding.

        Looks for CVEs in multiple locations:
        - ruleId field (e.g., "CVE-2024-1234")
        - raw.cve field (tool-specific)
        - message field (regex extraction)

        Args:
            finding: Finding dictionary

        Returns:
            List of CVE identifiers
        """
        cves = []

        # Check raw field
        if 'raw' in finding and isinstance(finding['raw'], dict):
            raw = finding['raw']

            # Common CVE field names
            cve_fields = ['cve', 'cveId', 'cve_id', 'CVE', 'vulnerabilityID', 'VulnerabilityID']
            for field_name in cve_fields:
                if field_name in raw:
                    cve_value = raw[field_name]
                    if isinstance(cve_value, str) and cve_value.startswith('CVE-'):
                        cves.append(cve_value)
                    elif isinstance(cve_value, list):
                        cves.extend([c for c in cve_value if isinstance(c, str) and c.startswith('CVE-')])

        # Check ruleId (some tools use CVE as rule ID)
        rule_id = finding.get('ruleId', '')
        if isinstance(rule_id, str) and rule_id.startswith('CVE-'):
            cves.append(rule_id)

        # Check message for CVE references
        message = finding.get('message', '')
        if isinstance(message, str):
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cves.extend(re.findall(cve_pattern, message))

        return list(set(cves))  # Deduplicate
