"""Cross-tool deduplication using similarity-based clustering.

This module implements Phase 2 of the deduplication strategy:
- Phase 1 (existing): Fingerprint-based exact deduplication (same tool, same location)
- Phase 2 (this module): Similarity-based clustering across tools

Algorithm:
    1. Calculate multi-dimensional similarity (location, message, metadata)
    2. Cluster findings using greedy single-pass algorithm
    3. Generate consensus findings with detected_by arrays

Performance:
    - Time: O(n×k) where k = avg cluster size (~3-5)
    - Space: O(n)
    - Target: <2 seconds for 1000 findings

Author: JMo Security
Version: 1.0.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

# Import rapidfuzz for fast fuzzy string matching
try:
    from rapidfuzz import fuzz
except ImportError:
    # Fallback to simple ratio calculation if rapidfuzz not available
    fuzz = None  # type: ignore

from scripts.core.common_finding import Severity


@dataclass
class FindingCluster:
    """Cluster of similar findings from different tools.

    Attributes:
        representative: Primary finding (highest severity in cluster)
        findings: All findings in this cluster
        similarity_scores: Mapping of finding ID to similarity score

    """

    representative: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)
    similarity_scores: dict[str, float] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize cluster with representative as first finding."""
        if not self.findings:
            self.findings = [self.representative]
            self.similarity_scores[self.representative["id"]] = 1.0

    def add(self, finding: dict[str, Any], similarity: float) -> None:
        """Add finding to cluster and update representative if needed.

        Args:
            finding: Finding to add to cluster
            similarity: Similarity score between finding and representative

        """
        self.findings.append(finding)
        self.similarity_scores[finding["id"]] = similarity

        # Update representative if new finding has higher severity
        if self._compare_severity(finding, self.representative) > 0:
            self.representative = finding

    def _compare_severity(self, f1: dict, f2: dict) -> int:
        """Compare severity: returns 1 if f1 > f2, -1 if f1 < f2, 0 if equal."""
        sev1 = Severity.from_string(f1.get("severity", "INFO"))
        sev2 = Severity.from_string(f2.get("severity", "INFO"))

        if sev1 > sev2:
            return 1
        elif sev1 < sev2:
            return -1
        else:
            return 0

    def to_consensus_finding(self) -> dict[str, Any]:
        """Generate single consensus finding from cluster.

        Returns:
            Dict representing consensus finding with:
                - All fields from representative finding
                - detected_by: Array of tool objects
                - confidence: Object with level and tool_count
                - severity: Elevated to highest in cluster
                - context.duplicates: Array of non-representative findings

        """
        # Start with representative as base
        consensus = self.representative.copy()

        # Build detected_by array
        detected_by = []
        for finding in self.findings:
            tool_info = finding.get("tool", {})
            if isinstance(tool_info, dict):
                detected_by.append(
                    {
                        "name": tool_info.get("name", "unknown"),
                        "version": tool_info.get("version", "unknown"),
                    }
                )

        consensus["detected_by"] = detected_by

        # Determine highest severity
        consensus["severity"] = self._get_highest_severity()

        # Calculate confidence
        consensus["confidence"] = self._calculate_confidence()

        # Attach duplicates to context
        duplicates = []
        for finding in self.findings:
            if finding["id"] != self.representative["id"]:
                duplicates.append(
                    {
                        "id": finding["id"],
                        "tool": finding.get("tool", {}),
                        "severity": finding.get("severity", "INFO"),
                        "message": finding.get("message", ""),
                        "similarity_score": self.similarity_scores.get(
                            finding["id"], 0.0
                        ),
                    }
                )

        if "context" not in consensus:
            consensus["context"] = {}
        consensus["context"]["duplicates"] = duplicates
        consensus["context"]["cluster_size"] = len(self.findings)

        # Generate new fingerprint for consensus finding
        # (Prepend "cluster-" to original fingerprint)
        consensus["id"] = f"cluster-{self.representative['id']}"

        return consensus

    def _get_highest_severity(self) -> str:
        """Get highest severity among all findings in cluster."""
        severities = [
            Severity.from_string(f.get("severity", "INFO")) for f in self.findings
        ]
        highest = max(severities)
        return highest.value

    def _calculate_confidence(self) -> dict[str, Any]:
        """Calculate confidence score based on tool count and agreement.

        Returns:
            Dict with:
                - level: "HIGH", "MEDIUM", "LOW"
                - tool_count: Number of tools detecting this issue
                - avg_similarity: Average similarity score

        """
        tool_count = len(self.findings)

        # Confidence levels
        if tool_count >= 4:
            level = "HIGH"
        elif tool_count >= 2:
            level = "MEDIUM"
        else:
            level = "LOW"

        # Average similarity
        avg_similarity = sum(self.similarity_scores.values()) / len(
            self.similarity_scores
        )

        return {
            "level": level,
            "tool_count": tool_count,
            "avg_similarity": round(avg_similarity, 3),
        }


class SimilarityCalculator:
    """Calculate multi-dimensional similarity between findings.

    Components:
        - Location similarity (35%): Path + line range overlap
        - Message similarity (40%): Fuzzy + token matching
        - Metadata similarity (25%): CWE/CVE/Rule ID matching

    Algorithm ensures incompatible vulnerability types never cluster.
    """

    # Security keywords for token matching
    SECURITY_KEYWORDS = {
        "injection",
        "sql",
        "xss",
        "csrf",
        "ssrf",
        "xxe",
        "hardcoded",
        "secret",
        "key",
        "password",
        "token",
        "vulnerability",
        "insecure",
        "unsafe",
        "weakness",
        "deserialization",
        "path traversal",
        "rce",
        "lfi",
        "rfi",
    }

    def __init__(
        self,
        location_weight: float = 0.35,
        message_weight: float = 0.40,
        metadata_weight: float = 0.25,
        similarity_threshold: float = 0.75,
    ):
        """Initialize with configurable weights.

        Args:
            location_weight: Weight for location similarity (default 0.35)
            message_weight: Weight for message similarity (default 0.40)
            metadata_weight: Weight for metadata similarity (default 0.25)
            similarity_threshold: Threshold for clustering (default 0.75)

        """
        assert (
            abs(location_weight + message_weight + metadata_weight - 1.0) < 0.01
        ), "Weights must sum to 1.0"
        self.location_weight = location_weight
        self.message_weight = message_weight
        self.metadata_weight = metadata_weight
        self.threshold = similarity_threshold

    def calculate_similarity(self, finding1: dict, finding2: dict) -> float:
        """Calculate multi-dimensional similarity between two findings.

        Returns:
            Float 0.0-1.0 where 1.0 = identical, 0.0 = completely different

        """
        # Component similarities
        loc_sim = self.location_similarity(
            finding1.get("location", {}), finding2.get("location", {})
        )

        msg_sim = self.message_similarity(
            finding1.get("message", ""), finding2.get("message", "")
        )

        meta_sim = self.metadata_similarity(
            finding1.get("raw", {}),
            finding2.get("raw", {}),
            finding1.get("ruleId"),
            finding2.get("ruleId"),
        )

        # Weighted composite
        composite = (
            (loc_sim * self.location_weight)
            + (msg_sim * self.message_weight)
            + (meta_sim * self.metadata_weight)
        )

        # Apply type conflict penalty
        if self._are_incompatible_types(finding1, finding2):
            composite *= 0.5

        return min(1.0, max(0.0, composite))

    def location_similarity(self, loc1: dict, loc2: dict) -> float:
        """Calculate location similarity (0.0-1.0).

        Algorithm:
            1. Normalize paths (strip ./ prefix, lowercase for case-insensitive FS)
            2. If paths differ → return 0.0
            3. Calculate line overlap using Jaccard index
            4. Apply distance penalty for gaps
        """
        path1 = self._normalize_path(loc1.get("path", ""))
        path2 = self._normalize_path(loc2.get("path", ""))

        if not path1 or not path2 or path1 != path2:
            return 0.0

        # Extract line ranges
        start1 = loc1.get("startLine", 0)
        end1 = loc1.get("endLine", start1)
        start2 = loc2.get("startLine", 0)
        end2 = loc2.get("endLine", start2)

        if start1 == 0 or start2 == 0:
            return 0.0

        # Calculate overlap using range intersection
        overlap = self._range_overlap(start1, end1, start2, end2)

        # Calculate gap penalty
        gap = self._range_gap(start1, end1, start2, end2)
        gap_penalty = max(0.0, 1.0 - (gap / 10.0))  # Penalty kicks in at gap>10

        return overlap * gap_penalty

    def _normalize_path(self, path: str) -> str:
        """Normalize path for comparison."""
        if not path:
            return ""
        # Remove leading ./
        path = path.lstrip("./")
        # Normalize separators (for cross-platform)
        path = path.replace("\\", "/")
        return path.lower()

    def _range_overlap(self, start1: int, end1: int, start2: int, end2: int) -> float:
        """Calculate Jaccard index for line ranges."""
        # Convert to sets for easy intersection/union
        range1 = set(range(start1, end1 + 1))
        range2 = set(range(start2, end2 + 1))

        if not range1 or not range2:
            return 0.0

        intersection = len(range1 & range2)
        union = len(range1 | range2)

        return intersection / union if union > 0 else 0.0

    def _range_gap(self, start1: int, end1: int, start2: int, end2: int) -> int:
        """Calculate minimum gap between line ranges."""
        if end1 < start2:
            return start2 - end1
        elif end2 < start1:
            return start1 - end2
        else:
            return 0  # Overlapping ranges have zero gap

    def message_similarity(self, msg1: str, msg2: str) -> float:
        """Calculate message similarity using hybrid approach.

        Combines:
            1. Token overlap (Jaccard on security keywords)
            2. Fuzzy ratio (character-level similarity)
            3. CWE/CVE ID boost
        """
        if not msg1 or not msg2:
            return 0.0

        # Normalize
        norm1 = self._normalize_message(msg1)
        norm2 = self._normalize_message(msg2)

        # Fast path: exact match after normalization
        if norm1 == norm2:
            return 1.0

        # Component 1: Token overlap (40%)
        token_sim = self._token_overlap(norm1, norm2)

        # Component 2: Fuzzy ratio (40%)
        if fuzz is not None:
            fuzzy_sim = fuzz.ratio(norm1, norm2) / 100.0
        else:
            # Simple fallback: character overlap ratio
            fuzzy_sim = self._simple_char_ratio(norm1, norm2)

        # Component 3: CWE/CVE boost (20%)
        metadata_boost = self._metadata_boost(msg1, msg2)

        # Composite
        base_sim = (token_sim * 0.40) + (fuzzy_sim * 0.40) + (metadata_boost * 0.20)

        return float(min(1.0, base_sim))

    def _normalize_message(self, msg: str) -> str:
        """Normalize message for comparison."""
        # Lowercase
        msg = msg.lower()
        # Remove punctuation (keep alphanumeric and spaces)
        msg = re.sub(r"[^\w\s-]", " ", msg)
        # Collapse whitespace
        msg = re.sub(r"\s+", " ", msg).strip()
        return msg

    def _token_overlap(self, msg1: str, msg2: str) -> float:
        """Calculate Jaccard index on security keyword tokens."""
        tokens1 = set(msg1.split())
        tokens2 = set(msg2.split())

        # Filter to security keywords only
        keywords1 = tokens1 & self.SECURITY_KEYWORDS
        keywords2 = tokens2 & self.SECURITY_KEYWORDS

        if not keywords1 or not keywords2:
            # Fallback to all tokens if no security keywords
            keywords1 = tokens1
            keywords2 = tokens2

        intersection = len(keywords1 & keywords2)
        union = len(keywords1 | keywords2)

        return intersection / union if union > 0 else 0.0

    def _metadata_boost(self, msg1: str, msg2: str) -> float:
        """Boost similarity if CWE/CVE IDs match."""
        cwes1 = self._extract_cwes(msg1)
        cwes2 = self._extract_cwes(msg2)

        cves1 = self._extract_cves(msg1)
        cves2 = self._extract_cves(msg2)

        # If any CWE or CVE matches, boost to 1.0
        if (cwes1 & cwes2) or (cves1 & cves2):
            return 1.0

        return 0.0

    def _extract_cwes(self, text: str) -> set[str]:
        """Extract CWE IDs from text."""
        # Match: CWE-89, CWE-79, etc.
        matches = re.findall(r"CWE-(\d+)", text, re.IGNORECASE)
        return set(matches)

    def _extract_cves(self, text: str) -> set[str]:
        """Extract CVE IDs from text."""
        # Match: CVE-2021-1234, etc.
        matches = re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE)
        return {m.upper() for m in matches}

    def _simple_char_ratio(self, s1: str, s2: str) -> float:
        """Simple character overlap ratio (fallback for missing rapidfuzz)."""
        if not s1 or not s2:
            return 0.0
        chars1 = set(s1)
        chars2 = set(s2)
        intersection = len(chars1 & chars2)
        union = len(chars1 | chars2)
        return intersection / union if union > 0 else 0.0

    def metadata_similarity(
        self,
        raw1: dict,
        raw2: dict,
        rule_id1: str | None,
        rule_id2: str | None,
    ) -> float:
        """Calculate metadata similarity based on CWE, CVE, Rule IDs.

        Returns:
            1.0 if exact CWE or CVE match
            0.7-0.9 if rule ID family match
            0.0 otherwise

        """
        # Extract CWEs from raw data (handle various formats)
        cwes1 = self._extract_cwes_from_raw(raw1)
        cwes2 = self._extract_cwes_from_raw(raw2)

        # Check for CWE match
        if cwes1 & cwes2:
            return 1.0

        # Extract CVEs
        cves1 = self._extract_cves_from_raw(raw1)
        cves2 = self._extract_cves_from_raw(raw2)

        # Check for CVE match
        if cves1 & cves2:
            return 1.0

        # Check rule ID family match
        if rule_id1 and rule_id2:
            rule_sim = self._rule_id_similarity(rule_id1, rule_id2)
            if rule_sim > 0.0:
                return rule_sim

        return 0.0

    def _extract_cwes_from_raw(self, raw: dict) -> set[str]:
        """Extract CWE IDs from raw finding data (various formats)."""
        cwes = set()

        # Format 1: {"CWE": "CWE-89"}
        if "CWE" in raw:
            cwes.add(str(raw["CWE"]).upper())

        # Format 2: {"cwe": ["CWE-89", "CWE-943"]}
        if "cwe" in raw:
            cwe_val = raw["cwe"]
            if isinstance(cwe_val, list):
                cwes.update(str(c).upper() for c in cwe_val)
            else:
                cwes.add(str(cwe_val).upper())

        # Format 3: {"issue_cwe": {"id": 89, ...}} (Bandit)
        if "issue_cwe" in raw and isinstance(raw["issue_cwe"], dict):
            cwe_id = raw["issue_cwe"].get("id")
            if cwe_id:
                cwes.add(f"CWE-{cwe_id}")

        # Normalize: strip "CWE-" prefix for comparison
        normalized = set()
        for cwe in cwes:
            if cwe.startswith("CWE-"):
                normalized.add(cwe[4:])  # Just the number
            else:
                normalized.add(cwe)

        return normalized

    def _extract_cves_from_raw(self, raw: dict) -> set[str]:
        """Extract CVE IDs from raw finding data."""
        cves: set[str] = set()

        # Common keys: CVE, VulnerabilityID, cve_id
        for key in ["CVE", "VulnerabilityID", "cve_id", "cve"]:
            if key in raw:
                val = raw[key]
                if isinstance(val, list):
                    cves.update(str(v).upper() for v in val)
                else:
                    cves.add(str(val).upper())

        return cves

    def _rule_id_similarity(self, rule1: str, rule2: str) -> float:
        """Calculate rule ID family similarity.

        Examples:
            python.lang.security.audit.sqli-injection
            python.lang.security.audit.sqli-format-string
            → Shared prefix: python.lang.security.audit.sqli
            → Similarity: 0.80

        """
        if rule1 == rule2:
            return 1.0

        # Split by dots/dashes
        parts1 = re.split(r"[.\-]", rule1.lower())
        parts2 = re.split(r"[.\-]", rule2.lower())

        # Find longest common prefix
        common_prefix_len = 0
        for p1, p2 in zip(parts1, parts2):
            if p1 == p2:
                common_prefix_len += 1
            else:
                break

        # Calculate similarity based on shared prefix ratio
        max_len = max(len(parts1), len(parts2))
        if max_len == 0:
            return 0.0

        prefix_ratio = common_prefix_len / max_len

        # Require at least 2 shared components for family match
        if common_prefix_len >= 2 and prefix_ratio >= 0.5:
            return 0.70 + (prefix_ratio * 0.20)  # 0.70-0.90 range

        return 0.0

    def _are_incompatible_types(self, finding1: dict, finding2: dict) -> bool:
        """Detect if findings represent incompatible vulnerability types.

        Returns True if:
            - Different CWEs (and both have CWEs)
            - One is CVE, other is code issue
            - Tags indicate different categories
        """
        # Check CWE conflict
        cwes1 = self._extract_cwes_from_raw(finding1.get("raw", {}))
        cwes2 = self._extract_cwes_from_raw(finding2.get("raw", {}))

        if cwes1 and cwes2 and not (cwes1 & cwes2):
            # Both have CWEs but they differ → incompatible
            return True

        # Check CVE vs code issue
        tags1 = set(finding1.get("tags", []))
        tags2 = set(finding2.get("tags", []))

        is_cve1 = "vulnerability" in tags1 or "cve" in tags1
        is_cve2 = "vulnerability" in tags2 or "cve" in tags2

        # If one is CVE and other isn't, they're different types
        if is_cve1 != is_cve2:
            return True

        return False


class FindingClusterer:
    """Main clustering engine using greedy similarity matching."""

    def __init__(self, similarity_threshold: float = 0.75):
        """Initialize clusterer with similarity threshold.

        Args:
            similarity_threshold: Minimum similarity score for clustering (default 0.75)

        """
        self.threshold = similarity_threshold
        self.calculator = SimilarityCalculator(
            similarity_threshold=similarity_threshold
        )

    def cluster(
        self,
        findings: list[dict[str, Any]],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[FindingCluster]:
        """Cluster findings using greedy algorithm.

        Args:
            findings: List of findings to cluster
            progress_callback: Optional callback(current, total, message) for progress

        Returns:
            List of FindingCluster objects

        """
        if not findings:
            return []

        # Sort by severity (CRITICAL first) for optimal representative selection
        sorted_findings = self._sort_by_severity(findings)

        clusters: list[FindingCluster] = []
        total = len(sorted_findings)

        for idx, finding in enumerate(sorted_findings):
            # Progress callback
            if progress_callback and idx % 10 == 0:
                progress_callback(idx, total, f"Clustering finding {idx+1}/{total}")

            # Find best matching cluster
            best_cluster = None
            best_score = 0.0

            for cluster in clusters:
                score = self.calculator.calculate_similarity(
                    finding, cluster.representative
                )
                if score > best_score:
                    best_score = score
                    best_cluster = cluster

            # Add to cluster or create new one
            if best_score >= self.threshold and best_cluster is not None:
                best_cluster.add(finding, best_score)
            else:
                clusters.append(FindingCluster(representative=finding))

        # Final progress callback
        if progress_callback:
            progress_callback(total, total, f"Clustered into {len(clusters)} groups")

        return clusters

    def _sort_by_severity(self, findings: list[dict]) -> list[dict]:
        """Sort findings by severity (CRITICAL → INFO)."""

        def severity_key(f: dict) -> int:
            """Convert severity level to numeric sort key for ordering findings.

            Maps severity strings to integers for consistent sorting from highest
            to lowest severity: CRITICAL → HIGH → MEDIUM → LOW → INFO.

            Args:
                f (dict): Finding dictionary with 'severity' field

            Returns:
                int: Numeric sort key (4=CRITICAL, 3=HIGH, 2=MEDIUM, 1=LOW, 0=INFO)

            Example:
                >>> severity_key({'severity': 'CRITICAL'})
                4
                >>> severity_key({'severity': 'low'})
                1
                >>> sorted([{'severity': 'LOW'}, {'severity': 'CRITICAL'}],
                ...        key=severity_key, reverse=True)
                [{'severity': 'CRITICAL'}, {'severity': 'LOW'}]

            Note:
                Unknown severity levels default to 0 (same as INFO).
                Used internally by _sort_by_severity for finding prioritization.

            """
            sev = Severity.from_string(f.get("severity", "INFO"))
            # Reverse order: CRITICAL=4, HIGH=3, ..., INFO=0
            order = {
                Severity.CRITICAL: 4,
                Severity.HIGH: 3,
                Severity.MEDIUM: 2,
                Severity.LOW: 1,
                Severity.INFO: 0,
            }
            return order.get(sev, 0)

        return sorted(findings, key=severity_key, reverse=True)
