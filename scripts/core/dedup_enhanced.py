"""Cross-tool deduplication using similarity-based clustering.

This module implements Phase 2 of the deduplication strategy:
- Phase 1 (existing): Fingerprint-based exact deduplication (same tool, same location)
- Phase 2 (this module): Similarity-based clustering across tools

Algorithms:
    1. Greedy (default for <500 findings): O(n×k) where k = avg cluster size
    2. LSH (default for ≥500 findings): O(n log n) average case using
       Locality-Sensitive Hashing with Union-Find

    The LSH algorithm:
        a. Generate hash signatures for each finding based on key features
        b. Build buckets of findings with shared signatures
        c. Only compare candidate pairs from same buckets
        d. Use Union-Find for efficient cluster membership tracking

Similarity Calculation:
    Multi-dimensional weighted similarity:
    - Location: 0.50 (same file + line strongly indicates same issue)
    - Message: 0.25 (different tools use very different terminology)
    - Metadata: 0.25 (CWE/CVE matching + rule equivalence mapping)

Threshold: 0.65 (lowered from 0.75 for better cross-tool clustering)

Rule Equivalence:
    Known equivalent rules across tools are mapped in rule_equivalence.py.
    Example: Trivy ":latest tag used" = Hadolint "DL3006" = Checkov "CKV_DOCKER_1"

Performance:
    - Greedy: O(n×k), best for small datasets (<500 findings)
    - LSH: O(n log n) average, O(n²) worst case, best for large datasets
    - Space: O(n)
    - Target: <2 seconds for 1000 findings, <10 seconds for 10000 findings

Classes:
    - FindingCluster: Represents a cluster of similar findings
    - SimilarityCalculator: Multi-dimensional similarity calculation
    - FindingClusterer: Main clustering engine (auto-selects algorithm)
    - UnionFind: Efficient disjoint set union data structure
    - LSHSignatureGenerator: Locality-sensitive hashing for finding signatures
    - LSHClusterer: LSH-accelerated clustering algorithm

Author: JMo Security
Version: 1.1.0
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
    fuzz = None  # type: ignore[assignment]  # Intentional fallback when rapidfuzz not installed

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
        location_weight: float = 0.50,
        message_weight: float = 0.25,
        metadata_weight: float = 0.25,
        similarity_threshold: float = 0.65,
    ):
        """Initialize with configurable weights.

        Args:
            location_weight: Weight for location similarity (default 0.50)
                Higher weight because same file + line strongly indicates same issue.
            message_weight: Weight for message similarity (default 0.25)
                Lower weight because different tools use very different terminology.
            metadata_weight: Weight for metadata similarity (default 0.25)
                Includes CWE/CVE matching AND rule equivalence mapping.
            similarity_threshold: Threshold for clustering (default 0.65)
                Lowered from 0.75 to enable better cross-tool clustering.
                With rule equivalence mapping, false positives are still prevented.

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

        # Extract tool names for rule equivalence checking
        tool1 = finding1.get("tool", {})
        tool2 = finding2.get("tool", {})
        tool1_name = tool1.get("name", "") if isinstance(tool1, dict) else ""
        tool2_name = tool2.get("name", "") if isinstance(tool2, dict) else ""

        meta_sim = self.metadata_similarity(
            finding1.get("raw", {}),
            finding2.get("raw", {}),
            finding1.get("ruleId"),
            finding2.get("ruleId"),
            tool1_name,
            tool2_name,
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
        tool1: str = "",
        tool2: str = "",
    ) -> float:
        """Calculate metadata similarity based on CWE, CVE, Rule IDs.

        Also checks rule equivalence mapping for known equivalent rules
        across different security tools (e.g., Hadolint DL3006 = Trivy :latest tag).

        Args:
            raw1: Raw finding data from first tool
            raw2: Raw finding data from second tool
            rule_id1: Rule ID from first tool
            rule_id2: Rule ID from second tool
            tool1: Name of first tool (for rule equivalence lookup)
            tool2: Name of second tool (for rule equivalence lookup)

        Returns:
            1.0 if exact CWE, CVE, or rule equivalence match
            0.7-0.9 if rule ID family match
            0.0 otherwise

        """
        # Check rule equivalence mapping first (highest priority for cross-tool dedup)
        if tool1 and tool2 and rule_id1 and rule_id2:
            try:
                from scripts.core.rule_equivalence import are_rules_equivalent

                is_equiv, _ = are_rules_equivalent(tool1, rule_id1, tool2, rule_id2)
                if is_equiv:
                    return 1.0
            except ImportError:
                pass  # Fallback if module not available

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
    """Main clustering engine with automatic algorithm selection.

    Uses improved weights (location-first) and rule equivalence mapping
    to better cluster findings from different security tools.

    Algorithm Selection:
        - <500 findings: Greedy algorithm (simpler, lower overhead)
        - ≥500 findings: LSH algorithm (O(n log n) average case)
        - Override with `algorithm` parameter

    """

    # Threshold for switching to LSH algorithm
    LSH_THRESHOLD = 500

    def __init__(
        self,
        similarity_threshold: float = 0.65,
        algorithm: str = "auto",
    ):
        """Initialize clusterer with similarity threshold.

        Args:
            similarity_threshold: Minimum similarity score for clustering (default 0.65)
                Lowered from 0.75 to enable better cross-tool deduplication.
                Rule equivalence mapping prevents false positives.
            algorithm: Algorithm to use: "auto" (default), "greedy", or "lsh"
                - "auto": Select based on finding count (greedy <500, lsh ≥500)
                - "greedy": Force O(n×k) greedy algorithm
                - "lsh": Force O(n log n) LSH algorithm

        """
        self.threshold = similarity_threshold
        self.algorithm = algorithm.lower()
        self.calculator = SimilarityCalculator(
            similarity_threshold=similarity_threshold
        )

    def cluster(
        self,
        findings: list[dict[str, Any]],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[FindingCluster]:
        """Cluster findings using selected algorithm.

        Automatically selects between greedy and LSH algorithms based on
        finding count, unless overridden via constructor.

        Args:
            findings: List of findings to cluster
            progress_callback: Optional callback(current, total, message) for progress

        Returns:
            List of FindingCluster objects

        """
        if not findings:
            return []

        # Select algorithm
        use_lsh = self._should_use_lsh(len(findings))

        if use_lsh:
            return self._cluster_lsh(findings, progress_callback)
        else:
            return self._cluster_greedy(findings, progress_callback)

    def _should_use_lsh(self, n: int) -> bool:
        """Determine if LSH algorithm should be used.

        Args:
            n: Number of findings

        Returns:
            True if LSH should be used, False for greedy

        """
        if self.algorithm == "lsh":
            return True
        elif self.algorithm == "greedy":
            return False
        else:  # "auto"
            return n >= self.LSH_THRESHOLD

    def _cluster_greedy(
        self,
        findings: list[dict[str, Any]],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[FindingCluster]:
        """Cluster findings using O(n×k) greedy algorithm.

        Best for smaller datasets (<500 findings) where overhead of LSH
        doesn't pay off.

        Args:
            findings: List of findings to cluster
            progress_callback: Optional callback(current, total, message)

        Returns:
            List of FindingCluster objects

        """
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

    def _cluster_lsh(
        self,
        findings: list[dict[str, Any]],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[FindingCluster]:
        """Cluster findings using O(n log n) LSH algorithm.

        Uses Locality-Sensitive Hashing to reduce comparisons from O(n²)
        to O(n × candidates) where candidates << n for typical datasets.

        Best for larger datasets (≥500 findings) where LSH overhead pays off.

        Args:
            findings: List of findings to cluster
            progress_callback: Optional callback(current, total, message)

        Returns:
            List of FindingCluster objects

        """
        lsh_clusterer = LSHClusterer(similarity_threshold=self.threshold)
        return lsh_clusterer.cluster(findings, progress_callback)

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


class UnionFind:
    """Union-Find (Disjoint Set Union) data structure for efficient cluster tracking.

    Supports near-constant time union and find operations using path compression
    and union by rank optimizations.

    Time Complexity:
        - find(): O(α(n)) ≈ O(1) amortized (inverse Ackermann function)
        - union(): O(α(n)) ≈ O(1) amortized
        - get_groups(): O(n)

    Space Complexity: O(n)

    Example:
        >>> uf = UnionFind(5)
        >>> uf.union(0, 1)
        >>> uf.union(2, 3)
        >>> uf.union(1, 2)
        >>> uf.find(0) == uf.find(3)  # All in same component
        True

    """

    def __init__(self, n: int):
        """Initialize Union-Find with n elements.

        Args:
            n: Number of elements (0 to n-1)

        """
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        """Find root of element x with path compression.

        Args:
            x: Element to find root for

        Returns:
            Root element of the set containing x

        """
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])  # Path compression
        return self.parent[x]

    def union(self, x: int, y: int) -> bool:
        """Union sets containing x and y using union by rank.

        Args:
            x: First element
            y: Second element

        Returns:
            True if union occurred, False if already in same set

        """
        px, py = self.find(x), self.find(y)
        if px == py:
            return False

        # Union by rank: attach smaller tree under larger tree
        if self.rank[px] < self.rank[py]:
            px, py = py, px
        self.parent[py] = px
        if self.rank[px] == self.rank[py]:
            self.rank[px] += 1

        return True

    def get_groups(self, items: list[Any]) -> list[list[Any]]:
        """Get all groups/clusters as lists of items.

        Args:
            items: List of items corresponding to indices 0..n-1

        Returns:
            List of groups, where each group is a list of items

        """
        from collections import defaultdict

        groups: dict[int, list[Any]] = defaultdict(list)
        for idx, item in enumerate(items):
            root = self.find(idx)
            groups[root].append(item)
        return list(groups.values())


class LSHSignatureGenerator:
    """Locality-Sensitive Hashing signature generator for fast similarity lookup.

    Creates hash signatures based on key finding features:
        - File path (normalized)
        - Line number bucket
        - Message tokens (security keywords)
        - CWE/CVE IDs

    Findings with similar signatures are likely to be similar, allowing us to
    reduce O(n²) comparisons to O(n × candidates) where candidates << n.

    The signature uses multiple "bands" to increase the probability that
    similar items hash to at least one common bucket.

    """

    # Security keywords for token-based hashing
    KEYWORDS = frozenset(
        {
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
            "traversal",
            "rce",
            "lfi",
            "rfi",
            "latest",
            "tag",
            "label",
            "user",
            "root",
            "healthcheck",
        }
    )

    def __init__(self, num_bands: int = 8):
        """Initialize LSH generator.

        Args:
            num_bands: Number of hash bands to generate (more bands = more candidates,
                      fewer false negatives but more false positives to filter)

        """
        self.num_bands = num_bands

    def generate_signatures(self, finding: dict[str, Any]) -> list[str]:
        """Generate LSH signatures for a finding.

        Creates multiple signatures based on different feature combinations.
        Findings with any matching signature are candidates for similarity check.

        Args:
            finding: Finding dictionary

        Returns:
            List of signature strings for bucketing

        """

        signatures = []

        # Extract features
        location = finding.get("location", {})
        path = self._normalize_path(location.get("path", ""))
        line = location.get("startLine", 0)
        message = finding.get("message", "").lower()
        rule_id = finding.get("ruleId", "").lower()
        raw = finding.get("raw", {})

        # Extract metadata
        cwes = self._extract_cwes(raw, message)
        cves = self._extract_cves(raw, message)
        keywords = self._extract_keywords(message)

        # Band 1: Path + line bucket (coarse location)
        if path and line:
            line_bucket = line // 5  # Group nearby lines
            sig = f"loc:{path}:{line_bucket}"
            signatures.append(self._hash(sig, 0))

        # Band 2: Exact path + line (fine location)
        if path and line:
            sig = f"exact:{path}:{line}"
            signatures.append(self._hash(sig, 1))

        # Band 3: CWE-based
        for cwe in cwes:
            sig = f"cwe:{cwe}"
            signatures.append(self._hash(sig, 2))

        # Band 4: CVE-based
        for cve in cves:
            sig = f"cve:{cve}"
            signatures.append(self._hash(sig, 3))

        # Band 5: Path + keywords
        if path and keywords:
            # Use sorted keywords for consistency
            kw_str = ",".join(sorted(keywords)[:3])  # Top 3 keywords
            sig = f"pathkw:{path}:{kw_str}"
            signatures.append(self._hash(sig, 4))

        # Band 6: Rule ID family (first 2 components)
        if rule_id:
            parts = re.split(r"[.\-_]", rule_id)
            if len(parts) >= 2:
                family = f"{parts[0]}.{parts[1]}"
                sig = f"rule:{family}"
                signatures.append(self._hash(sig, 5))

        # Band 7: Keyword pairs
        if len(keywords) >= 2:
            kw_list = sorted(keywords)[:4]
            for i in range(len(kw_list) - 1):
                sig = f"kwpair:{kw_list[i]}:{kw_list[i+1]}"
                signatures.append(self._hash(sig, 6))

        # Band 8: Path alone (for same-file findings)
        if path:
            sig = f"path:{path}"
            signatures.append(self._hash(sig, 7))

        return signatures

    def _hash(self, content: str, band: int) -> str:
        """Generate hash for a signature band.

        Args:
            content: Content to hash
            band: Band number (added to prevent cross-band collisions)

        Returns:
            8-character hex hash

        """
        import hashlib

        to_hash = f"{band}:{content}".encode("utf-8")
        return hashlib.md5(to_hash).hexdigest()[:8]

    def _normalize_path(self, path: str) -> str:
        """Normalize file path for comparison."""
        if not path:
            return ""
        path = path.lstrip("./")
        path = path.replace("\\", "/")
        return path.lower()

    def _extract_cwes(self, raw: dict, message: str) -> set[str]:
        """Extract CWE IDs from raw data and message."""
        cwes = set()

        # From raw data
        if "CWE" in raw:
            cwes.add(str(raw["CWE"]).upper())
        if "cwe" in raw:
            cwe_val = raw["cwe"]
            if isinstance(cwe_val, list):
                cwes.update(str(c).upper() for c in cwe_val)
            else:
                cwes.add(str(cwe_val).upper())
        if "issue_cwe" in raw and isinstance(raw["issue_cwe"], dict):
            cwe_id = raw["issue_cwe"].get("id")
            if cwe_id:
                cwes.add(f"CWE-{cwe_id}")

        # From message
        matches = re.findall(r"CWE-(\d+)", message, re.IGNORECASE)
        cwes.update(f"CWE-{m}" for m in matches)

        # Normalize
        normalized = set()
        for cwe in cwes:
            if cwe.startswith("CWE-"):
                normalized.add(cwe[4:])
            else:
                normalized.add(cwe)
        return normalized

    def _extract_cves(self, raw: dict, message: str) -> set[str]:
        """Extract CVE IDs from raw data and message."""
        cves: set[str] = set()

        for key in ["CVE", "VulnerabilityID", "cve_id", "cve"]:
            if key in raw:
                val = raw[key]
                if isinstance(val, list):
                    cves.update(str(v).upper() for v in val)
                else:
                    cves.add(str(val).upper())

        # From message
        matches = re.findall(r"CVE-\d{4}-\d+", message, re.IGNORECASE)
        cves.update(m.upper() for m in matches)

        return cves

    def _extract_keywords(self, message: str) -> set[str]:
        """Extract security keywords from message."""
        words = set(re.findall(r"\b\w+\b", message.lower()))
        return words & self.KEYWORDS


class LSHClusterer:
    """LSH-accelerated clustering for O(n log n) average case performance.

    Uses Locality-Sensitive Hashing to identify candidate pairs, then
    applies full similarity calculation only to candidates.

    Performance:
        - Average: O(n × avg_candidates) where avg_candidates << n
        - Worst case: O(n²) when all findings hash to same buckets
        - Typical: O(n log n) due to limited bucket collisions

    The algorithm:
        1. Generate LSH signatures for all findings
        2. Build hash buckets (findings with shared signatures)
        3. Identify candidate pairs from same buckets (with size limit)
        4. Calculate full similarity only for candidates
        5. Use Union-Find to build clusters from similar pairs
        6. Convert clusters to FindingCluster objects

    Bucket Size Limit:
        Large buckets (>100 items) are skipped to prevent O(n²) worst case.
        This is acceptable because findings in large buckets share only weak
        signatures (e.g., common CWE), and more specific signatures (path, line)
        will still catch true duplicates.

    """

    # Maximum bucket size before skipping (prevents O(n²) worst case)
    MAX_BUCKET_SIZE = 100

    def __init__(
        self,
        similarity_threshold: float = 0.65,
        num_bands: int = 8,
    ):
        """Initialize LSH clusterer.

        Args:
            similarity_threshold: Minimum similarity for clustering (default 0.65)
            num_bands: Number of LSH bands (default 8)

        """
        self.threshold = similarity_threshold
        self.lsh = LSHSignatureGenerator(num_bands=num_bands)
        self.calculator = SimilarityCalculator(
            similarity_threshold=similarity_threshold
        )

    def cluster(
        self,
        findings: list[dict[str, Any]],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[FindingCluster]:
        """Cluster findings using LSH-accelerated algorithm.

        Args:
            findings: List of findings to cluster
            progress_callback: Optional callback(current, total, message)

        Returns:
            List of FindingCluster objects

        """
        if not findings:
            return []

        n = len(findings)

        # Phase 1: Generate signatures and build buckets
        if progress_callback:
            progress_callback(0, n, "Building LSH signatures...")

        buckets: dict[str, list[int]] = {}
        for idx, finding in enumerate(findings):
            signatures = self.lsh.generate_signatures(finding)
            for sig in signatures:
                if sig not in buckets:
                    buckets[sig] = []
                buckets[sig].append(idx)

        # Phase 2: Identify candidate pairs from buckets
        if progress_callback:
            progress_callback(n // 4, n, "Identifying candidates...")

        candidates: set[tuple[int, int]] = set()
        for bucket_indices in buckets.values():
            # Skip buckets that are too large (would cause O(n²) behavior)
            # True duplicates will be caught by more specific signatures
            if len(bucket_indices) > 1 and len(bucket_indices) <= self.MAX_BUCKET_SIZE:
                # Add all pairs in bucket as candidates
                for i in range(len(bucket_indices)):
                    for j in range(i + 1, len(bucket_indices)):
                        # Store as ordered pair (smaller, larger)
                        pair = (
                            min(bucket_indices[i], bucket_indices[j]),
                            max(bucket_indices[i], bucket_indices[j]),
                        )
                        candidates.add(pair)

        # Phase 3: Calculate similarity for candidates and union similar pairs
        if progress_callback:
            progress_callback(n // 2, n, f"Checking {len(candidates)} candidates...")

        uf = UnionFind(n)
        similarity_cache: dict[tuple[int, int], float] = {}

        for idx, (i, j) in enumerate(candidates):
            if progress_callback and idx % 100 == 0:
                progress = n // 2 + (idx * n // 4 // max(len(candidates), 1))
                progress_callback(
                    progress, n, f"Comparing pair {idx+1}/{len(candidates)}"
                )

            similarity = self.calculator.calculate_similarity(findings[i], findings[j])
            if similarity >= self.threshold:
                uf.union(i, j)
                similarity_cache[(i, j)] = similarity

        # Phase 4: Build FindingCluster objects
        if progress_callback:
            progress_callback(3 * n // 4, n, "Building clusters...")

        # Get groups from Union-Find
        groups = uf.get_groups(list(range(n)))

        # Convert to FindingCluster objects
        clusters = []
        for group_indices in groups:
            if not group_indices:
                continue

            # Sort by severity to select best representative
            group_findings = [findings[idx] for idx in group_indices]
            sorted_group = self._sort_by_severity(group_findings)

            # Create cluster with highest severity as representative
            cluster = FindingCluster(representative=sorted_group[0])

            # Add remaining findings with their similarity scores
            rep_idx = group_indices[
                sorted_group.index(sorted_group[0]) if len(sorted_group) > 0 else 0
            ]
            for finding in sorted_group[1:]:
                orig_idx = group_indices[group_findings.index(finding)]
                # Look up cached similarity
                pair = (min(rep_idx, orig_idx), max(rep_idx, orig_idx))
                similarity = similarity_cache.get(pair, 0.0)
                if similarity == 0.0:
                    # Calculate if not in cache (transitive closure case)
                    similarity = self.calculator.calculate_similarity(
                        cluster.representative, finding
                    )
                cluster.add(finding, similarity)

            clusters.append(cluster)

        if progress_callback:
            progress_callback(n, n, f"Clustered into {len(clusters)} groups")

        return clusters

    def _sort_by_severity(self, findings: list[dict]) -> list[dict]:
        """Sort findings by severity (CRITICAL → INFO)."""

        def severity_key(f: dict) -> int:
            sev = Severity.from_string(f.get("severity", "INFO"))
            order = {
                Severity.CRITICAL: 4,
                Severity.HIGH: 3,
                Severity.MEDIUM: 2,
                Severity.LOW: 1,
                Severity.INFO: 0,
            }
            return order.get(sev, 0)

        return sorted(findings, key=severity_key, reverse=True)
