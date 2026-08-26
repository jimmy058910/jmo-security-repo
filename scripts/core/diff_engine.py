"""
Diff engine for comparing security scan results.

This module provides the core diff algorithm for JMo Security v1.0.0,
enabling comparison of security scans to identify new, resolved, modified,
and unchanged findings.

Key Features:
- Fingerprint-based matching (100% accuracy)
- Modification detection (5 change types)
- Directory and SQLite comparison modes
- O(n) complexity for fast diffs (<500ms for 1000 findings)

Copyright (c) 2025 JMo Security
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Cross-tool clustering rewrites a consensus finding's `id` to
# `cluster-<representative fingerprint>` (`dedup_enhanced.py`). Diff keys on
# identity, so without stripping this prefix a finding that merely gained a
# second tool's corroboration between two scans is reported as one resolved
# plus one new finding -- i.e. as fixed (#847).
CLUSTER_ID_PREFIX = "cluster-"

# Minimum absolute change in the 0-100 priority score that counts as a real
# move. Used both to decide whether a priority change is worth reporting and,
# when severity is unchanged, to decide the direction of `risk_delta`.
PRIORITY_CHANGE_THRESHOLD = 5.0


# ============================================================================
# Data Models
# ============================================================================


@dataclass(frozen=True)
class DiffSource:
    """
    Metadata about a diff source (baseline or current).

    Attributes:
        source_type: "directory" or "sqlite"
        path: Directory path (for directory mode) or scan ID (for SQLite mode)
        timestamp: ISO 8601 timestamp
        profile: Scan profile name (fast/balanced/deep)
        total_findings: Total number of findings in this scan
    """

    source_type: str  # "directory" or "sqlite"
    path: str  # Directory path or SQLite scan ID
    timestamp: str  # ISO 8601 timestamp
    profile: str  # fast/balanced/deep
    total_findings: int


@dataclass(frozen=True)
class ModifiedFinding:
    """
    A finding that exists in both scans but with changed metadata.

    Tracks 5 types of changes:
    1. severity: Severity level change (MEDIUM → HIGH)
    2. priority: Priority score change (>5 points)
    3. compliance_added: New compliance framework mappings
    4. cwe: CWE classification change
    5. message: Message content change (>10 chars difference)

    Attributes:
        fingerprint: Stable finding ID
        changes: Dict of change_type → [old_value, new_value]
        baseline: Full baseline finding dict
        current: Full current finding dict
        risk_delta: "improved", "worsened", "unchanged"
    """

    fingerprint: str
    changes: dict[str, list[Any]]
    baseline: dict[str, Any]
    current: dict[str, Any]
    risk_delta: str


@dataclass(frozen=True)
class DiffResult:
    """
    Results of comparing two scans.

    Contains classified findings and summary statistics.

    Attributes:
        new: Findings in current but not baseline
        resolved: Findings in baseline but not current
        unchanged: Findings in both (same fingerprint, same metadata)
        modified: Findings in both but with changed metadata
        baseline_source: Metadata about baseline scan
        current_source: Metadata about current scan
        statistics: Summary statistics dict
    """

    new: list[dict[str, Any]] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)
    unchanged: list[dict[str, Any]] = field(default_factory=list)
    modified: list[ModifiedFinding] = field(default_factory=list)
    baseline_source: DiffSource = None  # type: ignore[assignment]  # Dataclass default for optional field
    current_source: DiffSource = None  # type: ignore[assignment]  # Dataclass default for optional field
    statistics: dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Core Diff Engine
# ============================================================================


class DiffEngine:
    """
    Core diff engine for comparing security scans.

    Supports two comparison modes:
    1. Directory mode: Compare findings from two results directories
    2. SQLite mode: Compare two scan IDs from history database

    Performance:
    - O(n) complexity where n = max(baseline_count, current_count)
    - <500ms for 1000-finding diffs
    - <2s for 10,000-finding diffs

    Example:
        >>> engine = DiffEngine()
        >>> diff = engine.compare_directories(
        ...     baseline=Path("baseline-results"),
        ...     current=Path("current-results")
        ... )
        >>> print(f"New: {diff.statistics['total_new']}")
        >>> print(f"Resolved: {diff.statistics['total_resolved']}")
    """

    def __init__(self, detect_modifications: bool = True):
        """
        Initialize diff engine.

        Args:
            detect_modifications: Enable modification detection (default True)
                                  Disable for faster diffs when only
                                  new/resolved matters (e.g., CI gates)
        """
        self.detect_modifications = detect_modifications

    def compare_directories(
        self,
        baseline_dir: Path,
        current_dir: Path,
    ) -> DiffResult:
        """
        Compare findings from two scan results directories.

        Args:
            baseline_dir: Path to baseline results (e.g., baseline-results/)
            current_dir: Path to current results (e.g., current-results/)

        Returns:
            DiffResult with classified findings and statistics

        Raises:
            FileNotFoundError: If directories don't exist
            ValueError: If findings.json is malformed

        Example:
            >>> engine = DiffEngine()
            >>> diff = engine.compare_directories(
            ...     Path("baseline-results"),
            ...     Path("current-results")
            ... )
        """
        if not baseline_dir.exists():
            raise FileNotFoundError(f"Baseline directory not found: {baseline_dir}")
        if not current_dir.exists():
            raise FileNotFoundError(f"Current directory not found: {current_dir}")

        logger.info(f"Loading baseline findings from {baseline_dir}")
        baseline_findings = self._load_directory_findings(baseline_dir)

        logger.info(f"Loading current findings from {current_dir}")
        current_findings = self._load_directory_findings(current_dir)

        logger.info(
            f"Loaded {len(baseline_findings)} baseline, "
            f"{len(current_findings)} current findings"
        )

        # Extract source metadata
        baseline_source = self._extract_source_info(baseline_dir, baseline_findings)
        current_source = self._extract_source_info(current_dir, current_findings)

        # Perform diff
        return self._compare_findings(
            baseline_findings,
            current_findings,
            baseline_source,
            current_source,
        )

    def compare_scans(
        self,
        baseline_scan_id: str,
        current_scan_id: str,
        db_path: Path | None = None,
    ) -> DiffResult:
        """
        Compare two scans from SQLite history database.

        Args:
            baseline_scan_id: Baseline scan UUID
            current_scan_id: Current scan UUID
            db_path: Path to history.db (default: ~/.jmo/history.db)

        Returns:
            DiffResult with classified findings and statistics

        Raises:
            ValueError: If scan IDs don't exist
            sqlite3.Error: If database operations fail

        Example:
            >>> engine = DiffEngine()
            >>> diff = engine.compare_scans(
            ...     baseline_scan_id="abc123",
            ...     current_scan_id="def456"
            ... )
        """
        from scripts.core.history_db import (
            DEFAULT_DB_PATH,
            get_connection,
            get_scan_by_id,
        )

        db_path = db_path or DEFAULT_DB_PATH
        conn = get_connection(db_path)

        try:
            logger.info(f"Loading baseline scan {baseline_scan_id} from database")
            baseline_findings = self._load_sqlite_findings(conn, baseline_scan_id)
            baseline_scan = get_scan_by_id(conn, baseline_scan_id)

            logger.info(f"Loading current scan {current_scan_id} from database")
            current_findings = self._load_sqlite_findings(conn, current_scan_id)
            current_scan = get_scan_by_id(conn, current_scan_id)

            if not baseline_scan:
                raise ValueError(f"Baseline scan not found: {baseline_scan_id}")
            if not current_scan:
                raise ValueError(f"Current scan not found: {current_scan_id}")

            logger.info(
                f"Loaded {len(baseline_findings)} baseline, "
                f"{len(current_findings)} current findings"
            )

            # Build source metadata
            baseline_source = DiffSource(
                source_type="sqlite",
                path=baseline_scan_id,
                timestamp=baseline_scan.get("timestamp_iso", ""),
                profile=baseline_scan.get("profile", ""),
                total_findings=baseline_scan.get("total_findings", 0),
            )

            current_source = DiffSource(
                source_type="sqlite",
                path=current_scan_id,
                timestamp=current_scan.get("timestamp_iso", ""),
                profile=current_scan.get("profile", ""),
                total_findings=current_scan.get("total_findings", 0),
            )

            # Perform diff
            return self._compare_findings(
                baseline_findings,
                current_findings,
                baseline_source,
                current_source,
            )

        finally:
            conn.close()

    # ========================================================================
    # Private Methods - Loading
    # ========================================================================

    def _load_directory_findings(self, results_dir: Path) -> list[dict[str, Any]]:
        """Load findings from results directory summaries/findings.json."""
        findings_path = results_dir / "summaries" / "findings.json"

        if not findings_path.exists():
            raise FileNotFoundError(
                f"findings.json not found at {findings_path}. "
                "Run 'jmo scan' and 'jmo report' first."
            )

        try:
            with open(findings_path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {findings_path}: {e}")

        # Handle v1.0.0 metadata wrapper format
        if isinstance(data, dict) and "findings" in data:
            findings = data["findings"]
            logger.debug(f"Detected v1.0.0 metadata wrapper format in {findings_path}")
        elif isinstance(data, list):
            findings = data
            logger.debug(f"Detected legacy list format in {findings_path}")
        else:
            raise ValueError(
                f"Expected findings.json to contain a list or v1.0.0 wrapper, got {type(data).__name__}"
            )

        # `findings` must be a list of objects. A string is iterable, so
        # `{"findings": "oops"}` used to become one finding per character --
        # each silently discarded further down, leaving a diff that reported
        # every finding in the other scan as new. A corrupt baseline must not
        # read as a clean one.
        if not isinstance(findings, list):
            raise ValueError(
                f"Expected 'findings' in {findings_path} to be a list, "
                f"got {type(findings).__name__}"
            )

        usable = [f for f in findings if isinstance(f, dict)]
        if len(usable) != len(findings):
            logger.warning(
                f"{len(findings) - len(usable)} of {len(findings)} entries in "
                f"{findings_path} are not objects and were ignored"
            )

        logger.debug(f"Loaded {len(usable)} findings from {findings_path}")
        return usable

    def _load_sqlite_findings(self, conn, scan_id: str) -> list[dict[str, Any]]:
        """Load findings from SQLite database."""
        from scripts.core.history_db import get_findings_for_scan

        findings_rows = get_findings_for_scan(conn, scan_id)
        findings = []

        for row in findings_rows:
            # Reconstruct CommonFinding dict from SQLite row
            # raw_finding contains the full JSON
            try:
                raw = (
                    json.loads(row["raw_finding"])
                    if isinstance(row.get("raw_finding"), str)
                    else {}
                )
            except (json.JSONDecodeError, KeyError):
                raw = {}

            # Build CommonFinding format
            finding = {
                "id": row["fingerprint"],
                "severity": row["severity"],
                "ruleId": row["rule_id"],
                "tool": {"name": row["tool"]},
                "location": {
                    "path": row["path"],
                    "startLine": row.get("start_line", 0),
                },
                "message": row["message"],
                **raw,  # Merge full finding data
            }
            findings.append(finding)

        logger.debug(f"Loaded {len(findings)} findings for scan {scan_id}")
        return findings

    def _extract_source_info(
        self, results_dir: Path, findings: list[dict[str, Any]]
    ) -> DiffSource:
        """Extract metadata from findings.json if available."""
        findings_json = results_dir / "summaries" / "findings.json"

        if findings_json.exists():
            try:
                data = json.loads(findings_json.read_text(encoding="utf-8"))
                # Handle both formats:
                # 1. Plain list: [finding1, finding2, ...]
                # 2. v1.0.0 wrapper: {"meta": {...}, "statistics": {...}, "findings": [...]}
                if isinstance(data, dict):
                    meta = data.get("meta", {})
                    return DiffSource(
                        source_type="directory",
                        path=str(results_dir),
                        timestamp=meta.get("timestamp", ""),
                        profile=meta.get("profile", ""),
                        total_findings=len(findings),
                    )
            except (json.JSONDecodeError, KeyError):
                pass

        # Fallback: minimal metadata
        return DiffSource(
            source_type="directory",
            path=str(results_dir),
            timestamp="",
            profile="",
            total_findings=len(findings),
        )

    # ========================================================================
    # Private Methods - Core Diff Algorithm
    # ========================================================================

    @staticmethod
    def _primary_identity(finding: dict[str, Any]) -> str | None:
        """Return a finding's own identity, with any cluster prefix removed."""
        fid = finding.get("id")
        if not isinstance(fid, str) or not fid:
            return None
        if fid.startswith(CLUSTER_ID_PREFIX):
            return fid[len(CLUSTER_ID_PREFIX) :] or None
        return fid

    @classmethod
    def _identities(cls, finding: dict[str, Any]) -> list[str]:
        """Every underlying fingerprint a finding represents.

        A plain finding represents exactly its own id. A consensus finding
        produced by cross-tool clustering represents the fingerprints of every
        member of its cluster: the representative's, recoverable from the
        ``cluster-`` prefix, plus each entry in ``context.duplicates``. Matching
        on any of them keeps a finding's diff identity stable when it joins or
        leaves a cluster, and when the cluster's representative changes (#847).
        """
        if not isinstance(finding, dict):
            return []

        identities: list[str] = []
        primary = cls._primary_identity(finding)
        if primary:
            identities.append(primary)

        context = finding.get("context")
        duplicates = context.get("duplicates") if isinstance(context, dict) else None
        if isinstance(duplicates, list):
            for duplicate in duplicates:
                if not isinstance(duplicate, dict):
                    continue
                did = duplicate.get("id")
                if isinstance(did, str) and did and did not in identities:
                    identities.append(did)

        return identities

    def _build_identity_lookup(
        self, findings: list[dict[str, Any]], label: str
    ) -> tuple[dict[str, dict[str, Any]], int]:
        """Map every identity a finding covers to that finding.

        Returns the lookup plus a count of findings carrying no usable id.
        Those cannot be matched or classified, and were previously discarded
        with no record at any level.
        """
        lookup: dict[str, dict[str, Any]] = {}
        skipped = 0
        for finding in findings:
            identities = self._identities(finding)
            if not identities:
                skipped += 1
                continue
            for identity in identities:
                lookup.setdefault(identity, finding)
        if skipped:
            logger.debug(f"{skipped} {label} finding(s) carry no usable id")
        return lookup, skipped

    def _compare_findings(
        self,
        baseline_findings: list[dict[str, Any]],
        current_findings: list[dict[str, Any]],
        baseline_source: DiffSource,
        current_source: DiffSource,
    ) -> DiffResult:
        """
        Core diff algorithm using fingerprint matching.

        Steps:
        1. Build fingerprint indexes for O(1) lookup
        2. Classify findings using set operations
        3. Detect modifications (if enabled)
        4. Calculate summary statistics
        5. Return immutable DiffResult

        Complexity: O(n) where n = max(len(baseline), len(current))
        """
        logger.info("Building fingerprint indexes")

        # Step 1: Build identity lookups. A finding is matched on any of the
        # underlying fingerprints it represents, so clustering does not change
        # a finding's diff identity (#847).
        baseline_lookup, baseline_skipped = self._build_identity_lookup(
            baseline_findings, "baseline"
        )
        current_lookup, current_skipped = self._build_identity_lookup(
            current_findings, "current"
        )

        # Step 2: Pair each current finding with the baseline finding that
        # shares an identity with it, then classify by whether a pair exists.
        # Classification is per finding rather than per fingerprint: a
        # consensus finding covers several fingerprints and must still count
        # once.
        pairs: dict[int, dict[str, Any]] = {}
        matched_baseline: set[int] = set()
        for finding in current_findings:
            for identity in self._identities(finding):
                match = baseline_lookup.get(identity)
                if match is None:
                    continue
                # Every baseline finding this one covers is accounted for, not
                # just the first. When two findings reported separately in the
                # baseline are clustered into one in the current scan, matching
                # only the first left the second looking resolved -- the same
                # false "fixed" that #847 is about, one step along.
                matched_baseline.add(id(match))
                pairs.setdefault(id(finding), match)

        new = [
            f for f in current_findings if self._identities(f) and id(f) not in pairs
        ]
        resolved = [
            f
            for f in baseline_findings
            if self._identities(f) and id(f) not in matched_baseline
        ]
        unchanged = [f for f in current_findings if id(f) in pairs]
        modified = []

        logger.info(
            f"Classification: {len(new)} new, "
            f"{len(resolved)} resolved, "
            f"{len(unchanged)} unchanged"
        )

        if baseline_skipped or current_skipped:
            logger.warning(
                f"Diff ignored {baseline_skipped} baseline and {current_skipped} "
                "current finding(s) carrying no usable id. They appear in "
                "neither the new, resolved nor unchanged totals."
            )

        # Step 3: Detect modifications (optional)
        if self.detect_modifications:
            logger.info("Detecting modifications")
            modified = self._detect_modifications(pairs, unchanged)

            # Remove modified findings from unchanged list
            modified_objects = {id(m.current) for m in modified}
            unchanged = [f for f in unchanged if id(f) not in modified_objects]

            logger.info(f"Found {len(modified)} modified findings")

        # Step 5: Calculate statistics
        stats = self._calculate_statistics(new, resolved, unchanged, modified)

        return DiffResult(
            new=new,
            resolved=resolved,
            unchanged=unchanged,
            modified=modified,
            baseline_source=baseline_source,
            current_source=current_source,
            statistics=stats,
        )

    # ========================================================================
    # Private Methods - Modification Detection
    # ========================================================================

    def _detect_modifications(
        self,
        pairs: dict[int, dict[str, Any]],
        matched: list[dict[str, Any]],
    ) -> list[ModifiedFinding]:
        """
        Detect metadata changes in findings present in both scans.

        Approved algorithm (DIFF_IMPLEMENTATION_PLAN.md):
        - Track 5 change types: severity, priority, compliance, CWE, message
        - Performance: O(n) where n = len(matched)
        - Thresholds: priority >5 pts, message >10 chars

        Note on the message change type: ``message`` is an input to
        ``common_finding.fingerprint()``, truncated at
        ``MESSAGE_SNIPPET_LENGTH`` (120) characters. A message edit inside that
        window therefore changes the finding's identity, and the finding is
        reported as one resolved plus one new rather than as modified. This
        change type is only reachable for findings whose message exceeds 120
        characters and whose edit falls entirely beyond it -- measured at 6 of
        34 findings on a bandit corpus and 106 of 263 on a mixed one.

        Args:
            pairs: {id(current finding): matching baseline finding}
            matched: Current findings that have a baseline counterpart

        Returns:
            List of ModifiedFinding objects
        """
        modified = []

        for current in matched:
            baseline = pairs[id(current)]
            fp = self._primary_identity(current) or ""

            changes = {}

            # 1. Severity change (CRITICAL)
            baseline_sev = baseline.get("severity", "INFO")
            current_sev = current.get("severity", "INFO")
            if baseline_sev != current_sev:
                changes["severity"] = [baseline_sev, current_sev]

            # 2. Priority score change (HIGH) - threshold 5 points
            baseline_priority = self._extract_priority(baseline)
            current_priority = self._extract_priority(current)
            if abs(baseline_priority - current_priority) > PRIORITY_CHANGE_THRESHOLD:
                changes["priority"] = [baseline_priority, current_priority]

            # 3. Compliance framework additions (MEDIUM)
            baseline_compliance = set(
                self._flatten_compliance(baseline.get("compliance", {}))
            )
            current_compliance = set(
                self._flatten_compliance(current.get("compliance", {}))
            )
            new_mappings = current_compliance - baseline_compliance
            if new_mappings:
                changes["compliance_added"] = list(new_mappings)

            # 4. CWE changes (LOW)
            baseline_cwe = baseline.get("risk", {}).get("cwe")
            current_cwe = current.get("risk", {}).get("cwe")
            if baseline_cwe != current_cwe and baseline_cwe and current_cwe:
                changes["cwe"] = [baseline_cwe, current_cwe]

            # 5. Message changes (INFORMATIONAL) - threshold 10 chars
            baseline_msg = baseline.get("message", "")
            current_msg = current.get("message", "")
            if (
                baseline_msg != current_msg
                and abs(len(baseline_msg) - len(current_msg)) > 10
            ):
                changes["message"] = [baseline_msg[:100], current_msg[:100]]

            # Only include if changes detected
            if changes:
                risk_delta = self._calculate_risk_delta(baseline, current)
                modified.append(
                    ModifiedFinding(
                        fingerprint=fp,
                        changes=changes,
                        baseline=baseline,
                        current=current,
                        risk_delta=risk_delta,
                    )
                )

        return modified

    def _extract_priority(self, finding: dict[str, Any]) -> float:
        """
        Extract priority score from finding.

        Priority calculation (highest to lowest precedence):
        1. EPSS score (exploit probability) × 100
        2. CVSS base score × 10
        3. Severity-based fallback

        Args:
            finding: CommonFinding dict

        Returns:
            Priority score (0-100 scale)
        """
        # Try EPSS first (exploit probability)
        epss = finding.get("risk", {}).get("epss_score")
        if epss is not None:
            return float(epss) * 100  # Normalize to 0-100

        # Try CVSS base score
        cvss = finding.get("cvss", {}).get("baseScore")
        if cvss is not None:
            return float(cvss) * 10  # Normalize to 0-100

        # Fallback: severity-based score
        severity_scores = {
            "CRITICAL": 90,
            "HIGH": 70,
            "MEDIUM": 50,
            "LOW": 30,
            "INFO": 10,
        }
        return severity_scores.get(finding.get("severity", "INFO"), 0)

    def _flatten_compliance(self, compliance: dict[str, Any]) -> list[str]:
        """
        Flatten compliance object to list of framework IDs.

        Args:
            compliance: Compliance dict from CommonFinding

        Returns:
            List of "framework:id" strings
        """
        flat = []
        for framework, mappings in compliance.items():
            if isinstance(mappings, list):
                for item in mappings:
                    if isinstance(item, str):
                        flat.append(f"{framework}:{item}")
                    elif isinstance(item, dict):
                        # Handle complex objects (CWE, NIST, CIS)
                        id_key = item.get("id", item.get("category", ""))
                        if id_key:
                            flat.append(f"{framework}:{id_key}")
        return flat

    def _calculate_risk_delta(
        self, baseline: dict[str, Any], current: dict[str, Any]
    ) -> str:
        """
        Calculate risk trend: improved, worsened, unchanged.

        Severity decides on its own when it moves; priority decides otherwise.

        Args:
            baseline: Baseline finding
            current: Current finding

        Returns:
            "improved", "worsened", or "unchanged"
        """
        sev_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        baseline_sev = sev_scores.get(baseline.get("severity", "INFO"), 0)
        current_sev = sev_scores.get(current.get("severity", "INFO"), 0)

        # A severity change is categorical, and it is the change the report
        # shows the user, so it settles the direction by itself.
        #
        # It previously did not. The old weighted score gave a one-step
        # severity change exactly +/-0.5 and compared with a strict `> 0.5`,
        # so `MEDIUM -> HIGH` came out as "unchanged" whenever priority was
        # stable -- which is every finding carrying an EPSS or CVSS score,
        # since priority is then read from that score rather than from
        # severity. The markdown report printed the contradiction in one line:
        # "Severity: MEDIUM -> **HIGH** (unchanged)".
        if current_sev != baseline_sev:
            return "worsened" if current_sev > baseline_sev else "improved"

        # Otherwise the priority score decides, using the same threshold that
        # governs whether a priority change is reported at all.
        #
        # Compliance mappings are deliberately not a factor. Gaining a
        # framework mapping is the same finding described better, not more
        # risk, and at the old weight of 0.2 each, three new mappings alone
        # reported "worsened" with severity and priority both untouched. That
        # would fire broadly on upgrade to v1.1.0, whose compliance fix took
        # several mapping tables from 0 matches to dozens.
        priority_delta = self._extract_priority(current) - self._extract_priority(
            baseline
        )
        if priority_delta > PRIORITY_CHANGE_THRESHOLD:
            return "worsened"
        if priority_delta < -PRIORITY_CHANGE_THRESHOLD:
            return "improved"
        return "unchanged"

    # ========================================================================
    # Private Methods - Statistics
    # ========================================================================

    def _calculate_statistics(
        self,
        new: list[dict],
        resolved: list[dict],
        unchanged: list[dict],
        modified: list[ModifiedFinding],
    ) -> dict[str, Any]:
        """
        Calculate summary statistics for diff.

        Args:
            new: New findings
            resolved: Resolved findings
            unchanged: Unchanged findings
            modified: Modified findings

        Returns:
            Statistics dict with counts and trends
        """

        def severity_counts(findings: list[dict]) -> dict[str, int]:
            """Count findings by severity."""
            counts = Counter(f.get("severity", "INFO") for f in findings)
            # Ensure all severity levels present
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if sev not in counts:
                    counts[sev] = 0
            return dict(counts)

        new_by_sev = severity_counts(new)
        resolved_by_sev = severity_counts(resolved)

        net_change = len(new) - len(resolved)
        if net_change < 0:
            trend = "improving"
        elif net_change > 0:
            trend = "worsening"
        else:
            trend = "stable"

        return {
            "total_new": len(new),
            "total_resolved": len(resolved),
            "total_unchanged": len(unchanged),
            "total_modified": len(modified),
            "net_change": net_change,
            "trend": trend,
            "new_by_severity": new_by_sev,
            "resolved_by_severity": resolved_by_sev,
            "modifications_by_type": self._count_modification_types(modified),
        }

    def _count_modification_types(
        self, modified: list[ModifiedFinding]
    ) -> dict[str, int]:
        """
        Count how many modifications of each type occurred.

        Args:
            modified: List of modified findings

        Returns:
            Dict of modification_type → count
        """
        types = []  # type: ignore[var-annotated]  # Types inferred from append operations
        for m in modified:
            types.extend(m.changes.keys())
        return dict(Counter(types))

    def diff_with_context(
        self,
        baseline_id: str,
        current_id: str,
        db_path: Path | None = None,
    ) -> DiffResult:
        """
        Generate diff with trend analysis context (Phase 5 integration).

        This method combines diff results with trend analysis to provide
        richer context about security posture changes over time.

        Args:
            baseline_id: SQLite scan ID for baseline
            current_id: SQLite scan ID for current scan
            db_path: Path to history database (optional)

        Returns:
            DiffResult with additional trend_context field

        Example:
            >>> engine = DiffEngine()
            >>> diff = engine.diff_with_context("scan-abc123", "scan-def456")
            >>> if hasattr(diff, 'trend_context'):
            ...     print(f"Score change: {diff.trend_context['score_change']}")
        """
        from scripts.core.trend_analyzer import TrendAnalyzer

        # Standard diff using SQLite mode
        diff = self.compare_scans(baseline_id, current_id, db_path=db_path)

        # Add trend context
        try:
            with TrendAnalyzer(db_path=db_path) as analyzer:  # type: ignore[arg-type]  # Path validated before call
                trend = analyzer.analyze_trends(scan_ids=[baseline_id, current_id])

                # Extract key trend metrics
                security_score = trend.get("security_score", {})
                improvement = trend.get("improvement_metrics", {})
                insights = trend.get("insights", [])

                trend_context = {
                    "score_change": security_score.get("current_score", 0.0),
                    "score_trend": security_score.get("trend", "unknown"),
                    "velocity": improvement.get("net_change", 0),
                    "insights": [
                        {
                            "priority": i.get("priority", ""),
                            "message": i.get("message", ""),
                            "action": i.get("recommended_action", ""),
                        }
                        for i in insights[:5]  # Top 5 insights
                    ],
                }

                # Attach to diff result (note: dataclass is frozen, so we use setattr)
                object.__setattr__(diff, "trend_context", trend_context)

        except (
            Exception
        ) as e:  # Acceptable: trend context is optional enrichment — must not crash diff
            logger.warning(f"Failed to add trend context: {e}")
            object.__setattr__(diff, "trend_context", None)

        return diff
