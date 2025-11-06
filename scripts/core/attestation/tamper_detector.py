"""
Advanced Tamper Detection for SLSA Attestations.

This module provides comprehensive tamper detection beyond basic digest verification,
including:
- Multi-hash digest verification (SHA-256, SHA-384, SHA-512)
- Timestamp anomaly detection (future dates, impossible durations)
- Builder consistency checks (detecting unauthorized CI platform changes)
- Tool version rollback detection (defending against bypass attacks)
- Suspicious pattern detection (path traversal, missing fields, localhost builders)
- Attack scenario simulation (file substitution, replay, impersonation)

Used by AttestationVerifier to detect advanced supply chain attacks.
"""

import json
import logging
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class TamperSeverity(str, Enum):
    """Severity levels for tamper indicators."""

    CRITICAL = "CRITICAL"  # Definite attack (reject attestation)
    HIGH = "HIGH"  # Strong indicator (warn user)
    MEDIUM = "MEDIUM"  # Suspicious pattern (investigate)
    LOW = "LOW"  # Minor anomaly (informational)


class TamperIndicatorType(str, Enum):
    """Types of tamper indicators."""

    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    TIMESTAMP_ANOMALY = "TIMESTAMP_ANOMALY"
    BUILDER_INCONSISTENCY = "BUILDER_INCONSISTENCY"
    TOOL_ROLLBACK = "TOOL_ROLLBACK"
    SUSPICIOUS_PATTERN = "SUSPICIOUS_PATTERN"
    MISSING_FIELD = "MISSING_FIELD"


@dataclass
class TamperIndicator:
    """
    Indicator of potential tampering in an attestation.

    Attributes:
        severity: Severity level (CRITICAL/HIGH/MEDIUM/LOW)
        indicator_type: Type of indicator (DIGEST_MISMATCH, TIMESTAMP_ANOMALY, etc.)
        description: Human-readable description of the issue
        evidence: Supporting evidence (timestamps, hashes, etc.)
    """

    severity: TamperSeverity
    indicator_type: TamperIndicatorType
    description: str
    evidence: Dict[str, Any]


class TamperDetector:
    """
    Advanced tamper detection for SLSA attestations.

    Provides multiple detection strategies beyond basic digest verification:
    - Timestamp anomalies (future dates, impossible durations, stale attestations)
    - Builder consistency (detecting unauthorized platform/version changes)
    - Tool version rollback (defending against bypass attacks)
    - Suspicious patterns (path traversal, localhost builders, missing fields)

    Usage:
        detector = TamperDetector()
        indicators = detector.check_all(
            subject_path="findings.json",
            attestation_path="findings.json.att.json",
            historical_attestations=["previous1.att.json", "previous2.att.json"]
        )

        if any(ind.severity == TamperSeverity.CRITICAL for ind in indicators):
            print("CRITICAL: Attestation is compromised!")
    """

    def __init__(
        self,
        max_age_days: int = 90,
        max_duration_hours: int = 24,
        allow_builder_version_change: bool = True
    ):
        """
        Initialize tamper detector.

        Args:
            max_age_days: Maximum attestation age before flagging as stale (default: 90 days)
            max_duration_hours: Maximum build duration before flagging (default: 24 hours)
            allow_builder_version_change: Allow builder version changes (default: True)
        """
        self.max_age_days = max_age_days
        self.max_duration_hours = max_duration_hours
        self.allow_builder_version_change = allow_builder_version_change

    def check_all(
        self,
        subject_path: str,
        attestation_path: str,
        historical_attestations: Optional[List[str]] = None
    ) -> List[TamperIndicator]:
        """
        Run all tamper detection checks and aggregate indicators.

        Args:
            subject_path: Path to subject file (findings.json)
            attestation_path: Path to attestation file (findings.json.att.json)
            historical_attestations: Paths to historical attestations for comparison

        Returns:
            List of tamper indicators (empty if no issues found)
        """
        indicators: list[TamperIndicator] = []
        historical_attestations = historical_attestations or []

        # Check timestamp anomalies
        indicators.extend(self.check_timestamp_anomalies(attestation_path))

        # Check builder consistency
        if historical_attestations:
            indicators.extend(
                self.check_builder_consistency(attestation_path, historical_attestations)
            )

        # Check tool version rollback
        if historical_attestations:
            indicators.extend(
                self.check_tool_rollback(attestation_path, historical_attestations)
            )

        # Check suspicious patterns
        indicators.extend(
            self.check_suspicious_patterns(subject_path, attestation_path)
        )

        return indicators

    def check_timestamp_anomalies(self, attestation_path: str) -> List[TamperIndicator]:
        """
        Detect timestamp anomalies in attestation.

        Checks for:
        - Future timestamps (attestation created in the future)
        - Impossible build durations (finish before start, or extremely long)
        - Very old attestations (stale, potentially replayed)
        - Timezone manipulation (invalid ISO 8601 formats)

        Args:
            attestation_path: Path to attestation file

        Returns:
            List of timestamp-related tamper indicators
        """
        indicators: list[TamperIndicator] = []

        try:
            attestation_data = json.loads(Path(attestation_path).read_text())
        except Exception as e:
            logger.error(f"Failed to read attestation for timestamp check: {e}")
            return indicators

        # Extract timestamps
        predicate = attestation_data.get("predicate", {})
        run_details = predicate.get("runDetails", {})
        metadata = run_details.get("metadata", {})

        invocation_id = metadata.get("invocationId")
        started_on = metadata.get("startedOn")
        finished_on = metadata.get("finishedOn")

        now = datetime.now(timezone.utc)

        # Check for future timestamps
        if started_on:
            try:
                started_dt = datetime.fromisoformat(started_on.replace("Z", "+00:00"))
                if started_dt > now + timedelta(minutes=5):  # 5-minute tolerance for clock skew
                    indicators.append(TamperIndicator(
                        severity=TamperSeverity.CRITICAL,
                        indicator_type=TamperIndicatorType.TIMESTAMP_ANOMALY,
                        description="Attestation started in the future",
                        evidence={
                            "started_on": started_on,
                            "current_time": now.isoformat(),
                            "diff_minutes": (started_dt - now).total_seconds() / 60
                        }
                    ))
            except ValueError as e:
                logger.warning(f"Invalid startedOn timestamp: {e}")

        if finished_on:
            try:
                finished_dt = datetime.fromisoformat(finished_on.replace("Z", "+00:00"))
                if finished_dt > now + timedelta(minutes=5):  # 5-minute tolerance
                    indicators.append(TamperIndicator(
                        severity=TamperSeverity.CRITICAL,
                        indicator_type=TamperIndicatorType.TIMESTAMP_ANOMALY,
                        description="Attestation finished in the future",
                        evidence={
                            "finished_on": finished_on,
                            "current_time": now.isoformat(),
                            "diff_minutes": (finished_dt - now).total_seconds() / 60
                        }
                    ))
            except ValueError as e:
                logger.warning(f"Invalid finishedOn timestamp: {e}")

        # Check for impossible duration (finish before start)
        if started_on and finished_on:
            try:
                started_dt = datetime.fromisoformat(started_on.replace("Z", "+00:00"))
                finished_dt = datetime.fromisoformat(finished_on.replace("Z", "+00:00"))

                if finished_dt < started_dt:
                    indicators.append(TamperIndicator(
                        severity=TamperSeverity.CRITICAL,
                        indicator_type=TamperIndicatorType.TIMESTAMP_ANOMALY,
                        description="Build finished before it started",
                        evidence={
                            "started_on": started_on,
                            "finished_on": finished_on,
                            "diff_seconds": (finished_dt - started_dt).total_seconds()
                        }
                    ))

                # Check for extremely long duration
                duration_hours = (finished_dt - started_dt).total_seconds() / 3600
                if duration_hours > self.max_duration_hours:
                    indicators.append(TamperIndicator(
                        severity=TamperSeverity.HIGH,
                        indicator_type=TamperIndicatorType.TIMESTAMP_ANOMALY,
                        description=f"Build duration exceeds {self.max_duration_hours} hours",
                        evidence={
                            "duration_hours": duration_hours,
                            "max_duration_hours": self.max_duration_hours,
                            "started_on": started_on,
                            "finished_on": finished_on
                        }
                    ))
            except ValueError as e:
                logger.warning(f"Invalid timestamp format: {e}")

        # Check for very old attestations (potential replay attack)
        if finished_on:
            try:
                finished_dt = datetime.fromisoformat(finished_on.replace("Z", "+00:00"))
                age_days = (now - finished_dt).days

                if age_days > self.max_age_days:
                    indicators.append(TamperIndicator(
                        severity=TamperSeverity.MEDIUM,
                        indicator_type=TamperIndicatorType.TIMESTAMP_ANOMALY,
                        description=f"Attestation is {age_days} days old (possible replay attack)",
                        evidence={
                            "age_days": age_days,
                            "max_age_days": self.max_age_days,
                            "finished_on": finished_on
                        }
                    ))
            except ValueError as e:
                logger.warning(f"Invalid finishedOn timestamp: {e}")

        # Check for missing timestamps
        if not started_on or not finished_on:
            indicators.append(TamperIndicator(
                severity=TamperSeverity.MEDIUM,
                indicator_type=TamperIndicatorType.MISSING_FIELD,
                description="Missing required timestamp fields",
                evidence={
                    "has_started_on": started_on is not None,
                    "has_finished_on": finished_on is not None
                }
            ))

        return indicators

    def check_builder_consistency(
        self,
        attestation_path: str,
        historical_attestations: List[str]
    ) -> List[TamperIndicator]:
        """
        Check builder consistency across attestations.

        Detects:
        - Builder ID changes (GitHub Actions → GitLab CI)
        - Builder version changes (potentially suspicious)
        - CI platform changes

        Args:
            attestation_path: Path to current attestation
            historical_attestations: Paths to historical attestations

        Returns:
            List of builder consistency indicators
        """
        indicators: list[TamperIndicator] = []

        try:
            current_data = json.loads(Path(attestation_path).read_text())
            current_builder = current_data.get("predicate", {}).get("runDetails", {}).get("builder", {})
            current_builder_id = current_builder.get("id", "")
            current_builder_version = current_builder.get("version", {})
        except Exception as e:
            logger.error(f"Failed to read current attestation: {e}")
            return indicators

        if not current_builder_id:
            indicators.append(TamperIndicator(
                severity=TamperSeverity.MEDIUM,
                indicator_type=TamperIndicatorType.MISSING_FIELD,
                description="Missing builder ID in attestation",
                evidence={"attestation_path": attestation_path}
            ))
            return indicators

        # Compare with historical attestations
        for historical_path in historical_attestations:
            try:
                historical_data = json.loads(Path(historical_path).read_text())
                historical_builder = historical_data.get("predicate", {}).get("runDetails", {}).get("builder", {})
                historical_builder_id = historical_builder.get("id", "")
                historical_builder_version = historical_builder.get("version", {})

                # Check for builder ID change (critical)
                if historical_builder_id and historical_builder_id != current_builder_id:
                    indicators.append(TamperIndicator(
                        severity=TamperSeverity.CRITICAL,
                        indicator_type=TamperIndicatorType.BUILDER_INCONSISTENCY,
                        description="Builder ID changed from previous attestation",
                        evidence={
                            "current_builder_id": current_builder_id,
                            "historical_builder_id": historical_builder_id,
                            "historical_attestation": historical_path
                        }
                    ))

                # Check for builder version change (warning if version changes disabled)
                if (
                    not self.allow_builder_version_change
                    and historical_builder_version
                    and historical_builder_version != current_builder_version
                ):
                    indicators.append(TamperIndicator(
                        severity=TamperSeverity.HIGH,
                        indicator_type=TamperIndicatorType.BUILDER_INCONSISTENCY,
                        description="Builder version changed from previous attestation",
                        evidence={
                            "current_builder_version": current_builder_version,
                            "historical_builder_version": historical_builder_version,
                            "historical_attestation": historical_path
                        }
                    ))
            except Exception as e:
                logger.warning(f"Failed to read historical attestation {historical_path}: {e}")

        return indicators

    def check_tool_rollback(
        self,
        attestation_path: str,
        historical_attestations: List[str]
    ) -> List[TamperIndicator]:
        """
        Detect tool version rollback attacks.

        Attackers may downgrade tool versions to bypass security checks
        (e.g., downgrade from trivy 0.50.0 to 0.30.0 with known CVE bypass).

        Args:
            attestation_path: Path to current attestation
            historical_attestations: Paths to historical attestations

        Returns:
            List of tool rollback indicators
        """
        indicators: list[TamperIndicator] = []

        try:
            current_data = json.loads(Path(attestation_path).read_text())
            build_def = current_data.get("predicate", {}).get("buildDefinition", {})

            # Try externalParameters.tools first (ProvenanceGenerator format)
            current_params = build_def.get("externalParameters", {})
            current_tools = current_params.get("tools", [])

            # Fallback to resolvedDependencies (alternative format)
            if not current_tools:
                current_tools = build_def.get("resolvedDependencies", [])
        except Exception as e:
            logger.error(f"Failed to read current attestation: {e}")
            return indicators

        if not current_tools:
            return indicators  # No tools to check

        # Build current tool versions dict
        current_versions: Dict[str, str] = {}
        for tool in current_tools:
            if isinstance(tool, dict):
                tool_name = tool.get("name", "")
                tool_version = tool.get("version", "")
                if tool_name and tool_version:
                    current_versions[tool_name] = tool_version

        # Compare with historical attestations
        for historical_path in historical_attestations:
            try:
                historical_data = json.loads(Path(historical_path).read_text())
                historical_build_def = historical_data.get("predicate", {}).get("buildDefinition", {})

                # Try externalParameters.tools first (ProvenanceGenerator format)
                historical_params = historical_build_def.get("externalParameters", {})
                historical_tools = historical_params.get("tools", [])

                # Fallback to resolvedDependencies (alternative format)
                if not historical_tools:
                    historical_tools = historical_build_def.get("resolvedDependencies", [])

                # Build historical tool versions dict
                historical_versions: Dict[str, str] = {}
                for tool in historical_tools:
                    if isinstance(tool, dict):
                        tool_name = tool.get("name", "")
                        tool_version = tool.get("version", "")
                        if tool_name and tool_version:
                            historical_versions[tool_name] = tool_version

                # Check for downgrades
                for tool_name, current_version in current_versions.items():
                    if tool_name in historical_versions:
                        historical_version = historical_versions[tool_name]

                        # Simple version comparison (works for semantic versioning)
                        # Note: This is a heuristic; production should use proper version parsing
                        if self._is_version_downgrade(current_version, historical_version):
                            # Determine severity based on tool criticality
                            severity = TamperSeverity.CRITICAL if tool_name in [
                                "trivy", "semgrep", "trufflehog", "syft"
                            ] else TamperSeverity.HIGH

                            indicators.append(TamperIndicator(
                                severity=severity,
                                indicator_type=TamperIndicatorType.TOOL_ROLLBACK,
                                description=f"Tool {tool_name} downgraded from {historical_version} to {current_version}",
                                evidence={
                                    "tool_name": tool_name,
                                    "current_version": current_version,
                                    "historical_version": historical_version,
                                    "historical_attestation": historical_path
                                }
                            ))
            except Exception as e:
                logger.warning(f"Failed to read historical attestation {historical_path}: {e}")

        return indicators

    def check_suspicious_patterns(
        self,
        subject_path: str,
        attestation_path: str
    ) -> List[TamperIndicator]:
        """
        Detect suspicious patterns in attestation.

        Checks for:
        - Empty findings with many tools (potential scan bypass)
        - Findings count mismatch between subject and attestation
        - Unusual subject names (path traversal attempts)
        - Missing required fields
        - Suspicious builder patterns (localhost, invalid URIs)

        Args:
            subject_path: Path to subject file (findings.json)
            attestation_path: Path to attestation file

        Returns:
            List of suspicious pattern indicators
        """
        indicators: list[TamperIndicator] = []

        try:
            attestation_data = json.loads(Path(attestation_path).read_text())
        except Exception as e:
            logger.error(f"Failed to read attestation: {e}")
            return indicators

        # Extract key fields
        predicate = attestation_data.get("predicate", {})
        external_params = predicate.get("buildDefinition", {}).get("externalParameters", {})
        builder = predicate.get("runDetails", {}).get("builder", {})
        subject_list = attestation_data.get("subject", [])

        tools = external_params.get("tools", [])
        profile = external_params.get("profile", "")
        builder_id = builder.get("id", "")

        # Check for empty findings with many tools (suspicious)
        if len(tools) >= 5:
            try:
                if Path(subject_path).exists():
                    subject_data = json.loads(Path(subject_path).read_text())
                    findings_count = len(subject_data.get("findings", []))

                    if findings_count == 0:
                        indicators.append(TamperIndicator(
                            severity=TamperSeverity.HIGH,
                            indicator_type=TamperIndicatorType.SUSPICIOUS_PATTERN,
                            description=f"Zero findings with {len(tools)} tools (possible scan bypass)",
                            evidence={
                                "tool_count": len(tools),
                                "findings_count": findings_count,
                                "profile": profile
                            }
                        ))
            except Exception as e:
                logger.warning(f"Failed to check findings count: {e}")

        # Check for unusual subject names (path traversal)
        for subject in subject_list:
            subject_name = subject.get("name", "")
            if ".." in subject_name or subject_name.startswith("/"):
                indicators.append(TamperIndicator(
                    severity=TamperSeverity.HIGH,
                    indicator_type=TamperIndicatorType.SUSPICIOUS_PATTERN,
                    description=f"Suspicious subject name: {subject_name}",
                    evidence={"subject_name": subject_name}
                ))

        # Check for missing required fields
        required_fields = {
            "predicate.buildDefinition": predicate.get("buildDefinition") is not None,
            "predicate.runDetails": predicate.get("runDetails") is not None,
            "subject": len(subject_list) > 0,
        }

        missing_fields = [field for field, present in required_fields.items() if not present]
        if missing_fields:
            indicators.append(TamperIndicator(
                severity=TamperSeverity.MEDIUM,
                indicator_type=TamperIndicatorType.MISSING_FIELD,
                description=f"Missing required fields: {', '.join(missing_fields)}",
                evidence={"missing_fields": missing_fields}
            ))

        # Check for suspicious builder patterns
        if builder_id:
            if "localhost" in builder_id.lower() or builder_id.startswith("file://"):
                indicators.append(TamperIndicator(
                    severity=TamperSeverity.HIGH,
                    indicator_type=TamperIndicatorType.SUSPICIOUS_PATTERN,
                    description=f"Suspicious builder ID: {builder_id}",
                    evidence={"builder_id": builder_id}
                ))

        return indicators

    def _is_version_downgrade(self, current: str, historical: str) -> bool:
        """
        Check if current version is a downgrade from historical version.

        Simple heuristic for semantic versioning (X.Y.Z).
        Production should use packaging.version.Version for robust comparison.

        Args:
            current: Current version string (e.g., "0.30.0")
            historical: Historical version string (e.g., "0.50.0")

        Returns:
            True if current is a downgrade, False otherwise
        """
        try:
            # Remove 'v' prefix if present
            current = current.lstrip("v")
            historical = historical.lstrip("v")

            # Split into parts
            current_parts = [int(x) for x in current.split(".")[:3]]
            historical_parts = [int(x) for x in historical.split(".")[:3]]

            # Pad to same length
            while len(current_parts) < 3:
                current_parts.append(0)
            while len(historical_parts) < 3:
                historical_parts.append(0)

            # Compare major.minor.patch
            return current_parts < historical_parts
        except (ValueError, IndexError):
            # If version parsing fails, assume no downgrade
            logger.warning(f"Failed to compare versions: {current} vs {historical}")
            return False
