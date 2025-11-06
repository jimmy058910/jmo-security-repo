#!/usr/bin/env python3
"""
Developer attribution via git blame integration.

Analyzes git history to attribute security finding remediation efforts
to developers and teams. Provides insights into:
- Top remediators
- Remediation velocity by developer
- Team performance metrics
- Focus areas per developer

Phase 6 of Trend Analysis feature (#4).
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class DeveloperStats:
    """Statistics for a single developer."""

    name: str
    email: str
    findings_resolved: int = 0
    findings_introduced: int = 0
    focus_areas: List[str] = field(default_factory=list)  # File paths
    top_tools: List[str] = field(default_factory=list)  # Tools finding their fixes
    cwe_categories: Set[str] = field(default_factory=set)  # CWE IDs addressed
    severity_breakdown: Dict[str, int] = field(
        default_factory=dict
    )  # Severity -> count

    @property
    def net_contribution(self) -> int:
        """Net security contribution (resolved - introduced)."""
        return self.findings_resolved - self.findings_introduced


@dataclass
class TeamStats:
    """Aggregated statistics for a team."""

    team_name: str
    members: List[str] = field(default_factory=list)  # Emails
    total_resolved: int = 0
    total_introduced: int = 0
    top_remediators: List[DeveloperStats] = field(default_factory=list)

    @property
    def net_contribution(self) -> int:
        """Net team security contribution."""
        return self.total_resolved - self.total_introduced

    @property
    def member_count(self) -> int:
        """Number of team members."""
        return len(self.members)


# ============================================================================
# Main Attribution Class
# ============================================================================


class DeveloperAttribution:
    """
    Analyze developer contributions to security remediation via git blame.

    Example usage:
        attrib = DeveloperAttribution(Path("/path/to/repo"))
        dev_stats = attrib.analyze_remediation_by_developer(
            resolved_fingerprints={"fp1", "fp2"},
            history_db=db
        )
        for dev in dev_stats[:10]:
            print(f"{dev.name}: {dev.findings_resolved} resolved")
    """

    def __init__(self, repo_path: Path):
        """
        Initialize developer attribution analyzer.

        Args:
            repo_path: Path to git repository root
        """
        self.repo_path = Path(repo_path)
        self._validate_git_repo()

    def _validate_git_repo(self) -> None:
        """Validate that repo_path is a git repository."""
        if not (self.repo_path / ".git").exists():
            raise ValueError(f"Not a git repository: {self.repo_path}")

    def analyze_remediation_by_developer(
        self, resolved_fingerprints: Set[str], history_db
    ) -> List[DeveloperStats]:
        """
        Attribute resolved findings to developers via git blame.

        This is the main entry point for developer attribution analysis.
        It examines the git blame history for lines where findings were
        resolved and attributes credit to the developers who made the fixes.

        Args:
            resolved_fingerprints: Set of fingerprint IDs for resolved findings
            history_db: HistoryDatabase instance for finding lookups

        Returns:
            List of DeveloperStats sorted by net_contribution (desc)

        Example:
            resolved = {"abc123", "def456"}
            dev_stats = attrib.analyze_remediation_by_developer(resolved, db)
            print(f"Top remediator: {dev_stats[0].name}")
        """
        developer_map: Dict[str, Dict] = {}  # email -> stats dict

        logger.info(
            f"Analyzing {len(resolved_fingerprints)} resolved findings for attribution"
        )

        for fp in resolved_fingerprints:
            # Get finding details from database
            finding = history_db.get_finding_by_fingerprint(fp)
            if not finding:
                logger.debug(f"Finding not found in DB: {fp}")
                continue

            file_path = finding.get("path")
            line_num = finding.get("start_line")
            if not file_path or not line_num:
                logger.debug(f"Missing location for finding: {fp}")
                continue

            # Get git blame for this line
            author = self._git_blame_line(file_path, line_num)
            if not author:
                logger.debug(f"No git blame data for {file_path}:{line_num}")
                continue

            # Initialize developer entry if needed
            email = author["email"]
            if email not in developer_map:
                developer_map[email] = {
                    "name": author["name"],
                    "email": email,
                    "resolved": [],
                    "focus_files": set(),
                    "tools": set(),
                    "cwes": set(),
                    "severities": {},
                }

            # Update developer statistics
            dev = developer_map[email]
            dev["resolved"].append(fp)
            dev["focus_files"].add(file_path)

            tool = finding.get("tool", "unknown")
            dev["tools"].add(tool)

            # Track CWE categories if available
            risk = finding.get("risk", {})
            if isinstance(risk, dict):
                cwe = risk.get("cwe")
                if cwe:
                    dev["cwes"].add(cwe)

            # Track severity breakdown
            severity = finding.get("severity", "UNKNOWN")
            dev["severities"][severity] = dev["severities"].get(severity, 0) + 1

        # Convert to DeveloperStats objects
        results = []
        for email, data in developer_map.items():
            # Get top 5 focus areas (files)
            focus_areas = sorted(data["focus_files"])[:5]

            # Get top 3 tools by usage
            top_tools = sorted(data["tools"])[:3]

            results.append(
                DeveloperStats(
                    name=data["name"],
                    email=email,
                    findings_resolved=len(data["resolved"]),
                    findings_introduced=0,  # Future enhancement
                    focus_areas=focus_areas,
                    top_tools=top_tools,
                    cwe_categories=data["cwes"],
                    severity_breakdown=dict(data["severities"]),
                )
            )

        # Sort by net contribution (descending)
        results.sort(key=lambda x: x.net_contribution, reverse=True)

        logger.info(f"Attributed findings to {len(results)} developers")
        return results

    def _git_blame_line(self, file_path: str, line_num: int) -> Optional[Dict]:
        """
        Run git blame for a specific line in a file.

        Uses --porcelain format for easier parsing. Returns author info
        for the line at the given line number.

        Args:
            file_path: Path to file relative to repo root
            line_num: Line number (1-indexed)

        Returns:
            Dictionary with 'name' and 'email' keys, or None if not found

        Example:
            author = self._git_blame_line("src/main.py", 42)
            print(f"{author['name']} <{author['email']}>")
        """
        try:
            cmd = [
                "git",
                "blame",
                "-L",
                f"{line_num},{line_num}",
                "--porcelain",
                str(file_path),
            ]

            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                # File might have been deleted or renamed
                logger.debug(
                    f"git blame failed for {file_path}:{line_num}: {result.stderr.strip()}"
                )
                return None

            # Parse porcelain output
            # Format:
            #   <commit-hash> <line-num> <final-line-num> <num-lines>
            #   author <name>
            #   author-mail <<email>>
            #   ...
            lines = result.stdout.split("\n")
            author_name = None
            author_email = None

            for line in lines:
                if line.startswith("author "):
                    author_name = line[7:]  # Skip "author "
                elif line.startswith("author-mail "):
                    # Remove angle brackets
                    author_email = line[12:].strip("<>")

            if author_name and author_email:
                return {"name": author_name, "email": author_email}

            logger.debug(f"Incomplete git blame output for {file_path}:{line_num}")

        except subprocess.TimeoutExpired:
            logger.warning(f"git blame timeout for {file_path}:{line_num}")
        except Exception as e:
            logger.error(f"git blame error for {file_path}:{line_num}: {e}")

        return None

    def aggregate_by_team(
        self, developer_stats: List[DeveloperStats], team_mapping: Dict[str, str]
    ) -> List[TeamStats]:
        """
        Aggregate developer statistics by team.

        Args:
            developer_stats: List of individual developer stats
            team_mapping: Dictionary mapping email -> team_name

        Returns:
            List of TeamStats sorted by net_contribution (desc)

        Example:
            team_mapping = {
                "alice@example.com": "Backend",
                "bob@example.com": "Backend",
                "charlie@example.com": "Frontend",
            }
            team_stats = attrib.aggregate_by_team(dev_stats, team_mapping)
            for team in team_stats:
                print(f"{team.team_name}: {team.total_resolved} resolved")
        """
        team_map: Dict[str, Dict] = {}  # team_name -> aggregated data

        for dev in developer_stats:
            team_name = team_mapping.get(dev.email, "Unknown")

            if team_name not in team_map:
                team_map[team_name] = {
                    "members": [],
                    "resolved": 0,
                    "introduced": 0,
                    "developers": [],
                }

            team = team_map[team_name]
            team["members"].append(dev.email)
            team["resolved"] += dev.findings_resolved
            team["introduced"] += dev.findings_introduced
            team["developers"].append(dev)

        # Convert to TeamStats objects
        results = []
        for team_name, data in team_map.items():
            # Get top 5 remediators for this team
            top_remediators = sorted(
                data["developers"], key=lambda x: x.net_contribution, reverse=True
            )[:5]

            results.append(
                TeamStats(
                    team_name=team_name,
                    members=data["members"],
                    total_resolved=data["resolved"],
                    total_introduced=data["introduced"],
                    top_remediators=top_remediators,
                )
            )

        # Sort by net contribution (descending)
        results.sort(key=lambda x: x.net_contribution, reverse=True)

        logger.info(f"Aggregated stats for {len(results)} teams")
        return results

    def get_developer_velocity(
        self, developer_email: str, history_db, days: int = 30
    ) -> Dict[str, float]:
        """
        Calculate remediation velocity metrics for a specific developer.

        Args:
            developer_email: Email of developer to analyze
            history_db: HistoryDatabase instance
            days: Number of days to analyze (default: 30)

        Returns:
            Dictionary with velocity metrics:
                - findings_per_day: Average findings resolved per day
                - active_days: Number of days with at least one fix
                - avg_severity: Average severity score of fixes
                - fix_frequency: Fixes per active day

        Example:
            velocity = attrib.get_developer_velocity("alice@example.com", db, 30)
            print(f"Fixes per day: {velocity['findings_per_day']:.2f}")
        """
        # Future enhancement: Track remediation velocity over time
        # This would require storing timestamps for when findings were resolved
        # and correlating them with developer commits.

        logger.info(
            f"Developer velocity analysis not yet implemented for {developer_email}"
        )

        return {
            "findings_per_day": 0.0,
            "active_days": 0,
            "avg_severity": 0.0,
            "fix_frequency": 0.0,
        }


# ============================================================================
# Helper Functions
# ============================================================================


def load_team_mapping(team_file_path: Path) -> Dict[str, str]:
    """
    Load team mapping from JSON file.

    Args:
        team_file_path: Path to JSON file with email -> team mappings

    Returns:
        Dictionary mapping developer email to team name

    Example file format (teams.json):
        {
            "alice@example.com": "Backend Team",
            "bob@example.com": "Backend Team",
            "charlie@example.com": "Frontend Team",
            "diana@example.com": "Security Team"
        }
    """
    import json

    with open(team_file_path, "r") as f:
        return json.load(f)  # type: ignore[no-any-return]


def format_developer_stats(dev: DeveloperStats, rank: int = 0) -> str:
    """
    Format developer statistics for display.

    Args:
        dev: DeveloperStats object
        rank: Optional ranking number (0 = no rank)

    Returns:
        Formatted string with developer stats

    Example output:
        1. Alice Smith <alice@example.com>
           Resolved: 45 findings | Net: +42
           Focus: src/api/auth.py, src/api/users.py
           Tools: semgrep, trivy, bandit
           CWEs: CWE-79, CWE-89, CWE-798
    """
    lines = []

    # Header with rank
    rank_str = f"{rank}. " if rank > 0 else ""
    lines.append(f"{rank_str}{dev.name} <{dev.email}>")

    # Contribution summary
    lines.append(
        f"   Resolved: {dev.findings_resolved} findings | "
        f"Net: {dev.net_contribution:+d}"
    )

    # Focus areas (top files)
    if dev.focus_areas:
        focus = ", ".join(dev.focus_areas[:3])
        lines.append(f"   Focus: {focus}")

    # Top tools
    if dev.top_tools:
        tools = ", ".join(dev.top_tools)
        lines.append(f"   Tools: {tools}")

    # CWE categories
    if dev.cwe_categories:
        cwes = ", ".join(sorted(dev.cwe_categories)[:5])
        lines.append(f"   CWEs: {cwes}")

    # Severity breakdown
    if dev.severity_breakdown:
        severity_parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = dev.severity_breakdown.get(sev, 0)
            if count > 0:
                severity_parts.append(f"{sev}: {count}")
        if severity_parts:
            lines.append(f"   Severity: {', '.join(severity_parts)}")

    return "\n".join(lines)


def format_team_stats(team: TeamStats, rank: int = 0) -> str:
    """
    Format team statistics for display.

    Args:
        team: TeamStats object
        rank: Optional ranking number (0 = no rank)

    Returns:
        Formatted string with team stats

    Example output:
        1. Backend Team
           Members: 5 | Resolved: 128 findings | Net: +115
           Top remediators:
             - Alice Smith: 45 findings
             - Bob Johnson: 38 findings
    """
    lines = []

    # Header with rank
    rank_str = f"{rank}. " if rank > 0 else ""
    lines.append(f"{rank_str}{team.team_name}")

    # Team summary
    lines.append(
        f"   Members: {team.member_count} | "
        f"Resolved: {team.total_resolved} findings | "
        f"Net: {team.net_contribution:+d}"
    )

    # Top remediators
    if team.top_remediators:
        lines.append("   Top remediators:")
        for dev in team.top_remediators[:3]:
            lines.append(f"     - {dev.name}: {dev.findings_resolved} findings")

    return "\n".join(lines)
