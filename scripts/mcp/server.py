"""
JMo Security MCP Server

AI-powered remediation orchestration using Model Context Protocol (MCP).
Provides standardized interface for AI tools (GitHub Copilot, Claude Code, OpenAI Codex)
to query security findings and suggest fixes.

Architecture:
- Framework: FastMCP (Official Anthropic SDK)
- Tools: get_security_findings, apply_fix, mark_resolved
- Resources: finding://{id} for full context
- Transport: stdio, HTTP, SSE

Usage:
    # Development mode (stdio transport)
    uv run mcp dev scripts/mcp/server.py

    # Production mode (via jmo CLI)
    jmo mcp-server --results-dir ./results --repo-root .

Environment Variables:
    MCP_RESULTS_DIR: Path to results directory (default: ./results)
    MCP_REPO_ROOT: Path to repository root (default: .)
    MCP_API_KEY: API key for authentication (optional, dev mode if not set)
"""

import os
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

# NOTE: This import will fail until mcp[cli] is installed
# To install: pip install "mcp[cli]" or uv add "mcp[cli]"
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    raise ImportError(
        "MCP SDK not installed. Install with:\n"
        "  pip install 'mcp[cli]>=1.0.0'\n"
        "or:\n"
        "  uv add 'mcp[cli]>=1.0.0'"
    )

from scripts.mcp.utils.findings_loader import FindingsLoader
from scripts.mcp.utils.source_context import SourceContextExtractor

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Get configuration from environment
RESULTS_DIR = Path(os.getenv("MCP_RESULTS_DIR", "./results"))
REPO_ROOT = Path(os.getenv("MCP_REPO_ROOT", "."))

logger.info(f"MCP Server initialized")
logger.info(f"Results directory: {RESULTS_DIR.resolve()}")
logger.info(f"Repository root: {REPO_ROOT.resolve()}")

# Initialize MCP server
mcp = FastMCP("JMo Security")

# Initialize utilities (lazy-loaded on first use to handle missing files gracefully)
_findings_loader: Optional[FindingsLoader] = None
_context_extractor: Optional[SourceContextExtractor] = None


def get_findings_loader() -> FindingsLoader:
    """Get or initialize FindingsLoader (lazy loading)"""
    global _findings_loader
    if _findings_loader is None:
        _findings_loader = FindingsLoader(RESULTS_DIR)
    return _findings_loader


def get_context_extractor() -> SourceContextExtractor:
    """Get or initialize SourceContextExtractor (lazy loading)"""
    global _context_extractor
    if _context_extractor is None:
        _context_extractor = SourceContextExtractor(REPO_ROOT)
    return _context_extractor


# ============================================================================
# MCP Tools (Functions callable by AI agents)
# ============================================================================


@mcp.tool()
def get_security_findings(
    severity: Optional[list[str]] = None,
    tool: Optional[str] = None,
    rule_id: Optional[str] = None,
    path: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """
    Query security findings with filters.

    Use this tool to retrieve security vulnerabilities, secrets, misconfigurations,
    and other findings from JMo Security scans. Supports filtering and pagination.

    Args:
        severity: Filter by severity levels (e.g., ["HIGH", "CRITICAL"])
                 Valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO
        tool: Filter by tool name (e.g., "semgrep", "trivy", "trufflehog")
        rule_id: Filter by rule ID (e.g., "CWE-79" for XSS)
        path: Filter by file path (substring match, e.g., "src/api")
        limit: Maximum findings to return (default: 100, max: 1000)
        offset: Pagination offset (default: 0)

    Returns:
        Dictionary with:
        - findings: List of security findings (CommonFinding schema v1.2.0)
        - total: Total count of findings matching filters
        - limit: Applied limit
        - offset: Applied offset

    Example:
        >>> get_security_findings(severity=["HIGH", "CRITICAL"], limit=10)
        {
            "findings": [
                {
                    "id": "fingerprint-abc123",
                    "ruleId": "CWE-79",
                    "severity": "HIGH",
                    "tool": {"name": "semgrep", "version": "1.45.0"},
                    "location": {"path": "src/app.js", "startLine": 42},
                    "message": "Potential XSS vulnerability in user input"
                },
                ...
            ],
            "total": 3,
            "limit": 10,
            "offset": 0
        }
    """
    try:
        loader = get_findings_loader()
        all_findings = loader.load_findings()

        # Apply filters
        filtered = loader.filter_findings(
            all_findings,
            severity=severity,
            tool=tool,
            rule_id=rule_id,
            path=path,
            limit=min(limit, 1000),  # Cap at 1000
            offset=offset,
        )

        # Get total count matching filters (before pagination)
        total_matching = len(
            loader.filter_findings(
                all_findings,
                severity=severity,
                tool=tool,
                rule_id=rule_id,
                path=path,
                limit=999999,  # No limit for count
                offset=0,
            )
        )

        logger.info(
            f"get_security_findings: returned {len(filtered)} findings "
            f"(total matching: {total_matching}, filters: severity={severity}, "
            f"tool={tool}, rule_id={rule_id}, path={path})"
        )

        return {
            "findings": filtered,
            "total": total_matching,
            "limit": limit,
            "offset": offset,
        }

    except FileNotFoundError as e:
        logger.error(f"Findings file not found: {e}")
        raise ValueError(
            "No scan results found. Run a scan first: jmo scan --repo <path>"
        )
    except Exception as e:
        logger.error(f"Error querying findings: {e}", exc_info=True)
        raise


@mcp.tool()
def apply_fix(
    finding_id: str,
    patch: str,
    confidence: float,
    explanation: str,
    dry_run: bool = False,
) -> dict:
    """
    Apply AI-suggested fix patch to resolve a security finding.

    IMPORTANT: Always use dry_run=True first to preview the patch before applying!

    Args:
        finding_id: Fingerprint ID of the finding to fix
        patch: Unified diff patch (git diff format)
        confidence: AI confidence score (0.0-1.0) - recommend 0.9+ for auto-apply
        explanation: Human-readable explanation of the fix
        dry_run: Preview patch without applying (default: False, RECOMMEND True first)

    Returns:
        Dictionary with:
        - success: Boolean indicating if patch was applied
        - applied_at: ISO timestamp of application (if successful)
        - file_modified: Path to modified file (if successful)
        - dry_run_preview: Patch preview (if dry_run=True)
        - error: Error message (if failed)

    Security Note:
        This function modifies source code. Use with caution and review diffs carefully.
        High-confidence fixes (≥0.9) are safer for auto-application.

    Example:
        >>> # Step 1: Preview patch
        >>> result = apply_fix(
        ...     finding_id="fingerprint-abc123",
        ...     patch="diff --git a/src/app.js...\\n-  res.send(userInput)\\n+  res.send(sanitize(userInput))",
        ...     confidence=0.95,
        ...     explanation="Added sanitization to prevent XSS",
        ...     dry_run=True
        ... )
        >>> print(result["dry_run_preview"])

        >>> # Step 2: Apply if preview looks good
        >>> result = apply_fix(..., dry_run=False)
    """
    try:
        # Verify finding exists
        loader = get_findings_loader()
        finding = loader.get_finding_by_id(finding_id)

        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        if dry_run:
            logger.info(f"apply_fix: dry-run preview for {finding_id}")
            return {"success": True, "dry_run_preview": patch}

        # TODO: Implement patch application
        # This will be implemented in Phase 2 with:
        # 1. Patch validation (no shell commands, path traversal)
        # 2. Backup creation
        # 3. Patch application via subprocess
        # 4. Rollback mechanism if tests fail
        # 5. Update .jmo/fix-history.json

        logger.warning(f"apply_fix: patch application not yet implemented (finding: {finding_id})")

        return {"success": False, "error": "Patch application not yet implemented (coming in Phase 2)"}

    except ValueError as e:
        logger.error(f"apply_fix validation error: {e}")
        raise
    except Exception as e:
        logger.error(f"Error applying fix: {e}", exc_info=True)
        raise


@mcp.tool()
def mark_resolved(
    finding_id: str,
    resolution: str,
    comment: Optional[str] = None,
) -> dict:
    """
    Mark a security finding as resolved.

    Use this to track resolution status without applying a fix (e.g., for
    false positives, accepted risks, or manually fixed issues).

    Args:
        finding_id: Fingerprint ID of the finding
        resolution: Resolution type (valid values: fixed, false_positive, wont_fix, risk_accepted)
        comment: Optional comment explaining the resolution

    Returns:
        Dictionary with:
        - success: Boolean indicating success
        - finding_id: Confirmed finding ID
        - resolution: Applied resolution type
        - timestamp: ISO timestamp of resolution

    Example:
        >>> mark_resolved(
        ...     finding_id="fingerprint-abc123",
        ...     resolution="false_positive",
        ...     comment="This is a test file, not production code"
        ... )
        {
            "success": True,
            "finding_id": "fingerprint-abc123",
            "resolution": "false_positive",
            "timestamp": "2025-11-01T12:00:00Z"
        }
    """
    try:
        # Validate resolution type
        valid_resolutions = ["fixed", "false_positive", "wont_fix", "risk_accepted"]
        if resolution not in valid_resolutions:
            raise ValueError(
                f"Invalid resolution type: {resolution}. "
                f"Valid values: {', '.join(valid_resolutions)}"
            )

        # Verify finding exists
        loader = get_findings_loader()
        finding = loader.get_finding_by_id(finding_id)

        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        # TODO: Implement resolution tracking
        # This will be implemented in Phase 2 with:
        # 1. Create .jmo/resolutions.json
        # 2. Append resolution entry with timestamp
        # 3. Update dashboard to show resolution status
        # 4. Filter resolved findings from future scans

        timestamp = datetime.utcnow().isoformat() + "Z"

        logger.info(
            f"mark_resolved: {finding_id} → {resolution} "
            f"(comment: {comment if comment else 'none'})"
        )

        return {
            "success": True,
            "finding_id": finding_id,
            "resolution": resolution,
            "timestamp": timestamp,
            "note": "Resolution tracking will be persisted in Phase 2",
        }

    except ValueError as e:
        logger.error(f"mark_resolved validation error: {e}")
        raise
    except Exception as e:
        logger.error(f"Error marking finding resolved: {e}", exc_info=True)
        raise


# ============================================================================
# MCP Resources (Data access via URIs)
# ============================================================================


@mcp.resource("finding://{finding_id}")
def get_finding_context(finding_id: str, context_lines: int = 20) -> dict:
    """
    Get full context for a specific security finding.

    Use this resource to retrieve comprehensive information about a finding,
    including source code context, remediation guidance, and related findings.

    URI Pattern: finding://<fingerprint-id>

    Args:
        finding_id: Fingerprint ID of the finding (from get_security_findings)
        context_lines: Number of lines of source code context (default: 20)

    Returns:
        Dictionary with:
        - finding: Complete finding details (CommonFinding schema)
        - source_code: Source code with context
            - path: File path
            - lines: Source code text
            - language: Detected programming language
            - start_line: First line of context
            - end_line: Last line of context
        - remediation: Fix guidance
            - description: How to fix the issue
            - references: Links to OWASP, CWE, documentation
            - cwe: CWE identifier
            - owasp: OWASP Top 10 mappings
        - related_findings: Other findings in same file/CWE (coming in Phase 2)

    Example:
        >>> ctx = get_finding_context("fingerprint-abc123", context_lines=10)
        >>> print(ctx["source_code"]["lines"])  # Shows vulnerable code
        >>> print(ctx["remediation"]["description"])  # Shows fix guidance
    """
    try:
        # Get finding
        loader = get_findings_loader()
        finding = loader.get_finding_by_id(finding_id)

        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        # Extract source code context
        location = finding.get("location", {})
        extractor = get_context_extractor()

        source_context = extractor.get_context(
            file_path=location.get("path", ""),
            start_line=location.get("startLine", 1),
            end_line=location.get("endLine"),
            context_lines=context_lines,
        )

        # Build remediation guidance
        remediation = {
            "description": finding.get("remediation", {}).get("description", ""),
            "references": finding.get("remediation", {}).get("references", []),
            "cwe": finding.get("risk", {}).get("cwe"),
            "owasp": finding.get("compliance", {}).get("owaspTop10_2021", []),
        }

        # TODO: Find related findings (same CWE or same file/line range)
        # This will be implemented in Phase 2 with:
        # 1. Query findings by CWE ID
        # 2. Query findings by file path
        # 3. Rank by similarity
        related_findings: list[dict[str, str]] = []

        logger.info(f"get_finding_context: retrieved context for {finding_id}")

        return {
            "finding": finding,
            "source_code": source_context,
            "remediation": remediation,
            "related_findings": related_findings,
        }

    except ValueError as e:
        logger.error(f"get_finding_context validation error: {e}")
        raise
    except Exception as e:
        logger.error(f"Error getting finding context: {e}", exc_info=True)
        raise


# ============================================================================
# Server Metadata
# ============================================================================


@mcp.tool()
def get_server_info() -> dict:
    """
    Get JMo Security MCP Server metadata and configuration.

    Returns information about the server, scan results, and available tools.

    Returns:
        Dictionary with:
        - version: Server version
        - results_dir: Path to results directory
        - repo_root: Path to repository root
        - total_findings: Total findings in current scan
        - severity_distribution: Findings breakdown by severity
        - available_tools: List of security tools used in scan

    Example:
        >>> info = get_server_info()
        >>> print(f"Total findings: {info['total_findings']}")
        >>> print(f"Critical: {info['severity_distribution']['CRITICAL']}")
    """
    try:
        loader = get_findings_loader()

        return {
            "version": "1.0.0",
            "results_dir": str(RESULTS_DIR.resolve()),
            "repo_root": str(REPO_ROOT.resolve()),
            "total_findings": loader.get_total_count(),
            "severity_distribution": loader.get_severity_distribution(),
            "note": "Use get_security_findings() to query findings with filters",
        }

    except FileNotFoundError:
        return {
            "version": "1.0.0",
            "results_dir": str(RESULTS_DIR.resolve()),
            "repo_root": str(REPO_ROOT.resolve()),
            "total_findings": 0,
            "severity_distribution": {},
            "error": "No scan results found. Run: jmo scan --repo <path>",
        }
    except Exception as e:
        logger.error(f"Error getting server info: {e}", exc_info=True)
        raise


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    # This is called when running: uv run mcp dev scripts/mcp/server.py
    logger.info("Starting JMo Security MCP Server (stdio transport)")
    logger.info(f"Results directory: {RESULTS_DIR.resolve()}")
    logger.info(f"Repository root: {REPO_ROOT.resolve()}")

    # Run MCP server (stdio transport by default for Claude Desktop/GitHub Copilot)
    mcp.run()
