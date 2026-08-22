"""
JMo Security MCP Server

AI-powered remediation orchestration using Model Context Protocol (MCP).
Provides standardized interface for AI tools (GitHub Copilot, Claude Code, OpenAI Codex)
to query security findings and suggest fixes.

Architecture:
- Framework: MCPServer (Official Anthropic SDK; named FastMCP before mcp 2.0)
- Tools: get_security_findings, apply_fix, mark_resolved, query_findings_db,
  get_server_info  (five; this list read "three" until it was counted)
- Resources: finding://{id} for full context
- Transport: stdio only. `mcp.run()` is called with no arguments, which selects
  stdio. This line claimed "stdio, HTTP, SSE"; nothing here starts an HTTP or
  SSE listener.

Not implemented, despite being callable:
- `apply_fix(dry_run=False)` never writes a patch; it returns success=False.
- `mark_resolved` persists nothing; it returns success=False.
Both are documented as such in docs/MCP_SETUP.md. Do not build a workflow on
either until they are.

Usage:
    # Development mode (stdio transport)
    uv run mcp dev scripts/jmo_mcp/jmo_server.py

    # Production mode (via jmo CLI)
    jmo mcp-server --results-dir ./results --repo-root .

Environment Variables:
    MCP_RESULTS_DIR: Path to results directory (default: ./results)
    MCP_REPO_ROOT: Path to repository root (default: .)
    JMO_MCP_API_KEYS: Comma-separated API keys for authentication (optional)
    JMO_MCP_RATE_LIMIT_ENABLED: Enable rate limiting (default: true)
    JMO_MCP_RATE_LIMIT_CAPACITY: Burst capacity in requests (default: 100)
    JMO_MCP_RATE_LIMIT_REFILL_RATE: Tokens per second (default: 1.67 = 100/min)
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path

# NOTE: This import will fail until mcp[cli] is installed
# To install: pip install "mcp[cli]" or uv add "mcp[cli]"
#
# mcp 2.0 renamed the server framework: `mcp.server.fastmcp.FastMCP` became
# `mcp.server.mcpserver.MCPServer` (re-exported from `mcp.server`). There is no
# compatibility shim, so the old path raises ModuleNotFoundError on 2.x.
try:
    from mcp.server import MCPServer
except ImportError:
    raise ImportError(
        "MCP SDK not installed. Install with:\n"
        "  pip install 'mcp[cli]>=1.0.0'\n"
        "or:\n"
        "  uv add 'mcp[cli]>=1.0.0'"
    )

from scripts.jmo_mcp.utils.findings_loader import FindingsLoader
from scripts.jmo_mcp.utils.rate_limiter import RateLimiter
from scripts.jmo_mcp.utils.source_context import SourceContextExtractor

# Configure logging.
#
# `jmo mcp-server` accepts --log-level and --human-logs and exports them as
# MCP_LOG_LEVEL / MCP_HUMAN_LOGS. Until this read existed, both flags were
# parsed, advertised in --help, exported, and then discarded -- the server
# hardcoded INFO and the long format regardless.
_LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}
_LOG_LEVEL = _LOG_LEVELS.get(os.getenv("MCP_LOG_LEVEL", "INFO").upper(), logging.INFO)
_HUMAN_LOGS = os.getenv("MCP_HUMAN_LOGS", "").strip() not in ("", "0", "false", "False")

logging.basicConfig(
    level=_LOG_LEVEL,
    format=(
        "%(levelname)s %(message)s"
        if _HUMAN_LOGS
        else "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    ),
)
logger = logging.getLogger(__name__)

# Get configuration from environment
RESULTS_DIR = Path(os.getenv("MCP_RESULTS_DIR", "./results"))
REPO_ROOT = Path(os.getenv("MCP_REPO_ROOT", "."))

# Authentication configuration.
#
# READ THIS BEFORE TRUSTING THE NAME. These hashes are computed and then never
# compared against anything. MCP's stdio transport hands the tool functions no
# request context, so there is nowhere to read a caller's credential from --
# see `require_rate_limit` below. Keys are kept because the shape is right for
# the day a transport supplies one; nothing here enforces access today.
#
# Bound at MODULE IMPORT: setting JMO_MCP_API_KEYS after this module is
# imported has no effect.
API_KEYS_RAW = os.getenv("JMO_MCP_API_KEYS", "").split(",")
API_KEYS_HASHED = [
    hashlib.sha256(key.strip().encode()).hexdigest()
    for key in API_KEYS_RAW
    if key.strip()
]

# Rate limiting configuration
RATE_LIMIT_ENABLED = os.getenv("JMO_MCP_RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_CAPACITY = int(os.getenv("JMO_MCP_RATE_LIMIT_CAPACITY", "100"))
RATE_LIMIT_REFILL_RATE = float(os.getenv("JMO_MCP_RATE_LIMIT_REFILL_RATE", "1.67"))

logger.info("MCP Server initialized")
logger.info(f"Results directory: {RESULTS_DIR.resolve()}")
logger.info(f"Repository root: {REPO_ROOT.resolve()}")
# This line used to read "Authentication: enabled" whenever JMO_MCP_API_KEYS was
# set, and docs/KNOWN_LIMITATIONS.md told users in bold to read it before
# exposing the server to anything. Measured: with keys set it logged "enabled"
# and then served an unauthenticated caller. A security signal that reads
# positive for a control that does not exist is worse than no signal, because it
# ends the reader's investigation with a confirmation.
if API_KEYS_HASHED:
    logger.warning(
        f"Authentication: NOT ENFORCED -- {len(API_KEYS_HASHED)} key(s) configured "
        "via JMO_MCP_API_KEYS, but no transport supplies a caller credential to "
        "compare them against. EVERY caller is trusted. Do not expose this "
        "server to anything you do not already trust."
    )
else:
    logger.info(
        "Authentication: not enforced (no keys configured). Every caller is trusted."
    )
logger.info(
    f"Rate limiting: {'enabled' if RATE_LIMIT_ENABLED else 'disabled'} "
    f"(capacity={RATE_LIMIT_CAPACITY}, refill_rate={RATE_LIMIT_REFILL_RATE}/s)"
)

# Initialize MCP server
mcp = MCPServer("JMo Security")

# Initialize utilities (lazy-loaded on first use to handle missing files gracefully)
_findings_loader: FindingsLoader | None = None
_context_extractor: SourceContextExtractor | None = None

# Initialize rate limiter (if enabled)
rate_limiter = (
    RateLimiter(capacity=RATE_LIMIT_CAPACITY, refill_rate=RATE_LIMIT_REFILL_RATE)
    if RATE_LIMIT_ENABLED
    else None
)

# Every request is charged to this one bucket. Named so that the absence of
# per-client accounting is visible at the call site rather than looking like a
# placeholder someone forgot to fill in.
_SHARED_BUCKET_ID = "anonymous"


def _server_version() -> str:
    """Report the installed jmo-security version.

    ``get_server_info`` returned a hardcoded "1.0.0" for every release through
    1.0.8 -- the same shape as the frozen ``jmo_version`` chunk 14 found in the
    history writer. Resolved from package metadata so it cannot drift again.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("jmo-security")
    except (ImportError, PackageNotFoundError):  # pragma: no cover - packaging edge
        return "unknown"


def require_rate_limit(func):
    """
    Decorator enforcing the token-bucket rate limit on an MCP entry point.

    This was named ``require_auth_and_rate_limit``, which was the single most
    misleading token in this module: it appeared on every tool and read as
    proof that callers are authenticated. The body never referenced
    ``API_KEYS_HASHED`` and still does not. It is named for what it does.

    Rate limiting:
    - If JMO_MCP_RATE_LIMIT_ENABLED=true, enforces token bucket limits.
    - **One shared bucket**, not one per client. ``RateLimiter`` is keyed by
      client id and is perfectly capable of per-client buckets, but stdio
      transport gives the tool function no request context, so there is no
      caller identity to key on and every request is charged to the same
      ``anonymous`` bucket. One caller can exhaust everyone's budget. The old
      docstring said "Per-client tracking by 'anonymous' identifier", which
      contradicts itself in a single line.
    - Default: 100 requests burst, 1.67 tokens/sec (100/min sustained).

    Authentication: **none**. See ``API_KEYS_HASHED`` above.

    Raises:
        ValueError: If rate limit exceeded
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # One shared bucket -- see the docstring. Not a per-client identifier.
        client_id = _SHARED_BUCKET_ID

        # Rate limiting check
        if rate_limiter:
            if not rate_limiter.check_rate_limit(client_id):
                logger.warning(
                    f"{func.__name__}: Rate limit exceeded (client: {client_id})"
                )
                raise ValueError(
                    f"Rate limit exceeded. Try again later. "
                    f"(Limit: {RATE_LIMIT_CAPACITY} burst, {RATE_LIMIT_REFILL_RATE}/s refill)"
                )
            logger.debug(f"{func.__name__}: Rate limit OK (client: {client_id})")

        # Call the wrapped function
        return func(*args, **kwargs)

    return wrapper


_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", re.MULTILINE)


def _validate_patch(patch: str) -> None:
    """Reject anything that is not a unified diff.

    ``apply_fix(dry_run=True)`` used to echo its ``patch`` argument straight
    back as ``dry_run_preview`` with ``success: True``, whatever it contained --
    measured, it accepted the string ``"rm -rf / ; not a diff"``. A preview is
    shown to a human (or an agent) as "this is the change that would be made";
    a preview of something that is not a diff cannot be reviewed as one.

    Raises:
        ValueError: If *patch* is empty or has no unified-diff hunk header.
    """
    if not patch or not patch.strip():
        raise ValueError("Patch must not be empty")
    if not _HUNK_HEADER_RE.search(patch):
        raise ValueError(
            "Patch is not a unified diff: no hunk header (@@ -n,m +n,m @@) "
            "found. Pass the output of `git diff`."
        )


def _validate_confidence(confidence: float) -> None:
    """Reject a confidence score outside the documented 0.0-1.0 range.

    Both 99.0 and -4.0 were accepted before this check existed, so "recommend
    0.9+ for auto-apply" was advice about a number with no defined scale.

    Raises:
        ValueError: If *confidence* is not a real number in [0.0, 1.0].
    """
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ValueError(
            f"confidence must be a number, got {type(confidence).__name__}"
        )
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"confidence must be between 0.0 and 1.0, got {confidence}")


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
@require_rate_limit
def get_security_findings(
    severity: list[str] | None = None,
    tool: str | None = None,
    rule_id: str | None = None,
    path: str | None = None,
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
        limit: Maximum findings to return (default: 100, max: 1000). Must not
            be negative. Values above 1000 are capped, and the cap is what is
            reported back -- page with the returned `limit`, not the requested
            one.
        offset: Pagination offset (default: 0). Must not be negative.

    Raises:
        ValueError: If *limit* or *offset* is negative, or no scan results
            exist.

    Returns:
        Dictionary with:
        - findings: List of security findings (CommonFinding schema v1.2.0)
        - total: Total count of findings matching filters
        - limit: The limit actually applied (>= 1000 requests report 1000)
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
    # A negative limit or offset used to be accepted silently and answered with
    # Python slice semantics, which are not pagination semantics: limit=-5
    # returned 0 findings, and offset=-3 returned the LAST 3 findings out of 5.
    # Neither is what a caller asking for a negative page meant, and neither was
    # reported as an error.
    if limit < 0:
        raise ValueError(f"limit must not be negative, got {limit}")
    if offset < 0:
        raise ValueError(f"offset must not be negative, got {offset}")

    try:
        loader = get_findings_loader()
        all_findings = loader.load_findings()

        # Cap at 1000. `applied_limit` -- not `limit` -- is what gets reported
        # back: this returned the value the caller ASKED for while silently
        # applying the cap, so a client paginating with `offset += limit` after
        # requesting 5000 advanced 5000 places over a page of 1000 and skipped
        # 4000 findings without any error.
        applied_limit = min(limit, 1000)

        # Apply filters
        filtered = loader.filter_findings(
            all_findings,
            severity=severity,
            tool=tool,
            rule_id=rule_id,
            path=path,
            limit=applied_limit,
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
            "limit": applied_limit,
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
@require_rate_limit
def apply_fix(
    finding_id: str,
    patch: str,
    confidence: float,
    explanation: str,
    dry_run: bool = False,
) -> dict:
    """
    Preview an AI-suggested fix patch. Applying is NOT IMPLEMENTED.

    ``dry_run=True`` validates the patch and echoes it back for review.
    ``dry_run=False`` writes nothing and returns ``success: False`` -- there is
    no patch application yet. The two are distinguishable in the return value:
    a successful preview carries ``dry_run: True``, and the write path can never
    return ``success: True``.

    Args:
        finding_id: Fingerprint ID of the finding to fix. Must exist.
        patch: Unified diff patch (git diff format). Must contain a hunk header
            (``@@ -n,m +n,m @@``) or ValueError is raised -- an arbitrary string
            is not a previewable change.
        confidence: AI confidence score, 0.0-1.0 inclusive. Out-of-range values
            raise ValueError.
        explanation: Human-readable explanation of the fix
        dry_run: Preview patch without applying (default: False)

    Raises:
        ValueError: If *confidence* is out of range, *patch* is not a unified
            diff, or *finding_id* matches no finding.

    Returns:
        Dictionary with:
        - dry_run: True on a successful preview (absent on the write path)
        - success: True only for a validated preview; never True for a write
        - dry_run_preview: Patch preview (if dry_run=True)
        - error: Why nothing was written (always present when dry_run=False)

    Security Note:
        This function modifies source code. Use with caution and review diffs carefully.
        High-confidence fixes (≥0.9) are safer for auto-application.

    Example:
        >>> # A previewable patch needs a real hunk header.
        >>> result = apply_fix(
        ...     finding_id="fingerprint-abc123",
        ...     patch=(
        ...         "--- a/src/app.js\\n+++ b/src/app.js\\n"
        ...         "@@ -42,1 +42,1 @@\\n"
        ...         "-  res.send(userInput)\\n"
        ...         "+  res.send(sanitize(userInput))\\n"
        ...     ),
        ...     confidence=0.95,
        ...     explanation="Added sanitization to prevent XSS",
        ...     dry_run=True
        ... )
        >>> result["success"], result["dry_run"]
        (True, True)

        >>> # There is no step 2 yet: the write path is not implemented.
        >>> apply_fix(..., dry_run=False)["success"]
        False
    """
    # TODO(security): When implementing apply_fix(), add these controls:
    #   1. Directory traversal validation on patch paths (CWE-22)
    #   2. Backup-before-apply with rollback on failure
    #   3. Run tests after applying patch, rollback if tests fail
    #   4. Validate patch doesn't modify files outside project root
    #   5. Rate limit to prevent rapid-fire patch application
    try:
        # Validate the arguments BEFORE reporting any kind of success. A
        # preview that echoes an unvalidated string is not a preview.
        _validate_confidence(confidence)
        _validate_patch(patch)

        # Verify finding exists
        loader = get_findings_loader()
        finding = loader.get_finding_by_id(finding_id)

        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        if dry_run:
            logger.info(f"apply_fix: dry-run preview for {finding_id}")
            return {"success": True, "dry_run": True, "dry_run_preview": patch}

        # TODO(future): Implement full patch application - see
        # https://github.com/jimmy058910/jmo-security-repo/issues
        # Required steps for Phase 2:
        # 1. Validate patch content: reject shell commands, directory traversal
        #    (e.g., ../), and symlink targets outside repo root
        # 2. Create timestamped backup of target file(s) in .jmo/backups/
        # 3. Apply unified diff via subprocess (shell=False) using GNU patch
        #    or Python difflib as fallback
        # 4. Run project test suite; auto-rollback from backup if tests fail
        # 5. Record applied patch metadata in .jmo/fix-history.json
        #    (finding_id, timestamp, patch hash, confidence, rollback status)

        logger.warning(
            f"apply_fix: patch application not yet implemented (finding: {finding_id})"
        )

        return {
            "success": False,
            "error": "Patch application not yet implemented (coming in Phase 2)",
        }

    except ValueError as e:
        logger.error(f"apply_fix validation error: {e}")
        raise
    except Exception as e:
        logger.error(f"Error applying fix: {e}", exc_info=True)
        raise


@mcp.tool()
@require_rate_limit
def mark_resolved(
    finding_id: str,
    resolution: str,
    comment: str | None = None,
) -> dict:
    """
    NOT IMPLEMENTED. Validates its arguments and persists nothing.

    This tool always returns ``success: False``. There is no resolution store
    yet -- no file, no database table -- so a resolution recorded here is
    discarded and the finding reappears unchanged in the next scan. It is kept
    callable so a client can discover the capability's absence from the return
    value rather than from a scan that did not change.

    Args:
        finding_id: Fingerprint ID of the finding. Must exist; an unknown id
            raises ValueError.
        resolution: Resolution type (valid values: fixed, false_positive,
            wont_fix, risk_accepted)
        comment: Optional comment explaining the resolution

    Returns:
        Dictionary with:
        - success: always False
        - error: why nothing was persisted
        - finding_id: Confirmed finding ID
        - resolution: Validated resolution type
        - timestamp: ISO timestamp of the (discarded) decision

    Raises:
        ValueError: If *resolution* is not a valid type, or *finding_id* does
            not match any finding in the loaded results.

    Example:
        >>> mark_resolved(
        ...     finding_id="fingerprint-abc123",
        ...     resolution="false_positive",
        ...     comment="This is a test file, not production code"
        ... )
        {
            "success": False,
            "error": "Resolution tracking is not implemented. ...",
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

        # TODO(future): Implement persistent resolution tracking - see
        # https://github.com/jimmy058910/jmo-security-repo/issues
        # Required steps for Phase 2:
        # 1. Create .jmo/resolutions.json (or SQLite table in history.db)
        #    to persist resolution decisions across scans
        # 2. Append resolution entry: finding_id, resolution type, comment,
        #    timestamp, user identity (from git config or env)
        # 3. Update HTML dashboard to render resolution badges (fixed,
        #    false_positive, wont_fix, risk_accepted) with filter support
        # 4. Filter resolved findings from future scan reports (configurable
        #    via jmo.yml: show_resolved: true/false)
        # 5. Support bulk resolution import/export for team workflows

        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")

        # This returned success=True while writing nothing, anywhere. Measured:
        # a call with a valid finding id created no file, and no .jmo/ directory
        # existed afterwards. An AI agent reads success=True as "this finding is
        # now recorded as a false positive", stops working on it, and finds it
        # unchanged in the next scan. The only hint was a trailing `note` field,
        # which the documented example return value did not even include.
        #
        # success=False is the truthful answer for a call that persisted
        # nothing, and it matches what apply_fix already returns for its own
        # unimplemented path.
        logger.warning(
            f"mark_resolved: NOT PERSISTED -- {finding_id} -> {resolution} "
            f"(comment: {comment or 'none'}). Resolution tracking is not "
            "implemented; this decision was validated and then discarded."
        )

        return {
            "success": False,
            "error": (
                "Resolution tracking is not implemented. The finding id and "
                "resolution type were validated, but nothing was persisted and "
                "this finding will reappear unchanged in the next scan."
            ),
            "finding_id": finding_id,
            "resolution": resolution,
            "timestamp": timestamp,
        }

    except ValueError as e:
        logger.error(f"mark_resolved validation error: {e}")
        raise
    except Exception as e:
        logger.error(f"Error marking finding resolved: {e}", exc_info=True)
        raise


@mcp.tool()
@require_rate_limit
def query_findings_db(
    query: str,
    params: list[str] | None = None,
) -> dict:
    """Execute a read-only SQL query against the JMo Security history database.

    Use this tool for ad-hoc analysis of historical scan data stored in SQLite.
    Only SELECT, EXPLAIN, WITH, and safe PRAGMA queries are allowed.

    Tables: scans, findings, scan_metadata, schema_version, attestations
    Views: latest_scan_by_branch, finding_history

    Args:
        query: Read-only SQL query string.
        params: Optional list of bind-parameter values for ``?`` placeholders.

    Returns:
        Dictionary with:
        - columns: List of column names
        - rows: List of row tuples
        - row_count: Number of rows returned
        - truncated: True if results were capped at 500 rows

    Examples:
        - "SELECT * FROM scans ORDER BY timestamp DESC LIMIT 5"
        - "SELECT severity, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY severity"
        - "SELECT sql FROM sqlite_master WHERE type='table'"
        - "PRAGMA table_info(findings)"
    """
    from scripts.core.history_db import (
        DEFAULT_DB_PATH,
        QuerySecurityError,
        QueryTimeoutError,
        execute_readonly_query,
    )

    # Resolve database path: env var > .jmo/history.db relative to repo root > default
    db_path_env = os.getenv("JMO_HISTORY_DB")
    if db_path_env:
        db_path = Path(db_path_env)
    else:
        repo_db = REPO_ROOT / ".jmo" / "history.db"
        if repo_db.exists():
            db_path = repo_db
        else:
            db_path = DEFAULT_DB_PATH

    try:
        result = execute_readonly_query(
            db_path=db_path,
            query=query,
            params=params,
        )

        logger.info(
            f"query_findings_db: returned {result['row_count']} rows "
            f"(truncated={result['truncated']})"
        )

        return result

    except QuerySecurityError as e:
        logger.warning(f"query_findings_db: security violation: {e}")
        raise ValueError(f"Query rejected: {e}")
    except QueryTimeoutError as e:
        logger.warning(f"query_findings_db: timeout: {e}")
        raise ValueError(f"Query timeout: {e}")
    except ValueError as e:
        logger.error(f"query_findings_db: {e}")
        raise
    except Exception as e:
        logger.error(f"query_findings_db error: {e}", exc_info=True)
        raise


# ============================================================================
# MCP Resources (Data access via URIs)
# ============================================================================


@mcp.resource("finding://{finding_id}")
@require_rate_limit
def get_finding_context(finding_id: str) -> dict:
    """
    Get full context for a specific security finding.

    Use this resource to retrieve comprehensive information about a finding,
    including source code context and remediation guidance.

    This is the only entry point that reads arbitrary source files off disk, and
    it was the only one the rate limiter did not cover -- measured: with the
    shared bucket fully drained, `get_security_findings` and `get_server_info`
    were denied and this resource was still served. It is decorated now.

    URI Pattern: finding://<fingerprint-id>

    Args:
        finding_id: Fingerprint ID of the finding (from get_security_findings)

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
        >>> ctx = get_finding_context("fingerprint-abc123")
        >>> print(ctx["source_code"]["lines"])  # Shows vulnerable code (20 lines context)
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
            context_lines=20,  # Fixed at 20 lines (MCP resources don't support query params yet)
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
@require_rate_limit
def get_server_info() -> dict:
    """
    Get JMo Security MCP Server metadata and configuration.

    Returns information about the server, scan results, and available tools.

    Returns:
        Dictionary with:
        - version: installed jmo-security version (was hardcoded "1.0.0")
        - results_dir: Path to results directory
        - repo_root: Path to repository root
        - total_findings: Total findings in current scan
        - severity_distribution: Findings breakdown by severity
        - available_tools: List of security tools used in scan. This key was
          promised here and absent from the return value until it was checked.
        - authentication_enforced: always False. There is no request context on
          stdio transport, so JMO_MCP_API_KEYS cannot be checked against a
          caller. Ask this rather than inferring auth from the key list.

    Example:
        >>> info = get_server_info()
        >>> print(f"Total findings: {info['total_findings']}")
        >>> print(f"Critical: {info['severity_distribution']['CRITICAL']}")
    """
    try:
        loader = get_findings_loader()

        return {
            "version": _server_version(),
            "results_dir": str(RESULTS_DIR.resolve()),
            "repo_root": str(REPO_ROOT.resolve()),
            "total_findings": loader.get_total_count(),
            "severity_distribution": loader.get_severity_distribution(),
            "available_tools": sorted(loader.get_tool_names()),
            "authentication_enforced": False,
            "note": "Use get_security_findings() to query findings with filters",
        }

    except FileNotFoundError:
        return {
            "version": _server_version(),
            "results_dir": str(RESULTS_DIR.resolve()),
            "repo_root": str(REPO_ROOT.resolve()),
            "total_findings": 0,
            "severity_distribution": {},
            "available_tools": [],
            "authentication_enforced": False,
            "error": "No scan results found. Run: jmo scan --repo <path>",
        }
    except Exception as e:
        logger.error(f"Error getting server info: {e}", exc_info=True)
        raise


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    # This is called when running: uv run mcp dev scripts/jmo_mcp/jmo_server.py
    # (this comment said `scripts/mcp/server.py`, which has never existed)
    logger.info("Starting JMo Security MCP Server (stdio transport)")
    logger.info(f"Results directory: {RESULTS_DIR.resolve()}")
    logger.info(f"Repository root: {REPO_ROOT.resolve()}")

    # Run MCP server (stdio transport by default for Claude Desktop/GitHub Copilot)
    mcp.run()
