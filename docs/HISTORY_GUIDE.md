# Historical Storage Guide

**Track security scans over time for trend analysis, regression detection, and compliance reporting.**

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Security & Privacy Features](#security--privacy-features)
- [CLI Commands](#cli-commands)
- [Database Schema](#database-schema)
- [Workflow Examples](#workflow-examples)
- [CI/CD Integration](#cicd-integration)
- [Best Practices](#best-practices)
- [Performance Benchmarks](#performance-benchmarks)
- [Troubleshooting](#troubleshooting)
- [Advanced History Queries](#advanced-history-queries)
- [Future Enhancements](#future-enhancements)

---

## Overview

The Historical Storage feature stores scan results in a local SQLite database, enabling:

- **Trend Analysis**: Track finding counts over time (critical/high/medium/low)
- **Regression Detection**: Compare current scan with previous runs
- **Compliance Reporting**: Prove security posture improvements over time
- **Dashboard Data Layer**: Future support for time-series visualizations
- **Multi-Branch Tracking**: Compare security across dev/staging/prod branches

**Key Features:**

- **SQLite Database**: Zero-configuration, file-based storage (`.jmo/history.db`)
- **Full Finding History**: Stores all CommonFinding v1.2.0 fields with compliance mappings
- **Automatic Aggregation**: Severity counts updated via database triggers
- **Git Integration**: Tracks commit hash, branch, tag, dirty status
- **CI/CD Metadata**: Captures CI provider, build ID, environment variables
- **Multi-Target Support**: Works across all 6 target types (repos, images, IaC, URLs, GitLab, K8s)

---

## Quick Start

**Auto-store during scan (recommended):**

```bash
# Store scan results automatically after completion
jmo scan --repo ./myapp --profile balanced --store-history

# Custom database location
jmo scan --repo ./myapp --profile balanced --store-history --history-db ./scans.db
```

**Manual storage after scanning:**

```bash
# Run scan first
jmo scan --repo ./myapp --profile balanced --results-dir ./results

# Store results manually
jmo history store --results-dir ./results --profile balanced

# Specify database path
jmo history store --results-dir ./results --profile balanced --db ./scans.db
```

---

## Security & Privacy Features

The historical storage system includes comprehensive security and privacy controls designed with a **privacy-first, defense-in-depth approach**.

### Privacy-First Defaults

**By default, JMo does NOT collect hostname or username metadata.** This ensures your personal information stays private without requiring any configuration.

**Default Behavior:**

- **CI metadata collected** (ci_provider, ci_build_id, ci_run_number) - Non-PII, useful for tracking builds
- **Hostname NOT collected** - Your machine name stays private
- **Username NOT collected** - Your OS username stays private

**Opt-In to Metadata Collection:**

If you want to track which machine ran scans (useful for multi-developer teams or debugging), use the `--collect-metadata` flag:

```bash
# Opt-in to hostname/username collection
jmo scan --repo ./myapp --store-history --collect-metadata
```

**When to use `--collect-metadata`:**

- Team environments where you want to track which developer's machine ran the scan
- Debugging scan environment differences (production vs staging builders)
- Compliance requirements to log scan operator identity

**When to skip `--collect-metadata` (default):**

- Personal projects where privacy matters
- Shared CI/CD runners where hostname/username is meaningless
- Any scenario where you don't want PII in the database

**CI Metadata (Always Collected):**

CI metadata is always collected because it's non-PII and critical for tracking build context:

- `ci_provider`: Detected CI system (github-actions, gitlab-ci, jenkins, etc.)
- `ci_build_id`: Build number or job ID
- `ci_run_number`: Run attempt number (for retries)

### Secret Redaction

**Automatic secret redaction** prevents sensitive data from being stored in the history database.

**How it works:**

- Secret scanners (trufflehog, noseyparker, semgrep-secrets) automatically redact sensitive fields
- Redacted fields: `Raw`, `RawV2`, `snippet`, `lines`
- Non-secret scanners (trivy, semgrep, checkov) retain full raw data
- Redaction is **automatic and always enabled** for secret scanners

**Example:**

```bash
# Trufflehog finding BEFORE storage (in findings.json)
{
  "id": "abc123...",
  "ruleId": "aws-access-key",
  "raw": {
    "Raw": "AKIAIOSFODNN7EXAMPLE",  # Actual secret exposed
    "RawV2": "arn:aws:iam::123456789012:user/example"
  }
}

# AFTER storage in history.db (raw_finding column)
{
  "id": "abc123...",
  "ruleId": "aws-access-key",
  "raw": {
    "Raw": "[REDACTED]",  # Secret removed
    "RawV2": "[REDACTED]"
  }
}
```

**Disable raw finding storage entirely:**

If you want maximum privacy and don't need raw finding data in the history database, use `--no-store-raw-findings`:

```bash
# Don't store ANY raw finding data in history database
jmo scan --repo ./myapp --store-history --no-store-raw-findings
```

**When to use `--no-store-raw-findings`:**

- Compliance requirements prohibit storing any potential secret data
- Database size is a concern (reduces storage by ~40%)
- You only need aggregate statistics (severity counts, trends)

**Database Schema Impact:**

- The `findings.raw_finding` column is **nullable**
- Redacted secrets show `"[REDACTED]"` placeholder
- `--no-store-raw-findings` stores `NULL` in `raw_finding` column

### Finding Data Encryption

**Encrypt raw finding data** using Fernet symmetric encryption for defense-in-depth security.

**Setup:**

```bash
# 1. Generate encryption key (32-byte base64-encoded)
export JMO_ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# 2. Run scan with encryption enabled
jmo scan --repo ./myapp --store-history --encrypt-findings

# 3. Key is persisted in environment or CI secrets
echo $JMO_ENCRYPTION_KEY  # Save this securely!
```

**Key Requirements:**

- **Environment variable:** `JMO_ENCRYPTION_KEY` must be set
- **Key format:** Base64-encoded, minimum 32 bytes
- **Key derivation:** SHA-256 hashing ensures proper Fernet key length

**Error if key missing:**

```bash
jmo scan --repo ./myapp --store-history --encrypt-findings
# ERROR: JMO_ENCRYPTION_KEY environment variable not set. Required for --encrypt-findings.
```

**What gets encrypted:**

- Only the `raw_finding` column in the `findings` table
- Metadata (severity, rule_id, file paths, timestamps) remains **unencrypted** for querying
- Encryption uses **Fernet symmetric encryption** (AES-128-CBC with HMAC authentication)

**Decryption on retrieval:**

```bash
# Export JMO_ENCRYPTION_KEY in your shell
export JMO_ENCRYPTION_KEY="your-key-here"

# Findings are automatically decrypted when queried
jmo history query --severity CRITICAL

# JSON export also decrypts findings
jmo history export scan-report.json --scan-id abc123 --include-findings
```

**When to use `--encrypt-findings`:**

- Shared databases (multi-user access, need to protect raw findings)
- Compliance requirements for encryption at rest
- Defense-in-depth strategy (redaction + encryption + file permissions)

**When to skip `--encrypt-findings`:**

- Single-user local databases (file permissions sufficient)
- Performance-critical environments (encryption adds ~10-20ms overhead)
- Key management complexity outweighs benefits

### File Permissions Hardening

**Automatic file permissions** ensure only the database owner can read/write the history database.

**Default Behavior (Unix/Linux/macOS):**

```bash
# After first scan with --store-history
ls -la .jmo/history.db
# -rw------- 1 user user 2.4M Nov 04 14:30 .jmo/history.db
#  ^^^ Owner-only read/write (0o600)
```

**File Permissions:**

- **Unix/Linux/macOS:** `0o600` (owner read/write, no group/other access)
- **Windows:** NTFS permissions applied (owner full control)
- **Enforcement:** Applied automatically on database creation and connection

**Security Benefits:**

- Prevents other users on shared systems from reading scan results
- Protects against accidental disclosure if database copied
- Complements encryption (defense-in-depth)

**Override (NOT recommended):**

File permissions are enforced automatically and cannot be disabled. If you need to share the database, use proper access controls:

```bash
# BAD: Weakening permissions
chmod 644 .jmo/history.db  # Will be reset to 0o600 on next connection

# GOOD: Export data for sharing
jmo history export shared-report.json --include-findings
chmod 644 shared-report.json  # Share the export, not the database
```

### Defense-in-Depth Strategy

**Combine all three security layers for maximum protection:**

```bash
# 1. Generate encryption key
export JMO_ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# 2. Run scan with all security flags
jmo scan --repo ./myapp --store-history \
  --encrypt-findings \           # Layer 1: Encrypt raw findings
  --no-store-raw-findings \      # Layer 2: Don't store raw data at all
  # --collect-metadata omitted   # Layer 3: No PII collection (default)

# 3. Verify database permissions
ls -la .jmo/history.db
# -rw------- 1 user user ...    # Layer 4: File permissions
```

**Security Layers:**

1. **Privacy-first defaults:** No PII collection (hostname/username)
2. **Secret redaction:** Automatic for secret scanners
3. **Encryption:** Fernet symmetric encryption for raw findings
4. **File permissions:** Owner-only access (0o600 on Unix)

**Recommended Configurations by Use Case:**

| Use Case | `--collect-metadata` | `--encrypt-findings` | `--no-store-raw-findings` | Rationale |
|----------|---------------------|---------------------|--------------------------|-----------|
| **Personal projects** | No | No | Yes | Maximum privacy, minimal overhead |
| **Team development** | Yes | No | No | Track developers, file permissions sufficient |
| **Shared CI/CD runners** | No | Yes | No | Encrypt sensitive data, no PII |
| **Compliance audits** | Yes | Yes | Yes | Full auditability with maximum security |
| **Enterprise (multi-tenant)** | Yes | Yes | No | Encryption + PII for full context |

### Environment Variables Reference

| Variable | Purpose | Default | Required For |
|----------|---------|---------|--------------|
| `JMO_ENCRYPTION_KEY` | Fernet encryption key (base64) | Not set | `--encrypt-findings` |
| `JMO_TELEMETRY` | Enable/disable telemetry | `0` (disabled) | Telemetry opt-in |

**Generating encryption keys:**

```bash
# Python (cryptography library)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# OpenSSL (alternative)
openssl rand -base64 32

# Store in shell profile for persistence
echo "export JMO_ENCRYPTION_KEY='your-key-here'" >> ~/.bashrc
source ~/.bashrc
```

### CLI Integration Summary

**All security flags work with `jmo scan` and `jmo history store`:**

```bash
# jmo scan (integrated)
jmo scan --repo ./myapp \
  --store-history \
  --collect-metadata \
  --encrypt-findings \
  --no-store-raw-findings

# jmo history store (manual)
jmo history store --results-dir ./results \
  --collect-metadata \
  --encrypt-findings \
  --no-store-raw-findings
```

**Flag Compatibility:**

- `--encrypt-findings` + `--no-store-raw-findings`: Compatible (encrypts NULL column, no impact)
- `--collect-metadata` + `--encrypt-findings`: Compatible (metadata unencrypted, findings encrypted)
- All three flags together: Compatible (maximum security)

---

## CLI Commands

### `jmo history store`

**Store scan results in history database.**

```bash
jmo history store --results-dir RESULTS_DIR [OPTIONS]
```

**Options:**

- `--results-dir DIR` - Results directory containing `summaries/findings.json` (REQUIRED)
- `--profile PROFILE` - Profile name (fast/slim/balanced/deep, default: balanced)
- `--commit HASH` - Git commit hash (auto-detected if in Git repo)
- `--branch NAME` - Git branch name (auto-detected if in Git repo)
- `--tag TAG` - Git tag (auto-detected if in Git repo)
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
jmo history store --results-dir ./results --profile balanced --branch main
```

### `jmo history list`

**List stored scans with summary statistics.**

```bash
jmo history list [OPTIONS]
```

**Options:**

- `--branch NAME` - Filter by Git branch
- `--profile PROFILE` - Filter by profile (fast/slim/balanced/deep)
- `--since TIMESTAMP` - Filter by timestamp (Unix epoch or ISO 8601 format)
- `--limit N` - Limit results (default: 50)
- `--json` - Output as JSON instead of table
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
# List all scans
jmo history list

# List scans on main branch
jmo history list --branch main

# List last 10 scans in JSON format
jmo history list --limit 10 --json

# List scans since yesterday (Unix timestamp)
jmo history list --since 1730592000
```

**Sample Output:**

```text
+-------------+---------------------+----------+-----------+------------+------------+--------+----------------+
| Scan ID     | Timestamp           | Branch   | Profile   |   Findings |   Critical |   High | Duration (s)   |
+=============+=====================+==========+===========+============+============+========+================+
| a1b2c3d4... | 2025-11-02 14:30:15 | main     | balanced  |         42 |          3 |     12 | 245.2          |
| e5f6g7h8... | 2025-11-01 09:15:42 | main     | balanced  |         38 |          2 |     10 | 238.7          |
| i9j0k1l2... | 2025-10-31 16:20:03 | dev      | fast      |         15 |          0 |      5 | 89.3           |
+-------------+---------------------+----------+-----------+------------+------------+--------+----------------+
```

### `jmo history show`

**Show detailed information for a specific scan.**

```bash
jmo history show SCAN_ID [OPTIONS]
```

**Arguments:**

- `SCAN_ID` - Full or partial UUID (e.g., `a1b2c3d4` or full `a1b2c3d4-...`)

**Options:**

- `--json` - Output as JSON
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
# Show scan details (accepts partial UUID)
jmo history show a1b2c3d4

# Full output in JSON
jmo history show a1b2c3d4-5e6f-7890-abcd-1234567890ab --json
```

**Sample Output:**

```text
Scan ID:       a1b2c3d4-5e6f-7890-abcd-1234567890ab
Timestamp:     2025-11-02 14:30:15 (1730559015)
Profile:       balanced
Branch:        main
Commit:        abc1234567890def
Tag:           v1.2.3
Dirty:         No

Targets:       myapp, backend-api
Target Type:   repos
Tools:         trivy, semgrep, trufflehog, checkov

Findings:      42 total
  - CRITICAL:  3
  - HIGH:      12
  - MEDIUM:    18
  - LOW:       9
  - INFO:      0

Metadata:
  - Hostname:  builder-01
  - Username:  ci-user
  - CI Provider: github-actions
  - Build ID:  67890
  - Duration:  245.2 seconds
```

### `jmo history compare`

**Compare two historical scans from the SQLite database.**

```bash
jmo history compare SCAN_ID_1 SCAN_ID_2 [OPTIONS]
```

**Arguments:**

- `SCAN_ID_1` - First scan ID (typically baseline or older scan)
- `SCAN_ID_2` - Second scan ID (typically current or newer scan)

**Options:**

- `--severity LEVEL` - Filter by severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `--only {new,fixed,modified}` - Show only specific change types
- `--format {json,md,html}` - Output format (default: console)
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Use Cases:**

- Compare baseline scan vs current scan
- Track remediation progress over time
- Detect security regressions

**Example:**

```bash
# List available scans
jmo history list

# Compare two scans
jmo history compare abc123 def456

# Show only new HIGH/CRITICAL findings
jmo history compare abc123 def456 --severity HIGH CRITICAL --only new

# Generate HTML report
jmo history compare abc123 def456 --format html > comparison.html
```

**See Also:**

- `jmo diff` - Compare result directories
- `jmo trends compare` - Compare against baseline with statistics

### `jmo history query`

**Query findings across stored scans.**

```bash
jmo history query [OPTIONS]
```

**Options:**

- `--scan-id ID` - Filter by specific scan (full or partial UUID)
- `--severity LEVEL` - Filter by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- `--rule-id ID` - Filter by rule ID (e.g., CVE-2024-1234, CWE-79)
- `--path PATTERN` - Filter by file path pattern (supports wildcards)
- `--limit N` - Limit results (default: 100)
- `--json` - Output as JSON
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
# All critical findings
jmo history query --severity CRITICAL

# Findings in specific file
jmo history query --path "src/auth/*.py"

# Findings for specific rule
jmo history query --rule-id CVE-2024-9999

# Combined filters
jmo history query --severity HIGH --path "src/*" --limit 50
```

### `jmo history prune`

**Remove old scans from history database.**

```bash
jmo history prune [OPTIONS]
```

**Options:**

- `--older-than SECONDS` - Delete scans older than N seconds
- `--keep-scans N` - Keep only the N most recent scans
- `--dry-run` - Show what would be deleted without deleting
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
# Delete scans older than 90 days (7776000 seconds)
jmo history prune --older-than 7776000

# Keep only last 100 scans
jmo history prune --keep-scans 100

# Preview what would be deleted
jmo history prune --older-than 2592000 --dry-run
```

### `jmo history export`

**Export scan history to JSON file.**

```bash
jmo history export OUTPUT_FILE [OPTIONS]
```

**Arguments:**

- `OUTPUT_FILE` - Path to output JSON file

**Options:**

- `--scan-id ID` - Export specific scan only
- `--include-findings` - Include full finding details (default: metadata only)
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
# Export all scan metadata
jmo history export scans.json

# Export specific scan with findings
jmo history export scan-a1b2c3d4.json --scan-id a1b2c3d4 --include-findings
```

### `jmo history stats`

**Show database statistics and trends.**

```bash
jmo history stats [OPTIONS]
```

**Options:**

- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
jmo history stats
```

**Sample Output:**

```text
Database: .jmo/history.db
Size:     2.4 MB
------------------------------------------------------------------------
Scans:            127
Findings:         3,842
Date Range:       2024-08-15 to 2025-11-02

Scans by Profile:
  balanced      89 scans
  fast          28 scans
  deep          10 scans

Findings by Severity:
  CRITICAL        42  (1.1%)
  HIGH           385  (10.0%)
  MEDIUM         892  (23.2%)
  LOW          1,823  (47.4%)
  INFO           700  (18.2%)

Top Tools:
  trivy                   1,245 findings
  semgrep                   982 findings
  trufflehog                615 findings
  checkov                   412 findings
```

### `jmo history vacuum`

**Optimize the SQLite history database by reclaiming unused space and rebuilding indexes.**

```bash
jmo history vacuum [OPTIONS]
```

**Options:**

- `--db PATH` - Database path (default: `.jmo/history.db`)

**Description:**

Optimize the SQLite history database by:

- Reclaiming unused space
- Rebuilding indexes
- Improving query performance

**Use Cases:**

- After pruning old scans (`jmo history prune`)
- Database growing too large
- Query performance degradation
- Scheduled maintenance

**Example:**

```bash
# Vacuum database
jmo history vacuum

# Typical output:
# Database vacuumed successfully
# Space reclaimed: 15.2 MB -> 8.4 MB (45% reduction)
# Query performance improved
```

**See Also:**

- `jmo history prune` - Remove old scans
- `jmo history verify` - Check database integrity

### `jmo history verify`

**Verify SQLite history database integrity.**

```bash
jmo history verify [OPTIONS]
```

**Options:**

- `--db PATH` - Database path (default: `.jmo/history.db`)

**Description:**

Verify SQLite history database integrity by:

- Checking for corruption
- Validating foreign key constraints
- Ensuring schema consistency
- Testing read/write operations

**Use Cases:**

- Troubleshooting database errors
- Post-upgrade verification
- Scheduled health checks
- Before database backup

**Example:**

```bash
# Verify database integrity
jmo history verify

# Successful output:
# Database integrity check passed
# Foreign key constraints valid
# Schema version: 1.0.0
# Read/write test successful

# Failed output (if corrupted):
# Database corruption detected
# Recommendation: Restore from backup or reinitialize
```

**See Also:**

- `jmo history vacuum` - Optimize database
- Troubleshooting - SQLite issues

---

## Database Schema

The history database uses SQLite with the following schema:

**Tables:**

- `scans` - Scan metadata (timestamp, profile, branch, tools, severity counts, CI metadata)
- `findings` - Individual findings (fingerprint, severity, rule, location, message, full CommonFinding JSON)
- `compliance_mappings` - Framework mappings (OWASP, CWE, CIS, NIST, PCI-DSS, MITRE ATT&CK)
- `schema_version` - Database schema version for migrations

**Key Features:**

- **Foreign Key Constraints**: CASCADE deletion (deleting scan removes findings)
- **Automatic Triggers**: Severity counts auto-updated on INSERT/UPDATE/DELETE
- **Indices**: Optimized for common queries (timestamp DESC, branch, severity, rule_id)
- **Views**: `latest_scan_by_branch`, `finding_history` for quick queries
- **WAL Mode**: Write-Ahead Logging for concurrency and crash resilience

**Schema (Security & Privacy):**

- **`findings.raw_finding` column**: Changed from `NOT NULL` to **nullable** to support `--no-store-raw-findings` flag
- **`scans.hostname` column**: Changed from always populated to **NULL by default** (requires `--collect-metadata` opt-in)
- **`scans.username` column**: Changed from always populated to **NULL by default** (requires `--collect-metadata` opt-in)
- **Encryption support**: `raw_finding` column can store encrypted data (Fernet format) when `--encrypt-findings` used
- **File permissions**: Database file automatically set to `0o600` (owner-only) on Unix systems

**Database Location:**

- Default: `.jmo/history.db` (relative to working directory)
- Custom: Use `--db PATH` or `--history-db PATH` flags
- CI/CD: Recommended `.jmo/` directory (gitignored by default)
- **Security:** File permissions automatically enforced (0o600 on Unix)

---

## Workflow Examples

### Daily Development Workflow

```bash
# Morning: Baseline scan
jmo scan --repo ./myapp --profile balanced --store-history --branch dev

# Afternoon: After changes
jmo scan --repo ./myapp --profile balanced --store-history --branch dev

# Compare with previous scan
jmo history list --branch dev --limit 2
```

### Pre-Release Compliance Workflow

```bash
# Run comprehensive scan before release
jmo scan --repo ./myapp --profile deep --store-history --tag v1.2.3

# Generate compliance report
jmo history query --severity CRITICAL --json > critical-findings.json

# Verify no critical findings
if [ $(jq '.findings | length' critical-findings.json) -gt 0 ]; then
  echo "FAIL: Critical findings detected"
  exit 1
fi
```

### Multi-Branch Comparison

```bash
# Scan production branch
jmo scan --repo ./myapp --profile balanced --store-history --branch main

# Scan staging branch
jmo scan --repo ./myapp --profile balanced --store-history --branch staging

# Compare results
jmo history list --branch main --limit 1
jmo history list --branch staging --limit 1
```

### Historical Trend Analysis

```bash
# Weekly scans stored over 3 months
jmo scan --repo ./myapp --profile balanced --store-history

# View trends
jmo history list --branch main --limit 12  # Last 12 scans

# Export for external analysis
jmo history export --include-findings monthly-report.json
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run security scan with history
  run: |
    jmo scan --repo . --profile balanced --store-history

    # Upload database as artifact for trend tracking
    tar -czf history-db.tar.gz .jmo/history.db

- name: Upload history database
  uses: actions/upload-artifact@v4
  with:
    name: scan-history
    path: history-db.tar.gz
    retention-days: 90
```

### GitLab CI

```yaml
security_scan:
  script:
    - jmo scan --repo . --profile balanced --store-history --db scans.db
    - jmo history stats --db scans.db
  artifacts:
    paths:
      - scans.db
    expire_in: 3 months
```

---

## Best Practices

1. **Use `--store-history` flag** for automatic storage (no manual `history store` needed)
2. **Consistent profiles** - Use same profile for trend comparisons (balanced vs balanced)
3. **Regular pruning** - Run `jmo history prune` monthly to limit database size
4. **Git integration** - Run scans in Git repos for automatic branch/commit tracking
5. **CI artifact storage** - Upload `.jmo/history.db` as CI artifact for persistence
6. **Database backups** - Back up `.jmo/history.db` before major schema changes

---

## Performance Benchmarks

**Validated:** November 2025
**Test Environment:** Linux (WSL2), Python 3.12, SQLite 3.x

The historical storage database is **production-ready** with performance exceeding all targets by 9-117x:

| Operation | Volume | Performance | Target | Status |
|-----------|--------|-------------|--------|--------|
| Store findings | 1,000 findings | **0.017s** | <2s | **117x faster** |
| Query scans | 10,000 scans | **0.052s (52ms)** | <500ms | **9.6x faster** |
| Batch insert | 10,000 findings | **0.151s** | <5s | **33x faster** |
| Recent scans query | 100 scans | **<1ms** | N/A | **Sub-millisecond** |
| Single scan lookup | 1 scan | **<0.1ms** | N/A | **Near-instant** |

**Scalability Projections:**

- **Small Deployment** (1-10 repos, daily scans): <1 MB database, <1ms queries
- **Medium Deployment** (10-50 repos, multiple scans/day): ~20-50 MB, <10ms queries
- **Large Deployment** (100+ repos, CI/CD integration): ~200-500 MB, <50ms queries
- **Enterprise** (1000+ repos, continuous scanning): ~2-5 GB, <100ms queries

**Supported Scale:** Up to **1 million scans** without modification. For larger deployments, see [Future Enhancements](#future-enhancements) for sharding/archival options.

**Index Usage:** All 5 critical queries use indices (100% coverage verified). No full table scans on common operations.

**Throughput:**

- **Insert:** ~60,000 findings/second (batch operations)
- **Query:** ~190,000 scans/second (list operations)
- **Single lookup:** Near-instant (primary key lookup)

---

## Troubleshooting

### Issue: "Database is locked" error

- **Cause:** Multiple processes writing to database simultaneously
- **Fix:** Ensure only one scan writes at a time, or use separate database files

### Issue: "No findings.json found"

- **Cause:** Trying to store before report phase completes
- **Fix:** Ensure `jmo report` completes before `jmo history store`, or use `--store-history` flag which handles timing automatically

### Issue: Database growing too large

- **Cause:** Hundreds of scans accumulating
- **Fix:** Run `jmo history prune --keep-scans 100` to retain last 100 scans

### Issue: Git context not captured

- **Cause:** Not running scan in Git repository
- **Fix:** Run scans from Git repo root, or manually specify `--branch` and `--commit`

---

## Advanced History Queries

### Python API for custom integrations

Phase 7 adds 9 specialized query functions to `scripts/core/history_db.py` designed for future integrations with interactive dashboards, AI-powered remediation systems, and compliance reporting tools.

### React Dashboard Integration

These functions provide optimized, single-query data fetching for interactive web dashboards built with React and Recharts:

#### `get_dashboard_summary(conn, scan_id)` - Dashboard-Ready Summary

Single-query summary reducing multiple round-trips:

```python
from scripts.core.history_db import get_connection, get_dashboard_summary

conn = get_connection(".jmo/history.db")
summary = get_dashboard_summary(conn, "abc123")

# Returns:
{
    "scan": {...},  # Full scan metadata
    "severity_counts": {"CRITICAL": 5, "HIGH": 12, "MEDIUM": 18, ...},
    "top_rules": [
        {"rule_id": "CVE-2024-1234", "count": 8, "severity": "HIGH"},
        ...
    ],
    "tools_used": ["trivy", "semgrep", "trufflehog"],
    "findings_by_tool": {"trivy": 45, "semgrep": 32, ...},
    "compliance_coverage": {
        "total_findings": 100,
        "findings_with_compliance": 85,
        "coverage_percentage": 85.0
    }
}
```

**Performance:** ~5-10ms for single scan

#### `get_timeline_data(conn, branch, days=30)` - Time-Series Trends

Optimized for Recharts line/area charts showing severity trends:

```python
timeline = get_timeline_data(conn, branch="main", days=30)

# Returns list of daily data points:
[
    {
        "date": "2025-11-01",
        "scan_id": "abc123",
        "CRITICAL": 3,
        "HIGH": 12,
        "MEDIUM": 18,
        "LOW": 25,
        "INFO": 5,
        "total": 63
    },
    ...
]
```

**Performance:** 30 days: ~10-20ms, 90 days: ~20-40ms

#### `get_finding_details_batch(conn, fingerprints)` - Lazy Loading

Batch fetch finding details for drill-down views:

```python
# User clicks on "12 HIGH findings" in dashboard
fingerprints = ["abc123", "def456", "ghi789", ...]
findings = get_finding_details_batch(conn, fingerprints)

# Returns list of full CommonFinding objects
```

**Performance:** 100 findings: ~10-20ms, 1000 findings: ~50-100ms

#### `search_findings(conn, query, filters=None)` - Full-Text Search

Search across findings with filters:

```python
# Search for SQL injection findings
results = search_findings(
    conn,
    query="SQL injection",
    filters={
        "severity": "HIGH",
        "branch": "main",
        "date_range": ("2025-11-01", "2025-11-30"),
        "limit": 50
    }
)
```

**Performance:** Simple query: ~5-10ms, With filters: ~10-20ms

### MCP Server Integration

These functions provide AI-ready data formats for Model Context Protocol servers enabling Claude to suggest remediation strategies:

#### `get_finding_context(conn, fingerprint)` - Full Context for AI Remediation

```python
from scripts.core.history_db import get_finding_context

context = get_finding_context(conn, "abc123")

# Returns:
{
    "finding": {...},  # Current finding
    "history": [...],  # Same finding in past scans (up to 10)
    "similar_findings": [...],  # Related findings (up to 5)
    "remediation_history": [...],  # If fixed before, when/how?
    "compliance_impact": {
        "owasp": ["A03:2021"],
        "cwe": [{"id": "CWE-89", "rank": 3}],
        ...
    }
}
```

**Use Case:** AI assistant provides context-aware remediation:

```text
User: "How do I fix finding abc123?"

Claude (using MCP Server):
- "This SQL injection (CWE-89) has appeared 3 times in past 60 days"
- "Previous fix: Use parameterized queries (resolved 2024-10-15)"
- "Compliance impact: OWASP A03:2021, PCI DSS 6.5.1"
- "Suggested fix: [code snippet]"
```

**Performance:** ~10-30ms

#### `get_scan_diff_for_ai(conn, scan_id_1, scan_id_2)` - AI-Optimized Diff

```python
diff = get_scan_diff_for_ai(conn, "scan1", "scan2")

# Returns:
{
    "new_findings": [...],  # With priority scoring (1-10)
    "resolved_findings": [...],  # With "likely_fix" heuristics
    "unchanged_findings_count": 42,
    "priority_sorted": True  # Sorted by priority DESC
}

# Priority scoring formula:
# - CRITICAL: base 9-10
# - HIGH: base 7-8
# - + compliance frameworks (1-2 points)
# - + recent recurrence (1 point)
```

**Use Case:** AI prioritizes remediation tasks:

```text
Claude: "Top 3 priorities from this diff:
1. [Priority 10] CVE-2024-9999 (CRITICAL, PCI DSS, CIS)
2. [Priority 9] SQL injection in auth.py (HIGH, OWASP A03)
3. [Priority 8] Hardcoded AWS key (HIGH, recurring 3x)"
```

**Performance:** ~20-50ms

#### `get_recurring_findings(conn, branch, min_occurrences=3)` - Whack-a-Mole Detection

Identifies findings that keep reappearing (systemic issues):

```python
recurring = get_recurring_findings(conn, branch="main", min_occurrences=3)

# Returns:
[
    {
        "fingerprint": "abc123",
        "rule_id": "hardcoded-secret",
        "occurrence_count": 5,
        "first_seen": "2025-09-01 10:30:15",
        "last_seen": "2025-11-01 14:20:03",
        "avg_days_between_fixes": 12.5,
        "finding": {...}  # Full CommonFinding
    },
    ...
]
```

**Use Case:** AI suggests process improvements:

```text
Claude: "Warning: 'hardcoded-secret' has recurred 5 times (avg 12.5 days between fixes).
This indicates a systemic issue. Consider:
1. Pre-commit hooks (detect before push)
2. Developer training on secrets management
3. Secrets scanning in CI/CD pipeline"
```

**Performance:** 100 scans: ~50-100ms

### Compliance Reporting

These functions enable framework-specific compliance dashboards and trend analysis:

#### `get_compliance_summary(conn, scan_id, framework="all")` - Multi-Framework Summary

```python
summary = get_compliance_summary(conn, "abc123", framework="all")

# Returns:
{
    "framework_summaries": {
        "owasp_top10_2021": {
            "A01:2021": {"count": 5, "severities": {"HIGH": 3, "MEDIUM": 2}},
            "A02:2021": {"count": 8, "severities": {"CRITICAL": 2, "HIGH": 6}},
            ...
        },
        "cwe_top25_2024": {
            "CWE-79": {"count": 12, "rank": 1, "severities": {...}},
            ...
        },
        "cis_controls_v8_1": {...},
        "nist_csf_2_0": {...},
        "pci_dss_4_0": {...},
        "mitre_attack": {...}
    },
    "coverage_stats": {
        "total_findings": 100,
        "findings_with_compliance": 85,
        "coverage_percentage": 85.0,
        "by_framework": {
            "owasp": 72,
            "cwe": 68,
            "cis": 45,
            "nist": 52,
            "pci": 38,
            "mitre": 15
        }
    }
}
```

**Single-framework query:**

```python
# OWASP Top 10 only
owasp_summary = get_compliance_summary(conn, "abc123", framework="owasp")
```

**Performance:** Single framework: ~10-20ms, All frameworks: ~50-100ms

#### `get_compliance_trend(conn, branch, framework, days=30)` - Improvement Tracking

Track compliance improvements over time:

```python
trend = get_compliance_trend(conn, branch="main", framework="owasp", days=30)

# Returns:
{
    "trend": "improving",  # or "degrading", "stable", "insufficient_data"
    "data_points": [
        {
            "scan_id": "abc123",
            "timestamp": "2025-11-01 10:30:15",
            "framework_findings": 15,
            "categories": {
                "A01:2021": 2,
                "A02:2021": 5,
                ...
            }
        },
        ...
    ],
    "insights": [
        "OWASP findings reduced by 40% over 30 days (25 -> 15)",
        "A02:2021 (Cryptographic Failures) improved 60% (10 -> 4)",
        "A03:2021 (Injection) stable at 3 findings"
    ],
    "summary_stats": {
        "oldest_count": 25,
        "newest_count": 15,
        "reduction_percentage": 40.0,
        "avg_findings_per_scan": 18.5
    }
}
```

**Use Case:** Compliance dashboard showing progress:

```text
OWASP Top 10 Compliance (Last 30 Days)
--------------------------------------
Status: Improving (40% reduction)

Key Improvements:
  - A02:2021 (Cryptographic Failures): 60% reduction
  - A06:2021 (Vulnerable Components): 30% reduction

Stable Issues:
  - A03:2021 (Injection): 3 findings (no change)
```

**Performance:** 30 days: ~20-50ms, 90 days: ~50-100ms

### Performance Summary

All Phase 7 functions target <100ms response times:

| Function | Typical Data | Performance | Target |
|----------|--------------|-------------|--------|
| `get_dashboard_summary` | 1 scan | 5-10ms | <50ms |
| `get_timeline_data` | 30 days | 10-20ms | <50ms |
| `get_finding_details_batch` | 100 findings | 10-20ms | <100ms |
| `search_findings` | Simple query | 5-10ms | <50ms |
| `get_finding_context` | 1 finding + history | 10-30ms | <100ms |
| `get_scan_diff_for_ai` | 2 scans | 20-50ms | <100ms |
| `get_recurring_findings` | 100 scans | 50-100ms | <100ms |
| `get_compliance_summary` (single) | 1 scan | 10-20ms | <50ms |
| `get_compliance_summary` (all) | 1 scan | 50-100ms | <100ms |
| `get_compliance_trend` | 30 days | 20-50ms | <100ms |

**All functions use indices for optimal performance. No full table scans on common operations.**

### Example Use Cases

#### Use Case 1: React Dashboard Component

```javascript
// Dashboard.jsx
import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip } from 'recharts';

function SecurityDashboard({ scanId }) {
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState([]);

  useEffect(() => {
    // Fetch data from Python backend API
    fetch(`/api/history/dashboard/${scanId}`)
      .then(res => res.json())
      .then(data => setSummary(data));

    fetch(`/api/history/timeline?branch=main&days=30`)
      .then(res => res.json())
      .then(data => setTimeline(data));
  }, [scanId]);

  return (
    <div>
      <h2>Security Scan Summary</h2>
      <div>
        <span>CRITICAL: {summary?.severity_counts.CRITICAL}</span>
        <span>HIGH: {summary?.severity_counts.HIGH}</span>
      </div>

      <LineChart width={800} height={400} data={timeline}>
        <XAxis dataKey="date" />
        <YAxis />
        <Line type="monotone" dataKey="CRITICAL" stroke="#dc2626" />
        <Line type="monotone" dataKey="HIGH" stroke="#ea580c" />
        <Tooltip />
      </LineChart>
    </div>
  );
}
```

**Backend API endpoint (Flask example):**

```python
from flask import Flask, jsonify
from scripts.core.history_db import get_connection, get_dashboard_summary, get_timeline_data

app = Flask(__name__)

@app.route('/api/history/dashboard/<scan_id>')
def dashboard_summary(scan_id):
    conn = get_connection(".jmo/history.db")
    summary = get_dashboard_summary(conn, scan_id)
    return jsonify(summary)

@app.route('/api/history/timeline')
def timeline(branch, days=30):
    conn = get_connection(".jmo/history.db")
    data = get_timeline_data(conn, branch, days)
    return jsonify(data)
```

#### Use Case 2: MCP Server for Claude Integration

```python
# mcp_server.py
from mcp import Server
from scripts.core.history_db import get_connection, get_finding_context, get_scan_diff_for_ai

server = Server("jmo-security-mcp")

@server.tool("get_finding_remediation")
async def get_remediation(fingerprint: str) -> dict:
    """Provide AI with full context for remediation suggestions."""
    conn = get_connection(".jmo/history.db")
    context = get_finding_context(conn, fingerprint)

    return {
        "finding": context["finding"]["message"],
        "history": f"Seen {len(context['history'])} times before",
        "last_fix": context["remediation_history"][0] if context["remediation_history"] else None,
        "compliance": context["compliance_impact"],
        "suggestion": generate_fix_suggestion(context)  # AI-powered
    }

@server.tool("prioritize_findings")
async def prioritize_findings(scan1: str, scan2: str) -> list:
    """Return prioritized list of new findings for remediation."""
    conn = get_connection(".jmo/history.db")
    diff = get_scan_diff_for_ai(conn, scan1, scan2)

    return [
        {
            "priority": f["priority"],
            "rule_id": f["rule_id"],
            "path": f["location"]["path"],
            "message": f["message"]
        }
        for f in diff["new_findings"][:10]  # Top 10
    ]
```

#### Use Case 3: Compliance Reporting Dashboard

```python
# compliance_report.py
from scripts.core.history_db import get_connection, get_compliance_summary, get_compliance_trend

def generate_compliance_report(scan_id, output_format="html"):
    conn = get_connection(".jmo/history.db")

    # Get current compliance status
    summary = get_compliance_summary(conn, scan_id, framework="all")

    # Get trends for each framework
    frameworks = ["owasp", "cwe", "cis", "nist", "pci", "mitre"]
    trends = {}
    for framework in frameworks:
        trends[framework] = get_compliance_trend(conn, "main", framework, days=90)

    # Generate HTML report
    html = f"""
    <h1>Compliance Report</h1>
    <h2>Current Status</h2>
    <ul>
        <li>OWASP Top 10: {summary['framework_summaries']['owasp_top10_2021']}</li>
        <li>CWE Top 25: {summary['framework_summaries']['cwe_top25_2024']}</li>
    </ul>

    <h2>90-Day Trends</h2>
    <ul>
        <li>OWASP: {trends['owasp']['trend']} ({trends['owasp']['insights'][0]})</li>
        <li>CWE: {trends['cwe']['trend']} ({trends['cwe']['insights'][0]})</li>
    </ul>
    """

    return html
```

### Future Integration Examples

These functions are designed for extensibility:

1. **Grafana Dashboards**: Query functions provide Prometheus-style metrics
2. **Slack/Teams Bots**: Real-time compliance trend alerts
3. **Jupyter Notebooks**: Data science analysis of security posture
4. **GitHub Actions**: Automated compliance gate checks
5. **Security Information and Event Management (SIEM)**: Export findings to Splunk/ELK

See [scripts/core/history_db.py](../scripts/core/history_db.py) for complete function signatures and implementation details.

---

## Future Enhancements

- **Time-series dashboard** - Interactive charts showing trends over time
- **Automated comparisons** - Diff between scans with highlighted regressions
- **Metrics API** - REST API for external monitoring systems
- **Custom tags** - Label scans with custom metadata (environment, team, project)
- **Alert thresholds** - Notify when findings exceed baselines
- **Import command** - `jmo history import` for loading external scan data
- **Schema migrations** - Automatic database upgrades for future versions

**For Developers:** The history database API (`scripts/core/history_db.py`) is designed for extensibility. Future features can use:

- `list_scans(branch, since, profile)` - Time-series data for trend analysis
- `get_findings_for_scan(scan_id, severity)` - Finding details for comparisons
- `get_database_stats()` - Aggregate statistics for dashboards

See [scripts/core/history_db.py](../scripts/core/history_db.py) for complete API documentation.
