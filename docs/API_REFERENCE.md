# JMo Security API Reference

**Programmatic access to trend analysis, developer attribution, MCP server, export functionality, and the history database.**

This document provides comprehensive API documentation for developers who want to integrate JMo Security's programmatic capabilities into custom applications, dashboards, IDE integrations, or automation workflows.

## v1.0 API Stability

All public APIs documented here are stable under semver for the v1.x line. Breaking changes will bump the major version. Additions (new methods, new optional parameters, new module-level helpers) may land in minor releases.

## Table of Contents

1. [TrendAnalyzer API](#trendanalyzer-api)
2. [DeveloperAttribution API](#developerattribution-api)
3. [Trend Exporters API](#trend-exporters-api)
4. [Statistical Functions](#statistical-functions)
5. [MCP Server API](#mcp-server-api)
6. [History DB Query API](#history-db-query-api)
7. [Usage Examples](#usage-examples)

---

## TrendAnalyzer API

**Module:** `scripts.core.trend_analyzer`

**Purpose:** Analyze security scan trends using statistical methods (Mann-Kendall test), detect regressions, calculate security scores, and generate insights.

### Class: `TrendAnalyzer`

Main class for performing comprehensive trend analysis on historical scan data.

#### Constructor

```python
TrendAnalyzer(db_path: Path = Path(".jmo/history.db"))
```

**Parameters:**

- `db_path` (Path): Path to the SQLite history database (default: `.jmo/history.db`)

**Example:**

```python
from pathlib import Path
from scripts.core.trend_analyzer import TrendAnalyzer

# Use default database location
analyzer = TrendAnalyzer()

# Use custom database location
analyzer = TrendAnalyzer(db_path=Path("/path/to/scans.db"))
```

#### Context Manager Support

TrendAnalyzer supports context manager protocol for automatic resource cleanup:

```python
with TrendAnalyzer() as analyzer:
    results = analyzer.analyze_trends()
    # Database connection automatically closed
```

#### Methods

##### `analyze_trends()`

Perform comprehensive trend analysis across stored scans.

```python
def analyze_trends(
    self,
    branch: str | None = None,
    days: int | None = None,
    scan_ids: list[str] | None = None,
    last_n: int | None = None,
) -> dict[str, Any]
```

**Parameters:**

- `branch` (str, optional): Restrict to one Git branch. `None` (the default)
  analyses every branch. A branch filter cannot match a scan whose branch could
  not be determined and is stored NULL, so passing one always narrows to less
  than the whole database.
- `days` (int, optional): Analyse the last N days. Must be >= 1. Defaults to 30
  when neither `days` nor `last_n` is given. Returns every scan in the window --
  there is no hidden result cap.
- `scan_ids` (list[str], optional): Analyse exactly these scans. Mutually
  exclusive with `branch`, `days` and `last_n`, which select scans rather than
  name them.
- `last_n` (int, optional): Analyse the last N scans. Must be >= 1.

**Raises:** `ValueError` if `days` or `last_n` is less than 1.

**Returns:** Dictionary containing:

```python
{
    "metadata": {
        "scan_count": 12,
        "date_range": {                       # a mapping, not a pair
            "start": "2025-10-01T09:12:44+00:00",
            "end": "2025-11-05T14:30:15+00:00"
        },
        "branch": None,                       # None when no branch filter applied
        "analysis_timestamp": "2025-11-05T14:31:02+00:00"
    },
    "severity_trends": {
        "by_severity": {                      # UPPERCASE keys, each a list of
            "CRITICAL": [6, 5, 4, 3, 2],      # per-scan counts oldest-first
            "HIGH": [...],
            "MEDIUM": [...],
            "LOW": [...],
            "INFO": [...]
        },
        "total": [...],                       # per-scan totals
        "timestamps": [...]                   # ISO timestamps, same order
    },
    "top_rules": [
        {
            "rule_id": "CVE-2024-1234",
            "count": 18,
            "severity": "CRITICAL",
            "percentage": 14.5
        },
        ...
    ],
    "security_score": {
        "current": 78,
        "previous": 65,
        "change": 13,
        "grade": "C",  # "A" | "B" | "C" | "D" | "F"
        "history": [
            {"scan_id": "abc123", "timestamp": 1730000000, "score": 78, "grade": "C"},
            ...
        ]
    },
    "regressions": {
        "new_findings": 3,
        "remediated_findings": 4,
        "details": [
            {
                "id": "fingerprint-123",
                "severity": "CRITICAL",
                "rule_id": "CVE-2024-9999",
                "message": "Remote Code Execution",
                "location": {"path": "src/utils/parser.py", "startLine": 145}
            },
            ...
        ]
    },
    "insights": [
        {
            "type": "positive",  # "positive" | "warning" | "info"
            "message": "CRITICAL findings decreasing (-68% over 12 scans)",
            "recommendation": "Keep up the excellent work!"
        },
        ...
    ]
}
```

**Raises:**

- `ValueError`: If fewer than `min_scans` scans found in database
- `RuntimeError`: If database connection fails

**Example:**

```python
with TrendAnalyzer() as analyzer:
    # Analyze last 10 scans on main branch
    results = analyzer.analyze_trends(
        branch="main",
        scans=10,
        min_scans=5
    )

    # Check for statistically significant trends
    critical_trend = results["severity_trends"]["critical"]
    if critical_trend["significant"] and critical_trend["trend"] == "improving":
        print(f"✓ Critical findings improving (τ={critical_trend['tau']:.3f}, p={critical_trend['p_value']:.3f})")
```

---

### Statistical Functions

Module-level functions for Mann-Kendall trend testing and statistical utilities.

#### `mann_kendall_test()`

Perform Mann-Kendall trend test on time series data.

```python
def mann_kendall_test(data: List[float]) -> Tuple[str, float, float]
```

**Parameters:**

- `data` (List[float]): Time series data (chronological order)

**Returns:** Tuple of `(trend, tau, p_value)`:

- `trend` (str): "improving" | "stable" | "degrading"
- `tau` (float): Kendall's Tau coefficient (-1 to +1)
- `p_value` (float): Statistical significance (p < 0.05 = significant)

**Algorithm:**

1. Computes test statistic `S = Σ sgn(xⱼ - xᵢ)` for all pairs i < j
2. Calculates Kendall's Tau: `τ = S / (n(n-1)/2)`
3. Computes variance: `Var(S) = n(n-1)(2n+5) / 18`
4. Calculates Z-statistic and p-value from standard normal distribution
5. Classifies trend based on τ and p-value

**Example:**

```python
from scripts.core.trend_analyzer import mann_kendall_test

# Historical CRITICAL finding counts (newest last)
critical_counts = [6, 5, 4, 4, 3, 2, 2, 1]

trend, tau, p_value = mann_kendall_test(critical_counts)

print(f"Trend: {trend}")               # "improving"
print(f"Kendall's Tau: {tau:.3f}")     # -0.714
print(f"p-value: {p_value:.4f}")       # 0.002
print(f"Significant: {p_value < 0.05}") # True
```

#### `validate_trend_significance()`

Validate whether a trend is statistically significant and classify it.

```python
def validate_trend_significance(
    severity_trends: dict[str, list[int]],
) -> dict[str, dict[str, Any]]
```

**Parameters:**

- `severity_trends` (dict): The `by_severity` mapping from
  `analyze_trends()["severity_trends"]` -- severity name to a list of per-scan
  counts. It runs the Mann-Kendall test itself rather than taking a
  pre-computed tau and p-value.

**Returns:** one entry per severity, e.g.

```python
{
    "CRITICAL": {
        "trend": "no_trend",   # "increasing" | "decreasing" | "no_trend"
        "tau": -0.03,          # Kendall's Tau (-1 to +1)
        "p_value": 0.2843,
        "significant": False,  # p < 0.05
        "confidence": "low"
    },
    "HIGH": {...}
}
```

**Returns:**

```python
{
    "significant": True,  # p_value < alpha
    "trend": "improving",  # "improving" | "stable" | "degrading"
    "confidence": 0.95,    # 1 - p_value (capped at 0.99)
    "strength": "strong"   # "weak" | "moderate" | "strong" based on |τ|
}
```

**Example:**

```python
from scripts.core.trend_analyzer import validate_trend_significance

validation = validate_trend_significance(tau=-0.682, p_value=0.001)
print(validation["trend"])       # "improving"
print(validation["significant"]) # True
print(validation["confidence"])  # 0.999
print(validation["strength"])    # "strong"
```

---

## DeveloperAttribution API

**Module:** `scripts.core.developer_attribution`

**Purpose:** Track remediation efforts per developer using git blame, calculate developer velocity, and aggregate by team.

### Class: `DeveloperAttribution`

Analyzes which developers fixed which security findings using git blame attribution.

#### Constructor

```python
DeveloperAttribution(repo_path: Path)
```

**Parameters:**

- `repo_path` (Path): Path to Git repository root (must contain `.git` directory)

**Raises:**

- `RuntimeError`: If `repo_path` is not a valid Git repository

**Example:**

```python
from pathlib import Path
from scripts.core.developer_attribution import DeveloperAttribution

# Initialize with repository path
attrib = DeveloperAttribution(repo_path=Path("/path/to/repo"))
```

#### Methods

##### `analyze_remediation_by_developer()`

Analyze remediation efforts per developer by comparing baseline and current scans.

```python
def analyze_remediation_by_developer(
    self,
    baseline_findings: List[Dict[str, Any]],
    current_findings: List[Dict[str, Any]]
) -> Dict[str, DeveloperContribution]
```

**Parameters:**

- `baseline_findings` (List[Dict]): Findings from baseline scan (CommonFinding format)
- `current_findings` (List[Dict]): Findings from current scan (CommonFinding format)

**Returns:** Dictionary mapping developer email → `DeveloperContribution`:

```python
{
    "alice@example.com": DeveloperContribution(
        email="alice@example.com",
        name="Alice Johnson",
        fixes=[
            {
                "id": "fingerprint-123",
                "severity": "CRITICAL",
                "rule_id": "CVE-2024-1234",
                "file": "src/auth/oauth.py",
                "line": 145,
                "message": "SQL Injection vulnerability"
            },
            ...
        ],
        new_findings=[...],  # Findings introduced by this developer
        severity_distribution={"CRITICAL": 1, "HIGH": 3, "MEDIUM": 2},
        net_contribution=-4  # fixes - new_findings (negative = net improvement)
    ),
    ...
}
```

**Example:**

```python
from scripts.core.history_db import get_connection, get_findings_for_scan
from scripts.core.developer_attribution import DeveloperAttribution

# Load baseline and current scans from history database
conn = get_connection(".jmo/history.db")
baseline_findings = get_findings_for_scan(conn, scan_id="baseline-123")
current_findings = get_findings_for_scan(conn, scan_id="current-456")

# Analyze developer contributions
attrib = DeveloperAttribution(repo_path=Path("."))
contributions = attrib.analyze_remediation_by_developer(
    baseline_findings=baseline_findings,
    current_findings=current_findings
)

# Show top contributors
for email, contrib in sorted(contributions.items(), key=lambda x: len(x[1].fixes), reverse=True)[:5]:
    print(f"{contrib.name}: {len(contrib.fixes)} fixes, net contribution: {contrib.net_contribution}")
```

##### `aggregate_by_team()`

Aggregate developer contributions by team using team mapping.

```python
def aggregate_by_team(
    self,
    contributions: Dict[str, DeveloperContribution],
    team_map: Dict[str, List[str]]
) -> Dict[str, TeamContribution]
```

**Parameters:**

- `contributions` (Dict): Output from `analyze_remediation_by_developer()`
- `team_map` (Dict): Mapping of team name → list of developer emails

**Team Map Format:**

```python
{
    "Frontend Team": ["alice@example.com", "bob@example.com"],
    "Backend Team": ["charlie@example.com", "dave@example.com"],
    "DevOps Team": ["eve@example.com"]
}
```

**Returns:** Dictionary mapping team name → `TeamContribution`:

```python
{
    "Frontend Team": TeamContribution(
        name="Frontend Team",
        members=["alice@example.com", "bob@example.com"],
        total_fixes=13,
        total_new_findings=2,
        severity_distribution={"CRITICAL": 1, "HIGH": 5, "MEDIUM": 5, "LOW": 2},
        net_contribution=-11,  # Net improvement
        member_count=2
    ),
    ...
}
```

**Example:**

```python
import json
from pathlib import Path

# Load team mapping from JSON file
team_map = json.loads(Path("teams.json").read_text())

# Aggregate contributions by team
team_contributions = attrib.aggregate_by_team(
    contributions=contributions,
    team_map=team_map
)

# Show team leaderboard
for team_name, team in sorted(team_contributions.items(), key=lambda x: x[1].total_fixes, reverse=True):
    print(f"{team_name}: {team.total_fixes} fixes ({team.member_count} members)")
```

##### `get_developer_velocity()`

Calculate developer velocity metrics (fixes per week, average severity).

```python
def get_developer_velocity(
    self,
    contributions: Dict[str, DeveloperContribution],
    time_window_days: int = 30
) -> Dict[str, Dict[str, Any]]
```

**Parameters:**

- `contributions` (Dict): Output from `analyze_remediation_by_developer()`
- `time_window_days` (int): Time window for velocity calculation (default: 30 days)

**Returns:** Dictionary mapping developer email → velocity metrics:

```python
{
    "alice@example.com": {
        "fixes_per_week": 12.5,
        "avg_severity_score": 6.8,  # CRITICAL=10, HIGH=7, MEDIUM=4, LOW=2, INFO=1
        "consistency": 0.85,         # 0-1 scale (1 = very consistent)
        "trend": "increasing"        # "increasing" | "stable" | "decreasing"
    },
    ...
}
```

**Example:**

```python
# Calculate 30-day velocity
velocity = attrib.get_developer_velocity(
    contributions=contributions,
    time_window_days=30
)

# Show top performers
for email, metrics in sorted(velocity.items(), key=lambda x: x[1]["fixes_per_week"], reverse=True)[:5]:
    print(f"{email}: {metrics['fixes_per_week']:.1f} fixes/week (trend: {metrics['trend']})")
```

---

## Trend Exporters API

**Module:** `scripts.core.trend_exporters`

**Purpose:** Export trend analysis results to various formats for integration with external systems.

### Functions

#### `export_to_csv()`

Export trend analysis to CSV format (Excel, Google Sheets).

```python
def export_to_csv(analysis: Dict[str, Any], output_path: Path) -> None
```

**Parameters:**

- `analysis` (Dict): Output from `TrendAnalyzer.analyze_trends()`
- `output_path` (Path): Path to write CSV file

**CSV Format:**

```csv
Timestamp,Scan ID,CRITICAL,HIGH,MEDIUM,LOW,INFO,Total,Security Score,Score Trend,Remediation Rate
2026-08-16T05:38:51+00:00,e65298d2-38c7-4ac7-bbca-7dc3480ce716,2,28,81,6,146,263,0.0,,
2026-08-18T19:06:17+00:00,ea0fb72a-ed55-445a-bcb6-ac2d654ecf73,2,28,81,6,146,263,0.0,degrading,4.49
```

One row per scan, oldest first. `Score Trend` and `Remediation Rate` describe
the window as a whole and are written on the **last row only**; earlier rows
leave them blank by design.

**Example:**

```python
from pathlib import Path
from scripts.core.trend_analyzer import TrendAnalyzer
from scripts.core.trend_exporters import export_to_csv

with TrendAnalyzer() as analyzer:
    analysis = analyzer.analyze_trends()
    export_to_csv(analysis, Path("trends.csv"))
```

#### `export_to_prometheus()`

Export trend analysis to Prometheus metrics format.

```python
def export_to_prometheus(analysis: Dict[str, Any], output_path: Path) -> None
```

**Parameters:**

- `analysis` (Dict): Output from `TrendAnalyzer.analyze_trends()`
- `output_path` (Path): Path to write Prometheus metrics file (`.prom`)

**Prometheus Metrics:**

```prometheus
# HELP jmo_security_findings Total security findings by severity
# TYPE jmo_security_findings gauge
jmo_security_findings{severity="critical"} 2
jmo_security_findings{severity="high"} 28

# HELP jmo_security_score Security posture score (0-100)
# TYPE jmo_security_score gauge
jmo_security_score 0

# HELP jmo_remediation_rate Findings remediated per day
# TYPE jmo_remediation_rate gauge
jmo_remediation_rate 4.95
```

Seven metrics are emitted: `jmo_security_findings` (labelled by `severity`),
`jmo_security_score`, `jmo_remediation_rate`, `jmo_introduction_rate`,
`jmo_net_remediation`, `jmo_scan_count`, and `jmo_rule_findings` (labelled by
`rule_id` and `severity`). There are no `branch` or `profile` labels.

**Example:**

```python
from scripts.core.trend_exporters import export_to_prometheus

with TrendAnalyzer() as analyzer:
    analysis = analyzer.analyze_trends()
    export_to_prometheus(analysis, Path("metrics.prom"))
```

**Grafana Integration:**

```promql
# Show CRITICAL findings over time
jmo_scan_findings_total{severity="critical"}

# Alert on regressions
increase(jmo_scan_findings_total{severity="critical"}[1h]) > 0
```

#### `export_to_grafana()`

Export pre-built Grafana dashboard JSON.

```python
def export_to_grafana(analysis: Dict[str, Any], output_path: Path) -> None
```

**Parameters:**

- `analysis` (Dict): Output from `TrendAnalyzer.analyze_trends()`
- `output_path` (Path): Path to write Grafana dashboard JSON

**Dashboard Features:**

- Time-series line charts (severity trends)
- Stat panels (current score, grade)
- Bar charts (findings by tool)
- Heatmap (findings by day of week)
- Pre-configured alerts for regressions

**Import to Grafana:**

1. Navigate to Dashboards → Import
2. Upload generated `dashboard.json`
3. Configure Prometheus data source
4. Dashboard ready to use

**Example:**

```python
from scripts.core.trend_exporters import export_to_grafana

with TrendAnalyzer() as analyzer:
    analysis = analyzer.analyze_trends()
    export_to_grafana(analysis, Path("grafana-dashboard.json"))
```

#### `export_for_dashboard()`

Export trend data for custom React dashboards.

```python
def export_for_dashboard(analysis: Dict[str, Any], output_path: Path) -> None
```

**Parameters:**

- `analysis` (Dict): Output from `TrendAnalyzer.analyze_trends()`
- `output_path` (Path): Path to write dashboard JSON

> **Do not name this file `dashboard-data.json` inside a results directory.** That name is already taken: `html_reporter.py` writes the HTML dashboard's **findings** there in external mode, and the dashboard fetches it expecting `{meta, findings}` or a bare array. This function emits a trend object, so writing it to that path replaces the dashboard's data with a shape it cannot read. The examples here use `trend-dashboard.json`.

**JSON Structure:**

```json
{
  "summary": {
    "scan_count": 12,
    "date_range": ["2025-10-01", "2025-11-05"],
    "branch": "main",
    "profile": "balanced"
  },
  "current_scan": {
    "scan_id": "abc123",
    "timestamp": "2025-11-05T14:30:15",
    "critical": 2,
    "high": 10,
    "score": 78,
    "grade": "C"
  },
  "timeline": [
    {"date": "2025-11-01", "critical": 3, "high": 12, "score": 65},
    {"date": "2025-11-05", "critical": 2, "high": 10, "score": 78}
  ],
  "trends": {
    "critical": {"trend": "improving", "tau": -0.682, "p_value": 0.001}
  },
  "regressions": {...},
  "top_rules": [...]
}
```

**Example:**

```python
from scripts.core.trend_exporters import export_for_dashboard

with TrendAnalyzer() as analyzer:
    analysis = analyzer.analyze_trends()
    export_for_dashboard(analysis, Path("trend-dashboard.json"))
```

---

## MCP Server API

**Module:** `scripts.jmo_mcp.jmo_server`

**Purpose:** Expose JMo Security findings and operations to AI assistants (GitHub Copilot, Claude Code, Cline, etc.) via the [Model Context Protocol](https://modelcontextprotocol.io/).

**Transport:** stdio only. Run the server with:

```bash
pip install "jmo-security[mcp]"
jmo mcp-server              # stdio (the only mode, for IDE integrations)
```

> This said "stdio, HTTP, SSE" and offered `jmo mcp-server --http 8080` as a
> copy-pasteable command. `--http` is not a flag this subcommand defines:
> argparse rejects it with `unrecognized arguments: --http 8080`. `mcp.run()`
> is called with no arguments, which selects stdio, and nothing in the package
> starts an HTTP or SSE listener.

### Tools Exposed

AI clients call these as MCP tools. Each is annotated with `@mcp.tool()` in `scripts/jmo_mcp/jmo_server.py` and documented here with its public contract.

#### `get_security_findings(severity, tool, rule_id, path, limit=100, offset=0)`

Retrieve findings from the most recent scan, with optional filters.

**Parameters:**
- `severity` (list[str], optional): Filter by any of `CRITICAL`, `HIGH`,
  `MEDIUM`, `LOW`, `INFO` — a **list**, e.g. `["HIGH", "CRITICAL"]`
- `tool` (str, optional): Filter by tool name (e.g., `trivy`, `semgrep`)
- `rule_id` (str, optional): Filter by rule ID (e.g., `CWE-79`)
- `path` (str, optional): Filter by file path substring
- `limit` (int, optional): Max findings to return (default: **100**, capped at
  1000). Must not be negative.
- `offset` (int, optional): Pagination offset (default: 0). Must not be
  negative.

**Returns:** `{"findings": [...], "total": N, "limit": L, "offset": O}` — a
dict, not a list. `limit` is the limit **applied**, so paginate with
`offset += result["limit"]`.

> This documented four of six parameters, typed `severity` as a string, gave
> `limit` a default of 50 (it is 100), and described the return as a list.

**Example (Claude Code):**

```text
/mcp call get_security_findings severity=CRITICAL tool=semgrep limit=10
```

#### `apply_fix(finding_id, patch, confidence, explanation, dry_run=False)`

Validate and preview an AI-suggested patch. **Applying is not implemented.**

**Parameters:**
- `finding_id` (str, required): Fingerprint of the finding to fix
- `patch` (str, required): Unified diff. Must contain a hunk header
  (`@@ -n,m +n,m @@`) or `ValueError` is raised.
- `confidence` (float, required): 0.0–1.0 inclusive; out of range raises
  `ValueError`
- `explanation` (str, required): Human-readable explanation of the fix
- `dry_run` (bool, default **`False`**): If True, preview without writing

**Returns:** Dict with `success` and either `dry_run` + `dry_run_preview`
(preview) or `error` (write path, always `success: False`).

**Safety:** `dry_run` defaults to `False`, not `True`. Pass it explicitly.
The write path currently changes nothing regardless.

> This entry documented the signature as `(finding_id, patch, dry_run)` with
> `dry_run` defaulting to `True`, and a return of `files_changed` /
> `diff_preview`. `confidence` and `explanation` are required and have no
> defaults, so a call written from the old entry raised `TypeError`; neither
> named return key exists; and the documented default inverted the safety of
> the one that does.

#### `mark_resolved(finding_id, resolution, comment=None, expires_days=90)`

Record a resolution decision by appending a suppression entry to
`jmo.suppress.yml` under `MCP_REPO_ROOT`, keyed on the finding's fingerprint.
The report phase already reads that file, so the finding is filtered next run.

**Parameters:**
- `finding_id` (str, required): Fingerprint of the finding. Must exist.
- `resolution` (str, required): One of `fixed`, `false_positive`, `wont_fix`,
  `risk_accepted`
- `comment` (str, optional): Human-readable explanation, recorded as `reason`
- `expires_days` (int, optional): 1-365, default 90. Out of range raises
  `ValueError` — there is no permanent suppression through this tool.

**Returns:** `success`, `suppressed`, `config_path`, `expires`, `finding_id`,
`resolution`, `timestamp`; plus `already_suppressed: True` when an entry
existed already, and `error` whenever `success` is `False`.

**`resolution="fixed"` deliberately writes nothing** and returns
`success: False`. A suppressed finding and a fixed one produce identical scan
output, so suppressing a "fix" destroys the evidence that a fix did not take.

> The parameters were documented as `status` and `reason`; the code has never
> accepted those names. `risk_accepted` was missing from the list, and `reason`
> was described as "stored for audit" while nothing was stored at all. That
> last one is now true rather than aspirational — see
> [MCP_SETUP.md](MCP_SETUP.md#3-mark_resolved--records-the-decision-as-a-suppression).

#### `query_findings_db(query, params=None)`

Execute a read-only SQL query against the history database.

**Parameters:**
- `query` (str, required): SQL. `SELECT` / `EXPLAIN` / `WITH` and an allowlist
  of `PRAGMA`s only. **Named `query`, not `sql`.**
- `params` (list, optional): Bind values for `?` placeholders

**Returns:** `{"columns": [...], "rows": [[...], ...], "row_count": N,
"truncated": bool}` — rows are **lists**, not dicts, capped at 500.

**Use case:** aggregate queries across multiple scans (e.g., "findings that reappeared 3+ scans in a row").

**Safety:** two independent layers — the connection is opened `mode=ro`, and
the statement is validated against a forbidden-keyword, multi-statement and
unsafe-`PRAGMA` policy. The keyword scan is textual, so a search whose text
contains e.g. `DROP` is refused; pass it as a bind parameter instead.

#### `get_server_info()`

Returns `version` (the installed package version), `results_dir`, `repo_root`,
`total_findings`, `severity_distribution`, `available_tools`, and
`authentication_enforced` (always `false`).

> This said "loaded scan ID, supported transports, feature flags". None of
> those keys exist.

### Resources Exposed

MCP resources are read-only URIs the AI can dereference for context.

#### `finding://{finding_id}`

Get comprehensive context for a specific finding: full description, source code context (±20 lines around the location), CWE/OWASP mappings, and remediation guidance.

`related_findings` is present in the response and is **always an empty list** —
finding it is not implemented. This entry listed it as content.

**Use case:** the AI sees a finding ID in a `get_security_findings` response and fetches `finding://<id>` to get enough context to propose a fix.

### Security

**The MCP server does not authenticate callers, and there is no setting that
makes it.** Rate limiting is real and enforced (`JMO_MCP_RATE_LIMIT_*`), using
a single shared bucket rather than one per client. `JMO_MCP_API_KEYS` is hashed
at startup and never compared against anything. Ask `get_server_info()` for
`authentication_enforced` rather than inferring it from configuration.

Transport is **stdio only** — `mcp.run()` takes no arguments and there is no
HTTP or SSE listener. stdio trusts the parent process, which is the whole of
the security model.

> This section described "token-based auth for HTTP mode (see
> `scripts/jmo_mcp/utils/security.py`)". That module does not exist, and
> neither does the HTTP mode.

See [MCP_SETUP.md](MCP_SETUP.md) for client configuration and
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for what this means in practice.

---

## History DB Query API

**Module:** `scripts.core.history_db`

**Purpose:** Read and write the SQLite history database that stores scan results across runs. Used internally by `jmo history`, `jmo diff`, `jmo trend`, and the MCP server's `query_findings_db` tool. Also callable directly by user scripts.

**Default location:** `.jmo/history.db` (relative to the current working directory).

### Core Functions

#### `get_connection(db_path)`

Open a connection to the history database. Auto-initializes the schema if the file doesn't exist.

```python
from pathlib import Path
from scripts.core.history_db import get_connection

conn = get_connection(Path(".jmo/history.db"))
```

Returns a `sqlite3.Connection` with `row_factory = sqlite3.Row` so rows are dict-accessible.

#### `get_findings_for_scan(conn, scan_id)`

Retrieve all findings for a specific scan.

```python
from scripts.core.history_db import get_findings_for_scan

findings = get_findings_for_scan(conn, scan_id="abc123")
for f in findings:
    print(f["severity"], f["rule_id"], f["file_path"])
```

**Returns:** `List[Dict[str, Any]]` — each dict is a CommonFinding row with flattened columns (severity, rule_id, tool, file_path, line, message, fingerprint, etc.).

### Schema Overview

The DB has three primary tables:

- `scans` — one row per scan invocation (id, timestamp, branch, profile, target_type, tool counts)
- `findings` — normalized findings from each scan (scan_id FK, severity, rule_id, fingerprint, location, raw_finding JSON blob)
- `scan_metadata` — key-value metadata per scan (git SHA, author, CI run ID, etc.)

For schema evolution notes and migration steps, see [HISTORY_GUIDE.md](HISTORY_GUIDE.md).

### Custom Queries

Use the `conn` object directly for ad-hoc queries:

```python
import sqlite3
from scripts.core.history_db import get_connection

conn = get_connection()
cursor = conn.execute(
    "SELECT severity, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY severity",
    ("abc123",),
)
for severity, count in cursor.fetchall():
    print(f"{severity}: {count}")
```

Always use parameterized queries — the library intentionally does not expose a string-interpolation API.

### Safety

- The DB is single-writer: only one `jmo` process should hold a write lock at a time. If you see "database is locked", another process has the DB open. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md#sqlite-database-is-locked).
- Backups: `sqlite3 .jmo/history.db .backup /path/to/backup.db` before major operations.
- Don't edit the DB with a general-purpose SQLite client while `jmo` is running — schema migrations are checked at connection time.

---

## Usage Examples

### Example 1: Automated Regression Detection

```python
from pathlib import Path
from scripts.core.trend_analyzer import TrendAnalyzer

def check_for_regressions(branch="main"):
    """Check latest scan for CRITICAL/HIGH regressions, exit 1 if found."""
    with TrendAnalyzer() as analyzer:
        analysis = analyzer.analyze_trends(branch=branch, scans=2, min_scans=2)

        regressions = analysis["regressions"]
        critical_new = sum(1 for f in regressions["details"] if f["severity"] == "CRITICAL")
        high_new = sum(1 for f in regressions["details"] if f["severity"] == "HIGH")

        if critical_new > 0 or high_new > 0:
            print(f"❌ Regressions detected: {critical_new} CRITICAL, {high_new} HIGH")
            exit(1)

        print("✓ No regressions detected")
        exit(0)

if __name__ == "__main__":
    check_for_regressions()
```

### Example 2: Security Posture Tracking

```python
from pathlib import Path
from scripts.core.trend_analyzer import TrendAnalyzer
from scripts.core.trend_exporters import export_to_prometheus

def track_security_posture():
    """Generate Prometheus metrics and send to pushgateway."""
    import requests

    with TrendAnalyzer() as analyzer:
        analysis = analyzer.analyze_trends()

        # Export to Prometheus format
        metrics_path = Path("/tmp/jmo-metrics.prom")
        export_to_prometheus(analysis, metrics_path)

        # Push to Prometheus Pushgateway
        with open(metrics_path) as f:
            requests.post(
                "http://pushgateway:9091/metrics/job/jmo-security",
                data=f.read()
            )

        print(f"✓ Pushed security metrics (score: {analysis['security_score']['current']})")

if __name__ == "__main__":
    track_security_posture()
```

### Example 3: Developer Leaderboard

```python
import json
from pathlib import Path
from scripts.core.history_db import get_connection, get_findings_for_scan
from scripts.core.developer_attribution import DeveloperAttribution

def generate_developer_leaderboard(baseline_scan_id, current_scan_id, team_map_path):
    """Generate developer leaderboard with team aggregation."""
    # Load findings from history database
    conn = get_connection(".jmo/history.db")
    baseline = get_findings_for_scan(conn, baseline_scan_id)
    current = get_findings_for_scan(conn, current_scan_id)

    # Analyze developer contributions
    attrib = DeveloperAttribution(repo_path=Path("."))
    contributions = attrib.analyze_remediation_by_developer(baseline, current)

    # Aggregate by team
    team_map = json.loads(Path(team_map_path).read_text())
    teams = attrib.aggregate_by_team(contributions, team_map)

    # Print leaderboard
    print("🏆 Developer Leaderboard:")
    for email, contrib in sorted(contributions.items(), key=lambda x: len(x[1].fixes), reverse=True)[:10]:
        print(f"  {contrib.name}: {len(contrib.fixes)} fixes (net: {contrib.net_contribution})")

    print("\n🏆 Team Leaderboard:")
    for team_name, team in sorted(teams.items(), key=lambda x: x[1].total_fixes, reverse=True):
        print(f"  {team_name}: {team.total_fixes} fixes ({team.member_count} members)")

if __name__ == "__main__":
    generate_developer_leaderboard(
        baseline_scan_id="baseline-123",
        current_scan_id="current-456",
        team_map_path="teams.json"
    )
```

### Example 4: Custom Dashboard Data Pipeline

```python
from pathlib import Path
from scripts.core.trend_analyzer import TrendAnalyzer
from scripts.core.trend_exporters import export_for_dashboard

def refresh_dashboard_data():
    """Refresh dashboard data for React frontend."""
    with TrendAnalyzer() as analyzer:
        # Analyze all scans
        analysis = analyzer.analyze_trends()

        # Export for dashboard
        export_for_dashboard(analysis, Path("/var/www/dashboard/data.json"))

        # Print summary
        score = analysis["security_score"]["current"]
        grade = analysis["security_score"]["grade"]
        trend_summary = [
            f"{sev.upper()}: {info['trend']}"
            for sev, info in analysis["severity_trends"].items()
            if info["significant"]
        ]

        print(f"✓ Dashboard data refreshed")
        print(f"  Score: {score} ({grade})")
        print(f"  Significant trends: {', '.join(trend_summary)}")

if __name__ == "__main__":
    refresh_dashboard_data()
```

### Example 5: Statistical Validation

```python
from scripts.core.trend_analyzer import mann_kendall_test, validate_trend_significance

def analyze_custom_metric(data: list[float], metric_name: str):
    """Analyze custom security metric using Mann-Kendall test."""
    # Perform trend test
    trend, tau, p_value = mann_kendall_test(data)

    # Validate significance
    validation = validate_trend_significance(tau, p_value)

    print(f"Metric: {metric_name}")
    print(f"  Trend: {trend} ({validation['strength']})")
    print(f"  Kendall's Tau: {tau:.3f}")
    print(f"  p-value: {p_value:.4f}")
    print(f"  Significant: {validation['significant']}")
    print(f"  Confidence: {validation['confidence']:.1%}")

if __name__ == "__main__":
    # Example: Track custom metric (API security score)
    api_security_scores = [45, 52, 58, 62, 68, 71, 75, 78, 80, 82]
    analyze_custom_metric(api_security_scores, "API Security Score")
```

---

## Best Practices

1. **Use Context Managers**: Always use `with TrendAnalyzer() as analyzer:` to ensure proper resource cleanup
2. **Error Handling**: Wrap API calls in try/except blocks to handle database errors gracefully
3. **Minimum Scans**: Require at least 5-7 scans for statistically meaningful trend detection
4. **Consistent Profiles**: Only compare scans using the same profile (balanced vs balanced)
5. **Branch Isolation**: Track trends separately per branch (main, staging, dev)
6. **Database Backups**: Back up `.jmo/history.db` before major schema changes
7. **Statistical Validation**: Always check `p_value < 0.05` before trusting trend classifications

---

## Further Reading

- [User Guide - Trend Analysis](USER_GUIDE.md#trend-analysis): CLI usage and examples
- [User Guide - Historical Storage](USER_GUIDE.md#historical-storage): Database schema and query API
- [CHANGELOG.md](../CHANGELOG.md): Feature #5 implementation details
- [Source Code](../scripts/core/): Complete implementation with docstrings
