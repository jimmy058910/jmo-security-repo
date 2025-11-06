# JMo Security API Reference

**Programmatic access to trend analysis, developer attribution, and export functionality**

This document provides comprehensive API documentation for developers who want to integrate JMo Security's trend analysis capabilities into custom applications, dashboards, or automation workflows.

## Table of Contents

1. [TrendAnalyzer API](#trendanalyzer-api)
2. [DeveloperAttribution API](#developerattribution-api)
3. [Trend Exporters API](#trend-exporters-api)
4. [Statistical Functions](#statistical-functions)
5. [Usage Examples](#usage-examples)

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
    branch: Optional[str] = None,
    since: Optional[float] = None,
    scans: Optional[int] = None,
    min_scans: int = 2
) -> Dict[str, Any]
```

**Parameters:**

- `branch` (str, optional): Filter scans by Git branch (e.g., "main", "staging")
- `since` (float, optional): Analyze scans since Unix timestamp
- `scans` (int, optional): Analyze only the last N scans
- `min_scans` (int): Minimum number of scans required for analysis (default: 2)

**Returns:** Dictionary containing:

```python
{
    "summary": {
        "scan_count": 12,
        "date_range": ["2025-10-01", "2025-11-05"],
        "branch": "main",
        "profile": "balanced"
    },
    "severity_trends": {
        "critical": {
            "trend": "improving",  # "improving" | "stable" | "degrading"
            "tau": -0.682,          # Kendall's Tau (-1 to +1)
            "p_value": 0.001,       # Statistical significance
            "significant": True,    # p < 0.05
            "data": [6, 5, 4, 3, 2] # Historical counts
        },
        "high": {...},
        "medium": {...},
        "low": {...},
        "info": {...}
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
    tau: float,
    p_value: float,
    alpha: float = 0.05,
    tau_threshold: float = 0.3
) -> Dict[str, Any]
```

**Parameters:**

- `tau` (float): Kendall's Tau coefficient from Mann-Kendall test
- `p_value` (float): p-value from Mann-Kendall test
- `alpha` (float): Significance threshold (default: 0.05 = 95% confidence)
- `tau_threshold` (float): Minimum |τ| for "improving"/"degrading" (default: 0.3)

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
scan_id,timestamp,branch,profile,critical,high,medium,low,info,total,score,grade
abc123,2025-11-05T14:30:15,main,balanced,2,10,20,30,5,67,78,C
def456,2025-11-04T08:45:33,main,balanced,3,12,22,32,8,77,65,D
```

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
# HELP jmo_scan_findings_total Total findings by severity
# TYPE jmo_scan_findings_total gauge
jmo_scan_findings_total{severity="critical",branch="main",profile="balanced"} 2
jmo_scan_findings_total{severity="high",branch="main",profile="balanced"} 10

# HELP jmo_security_score Security posture score (0-100)
# TYPE jmo_security_score gauge
jmo_security_score{branch="main",profile="balanced"} 78
```

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
    export_for_dashboard(analysis, Path("dashboard-data.json"))
```

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

- [User Guide - Trend Analysis](USER_GUIDE.md#trend-analysis-v100): CLI usage and examples
- [User Guide - Historical Storage](USER_GUIDE.md#historical-storage-v100): Database schema and query API
- [CHANGELOG.md](../CHANGELOG.md): Feature #5 implementation details
- [Source Code](../scripts/core/): Complete implementation with docstrings
