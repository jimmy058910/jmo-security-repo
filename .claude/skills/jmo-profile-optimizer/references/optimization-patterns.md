# Optimization Patterns Reference

Detailed code implementations for bottleneck identification, timeout analysis, recommendation generation, and tool-specific tuning strategies.

---

## Phase 1: Load and Analyze timings.json

### timings.json Schema

```json
{
  "scan_start": "2025-10-21T14:30:00",
  "scan_end": "2025-10-21T14:50:15",
  "total_duration_seconds": 1215.3,
  "profile": "balanced",
  "threads": 4,
  "timeout": 600,
  "targets": {
    "repositories": 12,
    "images": 3,
    "iac_files": 8,
    "urls": 2
  },
  "tools": {
    "trufflehog": {
      "executions": 12,
      "successes": 12,
      "failures": 0,
      "timeouts": 0,
      "total_duration_seconds": 542.4,
      "avg_duration_seconds": 45.2,
      "min_duration_seconds": 12.3,
      "max_duration_seconds": 120.5
    },
    "trivy": {
      "executions": 23,
      "successes": 19,
      "failures": 1,
      "timeouts": 3,
      "total_duration_seconds": 4151.5,
      "avg_duration_seconds": 180.5,
      "min_duration_seconds": 45.2,
      "max_duration_seconds": 600.0
    }
  }
}
```

### Analysis Implementation

```python
import json
from pathlib import Path

def analyze_timings(timings_file: Path) -> dict:
    """Analyze timings.json and extract performance metrics."""
    data = json.loads(timings_file.read_text())

    analysis = {
        "total_duration": data["total_duration_seconds"],
        "profile": data["profile"],
        "bottlenecks": [],
        "timeout_issues": [],
        "failure_issues": [],
        "recommendations": []
    }

    # Identify bottlenecks (tools taking >50% of total time)
    total_time = data["total_duration_seconds"]
    for tool, metrics in data["tools"].items():
        tool_pct = (metrics["total_duration_seconds"] / total_time) * 100
        if tool_pct > 50:
            analysis["bottlenecks"].append({
                "tool": tool,
                "duration": metrics["total_duration_seconds"],
                "percentage": tool_pct
            })

    # Identify timeout issues
    for tool, metrics in data["tools"].items():
        timeout_rate = metrics["timeouts"] / metrics["executions"]
        if timeout_rate > 0.1:  # >10% timeout rate
            analysis["timeout_issues"].append({
                "tool": tool,
                "timeout_rate": timeout_rate,
                "timeouts": metrics["timeouts"],
                "executions": metrics["executions"]
            })

    # Identify failure issues
    for tool, metrics in data["tools"].items():
        failure_rate = metrics["failures"] / metrics["executions"]
        if failure_rate > 0.05:  # >5% failure rate
            analysis["failure_issues"].append({
                "tool": tool,
                "failure_rate": failure_rate,
                "failures": metrics["failures"],
                "executions": metrics["executions"]
            })

    return analysis
```

---

## Phase 3: Identify Bottlenecks

```python
def identify_bottlenecks(timings: dict, threshold_pct: float = 30.0) -> list:
    """
    Identify tools consuming >threshold% of total scan time.

    Args:
        timings: Parsed timings.json
        threshold_pct: Percentage threshold (default 30%)

    Returns:
        List of bottleneck tools with metrics
    """
    bottlenecks = []
    total_duration = timings["total_duration_seconds"]

    for tool, metrics in timings["tools"].items():
        tool_duration = metrics["total_duration_seconds"]
        tool_pct = (tool_duration / total_duration) * 100

        if tool_pct > threshold_pct:
            bottlenecks.append({
                "tool": tool,
                "total_duration": tool_duration,
                "percentage": tool_pct,
                "executions": metrics["executions"],
                "avg_duration": metrics["avg_duration_seconds"],
                "timeouts": metrics["timeouts"],
                "timeout_rate": metrics["timeouts"] / metrics["executions"]
            })

    # Sort by percentage (descending)
    bottlenecks.sort(key=lambda x: x["percentage"], reverse=True)
    return bottlenecks
```

### Example Output

```text
Bottlenecks Detected (>30% of total time):

1. trivy: 4151.5s (68% of total)
   - Executions: 23
   - Avg duration: 180.5s
   - Timeout rate: 13% (3/23 timeouts)
   - Recommendation: Reduce timeout from 600s to 300s, or exclude slow scans

2. semgrep: 450.2s (37% of total)
   - Executions: 12
   - Avg duration: 37.5s
   - Timeout rate: 0%
   - Recommendation: Consider adding --exclude patterns for vendor code
```

---

## Phase 4: Analyze Timeout Patterns

```python
def analyze_timeouts(timings: dict) -> dict:
    """Analyze timeout patterns and recommend fixes."""
    timeout_analysis = {
        "tools_with_timeouts": [],
        "recommendations": []
    }

    for tool, metrics in timings["tools"].items():
        timeout_rate = metrics["timeouts"] / metrics["executions"]

        if timeout_rate > 0:
            timeout_analysis["tools_with_timeouts"].append({
                "tool": tool,
                "timeout_count": metrics["timeouts"],
                "execution_count": metrics["executions"],
                "timeout_rate": timeout_rate,
                "current_timeout": timings["timeout"],
                "max_duration": metrics["max_duration_seconds"],
                "avg_duration": metrics["avg_duration_seconds"]
            })

            # Generate recommendation
            if timeout_rate > 0.2:  # >20% timeout rate
                recommended_timeout = int(metrics["max_duration_seconds"] * 1.5)
                timeout_analysis["recommendations"].append({
                    "tool": tool,
                    "severity": "high",
                    "issue": f"High timeout rate ({timeout_rate*100:.0f}%)",
                    "current_timeout": timings["timeout"],
                    "recommended_timeout": recommended_timeout,
                    "rationale": f"Max duration was {metrics['max_duration_seconds']}s, "
                                f"recommend {recommended_timeout}s (1.5x max)"
                })
            elif timeout_rate > 0.05:  # 5-20% timeout rate
                timeout_analysis["recommendations"].append({
                    "tool": tool,
                    "severity": "medium",
                    "issue": f"Moderate timeout rate ({timeout_rate*100:.0f}%)",
                    "recommendation": "Monitor performance, consider increasing timeout or adding retries"
                })

    return timeout_analysis
```

### Example Output

```text
Timeout Analysis:

Tools with Timeouts:
1. trivy: 3/23 timeouts (13%)
   - Current timeout: 600s
   - Max duration: 600.0s (hit timeout)
   - Avg duration: 180.5s

Recommendations:
  HIGH: trivy - High timeout rate (13%)
    - Current timeout: 600s
    - Recommended timeout: 900s (1.5x max observed duration)
    - Rationale: Max duration was 600s, recommend 900s buffer

  MEDIUM: nuclei - Moderate timeout rate (8%)
    - Recommendation: Monitor performance, consider adding retries
```

---

## Phase 5: Generate Optimization Recommendations

```python
def generate_recommendations(
    bottlenecks: list,
    timeout_analysis: dict,
    baseline_comparison: dict
) -> dict:
    """Generate comprehensive optimization recommendations."""
    recommendations = {
        "immediate": [],  # P1: High impact, low effort
        "short_term": [],  # P2: Medium impact, medium effort
        "long_term": []  # P3: High effort, strategic improvements
    }

    # Immediate: Fix high timeout rates
    for rec in timeout_analysis.get("recommendations", []):
        if rec.get("severity") == "high":
            recommendations["immediate"].append({
                "priority": "P1",
                "category": "timeout",
                "tool": rec["tool"],
                "action": f"Increase timeout from {rec['current_timeout']}s to {rec['recommended_timeout']}s",
                "config_change": f"""
per_tool:
  {rec['tool']}:
    timeout: {rec['recommended_timeout']}
""",
                "expected_impact": f"Reduce timeout rate from {rec.get('timeout_rate', 0)*100:.0f}% to <5%"
            })

    # Immediate: Reduce threads if thread contention detected
    current_threads = timings.get("threads", 4)
    if len(bottlenecks) > 0 and current_threads > 2:
        recommendations["immediate"].append({
            "priority": "P1",
            "category": "parallelism",
            "action": f"Reduce threads from {current_threads} to {current_threads // 2}",
            "rationale": "High thread count may cause contention for slow tools like Trivy",
            "config_change": f"""
profiles:
  balanced:
    threads: {current_threads // 2}
""",
            "expected_impact": f"Reduce overall scan time by 10-15% (less context switching)"
        })

    # Short-term: Optimize tool configurations
    for bottleneck in bottlenecks:
        if bottleneck["percentage"] > 40:
            recommendations["short_term"].append({
                "priority": "P2",
                "category": "optimization",
                "tool": bottleneck["tool"],
                "action": f"Optimize {bottleneck['tool']} configuration",
                "suggestions": [
                    f"Add --exclude patterns to skip vendor code",
                    f"Use tool-specific caching",
                    f"Consider moving to 'deep' profile only (not balanced)"
                ],
                "expected_impact": f"Reduce {bottleneck['tool']} time by 20-30%"
            })

    # Long-term: Profile restructuring
    if timings.get("total_duration_seconds", 0) > 1800:  # >30 min
        recommendations["long_term"].append({
            "priority": "P3",
            "category": "architecture",
            "action": "Consider profile restructuring",
            "rationale": "Scan duration exceeds 30 minutes, impacting developer experience",
            "suggestions": [
                "Move slow tools (trivy, nuclei) to 'deep' profile only",
                "Create 'quick' profile with fast tools (trufflehog, semgrep only)",
                "Implement differential scanning (scan only changed files)"
            ],
            "expected_impact": "Reduce CI pipeline time from 30min to <10min"
        })

    return recommendations
```

---

## v0.6.2 Tool-Specific Optimization Patterns

### Nuclei Optimization

**Tool Profile:**
- **Purpose:** Fast API/web vulnerability scanning with 4000+ templates
- **Target Type:** Web URLs (`--url`, `--urls-file`)
- **Output:** JSON-lines format (streaming)
- **Typical Runtime:** 60-180 seconds per URL

**Recommended Settings:**

```yaml
# jmo.yml
profiles:
  fast:
    tools: [trufflehog, semgrep, trivy]  # Nuclei not in fast (web-only)

  balanced:
    tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, zap, nuclei]
    per_tool:
      nuclei:
        timeout: 300  # 5 min sufficient for most URLs
        flags: ["-severity", "critical,high", "-rate-limit", "150"]

  deep:
    tools: [trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, nuclei, falco, afl++]
    per_tool:
      nuclei:
        timeout: 600  # 10 min for comprehensive scanning
        flags: ["-severity", "critical,high,medium", "-rate-limit", "100", "-bulk-size", "25"]
```

**Performance Characteristics:**

| Scenario | Timeout | Rate Limit | Templates | Duration |
|----------|---------|------------|-----------|----------|
| Single URL (fast) | 300s | 150 req/s | Critical/High | 60-120s |
| Single URL (deep) | 600s | 100 req/s | Crit/High/Med | 120-300s |
| Multiple URLs (5) | 300s each | 150 req/s | Critical/High | 5-10 min |

**Common Timeouts:**
- Default (unlimited): May run indefinitely on large sites
- 60s: Too short, misses critical findings
- 300s: Sweet spot for balanced profile
- 600s: Comprehensive scanning for deep profile

**Memory Optimization:**

Store nuclei performance data:

```json
{
  "tool": "nuclei",
  "version": "3.1.0",
  "avg_runtime_sec": 95,
  "timeout_sweet_spot": 300,
  "rate_limit_optimal": 150,
  "findings_per_url_avg": 8,
  "template_count": 4200,
  "last_profiled": "2025-10-24"
}
```

### GitLab Scanner Optimization

**Tool Profile:**
- **Purpose:** Full repository scanning for GitLab-hosted repos
- **Target Type:** GitLab repos (`--gitlab-repo`, `--gitlab-group`)
- **Tools:** 10/12 tools (all except ZAP, Nuclei which are web-only)
- **Typical Runtime:** 10-30 minutes per repo (depends on size)

**Key Change from v0.6.1:**

```diff
# v0.6.1: GitLab scanner ran trufflehog only (1 tool)
- Runtime: 2-5 minutes per repo
- Coverage: Secrets only

# v0.6.2: GitLab scanner runs full suite (10 tools)
+ Runtime: 10-30 minutes per repo
+ Coverage: Secrets, SAST, SCA, IaC, Dockerfiles, runtime, fuzzing
```

**Recommended Profile Adjustments:**

```yaml
# jmo.yml
profiles:
  balanced:
    threads: 4  # Reduce from 8 if GitLab scanning enabled
    timeout: 900  # Increase from 600s (GitLab repos may be large)
    per_tool:
      semgrep:
        timeout: 1200  # GitLab repos often larger than local
      trivy:
        timeout: 900
      noseyparker:
        timeout: 1800  # Deep scanning on GitLab Enterprise repos

  deep:
    threads: 2  # Conservative for GitLab + local repos
    timeout: 1800  # 30 min per tool for large GitLab repos
```

**Container Discovery Impact (v0.6.2):**

GitLab scanner now auto-discovers container images from:
- Dockerfiles (`FROM nginx:latest`)
- docker-compose.yml (`image: postgres:14`)
- K8s manifests (`image: myapp:v1.2.3`)

**Estimated Additional Time:**
- Small repo (no containers): +0 minutes
- Medium repo (2-3 images): +5-10 minutes (trivy image scans)
- Large repo (10+ images): +20-40 minutes (multiple trivy scans)

**Optimization Strategy:**

```yaml
# Option 1: Skip container discovery (faster)
# (Feature flag not yet implemented, future v0.7.0)

# Option 2: Limit threads to avoid timeout cascade
profiles:
  balanced:
    threads: 2  # When scanning GitLab with container discovery
    timeout: 1200  # Allow time for discovered images
```

**Memory Storage:**

```json
{
  "tool": "gitlab-scanner",
  "version": "0.6.2",
  "avg_runtime_sec": 1200,
  "container_discovery_overhead_sec": 300,
  "tools_run": 10,
  "typical_containers_discovered": 3,
  "timeout_recommendation": 1800,
  "thread_recommendation": 2
}
```
