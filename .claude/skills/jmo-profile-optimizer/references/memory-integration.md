# Memory Integration Reference

Detailed code and schemas for the memory-integrated performance baseline system introduced in v2.1.0.

---

## Phase 0: Memory Query - Loading Historical Baselines

**Purpose:** Load historical performance baselines before analysis begins.

```python
from scripts.core.memory import query_memory
from datetime import datetime, timedelta

def load_performance_baseline(profile_name: str) -> dict | None:
    """
    Load historical performance baseline for profile.

    Args:
        profile_name: Profile name (fast/balanced/deep)

    Returns:
        Baseline data if found, None otherwise
    """
    memory_data = query_memory("profiles", profile_name)

    if memory_data:
        print(f"[memory] Found baseline for {profile_name} profile")
        print(f"[memory] Last optimized: {memory_data.get('last_optimized')}")
        print(f"[memory] Baseline duration: {memory_data.get('baseline_duration_seconds')}s")

        # Display historical metrics
        for tool, metrics in memory_data.get("tool_performance", {}).items():
            print(f"  {tool}: avg={metrics['avg_duration_seconds']}s, "
                  f"timeout_rate={metrics['timeout_rate']*100:.1f}%")

        return memory_data

    print(f"[memory] No baseline for {profile_name}, establishing new baseline")
    return None
```

### Memory Schema

```json
{
  "profile": "balanced",
  "baseline_duration_seconds": 1200,
  "target_duration_seconds": 900,
  "tool_performance": {
    "trufflehog": {
      "avg_duration_seconds": 45.2,
      "p50_duration_seconds": 42.0,
      "p95_duration_seconds": 78.0,
      "p99_duration_seconds": 120.0,
      "timeout_rate": 0.02,
      "failure_rate": 0.01,
      "success_rate": 0.97,
      "sample_size": 150
    },
    "trivy": {
      "avg_duration_seconds": 180.5,
      "p50_duration_seconds": 165.0,
      "p95_duration_seconds": 285.0,
      "p99_duration_seconds": 420.0,
      "timeout_rate": 0.15,
      "failure_rate": 0.03,
      "success_rate": 0.82,
      "sample_size": 150,
      "notes": "High timeout rate, recommend increasing timeout to 900s"
    }
  },
  "recommended_config": {
    "threads": 4,
    "timeout": 600,
    "per_tool": {
      "trivy": {
        "timeout": 900
      }
    }
  },
  "last_optimized": "2025-09-15",
  "optimization_count": 3,
  "created_by": "jmo-profile-optimizer v2.1.0"
}
```

---

## Phase 2: Compare with Memory Baseline

**Purpose:** Detect performance regressions by comparing current metrics against stored baselines.

```python
def compare_with_baseline(current: dict, baseline: dict | None) -> dict:
    """
    Compare current performance with historical baseline.

    Args:
        current: Current timings analysis
        baseline: Historical baseline from memory (or None)

    Returns:
        Comparison report with regressions and improvements
    """
    if not baseline:
        return {
            "status": "no_baseline",
            "message": "Establishing new baseline"
        }

    comparison = {
        "status": "compared",
        "regressions": [],
        "improvements": [],
        "stable": []
    }

    # Compare total duration
    current_duration = current["total_duration"]
    baseline_duration = baseline["baseline_duration_seconds"]
    duration_change_pct = ((current_duration - baseline_duration) / baseline_duration) * 100

    if duration_change_pct > 10:  # >10% slower
        comparison["regressions"].append({
            "metric": "total_duration",
            "current": current_duration,
            "baseline": baseline_duration,
            "change_pct": duration_change_pct,
            "severity": "high" if duration_change_pct > 25 else "medium"
        })
    elif duration_change_pct < -10:  # >10% faster
        comparison["improvements"].append({
            "metric": "total_duration",
            "current": current_duration,
            "baseline": baseline_duration,
            "change_pct": duration_change_pct
        })

    # Compare per-tool performance
    for tool, current_metrics in current.get("tools", {}).items():
        baseline_metrics = baseline.get("tool_performance", {}).get(tool)
        if not baseline_metrics:
            continue

        # Compare average duration
        current_avg = current_metrics["avg_duration_seconds"]
        baseline_avg = baseline_metrics["avg_duration_seconds"]
        avg_change_pct = ((current_avg - baseline_avg) / baseline_avg) * 100

        if avg_change_pct > 15:  # >15% slower
            comparison["regressions"].append({
                "metric": f"{tool}_avg_duration",
                "current": current_avg,
                "baseline": baseline_avg,
                "change_pct": avg_change_pct,
                "severity": "medium"
            })

        # Compare timeout rate
        current_timeout_rate = current_metrics["timeouts"] / current_metrics["executions"]
        baseline_timeout_rate = baseline_metrics["timeout_rate"]
        timeout_change = current_timeout_rate - baseline_timeout_rate

        if timeout_change > 0.05:  # >5% increase in timeout rate
            comparison["regressions"].append({
                "metric": f"{tool}_timeout_rate",
                "current": current_timeout_rate,
                "baseline": baseline_timeout_rate,
                "change": timeout_change,
                "severity": "high"
            })

    return comparison
```

### Example Comparison Output

```text
[baseline] Comparing with baseline from 2025-09-15

Regressions Detected:
  total_duration: 1215s (current) vs 900s (baseline) = +35% slower [HIGH]
  trivy_timeout_rate: 0.13 (current) vs 0.02 (baseline) = +11% increase [HIGH]
  trivy_avg_duration: 180s (current) vs 145s (baseline) = +24% slower [MEDIUM]

Improvements Detected:
  trufflehog_avg_duration: 45s (current) vs 52s (baseline) = -13% faster

Recommendation: Investigate Trivy performance regression (timeout rate increased 11%)
```

---

## Phase 6: Store Optimization Memory

**Purpose:** Persist optimization results and updated baseline after analysis.

```python
from scripts.core.memory import store_memory
from datetime import datetime

def store_optimization_memory(profile: str, timings: dict, recommendations: dict):
    """Store optimization results in memory."""
    # Calculate percentiles from individual execution durations
    tool_performance = {}
    for tool, metrics in timings["tools"].items():
        tool_performance[tool] = {
            "avg_duration_seconds": metrics["avg_duration_seconds"],
            "p50_duration_seconds": metrics.get("p50", metrics["avg_duration_seconds"]),
            "p95_duration_seconds": metrics.get("p95", metrics["max_duration_seconds"] * 0.95),
            "p99_duration_seconds": metrics.get("p99", metrics["max_duration_seconds"]),
            "timeout_rate": metrics["timeouts"] / metrics["executions"],
            "failure_rate": metrics["failures"] / metrics["executions"],
            "success_rate": metrics["successes"] / metrics["executions"],
            "sample_size": metrics["executions"]
        }

    memory_data = {
        "profile": profile,
        "baseline_duration_seconds": timings["total_duration_seconds"],
        "target_duration_seconds": timings["total_duration_seconds"] * 0.75,  # 25% improvement goal
        "tool_performance": tool_performance,
        "recommended_config": {
            "threads": recommendations.get("threads", timings["threads"]),
            "timeout": recommendations.get("timeout", timings["timeout"]),
            "per_tool": recommendations.get("per_tool", {})
        },
        "last_optimized": datetime.now().isoformat(),
        "optimization_count": memory_data.get("optimization_count", 0) + 1 if memory_data else 1,
        "created_by": "jmo-profile-optimizer v2.1.0"
    }

    store_memory("profiles", profile, memory_data)
    print(f"[memory] Stored optimization results for {profile} profile")
    print(f"[memory] Location: .jmo/memory/profiles/{profile}.json")
```

---

## Upgrade Path from v2.0.0

### For Existing Profiles

1. **Establish Baseline:**

```bash
# Run scan with profiling
jmotools balanced --repos-dir ~/repos --profile

# Store baseline
python3 scripts/dev/store_profile_baseline.py results/summaries/timings.json
```

2. **Future Scans:**
   - Baselines automatically loaded from memory
   - Regressions detected and reported
