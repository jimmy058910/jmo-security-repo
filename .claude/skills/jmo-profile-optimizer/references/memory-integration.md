# Memory Integration Reference

How this skill persists performance baselines between sessions, using the
`.jmo/memory/` file convention shared by all JMo skills.

> **There is no memory module to import.** `.jmo/memory/` is a plain-file
> convention that each skill implements itself with Read and Write — see
> [`../../references/memory-integration-pattern.md`](../../references/memory-integration-pattern.md).
> This skill owns the `profiles/` namespace. `.jmo/` is gitignored
> (`.gitignore:179`), so the directory is absent from a fresh clone and is
> created on first store. A cache miss is normal operation, not an error.

---

## Profile name validation (required before any memory path)

The profile name reaches this skill as `$ARGUMENTS` — untrusted input that is
interpolated into a file path. Validate it **before** constructing any path, or
a value like `../../outside` redirects reads and writes outside the namespace.

```python
import re
from pathlib import Path

from scripts.core.config import load_config
from scripts.core.tool_registry import PROFILE_TOOLS

MEMORY_ROOT = Path(".jmo/memory/profiles")

# Deliberately no separators, no dots, no leading dash.
_SAFE_PROFILE = re.compile(r"[a-z][a-z0-9_-]*")


def memory_path(profile: str) -> Path:
    """Resolve a profile's memory file, rejecting anything unsafe or unknown.

    Two checks, because either alone is insufficient: the pattern rejects
    traversal and separators, and the membership check rejects well-formed names
    that are not real profiles.
    """
    if not _SAFE_PROFILE.fullmatch(profile):
        raise ValueError(
            f"Invalid profile name {profile!r}: expected lowercase alphanumerics, "
            "'-' or '_' only."
        )

    # Built-in profiles plus any the user defined under `profiles:` in jmo.yml,
    # which is a free-form dict -- do not hardcode the built-in list.
    known = set(PROFILE_TOOLS) | set(load_config("jmo.yml").profiles)
    if profile not in known:
        raise ValueError(
            f"Unknown profile {profile!r}. Known profiles: {', '.join(sorted(known))}"
        )

    return MEMORY_ROOT / f"{profile}.json"
```

At the time of writing, `PROFILE_TOOLS` defines `fast`, `slim`, `balanced`, and
`deep`. The list is read at runtime rather than reproduced, so a new profile
needs no change here.

---

## The two timing schemas

Two distinct objects flow through this skill. Mixing them is what previously
caused per-tool comparisons to be silently skipped, so they are named apart:

| Object | Produced by | Shape |
|---|---|---|
| **raw** | `jmo report --profile` | `aggregate_seconds`, `recommended_threads`, `jobs[]`, `meta` — see [optimization-patterns.md](optimization-patterns.md#timingsjson-schema) |
| **analysed** | `analyze_timings(raw)` | `aggregate_seconds`, `cumulative_parse_seconds`, `max_workers`, `recommended_threads`, `tools{}` |

**Every function on this page takes the analysed object.** Nothing here reads
raw `timings.json` keys.

---

## Phase 0: Memory Query — loading a historical baseline

```python
import json


def load_performance_baseline(profile: str) -> dict | None:
    """Load the stored baseline for a profile, or None on a cache miss."""
    path = memory_path(profile)
    if not path.exists():
        print(f"[memory] No baseline for {profile}, establishing a new one")
        return None

    baseline = json.loads(path.read_text(encoding="utf-8"))
    meta = baseline.get("metadata", {})
    print(f"[memory] Found baseline for {profile}")
    print(f"[memory] Last updated: {meta.get('last_updated')}")
    print(f"[memory] Cumulative parse time: {baseline.get('cumulative_parse_seconds')}s")

    for tool, metrics in baseline.get("tool_performance", {}).items():
        print(f"  {tool}: mean={metrics['mean_seconds']}s over {metrics['parse_count']} parses")

    return baseline
```

### Memory schema

```json
{
  "profile": "balanced",
  "aggregate_seconds": 3.402,
  "cumulative_parse_seconds": 12.1,
  "max_workers": 8,
  "recommended_threads": 8,
  "tool_performance": {
    "trivy": {
      "parse_seconds_total": 7.24,
      "parse_count": 23,
      "findings": 4310,
      "mean_seconds": 0.314783,
      "max_seconds": 0.981204,
      "p50_seconds": 0.288104,
      "p95_seconds": 0.981204,
      "p99_seconds": null,
      "share_pct": 59.8
    }
  },
  "metadata": {
    "last_updated": "2026-08-05T09:14:22",
    "optimization_count": 3,
    "created_by": "jmo-profile-optimizer"
  }
}
```

`p95_seconds` and `p99_seconds` are `null` when the sample was too small to
support them (20 and 100 parses respectively). `null` means "not enough data",
never "zero" — do not substitute a value derived from `max_seconds`.

---

## Phase 2: Compare with the memory baseline

```python
def pct_change(current: float, baseline: float) -> float | None:
    """Percentage change, or None when the baseline offers no denominator."""
    if not baseline:  # zero or missing -- no meaningful ratio exists
        return None
    return (current - baseline) / baseline * 100


def compare_with_baseline(analysis: dict, baseline: dict | None) -> dict:
    """Compare an analysed timing object with a stored baseline.

    Args:
        analysis: the object returned by analyze_timings()
        baseline: the object returned by load_performance_baseline(), or None
    """
    if not baseline:
        return {"status": "no_baseline", "message": "Establishing a new baseline"}

    comparison = {
        "status": "compared",
        "regressions": [],
        "improvements": [],
        "no_sample": [],
    }

    # Total parse cost.
    change = pct_change(
        analysis["cumulative_parse_seconds"],
        baseline.get("cumulative_parse_seconds", 0),
    )
    if change is None:
        comparison["no_sample"].append("cumulative_parse_seconds")
    elif change > 10:
        comparison["regressions"].append({
            "metric": "cumulative_parse_seconds",
            "current": analysis["cumulative_parse_seconds"],
            "baseline": baseline["cumulative_parse_seconds"],
            "change_pct": change,
            "severity": "high" if change > 25 else "medium",
        })
    elif change < -10:
        comparison["improvements"].append({
            "metric": "cumulative_parse_seconds",
            "current": analysis["cumulative_parse_seconds"],
            "baseline": baseline["cumulative_parse_seconds"],
            "change_pct": change,
        })

    # Per-tool mean parse duration.
    for tool, current_metrics in analysis["tools"].items():
        baseline_metrics = baseline.get("tool_performance", {}).get(tool)
        if not baseline_metrics:
            continue  # new tool -- nothing to compare against

        change = pct_change(
            current_metrics["mean_seconds"], baseline_metrics.get("mean_seconds", 0)
        )
        if change is None:
            comparison["no_sample"].append(f"{tool}_mean_seconds")
        elif change > 15:
            comparison["regressions"].append({
                "metric": f"{tool}_mean_seconds",
                "current": current_metrics["mean_seconds"],
                "baseline": baseline_metrics["mean_seconds"],
                "change_pct": change,
                "severity": "medium",
            })

    return comparison
```

Every ratio goes through `pct_change`, so a zero or absent baseline produces a
`no_sample` entry instead of `ZeroDivisionError`. Newly introduced tools are
skipped explicitly rather than compared against nothing.

> **Timeout and failure rates are not compared, because JMo does not record
> them.** See [optimization-patterns.md Phase 4](optimization-patterns.md#phase-4-timeout-and-failure-analysis--no-data-source).

### Example comparison output

```text
[baseline] Comparing with baseline from 2026-07-02

Regressions:
  cumulative_parse_seconds: 12.10s vs 8.90s = +36.0% [HIGH]
  trivy_mean_seconds: 0.315s vs 0.244s = +29.1% [MEDIUM]

Improvements:
  semgrep_mean_seconds: 0.324s vs 0.401s = -19.2%

No sample:
  grype_mean_seconds (no baseline value)

Note: this measures report-phase parsing. A parse-time regression usually means
more findings, not a slower scan -- check the findings counts first.
```

---

## Phase 6: Store the updated baseline

```python
from datetime import datetime


def store_optimization_memory(profile: str, analysis: dict) -> None:
    """Persist the analysed timings as the profile's new baseline."""
    path = memory_path(profile)

    # Load the existing record FIRST, into its own variable. Reading the record
    # being built is an UnboundLocalError on every call.
    previous = load_performance_baseline(profile)
    previous_count = (previous or {}).get("metadata", {}).get("optimization_count", 0)

    memory_data = {
        "profile": profile,
        "aggregate_seconds": analysis["aggregate_seconds"],
        "cumulative_parse_seconds": analysis["cumulative_parse_seconds"],
        "max_workers": analysis["max_workers"],
        "recommended_threads": analysis["recommended_threads"],
        "tool_performance": analysis["tools"],
        "metadata": {
            "last_updated": datetime.now().isoformat(timespec="seconds"),
            "optimization_count": previous_count + 1,
            "created_by": "jmo-profile-optimizer",
        },
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(memory_data, indent=2), encoding="utf-8")
    print(f"[memory] Stored baseline for {profile} at {path}")
```

`analysis["tools"]` is stored as-is, so the memory schema and the analysed schema
never drift apart — there is one shape, written once and read back unchanged.

---

## Establishing a first baseline

```bash
# 1. Run a scan, then a report with profiling enabled.
jmo scan --repos-dir ~/repos --profile-name balanced --results-dir ./results
jmo report ./results --profile

# 2. Confirm the timings file exists.
cat results/summaries/timings.json

# 3. Run this skill against it -- Phase 6 writes the baseline automatically.
```

`jmo scan --profile-name` selects the profile; `jmo report --profile` is the
timing flag. They are different options with similar names.

Whole-scan wall-clock durations, which `timings.json` does not contain, come
from the history database instead:

```bash
jmo history list --limit 10     # includes a Duration column
jmo history show <scan-id>      # includes "Duration: N seconds"
```
