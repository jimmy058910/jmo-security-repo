# Optimization Patterns Reference

Code implementations for the report-phase profiling that `jmo report --profile`
makes available: per-adapter parse cost, findings volume, and worker-count
tuning.

> **Read this before using any code below.**
>
> `timings.json` is written by the **report** phase, not the scan phase.
> `aggregate_seconds` wraps `gather_results()`
> (`scripts/cli/report_orchestrator.py:106-108`), and each `jobs[]` entry times a
> single `adapter.parse(path)` call
> (`scripts/core/normalize_and_report.py:305-318`). The file measures how long
> JMo took to **read and normalize tool output** — not how long the tools took to
> **run**.
>
> **Do not infer tool runtime, timeouts, or failures from this file.** Those
> live in `scan-timings.json`, written by the scan phase — see
> [Phase 4](#phase-4-timeout-and-failure-analysis). `history_db` still stores a
> single `duration_seconds` per *scan* (`scripts/core/history_db.py:103`) with
> no tool breakdown, so cross-scan *rates* remain unavailable.

---

## Phase 1: Load and Analyze timings.json

### timings.json schema

Written to `<results-dir>/summaries/timings.json` by
`scripts/cli/report_orchestrator.py:344-352` when `jmo report --profile` is used.
**Treat that function as the source of truth**; the sample below is illustrative.

```json
{
  "aggregate_seconds": 3.402,
  "recommended_threads": 8,
  "jobs": [
    {"tool": "trivy", "path": "results/individual-repos/acme/trivy.json", "seconds": 0.314772, "count": 412},
    {"tool": "trivy", "path": "results/individual-repos/beta/trivy.json", "seconds": 0.288104, "count": 377},
    {"tool": "semgrep", "path": "results/individual-repos/acme/semgrep.json", "seconds": 0.301988, "count": 96}
  ],
  "meta": {"max_workers": 8}
}
```

| Key | Type | Meaning |
|---|---|---|
| `aggregate_seconds` | float | Wall-clock duration of the whole aggregation pass |
| `recommended_threads` | int | CPU-derived suggestion, clamped to `profiling_min_threads`..`profiling_max_threads` (`scripts/core/config.py:168-170`) |
| `jobs` | list | One entry per *(tool, result file)* parsed |
| `jobs[].tool` | str | Adapter name |
| `jobs[].path` | str | Result file that was parsed |
| `jobs[].seconds` | float | Parse duration for that one file |
| `jobs[].count` | int | Findings produced by that parse |
| `meta.max_workers` | int | Worker count actually used (`scripts/core/normalize_and_report.py:155`) |

There is **no** `profile`, `total_duration_seconds`, `tools`, `threads`,
`timeout`, `timeouts`, or `failures` key. `jobs` is a flat list, not a per-tool
dict — a tool appears once per result file, so a tool with 23 result files
contributes 23 duration samples. That is what makes real percentiles possible.

### Analysis implementation

```python
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

# One threshold for every phase, and for SKILL.md Phase 3. Changing it here
# changes it everywhere; do not introduce a second value.
BOTTLENECK_THRESHOLD_PCT = 30.0


def load_timings(timings_file: Path) -> dict:
    """Load timings.json, rejecting shapes this skill cannot analyse."""
    data = json.loads(timings_file.read_text(encoding="utf-8"))
    if "jobs" not in data:
        raise ValueError(
            f"{timings_file} has no 'jobs' key, so it was not produced by "
            "'jmo report --profile'. See scripts/cli/report_orchestrator.py:344."
        )
    return data


def percentiles(samples: list[float]) -> dict:
    """Real percentiles from observed samples, or None when unsupported.

    A percentile is only reported once the sample is large enough to express it.
    Deriving p95 from the maximum is not a percentile and produces false latency
    trends, so this returns None instead of approximating.
    """
    n = len(samples)
    if n == 0:
        return {"p50_seconds": None, "p95_seconds": None, "p99_seconds": None}

    ordered = sorted(samples)

    def nearest_rank(q: float) -> float:
        idx = min(n - 1, max(0, math.ceil(q * n) - 1))
        return round(ordered[idx], 6)

    return {
        "p50_seconds": nearest_rank(0.50),
        "p95_seconds": nearest_rank(0.95) if n >= 20 else None,
        "p99_seconds": nearest_rank(0.99) if n >= 100 else None,
    }


def analyze_timings(data: dict) -> dict:
    """Group jobs by tool and compute per-tool parse cost.

    Returns the *analysed* schema consumed by every later phase and by
    references/memory-integration.md. It is deliberately distinct from the raw
    timings.json schema above: raw goes in, analysed comes out, and no phase
    mixes the two.
    """
    samples: dict[str, list[float]] = defaultdict(list)
    findings: dict[str, int] = defaultdict(int)

    for job in data.get("jobs", []):
        samples[job["tool"]].append(job["seconds"])
        findings[job["tool"]] += job.get("count", 0)

    cumulative = sum(sum(v) for v in samples.values())

    tools = {}
    for tool, secs in samples.items():
        total = sum(secs)
        tools[tool] = {
            "parse_seconds_total": round(total, 6),
            "parse_count": len(secs),
            "findings": findings[tool],
            "mean_seconds": round(statistics.fmean(secs), 6),
            "max_seconds": round(max(secs), 6),
            # Share of CUMULATIVE parse work, not of wall clock. Jobs run in
            # parallel across meta.max_workers, so per-tool shares of wall clock
            # are not well defined and would not sum to 100.
            "share_pct": (total / cumulative * 100) if cumulative else None,
            **percentiles(secs),
        }

    return {
        "aggregate_seconds": data.get("aggregate_seconds"),
        "cumulative_parse_seconds": round(cumulative, 6),
        "max_workers": data.get("meta", {}).get("max_workers"),
        "recommended_threads": data.get("recommended_threads"),
        "tools": tools,
    }
```

Every division above is guarded: `share_pct` is `None` when nothing was parsed,
`percentiles` returns `None` entries for an empty sample, and `statistics.fmean`
and `max` are only reached for a tool that has at least one job. An empty scan
yields an analysis with `tools == {}` rather than a `ZeroDivisionError`.

---

## Phase 3: Identify Bottlenecks

```python
def identify_bottlenecks(
    analysis: dict,
    threshold_pct: float = BOTTLENECK_THRESHOLD_PCT,
) -> list:
    """Tools above `threshold_pct` of cumulative parse time, slowest first."""
    if not analysis["cumulative_parse_seconds"]:
        return []  # nothing was parsed; there is nothing to rank

    bottlenecks = [
        {"tool": tool, **metrics}
        for tool, metrics in analysis["tools"].items()
        if metrics["share_pct"] is not None
        and metrics["share_pct"] > threshold_pct
    ]
    bottlenecks.sort(key=lambda x: x["share_pct"], reverse=True)
    return bottlenecks
```

### Example output

```text
Aggregation wall clock: 3.402s   Cumulative parse time: 12.100s   max_workers: 8

Bottlenecks (>30% of cumulative parse time):

1. trivy: 7.240s (59.8% of cumulative parse time)
   - Parses: 23 result files, 4310 findings
   - Mean: 0.315s   p50: 0.288s   p95: 0.981s

2. semgrep: 3.890s (32.1% of cumulative parse time)
   - Parses: 12 result files, 1204 findings
   - Mean: 0.324s   p50: 0.301s   p95: n/a (12 samples, needs 20)
```

Cumulative parse time exceeds wall clock because jobs run in parallel. Shares are
taken against cumulative parse time, so they sum to at most 100% — reporting them
against wall clock would let them exceed it.

---

## Phase 4: Timeout and Failure Analysis

Earlier revisions of this skill documented an `analyze_timeouts()` function
computing per-tool timeout and failure rates from
`metrics["timeouts"] / metrics["executions"]`. Those keys never existed, and
when this skill was rewritten there was no per-tool scan data at all, so the
analysis was deleted rather than repaired.

**#722 added the data source.** Every scan now writes
`<results-dir>/individual-*/<target>/scan-timings.json`, built from the
`ToolResult` objects `ToolRunner` had always produced and the scan jobs had
always discarded.

Schema — the authority is `scripts/core/scan_timings.py`, and `schema_version`
guards it:

| Key | Meaning |
|---|---|
| `schema_version` | `1`. Refuse a shape you do not recognise rather than misreading it. |
| `target` / `target_type` | Which target, and one of `repo` / `image` / `iac` / `url` / `k8s`. |
| `wall_seconds` | Elapsed time of the whole parallel tool batch. |
| `tools[]` | One entry per invocation: `tool`, `status`, `timed_out`, `returncode`, `attempts`, `duration`, `output_file`, `error_message`. |

`tools[].status` carries **four** values, not a coarse pass/fail:
`success`, `no_output`, `error`, `retry_exhausted`. Read `no_output`
carefully — it means an *accepted* return code with an empty artifact, which
is a tool that appeared to work and did not.

> **A timeout is `tools[].timed_out`, not a `status` value.** `status` has no
> `"timeout"` member — its docstring claimed one for months while `run_tool`
> never assigned it, which is how #722 came to be filed on a false premise.
> #727 added a separate boolean instead of a fifth status, so that
> `retry_exhausted` keeps its own meaning: *this failure burned the whole retry
> budget*. A timed-out tool therefore reports **both**
> `status: "error" | "retry_exhausted"` **and** `timed_out: true`.
>
> Read them together. `timed_out` with `retry_exhausted` and `attempts: 4` is a
> tool that is reliably too slow for its budget; `timed_out` with `error` and
> `attempts: 1` timed out once and was not retried.

### The denominator trap

Tools run concurrently, so `sum(tools[].duration)` **exceeds** `wall_seconds`.
Use `wall_seconds` as the denominator for "what share of the scan was tool X".
Using the sum understates every tool by the parallelism factor — the same
invalid-denominator defect this skill was reviewed for.

### What is still not answerable

A **rate** needs more than one scan. `scan-timings.json` is per-scan and per-
target, and nothing collects it across runs — `history_db` still stores only
one `duration_seconds` per scan (`scripts/core/history_db.py:103`) with no
per-tool breakdown. So:

- "did `dependency-check` time out on this scan" — yes, read `status`.
- "does `dependency-check` time out 30% of the time" — no. That needs the
  history persistence deferred out of #722.

---

## Phase 5: Generate Optimization Recommendations

```python
def generate_recommendations(analysis: dict, bottlenecks: list) -> dict:
    """Build recommendations from measured report-phase data.

    Every value read here comes from `analysis` (the object returned by
    analyze_timings) or from `bottlenecks`, so the function has no free
    variables and no caller has to supply anything it did not compute.
    """
    recommendations = {
        "immediate": [],  # P1: high impact, low effort
        "short_term": [],  # P2: medium impact, medium effort
        "long_term": [],  # P3: strategic
    }

    # P1: worker count. report_orchestrator already derives a recommendation
    # from CPU count; surface it only when it disagrees with what actually ran.
    used = analysis.get("max_workers")
    recommended = analysis.get("recommended_threads")
    if used and recommended and used != recommended:
        recommendations["immediate"].append({
            "priority": "P1",
            "category": "parallelism",
            "action": f"Set report threads to {recommended} (this run used {used})",
            "rationale": (
                "recommended_threads is derived from os.cpu_count() and clamped to "
                "profiling_min_threads..profiling_max_threads "
                "(scripts/core/config.py:168-170)."
            ),
            "config_change": f"jmo report <results-dir> --threads {recommended}",
        })

    # P2: a dominant adapter is worth profiling directly.
    for bottleneck in bottlenecks:
        recommendations["short_term"].append({
            "priority": "P2",
            "category": "adapter-performance",
            "tool": bottleneck["tool"],
            "action": f"Profile the {bottleneck['tool']} adapter's parse path",
            "evidence": (
                f"{bottleneck['parse_seconds_total']:.2f}s over "
                f"{bottleneck['parse_count']} files "
                f"({bottleneck['share_pct']:.1f}% of cumulative parse time), "
                f"{bottleneck['findings']} findings"
            ),
        })

    # P3: findings volume drives parse and dedup cost more than adapter code does.
    if analysis["tools"]:
        noisiest, metrics = max(
            analysis["tools"].items(), key=lambda kv: kv[1]["findings"]
        )
        if metrics["findings"] > 5000:
            recommendations["long_term"].append({
                "priority": "P3",
                "category": "noise",
                "tool": noisiest,
                "action": f"Reduce {noisiest} finding volume at the source",
                "rationale": (
                    f"{metrics['findings']} findings dominate both parse time and "
                    "downstream deduplication cost. Tune the tool's own severity "
                    "and exclude flags under per_tool in jmo.yml before optimising "
                    "the adapter."
                ),
            })

    return recommendations
```

Call it with the objects the earlier phases produced:

```python
data = load_timings(Path("results/summaries/timings.json"))
analysis = analyze_timings(data)
bottlenecks = identify_bottlenecks(analysis)
recommendations = generate_recommendations(analysis, bottlenecks)
```

---

## Tool-Specific Optimization Patterns

**Profile tool lists are not reproduced here.** They live in
`scripts/core/tool_registry.py:PROFILE_TOOLS`, which `jmo.yml` names as the
single source of truth. Read them with:

```bash
python -c "from scripts.core.tool_registry import PROFILE_TOOLS; print(sorted(PROFILE_TOOLS['balanced']))"
```

The snippets below show **per-tool overrides only** — the part a profile actually
configures in `jmo.yml`.

### Nuclei

- **Purpose:** web/API vulnerability scanning across a large template set
- **Target flags:** `--url`, `--urls-file`
- **Output:** JSON-lines (streaming)
- **Present in:** `fast`, `slim`, `balanced`, `deep`

```yaml
# jmo.yml
profiles:
  balanced:
    per_tool:
      nuclei:
        timeout: 300
        flags: ["-severity", "critical,high", "-rate-limit", "150"]

  deep:
    per_tool:
      nuclei:
        timeout: 600
        flags: ["-severity", "critical,high,medium", "-rate-limit", "100", "-bulk-size", "25"]
```

Timeout guidance, from configured values rather than measured runtime:

| Configured timeout | Effect |
|---|---|
| unset | May run until the scan-level timeout on large sites |
| 60s | Frequently too short for a full template pass |
| 300s | Common choice for `balanced` |
| 600s | Common choice for `deep` |

### GitLab targets

- **Target flags:** `--gitlab-repo`, `--gitlab-group`
- **Runs:** the same profile tool list as any other repository target, minus
  tools that need a live URL

Remote repositories are usually larger than local checkouts, and cloning is
included in the scan window, so per-tool timeouts tuned for local repos are
often too tight:

```yaml
# jmo.yml
profiles:
  balanced:
    threads: 4
    timeout: 900
    per_tool:
      semgrep:
        timeout: 1200
      trivy:
        timeout: 900
      noseyparker:
        timeout: 1800
```

**Container discovery.** The GitLab path also discovers container images
referenced by Dockerfiles, `docker-compose.yml`, and Kubernetes manifests, then
scans each with Trivy. Every discovered image is an additional scan target, so
budget scan time by image count rather than by repository count.

> Whether any of these settings actually helps is not measurable from
> `timings.json` — it records report-phase parsing only. Verify a timeout change
> against `scan-timings.json`: re-run the scan and compare that tool's
> `duration` and `timed_out`. A cap that "fixed" a slow tool by killing it shows
> up as `timed_out: true`, which a whole-scan duration from `jmo history list`
> would have reported as an improvement.
