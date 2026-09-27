# Optimization Patterns Reference

Code implementations for the report-phase profiling that `jmo report --profile`
makes available (per-adapter parse cost, findings volume, worker-count tuning),
and for the per-tool run times and timeouts every `jmo scan` records in
`scan-timings.json` ([Phase 4](#phase-4-timeout-and-failure-analysis)).

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
| `recommended_threads` | int | CPU-derived suggestion, clamped to `profiling_min_threads`..`profiling_max_threads` (`scripts/core/config.py`, set from `jmo.yml`'s `profiling:` block) |
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

**#722 added the data source, and v2.0.0 made it complete.** Every scan writes
`<results-dir>/individual-*/<target>/scan-timings.json`. Since schema 3 (v2.0.0)
it has one row for **every requested tool** on the target, whether the tool ran,
was skipped or failed, and the same rows reach the history database's
`scan_tool_runs` table.

Schema — the authority is `scripts/core/scan_timings.py`, and `schema_version`
guards it:

| Key | Meaning |
|---|---|
| `schema_version` | `3` (`SCAN_TIMINGS_SCHEMA_VERSION`). Refuse a shape you do not recognise rather than misreading it. |
| `target` / `target_type` | Which target, and one of `repo` / `image` / `iac` / `url` / `k8s` / `gitlab`. |
| `wall_seconds` | Elapsed time of the whole parallel tool batch. |
| `outcome` / `error` | `completed`, or `failed-before-tools` with a one-line `error` (a failed clone, a missing credential, a tree with no files to scan). A failed target still has a row per tool, each `failed` with that reason, or `skipped` when the tool does not read that kind of target. |
| `tools[]` | One row per requested tool: `tool`, `state`, `reason`, `seconds`, `exit_code`, `attempts`, `invocations`, `detail`. |

`state` is `ran`, `skipped` or `failed`. `reason` is `null` for `ran` and one of
a closed set otherwise (`Reason` in `scan_timings.py`):

- **skipped:** `needs --url`, `not for this target type`, `not installed` (only
  under `--allow-missing-tools`), `no Dockerfiles`, `no shell scripts`,
  `no Go sources`, `no IaC or workflow files`
- **failed:** `not installed`, `timed out`, `no files to scan`,
  `examined 0 files`, `unaccepted exit code`, `no output`,
  `not found at run time`, `could not be run`, `target not scanned`,
  `scanner error`

> **Only `timed out` is a budget question.** `no output` is an accepted exit
> code with an empty artifact, a tool that appeared to work and did not.
> `examined 0 files` is a tool whose own output says it read nothing (semgrep's
> `paths.scanned`, gosec's `Stats.files`). Both belong in a bug report, not in
> `jmo.yml`.
>
> `attempts` counts every try. `timed out` with `attempts: 4` is a tool that is
> reliably too slow for its budget; with `attempts: 1` it timed out once and was
> not retried. `exit_code` is the failed run's own code, or `null` when there was
> none (a timeout, a spawn failure).

### The denominator trap

Tools run concurrently, so `sum(tools[].seconds)` **exceeds** `wall_seconds`.
Use `wall_seconds` as the denominator for "what share of the scan was tool X".
Using the sum understates every tool by the parallelism factor — the same
invalid-denominator defect this skill was reviewed for.

### Summarising one scan per tool

```python
import json
from collections import defaultdict
from pathlib import Path


def summarize_scan_timings(results_dir: Path) -> dict:
    """Per-tool run time and outcomes across every target of ONE scan.

    Shares are of each target's own wall_seconds (see the denominator trap), so
    `worst_share_pct` answers "on which target did this tool dominate the scan".
    `runs` counts every row that was not skipped, ran or failed; a skipped row
    is counted apart and never timed, because it did not run.
    """
    per_tool: dict[str, dict] = defaultdict(
        lambda: {"runs": 0, "skipped": 0, "timed_out": 0, "no_output": 0,
                 "max_seconds": 0.0, "worst_share_pct": None, "worst_target": None}
    )
    failed_targets = []

    for path in sorted(results_dir.glob("individual-*/*/scan-timings.json")):
        doc = json.loads(path.read_bytes())
        if doc.get("schema_version") != 3:
            raise ValueError(f"{path}: unrecognised schema_version {doc.get('schema_version')!r}")
        if doc.get("outcome") != "completed":
            failed_targets.append((doc.get("target"), doc.get("error")))
            continue
        wall = doc.get("wall_seconds") or 0
        for row in doc.get("tools", []):
            t = per_tool[row["tool"]]
            if row["state"] == "skipped":
                t["skipped"] += 1
                continue
            t["runs"] += 1
            t["timed_out"] += row.get("reason") == "timed out"
            t["no_output"] += row.get("reason") in ("no output", "examined 0 files")
            seconds = row.get("seconds") or 0.0
            t["max_seconds"] = max(t["max_seconds"], seconds)
            share = seconds / wall * 100 if wall else None
            if share is not None and (t["worst_share_pct"] is None or share > t["worst_share_pct"]):
                t["worst_share_pct"], t["worst_target"] = round(share, 1), doc.get("target")

    return {"tools": dict(per_tool), "failed_targets": failed_targets}
```

A tool with `timed_out > 0` is a P1 recommendation: raise its
`per_tool.<tool>.timeout`, or give it flags that shrink its work. A tool with
`no_output > 0` is not a performance problem at all; it is a tool that appeared
to succeed and read or wrote nothing, and belongs in a bug report rather than in
`jmo.yml`.

### Rates across scans: `scan_tool_runs`

A **rate** needs more than one scan. Since v2.0.0, `store_scan` writes every row
into the history database's `scan_tool_runs` table, keyed by scan, target type,
target and tool (#722). So "does semgrep time out 30% of the time" is one query:

```bash
jmo history query "SELECT tool, COUNT(*) AS runs, SUM(reason IS 'timed out') AS timeouts, ROUND(AVG(seconds), 1) AS mean_s, MAX(seconds) AS max_s FROM scan_tool_runs WHERE state != 'skipped' GROUP BY tool ORDER BY mean_s DESC"
```

`IS`, not `=`: a `ran` row's `reason` is `NULL`, and `NULL = 'timed out'` is
`NULL`, which `SUM` skips, so a tool that never timed out would show a blank
instead of 0. Only scans stored since v2.0.0 have rows; an older scan is simply
not in the rate. `jmo history show <scan-id>` prints one scan's rows.

---

## Phase 5: Generate Optimization Recommendations

```python
def generate_recommendations(
    analysis: dict, bottlenecks: list, scan_summary: dict | None = None
) -> dict:
    """Build recommendations from measured scan- and report-phase data.

    Every value read here comes from `analysis` (the object returned by
    analyze_timings), from `bottlenecks`, or from `scan_summary` (the object
    returned by summarize_scan_timings), so the function has no free variables
    and no caller has to supply anything it did not compute.
    """
    recommendations = {
        "immediate": [],  # P1: high impact, low effort
        "short_term": [],  # P2: medium impact, medium effort
        "long_term": [],  # P3: strategic
    }

    # P1: a tool that timed out lost its findings on that target. The fix is a
    # budget it can finish inside -- never a lower cap, which trades findings
    # for a faster-looking scan.
    for tool, t in (scan_summary or {}).get("tools", {}).items():
        if t["timed_out"]:
            recommendations["immediate"].append({
                "priority": "P1",
                "category": "timeout",
                "tool": tool,
                "action": f"Raise per_tool.{tool}.timeout above its longest run",
                "evidence": (
                    f"timed out on {t['timed_out']} of {t['runs']} targets; "
                    f"longest run {t['max_seconds']:.0f}s"
                ),
                "config_change": f"per_tool:\n  {tool}:\n    timeout: <seconds>",
            })

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
                "(scripts/core/config.py)."
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
scan_summary = summarize_scan_timings(Path("results"))
recommendations = generate_recommendations(analysis, bottlenecks, scan_summary)
```

---

## Tool-Specific Optimization Patterns

**The tool list is not reproduced here.** It lives in
`scripts/core/tool_registry.py:TOOL_MATRIX`, the single source of the default.
Read it with:

```bash
python -c "from scripts.core.tool_registry import TOOL_MATRIX; print(sorted(TOOL_MATRIX))"
```

The snippets below show **top-level `jmo.yml` overrides only** — `threads`,
`timeout` and `per_tool`. None of them changes which tools run; that is
`--tools`, `--skip-tools` or a `tools:` list.

### semgrep

- **Purpose:** multi-language SAST
- **Runs on:** repositories
- **Timeout floor:** 900s in `TOOL_TIMEOUT_DEFAULTS` (`scripts/cli/scan_utils.py`)

semgrep's cost is its **rule count**, not the size of the tree: it restricts
itself to git-tracked files, so `--exclude` flags for vendored directories do
not move its runtime. The floor exists because two measurements of the same
work on the same machine were 410s and 583s apart (#1204). A
`per_tool.semgrep.timeout` below the floor is honoured, and a cap that kills a
healthy semgrep run discards its findings.

```yaml
# jmo.yml
per_tool:
  semgrep:
    timeout: 1200   # only if scan-timings.json shows it timing out at 900
```

### Nuclei

- **Purpose:** web/API vulnerability scanning across a large template set
- **Runs on:** `--url` / `--urls-file` targets only (DAST; never on a repository)
- **Output:** JSON-lines (streaming)

```yaml
# jmo.yml
per_tool:
  nuclei:
    timeout: 300
    flags: ["-severity", "critical,high", "-rate-limit", "150"]
```

Timeout guidance, from configured values rather than measured runtime:

| Configured timeout | Effect |
|---|---|
| unset | Takes the top-level `timeout`; may run to that limit on large sites |
| 60s | Frequently too short for a full template pass |
| 300s | Enough for a critical/high template pass on most sites |
| 600s | Room for medium-severity templates as well |

### GitLab targets

- **Target flags:** `--gitlab-repo`, `--gitlab-group`
- **Runs:** the same tools as any other repository target (zap and nuclei never
  run on a repository)

Remote repositories are usually larger than local checkouts, and cloning is
included in the scan window, so per-tool timeouts tuned for local repos are
often too tight:

```yaml
# jmo.yml
threads: 4
timeout: 900
per_tool:
  semgrep:
    timeout: 1200
  trivy:
    timeout: 900
  trufflehog:
    timeout: 1800
```

**Container discovery.** The GitLab path also discovers container images
referenced by Dockerfiles, `docker-compose.yml`, and Kubernetes manifests, but
it has never scanned one: every call raised before it started (#1311). Budget
GitLab scan time by repository count until that is fixed or removed.

> Whether any of these settings actually helps is not measurable from
> `timings.json` — it records report-phase parsing only. Verify a timeout change
> against `scan-timings.json`: re-run the scan and compare that tool's
> `seconds` and `state`. A cap that "fixed" a slow tool by killing it shows
> up as `failed` with reason `timed out`, which a whole-scan duration from
> `jmo history list` would have reported as an improvement.
