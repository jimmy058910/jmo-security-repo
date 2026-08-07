---
name: jmo-profile-optimizer
description: Analyze report-phase timing data from `jmo report --profile` and tune profile configuration (threads, timeouts, per-tool flags) against measured evidence. Use when report aggregation is slow or a profile needs rebalancing.
argument-hint: <profile-name>
user-invocable: true
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

## Execution

Optimize profile: **$ARGUMENTS**

**Current config:**
!head -30 jmo.yml 2>/dev/null || echo "jmo.yml not found"

---

## Purpose

Measure before optimizing. Every recommendation must cite actual timing data.

### What this skill can and cannot measure

`jmo report --profile` writes `<results-dir>/summaries/timings.json`, which
records the **report phase**: how long JMo took to read and normalize each tool's
output. It does **not** record how long the tools took to run.

| Question | Answerable | Source |
|---|---|---|
| Which adapter costs the most parse time? | yes | `timings.json` `jobs[]` |
| How many findings does each tool produce? | yes | `timings.json` `jobs[].count` |
| Is the report worker count right? | yes | `recommended_threads` vs `meta.max_workers` |
| How long did the whole scan take? | yes | `jmo history list` / `jmo history show` |
| How long did **one tool** take to run? | **no** | not recorded anywhere |
| What is a tool's timeout or failure rate? | **no** | not recorded anywhere |

If the question is "why is the scan slow", this skill can only narrow it to
whole-scan durations from history plus configured timeouts. Per-tool scan
timing needs instrumentation that does not exist yet.

---

## Skill Invocation

### Natural Language Triggers

**Direct actions:**

- "Optimize the {profile} profile configuration"
- "Analyze timings.json and recommend improvements"
- "Which adapter is slowest to parse?"

**Problem statements:**

- "Report generation is taking too long"
- "Aggregation is slow on large result sets"
- "{tool} produces too many findings"

**Context clues:**

- References to `timings.json`, aggregation time, or worker/thread counts
- Questions about `per_tool` timeout or flag configuration in `jmo.yml`

---

## Skill Workflow (6 Phases)

### Phase 0: Validate the profile name, then query memory

`$ARGUMENTS` is untrusted input that becomes part of a file path. **Validate it
before any file tool call.** Reject anything containing path separators or `..`,
then confirm it names a profile that actually exists — built-in profiles come
from `scripts/core/tool_registry.py:PROFILE_TOOLS`, and users may define more
under `profiles:` in `jmo.yml`.

Only after validation, load `.jmo/memory/profiles/{profile}.json`. A missing file
is a cache miss, not an error — `.jmo/` is gitignored and absent from a fresh
clone.

> Validation helper and query implementation: [references/memory-integration.md](references/memory-integration.md#profile-name-validation-required-before-any-memory-path)

---

### Phase 1: Load and analyze timings.json

Parse `<results-dir>/summaries/timings.json`. Group the flat `jobs` list by tool
and compute, per tool: total parse seconds, parse count, findings produced, mean,
max, and real percentiles from the observed samples.

> Schema and analysis code: [references/optimization-patterns.md](references/optimization-patterns.md#phase-1-load-and-analyze-timingsjson)

---

### Phase 2: Compare with the memory baseline

Compare the analyzed timings against the stored baseline. Flags a regression when
cumulative parse time rises more than 10%, or a tool's mean parse duration rises
more than 15%. Zero or missing baselines are reported as `no_sample` rather than
divided by.

> Comparison logic and example output: [references/memory-integration.md](references/memory-integration.md#phase-2-compare-with-the-memory-baseline)

---

### Phase 3: Identify bottlenecks

Find tools above `BOTTLENECK_THRESHOLD_PCT` (**30%**) of cumulative parse time,
sorted descending. The threshold is defined once, in
`references/optimization-patterns.md`, and every phase uses that single value.

Percentages are shares of **cumulative parse time**, not of wall clock — jobs run
in parallel across `meta.max_workers`, so shares of wall clock would not sum to
100%.

> Implementation: [references/optimization-patterns.md](references/optimization-patterns.md#phase-3-identify-bottlenecks)

---

### Phase 4: Generate optimization recommendations

Produce prioritized recommendations in three tiers, each citing the measurement
that produced it:

- **P1 Immediate:** correct the report worker count when it disagrees with
  `recommended_threads`
- **P2 Short-term:** profile the parse path of any adapter over the bottleneck
  threshold
- **P3 Long-term:** reduce finding volume at source for tools whose output
  dominates parse and deduplication cost

> Recommendation engine: [references/optimization-patterns.md](references/optimization-patterns.md#phase-5-generate-optimization-recommendations)

**Timeout and failure-rate analysis is not part of this skill** — JMo records
neither. See [the Phase 4 note](references/optimization-patterns.md#phase-4-timeout-and-failure-analysis--no-data-source)
before adding recommendations about timeouts.

---

### Phase 5: Store memory

Persist the analyzed timings as the profile's updated baseline in
`.jmo/memory/profiles/{profile}.json`, incrementing `optimization_count` from the
previously stored record.

> Storage implementation: [references/memory-integration.md](references/memory-integration.md#phase-6-store-the-updated-baseline)

---

### Phase 6: Generate the optimization report

Write `OPTIMIZATION_REPORT.md`: baseline comparison table, bottleneck analysis,
prioritized recommendations with ready-to-paste `jmo.yml` snippets, and a
next-steps checklist.

> Report template: [references/output-report-format.md](references/output-report-format.md)

---

## Producing the input

```bash
# Profile selection is --profile-name; --profile is the report timing flag.
jmo scan --repos-dir ~/repos --profile-name balanced --results-dir ./results
jmo report ./results --profile

cat results/summaries/timings.json
```

Whole-scan wall-clock durations come from the history database, not from
`timings.json`:

```bash
jmo history list --limit 10
jmo history show <scan-id>
```

---

## Tool-Specific Optimization Patterns

Per-tool `jmo.yml` overrides for Nuclei and GitLab targets, including timeout
guidance and the container-discovery cost of GitLab scanning.

> Full patterns: [references/optimization-patterns.md](references/optimization-patterns.md#tool-specific-optimization-patterns)

---

## Reference Files

| File | Contents |
|------|----------|
| [references/memory-integration.md](references/memory-integration.md) | Profile-name validation, memory query/store, baseline comparison |
| [references/optimization-patterns.md](references/optimization-patterns.md) | timings.json schema, bottleneck analysis, recommendation engine, per-tool tuning |
| [references/output-report-format.md](references/output-report-format.md) | OPTIMIZATION_REPORT.md template and section explanations |
