---
name: jmo-profile-optimizer
description: Optimize scan profile performance through timing analysis, tool configuration tuning, and memory-integrated baselines. Use when scans are slow or profiles need rebalancing.
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

**Approach:** Measure before optimizing. Every recommendation must cite actual timing data.

---

## What's New in v2.1.0

### Memory Integration Features

1. **Query-Before-Analyze Pattern** -- Check `.jmo/memory/profiles/{profile}.json` for historical baselines; saves 15-25 min if baseline exists.
2. **Store-After-Optimization Pattern** -- Store optimization results and tool performance metrics; detect regressions across versions.
3. **Tool Performance History** -- Track avg duration, timeout rate, failure rate per tool; identify trending issues.
4. **Profile Tuning Recommendations** -- Auto-suggest thread count and timeout adjustments based on P95 durations.

---

## Skill Invocation

### Natural Language Triggers

**Direct Actions:**

- "Optimize {profile} profile performance"
- "Analyze timings.json and recommend improvements"
- "Why are scans so slow?"

**Problem Statements:**

- "Scans are taking too long"
- "Too many timeouts in {profile} profile"
- "{tool} keeps timing out"

**Context Clues:**

- Mentions of slow scans, timeouts, performance issues
- References to timings.json or profiling data
- Questions about thread counts or timeout configuration

---

## Skill Workflow (7 Phases)

### Phase 0: Memory Query

Load historical performance baselines from `.jmo/memory/profiles/{profile}.json`. If a baseline exists, display stored metrics (avg durations, timeout rates) for comparison. If no baseline exists, establish a new one.

> Full implementation: [references/memory-integration.md](references/memory-integration.md#phase-0-memory-query---loading-historical-baselines)

---

### Phase 1: Load and Analyze timings.json

Parse `results/summaries/timings.json` from the most recent scan. Extract total duration, per-tool metrics, and identify bottlenecks (>50% of total time), timeout issues (>10% rate), and failure issues (>5% rate).

> Full schema and analysis code: [references/optimization-patterns.md](references/optimization-patterns.md#phase-1-load-and-analyze-timingsjson)

---

### Phase 2: Compare with Memory Baseline

Detect performance regressions by comparing current metrics against stored baselines. Flags regressions when total duration increases >10% or per-tool timeout rates increase >5%. Also identifies improvements.

> Full comparison logic and example output: [references/memory-integration.md](references/memory-integration.md#phase-2-compare-with-memory-baseline)

---

### Phase 3: Identify Bottlenecks

Find tools consuming >30% of total scan time. Sort by percentage descending. For each bottleneck, report total duration, execution count, avg duration, and timeout rate.

> Full implementation: [references/optimization-patterns.md](references/optimization-patterns.md#phase-3-identify-bottlenecks)

---

### Phase 4: Analyze Timeout Patterns

For each tool with timeouts, calculate timeout rate and generate severity-rated recommendations. High severity (>20% rate): recommend 1.5x max observed duration as new timeout. Medium severity (5-20%): recommend monitoring and retries.

> Full implementation and examples: [references/optimization-patterns.md](references/optimization-patterns.md#phase-4-analyze-timeout-patterns)

---

### Phase 5: Generate Optimization Recommendations

Produce prioritized recommendations in three tiers:

- **P1 Immediate:** Fix high timeout rates, reduce thread contention
- **P2 Short-Term:** Optimize tool configurations (exclude patterns, caching)
- **P3 Long-Term:** Profile restructuring for scans exceeding 30 minutes

Each recommendation includes config changes (ready-to-paste YAML) and expected impact estimates.

> Full recommendation engine: [references/optimization-patterns.md](references/optimization-patterns.md#phase-5-generate-optimization-recommendations)

---

### Phase 6: Store Memory

Persist optimization results as updated baseline in `.jmo/memory/profiles/{profile}.json`. Stores per-tool percentiles (p50/p95/p99), timeout/failure/success rates, recommended config, and optimization count.

> Full storage implementation: [references/memory-integration.md](references/memory-integration.md#phase-6-store-optimization-memory)

---

### Phase 7: Generate Optimization Report

Output a comprehensive `OPTIMIZATION_REPORT.md` with sections: baseline comparison table, bottleneck analysis, prioritized recommendations with YAML config snippets, and a next-steps checklist.

> Full report template and example: [references/output-report-format.md](references/output-report-format.md)

---

## Time Savings Comparison

### v2.0.0 (Non-Memory)

| Phase | Duration |
|-------|----------|
| Load timings (Phase 1) | 5 min |
| Analyze performance (Phase 2-4) | 30 min |
| Generate recommendations (Phase 5) | 20 min |
| Write report (Phase 7) | 10 min |
| **Total** | **65 min** |

### v2.1.0 (Memory-Integrated)

| Phase | Duration | Savings |
|-------|----------|---------|
| Memory query (Phase 0) | 2 min | - |
| Load timings (Phase 1) | 5 min | - |
| Compare baseline (Phase 2) | **5 min** (automated) | **-25 min** |
| Analyze bottlenecks (Phase 3) | 5 min | - |
| Analyze timeouts (Phase 4) | 5 min | - |
| Generate recommendations (Phase 5) | 10 min (data-driven) | -10 min |
| Store memory (Phase 6) | 2 min | - |
| Write report (Phase 7) | 5 min (template) | -5 min |
| **Total** | **39 min** | **-40 min (40%)** |

**Second Optimization (Memory Hit):**
- Baseline comparison: Instant (memory lookup)
- Regression detection: Automated
- **Total: 25 min (62% savings)**

---

## Tool-Specific Optimization Patterns (v0.6.2)

Nuclei and GitLab scanner optimization strategies including timeout sweet spots, rate limiting, container discovery impact, and recommended per-profile settings.

> Full tool-specific patterns: [references/optimization-patterns.md](references/optimization-patterns.md#v062-tool-specific-optimization-patterns)

---

## Reference Files

| File | Contents |
|------|----------|
| [references/memory-integration.md](references/memory-integration.md) | Memory query/store code, baseline comparison logic, upgrade path |
| [references/optimization-patterns.md](references/optimization-patterns.md) | timings.json schema, bottleneck/timeout analysis, recommendation engine, tool-specific tuning |
| [references/output-report-format.md](references/output-report-format.md) | OPTIMIZATION_REPORT.md template and section explanations |
