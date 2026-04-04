---
name: jmo-systematic-debugging
description: Four-phase debugging framework (root cause investigation, pattern analysis, hypothesis testing, implementation) for any bug, test failure, or unexpected behavior. Use BEFORE proposing fixes.
disable-model-invocation: true
user-invocable: true
allowed-tools: Read, Glob, Grep, Bash
---

## Purpose

Use when encountering any bug, test failure, or unexpected behavior in JMo Security, before proposing fixes -- four-phase framework (root cause investigation, pattern analysis, hypothesis testing, implementation) with JMo-specific patterns and common failure modes.

**Approach:** Root cause first, always. If you cannot explain WHY the bug occurs, you are not ready to propose a fix.

## The Iron Law

```text
NO FIXES WITHOUT ROOT CAUSE INVESTIGATION FIRST
```

If you haven't completed Phase 1, you cannot propose fixes. Random fixes waste time and create new bugs. Quick patches mask underlying issues.

**Core principle:** ALWAYS find root cause before attempting fixes. Symptom fixes are failure.

**JMo-Specific Focus:** This skill applies systematic debugging to JMo Security's two-phase architecture (scan -> report), multi-target scanning (6 target types), tool adapter patterns, and CI/CD workflows.

## When to Use

Use for ANY technical issue in JMo Security:

**Common JMo Security Issue Categories:**

- **Adapter failures:** Tool output parsing errors, empty findings lists, schema validation failures
- **Scan failures:** Tool timeouts, missing tools, subprocess errors, exit code mismatches
- **Report failures:** Deduplication issues, missing findings, compliance enrichment failures
- **Test failures:** Adapter tests, integration tests, coverage drops below 85%
- **CI/CD failures:** GitHub Actions timeouts, Docker build failures, pre-commit failures
- **Performance issues:** Slow scans, thread inefficiency, memory exhaustion
- **Multi-target issues:** Specific target type failing (repos work, images fail)
- **Configuration issues:** Profile not applying, per_tool overrides ignored

**Use this ESPECIALLY when:**

- Under time pressure (emergencies make guessing tempting)
- "Just one quick fix" seems obvious (adapter change, tool flag adjustment)
- You've already tried multiple fixes (changed exit codes 3 times)
- Previous fix didn't work (still getting empty findings)
- You don't fully understand the issue (why is trivy failing only for images?)
- **JMo-specific:** Findings appear in raw tool JSON but not in `findings.json`
- **JMo-specific:** Tool works locally but fails in Docker/CI
- **JMo-specific:** One target type works but another doesn't

**Don't skip when:**

- Issue seems simple ("just add this exit code to OK list")
- You're in a hurry (rushing guarantees rework)
- User wants immediate fix (systematic is faster than thrashing)
- **JMo-specific:** "Just regenerate the adapter" seems like the answer

## The Four Phases

You MUST complete each phase before proceeding to the next. For full detailed instructions, examples, and JMo-specific commands for each phase, see [references/detailed-phase-guide.md](references/detailed-phase-guide.md).

### Phase 1: Root Cause Investigation

**BEFORE attempting ANY fix.** Read error messages carefully (including stack traces, line numbers, error codes). Reproduce consistently. Check recent changes (git diff, versions.yaml, config). Gather evidence at component boundaries. Trace data flow backward from symptom to source.

**JMo component boundaries to check:**
1. CLI -> Tool Subprocess (invocation, exit codes, output file)
2. Tool Output -> Adapter Parsing (JSON validity, structure, field mapping)
3. Adapter -> normalize_and_report.py (findings list, schema compliance, fingerprints)
4. Aggregation -> Reporters (deduplication, enrichment, output files)

### Phase 2: Pattern Analysis

**Find the pattern before fixing.** Compare working examples against broken ones (adapters, scan jobs, target types). Use reference implementations (`trivy_adapter.py` as adapter gold standard, `repository_scanner.py` for scan jobs). Systematically identify differences: exit codes, JSON structure, field names, nesting, empty handling, tool versions.

### Phase 3: Hypothesis and Testing

**Scientific method.** Form a single, specific hypothesis ("I think X because Y"). Test with the SMALLEST possible change -- one variable at a time. Verify before continuing. If it didn't work, form a NEW hypothesis; don't stack fixes.

### Phase 4: Implementation

**Fix the root cause, not the symptom.** Create a failing test case FIRST. Implement a single fix addressing the root cause. Verify: new test passes, no regressions, coverage >= 85%, pre-commit clean. If fix doesn't work and you've tried 3+ times, STOP and question the architecture.

## Red Flags -- STOP and Follow Process

If you catch yourself thinking:

- "Quick fix for now, investigate later"
- "Just try changing X and see if it works"
- "Add multiple changes, run tests"
- "Skip the test, I'll manually verify"
- "It's probably X, let me fix that"
- "I don't fully understand but this might work"
- "Pattern says X but I'll adapt it differently"
- "Here are the main problems: [lists fixes without investigation]"
- Proposing solutions before tracing data flow
- **"One more fix attempt" (when already tried 2+)**
- **Each fix reveals new problem in different place**

**JMo-specific red flags:**

- "Just regenerate the adapter with jmo-adapter-generator"
- "Let me add this exit code and see if it works"
- "I'll update all 6 target types at once"
- "The tool output looks right, so it must be the adapter"
- "I'll fix this test failure and that one while I'm here"
- "Just copy-paste from trivy_adapter, it'll probably work"
- "I don't need to check the raw JSON, the error message is clear"
- **"Findings are in tool.json but not findings.json, must be deduplication"** (haven't checked adapter parsing)
- **"Tool works locally, must be a Docker issue"** (haven't checked tool versions)
- **"One target type works, others should too"** (haven't checked directory structure)

**ALL of these mean: STOP. Return to Phase 1.**

**If 3+ fixes failed:** Question the architecture (see Phase 4, Step 5 in detailed guide).

## Your Human Partner's Signals You're Doing It Wrong

- "Is that not happening?" -- You assumed without verifying
- "Will it show us...?" -- You should have added evidence gathering
- "Stop guessing" -- You're proposing fixes without understanding
- "Ultrathink this" -- Question fundamentals, not just symptoms
- "We're stuck?" (frustrated) -- Your approach isn't working

**When you see these:** STOP. Return to Phase 1.

## Common Rationalizations

| Excuse | Reality |
|--------|---------|
| "Issue is simple, don't need process" | Simple issues have root causes too. Process is fast for simple bugs. |
| "Emergency, no time for process" | Systematic debugging is FASTER than guess-and-check thrashing. |
| "Just try this first, then investigate" | First fix sets the pattern. Do it right from the start. |
| "I'll write test after confirming fix works" | Untested fixes don't stick. Test first proves it. |
| "Multiple fixes at once saves time" | Can't isolate what worked. Causes new bugs. |
| "Reference too long, I'll adapt the pattern" | Partial understanding guarantees bugs. Read it completely. |
| "I see the problem, let me fix it" | Seeing symptoms != understanding root cause. |
| "One more fix attempt" (after 2+ failures) | 3+ failures = architectural problem. Question pattern, don't fix again. |

## Quick Reference

| Phase | Key Activities | Success Criteria |
|-------|---------------|------------------|
| **1. Root Cause** | Read errors, reproduce, check changes, gather evidence | Understand WHAT and WHY |
| **2. Pattern** | Find working examples, compare | Identify differences |
| **3. Hypothesis** | Form theory, test minimally | Confirmed or new hypothesis |
| **4. Implementation** | Create test, fix, verify | Bug resolved, tests pass |

## When Process Reveals "No Root Cause"

If systematic investigation reveals issue is truly environmental, timing-dependent, or external:

1. You've completed the process
2. Document what you investigated
3. Implement appropriate handling (retry, timeout, error message)
4. Add monitoring/logging for future investigation

**But:** 95% of "no root cause" cases are incomplete investigation.

## Supporting References

**Detailed phase instructions** with full JMo-specific commands, examples, and verification steps:
[references/detailed-phase-guide.md](references/detailed-phase-guide.md)

**Common failure modes** -- catalog of 5 frequent JMo issues (empty findings, CI timeouts, target type failures, local-vs-CI mismatches, pre-commit divergence) with phase-by-phase walkthroughs:
[references/jmo-common-failure-modes.md](references/jmo-common-failure-modes.md)

**Memory integration** -- caching failure patterns in `.jmo/memory/debugging/` for 35% faster repeated debugging, with storage format, query patterns, and maintenance schedule:
[references/memory-integration.md](references/memory-integration.md)

**Skill integration** -- how this skill connects to jmo-ci-debugger, jmo-adapter-generator, jmo-test-fabricator, and generic skills (root-cause-tracing, test-driven-development):
[references/integration-with-skills.md](references/integration-with-skills.md)
