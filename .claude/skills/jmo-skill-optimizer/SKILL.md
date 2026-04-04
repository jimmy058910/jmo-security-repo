---
name: jmo-skill-optimizer
description: Review, enhance, condense, and upgrade skills in .claude/skills/ to ensure they remain current with codebase changes. Use for periodic skill maintenance or before releases.
disable-model-invocation: true
user-invocable: true
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

## Purpose

Systematically review, enhance, condense, and upgrade each skill in `.claude/skills/` to ensure they remain current with codebase changes, development practices, memory integrations, and architectural patterns. This meta-skill ensures all 14 skills stay relevant, accurate, and optimized for maximum value.

**IMPORTANT:** Skills (`.claude/skills/`) and memory (`.jmo/memory/`) are **gitignored** -- they are private development aids, not committed to the open source project. This skill is invoked **manually only**, not via CI/CD automation.

**Approach:** Optimize for actionability. A shorter skill that produces correct output beats a comprehensive one that confuses.

## Trigger Patterns

- "Review [skill-name] skill for updates"
- "Optimize skills for memory integration"
- "Check for stale skills"
- "Update skill examples to match current codebase"
- "Consolidate duplicate content across skills"
- "Weekly skill maintenance"
- "Skill audit before release"

## Skill Optimization Framework

### Phase 1: Staleness Detection (5-10 min)

**Goal:** Identify skills needing updates based on age, codebase changes, and relevance.

**Detection Criteria:**

1. **Last Modified Date:** Find skills not updated in 6+ months (`find .claude/skills -name "SKILL.md" -mtime +180`)

2. **Codebase Drift:** Compare code change frequency to skill update frequency. If code changes >> skill updates, skills likely stale.

3. **Version Discrepancies:** Check skill version vs last significant codebase change.

4. **Memory Integration Status:** Find skills without memory integration (`grep -L "Memory Integration" .claude/skills/*/SKILL.md`)

**Output:** List of skills ranked by staleness priority (HIGH/MEDIUM/LOW).

### Phase 2: Content Review (15-30 min per skill)

**Goal:** Systematically review each skill section for accuracy, completeness, and optimization opportunities.

**Review Checklist (per skill):**

#### 1. Metadata Accuracy

- [ ] Version number reflects recent updates
- [ ] Category appropriate (Code Generation, QA, Operations, etc.)
- [ ] Complexity rating accurate (Low/Medium/High)
- [ ] Time savings estimate realistic

#### 2. Trigger Patterns

- [ ] All trigger patterns still relevant
- [ ] New trigger patterns identified (from recent user queries)
- [ ] Examples up-to-date with current CLI syntax

#### 3. Prerequisites

- [ ] All prerequisites still apply
- [ ] New prerequisites added (e.g., memory system setup)
- [ ] Tool versions current (check versions.yaml)

#### 4. Step-by-Step Workflow

- [ ] Workflow steps match current codebase architecture
- [ ] File paths accurate (e.g., `scripts/core/adapters/` not `src/adapters/`)
- [ ] CLI commands use current syntax
- [ ] Code examples use current patterns

#### 5. Examples and Templates

- [ ] Examples use current tool versions
- [ ] Code templates match current style (black, ruff formatting)
- [ ] Output examples reflect current CommonFinding schema version

**Example update:**

```diff
# Old template (pre-v1.2.0 compliance field)
finding = {
    "schemaVersion": "1.0.0",
    "id": generate_fingerprint(...),
-   # ... no compliance field
}

# New template (v1.2.0 with compliance)
finding = {
    "schemaVersion": "1.2.0",
    "id": generate_fingerprint(...),
+   "compliance": enrich_compliance(vuln["cwe"]),  # NEW in v1.2.0
}
```

#### 6. Success Criteria

- [ ] Criteria measurable and specific
- [ ] Thresholds current (e.g., coverage >= 85%)
- [ ] Validation commands accurate

#### 7. Troubleshooting Guide

- [ ] Common issues still applicable
- [ ] Solutions tested and working
- [ ] Dead links removed

#### 8. Memory Integration (v2.x skills)

- [ ] Memory namespace defined (e.g., `.jmo/memory/adapters/`)
- [ ] What's stored documented
- [ ] Query patterns provided
- [ ] Time savings from caching quantified

### Phase 3: Optimization Opportunities (10-20 min per skill)

**Goal:** Identify areas for condensation, enhancement, or removal.

#### Optimization Patterns

**1. Condense Redundancy** -- Replace repetitive per-tool examples with shared templates + tool-specific overrides. Target 50% reduction in maintenance burden.

**2. Enhance with Memory** -- Add memory caching for frequently repeated analyses:

```python
def analyze_tool_output(json_path, tool_name):
    memory_path = f".jmo/memory/adapters/{tool_name}.json"
    if memory_path.exists():
        return load_cached_analysis(memory_path)  # Instant
    analysis = perform_analysis(json_path)  # 5 minutes
    save_to_memory(memory_path, analysis)
    return analysis
```

**3. Add Cross-References** -- Link related skills for workflow composition:

```markdown
## Related Skills
- **Prerequisite:** jmo-adapter-generator (create adapter first)
- **Follow-up:** jmo-compliance-mapper (add framework mappings)
- **Parallel:** jmo-documentation-updater (document new tool)
```

**4. Prune Obsolete Content** -- Remove references to deprecated tools/patterns.

### Phase 4: Version Bump & Documentation (5-10 min)

**Goal:** Update skill version, changelog, and INDEX.md.

#### Version Bump Rules

- **Patch (1.0.X):** Typos, broken links, updated examples, clarified sections
- **Minor (1.X.0):** New sections, new examples, enhanced workflows (backward compatible)
- **Major (X.0.0):** Breaking workflow changes, complete restructure, new architecture

#### Update Checklist

1. Update skill header (version, time savings)
2. Update INDEX.md with new versions

## Automated Skill Audit

Staleness detection, memory integration checks, and version consistency can be checked manually by reviewing skill files against the codebase.

For the full audit script source code and output format, see [references/automated-audit-details.md](references/automated-audit-details.md).

## Success Criteria

- [ ] Stale skills identified (age >180 days)
- [ ] Content review completed for each skill
- [ ] Memory integration added (where applicable)
- [ ] Examples updated to current codebase
- [ ] Version bumped appropriately (patch/minor/major)
- [ ] INDEX.md updated with new versions
- [ ] Time savings quantified (before/after optimization)

## Output Artifacts

- Updated skill files (`.claude/skills/*/SKILL.md`)
- Updated INDEX.md with new versions

## Prerequisites

- All skills exist in `.claude/skills/`
- INDEX.md up-to-date
- Understanding of skill versioning (semantic versioning)

## Troubleshooting

**Issue:** Skill audit script reports false positives for staleness.
**Solution:** Check git log for skill changes committed via different paths:
```bash
git log --all --full-history -- ".claude/skills/jmo-adapter-generator/SKILL.md"
```

**Issue:** Memory integration unclear for certain skills.
**Solution:** Review existing memory-integrated skills (jmo-adapter-generator v2.2.0, jmo-compliance-mapper v2.1.0, jmo-profile-optimizer v2.1.0) for patterns.

**Issue:** Version bump unclear (patch vs minor vs major).
**Solution:** Patch = bug fixes/typos (no workflow changes). Minor = new sections/examples (backward compatible). Major = breaking workflow changes or restructure.
