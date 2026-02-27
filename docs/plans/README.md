# docs/plans/ Convention

This directory holds implementation plans for non-trivial changes to JMo Security.

## When to Write a Plan

- Changes spanning 3+ files or multiple modules
- Architectural decisions with lasting impact
- Multi-step work that benefits from pre-alignment
- Work that other contributors need to review before implementation

## Naming Convention

```text
YYYY-MM-DD-<short-description>.md
```

Examples:
- `2026-03-01-typed-retry-logic.md`
- `2026-03-05-mcp-query-tool.md`

## Plan Template

```markdown
# <Title>

**Date:** YYYY-MM-DD
**Status:** Draft | Approved | Implemented

## Goal

One paragraph describing what this plan achieves and why.

## Architecture

Key design decisions, data flow, component interactions.
Include diagrams if helpful.

## Changes

- `scripts/core/config.py:89` - add RetryConfig dataclass
- `scripts/cli/jmo.py:234` - wire --timeout flag
- `tests/unit/test_config.py` - validation tests

## Test Plan

How to verify the implementation works.

## Unresolved Questions

- Question 1? (Recommendation: ...)
- Question 2?
```

## Guidelines

- Plans are living documents -- update status as work progresses
- Keep plans concise: the CLAUDE.md format rules apply here too
- Existing plans are not retroactively reformatted to this template
- Delete or archive plans once fully implemented (optional)
