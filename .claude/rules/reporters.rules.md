---
title: Reporter & Output Format Rules
paths:
  - scripts/core/reporters/**/*.py
  - tests/reporters/test_*_reporter.py
references:
  - docs/RESULTS_GUIDE.md (output format reference)
---

# Reporter & Output Format Rules

**What this covers:** Implementing new output reporters and formatters that normalize the CommonFinding schema into user-facing reports.

## Reporter Plugin Architecture

All reporters implement the `Reporter` base class and are registered with the `@reporter_plugin` decorator.

**Location:** `scripts/core/reporters/<name>_reporter.py`.

## Standard Reporters

| Reporter | Output | Use Case |
|----------|--------|----------|
| `json_reporter` | Structured findings JSON | Programmatic parsing, integrations |
| `html_reporter` | Interactive dashboard | Executive summaries, trend analysis |
| `csv_reporter` | Spreadsheet-friendly | Data analysis, Excel imports |
| `sarif_reporter` | GitHub/IDE compatible | GitHub Security tab, IDE plugins |
| `markdown_reporter` | Human-readable markdown | GitHub issues, commit comments |
| `policy_reporter` | Policy violations | Compliance tracking, audit trails |

## Diff Reporters

Diff reporters compare two scan results and highlight changes:

- `diff_json_reporter` — JSON diff with added/removed/changed findings.
- `diff_html_reporter` — Visual diff dashboard.
- `diff_markdown_reporter` — Markdown diff for PR comments.
- `diff_sarif_reporter` — SARIF-format diff.

## Input Contract

All reporters receive:

1. **findings:** List of CommonFinding objects (normalized, already deduplicated).
2. **metadata:** Scan metadata (`scan_id`, `timestamp`, `profile`, `target`, etc.).
3. **options:** Reporter-specific config dict (e.g., `include_compliance=true`, `threshold=HIGH`).

## Output Contract

- Write to `output_file` (provided by the orchestrator).
- Log non-fatal errors to stderr.
- Exit 0 on success, 1 on failure.
- Never log to stdout (reserved for JSON output when applicable).

## Testing Pattern

```python
# Mock findings + metadata, call reporter, verify output format
from scripts.core.reporters.json_reporter import JsonReporter

reporter = JsonReporter()
reporter.report(findings=[], metadata={}, output_file="/tmp/test.json")
# Verify /tmp/test.json is valid JSON
```

**Reference:** [docs/RESULTS_GUIDE.md](../../docs/RESULTS_GUIDE.md)
