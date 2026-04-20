---
title: Tool Adapter Development Rules
paths:
  - scripts/core/adapters/**/*.py
  - tests/adapters/test_*_adapter.py
  - docs/schemas/**/*.json
references:
  - CONTRIBUTING.md (detailed workflow)
  - scripts/core/common_finding.py (TOOL_SEVERITY_MAPPINGS)
---

# Tool Adapter Development Rules

**What this covers:** Creating new security tool adapters (plugin architecture), naming conventions, CommonFinding schema mapping, and compliance enrichment architecture.

## Adding a New Tool Adapter

1. Create `scripts/core/adapters/<tool>_adapter.py` with `@adapter_plugin` decorator.
2. **Use `safe_load_json_file()` from `scripts/core/adapters/common.py`** for consistent JSON loading.
3. **Use `map_tool_severity()` from `scripts/core/common_finding.py`** for severity normalization.
   - Add to `TOOL_SEVERITY_MAPPINGS` if the tool has custom severity levels.
4. Map tool output to the CommonFinding schema.
5. Add a test in `tests/adapters/test_<tool>_adapter.py`.
6. Update documentation.

## Naming Convention (CRITICAL)

- `PluginMetadata.name` must use **underscores**, matching the adapter filename.
  - Example: `dependency_check_adapter.py` → `name="dependency_check"`.
- `PluginMetadata.tool_name` is the actual binary name (can use hyphens).
  - Example: `tool_name="dependency-check"`.

## Compliance Enrichment Architecture

**IMPORTANT:** Adapters must NOT handle compliance enrichment. Return raw findings and let `normalize_and_report.py` handle enrichment centrally via `enrich_findings_with_compliance()`.

**Why:** Single-pass batch enrichment (OWASP, CWE, CIS, NIST, PCI DSS, MITRE ATT&CK) is more efficient than per-adapter enrichment and ensures consistent mappings across all tools.

## CommonFinding Schema

- **Current version:** v1.2.0
- **Reference:** `docs/schemas/common_finding.v1.json` (JSON Schema Draft 2020-12)
- **Fields include:** severity, tool_name, path, line, message, rule_id, compliance_mappings.

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the detailed workflow.
