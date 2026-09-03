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

## Fingerprints: the report phase re-keys the path, but only if it recognises the id

`normalize_and_report._normalize_paths_and_ids` normalises `location.path` and
then **recomputes the id from the normalised path** — but only when it can prove
the id came from the path, by recomputing
`fingerprint(tool, ruleId, path, startLine, message)` and comparing. That check
is what lets zap, cdxgen, nuclei and mobsf key on something else without being
silently collapsed into one finding.

**So an adapter that keys on the path with a *different* second component falls
through the crack**: it wants re-keying and does not get it, and the host's raw
path stays hashed into the id forever. `syft` is the measured case (#1135) — it
sets `ruleId = "SBOM.PACKAGE"` (a constant) but fingerprints on the package
name, so 41 paths are normalised and **0 ids are re-keyed**, and no finding
matches across Windows and Linux. `horusec` had the same shape until #1141 gave
it a real `rule_id`; it now re-keys 579 of 584.

**When you add or change an adapter:** either fingerprint as
`fingerprint(tool, <the ruleId you set>, path, line, message)`, or normalise the
path yourself before hashing. Nothing enforces this — a guard over the golden
fixtures would be vacuous, since the four adapters with fixtures all already
pass and the broken one has none.
