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
  - Example: `osv_scanner_adapter.py` → `name="osv_scanner"`.
- `PluginMetadata.tool_name` is the actual binary name (can use hyphens).
  - Example: `tool_name="osv-scanner"`.

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
is what lets zap and nuclei key on something else without being silently
collapsed into one finding.

**So an adapter that keys on the path with a *different* second component falls
through the crack**: it wants re-keying and does not get it, and the host's raw
path stays hashed into the id forever. `syft` was the measured case (#1135) — it
sets `ruleId = "SBOM.PACKAGE"` (a constant) but fingerprints on the package
name, so 23 paths were normalised and **0 ids re-keyed**, and **0 of 22**
packages common to a Windows and a WSL run of juice-shop shared an id.

**syft is fixed the other way, and the crack is still there.** Rather than
align the rule slot, its artifacts branch now hashes
`normalize_finding_path(location)` — 22 of 22 shared ids, and the report phase
still re-keys 0 of 23, which is fine because the adapter no longer needs it to.
Aligning the slot would have worked too; normalising first keeps the adapter
correct on its own instead of depending on the report phase running with the
right roots. **Any new adapter with a constant `ruleId` has the same choice to
make, and nothing will tell it so** — `_normalize_paths_and_ids` fails silently
by design, since the alternative is collapsing the findings of adapters such
as zap that key on something other than the path.

**When you add or change an adapter:** either fingerprint as
`fingerprint(tool, <the ruleId you set>, path, line, message)`, or normalise the
path yourself before hashing. Nothing enforces this — a guard over the golden
fixtures would be vacuous, since the adapters with fixtures all already pass
and the broken one has none.

## SARIF tools: one binding file over `sarif_common.py`

zizmor, gitleaks and osv-scanner are each a ~34-line `<tool>_adapter.py` holding one
`SarifToolSpec` and delegating `parse()` to `sarif_common.parse_sarif`. A fourth SARIF
tool is another file of that shape and **no change to `sarif_common.py`**;
`tests/adapters/test_sarif_common.py::test_a_fourth_sarif_tool_is_one_small_file` proves
it through the real loader. `CONTRIBUTING.md` has the template.

- **`sarif_common.py` must never define an `AdapterPlugin` subclass, and a binding must
  never import one.** `PluginLoader._load_plugin` registers the first subclass in
  `sorted(dir(module))`: a shared `SarifAdapter` base would beat `ZizmorAdapter` and lose
  to `GitleaksAdapter`, breaking one tool in three by its class name's first letter.
- **The bindings are deliberately absent from `test_adapter_malformed.py::ALL_ADAPTERS`.**
  They raise `AdapterParseException` on valid JSON that is not SARIF (spec 3.6, the #822
  class), and that suite asserts every adapter returns a list. Their malformed-input
  coverage is `test_sarif_common.py`.
- **`SarifToolSpec.tool` is both `Finding.tool["name"]` and the `versions.yaml` key**, so
  it is the binary name with hyphens (`osv-scanner`); `PluginMetadata.name` stays
  the underscored file stem.
- **Severity never comes from `level` alone.** osv-scanner writes `warning` on every
  result and its real score is the rule's `security-severity`; zizmor's `Low` and
  `Informational` both map to `note`. Rank order: `security-severity`, a `severity` or
  `*/severity` property, `level`, `defaultConfiguration.level`, then MEDIUM. gitleaks has
  no severity anywhere and resolves to MEDIUM by that default; its binding then sets
  HIGH. PR C, which wired it into scans, decided (Jimmy, 2026-09-26) that a secret is
  HIGH verified or not, TruffleHog's included, so `--fail-on HIGH` stops on a leak with
  verification off. `tests/fixtures/golden/gitleaks/` was re-derived from its raw output
  then, through `generate_golden.run_adapter` (it has no gitleaks entry of its own).
- **gitleaks' binding does more than delegate.** It pops `region.snippet` (the matched
  secret, unredacted) out of `raw`, digests it for pairing, and fills `secretContext`
  from `partialFingerprints` when `commitSha` is set (git mode).

## Secret scanners and git history (G1)

- A tool with a second invocation writes `<tool>.git.json`; the report maps an output
  to its tool by the name before the first dot (`tool_of_output`).
- A history record's id carries its commit, so a key rotated in place (the old one at
  the new one's line) keeps an id of its own. trufflehog's message names the commit,
  well inside the 120 characters an id hashes. gitleaks' names it after the path, past
  them when the path is long, so its binding passes `fingerprint(..., commit=)`,
  appended only when given, like `start_column`; `_normalize_paths_and_ids` tries
  that shape too. (A mutation dropping trufflehog's explicit `commit=` survived, which
  is how the redundant copy was found and removed.)
- `Finding.secretDigest` is transient: a keyed HMAC (per-process random key) that
  `pair_history_with_tree` reads and removes. Never write it anywhere else.
- **`file:` URIs are decoded in the adapter** (`file:///C:/x` -> `C:/x`) because
  `normalize_finding_path` passes anything containing `://` through unchanged, and an
  undecoded URI would ship the scanning machine's path into `findings.sarif` (#861).
