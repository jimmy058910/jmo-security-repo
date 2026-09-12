# Generic SARIF 2.1.0 importer — design

**Date:** 2026-09-12
**Status:** approved, not yet implemented
**Source:** the 2026-09-11 coverage review, section 8 step 3″ ("Generic SARIF adapter
first, then zizmor, gitleaks, osv-scanner through it")

---

## 1. Problem

JMo **exports** SARIF (`scripts/core/reporters/sarif_reporter.py`) and cannot **import**
it. Every new tool therefore costs a bespoke adapter of roughly 250 lines plus a golden
fixture, and the coverage review wants three new tools — zizmor, gitleaks and
osv-scanner — each of which already emits SARIF 2.1.0.

Thirteen of the tools in that review emit SARIF: trivy, gitleaks, trufflehog,
osv-scanner, zizmor, opengrep, semgrep, checkov, kube-linter, hadolint, gosec, bandit
and CodeQL. One importer turns every one of them, present or future, into a
configuration entry.

This document covers the importer and the three tool bindings **only**. It does not add
any tool to `PROFILE_TOOLS`, to `versions.yaml`, to the installer, to any `Dockerfile`,
or to the scan phase. Those are separate changes with their own cascading count updates
(`tests/e2e/test_docker_workflows.py::DOCKER_VARIANTS`, the `DEEP_EXPECTED_TOOLS` lists
and `.github/workflows/scheduled.yml`).

### What this delivers even without a scan-phase change

The report phase discovers tool outputs by filename: `results/individual-*/<target>/
<tool>.json` is routed through `_tool_to_adapter_name()` to an adapter of that name. So
the moment these three adapters exist, a `zizmor.json` written by any means — a user's
own `zizmor --format sarif`, a CI step, a later JMo scan job — is parsed, normalised,
deduplicated, compliance-enriched, and rendered into every JMo report format. Nothing
about that path needs a profile entry.

---

## 2. Measurements this design rests on

Everything below was measured on 2026-09-12 against the real binaries recovered from the
coverage review's scratchpad, at the versions that review used: **zizmor 1.30.1,
gitleaks 8.30.1, osv-scanner 2.5.1**. Documents were generated fresh:

- `zizmor --format sarif --no-online-audits .` on this repository → 217 results
- `gitleaks dir <juice-shop> --report-format sarif` → 69 results
- `osv-scanner scan source -L <NodeGoat/package-lock.json> --format sarif` → 303 results

### 2.1 The three tools express severity three different ways

| Tool | `result.level` | Native severity lives in | Form |
|---|---|---|---|
| zizmor | error 144 / note 61 / warning 12 | `result.properties["zizmor/severity"]` | `High`, `Medium`, `Low`, `Informational` |
| gitleaks | **absent on all 69** | nowhere — gitleaks has no severity concept | — |
| osv-scanner | `warning` on all 303 | `rules[ruleIndex].properties["security-severity"]` | CVSS base score as a string, e.g. `"7.5"` |

Two consequences:

- **`level` is not sufficient.** Reading it alone makes all 303 osv findings MEDIUM, and
  collapses zizmor's 49 `Low` and 12 `Informational` into one bucket, because both map to
  `note`.
- **`level` is not even always present.** SARIF's documented default when `level` is
  absent and the rule sets no `defaultConfiguration.level` is `warning`.

`security-severity` is GitHub's de-facto standard property for SARIF severity and is what
osv-scanner uses; 162 of its 178 rules carry one, and 285 of 303 results resolve through
it.

### 2.2 `artifactLocation.uri` arrives in three incompatible shapes

| Tool | Shape | Example |
|---|---|---|
| zizmor | repository-relative | `.github/workflows/release.yml` |
| gitleaks | absolute native path | `C:/Users/Jimmy/.../juice-shop/data/static/users.yml` |
| osv-scanner | `file://` URI | `file:///C:/Users/Jimmy/.../NodeGoat/package-lock.json` |

`normalize_finding_path()` returns **unchanged** any value containing `://` — a guard
that exists so zap's URLs and lynis's hostnames survive. An undecoded `file://` URI
matches that guard, so the scanning user's home directory would be written into
`location.path` and ship inside `findings.sarif` and `dashboard.html`. That is exactly
the #861 failure, whose residue is still open as #1007.

### 2.3 Rule lookup needs two strategies

`ruleIndex` is present and valid on osv-scanner (0..177) and **absent** on both zizmor
and gitleaks. Rule metadata must therefore be found by index when one is supplied and in
range, and by matching `rules[].id == result.ruleId` otherwise.

### 2.4 `driver.semanticVersion` cannot be trusted

gitleaks 8.30.1 reports `"semanticVersion": "v8.0.0"`. Tool version must come from
`ToolRegistry` (that is, `versions.yaml`) first, as `hadolint_adapter._get_hadolint_version()`
already does, with the document only as a fallback.

### 2.5 Fingerprint collisions, and which ones are real

With the canonical `fingerprint(tool, ruleId, path, startLine, message)`:

| Tool | Results | Distinct ids | Colliding groups | Verdict |
|---|---|---|---|---|
| zizmor | 217 | 216 | 1 | byte-identical duplicate results — collapsing is correct |
| osv-scanner | 303 | 291 | 12 | byte-identical duplicate results — collapsing is correct |
| gitleaks | 69 | 68 | 1 | **two different secrets on one line**, columns 82 and 116 |

The zizmor and osv duplicates were confirmed identical by comparing the complete result
objects, not just the fields that feed the fingerprint. The gitleaks pair differs only in
`region.startColumn`, so one of two real secrets is dropped by
`deduplicate_findings_memory_efficient`, which keys on `id` and keeps the first
occurrence.

### 2.6 A shared registrable base class would break registration, alphabetically

`PluginLoader._load_plugin` iterates `dir(module)` — which is sorted — and registers the
**first** `AdapterPlugin` subclass it finds that is not `AdapterPlugin` itself. If the
shared code were a registrable base class named `SarifAdapter` imported into each shim:

- `sorted(["SarifAdapter", "ZizmorAdapter"])` → `SarifAdapter` wins. **Broken.**
- `sorted(["GitleaksAdapter", "SarifAdapter"])` → `GitleaksAdapter` wins. Fine.
- `sorted(["OsvScannerAdapter", "SarifAdapter"])` → `OsvScannerAdapter` wins. Fine.

One of three tools would fail to register, decided by the first letter of its class name,
and would look like a zizmor-specific problem.

---

## 3. Design

### 3.1 Module layout

```text
scripts/core/adapters/sarif_common.py          NEW   the importer
scripts/core/adapters/zizmor_adapter.py        NEW   binding
scripts/core/adapters/gitleaks_adapter.py      NEW   binding
scripts/core/adapters/osv_scanner_adapter.py   NEW   binding
```

`sarif_common.py` contains **no `AdapterPlugin` subclass** — see 2.6. It exports:

```python
@dataclass(frozen=True)
class SarifToolSpec:
    tool: str                      # Finding.tool["name"] AND the ToolRegistry key
    tags: tuple[str, ...] = ()     # static tags added to every finding

def parse_sarif(output_path: Path, spec: SarifToolSpec) -> list[Finding]: ...
```

Each binding is an ordinary adapter, matching the shape of all 27 existing ones — a
`@adapter_plugin`-decorated `AdapterPlugin` subclass whose `parse()` delegates to a
module-level function:

```python
_SPEC = SarifToolSpec(tool="zizmor", tags=("github-actions", "workflow", "sarif"))

@adapter_plugin(PluginMetadata(
    name="zizmor", version="1.0.0", tool_name="zizmor",
    description="Adapter for zizmor GitHub Actions auditor (SARIF)",
    schema_version="1.2.0", output_format="sarif",
    exit_codes={0: "clean", 14: "findings"},
))
class ZizmorAdapter(AdapterPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> list[Finding]:
        return parse_sarif(output_path, _SPEC)
```

Per `adapters.rules.md`, `PluginMetadata.name` uses underscores and matches the filename
(`osv_scanner_adapter.py` → `name="osv_scanner"`), while `tool_name` carries the binary
name (`osv-scanner`).

Nothing in `plugin_loader.py`, `_tool_to_adapter_name()`, `tool_registry.py` or
`normalize_and_report.py` is modified.

### 3.2 Severity resolution

First hit wins:

1. `security-severity` — on `result.properties`, then on the resolved rule's
   `properties`. Parsed as a float and bucketed by the CVSS v3.1 qualitative ranges:
   `>= 9.0` CRITICAL, `>= 7.0` HIGH, `>= 4.0` MEDIUM, `> 0.0` LOW, `0.0` INFO. A
   non-numeric value is ignored and resolution continues at step 2.
2. A property named exactly `severity`, or any property whose key ends in `/severity` —
   on the result, then on the rule. Passed to `normalize_severity()`. The suffix form is
   what catches `zizmor/severity` and any future `<tool>/severity`.
3. `result.level`, passed to `normalize_severity()`.
4. `rule.defaultConfiguration.level`, passed to `normalize_severity()`.
5. `MEDIUM` — SARIF's documented default of `warning`, resolved through the same
   `normalize_severity()` call so there is one mapping table, not two.

`normalize_severity()` already maps the entire SARIF vocabulary: `ERROR` → HIGH,
`WARNING` → MEDIUM, `NOTE` → LOW, `INFORMATIONAL` → INFO, and zizmor's
`High`/`Medium`/`Low` directly. Steps 2 through 5 are therefore one existing call each;
only step 1's bucketing is new code.

When step 1 resolves, the score is also written to `Finding.cvss` as `{"score": <float>}`
so it stays auditable. The schema requires `score` when `cvss` is present and leaves
`version` and `vector` optional, so this is valid without inventing a vector JMo does not
have.

**gitleaks deliberately gets no per-tool severity override.** It resolves at step 5 to
MEDIUM. Whether a detected secret should outrank that is a product question for the PR
that puts gitleaks into a profile, where the review's `generic-api-key` noise finding is
also in scope.

### 3.3 Location

For each result the importer reads `locations[0].physicalLocation`. SARIF permits many
locations per result; all three tools emit exactly one, and every existing JMo adapter
models one finding as one location, so additional locations are ignored rather than
fanned out into extra findings.

`artifactLocation.uri` is converted to a plain filesystem spelling:

- a `file:` URI is percent-decoded, its leading `/` stripped when it precedes a drive
  letter (`/C:/x` → `C:/x`), and a non-empty authority restored as a UNC prefix
  (`file://server/share` → `//server/share`);
- anything else is passed through unchanged.

Root-stripping is **not** done here. The existing `_normalize_paths_and_ids()` pass in
`normalize_and_report.py` does it with the scan roots from `.scan_metadata.json`, which
the adapter does not have. Decoding in the adapter exists solely so that pass can see a
path instead of a URI.

`region.startLine` and `region.endLine` are carried when present; osv-scanner supplies
neither, and `location.startLine` is simply absent for those findings rather than being
invented as 0.

### 3.4 Fingerprints

Canonical: `fingerprint(spec.tool, ruleId, path, startLine, message)` — the exact five
components `_normalize_paths_and_ids()` recomputes when it decides whether an id came
from the path. That keeps all three tools in the re-keyable lane described in
`adapters.rules.md`, so ids survive path normalisation and stay identical across machines
and across Windows/WSL runs.

The known cost is the gitleaks column collision from 2.5: one finding in 69 on juice-shop.
It is **not** fixed here. Making `fingerprint()` column-aware also requires
`_normalize_paths_and_ids()` to pass the column, and `shellcheck_adapter.py` already
writes `location.startColumn` while fingerprinting without it — so the pass would compute
a six-component hash, fail to match shellcheck's five-component ids, and silently stop
re-keying every shellcheck finding. The real fix is a multi-shape key chain in that
function, which is its own change with its own regression evidence. An issue covering the
class (shellcheck today, SARIF once these tools ship) is filed and rostered by this PR.

### 3.5 Field mapping

| CommonFinding | Source |
|---|---|
| `ruleId` | `result.ruleId`, else the resolved rule's `id`, else `"SARIF"` |
| `title` | rule `name`, else rule `shortDescription.text`, else `ruleId` |
| `message` | `result.message.text` |
| `description` | rule `fullDescription.text`, else `shortDescription.text`, else the message |
| `severity` | section 3.2 |
| `cvss` | `{"score": n}` when and only when step 1 resolved |
| `tool` | `{"name": spec.tool, "version": <ToolRegistry, else driver.version, else driver.semanticVersion, else "unknown">}` |
| `location` | section 3.3 |
| `remediation` | rule `help.text`, else `"See rule documentation"` |
| `references` | rule `helpUri` when present |
| `tags` | `spec.tags` plus the rule's `properties.tags` |
| `raw` | the complete SARIF result object |

Compliance enrichment is **not** performed here; `adapters.rules.md` requires adapters to
return raw findings and let `enrich_findings_with_compliance()` run centrally.

`raw` carries the full result. On zizmor this averages 3.0 KB per finding, about half of
it `codeFlows`, giving 648 KB for this repository's 217 findings. That matches what every
other adapter does; trimming would be a new policy, and if the size proves to matter it is
a measurable question of its own.

### 3.6 Error handling

`safe_load_json_file()` performs the read, so missing, empty, malformed and
wrong-type files already produce the shared warnings.

Beyond that, the importer applies a **shape check**: the parsed document must be a `dict`
whose `runs` is a `list`. If it is not, the importer raises
**`AdapterParseException(spec.tool, path, reason)`**.

Today **no adapter raises that exception** — 0 of 27 — because they route through
`safe_load_json_file()` and turn "unparseable" into "empty" — which leaves the better diagnostic in
`_safe_load_plugin` unreachable:

> *"X produced output that could not be parsed, so its findings are MISSING from this
> report"*

A tool invoked with a JSON flag instead of a SARIF flag writes valid JSON that is not
SARIF, exits 0, and would otherwise report zero findings silently. That is the #822
class, so this importer becomes the first real user of the exception.

A document whose `version` is present and is not `2.1.0` is logged at WARNING and
**parsed anyway** — SARIF is additive, and refusing a future 2.2.0 would be a silent-zero
of its own.

---

## 4. Testing

### 4.1 Golden fixtures

Three new fixtures under `tests/fixtures/golden/`, in the existing
`<tool>/<version>/{<tool>.json, expected-findings.json, metadata.json}` layout, generated
from the real documents described in section 2:

- `zizmor/v1.30.1/`
- `gitleaks/v8.30.1/`
- `osv_scanner/v2.5.1/`

With `ADAPTER_REGISTRY` entries in `tests/adapters/test_adapter_golden.py`, golden
coverage goes from **5 of 27 adapters to 8 of 30**.

### 4.2 Unit tests

Cases the three real documents do not exercise, so the chain is not tested only where it
happens to be easy:

- each severity rank in isolation, including `defaultConfiguration.level` (no tool in the
  corpus sets it) and a malformed `security-severity` falling through to the next rank;
- CVSS bucket boundaries at 0.0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0 and 10.0;
- `ruleIndex` absent, negative, and out of range;
- a document with multiple `runs`;
- `file://` decoding: POSIX, Windows drive, UNC authority, and percent-encoded spaces;
- valid JSON that is not SARIF raises `AdapterParseException`;
- a `version` of `2.2.0` warns and still parses.

### 4.3 The merge gate

CI cannot run these three binaries — they are in no profile, no `versions.yaml` entry and
no image. The verification only a local run can provide is a full `jmo report` over each
real SARIF document, asserting:

| Assertion | Expected |
|---|---|
| zizmor findings | 216 (217 results, 1 identical duplicate collapsed) |
| zizmor severities | HIGH 143, MEDIUM 12, LOW 49, INFO 12 |
| gitleaks findings | 68 (69 results, 1 column collision — the known cost of 3.4) |
| gitleaks severities | MEDIUM 68 |
| osv-scanner findings | 291 (303 results, 12 identical duplicates collapsed) |
| osv-scanner severities | CRITICAL 30, HIGH 147, MEDIUM 102, LOW 12 |

**These are post-deduplication counts**, which is what `jmo report` writes. The
pre-deduplication severity split differs and is not what to assert: zizmor HIGH 144,
osv-scanner HIGH 154 / MEDIUM 107.

**Each tool is reported separately, and that is load-bearing.** Cross-tool clustering
runs by default in the report path, but `FindingCluster.can_accept()` refuses a finding
whose tool is already in the cluster — the one-finding-per-tool invariant. A single-tool
run therefore cannot cluster, so these counts are exact; a combined run legitimately may
merge across the three and would not be a stable assertion.

A fourth run over all three documents together then asserts only that all three tool
names survive into `findings.json` and that no `location.path` contains `://` or the
string `Users`.

The osv severity split is the load-bearing number: reading `level` alone yields 303
MEDIUM, so that row alone proves the chain is wired and not bypassed. The path assertion
is the #861 regression guard.

---

## 5. Out of scope, and where it goes instead

| Thing | Where |
|---|---|
| zizmor/gitleaks/osv-scanner in a profile, installer, `versions.yaml`, Dockerfiles | the next PR in the review's sequence |
| The column-collision defect (shellcheck today, SARIF later) | a new issue, filed and rostered by this PR |
| gitleaks' severity being MEDIUM rather than HIGH | the PR that puts gitleaks in a profile |
| `diff_engine` reading `cvss.baseScore` where adapters write `cvss.score` | pre-existing; noted here, not touched |
| Dependabot alerts import | review section 6, separate workstream |

---

## 6. Success criteria

1. `jmo report` over a results directory containing `zizmor.json`, `gitleaks.json` and
   `osv-scanner.json` in SARIF form produces every number in the table in 4.3.
2. No file under `scripts/core/` outside `adapters/` is modified.
3. `make fmt && make lint && make test` pass, and the `windows-2022` shard's **job log**
   shows no new failures against the 9815 passed / 98 skipped / 256 deselected baseline.
4. Adding a fourth SARIF tool requires one new file of roughly 25 lines and no change to
   `sarif_common.py`.
