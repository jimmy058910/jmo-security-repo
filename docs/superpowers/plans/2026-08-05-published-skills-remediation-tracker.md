# Remediation tracker: the 103 published-skill review findings

**Strategy and per-chunk protocol:** [2026-08-05-published-skills-remediation.md](2026-08-05-published-skills-remediation.md)
**Tracking issue:** [#718](https://github.com/jimmy058910/jmo-security-repo/issues/718)
**Branch:** work each chunk off `dev`; PR into `dev`. Never `main`.

## Progress

**18 / 103 resolved.**

| Chunk | Scope | Findings | Done | Status |
|---|---|---:|---:|---|
| **A** | jmo-profile-optimizer | 13 | 13 | **complete** |
| **B** | dashboard-builder + documentation-updater | 13 | 1 | in progress |
| **C** | adapter-generator + test-fabricator | 15 | 1 | in progress |
| **D** | jmo-ci-debugger | 13 | 0 | not started |
| **E** | target-type-expander + security-hardening | 19 | 0 | not started |
| **F** | the 7 agents | 13 | 0 | not started |
| **G** | tail: refactoring, compliance, systematic-debugging, references | 11 | 0 | not started |
| **H** | repo config authored by PR #717 | 6 | 3 | in progress |
| | **total** | **103** | **18** | |

## How to mark a finding off

Every finding ends in one of three states, and **all three count as resolved**:

- `[x] FIXED` - changed the content; say what changed
- `[x] DELETED` - removed the fictional example rather than repairing it
- `[x] DISMISSED` - verified against the code and the claim is wrong; **say why**

Tick the box, append the verdict inline, and update the Progress table in the
same commit. A finding without a stated verdict is not resolved.

Verify every claim against real code before acting. Measured so far: 3/3 claims
against `check_doc_links.py` were real, but the `exit_codes` batch also implied
changing two blocks where string keys are correct because those blocks are JSON.


## Chunk A - jmo-profile-optimizer  (13/13)

**Policy set here, and it governs chunks B-G: rewrite against real data.** Repair
the example against the code, drop what has no data source, and cite the module
rather than reproducing it where citing is enough.

**Root cause, measured.** The skill was fictional at three independent levels,
not one:

1. **Wrong phase.** `timings.json` is written by `jmo report --profile`;
   `aggregate_seconds` wraps `gather_results()`
   (`report_orchestrator.py:106-108`) and each `jobs[]` entry times one
   `adapter.parse(path)` (`normalize_and_report.py:305-318`). It measures
   *parsing tool output*, never *running tools*.
2. **Wrong schema.** Real: `aggregate_seconds`, `recommended_threads`, `jobs[]`
   (flat list), `meta`. Documented: `total_duration_seconds`, `profile`, `tools`
   (dict). Disjoint.
3. **Wrong API.** `from scripts.core.memory import query_memory` - no such
   module. `scripts/dev/store_profile_baseline.py` absent. `jmotools` removed in
   v0.9.0 (`pyproject.toml:130`).

`.jmo/memory/` itself is **not** fictional - it is a real file convention
(`.claude/skills/references/memory-integration-pattern.md`), gitignored at
`.gitignore:179`, implemented by each skill with Read/Write. Only the Python
import was invented.

**Verification.** Markdown is not executed by any test, so the examples were
extracted with `ast` and run. Old code reproduced all three claimed crashes
(`UnboundLocalError`, `NameError`, `KeyError: 'total_duration_seconds'`);
rewritten code passes 55 checks including degenerate inputs, traversal payloads,
and a two-cycle store/reload.

**`.claude/skills/jmo-profile-optimizer/references/memory-integration.md`**

- [x] **Critical** L231: Load the previous optimization count before constructing `memory_data`
      -> FIXED: reproduced `UnboundLocalError: cannot access local variable
      'memory_data'`. Prior record now loads into `previous` before the dict is
      built. Verified count goes 1 -> 2 across two stores.

**`.claude/skills/jmo-profile-optimizer/references/optimization-patterns.md`**

- [x] **Critical** L241: Pass `timings` into `generate_recommendations`
      -> FIXED: reproduced `NameError: name 'timings' is not defined`. Signature
      is now `generate_recommendations(analysis, bottlenecks)`; every value read
      comes from a parameter, so no free variable remains.

**`.claude/skills/jmo-profile-optimizer/SKILL.md`**

- [x] **Major** L65: Reject separators before using the profile name in a memory path (CWE-22)
      -> FIXED: `memory_path()` validates shape (`[a-z][a-z0-9_-]*`, rejecting
      `..` and separators) then membership against `PROFILE_TOOLS` plus
      user-defined `profiles:` in `jmo.yml`. **The review's own remedy was
      wrong** - it proposed allowing only fast/balanced/deep, which omits `slim`
      and breaks custom profiles. Verified: 8 traversal payloads rejected, 4 real
      profiles accepted.

**`.claude/skills/jmo-profile-optimizer/references/memory-integration.md`**

- [x] **Major** L149: Define one timing object for comparison and storage
      -> FIXED: raw and analysed schemas named and tabulated; every function on
      the page takes the analysed object. Verified per-tool comparison now
      executes (it was silently skipped).
- [x] **Major** L163: Guard baseline ratio calculations
      -> FIXED: all ratios go through `pct_change()`, which returns `None` for a
      zero or missing denominator; those land in an explicit `no_sample` list.
- [x] **Major** L216: Do not derive p95 from the maximum duration
      -> FIXED: `jobs[]` gives one sample per parsed file, so real nearest-rank
      percentiles are computable. p95 needs n>=20, p99 n>=100, else `null`.
      Measured p95=0.83 against the old fabrication max*0.95=0.817.

**`.claude/skills/jmo-profile-optimizer/references/optimization-patterns.md`**

- [x] **Major** L72: Align this parser with the report producer
      -> FIXED: reproduced `KeyError: 'total_duration_seconds'` against real
      producer output. Parser rewritten to the real schema and the flat `jobs`
      list; schema table cites `report_orchestrator.py:344-352` as source of truth.
- [x] **Major** L94: Handle empty timing sets
      -> FIXED: every denominator guarded. Empty jobs yields `tools == {}` and
      empty recommendations rather than `ZeroDivisionError`.

**`.claude/skills/jmo-profile-optimizer/references/output-report-format.md`**

- [x] **Major** L104: Keep the Trivy recommendation enabled
      -> FIXED: the partial `tools:` list is removed rather than patched. Real
      `balanced` has 17 tools including trivy; the example listed 7 without it.
      Omitting `tools:` is `jmo.yml`'s own convention (the registry is the single
      source of truth), so the `per_tool.trivy` settings now apply.

**`.claude/skills/jmo-profile-optimizer/SKILL.md`**

- [x] **Minor** L89: Use one bottleneck threshold
      -> FIXED: single `BOTTLENECK_THRESHOLD_PCT = 30.0`, defined once and cited
      by name from SKILL.md. The competing 50% literal is gone.

**`.claude/skills/jmo-profile-optimizer/references/optimization-patterns.md`**

- [x] **Minor** L159: Use one valid denominator for all bottleneck percentages
      -> FIXED: shares are of **cumulative parse time**, labelled as such in both
      files. Wall clock is reported separately, because jobs run in parallel
      across `meta.max_workers` and shares of wall clock would not sum to 100.
      Verified shares sum to exactly 100.0000%.
- [x] **Minor** L226: Correct the timeout severity in the example
      -> DELETED: the mismatch is real, but the entire timeout analysis has no
      data source - no timeout count is recorded in `timings.json`, `history_db`
      (one `duration_seconds` per *scan*, `history_db.py:103`), or the scan
      orchestrator. Removed rather than re-labelled; restoring it needs
      instrumentation, which is a code change.
- [x] **Minor** L263: Carry the actual timeout rate into the recommendation
      -> DELETED: same root cause. `rec.get("timeout_rate")` fed a recommendation
      built from a value JMo never records.

**Also corrected while rewriting** (not review findings; found by auditing every
documented symbol): `jmotools ... --profile` in the upgrade path (command removed
in v0.9.0, and `--profile` is the report timing flag while `--profile-name`
selects the profile); `scripts/dev/store_profile_baseline.py` (absent); profile
tool lists that contradicted `PROFILE_TOOLS`, including "Nuclei not in fast",
which is false; the unanchored "v2.1.0 / v2.0.0" version scheme and its invented
time-savings tables; and `jmo scan --out`, which this rewrite introduced and the
audit caught (the flag is `--results-dir`). Two one-line summaries in
`AGENTS.md` and `.claude/skills/INDEX.md` were synced to the new description so
the change does not create fresh drift.

## Chunk B - dashboard-builder + documentation-updater  (1/13)


**`.claude/skills/jmo-dashboard-builder/SKILL.md`**

- [ ] **Major** L15: (claim nested; read from the PR conversation)
- [ ] **Major** L33: Use one bundle-size policy across the dashboard documentation
- [ ] **Major** L145: (claim nested; read from the PR conversation)
- [ ] **Major** L219: Fail when the findings placeholder is missing
- [ ] **Major** L219: (claim nested; read from the PR conversation)
- [ ] **Major** L230: Call the React reporter from the CLI

**`.claude/skills/jmo-dashboard-builder/references/troubleshooting.md`**

- [ ] **Major** L11: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-documentation-updater/SKILL.md`**

- [ ] **Major** L111: Use paths relative to the Markdown file

**`.claude/skills/jmo-documentation-updater/templates/doc-update-templates.md`**

- [ ] **Major** L364: Make the verification checklist fail when required updates are missing

**`.claude/skills/jmo-documentation-updater/SKILL.md`**

- [ ] **Minor** L47: Fix the `DOCKER_README.md` quick-start link

**`.claude/skills/jmo-documentation-updater/references/managing-skills-docs.md`**

- [x] **Minor** L8: Describe the public/private allowlist accurately
      -> RESOLVED: PR #717 - allowlist described accurately
- [ ] **Minor** L14: Apply the changelog rule or narrow it

**`.claude/skills/jmo-documentation-updater/templates/doc-update-templates.md`**

- [ ] **Minor** L209: Limit the batch migration to reviewed files

## Chunk C - adapter-generator + test-fabricator  (1/15)


**`.claude/skills/jmo-adapter-generator/templates/adapter-template.py`**

- [ ] **Major** L130: Use the `AdapterPlugin.get_fingerprint()` contract

**`.claude/skills/jmo-test-fabricator/SKILL.md`**

- [ ] **Major** L203: Keep compliance enrichment in `normalize_and_report.py`

**`.claude/skills/jmo-test-fabricator/references/ci-platform-validation.md`**

- [ ] **Major** L35: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-test-fabricator/references/integration-patterns.md`**

- [ ] **Major** L155: Fail when the expected report is missing

**`.claude/skills/jmo-test-fabricator/references/memory-integration.md`**

- [ ] **Major** L91: Validate cached patterns before skipping schema analysis

**`.claude/skills/jmo-test-fabricator/references/required-test-functions.md`**

- [ ] **Major** L52: Assert the actual schema and fingerprint contract
- [ ] **Major** L504: Test compliance enrichment at the reporting boundary
- [ ] **Major** L783: Do not require non-empty tags from every adapter

**`.claude/skills/jmo-adapter-generator/references/memory-integration.md`**

- [ ] **Minor** L83: Keep compliance enrichment centralized

**`.claude/skills/jmo-adapter-generator/templates/adapter-template.py`**

- [ ] **Minor** L46: Normalize `PluginMetadata.name` from the adapter filename
- [x] **Minor** L46: Use integer exit-code keys in `PluginMetadata`
      -> RESOLVED: PR #717 - exit_codes int keys (10 sites); TWO other claims on this line still open

**`.claude/skills/jmo-test-fabricator/SKILL.md`**

- [ ] **Minor** L75: Limit the five-second requirement to fast tests

**`.claude/skills/jmo-test-fabricator/references/ci-platform-validation.md`**

- [ ] **Minor** L249: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-test-fabricator/references/common-mistakes.md`**

- [ ] **Minor** L80: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-test-fabricator/references/coverage-strategies.md`**

- [ ] **Minor** L26: Correct the uncovered-line count

## Chunk D - jmo-ci-debugger  (0/13)


**`.claude/skills/jmo-ci-debugger/references/ci-failure-catalog.md`**

- [ ] **Major** L158: (claim nested; read from the PR conversation)
- [ ] **Major** L463: (claim nested; read from the PR conversation)
- [ ] **Major** L1405: (claim nested; read from the PR conversation)
- [ ] **Major** L1466: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-ci-debugger/references/installation-config.md`**

- [ ] **Major** L96: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-ci-debugger/references/memory-integration.md`**

- [ ] **Major** L30: Handle invalid memory timestamps as cache misses
- [ ] **Major** L34: Do not return stale mappings as fresh results
- [ ] **Major** L99: Do not assign `high` confidence unconditionally
- [ ] **Major** L153: Handle reports with no CWE identifiers

**`.claude/skills/jmo-ci-debugger/references/ci-failure-catalog.md`**

- [ ] **Minor** L3: Index failure pattern 18 everywhere
- [ ] **Minor** L490: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-ci-debugger/references/error-pattern-matching.md`**

- [ ] **Minor** L29: Use one regex dialect consistently

**`.claude/skills/jmo-ci-debugger/references/prevention-strategies-full.md`**

- [ ] **Minor** L158: Pass staged paths as discrete arguments

## Chunk E - target-type-expander + security-hardening  (0/19)


**`.claude/skills/jmo-security-hardening/examples/vulnerability-fix-examples.md`**

- [ ] **Major** L159: (claim nested; read from the PR conversation)
- [ ] **Major** L331: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-security-hardening/references/rollback-performance.md`**

- [ ] **Major** L55: Remove force-push from the standard rollback procedure

**`.claude/skills/jmo-target-type-expander/SKILL.md`**

- [ ] **Major** L169: Do not convert scanner failures into missing-tool stubs
- [ ] **Major** L174: Make sanitized output names collision-resistant
- [ ] **Major** L244: Use one result-directory contract across producers and reporting

**`.claude/skills/jmo-target-type-expander/examples/real-world-examples.md`**

- [ ] **Major** L286: (claim nested; read from the PR conversation)
- [ ] **Major** L533: Mirror target flags in `ci_parser`

**`.claude/skills/jmo-target-type-expander/references/authentication-patterns.md`**

- [ ] **Major** L68: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-security-hardening/SKILL.md`**

- [ ] **Minor** L245: Correct the contradictory MEDIUM finding counts

**`.claude/skills/jmo-security-hardening/examples/vulnerability-fix-examples.md`**

- [ ] **Minor** L76: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-security-hardening/references/python-compat.md`**

- [ ] **Minor** L23: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-security-hardening/templates/security-commit-template.md`**

- [ ] **Minor** L84: Do not hard-code a co-author in the example

**`.claude/skills/jmo-target-type-expander/SKILL.md`**

- [ ] **Minor** L49: Make the implementation-step count consistent

**`.claude/skills/jmo-target-type-expander/examples/real-world-examples.md`**

- [ ] **Minor** L188: Make the batch-file syntax match the parser

**`.claude/skills/jmo-target-type-expander/references/authentication-patterns.md`**

- [ ] **Minor** L17: Reject empty environment credentials

**`.claude/skills/jmo-target-type-expander/references/memory-integration.md`**

- [ ] **Minor** L29: Handle cache misses explicitly

**`.claude/skills/jmo-target-type-expander/references/tool-selection.md`**

- [ ] **Minor** L64: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-security-hardening/templates/security-commit-template.md`**

- [ ] **Trivial** L30: Record the repository-required verification

## Chunk F - the 7 agents  (0/13)


**`.claude/agents/code-quality-auditor.md`**

- [ ] **Major** L319: (claim nested; read from the PR conversation)

**`.claude/agents/coverage-gap-finder.md`**

- [ ] **Major** L153: Make the proposed tests executable

**`.claude/agents/dependency-analyzer.md`**

- [ ] **Major** L50: Keep compliance enrichment in the report phase
- [ ] **Major** L124: (claim nested; read from the PR conversation)

**`.claude/agents/doc-sync-checker.md`**

- [ ] **Major** L579: Fix the relative-link example

**`.claude/agents/release-readiness.md`**

- [ ] **Major** L38: Push only the release tag
- [ ] **Major** L310: Do not infer branch parity from a one-sided log range
- [ ] **Major** L336: Run the image tag that the checklist builds

**`.claude/agents/security-auditor.md`**

- [ ] **Major** L182: Correct the command-injection analysis
- [ ] **Major** L273: Correct the path-traversal analysis
- [ ] **Major** L551: (claim nested; read from the PR conversation)

**`.claude/agents/codebase-explorer.md`**

- [ ] **Minor** L18: (claim nested; read from the PR conversation)

**`.claude/agents/security-auditor.md`**

- [ ] **Minor** L367: Avoid mutating input findings during redaction

## Chunk G - tail: refactoring, compliance, systematic-debugging, references  (0/11)


**`.claude/skills/jmo-compliance-mapper/references/framework-version-updates.md`**

- [ ] **Major** L14: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-refactoring-assistant/SKILL.md`**

- [ ] **Major** L86: Enforce the 85% coverage floor in every refactoring checklist
- [ ] **Major** L250: (claim nested; read from the PR conversation)
- [ ] **Major** L250: Do not expose an unrestricted `--skip-tests` path

**`.claude/skills/jmo-refactoring-assistant/references/test-migration-patterns.md`**

- [ ] **Major** L47: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-systematic-debugging/references/detailed-phase-guide.md`**

- [ ] **Major** L110: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-compliance-mapper/examples/compliance-report-examples.md`**

- [ ] **Minor** L69: (claim nested; read from the PR conversation)

**`.claude/skills/jmo-compliance-mapper/references/memory-integration.md`**

- [ ] **Minor** L67: Keep the framework-version schema complete

**`.claude/skills/jmo-refactoring-assistant/references/best-practices-troubleshooting.md`**

- [ ] **Minor** L13: Use the selected target in the import search

**`.claude/skills/references/memory-integration-pattern.md`**

- [ ] **Minor** L56: Write valid JSON in the storage example

**`.claude/skills/jmo-refactoring-assistant/references/memory-integration.md`**

- [ ] **Trivial** L81: Make rollback non-destructive

## Chunk H - repo config authored by PR #717  (3/6)


**`scripts/dev/check_doc_links.py`**

- [x] **Major** L114: Scan every tracked Markdown file
      -> RESOLVED: 1a4ab65 - coverage from git ls-files (87->162 files, 17 dead refs fixed)
- [x] **Major** L182: Use the repository console-output helpers
      -> RESOLVED: 1a4ab65 - harden_console_streams + safe_print

**`.claude/rules/testing.rules.md`**

- [ ] **Minor** L156: (claim nested; read from the PR conversation)

**`.pre-commit-config.yaml`**

- [ ] **Minor** L126: (claim nested; read from the PR conversation)

**`ROADMAP.md`**

- [ ] **Minor** L9: (claim nested; read from the PR conversation)

**`scripts/dev/check_doc_links.py`**

- [x] **Minor** L62: Handle multi-backtick inline code spans
      -> RESOLVED: 1a4ab65 - multi-backtick code spans
