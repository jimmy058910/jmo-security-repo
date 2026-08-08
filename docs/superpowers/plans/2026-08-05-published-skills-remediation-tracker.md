# Remediation tracker: the 103 published-skill review findings

**Strategy and per-chunk protocol:** [2026-08-05-published-skills-remediation.md](2026-08-05-published-skills-remediation.md)
**Tracking issue:** [#718](https://github.com/jimmy058910/jmo-security-repo/issues/718)
**Branch:** work each chunk off `dev`; PR into `dev`. Never `main`.

## Progress

**79 / 103 resolved.**

| Chunk | Scope | Findings | Done | Status |
|---|---|---:|---:|---|
| **A** | jmo-profile-optimizer | 13 | 13 | **complete** |
| **B** | dashboard-builder + documentation-updater | 13 | 13 | **complete** |
| **C** | adapter-generator + test-fabricator | 15 | 15 | **complete** |
| **D** | jmo-ci-debugger | 13 | 13 | **complete** |
| **E** | target-type-expander + security-hardening | 19 | 19 | **complete** |
| **F** | the 7 agents | 13 | 0 | not started |
| **G** | tail: refactoring, compliance, systematic-debugging, references | 11 | 0 | not started |
| **H** | repo config authored by PR #717 | 6 | 6 | **complete** |
| | **total** | **103** | **79** | |

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

## Chunk B - dashboard-builder + documentation-updater  (13/13)

Root cause for the dashboard half: **the skill reproduced an early prototype of
`scripts/core/reporters/html_reporter.py`.** The real module has since grown
placeholder validation and `<script>`-context escaping the copy never had, so
three findings were one stale snippet. Deleted and replaced with a citation.

**`.claude/skills/jmo-dashboard-builder/SKILL.md`**

- [x] **Major** L15: Make local data loading deterministic
      -> FIXED: it never loaded `findings.json`. `html_reporter.py` picks inline
      vs external on `INLINE_THRESHOLD`; external writes `dashboard-data.json`
      (not `findings.json` - that name is `basic_reporter.write_json()`'s
      metadata-wrapped output). Documented both modes. The review's remedy
      ("remove fetch") was **not** applied: it would reintroduce 50-100 MB HTML
      files, which is what the threshold exists to prevent. The `file://`
      opaque-origin caveat is recorded instead.
- [x] **Major** L33: Use one bundle-size policy across the dashboard documentation
      -> FIXED: no authoritative threshold existed in tests or CI, so there was
      nothing to align to. Made SKILL.md's <2 MB target authoritative and had
      troubleshooting.md defer to it. Measured the real artifact: 0.93 MB.
- [x] **Major** L145: Do not enable `inlineDynamicImports` while requiring code splitting
      -> FIXED: the skill demanded "code split by route" while its own config set
      `inlineDynamicImports: true`. Real `vite.config.ts` also sets
      `manualChunks: undefined`. Dropped the code-splitting requirement and
      replaced the reproduced config with a citation.
- [x] **Major** L219: Fail when the findings placeholder is missing
      -> DELETED: the real `html_reporter.py:64-75` already verifies the
      placeholder and falls back with a logged warning. Only the reproduced
      prototype lacked it.
- [x] **Major** L219: Escape findings before inserting them into the inline script (CWE-79)
      -> DELETED: `html_reporter.py:88-94` already escapes `</script>`,
      `<script`, `<!--` and backticks after `json.dumps`. Same stale snippet.
- [x] **Major** L230: Call the React reporter from the CLI
      -> DELETED: `write_html_react` does not exist. The CLI already calls
      `html_reporter.write_html`; the snippet's own fallback imported `write_html`
      from its own module, a circular import that could never have run.

**`.claude/skills/jmo-dashboard-builder/references/troubleshooting.md`**

- [x] **Major** L11: Do not lazy-load the Recharts namespace directly
      -> FIXED: `React.lazy` needs a default export; Recharts has published only
      named exports since v2.0. Real `src/App.tsx` lazy-loads local
      default-exporting wrappers. Also noted it buys zero bytes in a
      single-file build, since every dynamic import is inlined.

**`.claude/skills/jmo-documentation-updater/SKILL.md`**

- [x] **Major** L111: Use paths relative to the Markdown file
      -> FIXED: the file contradicted itself - its "Where to Start" table already
      used `../../../` while the guidance section taught root-relative paths that
      `check_doc_links.py` rejects. Also recorded that the checker validates the
      file but not the `#fragment`.
- [x] **Minor** L47: Fix the `DOCKER_README.md` quick-start link
      -> FIXED: the real heading is `## Quick Start (Absolute Beginners)`, so the
      anchor is `#quick-start-absolute-beginners`, not `#quick-start`.

**`.claude/skills/jmo-documentation-updater/templates/doc-update-templates.md`**

- [x] **Major** L364: Make the verification checklist fail when required updates are missing
      -> FIXED, and the defect was worse than claimed: step 1 grepped `jmo.yml`
      for a `tools:` key under `deep:` that **does not exist**, so it returned 0
      on every run. Rewritten against `tool_registry.py:PROFILE_TOOLS` with a
      real non-zero exit. Two of my own remedies were measured wrong first: a
      deep-only assertion produced **16 false positives** because 9/13/17 are
      fast/slim/balanced. Final form asserts membership in the live count set
      {9,13,17,28,29} - 5 hits, no false positives.
- [x] **Minor** L209: Limit the batch migration to reviewed files
      -> FIXED: replaced `find . -exec sed -i` with list-review-then-edit, and
      recorded two traps it hid (BSD `sed -i` eats the next filename without an
      explicit suffix; `sed -i` on Windows rewrites whole-file line endings).
      Marked the `--results` rename as illustrative: it is not a live
      deprecation - measured, `--results` still resolves today purely because
      argparse accepts unambiguous prefixes.

**`.claude/skills/jmo-documentation-updater/references/managing-skills-docs.md`**

- [x] **Minor** L8: Describe the public/private allowlist accurately
      -> RESOLVED: PR #717 - allowlist described accurately
- [x] **Minor** L14: Apply the changelog rule or narrow it
      -> FIXED (narrowed): measured, **zero** tracked skills or agents have a
      changelog section, so the rule was universally unmet. A per-skill changelog
      duplicates git history with nothing to keep it honest. Points at
      `git log -- .claude/skills/<skill>/` and the repository `CHANGELOG.md`.

## Chunk C - adapter-generator + test-fabricator  (15/15)


**`.claude/skills/jmo-adapter-generator/templates/adapter-template.py`**

- [x] **Major** L130: Use the `AdapterPlugin.get_fingerprint()` contract
      -> FIXED: template called it with 5 kwargs; real signature is
      `get_fingerprint(finding)` (plugin_api.py:144), so it raised TypeError.
      Adapters do not fingerprint at all - `BaseAdapter.load()` calls
      `_generate_fingerprint()` (base_adapter.py:181) and injects the digest.
      Template now leaves `id=""`, as bandit_adapter.py:105 does.

**`.claude/skills/jmo-test-fabricator/SKILL.md`**

- [x] **Major** L203: Keep compliance enrichment in `normalize_and_report.py`
      -> FIXED: Category 4 renamed to "v1.2.0 metadata" at all 4 sites
      (L101 outline, L133 header convention, L175 template, L339 checklist)
      plus the summary table, with a note routing framework mappings to the
      reporting boundary. Verified: `TestBanditCompliance`
      (test_bandit_adapter.py:365) is named for compliance and asserts
      schemaVersion/tool name/remediation - because that is what the adapter
      boundary guarantees.

**`.claude/skills/jmo-test-fabricator/references/ci-platform-validation.md`**

- [x] **Major** L35: Use the supported GitLab report format for the SAST artifact
      -> FIXED: `reports.sast` expects GitLab's SAST schema, not SARIF. GitLab
      does not error - it renders an empty Security tab, so the pipeline is
      green and reports nothing. SARIF is now a plain artifact.

**`.claude/skills/jmo-test-fabricator/references/integration-patterns.md`**

- [x] **Major** L155: Fail when the expected report is missing
      -> FIXED at 3 sites, not the 1 reported. `if findings_json.exists():`
      makes a scan that wrote nothing pass having asserted nothing; at the
      multi-tool pattern the ENTIRE assertion sat inside the guard.

**`.claude/skills/jmo-test-fabricator/references/memory-integration.md`**

- [x] **Major** L91: Validate cached patterns before skipping schema analysis
      -> FIXED: a hit proves a pattern was stored once, not that the schema is
      current. The format recorded no tool version, so a hit could not be
      validated at all; added `tool_version` + compare against versions.yaml.

**`.claude/skills/jmo-test-fabricator/references/required-test-functions.md`**

- [x] **Major** L52: Assert the actual schema and fingerprint contract
      -> FIXED: 3 defects. `len(id) > 20` is wrong in the FAILING direction -
      the digest is 16 chars (FINGERPRINT_LENGTH), measured b52adc71af4ac748.
      `startswith(("<tool>", ""))` is a tautology. schemaVersion is an
      equality, not a membership test over stale versions.
- [x] **Major** L504: Test compliance enrichment at the reporting boundary
      -> FIXED: there is no `enrich_finding_with_compliance` on the adapter
      path; normalize_and_report.py:234 does it in the report phase. The block
      was also guarded by `if "compliance" in item:` - a no-op reporting green.
- [x] **Major** L783: Do not require non-empty tags from every adapter
      -> FIXED: `tags` is absent from the schema's `required` list
      (docs/schemas/common_finding.v1.json). Checked only when present.

**`.claude/skills/jmo-adapter-generator/references/memory-integration.md`**

- [x] **Minor** L83: Keep compliance enrichment centralized
      -> FIXED: "Pre-populate compliance fields" -> cache mapping *inputs*;
      enrichment is `normalize_and_report.py:234`.

**`.claude/skills/jmo-adapter-generator/templates/adapter-template.py`**

- [x] **Minor** L46: Normalize `PluginMetadata.name` from the adapter filename
      -> FIXED: it matches the ADAPTER filename identifier, not the output
      filename. dependency_check_adapter.py:50 uses `name="dependency_check"`.
      plugin_loader.py:235 has to try both variants because this drifts.
      Sibling bullet in SKILL.md L61-67 corrected too.
- [x] **Minor** L46: Use integer exit-code keys in `PluginMetadata`
      -> RESOLVED: PR #717 - exit_codes int keys (10 sites); TWO other claims on this line still open

**`.claude/skills/jmo-test-fabricator/SKILL.md`**

- [x] **Minor** L75: Limit the five-second requirement to fast tests
      -> FIXED: contradicted by this skill's own integration-patterns.md
      (timeout=120..240). Measured: tests/adapters/ is 1819 tests in ~18s,
      slowest 0.43s. Rule is now per-test and per-layer.

**`.claude/skills/jmo-test-fabricator/references/ci-platform-validation.md`**

- [x] **Minor** L249: Test Python 3.8 in the CI example
      -> DISMISSED as stated; the surrounding CLAIM was the defect. pyproject
      sets requires-python ">=3.12", CI pins 3.12, and scripts/core/ uses
      `str | None` which 3.8 cannot parse. The example was right. The "3.8
      compatibility" rule was actively harmful - it told contributors to write
      Optional[str] in a codebase written the other way. Fixed at 3 sites.

**`.claude/skills/jmo-test-fabricator/references/common-mistakes.md`**

- [x] **Minor** L80: Do not describe `pytest.mark.slow` as timeout protection
      -> FIXED: `slow` is a selection marker. In THIS repo it means "runs in
      the PR shards but not the quick coverage gate" - see #742. Example now
      shows subprocess timeout= and @pytest.mark.timeout().

**`.claude/skills/jmo-test-fabricator/references/coverage-strategies.md`**

- [x] **Minor** L26: Correct the uncovered-line count
      -> FIXED: and a second inconsistency the finding missed - the Miss
      column said 15 while the ranges summed to 10. Ranges are now
      18-22, 35-39, 45-49 = 15, with 27/42 giving the stated 64%.

## Chunk D - jmo-ci-debugger  (13/13)

**Two root causes, plus a review-tool defect worth knowing about.**

1. **Speculative content presented as battle-tested.** The skill opens "Every fix
   has been battle-tested in production CI/CD workflows." Pattern #13 was not:
   `createCommitStatus` appears **nowhere** in `.github/workflows/`, in any
   commit (`git log -S`), and its central claim is measurably false against this
   repo's own ruleset.
2. **Staleness against hardened originals** - chunk B's shape. The Dockerfile
   snippet reproduces a prototype from before the v1.0.3 download hardening, so
   it carries the exact `curl | tar` pipe that `.claude/rules/docker.rules.md`
   now forbids.

**Review-tool defect: 4 of the 13 were anchored to the wrong file.** The API
`path` for the four `memory-integration.md` findings is *jmo-ci-debugger*, and
the `diff_hunk` confirms the anchor really sits in that file - but the finding
bodies analyse Python (`datetime.fromisoformat`, `store_compliance_mapping`,
`unique_cwes`) that exists only in **`jmo-compliance-mapper/references/memory-integration.md`**,
at those exact line numbers. Two files, same basename, similar length. The
claims are all real *there*, so they were fixed there and are counted here.
Grep the cited symbol before trusting a path.

**Verification.** Markdown is not executed by any test, so the examples were
extracted and run. Pre-fix code reproduced every claimed failure
(`TypeError: fromisoformat: argument must be str`, `ValueError: Invalid
isoformat string`, a 200-day-old record returned as fresh, `confidence='high'`
on an empty mapping, `ZeroDivisionError`); rewritten code passes 17 checks
including traversal payloads and a store/reload cycle. The regex table was run
through `grep -E` against sample log lines, and the actionlint recipe was
downloaded, checksummed and extracted for real.

**`.claude/skills/jmo-ci-debugger/references/ci-failure-catalog.md`**

- [x] **Major** L158: Do not execute an unpinned remote script (CWE-494)
      -> FIXED: `bash <(curl .../actionlint/main/scripts/download-actionlint.bash)`
      runs whatever `main` holds at job time. Replaced with a pinned release,
      `sha256sum -c`, and `gzip -t`, per the repo's own Download Hardening
      Convention - which the old line also violated (no `-f`, no `--retry`).
      **Executed end-to-end**; the first draft was wrong and the run caught it:
      `sha256sum -c` resolves the filename *inside* the checksums line, so
      saving as `actionlint.tar.gz` could never verify. Keeps the canonical
      asset name now. Verified 2353908 bytes, checksum OK, valid x86-64 ELF.
- [x] **Major** L463: Use the least-privileged Docker Hub token
      -> FIXED: README sync PATCHes the repository description, which needs
      Read & Write. `Delete (required for README updates)` was false and only
      widened a leaked token's blast radius.
- [x] **Major** L1405: Do not assume rulesets require commit statuses
      -> FIXED, and the claim was wrong in four places, not one (heading,
      root-cause paragraph, comparison-table row, prevention list).
      **Measured against this repo:** ruleset `9147592` requires
      `{"context":"quick-checks","integration_id":15368}`;
      `commits/<sha>/status` returns `{"state":"pending","statuses":[]}` -
      zero commit statuses have ever existed - while `check-runs` shows
      `quick-checks` succeeding from app 15368, and PRs merge normally. A check
      run alone satisfies the rule. Section re-rooted on the real cause: a
      required context that matches no job name, or a job filtered out by
      `paths:`/`if:` so it never reports.
- [x] **Major** L1466: Grant `statuses: write` for the commit-status step
      -> FIXED at both sites, plus two defects the finding missed. The call was
      **not awaited**, so the step could finish green having posted nothing; and
      it used `context.sha`, which on `pull_request` is the merge commit rather
      than the head the ruleset checks. `job.status` now arrives via `env:`
      instead of being interpolated into JavaScript source.
- [x] **Minor** L3: Index failure pattern 18 everywhere
      -> FIXED: pattern 18 exists at L1921 while the header said "all 17".
      Corrected at 4 real sites - catalog L3, `SKILL.md` "All 17 failures",
      the SKILL.md quick-lookup list, and the error-pattern table - plus the
      decision tree, which the finding did not mention. The cited `SKILL.md:92`
      needed **no** change: it carries no count.
- [x] **Minor** L490: Update the Docker Hub authentication example
      -> FIXED, and understated: `curl -u ... GET /v2/users/login/` returns
      **HTTP 415** (measured, no credentials needed), so it fails on method
      before the token is evaluated - meaning the old "If error 401: token
      expired" guidance was also unreachable. Now `POST /v2/auth/token` with a
      JSON body, whose 400 response names `identifier`/`secret`.

**`.claude/skills/jmo-ci-debugger/references/installation-config.md`**

- [x] **Major** L96: Install `xz-utils` before extracting the archive
      -> FIXED, and the surrounding snippet was stale in three further ways.
      All four real Dockerfiles already install `xz-utils` in the base layer
      (`fast:18`, `slim:18`, `balanced:18`, `deep:19`), so the trailing comment
      "deep variant has it via build-essential transitive dependency" is false.
      The real files download to a file and run `xz -t` before `tar`; the
      snippet piped `curl` straight into `tar`, the exact "not in gzip format"
      failure the hardening convention exists to prevent. Version literal now
      defers to `versions.yaml` rather than pinning a stale `0.10.0` (real:
      `0.11.0`).

**`.claude/skills/jmo-compliance-mapper/references/memory-integration.md`** *(the four mis-anchored findings)*

- [x] **Major** L30: Handle invalid memory timestamps as cache misses
      -> FIXED: reproduced both `TypeError` (key absent -> `.get()` returns
      `None`) and `ValueError` (hand-edited value). Both, plus `KeyError`, now
      resolve to a miss. Corrupt JSON and unreadable files too.
- [x] **Major** L34: Do not return stale mappings as fresh results
      -> FIXED: reproduced - a 200-day-old record printed "recommend refresh"
      and then returned itself, so nothing ever refreshed. Stale now returns
      `None`. Verified at 200d (miss), 5d (hit) and 179d23h (hit).
- [x] **Major** L99: Do not assign `high` confidence unconditionally
      -> FIXED: reproduced `confidence='high'` on a mapping with **zero**
      frameworks and no evidence, which made the field meaningless. Now derived
      - `high` only when all six frameworks resolve *and* evidence is cited,
      else `partial`/`unverified` - with an `unresolved` list naming the gaps.
- [x] **Major** L153: Handle reports with no CWE identifiers
      -> FIXED: reproduced `ZeroDivisionError` on an empty finding list, which
      is a normal input (a clean scan, or tools emitting only rule ids).
      **Root cause behind all four:** the enclosing examples begin
      `from scripts.core.memory import query_memory` - no such module, so every
      one was dead on line 1 and fixing the four bugs alone would have repaired
      fiction. Rewritten against the real file convention per chunk A's policy.
      Also renamed the helper: it was called `enrich_findings_with_compliance`,
      colliding with **production code** at `compliance_mapper.py:1278` that
      does something entirely different.

**`.claude/skills/jmo-ci-debugger/references/error-pattern-matching.md`**

- [x] **Minor** L29: Use one regex dialect consistently
      -> **FIXED in part, DISMISSED in part - the review's remedy corrupts the
      file.** Measured: rows 21 and 28 (`\d`) match **nothing** under `grep -E`,
      because GNU grep reads `\d` as a literal `d`; fixed to `[0-9]`, and the
      standalone regex blocks fixed likewise (`[\w.]` also fails - GNU
      extensions do not work inside a bracket expression). But rows 17 and 27
      are **correct as written**: `\|` there is the mandatory *GFM table* escape,
      not regex. Verified via `gh api markdown` that it renders as a bare `|`;
      verified that applying the remedy splits the code span across two cells
      and pushes the `#5` column out of the row. All 18 table patterns now
      re-verified as valid ERE matching a real log line.

**`.claude/skills/jmo-ci-debugger/references/prevention-strategies-full.md`**

- [x] **Minor** L158: Pass staged paths as discrete arguments
      -> FIXED: measured, `mypy $STAGED_PY` turned 4 staged files into 5 wrong
      arguments (`has space.py` -> `has` + `space.py`). Now `-z` +
      `xargs -0` + `--`, with `--diff-filter=ACMR` so deleted files are not
      linted, and a guard because GNU `xargs` still runs once on empty input.
      **Sibling the review missed:** the same hook loops over
      `scripts.core.constants`, which does not exist - so it hit `exit 1` on
      every run, and a hook that always fails gets bypassed with `--no-verify`.

## Chunk E - target-type-expander + security-hardening  (19/19)

Root-cause shape: **SPECIFICITY**. Three findings turned out to be claims
*about* claims — a package that does not exist, a protection that cannot work
as delivered, and a gate that fires nowhere. Each had survived because it was
precise: a vague claim invites checking, a specific one does not.

**`.claude/skills/jmo-security-hardening/examples/vulnerability-fix-examples.md`**

- [x] **Major** L159 **FIXED, and the finding understated it.** It said
  `--profile` is "a timing/reporting flag" on scan. Measured: `jmo scan` has
  **no `--profile` at all** — `--help` lists only `--profile-name`, and
  `--profile balanced` is silently accepted only because argparse abbreviates
  unambiguous prefixes. Reproduced in isolation: with just `--profile-name`
  defined, `parse_known_args(["--profile","fast"])` → `profile_name='fast'`;
  with both defined (which is `jmo ci`) it binds the boolean and leaves
  `'fast'` stray. Switched to `--profile-name` and recorded why.
- [x] **Major** L331 **FIXED at both sites, scope wider than reported.** The
  finding named 2 inert mechanisms; there are **3**. `X-Frame-Options` **and**
  `X-Content-Type-Options` are header-only in a `<meta>`, plus CSP's
  `frame-ancestors`. `<meta name="referrer">` and `<meta name="robots">` are
  correct meta forms. Production emits all of them
  (`scripts/dashboard/index.html:8-12`), so the docs now say these are
  documentation of intent, not enforcement — and note that
  `tests/reporters/test_html_security.py` asserts *presence*, not enforcement.
- [x] **Minor** L76 **FIXED by rewriting against real code.** The finding asked
  for `hostname`/`action` validation after `verify()`. But `verify()` came from
  `require('@cloudflare/turnstile')`, and **`npm view @cloudflare/turnstile`
  returns 404** — the package does not exist. Polishing that call would have
  refined fiction. Rewrote the example as the siteverify POST the shipped
  endpoint actually performs (`scripts/api/subscribe_endpoint.js:104-126`),
  then added the context checks, keeping its fail-closed 503 behaviour.

**`.claude/skills/jmo-security-hardening/references/rollback-performance.md`**

- [x] **Major** L55 **FIXED, scope wider than reported.** The finding flagged
  the force-push in Option 3; Option 1 also pushed straight to `main`. Both are
  blocked, and this was checked against the live API rather than assumed:
  ruleset `9147592` is `active` on `refs/heads/main` with `pull_request` and
  `non_fast_forward`; only `actor_id: 5` (Repository Admin) has
  `bypass_mode: always`. Rewrote all three options to go through a PR and
  documented the `gh api` command that re-verifies the rules.

**`.claude/skills/jmo-target-type-expander/SKILL.md`**

- [x] **Major** L169 **FIXED — highest-value item in the chunk.** The `elif
  args.allow_missing_tools` sat inside the `_tool_exists` branch, so a tool
  that ran and *failed* got a stub and reported success. This is the exact bug
  the scan core carried in five jobs, which hid three scanners (yara,
  dependency-check, prowler) that had never once worked. Rewrote to record the
  real exit code, and pointed at the production shape in
  `scripts/cli/scan_jobs/image_scanner.py:88-116`. **Six copied instances** in
  `examples/real-world-examples.md` fixed too — the finding said "branches"
  without a count.
- [x] **Major** L174 **FIXED.** Replaced the skill's private
  `re.sub(r"[^a-zA-Z0-9._-]", "_", ...)` with the shared
  `_sanitize_path_component` (`scripts/cli/path_sanitizers.py:16`) — the skill
  had been documenting a *second*, different sanitizer. Executed it: `a/b`,
  `a?b`, `a:b`, `a|b`, `a<b` → **5 distinct inputs, 1 output** (`a_b`).
  Documented a sha256-suffix disambiguation and ran that too.
- [x] **Major** L244 **FIXED, and the real defect was bigger.** Not a naming
  mismatch: the table claimed "currently supports 9 target types" while
  **6** exist. All seven CLI flags for Cloud/Mobile/Host are absent from
  `jmo scan --help`, nothing in `scripts/` references
  `individual-cloud|mobile|hosts`, and `normalize_and_report.py:162-167` lists
  six. Marked those three rows *(not implemented)*, made the `target_dirs`
  example match reality verbatim, and added a `jq` check that proves the wiring
  end-to-end — because omitting this step fails **silently**.
- [x] **Minor** L49 **FIXED.** Three counts disagreed: "4-function pattern"
  (L45), "4-Step Implementation Pattern" (L97), and a 6-item checklist against
  5 defined sections. Settled on **5**, folding the checklist's "results
  directory created" into Step 2, which is where `job_<type>` does the `mkdir`.

**`.claude/skills/jmo-target-type-expander/examples/real-world-examples.md`**

- [x] **Major** L286 **FIXED.** The Snyk branch declared `out = out_dir /
  "snyk.json"` and never wrote it — `rc, _, _, used` discarded stdout with no
  `capture_stdout=True`, so the file never existed and the report phase found
  nothing while the tool reported success. Mirrored the npm-audit handling
  directly above it.
- [x] **Major** L533 **FIXED at both sites.** Examples 1-3 register `scan_parser`
  *and* `ci_parser`; mobile (L524-527) and host (L604) registered only
  `scan_parser`, contradicting the skill's own Step 4 rule. Added the `ci_parser`
  mirrors. Confirmed the failure is real, not theoretical: `jmo ci --repo .
  --fail-on HIGH --profile balanced` exits **2**, `unrecognized arguments`.
- [x] **Minor** L188 **FIXED.** Executed the documented parser against the
  documented sample: both entries came back as
  `'123456789012  # Main prod'`, and **0 of 2** parsed as valid account IDs.
  Moved the annotations onto their own lines, and recorded why the parser is
  right *not* to strip trailing `#` — it is legal in other target identifiers,
  URL fragments especially.

**`.claude/skills/jmo-target-type-expander/references/authentication-patterns.md`**

- [x] **Major** L68 **FIXED at all 3 sites**, and the anchors were correct this
  time (chunk D's wrong-file trap did not recur — verified by grepping the
  cited symbols first). Pattern 2's cons now name CWE-214 and the three ways
  `argv` leaks (`ps -ef`, `/proc/<pid>/cmdline`, `Get-CimInstance
  Win32_Process`). `real-world-examples.md` GraphQL header carries the warning
  and points at Pattern 1. `common-pitfalls.md` "Good!" example now shows the
  tool reading the variable itself — sourcing from `os.environ` keeps a secret
  out of *git* but puts it straight back in the *process list*.
  **Self-correction:** the first draft invented a `--header-from-env` flag for
  graphql-cop. That tool is not in `versions.yaml`, so the flag was
  unverifiable — exactly the fiction this chunk exists to remove. Reverted to
  the flag that exists, with the exposure stated plainly.
- [x] **Minor** L17 **FIXED.** `"<TYPE>_TOKEN" not in os.environ` accepts an
  empty value; an unresolved CI secret is exported as `""`, so the scan runs
  unauthenticated and reports success. Now `not os.environ.get(...)`. One site
  — grepped for siblings; `common-pitfalls.md:122` already used `.get`.

**`.claude/skills/jmo-target-type-expander/references/memory-integration.md`**

- [x] **Minor** L29 **FIXED, and executing it caught a bug in my own fix.**
  `cat <missing> | jq` errors on a miss, which is the normal case. First
  replacement used `jq -e ... 2>/dev/null || echo "cache miss"` — and on this
  box, where `jq` is **not installed**, that reports "cache miss" for *every*
  lookup including present-and-correct entries. A cache that can only miss is
  indistinguishable from no cache. Final version guards with `command -v jq`
  and separates rc 2 (no jq) from rc 1 (no entry); all four paths executed
  against a stub `jq`. Also recorded that **nothing creates `.jmo/memory/`** —
  no `scripts/` file references it and it is absent from a checkout.

**`.claude/skills/jmo-target-type-expander/references/tool-selection.md`**

- [x] **Minor** L64 **FIXED, verified from the package rather than the web.**
  Downloaded the ScoutSuite 5.14.0 wheel from PyPI and read
  `entry_points.txt`: `[console_scripts]` declares exactly `scout =
  ScoutSuite.__main__:run_from_cli` and no `scoutsuite`. Corrected the command
  and annotated the tool table.

**`.claude/skills/jmo-security-hardening/SKILL.md`**

- [x] **Minor** L245 **FIXED.** "0 MEDIUM (from 6)" vs an enumerated list of 3
  IDs. Took the enumerated list as authoritative → "from 3". Checked first that
  the four cited target files all exist; they do, so this skill is grounded in
  real code and only the count was wrong.

**`.claude/skills/jmo-security-hardening/references/python-compat.md`**

- [x] **Minor** L23 **DELETED (whole file).** The finding asked to change one
  row from 3.9+ to 3.10+. That row is wrong, but the file's *premise* is the
  defect: it teaches Python 3.8 workarounds for a repo pinned to
  `requires-python = ">=3.12"`, which its own line 24 admitted. Measured: 151
  of 183 `scripts/*.py` (83%) carry `from __future__ import annotations`;
  `is_relative_to`/`removeprefix`/`removesuffix` are used freely; and its
  "3.8-compatible" example **is** the production `_validate_output_path`
  (`scripts/cli/path_sanitizers.py:62-99`), so it taught strictly less than the
  source. Both `SKILL.md` references replaced with a pointer to that module.
  > Also corrected the handoff's framing: `str | None` **parses** fine under
  > `ast.parse(..., feature_version=(3,8))`. It fails at *evaluation* on <3.10,
  > and not at all under `from __future__ import annotations`.

**`.claude/skills/jmo-security-hardening/templates/security-commit-template.md`**

- [x] **Minor** L84 **FIXED, and it broke a standing convention.** Not merely a
  hardcoded co-author: `Co-Authored-By: Claude <noreply@anthropic.com>` is an
  AI-attribution marker, which this project forbids in commits and PRs. Removed
  from the example; the template slot is documented as being for a human
  reviewer who has agreed.
- [x] **Trivial** L30 **FIXED, with the 85% claim corrected rather than
  copied.** Added `make fmt && make lint && make test` (real). Did **not** add
  a ">=85% coverage" gate, because it does not exist: `--cov-fail-under=85`
  appears only in `.claude/` prose, `make test` runs `pytest ... --cov
  --cov-report=term-missing` with no threshold, `[tool.coverage.report]` sets
  no `fail_under`, and CI's only enforced floor is **70%**
  (`.github/workflows/ci.yml:734`) — whose own comment claims `make test`
  enforces 85%. Filed separately; template now says "Coverage: [NN]% (CI floor:
  70%)". Same correction applied to the target-type-expander checklist.

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

> Chunk D already rewrote the Python in this file (the four mis-anchored
> findings). The JSON example below was **deliberately left alone** so the chunk
> tallies stay honest - it belongs to G, not D.

- [ ] **Minor** L67: Keep the framework-version schema complete

**`.claude/skills/jmo-refactoring-assistant/references/best-practices-troubleshooting.md`**

- [ ] **Minor** L13: Use the selected target in the import search

**`.claude/skills/references/memory-integration-pattern.md`**

- [ ] **Minor** L56: Write valid JSON in the storage example

**`.claude/skills/jmo-refactoring-assistant/references/memory-integration.md`**

- [ ] **Trivial** L81: Make rollback non-destructive

## Chunk H - repo config authored by PR #717  (6/6)

Unlike A-G this chunk is repo *behaviour*, not skill prose, so CI alone is not
sufficient evidence — the hook-scope change was verified by running the hook
before and after.

**`scripts/dev/check_doc_links.py`**

- [x] **Major** L114: Scan every tracked Markdown file
      -> RESOLVED: 1a4ab65 - coverage from git ls-files (87->162 files, 17 dead refs fixed)
- [x] **Major** L182: Use the repository console-output helpers
      -> RESOLVED: 1a4ab65 - harden_console_streams + safe_print

**`.claude/rules/testing.rules.md`**

- [x] **Minor** L156: Synchronize the missing deliberate verification gaps
      -> FIXED: the rules file lists three Deliberate Verification Gaps and says
      a gap a user can hit belongs in `KNOWN_LIMITATIONS.md` too; only
      *Concurrent scans on Windows* had made it across. Added the user-facing
      halves of the other two. The reboot entry was **corrected mid-draft by
      checking the code**: `jmo schedule install` is cron-only, Linux/macOS,
      with no Windows Scheduled Task backend (`--help` says so;
      `tests/unit/test_cron_installer.py:20` skips on win32), so it now points
      Windows users at `schedule export`.

**`.pre-commit-config.yaml`**

- [x] **Minor** L126: Make the `doc-links` scope match the documented guarantee
      -> FIXED on both halves. `files:` named 7 root files plus `docs/` and
      `.claude/`, leaving **28** tracked Markdown files outside it. Because
      `pass_filenames: false` the checker already scans every tracked file when
      it runs, so `files:` only decides *when* — widening it to all Markdown
      costs nothing per run and takes uncovered from 28/177 to **0/177**.
      **The CI half was false too:** `CLAUDE.md:201` and `.gitignore:121` both
      claim the checker "fails CI and pre-commit", but `lint-quick` ran 8 named
      hooks and `doc-links` was not among them — only the nightly all-hooks job
      enforced it. Added to that step. Verified by running the hook: old config
      **Skipped** `CHANGELOG.md`, new config runs it, and a non-Markdown path
      stays correctly inert.

**`ROADMAP.md`**

- [x] **Minor** L9: Update stale v1.0.5 release references
      -> FIXED: `pyproject.toml:7` and `ROADMAP.md` say v1.0.8 while
      `CLAUDE.md:11` and `docs/index.md:192` still said v1.0.5.
      `docs/CLI_REFERENCE.md:5` says `1.0.0` and was **deliberately left** ->
      #750: bumping that header asserts the document's *contents* describe
      v1.0.8's CLI, which is unaudited. #750 also covers the missing guard —
      `test_version_consistency.py` checks only the three code sites, never the
      prose headers, which is why these drifted across three releases.

**`scripts/dev/check_doc_links.py`**

- [x] **Minor** L62: Handle multi-backtick inline code spans
      -> RESOLVED: 1a4ab65 - multi-backtick code spans
