# Phase 5 — The rule bundle, and opengrep replaces semgrep: task plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** semgrep and its registry leave; opengrep runs a committed, offline,
security-only rule bundle chosen by the languages a repository contains; nothing a scan
does touches the network or leaves matched code in the user's home; and the two
rostered issues, #1228 and #1229, close.

**Architecture:** two PRs. PR A adds the bundle and nothing that runs it: a builder
script fetches two pinned rule sources, keeps `category: security`, namespaces every id
by its path, drops the snapshot rules GitLab's maintained set duplicates, and writes one
YAML per language into `scripts/jmo_rules/`, which is committed and shipped as package
data. PR B swaps the `semgrep` descriptor row for an `opengrep` row that hands the
engine the bundle files for the languages present, renames the adapter, and removes
semgrep everywhere. The juice-shop fixture is fetched at a pinned commit at test time,
never committed.

**Tech Stack:** Python 3.12, pytest (+xdist), opengrep 1.31.0 (static binary, new),
opengrep-rules `f1d2b56`, GitLab `sast-rules` v2.10.1, the MIT packs 0xdea `e0121ac1` and
elttam `24426856` (added 2026-10-29, D13), GitHub Actions, Docker.

**Spec:** [2026-09-12-v2.0.0-program-design.md](../specs/2026-09-12-v2.0.0-program-design.md)
§3, §4.2 R3 and R4, §5, §12; program plan
[2026-09-12-v2.0.0-program.md](2026-09-12-v2.0.0-program.md) § Phase 5; the model is
[the Phase 4 task plan](2026-09-27-phase-4-new-tools.md).

## Global Constraints

- **Backward compatibility is NOT a constraint.** No users. The tool name is hashed into
  every finding id (`fingerprint()`, `scripts/core/common_finding.py:325-335`), so every
  SAST finding id changes once, deliberately; `UPGRADE.md` says so.
- **One formatter:** `ruff format`. `make fmt && make lint` (or `pre-commit run --all-files`).
- **No `shell=True`.** Every `subprocess.run` passes `timeout=`.
- **Conventional commits, no AI-attribution markers of any kind** (no `Co-Authored-By`,
  no "Generated with", no `Claude-Session:`), in commits and PR bodies.
- **Commit and merge only when Jimmy says.** PR into `dev`, squash; subject
  `feat!: v2.0.0 Phase 5 PR <X>, …` as Phase 4's were. `Closes #N` goes in the COMMIT
  body; a PR body into `dev` is inert. The `dev` → `main` sync is a fast-forward push.
- **Work in a worktree.** The maintainer's main checkout stays on `dev` for the
  metrics timer. Scratch and `pytest --basetemp` go under `~/.cache/`: `/tmp` is tmpfs.
- **`uv` must equal `PINNED_UV_VERSION` (0.13.1) before any relock.**
- **Gates are numbers through `jmo scan` / `jmo report`, never a bare binary**, except
  where a task measures the binary itself. Every spawned `jmo scan` gets
  `--history-db <tmp>` and `--results-dir <tmp>`.
- **Suite:** `.venv/bin/python -m pytest <part> -n 8 -q -rfEs --basetemp ~/.cache/pytest-p5 -m "not smoke and not requires_tools and not docker"`.
  **Diff failing-test ID sets, never counts.** Read the `windows-2022` and `docker-smoke`
  job logs, never their ticks. Windows is CI plus the laptop (`.218`).
- **Mutation-test every guard** from a byte backup; restore byte for byte.
- **Never edit tool versions in `Dockerfile` by hand**: `versions.yaml`, then
  `python3 scripts/dev/update_versions.py --sync`.
- **No juice-shop file is ever committed.** `lib/insecurity.ts` holds an RSA private key
  (the `detect-private-key` hook) and `routes/login.ts:65` trips gitleaks
  `generic-api-key` (measured). No private repository's name or content beyond counts
  and timings; measure them on `git archive` exports, never in place.
- **Line endings:** `python scripts/dev/check_eol_flips.py --base origin/dev` after
  `git add`. Generated files are written with `write_bytes`, LF.

## Measured before this plan was written (2026-10-22 and 2026-10-23, Debian `.199`)

Evidence and scripts were in `~/.cache/jmo-phase5/` (not backed up); every number this
plan argues from is copied here. Binary: opengrep 1.31.0 `opengrep_manylinux_x86`,
sha256 `dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147`. Sources:
opengrep-rules `f1d2b562b414783763fd02a6ed2736eaed622efa`, GitLab `sast-rules` v2.10.1
`53bf5cf6df3c51b6c02110f5a638b5e6213666cd`, juice-shop
`401393872069a1cedc8cdd26e89f2f8e05fe0dab` (2025-12-22). semgrep 1.181.0 for comparison.

**Parity.** The parity target's `src/`, unfiltered JavaScript + TypeScript rules: the
identical 212-finding set, keyed `(rule, path, line, col)`, across ten runs (merged or
per-directory configs, semgrep or opengrep, `-j 8/4/1`). With the `category: security`
filter the same target gives **0 findings**: all 212 were non-security rules.

**R3 is closed by measurement, not by rewriting rules.** On juice-shop, the namespaced
merge with no id dedup fires all eight "semgrep-only" findings in opengrep:
`tainted-sql-string` ×6 (`routes/login.ts:34`, `routes/search.ts:23`, and four in
`data/static/codefixes/`), `jsonwebtoken…hardcoded-jwt-secret` (taint mode) at
`lib/insecurity.ts:56`, and the Pug `template-explicit-unescape` at
`views/promotionVideo.pug:79`. The gap R3 described came from B's archived merge script,
which deduplicated by bare id and dropped nine distinct rules, both
`tainted-sql-string` variants and the jsonwebtoken taint rule among them. Same config,
both engines: 96 findings each at `(rule, path, line)`, 95 shared; one `raw-html-format`
only in semgrep, one `express-detect-notevil-usage` only in opengrep; columns differ on
some taint sinks (`login.ts:34`: 64 vs 66). Files scanned: opengrep 1040, semgrep 936.

**Rule ids.** By default the engine prefixes every `check_id` with the config file's
directory, dotted (`home.jimmy..cache.jmo-phase5.out.javascript…`), so the prefix moves
with the working directory. With `--no-rewrite-rule-ids` the id is exactly the one in
the YAML, from `/`, from `$HOME` and from the target root alike.

**The bundle, built by a probe of PR A's builder.** Every opengrep-rules language
directory except `scripts`, `stats`, `problem-based-packs`; `.yaml`/`.yml` files that
are not `*.test.yaml`; GitLab `rules/lgpl-cc/**/rule-*.yml`; `category: security`; ids
namespaced by path. With `generic/secrets/` excluded: **25 files, 1,401 rules, 2.3 MB**;
gitleaks 0, trufflehog 0, `BEGIN … PRIVATE KEY` lines 0; `opengrep scan --validate`
"0 configuration error(s)" on 25 of 25. With `generic/secrets/` included: 1,626 rules,
and all five secret-scanner hits (gitleaks `private-key`, `slack-webhook-url`; trufflehog
2× SlackWebhook; 2 private-key header lines) come from it, which is 225 of 248 generic
security rules, including a port of gitleaks' own rules. Per language without it:
python 275, terraform 260, javascript 170, java 155, ruby 130, go 71, php 70, csharp 48,
yaml 39, solidity 35, scala 26, generic 23, typescript 18, kotlin 14, c 12, apex 11,
rust 10, ocaml 7, dockerfile 6, clojure 5, html 4, json 4, swift 4, bash 3, properties 1.

**GitLab overlap.** `lgpl-cc` has 100 security rules (java 39, ruby 40, php 9, python 9,
javascript 1, properties 1, yaml 1). With a rule's body defined as the rule minus `id`,
`message`, `metadata` and `severity`, as canonical JSON, **50** are body-identical to a
snapshot security rule: ruby 32, php 9, java 6, python 2, properties 1.

**Memory and time** (peak RSS of the process tree, 8 CPUs):

| Run | `-j 8` | `-j 4` | `-j 2` | `-j 1` |
|---|---|---|---|---|
| parity target, unfiltered js+ts, per-directory configs | 1,068–1,084 MB, 14 procs, 6 s | | | |
| parity target, unfiltered js+ts merged | 575–598 MB, 3.3 s | 451 MB | | 306 MB |
| parity target, 8 bundle files (js, ts, generic, json, yaml, html, bash, dockerfile) | 601 MB, 4.0 s | **467 MB**, 3.9 s | | |
| parity target, all 25 bundle files | 822 MB, 11.4 s | 683 MB, 11.5 s | | |
| juice-shop, 8 bundle files | 1,853 MB, 28.0 s | 1,492 MB, 27.3 s | 1,410 MB | 791 MB, 53.5 s, 20 `three.js` findings lost to timeouts |

`--exclude-minified-files` does not help juice-shop (1,557 MB at `-j 4`, same 211
findings). juice-shop with the 8 files: 46 errors (`PartialParsing`, `Syntax error`,
2 `Timeout` on `frontend/src/assets/private/three.js`). The merge lever is about 1.85×
on Linux, not A's 3.5× (Windows).

**Output.** `--json` carries `extra.severity`, `extra.metadata` (CWE, OWASP, confidence,
likelihood, impact), `errors` and `paths.scanned`. `--sarif` carries the id in `ruleId`
and CWE/OWASP/confidence as rule `tags`, the level only on the rule's
`defaultConfiguration`, and no scanned-file list.

**The binary.** It self-extracts **246 MB** into `~/.cache/opengrep/v1.31.0/` on first
run. It writes `~/.opengrep/semgrep.log`, a debug log holding each match's source text:
after the fixture run it held juice-shop's private key in full. No settings file and no
token are written (#1229's mechanism does not exist). It has no `--metrics` flag
(`unknown option '--metrics'`, rc 2). `-j` given twice is rc 2 ("option '-j' cannot be
repeated"). With network removed (`unshare -rn`), the four fixture files below give the
four expected findings, rc 0.

**Releases.** v1.31.0, 2026-10-15; v1.32.0, 2026-10-22 11:58 UTC. Assets per release:
`opengrep_manylinux_x86`, `opengrep_manylinux_aarch64`, `opengrep_musllinux_x86`,
`opengrep_musllinux_aarch64`, `opengrep_osx_x86`, `opengrep_osx_arm64`,
`opengrep_windows_x86.exe`, each binary with `.sig` and `.cert` (cosign), plus
`opengrep-core_*` archives. No checksum file is published.

**The fixture,** fetched by commit from
`https://raw.githubusercontent.com/juice-shop/juice-shop/<sha>/<path>`:

| File | sha256 |
|---|---|
| `routes/login.ts` | `a75800151ddeda7b18ad683cd3c75fecadf48d23b507c5e531426285a1feb67a` |
| `routes/search.ts` | `0c23e746dfe31ec29aa6477e076a0a4d55d27afd90446e668b1dc10b88416967` |
| `lib/insecurity.ts` | `cc8eb6a6bc249de6c2616706a27123842dbfafb8b967595365f671be5e9ca7f0` |
| `views/promotionVideo.pug` | `d9c4ab0b3a96c832fbde18346f900df727ab20cd0d4ce229e7a8ef3d0bd0c285` |

**Footprint.** 352 tracked files name semgrep: 52 in `scripts/`, 185 in `tests/`, the CI
workflows, `Dockerfile`, `versions.yaml`, packaging and 55 docs. The structural ones are
listed in B4 and B6. `jmo tools install` verifies no checksum (only the Dockerfile's
osv-scanner block does); no URL placeholder renders `x86`; `jmo-native` (Phase 4,
`5847d94b`) is Python, and no opengrep-format JMo rule exists in the tree.

**The MIT packs (measured 2026-10-29, `.199`).** Jimmy chose to measure and add them in
Phase 5. All three are MIT and not archived:

| Pack | Pin | Rules | `category: security` | opengrep `--test` | Taken |
|---|---|---|---|---|---|
| 0xdea/semgrep-rules `main` | `e0121ac19d9fa259a44f3a24d3e42c95719b17c7` (2026-10-18) | `rules/c` 49 (`[c, cpp]`), `rules/noisy` 1 | 50 of 50 | 48/49: `raptor-use-after-free` overflows opengrep 1.31.0's stack on its own test file | `rules/c` minus that one: **48** |
| elttam/semgrep-rules `main` | `244268562cc92d33f54b8a60a187df5520f91b26` (2026-08-03; pushed 2026-10-27) | `rules/` 29, `rules-audit/` 78 | 107 of 107 | `rules/` 28/28 (the join rule excluded) | `rules/` minus the join rule and `yaml/kubernetes`: **22** (java 16, go 3, yaml/github-actions 2, php 1) |
| dgryski/semgrep-go `master` | `db0227c03f4b3c4e71d900188d51db4c81d66932` (2024-11-17) | 66, all `go` | **0 of 66** (no `category` key) | no tests | none |

- elttam's one `mode: join` rule (`jsp-likely-xss`) does not load in opengrep 1.31.0
  ("missing languages"); every other rule of all three packs validates, 0 errors.
- elttam's six `yaml/kubernetes` rules anchor on different lines from the snapshot's
  same-named rules (on both projects' synthetic test manifests: `allow-privilege-escalation`
  147 elttam vs 62 snapshot lines, 0 shared), so one pod spec would report twice; the
  snapshot's 20 k8s rules plus checkov and trivy already cover manifests.
- `rules-audit/` is, by elttam's README, for "enumerating entrypoints, to augment manual
  source code review". Measured through opengrep `-j 4`: juice-shop 149 findings (111
  `express-app-router-handler`, 19 + 19 Prisma rules on Sequelize `where` calls, the same
  line under both rules); the TS application 6 (the same two Prisma rules, 3 lines each,
  0 real on review); the parity target 0. 0 real of 155.
- On the three JS/TS targets elttam `rules/`, 0xdea and dgryski give 0 findings; 0xdea and
  dgryski scan 0 files (language selection never loads them there).
- **Unmeasured:** precision on C, C++, Java and Go. No such code exists on `.199`. The
  rules cost nothing on the target archetype; whether they are precise is not known.
- The two packs taken: gitleaks 0, trufflehog 0, private-key lines 0; body-identical to
  a snapshot or `lgpl-cc` rule: 0. Four elttam k8s ids collide bare with the snapshot's,
  which namespacing resolves (and the k8s rules are not taken).

**The YAML 1.1 boolean trap (measured 2026-10-29).** `yaml.safe_load` resolves a bare
`on`, `off`, `yes` or `no` as a boolean, so a `join` rule's `on:` key became `true:` and
opengrep rejected the merged file. Across all 2,330 rules of the five sources, exactly one
rule parses differently under YAML 1.1 and 1.2 booleans (that join rule), so the 10-23
numbers stand. The dumper is safe: `yaml.safe_dump({"on": 1})` writes `'on': 1`.

## Program-plan and spec corrections (land in PR A, Task A1)

- Spec §2 decision 2 and §4.2 R3: no rewrite; the eight fire in opengrep once the merge
  keeps every rule. The fixture guards that they stay in the bundle.
- Spec §5: the merge lever is ~1.85× here; overlap with GitLab is by body as defined
  above, 50 rules; the counts table is the builder's `SOURCES.json`, not the 2026-09-12
  figures (`yaml` 69 → 39, `python` 266 → 275 with lgpl-cc, …); `generic/secrets/` is
  excluded; the JMo pack row is `jmo-native`.
- Program plan § Phase 5: "never vendored" applies to the source corpora, not to the
  merged bundle, which is committed; "the seven taint rules (R3) are rewritten" goes;
  acceptance "the fixture fires `tainted-sql-string` ×6" becomes the four fixture
  triples (two of the six are in the fixture's files, four in `data/static/codefixes/`);
  "peak < 600 MB" is on the parity target with language selection at `-j 4`, and
  juice-shop's 1.4–1.85 GB is recorded for Phase 7 by name.
- Spec §5, the MIT row: 0xdea `rules/c` 48 (C/C++) and elttam `rules/` 22 (Java 16, Go 3,
  GitHub Actions 2, PHP 1) are in; dgryski is excluded (none of its 66 rules carries
  `category`), as are elttam's `rules-audit/` (0 real of 155 measured) and its
  Kubernetes rules, 0xdea's `rules/noisy/`, the one `join` rule and the one rule that
  overflows opengrep's stack. Their precision on C, C++, Java and Go is unmeasured.
- Program plan, Phase summary: Phase 4's State "open" becomes "on `dev` and `main` as
  `d2baed26` `c56e201d` `4f253e24` `5847d94b` `63f2f0e9` `6881e0e4`".
- Program plan, After the tag: "and changes this count to 25" and the summary row's
  "becomes 25 in Phase 0" read as pending. Put both in the past tense ("took this count to
  25"), with today's 29 beside them.

## Decided from measurement (veto any in review)

1. **R3 needs no rule rewrite** (spec decision 2 withdrawn).
2. **`--no-rewrite-rule-ids` on every run.** No adapter strips a prefix.
3. **`generic/secrets/` is excluded.** Secrets are gitleaks' and trufflehog's class (spec §4.1);
   with it, the bundle cannot be committed past JMo's own secret scanning.
4. **The bundle is a generated, committed directory, `scripts/jmo_rules/`**, shipped as
   package data (the wheel only carries files under `scripts`). Its `SOURCES.json` pins
   each source and each file's sha256. Spec §5's "separable directory with a swap
   path" holds: replace the directory, keep the file names.
5. **Body duplicates: GitLab wins.** A snapshot rule whose body equals an `lgpl-cc` rule's
   is dropped (50 expected).
6. **One config file per language present, plus `generic`; `-j 4`, reserved.** All 25
   files cost the parity target 683 MB at `-j 4`, the selected ones 467 MB. TypeScript selects
   `javascript.yaml` too: opengrep runs `languages: [javascript]` rules on `.ts`
   (31 of 31 hits on a TS app were JavaScript rules, 2026-10-22). Phase 7 owns tuning.
7. **JSON output; `semgrep_adapter.py` becomes `opengrep_adapter.py`.** SARIF has no
   `paths.scanned`, which the zero-files accounting reads (#1231).
8. **The JMo pack is `jmo-native`.** The bundle carries no JMo YAML.
9. **The fixture is four juice-shop files fetched by commit and sha256 at test time**
   into a gitignored directory; the guard asserts `(rule, file, line)`, never columns.
10. **opengrep's log goes into the scan's dot-prefixed scratch**, never `~/.opengrep`;
    its extraction cache stays where it is (moving it costs 246 MB per scan).
11. **The pin is the newest release at least seven days old when PR B is cut**
    (v1.31.0 today; v1.32.0 qualifies from 2026-10-29 11:58 UTC). Downloaded without a
    checksum, as zizmor is: none is published.
12. **`semgrep` joins `REMOVED_TOOLS`.** A config still carrying `per_tool.semgrep` gets
    one warning naming `per_tool.opengrep`. "bandit's config" in the program plan is
    already gone (Phase 2); the `bandit` dev linter on JMo's own code stays.
13. **The MIT packs: 0xdea `rules/c` (48) and elttam `rules/` (22) are in** (Jimmy,
    2026-10-29, on the measurement above). Ids are namespaced by path like every other
    source's, prefixed `0xdea.` and `elttam.`; each rule goes to the bundle file named by
    its top directory under the pack's rules root (`c`, `java`, `go`, `php`, `yaml`), so
    the file count stays 25.
14. **YAML 1.2 booleans.** The builder loads with a `SafeLoader` whose boolean resolver
    matches only `true`/`false` in their three casings; a bare `on:` stays the string
    `on`.
15. **Exclusions are data, each with its reason, all in `SOURCES.json`:** directories
    (`generic/secrets/`; elttam `yaml/kubernetes`; 0xdea `noisy`), modes (`join`: opengrep
    1.31.0 does not load it), and single ids (0xdea `raptor-use-after-free`: stack overflow
    in opengrep 1.31.0 on its own test). The packs' unused trees are never read, and
    `docs/RULE_BUNDLE.md` says why: all of dgryski is never fetched, and elttam's
    `rules-audit/` is fetched with the pack and never read.
16. **Body-duplicate precedence: `lgpl-cc`, then the snapshot, then the MIT packs.** A
    rule whose body equals a higher source's is dropped (50 expected, all snapshot rules;
    the packs have 0).
17. **Proprietary rules leave the bundle (R9).** The builder drops any rule whose
    `metadata.license` contains "proprietary" (case-insensitive), from any source, and
    records it in `SOURCES.json` as a `license` exclusion whose reason quotes the license
    text. One rule measured: the snapshot's Java `no-direct-response-writer`
    (`proprietary license - copyright © Semgrep, Inc.`). Of the other 1,420, 1,311 carry no
    `metadata.license` and 109 say Commons Clause + LGPL-2.1 (measured). So 1,421 becomes
    1,420. The match is a deliberately broad substring. Guards:
    `test_a_proprietary_rule_is_dropped_with_its_reason` (builder) and
    `test_no_rule_declares_a_proprietary_license` (the committed bundle).
18. **The wheel ships the notices (R10).** `pyproject.toml`'s `license-files` carries
    `THIRD_PARTY_LICENSES.md`: the wheel ships the rules, so it ships their notices.
    Guarded by `test_the_wheel_ships_the_third_party_notices`.
19. **Each generated file carries its license notice (R15).** LGPL-2.1 §1 asks that notices
    referring to the license be kept, and §2(b) that a modified file carry a prominent
    notice of the change and its date. The builder writes a fixed comment header at the
    top of each `.yaml`: that the file is generated by `scripts/dev/build_rule_bundle.py`
    and not to be edited by hand; the sources that gave THAT file rules, each with its pin
    and its license as `THIRD_PARTY_LICENSES.md` names it; what the builder changed (kept
    only `category: security` rules, namespaced ids by path, dropped body duplicates and
    excluded rules, merged them into one file per language); the date, `BUNDLE_DATE =
    "2026-10-29"` in the builder, bumped with the pins; and a pointer to
    `THIRD_PARTY_LICENSES.md`. There is no build-time timestamp, so `--check` still holds.
    The rule counts do not change (25 files, 1,420 rules); the manifest's sha256s do.
    Guards: `test_each_file_names_the_sources_that_gave_it_rules_with_pin_and_license`
    (builder) and `test_every_file_opens_with_the_license_header` (the committed bundle).

## PR sequence

| PR | Tasks | Closes |
|---|---|---|
| A — the bundle | A1–A5 | none |
| B — opengrep replaces semgrep | B1–B8 | #1228, #1229 |

PR A ships no code a scan runs, so it can merge before PR B and be reviewed on its own.

## Review Focus

1. A TypeScript-only repository gets `javascript.yaml` and `typescript.yaml` (B2).
2. A repository with no file any bundle language reads is `skipped:<reason>`, not
   `ran` with 0 findings (B3).
3. A file opengrep times out on or cannot parse leaves the other files' findings in
   the report and is named in the row's diagnostics (B3).
4. A v1 config's `per_tool.semgrep.configs` (a user's own packs) is not dropped
   silently (B6).
5. The same scan run from another working directory, or on a target whose path holds
   dots, gives identical rule ids (B7).

---

## Task A1: Plan text and corrections

**Files:**
- Modify: `docs/superpowers/plans/2026-09-12-v2.0.0-program.md` (§ Phase 5)
- Modify: `docs/superpowers/specs/2026-09-12-v2.0.0-program-design.md` (§2 row 2, §4.2 R3, §5, §12 P5)
- Create: this file, as committed

- [ ] **Step 1:** Apply the corrections section above, one edit per bullet. Cite
  commits by sha in prose; a `#NNNN` the plan does not roster reddens `phase_audit`.
- [ ] **Step 1b:** Roster #1501 (filed 2026-10-29: `tests/unit/test_empty_parameter_set_fails.py`'s
  child pytest inherits `PYTEST_ADDOPTS`, so a `--basetemp` given that way fails its 2
  tests) in Phase 9, beside #1475's dev-tooling paragraph: the roster line and its
  `**N issues:**` count (32 → 33), the summary-table row (32 → 33) and `before tag`
  (166 → 167), and one sentence of prose. Add `# TODO(issue-#1501): drop PYTEST_ADDOPTS from the child's env.`
  above `_run_pytest`'s `subprocess.run`. No other change to that test.
- [ ] **Step 2:** `python3 scripts/dev/phase_audit.py derive | tail -2` → "all four
  plan checksums agree"; `verify` → `unclaimed: 0`.
- [ ] **Step 3:** Commit `docs: Phase 5 task plan, and what its measurement corrected`.

## Task A2: The bundle builder

**Files:**
- Create: `scripts/dev/build_rule_bundle.py`
- Create: `tests/unit/test_build_rule_bundle.py`
- Create: `tests/fixtures/rule_bundle/sources/` (a tiny synthetic tree: two sources,
  a few rules each, written for the tests; no real rule corpus)

**Interfaces:**
- Produces: `SOURCES: dict[str, Source]` where `Source` carries `url`, `sha256`,
  `rules_root`, the file glob, the id prefix, and the exclusions of D15 (directories,
  modes and ids, each with its reason). Four tarballs, in D16's precedence order:
  GitLab `lgpl-cc` (`https://gitlab.com/gitlab-org/security-products/sast-rules/-/archive/v2.10.1/…tar.gz`,
  `rules/lgpl-cc`, `rule-*.yml`, prefix `lgpl-cc`), opengrep-rules
  (`https://github.com/opengrep/opengrep-rules/archive/f1d2b562b414783763fd02a6ed2736eaed622efa.tar.gz`,
  the repository root, no prefix), 0xdea
  (`https://github.com/0xdea/semgrep-rules/archive/e0121ac19d9fa259a44f3a24d3e42c95719b17c7.tar.gz`,
  `rules/`, prefix `0xdea`) and elttam
  (`https://github.com/elttam/semgrep-rules/archive/244268562cc92d33f54b8a60a187df5520f91b26.tar.gz`,
  `rules/`, prefix `elttam`). Record each sha256 on first fetch.
- Produces: `rule_body(rule: dict) -> str`, `collect(root: Path, kind: str) -> dict[str, list[dict]]`
  (language → rules), `build(trees: dict[str, Path], out_dir: Path) -> dict` (the manifest).
- Produces: CLI `python scripts/dev/build_rule_bundle.py --out scripts/jmo_rules [--cache ~/.cache/jmo-rule-sources] [--check]`;
  `--check` builds into a temporary directory and exits 1 naming any file that differs.

- [ ] **Step 1: Failing tests**, against the synthetic tree:
  - `test_only_security_rules_are_kept`: a `category: correctness` rule is absent.
  - `test_test_targets_and_non_rule_yaml_are_skipped`: `x.test.yaml` and a YAML with no
    `rules` list contribute nothing; GitLab files are read only as `rule-*.yml`.
  - `test_generic_secrets_is_excluded`.
  - `test_ids_are_namespaced_by_path`: `javascript/express/security/a.yaml` rule `r`
    becomes `javascript.express.security.a.r`; GitLab's become `lgpl-cc.<lang>.….<id>`.
  - `test_gitlab_wins_a_body_duplicate`: same body, different id and message → only the
    GitLab rule remains; a different `patterns` keeps both.
  - `test_a_colliding_id_fails_the_build` (`ValueError` naming the id).
  - `test_a_bare_on_key_stays_a_string` (D14): a rule with `on:` keeps the key `"on"`
    through `collect` and the written file.
  - `test_join_rules_are_dropped_with_their_reason`, `test_an_excluded_id_is_dropped_with_its_reason`
    and `test_an_excluded_directory_is_dropped_with_its_reason` (D15): each shows up in
    the manifest's exclusions, never in a bundle file.
  - `test_precedence_follows_the_source_order` (D16): a body shared by three sources
    keeps only the highest source's rule.
  - `test_two_builds_are_byte_identical` and `test_files_are_lf`.
  - `test_the_manifest_records_each_file`: per file, sha256 and rule count; per source,
    url, sha256 and commit or tag; the exclusions with their reasons.
- [ ] **Step 2:** Run them; all fail on the missing module.
- [ ] **Step 3:** Implement. Rules within a file sorted by id; `yaml.safe_dump(…, sort_keys=False, allow_unicode=True)`;
  `write_bytes`. Fetch with `urllib.request` (no shell), verify sha256 before extracting,
  extract with `tarfile`'s `data` filter. Each language file's name is the source
  directory name (`javascript.yaml`, …); GitLab's language directories merge into the
  same files.
- [ ] **Step 4:** Tests pass. Commit `feat: a builder for the offline opengrep rule bundle`.

## Task A3: The committed bundle, packaged and guarded

**Files:**
- Create: `scripts/jmo_rules/*.yaml`, `scripts/jmo_rules/SOURCES.json` (generated)
- Modify: `pyproject.toml` `[tool.setuptools.package-data]` (`jmo_rules/*.yaml`, `jmo_rules/SOURCES.json`)
- Create: `tests/unit/test_jmo_rules_bundle.py`
- Modify: `.github/workflows/ci.yml` (a path-filtered `rule-bundle-reproducible` job)

- [ ] **Step 1:** Build: `python scripts/dev/build_rule_bundle.py --out scripts/jmo_rules`.
  Expect 25 files and 1,420 rules (1,401 − 50 + 48 + 22 − 1; one proprietary-licensed
  rule excluded, R9). A different number is a finding to explain in the PR, not to
  absorb.
- [ ] **Step 2: Offline tests** in `test_jmo_rules_bundle.py`:
  - `test_every_file_matches_its_manifest_entry` (sha256 and count).
  - `test_every_rule_is_security`, `test_ids_are_unique_across_the_bundle`.
  - `test_no_generic_secrets_rule_ships`.
  - `test_no_rule_declares_a_proprietary_license` (D17).
  - `test_the_wheel_ships_the_third_party_notices` (D18): `license-files` names
    `THIRD_PARTY_LICENSES.md`, which exists at the repository root.
  - `test_every_file_opens_with_the_license_header` (D19): the builder's header on every
    committed file, naming the sources its rule ids come from, each with its pin and a
    license `THIRD_PARTY_LICENSES.md` names.
  - `test_the_wheel_carries_the_bundle`: extend the test that guards
    `dashboard/dist/index.html`'s package-data entry (`grep -rn "dashboard/dist/index.html" tests/`).
  - `@requires_tools test_every_file_validates`: `opengrep scan --validate --config <f>`
    → rc 0 and "0 configuration error(s)" for each file.
- [ ] **Step 3:** The CI job runs `--check` when `scripts/jmo_rules/**` or the builder
  changes (`dorny/paths-filter`, as `tool-contract-tests` does); a hand-edited rule
  fails it. Mutation-test: edit one rule in a byte backup, run `--check`, restore.
- [ ] **Step 4:** `pre-commit run --files scripts/jmo_rules/*` passes (secret hooks
  included), and gitleaks and trufflehog over the directory report 0, as measured.
- [ ] **Step 5:** Commit `feat: the opengrep rule bundle, 25 languages, security rules only`.

## Task A4: Licenses and the swap path

**Files:**
- Create: `THIRD_PARTY_LICENSES.md` (each source's notice and license text, copied from
  the fetched tarballs: opengrep-rules LGPL-2.1 + Commons Clause, GitLab `lgpl-cc`, and
  the MIT notices of 0xdea and elttam)
- Create: `docs/RULE_BUNDLE.md`: what is in it (from `SOURCES.json`), what is excluded
  and why (`generic/secrets/`, `rules/lgpl` → #1465, `rules/gitlab`, Trail of Bits, the
  Semgrep registry, and D15's pack exclusions: elttam `rules-audit/` and its Kubernetes
  rules, all of dgryski, 0xdea `noisy`, the `join` rule, `raptor-use-after-free`), that the
  MIT packs' precision on C, C++, Java and Go is unmeasured, the freeze (R4: JavaScript
  and TypeScript rules are the snapshot's),
  the rebuild command, and the swap path (replace `scripts/jmo_rules/`, keep the file
  names, run the fixture guard and `--validate`).
- Modify: `docs/KNOWN_LIMITATIONS.md` (R4's freeze, one entry). In the same file, the
  "Defects shipping in v1.1.0" section is a release behind: v1.1.1 is the latest release,
  and #1156, which it still lists, closed on 2026-09-09, before v1.1.1's tag
  (2026-09-11). Retitle it "Defects shipping in v1.1.1", say v1.1.1 in its first
  paragraph, drop the #1156 bullet, and replace "What remains is the after-tag set" with
  "What remains is scheduled in the v2.0.0 program, or after its tag". The #1082 and
  #1007 bullets stay.

- [ ] **Step 1:** Write them; `python scripts/dev/check_doc_links.py` green.
- [ ] **Step 2:** Commit `docs: third-party rule licenses and the rule bundle's swap path`.

## Task A5: Gates, then PR A

- [ ] **Step 1:** Suite in three parts; diff failing ID sets against `origin/dev`'s.
- [ ] **Step 2: Windows, on the laptop (`.218`):** clone the branch; Defender leaves
  `scripts/jmo_rules/` intact after 5 minutes (file count and sha256s equal
  `SOURCES.json`). The quarantine measured in Phase 4 was of test files, never rule YAML.
  If the laptop is unavailable, stop and ask.
- [ ] **Step 3:** Push, open PR A. Body: the numbers from A3 and A5, and what CI cannot
  provide (the Defender check).

## Task B1: The opengrep binary

**Files:**
- Modify: `versions.yaml` (`binary_tools.opengrep`: version, `github_repo: opengrep/opengrep`; remove `python_tools.semgrep` and its `critical_tools` entry)
- Modify: `scripts/core/install_config.py` (`BINARY_URLS["opengrep"]`; remove `ISOLATED_TOOLS["semgrep"]`)
- Modify: `scripts/cli/tool_installer.py:1470-1484` (placeholder `arch_x86`)
- Modify: `Dockerfile` (builder `RUN OPENGREP_VERSION=…`, `COPY --from=builder`; remove the semgrep pip line and its verify)
- Modify: `.github/workflows/ci.yml`, `scheduled.yml` (`OPENGREP_VERSION` env, curl install, `--version` echo, replacing every `pip install semgrep` and `brew install semgrep`; `maintenance.yml:558` drops semgrep)
- Test: `tests/unit/test_opengrep_wiring.py` (new), `tests/unit/test_install_config.py:188`

**Interfaces:**
- Produces: `{arch_x86}`: `"x86"` on x86_64/AMD64, otherwise the machine name as the
  platform reports it (`aarch64` on Linux, `arm64` on macOS).
- Produces: `BINARY_URLS["opengrep"] = {"windows": …/v{version}/opengrep_windows_x86.exe, "macos": …/opengrep_osx_{arch_x86}, "default": …/opengrep_manylinux_{arch_x86}}`.

- [ ] **Step 1: Failing test** `test_the_url_names_a_real_asset`, parametrized like
  zizmor's (`tests/unit/test_zizmor_wiring.py`): linux x86_64 → `opengrep_manylinux_x86`,
  linux aarch64 → `opengrep_manylinux_aarch64`, macOS x86_64 → `opengrep_osx_x86`,
  macOS arm64 → `opengrep_osx_arm64`, Windows AMD64 and ARM64 →
  `opengrep_windows_x86.exe`; each asset is in `RELEASE_ASSETS_1_31_0` (the list above).
  Plus `test_install_config.py`: `set(ISOLATED_TOOLS) == {"checkov"}`.
- [ ] **Step 2:** Implement; `update_versions.py --sync`; `--sync --dry-run` rc 0.
- [ ] **Step 3: Measure the image's first run.** In the built image, as the `jmo` user,
  time the first `opengrep --version`. If it takes over 5 s, run it once at build time
  as that user and record the image's size change in the PR.
- [ ] **Step 4:** Commit `feat!: opengrep's binary replaces semgrep's pip install`.

## Task B2: Language selection

**Files:**
- Create: `scripts/core/rule_bundle.py`
- Test: `tests/unit/test_rule_bundle.py`

**Interfaces:**
- Produces: `BUNDLE_DIR: Path` (`scripts/jmo_rules`, resolved from `__file__`),
  `LANGUAGE_PATTERNS: dict[str, tuple[str, ...]]` (bundle file stem → the file patterns
  that select it, e.g. `"typescript": ("*.ts", "*.tsx")`, `"dockerfile": ("Dockerfile", "Dockerfile.*", "*.Dockerfile")`,
  `"terraform": ("*.tf", "*.hcl")`; `"c"` includes the C++ extensions `*.cpp`, `*.cc`,
  `*.cxx`, `*.hpp`, `*.hh`, because 0xdea's rules are `[c, cpp]` and live in `c.yaml`), and
  `select_configs(files: Iterable[Path]) -> list[Path]` (sorted; always `generic.yaml`).

- [ ] **Step 1: Failing tests:** `test_typescript_selects_javascript_too`;
  `test_generic_is_always_selected`; `test_a_python_repo_gets_python_and_generic_only`;
  `test_every_bundle_file_has_patterns` (the keys equal the stems in `BUNDLE_DIR`, so a
  rebuilt bundle with a new language fails here); `test_no_files_selects_nothing_but_generic`.
- [ ] **Step 2:** Implement with `fnmatch` on `Path.name`, case-sensitive as
  `collect_files` is.
- [ ] **Step 3:** Commit `feat: choose the rule files a repository's languages need`.

## Task B3: The descriptor row

**Files:**
- Modify: `scripts/core/tool_descriptors.py:766-787` (`_semgrep_repo` → `_opengrep_repo`),
  `:630-637` (`_semgrep_scanned` → `_opengrep_scanned`), `:1674-1707` (the row),
  `:2033-2053` (`REMOVED_TOOLS` gains `"semgrep"`)
- Test: `tests/unit/test_opengrep_wiring.py`, `tests/unit/test_tool_descriptors.py`
  (`:335` count 17 → 18), `tests/unit/test_tool_registry.py:26`

**Interfaces:**
- Consumes: `select_configs` (B2); the walk (`file_patterns` → `collect_files` → `ctx.files`).
- Produces: the command
  `(binary, "scan", *("--config", p for p in configs), "--no-rewrite-rule-ids", "--json", "--output", out, "--disable-version-check", "-j", "4", *exclusion_args, *flags, target)`,
  where `configs` is `per_tool.opengrep.configs` when set, else `select_configs(ctx.files)`.
  `file_patterns` is the union of `LANGUAGE_PATTERNS`; an empty walk is
  `skipped:<no_files_reason>`, a new `Reason` member in `scripts/core/scan_timings.py`
  (zizmor's `c56e201d` added its own the same way).
- Reserved: semgrep's OUTPUT and EXIT_CODE sets, plus `PASSED`: `-j`, `--jobs`,
  `--rewrite-rule-ids`, `--no-rewrite-rule-ids`, `--enable-version-check`,
  `--disable-version-check`.

- [ ] **Step 1: Failing tests:** `test_the_command_line` (exact tuple, a TS repo);
  `test_user_configs_replace_the_bundle`; `test_a_repo_with_no_bundle_language_is_skipped_and_says_why`;
  `test_a_user_jobs_flag_is_refused_with_its_reason` (rc 2 measured: a second `-j`);
  `test_errors_keep_the_other_files_findings` (an output with one `Timeout` error and
  two results → two findings, the timeout named by `DIAGNOSTIC_EXTRACTORS`).
- [ ] **Step 2:** Implement. `ok_return_codes` and `timeout_floor` start from semgrep's
  `(0, 1, 2)` and 900; measure opengrep's rc on a run with errors and on a bad config,
  and record both in a comment.
- [ ] **Step 3:** Commit `feat!: opengrep runs the bundle's files for the languages present`.

## Task B4: The adapter, and every table keyed by tool name

**Files:**
- Rename: `scripts/core/adapters/semgrep_adapter.py` → `opengrep_adapter.py` (`git mv`;
  tool name and plugin metadata `"opengrep"`)
- Modify: `common_finding.py:128-132` (`TOOL_SEVERITY_MAPPINGS`), `compliance_mapper.py:250-259, 910`,
  `compliance_frameworks.py:241-250`, `rule_equivalence.py:245-295`, `tool_diagnostics.py:118`,
  `validators/scan_validator.py:41, 2022`, `reporters/basic_reporter.py:265`,
  `attestation/tamper_detector.py:520`, `cli/wizard_flows/ui_helpers.py:43`,
  `cli/tool_manager.py:139-146`, `core/tool_utils.py:27`
- Replace: `tests/fixtures/golden/semgrep/v1.146.0/` with `tests/fixtures/golden/opengrep/v1.31.0/`
  (the fixture run's JSON with paths made relative and `extra.lines` and
  `extra.dataflow_trace` removed from every result: the taint rule's source is the
  string literal that holds juice-shop's private key; the secret hooks must pass on it)
- Tests: the adapter tests the footprint names (`test_adapter_error_paths`,
  `_fuzzing`, `_malformed`, `_golden`, `test_builtin_policy_decisions`,
  `test_policy_field_contract`, `test_scan_validator`, `test_rule_equivalence*`)

- [ ] **Step 1:** `rule_equivalence`: the `generic.secrets.*` rows go (D3: those rules no
  longer ship); `python.lang.security.audit.hardcoded-password` stays only if
  `grep -c` finds that id in `scripts/jmo_rules/python.yaml`. The compliance globs keep
  their registry shapes: path-namespaced ids reproduced 1,022 of 1,074 registry ids.
- [ ] **Step 2: Failing test** `test_the_golden_document`: 4 findings, tool
  `{"name": "opengrep", "version": "1.31.0"}`, severities from `extra.severity`, CWE
  from `extra.metadata`.
- [ ] **Step 3:** Implement the rename and the rekeying; run the adapter and table tests.
- [ ] **Step 4:** Commit `feat!: the opengrep adapter, and the tables keyed by its name`.

## Task B5: The log stays out of the user's home

**Files:** `scripts/core/tool_descriptors.py` (`_opengrep_repo`'s `env`), `tests/unit/test_opengrep_wiring.py`

- [ ] **Step 1: Measure** which variable moves `~/.opengrep/semgrep.log`: try
  `SEMGREP_LOG_FILE`, `OPENGREP_LOG_FILE`, `SEMGREP_USER_DATA_FOLDER`,
  `OPENGREP_USER_DATA_FOLDER`, then `strings` on the binary. Record what worked.
- [ ] **Step 2: Failing `@requires_tools` test**
  `test_a_scan_leaves_no_log_in_the_home_directory`: `~/.opengrep/semgrep.log`'s mtime
  and size are unchanged by a fixture scan, and the scan's
  `<out_dir>/.opengrep/` holds the log (scratch is dot-prefixed, as every tool's is).
- [ ] **Step 3:** Set it in the Invocation's `env`. The extraction cache
  (`~/.cache/opengrep/`) is left alone (D10).
- [ ] **Step 4:** Commit `fix: opengrep's debug log, which holds matched code, stays in the scan`.

## Task B6: semgrep leaves

**Files:** the footprint's remaining list, by group:
- Config: `jmo.yml:25-30` (`per_tool.semgrep`, and the cache comment #1228 describes),
  `.devcontainer/devcontainer.json:5`
- Scripts: `scripts/core/check_and_install_tools.sh`, `check_tools.sh`,
  `generate_comparison_report.sh`, `scripts/dev/ci-local.sh:71-75`, `install_tools.sh`,
  `verify-env.sh`, `generate_golden.py:104-117,200`, `tool_runner.py:445-447` (the
  semgrep rationale), `tool_commands.py:1192,1232`, `jmo.py` help text
- Packaging: `packaging/scripts/*`, `packaging/homebrew/jmo-security.rb`, the winget
  manifests, `packaging/WINDOWS_COMPATIBILITY.md`
- semgrep-secrets remnants: `tool_diagnostics.py:35`, `.gitignore:209`
- Tests: `conftest.py` spawn guard (`:571` justification, `:831-845` `semgrep_argv_uses_config_auto`),
  `test_scanner_spawn_guard.py`, `test_spawn_guard_scope.py`, `test_per_tool_flag_policy.py`,
  `test_cli_per_tool_config.py:372-610`, `test_repository_scanner.py`, `test_scan_utils.py`,
  `test_tool_contracts.py:131-145`, `test_tool_smoke.py:135-148`, `test_real_tool_scans.py`,
  `test_docker_workflows.py`, the installer tests, `test_version_validation_gate.py:138-144`
  (index checkov instead), `.test_durations`
- Docs: `UPGRADE.md` (breaking: semgrep → opengrep, `per_tool.semgrep.configs` →
  `per_tool.opengrep.configs`, every SAST finding id changes), `CHANGELOG.md`,
  `docs/TOOLS.md`, `docs/USER_GUIDE.md:1615-1623`, `docs/SCAN_OPTIMIZATION.md:154`.
  The tool-count sweep across the other docs is Phase 9's. Also remove the v2.0.0 status
  lines from `docs/RULE_BUNDLE.md` and the KNOWN_LIMITATIONS bundle entry (R12), which
  say the scanner is still Semgrep until v2.0.0 ships.

- [ ] **Step 1: Failing test** `test_a_v1_semgrep_config_is_named_not_dropped`: a config
  with `per_tool.semgrep.configs: [p/python]` produces one warning naming
  `per_tool.opengrep.configs`; `jmo scan --tools semgrep` says "removed in v2.0.0".
- [ ] **Step 2:** Implement; work through the list; `git grep -in semgrep -- scripts .github Dockerfile versions.yaml jmo.yml packaging`
  leaves only `REMOVED_TOOLS`, the warning, `version_history`, and comments that say
  what replaced it.
- [ ] **Step 3:** Commit `feat!: semgrep leaves`, body `Closes #1228` and `Closes #1229`
  (both describe behaviour of a tool JMo no longer runs; B5 covers #1229's class).

## Task B7: The fixture guard and the no-network proof

**Files:**
- Create: `scripts/dev/fetch_rule_fixture.py` (the four files by commit, sha256-checked,
  into `tests/fixtures/rule_bundle/juice-shop/`, which `.gitignore` lists)
- Create: `tests/integration/test_rule_bundle_fixture.py` (`requires_tools`)
- Modify: `ci.yml` and `scheduled.yml` `tool-contract-tests` (fetch step; the new file
  and `test_opengrep_wiring.py` in the path filter and the pytest list)

- [ ] **Step 1: Failing tests**, through `tool_loop.run_tools` as
  `tests/unit/test_osv_scanner_wiring.py::_real_scan` does:
  - `test_the_four_fixture_findings`: exactly these `(rule id suffix, file, line)` are
    present: `tainted-sql-string` `login.ts` 34, `tainted-sql-string` `search.ts` 23,
    `hardcoded-jwt-secret` `insecurity.ts` 56, `template-explicit-unescape`
    `promotionVideo.pug` 79. Skips, naming the fetch script, when the files are absent.
  - `test_ids_do_not_depend_on_the_working_directory`: the same scan from `/` and from
    the target's root gives identical rule ids; the target's path contains a dot.
  - `test_a_scan_makes_no_network_call`: proxies at `127.0.0.1:9`, `NO_PROXY` empty;
    rc 0, the four findings, no connection error in stderr.
- [ ] **Step 2:** Implement the fetch script; CI runs it before the job's pytest.
  `docs/RULE_BUNDLE.md` swap step 4 names the guard's test path
  (`tests/integration/test_rule_bundle_fixture.py`); until this step it names none.
- [ ] **Step 3:** Commit `test: the juice-shop fixture keeps the R3 rules firing`.

## Task B8: Gates, then PR B

- [ ] **Step 1:** Suite in three parts; ID-set diff against `origin/dev`.
- [ ] **Step 2: Through `jmo scan`** on `git archive` exports, `--tools opengrep`:
  the parity target's peak ≤ 600 MB (record it; 467 MB measured for its 8 files at
  `-j 4`); the TS application's opengrep findings whose rule is not `category: security`
  = 0; juice-shop's peak recorded for Phase 7.
- [ ] **Step 3: No network, proven:** `unshare -rn` around the same `jmo scan` gives the
  same finding set as the networked run.
- [ ] **Step 4: Windows (`.218`):** `jmo tools install opengrep` fetches
  `opengrep_windows_x86.exe`; the fixture scan gives the four triples; `--config` with a
  drive-letter path works. Read the `windows-2022` job log.
- [ ] **Step 5:** Push, open PR B; body carries the numbers and what CI cannot provide
  (Steps 2–4). Read `docker-smoke`'s log.

## Acceptance (Phase 5)

- `scripts/jmo_rules/`: 25 files (or the builder's recorded number, explained), every
  rule `category: security`, 0 gitleaks / 0 trufflehog / 0 private-key lines, 25/25
  validate, `--check` reproduces it.
- The four fixture triples in `tool-contract-tests`, on Linux and on the laptop.
- the parity target through `jmo scan`: opengrep peak ≤ 600 MB at `-j 4`; no network
  call (`unshare -rn` equality).
- No match text written under the user's home by a scan.
- `THIRD_PARTY_LICENSES.md` and `docs/RULE_BUNDLE.md` exist; `check_doc_links.py` green.
- #1228 and #1229 closed by PR B's commit; `jmo scan --tools semgrep` names the removal.

## Decided by Jimmy (2026-10-29)

1. **The MIT packs:** measured and added in Phase 5, on the terms of D13 and D15.
2. **Signature checks for binary downloads:** opengrep joins #1374's scope (Phase 8),
   not an opengrep-only mechanism. opengrep publishes cosign `.sig`/`.cert` and no
   checksums; `jmo tools install` verifies nothing for any tool today.
3. **`-j` is fixed at 4,** and Phase 7's scheduler owns tuning it. juice-shop needs 1.4 GB
   at `-j 4`; only `-j 1` fits 800 MB, and it loses findings to timeouts.

## Unresolved (Jimmy)

1. **Reporting upstream** that opengrep's debug log records matched source text.
   Recommendation: after B5 shows which variable moves it.
