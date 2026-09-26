# Phase 3 — Descriptor table, single exclusion list, honest accounting: task plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** every scanner's tool blocks become one declarative table. Every requested
tool lands in exactly one of **ran / skipped:\<reason\> / failed:\<reason\>**, with
its duration, in `scan-timings.json` and in `history.db`. One exclusion list is
rendered in every tool's own grammar. A scan that examined nothing is `failed`. And
when `.git` exists, secrets are also read from history: `trufflehog git` and `gitleaks
git`, with gitleaks wired into the matrix here (12 → 13). It closes twelve issues: the
nine rostered (#722 #1073 #1227 #1231 #1235 #1237 #1277 #1279 #1283), two filed
with PR A: the wizard issue (#1298) and the tsv issue (#1299),
which PR T closes by making `jmo scan --tsv` real, and one filed with PR T: #1303, two
repositories of one folder name sharing a results folder, which PR B closes.

**Architecture:** a `ToolDescriptor` per tool (target types, trigger predicate, one or
more invocations, exclusion style, cost class, version probe, return codes, output
shape, optional scanned-count reader), in `scripts/core/tool_descriptors.py`. The six
scan jobs iterate the descriptors that apply to their target type instead of
hand-written `if "<tool>" in tools:` blocks. A shared `AccountingRecord` builder
produces one row per requested tool. `scan-timings.json` moves to schema v3 (rows for
every tool, not only those that ran), and a new `scan_tool_runs` table persists the
rows per scan.

**Tech Stack:** Python 3.12, pytest (+xdist), SQLite, trufflehog 3.97.1, gitleaks 8.30.1
(new), GitHub Actions, Docker (WSL only on this machine).

**Spec:** [2026-09-12-v2.0.0-program-design.md](../specs/2026-09-12-v2.0.0-program-design.md)
§4.3 (G1, G2), §6 row 3; program plan
[2026-09-12-v2.0.0-program.md](2026-09-12-v2.0.0-program.md) § Phase 3.

## Global Constraints

Copied from the program plan; every task's requirements include these.

- **Backward compatibility is NOT a constraint.** No users. `scan-timings.json` v2
  readers, the `__not_attempted__` status key and the unrouted warning's wording change
  without a shim.
- **One formatter:** `ruff format`. `make` is not on PATH: run `pre-commit run --all-files`.
- **No `shell=True`.** Every `subprocess.run` passes `timeout=`.
- **Conventional commits, and no AI-attribution markers of any kind** (no `Co-Authored-By`,
  no "Generated with", no `Claude-Session:`), in commits and PR bodies.
- **Commit only when Jimmy says.** Never to `dev`; PR into it, squash.
- **Closing keywords go in an individual COMMIT message.** A PR body into `dev` is inert.
- **Gates are numbers through `jmo scan` / `jmo report`, never a bare binary.** Every
  spawned `jmo scan` / `jmo ci` gets `--history-db <tmp>`: a gate scan writes the live
  `.jmo/history.db` otherwise.
- **Check line endings over the whole diff:** `python scripts/dev/check_eol_flips.py
  --base origin/dev` (after `git add` of new files). Scripts write with `write_bytes`.
- **Run local suites from Git Bash with `PYTHONUTF8` unset**, on `.venv/Scripts/python.exe`
  (a PowerShell-launched run produced 31 false failures). Bounded:
  `JMO_THREADS=2 .venv/Scripts/python.exe -m pytest tests/ -n 8 -q -m "not smoke and not requires_tools and not docker"`.
- **Diff failing-test ID sets, never counts. Read the `windows-2022` job log, never its
  tick.** Baseline at `27900a32`: **8685 passed / 90 skipped / 181 deselected**.
- **Mutation-test every guard.** Restore from a file backup, never `git checkout --`.
- **Never edit tool versions in `Dockerfile` by hand**: `versions.yaml`, then
  `python3 scripts/dev/update_versions.py --sync`.
- **Nothing about a private repository's secrets goes into this public repository** —
  not in code, tests, plans, issues or PR bodies. Measure on them; publish only
  timings and counts, as below.
- `--plan` goes **before** the `phase_audit.py` subcommand. Do not touch
  `.jmo/history.db` or its snapshots, `dev-only/`, or the two stray merged branches.

## Decisions taken 2026-09-24 (Jimmy)

| # | Question | Decision |
|---|---|---|
| 0 | PR 1297 open at session start | Merged first (`27900a32`); dev CI green, `windows-2022` 8685 / 90 / 181. This branch is cut from it. |
| 1 | How far the conversion goes | **All 18 blocks**, in all six scan jobs, not only the repository scanner's 11. |
| 2 | G1 needs `gitleaks git`; gitleaks is Phase 4's | **gitleaks is pulled into Phase 3**: `versions.yaml`, installer, `Dockerfile`, descriptor. `TOOL_MATRIX` 12 → 13. Phase 4 keeps zizmor, osv-scanner and the native pack. |
| 3 | Where #722's per-tool record persists | **A new table**, `scan_tool_runs`, not a JSON blob in `scan_metadata`. |
| 4 | Comma-joined and unknown tool names | **Split commas; reject unknowns.** `--tools a,b` and `a b` both work, in `jmo.yml` `tools:` too. An unknown name is a usage error (exit 2) naming it. The 16 tools the cut removed get "removed in v2.0.0". |
| 5 | #1283's scope, once the host misread proved to be a probe bug | **Pattern and probe.** The `(?<!\.)` lookbehind, no default-pattern fallback for zap, and the zap probe runs with `cwd` = its install directory. |
| 6 | The wizard's tsv mode, found to emit a flag `jmo scan` never had | **Make it real now**: `jmo scan --tsv FILE --dest DIR` clones, then scans the clones. Not removed, not deferred. |
| 7 | Where tsv lands | **Its own PR (PR T), after A and before B.** A new target path with network and security surface gets its own review; PR A stays free of engine code. |

Decided here, from the spec and measurement, and not asked (veto any of these in review):

- **States.** `ran`, `skipped:<reason>`, `failed:<reason>`. The dev reconciler's eight
  states map onto them: output → ran; no_output, failed → failed; unrouted, idle,
  not_impl → skipped; unresolved → failed without `--allow-missing-tools` and
  `skipped:not installed` with it (#825's semantics, unchanged). Reasons are a closed
  enum, so none is recorded and then never printed (the trap that removed a third
  `NOT_ATTEMPTED_*` reason in Phase 2).
- **checkov's trigger** is terraform / cloudformation / helm content **plus
  `.github/workflows`**. The cut folded checkov-cicd into checkov, so Actions coverage
  is checkov's until Phase 4 hands it to zizmor and narrows `--framework` (spec §3).
- **zap and nuclei on a non-URL target** are `skipped:needs --url`. The "applicable to
  no target type" warning names only tools the user explicitly requested (#1279 item 1).
- **G1 is on by default when `.git` exists.** It costs little (below).
- **The secret scanners join the vendored-exclusion tier** (`VENDOR_NOISE_TOOLS` today:
  semgrep, trivy, checkov). Measured on a real Next.js application: trufflehog
  filesystem took **295.8 s and returned 253 findings, 222 of them in `node_modules`**;
  with vendored directories excluded, **18.8 s and 31**. The golden gitleaks run already
  used that allowlist. syft and grype keep reading vendored trees (#1205), except
  grype's `.venv`/`venv`, which was decided 2026-09-11 on #1235.
- **gitleaks' exclusions are a generated config file** (`[extend] useDefault = true` plus
  `[[allowlists]] paths`). gitleaks has no exclude flag, so this is a fourth rendering
  style beside inline, separate and regex.
- **The wizard's Docker branch rejects `targets` mode** with a message: a targets file
  lists host paths the container cannot see. `repo` → `--repo /scan`, `repos-dir`
  unchanged, `tsv` per PR T.
- **`stop_flag` stays unread here.** Ctrl-C is Phase 7's (the program plan says so). Spec
  §6 row 3's "`stop_flag` is read" contradicts that and moves to row 7 in PR A.

## Measured before this plan was written (2026-09-24)

| Claim | Measured |
|---|---|
| Tool blocks | **11** in `repository_scanner.py` (923 lines: trufflehog, semgrep, trivy, syft, checkov, hadolint, shellcheck, zap [stub only], gosec, yara, grype). The program plan said 12: nuclei has no repository block. **18** across the six jobs: repository 11, iac 2, image 2, url 2, k8s 1, gitlab 0 (it delegates) |
| Version probes | none in any scan job. They live in `scripts/cli/tool_manager.py` as three tool-keyed dicts, `VERSION_PATTERNS` (:71), `VERSION_COMMANDS` (:108), `VERSION_TIMEOUTS` (:127) |
| Other per-tool tables the descriptors absorb | `tool_registry`: `TOOL_BINARY_NAMES`, `TOOL_EXECUTION_COMMANDS`, `_REPO_TOOLS`, `TOOL_SCAN_TYPES`. `scan_utils`: `VENDOR_NOISE_TOOLS`, `TOOL_EXCLUSION_FLAG`, `TOOL_TIMEOUT_DEFAULTS`, `write_stub`'s shapes |
| Exclusion handling today | flags for 3 (semgrep inline, trivy `**/` separate, checkov regex); trufflehog an `--exclude-paths` file (`.git`, `.jmo`, in-tree results); hadolint and shellcheck walk-fed (`VENDORED_DIRS` + the results tree); gosec's walk only gates whether it runs, its `./...` gets nothing; **syft, grype, yara: nothing** |
| Content triggers today | hadolint and shellcheck: files collected, but no files means **no stub and no record** (#1227). gosec: `go.mod`/`.go`, recorded. **checkov: none**, so it runs on every repository |
| `stop_flag` | set at `jmo.py:3204`, written by the SIGINT/SIGTERM handler at `:3207`, **read nowhere** in `scripts/` or `tests/`. The handler replaces `KeyboardInterrupt`, so Ctrl-C logs, saves a checkpoint, and does not stop the scan |
| gitleaks `git` vs `dir` on the archived juice-shop | **63 vs 69.** The clone is shallow (`is-shallow-repository` true, 1 commit), so git mode saw one commit; its 63 are a subset (0 git-only), and dir has 6 `jwt` hits in `test/server/*.test.ts` that git mode omits. That evidence cannot measure history, and git mode must add to dir mode, never replace it |
| G1 fixture: a throwaway RSA key committed, then deleted | trufflehog filesystem **0** with the product's exclusions (without them: 1 hit at `.git/objects/72/3f87…`, naming no commit, which is #1134's objection); **trufflehog git 1**, commit `14b46f7c`, file, line 1, author, timestamp; **gitleaks git 1**, `partialFingerprints.commitSha` the same commit; gitleaks dir 0 |
| Git-mode cost, four real repositories (134–1,280 commits) | trufflehog git **5.2–16.5 s**; filesystem **98.9–284.2 s** on the same trees |
| This repository's history | git mode: 91 findings (34 unique) in 13 commits, all in once-committed third-party trees and old scan outputs (a venv, a checkov wheel, `results-*/`). **Git mode needs the same exclusion list** |
| What the adapters keep | trufflehog's reads only `SourceMetadata.Data.Filesystem`, so a git record gets an empty path, no line, and its commit only inside `raw`. CommonFinding's `secretContext.commit/author/date` exists, and **nothing writes it**. `sarif_common` has no `partialFingerprints` handling |
| Report-phase discovery | `normalize_and_report.py:~370` maps `<stem>.json` to the adapter named by the stem. A second output per tool needs a naming rule |
| `scan-timings.json` | schema v2; `tools[]` holds only tools that **ran**. A skipped tool has no row. `history.db` stores one `duration_seconds` per scan, so #722's step 3 is undone. `scripts/dev/reconcile_scan_accounting.py` rebuilds 8 states from logs, since no artifact has them |
| gitleaks today | absent from `versions.yaml`, `install_config.py`, `tool_registry.py`, `tool_manager.py`. The Phase 1 binding reads SARIF at `gitleaks.json`. Golden at v8.30.1: **69** raw = 69 expected, made with an allowlist config (`node_modules`, `.venv`, `.next`, `dist`); juice-shop has **none** of those directories, so `VENDORED_DIRS` renders the same set there |
| G2 today | nothing reads semgrep's `paths.scanned` or any tool's examined-files count |
| Tool-count claims | `tests/unit/test_tool_catalogue_count_claims.py` compares prose to `len(TOOL_MATRIX)`; about 25 documents state 12 today |
| The unrouted nuclei line | `scan_orchestrator.py:988-994` computes it over `self.config.tools`, which defaults to all of `TOOL_MATRIX`, so it cannot tell requested from defaulted |
| zap's probe on the host (session 2) | `zap.bat -version` with no `cwd`: **rc 1**, the batch file echoes `java -Xmx512m -jar zap-2.17.0.jar -version` then `Error: Unable to access jarfile zap-2.17.0.jar`; `_parse_version` returns `2.17.0` from the echoed jar name. With `cwd` = the install directory: **rc 0**, last line `2.17.0`, the real version. `_get_tool_version` parses whatever a non-zero probe printed (`tool_manager.py:1106`) |
| `_parse_version`'s fallback | when a tool's own pattern misses, it retries the **default** pattern (`tool_manager.py:1192-1198`). For zap that is the defect: it turns a correct miss into `17.0.20` (the image's Java line) or `2.17.0` (the jar name). Filtering the error line alone cannot work either: when every line is filtered, the raw output is parsed (`:1181`) |
| The wizard's Docker branch, all four modes | `build_repo_args` reads `repo_mode` only on the native path (`command_builder.py:18-22`). Docker: `repo` → `--repos-dir /scan` (each subdirectory scanned as a repository, never the root); `targets` mounts the **file** at `/scan` as `--repos-dir`; `tsv` → no target flag at all. The wizard reaches all four (`target_configurators.py:54-60`, `wizard.py:189-208`) |
| `jmo scan --tsv` | **never existed.** Through `build_parser()`: `scan --tsv repos.tsv --dest repos-tsv` exits 2, `unrecognized arguments`; `git log -S'"--tsv"' -- scripts/cli/jmo.py` is empty. `--tsv`/`--dest` belong to `clone_from_tsv.py`'s own parser, which has no entry point in `pyproject.toml`. So the wizard's tsv mode fails natively too. `test_wizard_command_builder.py:67-79` asserts `"--tsv" in args` and never parses it; `test_error_text_names_real_flags.py:34-35` knows `--tsv` belongs to another program. `git` is in the image (`Dockerfile:140`) |
| `clone_or_update` as it stands | `git clone url target` with no `--` before the URL (`clone_from_tsv.py:174`): a row starting with `-` is an option to git (CWE-88). The folder is the URL's last two segments with no containment check (`:155-162`): `..` segments leave `--dest`, and an existing escaped path gets `git fetch --all --tags --prune` (CWE-22) |
| #1073's return code | `run_tool_on_sample` returns parsed output only; `result.returncode` is logged on empty output and otherwise dropped (`test_tool_contracts.py:124-170`). No contract declares accepted exit codes |

## Issue premises, re-verified 2026-09-24

Each body was corrected on GitHub the same day. A detailed body is not a true one.

| Issue | Verdict | What changed |
|---|---|---|
| #722 | **half done** | #729 wrote `scan-timings.json`; `run_cmd` is deleted; #727 made `timed_out` real. Left: skipped tools have no row, and nothing reaches `history.db` |
| #1073 | stale | 8 tools, not 9 (bandit went). #1077 added a root-type assertion that every tool reaches, so the title's "no reachable assertion" is false. Still true: the dead `else`, the latent `IndexError` (`:356`), `{}`/`[]` passing, and **return code never asserted** |
| #1227 | holds | lines moved (hadolint `:529`, shellcheck `:580`, gosec `:658`); "18 blocks" is now 11; a DEBUG-level "No matching files" line exists, invisible at the default level |
| #1231 | holds | semgrep-secrets left with the cut; opengrep (Phase 5) emits the same `paths.scanned` |
| #1235 | **central premise gone** | horusec, cdxgen, dependency-check and `.horusec` staging left with the cut. Left: syft, grype and yara get no exclusion at all, not even the in-tree results directory; grype's `.venv` (decided 2026-09-11, promised issue never filed) |
| #1237 | stale counts | 10 tests and 10 entries, not 13; `jmo.py:3001`/`:2222`/`:2993`; `cmd_profile` is gone; three per-helper patches (`:444`, `:905`, `:992`), not two; the other four entries are named correctly now |
| #1277 | holds | `gitlab_ci.py:272-273`; the leftover `HIGH` is an unrecognized argument; **the wizard's Docker branch also drops `fail_on` silently** (`command_builder.py:134-162`, `scan` at `:153`) |
| #1279 | holds, mechanisms differ | item 2's message depends on a stray `bandit` binary (`.venv` has one); without it pre-flight says "None of the requested tools are installed". Item 3's native cases stop at pre-flight; all six e2e sites run only in scheduled or Docker jobs, under `continue-on-error` |
| #1283 | holds | not reproducible without Docker; the fixed pattern returns None on the Java line alone and falls back to the default pattern. **The host's `zap OK 2.17.0` is a false positive too**: `zap.bat -version` fails to find its jar, and the pattern matches the version inside the echoed jar filename |
| #1298 | filed with PR A | the wizard's Docker branch ignores `repo_mode`: a single repository is mounted and passed as `--repos-dir /scan`, which scans each subdirectory as its own repository and never the root's files (`command_builder.py:19-22`, `scan_orchestrator.py:498-500`); `targets` mounts a file as a directory |
| #1299 | filed with PR A, closed by PR T | the wizard's tsv mode emits `jmo scan --tsv FILE --dest DIR`, which `jmo scan` has never accepted (exit 2), natively and in Docker; the clone path it would promote has CWE-88 and CWE-22 defects (measurement table) |

## PR sequence

Four PRs into `dev`, each green before the next is cut from it.

| PR | Carries | Closes |
|---|---|---|
| **A** | this plan; program-plan and spec text; both new issues, filed and rostered; riders that touch no engine code (see "PR A riders") | #1073 #1237 #1277 #1283 #1298 |
| **T** | `jmo scan --tsv/--dest`: parser flags, target collection, the hardened clone path, the wizard's tsv mode native and Docker | #1299 |
| **B** | the descriptor table over the 18 blocks, the accounting record, the single exclusion list, G2, tool-name validation, `scan_tool_runs`, a results folder unique per repository | #722 #1227 #1231 #1235 #1279 #1303 |
| **C** | gitleaks wired as descriptor rows (dir and git), trufflehog's git invocation, both adapters writing `secretContext` | G1 (spec §4.3) |

B precedes C because the program's rule holds inside the phase too: a new tool is a
descriptor row, not a nineteenth block.

---

## Task A1: Plan text (PR A)

**Files:** `docs/superpowers/plans/2026-09-12-v2.0.0-program.md`,
`docs/superpowers/specs/2026-09-12-v2.0.0-program-design.md`, this file.

- [x] Program plan § Phase 3: roster both new issues (**11 issues**); "12 hand-written
  `if` blocks" → 18 across six jobs; the `stop_flag` line (`jmo.py:3204`); gitleaks and
  its golden-count gate move here from Phase 4; acceptance sums to **13**.
- [x] § Phase 4: gitleaks leaves its "Why here", "Measure first" and "Acceptance".
- [x] § Phase 10 "Measure first" gains the four release-time actions carried in #1292's
  body: dry-run `release.yml`'s untested single-image path; re-measure
  `IMAGE_SIZE_RANGE` from the published v2 manifest (predicted ~976–1465 MiB); dismiss
  the `docker-deep/-balanced/-slim/-fast` code-scanning categories; expect
  `validate-image` to fail between the sync and the image publish.
- [x] Summary table: Phase 2 state → `on dev as 0894ca72`; Phase 3 `n` 9 → 11;
  `before tag` 59 → 61. Plan prose cites no `#NNNN` except issues being scheduled.
- [x] Spec §6 rows 3 and 4 follow; `stop_flag is read` moves to row 7.
- [x] `phase_audit.py --plan docs/superpowers/plans/2026-09-12-v2.0.0-program.md derive`
  → checksums agree, 61 + 26 = 87; `verify` → unclaimed 0, labels agree (label both new
  issues `phase:3` when filing them, and replace `#NEW-wizard` and `#NEW-tsv` with their
  numbers; `derive` exits 2 until both are replaced). **Done 2026-09-25:** filed as #1298
  and #1299; `derive` 61 + 26 = 87, four checksums agree; `verify` unclaimed 0 of 85,
  61 labels agree; `test_real_plan_parses` green.

## Task A2: #1283 — zap's version probe

**Files:** `scripts/cli/tool_manager.py` (`VERSION_PATTERNS["zap"]` `:94-97`,
`_parse_version`'s fallback `:1192-1198`, `_get_tool_version`'s `subprocess.run`
`:1050`); `tests/cli/test_tool_manager.py`.

Two defects, one symptom (decision 5): the image misreads the JVM line; the host probe
runs without `cwd`, fails, and the version is read out of the echoed jar name.

**Done 2026-09-25, uncommitted** (`tests/cli/test_tool_manager.py::TestZapVersionProbe`,
8 cases). Red: 6 of 7 failed for the named reasons (`0.20.1` from the JVM line, `2.17.0`
from the jar name, no `cwd`); the 3-part case passed, a regression guard. Green: the file
110 passed. Five mutations, each caught by its own case, the file restored byte-identical:
drop `(?<!\.)`, drop `\d` from `(?!\d|\.jar)` (backtracking reads `zap-2.17.10.jar` as
`2.17.1`), drop `\.jar`, restore the fallback, drop `cwd`. Product path: the real
`zap.bat -version` ran with `cwd` = its directory, **rc 0**, `2.17.0`; `jmo tools check zap`
→ `OK 2.17.0 2.17.0`.

- [x] Red first: parametrize `_parse_version("zap", out)` over (a) the image's
  multi-line output ending `2.17.0` with `Found Java version 17.0.20.1` → `2.17.0`;
  (b) the Java line alone → `None`, asserted both on `VERSION_PATTERNS["zap"]` and
  through `_parse_version` (today the fallback returns `17.0.20`); (c) a 3-part Java
  line + `2.16.1` → `2.16.1`; (d) the host's measured failure output verbatim (the
  echoed `java … -jar zap-2.17.0.jar -version` line and `Error: Unable to access
  jarfile zap-2.17.0.jar`) → `None`, not `2.17.0`.
- [x] Fix the pattern: `(?<!\.)`, and no match inside a `*.jar` token. Take zap out of
  the default-pattern fallback (B2 later moves this onto the descriptor's
  `version_probe`).
- [x] Fix the probe: zap's version command runs with `cwd` = its binary's directory.
  Test the `cwd` passed to `subprocess.run`; then `jmo tools check` on the host shows
  zap `2.17.0` from an rc-0 probe.
- [x] Mutations, each restored from a file backup: drop the lookbehind → (a) fails;
  restore the fallback → (b) and (d) fail; drop `cwd` → the probe test fails.

## Task A3: #1277 and the wizard Docker issue

**Files:** `scripts/core/workflow_generators/{gitlab_ci,github_actions}.py`,
`scripts/core/cron_installer.py:392-400`, `scripts/cli/wizard_flows/command_builder.py`,
`scripts/core/schedule_manager.py:157`, `scripts/core/attestation/metadata_capture.py:73`;
`tests/unit/test_schedule_mutually_exclusive_targets.py`, `test_schedule_target_coverage.py`.

**Done 2026-09-25, uncommitted.** Red, each for its named reason: the GitLab cases of
the conflicting test and a new single-target control, `invalid choice: 'jmo'` (2); both
consumers' parse and flag tests once `_maximal_schedule` has a threshold,
`unrecognized arguments: HIGH` (4); cron through `test_emitted_flags_are_defined.py`,
whose schedule gains a threshold (2); Docker `repo` → `repos_dir='/scan'`, `targets` not
refused, threshold → `scan` (3); the two factories (3). Green: the guard files 72, every
exporter test file 204 passed / 35 skipped (cron's skip off Linux), every wizard test
file 549. Thirteen mutations, each caught and restored byte-identical, including putting
the `jmo` head back (both GitLab cases fail). Product path: a cron-rendered threshold
command run through the real `jmo` (`--tools trufflehog`, `--history-db` in tmp): rc 0,
`threshold=HIGH`, reports written; the pre-fix `jmo scan … --fail-on HIGH` exits 2.

- [x] Red first: fix the vacuous test (strip the leading `jmo`, as
  `test_schedule_target_coverage.py:247-250` does), then add a threshold to
  `_maximal_schedule` so "actually parses" exercises `fail_on`. Both fail today.
- [x] A schedule with a threshold emits `jmo ci … --fail-on X` in all three exporters
  (the wizard's native path already does).
- [x] Docker branch: emits `ci` when there is a threshold, and honours `repo_mode`:
  `repo` mounts at `/scan` and passes `--repo /scan`; `repos-dir` keeps `--repos-dir`;
  `targets` is refused with a message naming why. `tsv` is PR T's. Test each mode's
  argv through `build_parser()`, never by membership (`"--tsv" in args` passed for a
  command that never parsed).
- [x] `from_simple_args` raises on an unknown kwarg; `from_scan_args` copies only its
  declared keys. Tests name `profile=` and `password=`.

## Task A4: #1237 and #1073 — two test-infrastructure fixes

**Files:** `tests/cli/test_scan_runtime_accounting.py` (`scan_env` `:376-399`, patches
`:444`, `:905`, `:992`); `tests/conftest.py:596-638`;
`tests/integration/test_tool_contracts.py:316-370`.

**Done 2026-09-25, uncommitted.** #1237, with fake `trufflehog.exe` and `gosec.exe` on a
`/c/...` PATH entry: the 10 entries removed and no pin, 39 passed / 10 errors; pinned,
39 passed / 0 spawns; pin removed again, 16 errors (the 10, plus 2 for each of the three
helpers whose own patches were deleted). A recorded stack of every spawn put all 10 on
`_warn_critical_updates`, none on `_check_scan_tools`. #1073, measured on each sample:
trivy, grype, syft rc 0 with findings; hadolint rc 1 (10), checkov 3.3.16 rc 1 (37
failed; the host's venv is broken, so via `uvx`); trufflehog rc 0 with **nothing on
stdout**, the "2 items" were its stderr log lines, which the harness parsed when stdout
was empty; shellcheck rc 0, `[]`, because the sample opens `# shellcheck disable=all`;
semgrep scanned **0 files** on Windows and on Linux (its built-in ignore skips `tests/`
when there is no `.semgrepignore`), and 1 file with 4 results when named. So the harness
reads stdout only, semgrep's command names the file, and trufflehog and shellcheck
declare `may_be_empty` with those reasons. A real process exiting 2 with a well-formed
hadolint report passed the old test and fails the new one (`exit code 2, contract
accepts (1,)`); exit 1 passes. The real host tools: 22 passed, 2 skipped (checkov). Five
mutations, each caught.

- [x] #1237: pin `ToolManager._find_binary` to `None` in `scan_env`; delete the three
  per-helper patches and the 10 allowlist entries. Measure with the issue's recipe (a
  `true.exe` named `trufflehog.exe` on a `/c/...` PATH entry): 0 spawns, 39 passed.
  Rewrite the conftest comment's two false claims and its three disagreeing counts.
- [x] #1073: delete the dead `else`; take `required_keys` without indexing a possibly
  empty list; assert the return code is in the contract's accepted set. That needs
  `run_tool_on_sample` to return the return code beside the output, and each contract
  to declare `ok_return_codes`, **measured per tool** on its sample (the linters are
  expected to exit 1 on findings; that is a hypothesis until run). The
  "non-empty output" question is a contract property: a tool that may legitimately
  report nothing declares it, and the test asserts non-empty for the rest. Mutation:
  a hadolint stub that exits 2 must now fail.

## PR A riders (Jimmy, 2026-09-25)

After A4's review Jimmy asked for every finding to be fixed here rather than routed:
the review's minors, the defects it found that predate the PR, and the Docker settings.
Each went red first for its named reason, then green; none touches scan-engine code.

- **Docker's other settings (#1298):** the advanced-options block is shared by both
  branches, so Docker carries `--threads`, `--timeout`, `--allow-missing-tools` and
  `--human-logs` as well as the threshold. Red: `(None, None)` for threads and timeout.
- **`from_scan_args` loses `**kwargs` (#1277):** an unknown keyword is a `TypeError`, the
  same rule as `from_simple_args`. Nothing in the product calls it.
- **GitLab `--threads` / `--timeout` quoted (#1277):** red, `4; id` split into `4;` and `id`.
- **Cron `--results-dir` (#1277):** the default rendered `'~/jmo-results'/…`, and a quoted
  `~` is never expanded (measured in Linux bash: literal `~/jmo-results/run`; `"$HOME"/…`
  gives `/home/…`); `jmo` does not expand `--results-dir` (`jmo.py:2979`). Now
  `"$HOME"/jmo-results`. Two Linux-only tests in `test_cron_installer_additional.py`
  pinned the old forms, one of them `jmo scan` with a threshold: they skip on Windows,
  so they were run under WSL, 32 passed.
- **The wizard's artifacts (#1298):** native GitHub Actions emitted `--repos-dir .` for
  `repos-dir` and no target for `targets`/`tsv` (now `--repo .` in every mode, as Docker
  already did) and set up Python 3.11 for `requires-python >=3.12` (now 3.12, checked
  against `pyproject.toml` by a test). `--emit-script`/`--emit-make` joined the command
  with bare spaces (now `shlex.join`, `$` doubled for make) and wrote CRLF on Windows (now
  LF bytes; measured, Linux bash stops at `set: pipefail: invalid option name`, rc 2).
  `ArtifactGenerator` was dead (never read, wrong argument order, text discarded) and is
  deleted with its three mock-only tests.
- **Contracts (#1073):** the shellcheck sample loses `disable=all`, the hook excludes
  `tests/fixtures/samples/`, and the contract requires findings with rc 1 (measured 17,
  rc 1). trivy and checkov count findings, not containers (`findings` extractors;
  measured, trivy's `Results` is non-empty for a manifest with no vulnerabilities).
  grype and syft are installed by both CI contract jobs (pinned `GRYPE_VERSION` /
  `SYFT_VERSION`, kept by `update_versions.py --sync`), guarded by a test deriving the
  tool list from `TOOL_CONTRACTS`. The harness decodes UTF-8: on Windows a cp1252 decode
  error was swallowed and stdout came back `None`.
- **zap (#1283):** the lookahead gains `\.\d`, so `openjdk version "17.0.20.1"` no longer
  reads as `17.0.20`.
- The minors: GitLab's warnings no longer say "`jmo scan` command"; the no-threshold
  control checks every target; the conftest comment says why the three real trufflehog
  scans are offline (each scans a freshly `mkdir`-ed, empty directory).

Second review of the riders, then fixed here too:

- **Cron never ran a job (#1277).** crontab(5): an unescaped `%` ends the command and the
  rest goes to stdin. Every installed line carried `$(date +%Y-%m-%d)`, so `sh` received
  `... $(date +` and stopped (reviewer, under WSL: `sh -n` rc 2). Every `%` is escaped
  now; a test applies cron's rule and parses what the shell gets (red: the threshold went
  to stdin). Not a real cron run: that would edit the WSL user's crontab. `~bob/...` is
  refused. The CHANGELOG's earlier "results landed in a literal `~`" was impossible and
  is corrected.
- **`timeout` dropped (#1277):** GitHub Actions and cron never emitted it; GitLab did.
- **`GITLAB_TOKEN` never read (scan-job code, one line):** `jmo scan` always passes
  `"token": None`, and `dict.get`'s default only covers a missing key; the old tests
  omitted the key. The wizard no longer puts the token on the command line (printed,
  and written by `--emit-script`/`--emit-make`); it passes it in the scan's environment
  and Docker forwards it with `-e GITLAB_TOKEN` (#1298).
- **The native workflow installed no scanner (#1298):** its install step now runs
  `jmo tools install --yes`; the generated-commands guard resolves nested subcommands.
- **Docs:** `SCHEDULE_GUIDE.md` taught `jmo scan … --fail-on HIGH` in three runnable
  blocks, now `jmo ci`, with a guard over every fenced block in the docs;
  `docs/examples/wizard-examples.md` shows the generators' current output.
- Kept, as a ruling: the wizard displays POSIX-quoted commands on Windows too. PowerShell
  and bash accept them; `subprocess.list2cmdline` would suit cmd.exe but lets PowerShell
  expand a `$` inside double quotes, and the emitted scripts must stay POSIX.

## Task A5: gates, then PR A

- [x] Touched test files, then the bounded suite from Git Bash; diff failing IDs against
  `27900a32`. **Expected red until the swap:** `tests/unit/test_phase_audit.py::test_real_plan_parses`
  fails while `#NEW-wizard`/`#NEW-tsv` stand in the roster (the in-suite form of
  `derive`'s rc 2). After A2, 2026-09-25: 8711 passed, 97 skipped, that 1 failed. `pre-commit run --all-files`; `check_eol_flips.py --base origin/dev`.
  After A4: touched files 382 passed; bounded suite **8728 passed, 97 skipped, 1 failed**,
  the same one test (+17 passed = the new tests, skips unchanged); pre-commit 23 hooks
  passed; `check_eol_flips` rc 0.
- [x] File both new issues (label `phase:3`) **immediately before pushing**, then swap
  their numbers into the roster. Filing reddens every open PR's `phase-audit` until
  this merges. #1299 stays open, rostered, until PR T closes it. Filed before the commit
  instead, on Jimmy's word ("fix the failing test fully, then commit").
- [ ] PR body: the verification numbers; closing keywords go in individual commit
  messages at squash time, one `Closes #N` each.

---

## Task T1: Measure first (PR T)

- [x] `clone_from_tsv.py`'s existing tests (`tests/cli/test_clone_from_tsv.py`): what
  they cover, and which of them survive the move into the product path.
- [x] How `--targets` flows from the parser through target collection
  (`scan_orchestrator.py:482-532`) and into the repository job: `--tsv` produces the same
  kind of list, after cloning.
- [x] The CWE-88 and CWE-22 claims in the measurement table, reproduced against
  `clone_or_update` in a temp directory with a local bare repository, no network: a URL
  that starts with `-`, and one whose path segments are `..`. The test must not execute
  anything a hostile row names.
- [x] Docker: does `git clone` over `https://` work inside the image (a public repository,
  once), and where do clones land so a second run updates rather than re-clones.

**Measured (T1, 2026-09-25).** Git 2.55.0.windows.3 on the host; the image is
`jmo-security-dev:v2` under WSL (git 2.43.0, uid 1000).

| Claim | Measured |
|---|---|
| The 23 existing tests | `parse_tsv` 9 (survive as they are); `run` 3; `ensure_unshallowed` 3 and `clone_or_update` 4 **mock `run` with fixed `side_effect` sequences**, so they pin git's call order, never run git, and passed over every defect below; `main` 4 |
| `--targets`' flow | `--repo`/`--repos-dir`/`--targets` share scan's mutually exclusive group (`jmo.py:147-151`), and `ci` gets the same group (`:366`). `_discover_repos` `_reject`s each bad entry by name (`scan_orchestrator.py:509-532`); `cmd_scan` exits 1, "Every target was rejected", when nothing is left (`jmo.py:3076-3091`). `rejected` is logged, never persisted. `jmo ci` copies the namespace (`_phase_args`), so a `getattr`-read `tsv`/`dest` needs no `_SCAN_REQUIRED` entry. The wizard runs its argv through a subprocess, so the parser is the only route in |
| CWE-88 | `clone_or_update("-h", dest)` ran `git clone -h <dest>/misc/-h`: **rc 129 and git's usage text**, the row parsed as an option. `git clone -- -h d`: `fatal: repository '-h' does not exist`, rc 128 |
| CWE-22 | `https://example.invalid/../escape.git` returned `dest/../escape` and ran `remote -v`, `fetch --all --tags --prune` (twice) and `rev-parse` **in a repository outside `dest`**. `…/owner/..` with `dest` inside another repository returned `dest` itself; `remote -v` walked up and **the fetch ran in the enclosing repository**. A plain (contained) directory at `dest/owner/repo` inside a repository: the same walk-up. On Windows, `…/..\..\made-outside\o/r.git` made **`made-outside\o` two levels above `dest`** in `mkdir(parents=True)`, before git ran |
| scp-form rows | `git@github.com:owner/repo.git`, which the allowlist below permits, **crashes on Windows**: the folder `git@github.com:owner` raises `NotADirectoryError` (WinError 267) out of `mkdir`. A trailing `/` makes the repository name empty and the clone lands at `dest/repo` |
| The update path | `fetch` does not move the working tree: after a new commit on origin the clone stayed on the first commit (`173f96c` vs `34c766e`); `merge --ff-only` moved it. **A second run scanned the first run's files** |
| Credentials | git strips userinfo from its own messages (`unable to access 'https://127.0.0.1:9/x.git/'` for a `user:TOKEN@` URL); the module's own lines print the raw URL. `run()` has **no `timeout=`**, and nothing stops git prompting for credentials |
| Docker | https clone inside the image rc 0, owned 1000:1000 on the host; a second run on the same mount reads origin, fetches and fast-forwards, all rc 0. **A host directory that does not exist is created by Docker as root:root 755, and the image user cannot write it** (`mkdir: Permission denied`): the wizard's existing `results` mount has the same trap. A clone owned by another uid: `git config --get` rc 1 **with no message**; `rev-parse --show-toplevel` rc 128, `dubious ownership` |
| Tests without network | `url.<base>.insteadOf` through `GIT_CONFIG_COUNT`/`KEY_0`/`VALUE_0` rewrites `https://example.invalid/owner/repo.git` to a local bare repository: clone rc 0, and `remote.origin.url` keeps the row's URL, so an origin check still compares against the row |

**Decided in T1** (veto any in review):

- **No `file://`.** The allowlist is `https://`, `ssh://` and `git@host:`, each followed by
  an alphanumeric host, printable ASCII only. A TSV names remote repositories; a
  `file://` or bare-path row would copy any local repository into `--dest`. Tests keep
  real git and no network with `insteadOf` from the environment, rewriting
  `https://example.invalid/...` (RFC 6761: never resolves). No test-only switch in
  product code.
- **`--dest` has no default; `--tsv` without it is rejected by name.** Every default is
  wrong somewhere: the working directory puts clones inside whatever repository the
  user runs from (its `git status`, its next scan); the results directory is uploaded
  whole by the wizard's own workflow (`upload-artifact`, `path: results/`), so cloned
  private source would become a CI artifact, and users delete it between runs, which
  defeats updating. The wizard already asks (default `repos-tsv`).
- **Every guard lives in `clone_or_update`**, the one entry point, which returns the
  clone or the reason: allowlist, then containment (resolved target must be exactly
  `<dest>/<owner>/<repo>`, checked **before** anything touches the disk), then `--`.
  The folder comes from the URL's path (after `host:` for the scp form, trailing `/`
  dropped).
- **An existing target must be a clone of the row's URL**: `rev-parse --show-toplevel`
  is the target (no walk-up; it also names `dubious ownership`) and `remote.origin.url`
  equals the row. Otherwise the row fails by name. This closes the walk-up and the
  collision of two hosts' `owner/repo`.
- **Update means fast-forward**: fetch, then `merge --ff-only`. A failed fetch or a
  clone that cannot fast-forward fails its row. Scanning the old checkout would report
  on code that is no longer there.
- **Every git call gets `timeout=`, `GIT_TERMINAL_PROMPT=0` and no stdin**: a private
  https repository fails at once instead of waiting on a prompt. Private repositories
  need a credential helper or an ssh key; the docs say so. Messages show `https://***@`
  in place of userinfo. *Corrected by the review below:* `GIT_TERMINAL_PROMPT=0` alone
  is not enough, and ssh prompts on the terminal itself (see option C).
- **`clone_from_tsv.py`'s `main()` goes** (and with it `--targets-out` and `--max`): no
  entry point in `pyproject.toml`, so it ran only from a checkout, and `jmo scan --tsv`
  replaces it. The module stays as the library discovery calls.
- **Docker mounts the wizard's clone destination** at `/repos-tsv` rather than putting
  clones under `/results`: the wizard asks for that directory, native mode honours it,
  and `results` is what gets uploaded. The wizard creates the host directory first
  (measured above).

## Task T2: `jmo scan --tsv FILE --dest DIR`

**Files:** `scripts/cli/jmo.py` (`_add_target_args`), `scripts/cli/scan_orchestrator.py`
(target collection), `scripts/cli/clone_from_tsv.py`; tests beside each.

- [x] Red first, through `build_parser()` and `jmo scan --history-db <tmp>` on a local
  bare repository listed in a TSV (a `file://` URL, allowed in tests only if the scheme
  allowlist permits it by design; decide in T1): today exit 2.
- [x] Parser: `--tsv` in the target group beside `--targets`, `--dest` required with it
  (or a default under the results directory; decide in T1 and say why). The same
  `_reject` validation as `--targets`: missing file, no header, no `url`/`full_name`.
- [x] Hardening, each red first: `--` before the URL; schemes `https://`, `ssh://`,
  `git@host:` only; the resolved destination must stay under `--dest`, or the row is
  rejected by name. Mutation: remove each guard and its test fails.
- [x] Clone failures are per-row and named; a TSV whose every row failed is a target
  failure, not a clean scan of nothing.

**Done (2026-09-25).** The tests run real git against a bare repository behind
`insteadOf` (`tests/cli/conftest.py`), replacing the `side_effect` mocks. 23 mutations
(allowlist ×4, containment, mkdir-before-check, `--`, top-level, origin, fast-forward,
fetch failure, timeout ×3, prompt, stdin, the scp and trailing-slash folders, redaction
×2, no-`--dest`, all-failed, header-only, parser): **23 caught**. One survived first: the
top-level check's test used an enclosing repository with no origin, so the origin check
refused it too. The test now uses a clone of the row's own URL.

## Task T3: The wizard's tsv mode, native and Docker

**Files:** `scripts/cli/wizard_flows/command_builder.py`, `tests/unit/test_wizard_command_builder.py`.

- [x] Replace `test_build_repo_args_tsv_mode_native`'s membership asserts with a parse
  through `build_parser()`; it fails today. The parser oracle already exists,
  `tests/unit/test_wizard_generated_commands_parse.py`, and it fixes
  `repo_mode = "repo"` (`:70`, `:169`), which is why it never saw tsv: extend its cases
  to all four modes, native and Docker, rather than writing a second oracle.
- [x] Docker: mount the TSV read-only and point `--dest` under the `/results` mount so
  clones persist between runs. Private repositories need credentials the container does
  not have: say so in the wizard's output, and in `docs/examples/scan_from_tsv.md`.
  **Changed in T1:** `--dest` is the wizard's own destination mounted at `/repos-tsv`,
  not a path under `/results` (see "Decided in T1").
- [x] Gate: the wizard's generated tsv command, native, runs end to end on the bare-repo
  fixture through `jmo scan --history-db <tmp>`.

**Done (2026-09-25).** The oracle's new case parses each mode's command and asserts
that the mode's own target is set, since a command with no target parses. Docker tsv
mode emitted exactly that (`scan --results-dir /results ...`). 6 mutations (the Docker
branch, native `--dest`, `:ro`, both `mkdir`s, the Docker note): **6 caught**.
Gates, real scanners, `--history-db <tmp>`, a TSV of one good row and one `http://` row:

| Run | rc | Wall | Clone HEAD | Outputs | History rows |
|---|---|---|---|---|---|
| native 1 | 0 | 50.2 s | first commit | 10 tools + `scan-timings.json` | 1 |
| native 2, after an upstream commit | 0 | 24.9 s | the new commit | the same 10 | 2 |
| Docker 1 (WSL; the branch's `scripts/` over the image's) | 0 | 4 s | first commit, owned 1000:1000 | `trufflehog.json` + `scan-timings.json` (`--tools trufflehog shellcheck`; no shell file for shellcheck) | 1 |
| Docker 2, after an upstream commit | 0 | 3 s | the new commit | the same | 2 |

Re-run after the review's fixes, same outcomes: native 42.6 s and 20.9 s, Docker 3 s
and 3 s. The `http://` row was named each time (`not an allowed clone URL`); the live
`.jmo/history.db` read 2,492 scans before and after; the TSV mount refuses a write
(`Read-only file system`). The Docker runs are the wizard's own argv with three
test-only additions: the source mount, the bare-repository mount and the `insteadOf`
environment.

Filed with this PR and scheduled into Phase 8 (handoff 3.2): **#1301**, the five wizard
flow classes `jmo wizard` never constructs, and **#1302**, `--results-dir` with no
`expanduser` (measured: `--results-dir '~/x'` wrote `./~/x/summaries`, rc 0).

**Review (2026-09-25), then fixed here.** A fresh review of T1-T3. Each finding was
reproduced before it was fixed, and each fix went through the same mutation run
(**17 caught**; the symlink-loop guard under WSL, where its test runs).

| Finding | Reproduced | Fix |
|---|---|---|
| Two repositories of one name share `individual-repos/<name>`: concurrent writes, last writer wins | `results_dir / _sanitize_path_component(repo.name)` (`repository_scanner.py:275`) | The second is refused by name; a URL listed twice is cloned and scanned once |
| One row crashes the scan | a `--dest` that is a file: `FileExistsError`; `own:er` on Windows: `NotADirectoryError`; a symlink loop: `RuntimeError` (Python 3.12.3) | Every filesystem call fails its row; an unusable `--dest` is refused once for the file |
| `GIT_TERMINAL_PROMPT=0` does not stop prompts | under WSL, a local 401 server: with `GIT_ASKPASS` (as VS Code sets it) or `SSH_ASKPASS` set, the askpass program **ran**; with both removed, "terminal prompts disabled" | Superseded by option C below; `GCM_INTERACTIVE=never` (GCM's documented switch, not measured) |
| Credentials logged for non-https rows | `http://`, `HTTPS://`, `ssh://u:pw@` passed `redact` unchanged | Any scheme, any case |
| A token in a folder name | `https://user:TOK@host/project.git` → `dest/user:TOK@host/project` | A one-segment path's owner is the host without userinfo or port |
| ssh user and host unrestricted | `ssh://h$(id)/o/r` and `ssh://a@-oProxyCommand=x/o/r` passed | https and ssh hosts get the scp form's alphabet; an ssh user too (CVE-2023-51385 class) |
| `parse_tsv` on a spreadsheet export | a BOM: "must include either"; a `URL` header: zero rows | `utf-8-sig`; rows keyed by the matched header |
| The wizard mounts a TSV that is not there | Docker creates a root-owned directory of that name | The wizard asks again |
| A clone that cannot fast-forward fails every run | traced | Its message says to delete the clone |
| Test gaps | the backslash test passed on POSIX without its guard; the fixture failed under `protocol.file.allow=never`; the leading-dash rows were refused by the host alphabet first (a mutant survived) | Windows-only; the fixture sets it; three rows only the leading-character rule refuses |

Left open, decided by Jimmy (2026-09-25):

- **Same-name collision** (it predates this PR for `--targets`): **#1303**, fixed in
  PR B by a results folder unique per repository. Measured with `--targets`: two
  `app` repositories, "2 repos" scanned, one `individual-repos/app`, whose
  `shellcheck.json` names only the first repository's file. PR B also removes PR T's
  same-name refusal.
- **Docker Desktop on Windows**, where bind mounts may read as another owner and make
  every second run fail with `dubious ownership`: **#1304**, Phase 8. It can't be
  measured here, since Docker runs only under WSL.
- **The wizard's `repos-tsv` default** is kept: the wizard shows it and asks, which is
  not the silent default the T1 decision rules out.
- **ssh prompts: option C** (a second commit). ssh asks on the terminal itself, so
  git's prompt switches never reached it. `ssh -o BatchMode=yes` would override a
  user's `core.sshCommand` and PuTTY setups, so it was not used. Both askpass variables
  are now `/dev/null` (a path that cannot run, and absolute, so nothing is looked up
  on `PATH`), with `SSH_ASKPASS_REQUIRE=force`. Measured:

  | Probe | Before | Option C |
  |---|---|---|
  | ssh with a terminal (WSL, OpenSSH 9.6), unknown host | waits at "Are you sure you want to continue connecting" until killed | `Host key verification failed.`, exits on its own |
  | ssh on Windows (Git for Windows' OpenSSH 10.3p1) | (no terminal in the harness, so it failed either way) | tries the askpass program (`ssh_askpass: exec(/dev/null)`): the variable is honoured |
  | https, 401 server, `core.askPass` configured (WSL and Windows) | the configured program **ran**: removing the two variables had left this third source live | not run; "terminal prompts disabled" (Windows maps the path to `nul`: "cannot spawn nul") |

  A new test drives real git against a local 401 server with a `core.askPass` marker,
  red before the change. 5 mutations (one per variable): **5 caught**, the
  `GIT_ASKPASS` one by the real-git test on its own too. Older ssh (before 8.4)
  ignores the variable, and the docs say so.
- `--dest` without `--tsv`, and `include`/`exclude` filters that run after cloning:
  **corrected 2026-09-25 (PR B).** This line said both were "left as they are" by
  Jimmy's decision; he had not decided them. Asked in PR B, he chose: `--dest`
  without `--tsv` is a usage error (exit 2), and the filters drop a row by its folder
  name before anything is cloned. Both land in PR B.

---

## Task B1: Measure first (PR B)

Numbers the descriptor table must preserve, taken before any code moves:

- [x] **The golden per-tool record.** For each of the six target types, a fixture scan
  through `jmo scan --history-db <tmp>` with the tools this machine has. Save each
  `scan-timings.json`, `.scan_metadata.json`, the tool output files and the stderr log.
  Run `reconcile_scan_accounting.py` on each: this is the before-picture every
  descriptor row is checked against.
- [x] **Which tools report an examined-files count** (G2): run each installed tool once on
  a 4-file fixture and once on an empty tree, and record the field (semgrep
  `paths.scanned`; gosec `Stats.files`; checkov's summary; trivy, syft, grype,
  trufflehog, yara are expected to have none). Only a field that means "files examined"
  qualifies.
- [x] **Every reader of the per-tool tables** the descriptors absorb (list above), and of
  `scan-timings.json` and `__not_attempted__`, including `rich_progress.py`, the
  reconciler, `jmo-profile-optimizer` and the tests. Record the list in the PR.
- [x] **Each tool's exclusion syntax at the pinned version**, where not already measured:
  syft 1.51.1 and grype 0.118.0 `--exclude` (does a dir scan need a `./` prefix?);
  yara_runner's walk; trufflehog `--exclude-paths` in **git** mode.

**Measured (B1, 2026-09-25).** Host Windows 11: 11 of 12 installed (yara-python absent;
gosec 2.28.0, grype 0.115.0, hadolint 2.14.0, nuclei 3.11.0 behind their pins). Every
scan ran from an empty directory with no `jmo.yml`, so the defaults applied.

| Claim | Measured |
|---|---|
| Golden, repository (7 files: py, Dockerfile, sh, go.mod + go, tf, requirements) | rc 0, 27 s. **9 rows for 12 tools**: yara was dropped by pre-flight ("Skipping 1 missing tool"), nuclei by routing (the unrouted line, though nothing was requested), and zap wrote a stub that the reconciler counts as `output` |
| Golden, repository with only `lib.py` and `README.md` | 6 rows. **hadolint and shellcheck: no row, no file, no line at any level** (#1227). gosec and zap in the INFO "SKIPPED" line. checkov **ran**, on a tree with no IaC |
| Golden, IaC / image / k8s / GitLab | IaC `main.tf`: 2 rows. `alpine:3.19`: 2 rows. A context that does not exist: trivy exits 1 with `FATAL`, which (0, 1) grades as `no_output`. GitLab without a token: `failed-before-tools`, and the ERROR names **nuclei** among "every tool failed": `TOOL_SCAN_TYPES["gitlab"]` includes nuclei, which `scan_repository` has no path for |
| Golden, URL (a local `http.server`) | Both tools failed, and **neither has produced findings on this host**. nuclei 3.x exits 2: `flag provided but not defined: -json` (it is `-jsonl`; `-je` exports a file). zap resolves to `~/.jmo/bin/zap/zap.bat` (so a Windows scan does find it, handoff 3.4) and exits 1: `Unable to access jarfile zap-2.17.0.jar`, the #1283 probe defect in the scan. `zap.sh` changes into its own directory; `zap.bat` does not |
| Examined-files fields (G2) | semgrep `paths.scanned`: 2 of 4 with `p/python`, 0 on an empty tree. gosec `Stats.files`: **0 on this host and in the image, always**: neither has a Go toolchain, and gosec cannot load a package without one (`Golang errors: loading files from package`), so every gosec run so far scanned nothing and was graded success. checkov's `resource_count` counts resources, not files. trivy, syft, grype: none. trufflehog: `chunks` in a stderr log line, not files |
| syft 1.51.1, grype 0.115.0 (host) and 0.118.0 (image) `--exclude` | A bare `results` is **fatal**, rc 1: "must start with one of: './', '*/', or '**/'". `./results` drops only the root copy; `**/results` drops root and nested. Identical across all three binaries |
| gosec 2.29.0 `-exclude-dir` (image) | `-exclude-dir=results` matches the name at any depth; `-exclude-dir=**/results` exits 2 |
| trufflehog 3.97.1 `--exclude-paths` in git mode | Paths are repository-relative (`results/creds.txt`), so today's `[\\/]results[\\/]` misses a root `results/`. `(^\|[\\/])results[\\/]` works in git and filesystem mode. On Windows the git target must be `file://C:/...`: `file:///C:/...` doubles the drive (`C:/C:/...`, PR C) |
| yara_runner's walk | Prunes `SKIP_DIRS`, a copy of `VENDORED_DIRS`, and never the results directory |
| semgrep's built-in list (Unresolved #3), 1.161.0, re-measured on 1.175.0 | With no `.semgrepignore`, semgrep skips `tests/`, `test/` (any depth), `build/`, `dist/`, `node_modules/`, `vendor/`, `.venv/`, in a git work tree or not. An empty `.semgrepignore` at the scan root disables the list. There is no flag or environment variable (semgrep-core's strings checked). ~~`find_tool("semgrep")` runs 1.161.0 while `jmo tools check` reports 1.175.0~~: **measured false**, corrected below |
| Readers of `individual-repos/<name>` (#1303) | `scan_repository` (output folder), `gitlab_scanner` (copies `temp_results/<name>`), `ScanOrchestrator.scan_all` (session key and target id), `cmd_scan` (`register_target`, progress lines), `history_db.collect_targets` (folder names become `scans.targets`), `normalize_and_report` and the reconciler (walk every folder; the name is unused), and PR B's `scan_tool_runs.target` |
| Two repositories, identical `deploy.sh`, `--repos-dir` | **2 findings, not 4.** `normalize_finding_path` strips each scan root, so both files are `deploy.sh`, the ids match, and dedup keeps one. Not #1303: the folders are distinct |
| #1303 through `--targets` | Reproduced: one `individual-repos/app`, `bob.sh`'s 2 findings only |

**Decided in B1** (Jimmy, 2026-09-25): `--dest` without `--tsv` exits 2; `include`/`exclude`
drop a TSV row before it is cloned; semgrep keeps its built-in list, recorded in
`docs/KNOWN_LIMITATIONS.md` (the alternative writes a file into the user's tree); the
nuclei flag and zap's working directory are fixed here, red first through `jmo scan
--url`. Unresolved #2 was decided at PR time: folded into #1235.

**Decided in B1** (from the measurements; veto any in review):

- **Rows, not booleans.** Each scan job returns `(name, rows)`, one `ToolRun` per
  requested tool; the boolean map, `__not_attempted__` and `__attempts__` go.
  `classify_target_outcome`, both progress trackers, the session and `cmd_scan`'s
  summary read rows. A job that raises gets `failed:scanner error` rows from
  `scan_all`. History reads the rows from `.scan_metadata.json`'s `tool_runs`, which
  `cmd_scan` writes from what every target returned, so a target whose job raised
  (and wrote no `scan-timings.json`) is still in `scan_tool_runs`.
- **Pre-flight stops removing tools.** It still offers to install, and it still stops
  when `--allow-missing-tools` leaves nothing installed (#811). Otherwise every
  requested tool reaches the jobs, which resolve it and write `failed:not installed`
  or, with the flag, `skipped:not installed`. That is what makes B8's stripped-PATH
  run produce rows at all; today it exits 1 before any target.
- **Order per tool:** off-target, then the binary, then the content trigger, then the
  run. A target whose pruned walk yields no file fails every row first (G2). zap and
  nuclei are URL-only, so `repo` loses zap and `gitlab` loses nuclei from
  `TOOL_SCAN_TYPES`: the two deliberate differences from its old literal.
- **Stubs** stay for a skipped row of a tool that applies to the target type (not
  installed, or no content) and for a timeout, in the descriptor's shape. An
  off-target tool gets no file. The row, not the file, is the record.
- **`cost_class` becomes `timeout_floor`**, its one consumer (`TOOL_TIMEOUT_DEFAULTS`).
- **Exclusion styles**, from the table above: semgrep `--exclude=N`, gosec
  `-exclude-dir=N`, trivy `--skip-dirs **/N`, syft and grype `--exclude **/N`, checkov
  `--skip-path N`, trufflehog a generated file of `(^|[\\/])N[\\/]`, hadolint,
  shellcheck and yara walk-fed (yara_runner gains `--exclude-dir`), zap and nuclei
  "not a filesystem scan".
- **G2's tool-level count** is semgrep's `paths.scanned` and gosec's `Stats.files`, read
  from the output file. No other tool has a count that means files.
- **Defects routed**, filed and rostered in this branch: identical findings in two
  repositories collapse into one; gosec needs a Go toolchain that neither the image nor
  `jmo tools install` provides; GitLab's container-image discovery has never scanned
  an image (`scan_image` is called with `tool_exists_func`, which it does not take, so
  every call raises into the `except`; and its results would be discarded with the
  temporary directory).

**Correction (2026-09-25, before filing).** The fifth routed defect, "`jmo tools check`
probes a different semgrep from the one the scan runs", is false, and it was not
filed. Both resolvers return the same `~/.jmo/tools/venvs/semgrep/Scripts/semgrep.exe`.
That file is a pip launcher, and it finds its interpreter through `PATH`. Run bare,
with another Python's semgrep ahead on `PATH`, it printed 1.161.0. Run with the
venv's `Scripts` first, the way `ToolRunner` and the version probe both run it, it
prints 1.175.0.

Every `semgrep.json` a real `jmo scan` wrote in B1 and B8 says 1.175.0. The 1.161.0
came from B1's own bare invocations, so the hidden-list row was re-measured on
1.175.0, and it holds.

## Task B1a: A results folder unique per repository (#1303)

**Files:** `scripts/cli/scan_orchestrator.py` (discovery assigns the name; `_clone_tsv`
loses the refusal), `scripts/cli/scan_jobs/repository_scanner.py` (takes the name),
`scripts/cli/jmo.py` (session and progress use it).

- [x] Red first, through `jmo scan --targets` with two `app` repositories
  (`alice/app/alice.sh`, `bob/app/bob.sh`): today one folder, bob's findings only.
- [x] Discovery gives every repository a folder name unique in the scan,
  case-insensitively: a name that collides is prefixed with its parent's
  (`alice__app`, `bob__app`), and a numeric suffix settles a collision that survives
  that. A name that does not collide is unchanged. The session key, the target id in
  progress lines and `scan_tool_runs.target`, and `scans.targets` all carry it.
- [x] `_clone_tsv` loses its same-name refusal (`TODO(issue-#1303)`), and a test clones
  two repositories of one name and reports both.

**Done (2026-09-25).** Old code: one `individual-repos/app` and 2 findings. New:
`alice__app` and `bob__app`, 4 findings, both in `scans.targets`, 2 `scan_tool_runs`
rows. `repo_result_names` names each repository once, at discovery. `scan_all`, the
session and the progress lines read the name from there. `TestUniqueResultNames`
tests the case collision in both orders: a count keyed on one spelling passes in one
order only, and that is how mutation N2 first survived.

## Task B2: `ToolDescriptor` and the table

**Files:** Create `scripts/core/tool_descriptors.py`, `tests/unit/test_tool_descriptors.py`.
Modify `tool_registry.py`, `scan_utils.py`, `scripts/cli/tool_manager.py`.

**Interfaces:**
- Produces: `ToolDescriptor` (frozen dataclass): `name`, `target_types`,
  `trigger(ctx) -> SkipReason | None`, `invocations(ctx) -> list[Invocation]`,
  `exclusion_style`, `vendor_noise: bool`, `cost_class`, `version_probe`
  (command, pattern, timeout), `ok_return_codes`, `capture_stdout`, `stub_shape`,
  `scanned_count(path) -> int | None`. `DESCRIPTORS: dict[str, ToolDescriptor]`.
  `TOOL_MATRIX = tuple(DESCRIPTORS)`; `TOOL_SCAN_TYPES` derives from `target_types`.
- [x] Red first: `set(DESCRIPTORS) == set(TOOL_MATRIX)`; each of today's tables is
  **derived** from the descriptors and equals its pre-change literal (captured in the
  test from B1). Then build the table and delete the literals.

**Done (2026-09-25).** `scripts/core/tool_descriptors.py` holds 12 descriptors in
`TOOL_MATRIX` order. `tests/unit/test_tool_descriptors.py` pins each derived table
against its pre-change literal, and every difference is a named one:

- `repo` loses zap and `gitlab` loses nuclei (URL-only).
- shellcheck, gosec and yara declare the `{}` stub they already fell back to.
- syft and grype (`--exclude`) and gosec (`-exclude-dir`) gain an exclusion.
- trufflehog, hadolint, shellcheck, gosec and yara join the vendored tier.

The field list differs from the Interfaces line above, by the B1 rulings:

- `cost_class` became `timeout_floor`.
- `invocations` maps target type to builder.
- `vendor_noise` became `excluded_vendored`.
- `stub_shape` became `stub`.
- `ok_return_codes` and `capture_stdout` live on each `Invocation`.

Mutations DV1-DV14 were all caught.

## Task B3: Six scan jobs iterate the table

**Files:** `scripts/cli/scan_jobs/{repository,iac,image,k8s,url,gitlab}_scanner.py`.

- [x] One generic loop: for each requested tool whose descriptor applies to the target
  type, resolve the binary, evaluate the trigger, render exclusions, build the
  invocations, and hand them to `ToolRunner`. Every branch returns a row; none returns
  nothing (#1227).
- [x] For each job, the B1 golden record reproduces, except for the changes this phase
  intends (the rows B4 adds). Diff the artifacts, not the log lines.

**Done (2026-09-25).** `scripts/cli/scan_jobs/tool_loop.py`'s `run_tools` is the loop.
The five jobs are thin wrappers around it, and gitlab delegates to `scan_repository`
with `target_type="gitlab"`. Re-running the golden repository fixture gave 12 rows
where it had given 9. On a tree with nothing for them, hadolint and shellcheck now
read `skipped:no Dockerfiles` and `skipped:no shell scripts`. Before, they had no
row, no file and no mention. Found on the way and fixed: checkov's content trigger
fired on an IaC **file** target, which has no tree to walk, so a file scan would
have been skipped. Triggers now run only on a tree
(`test_checkov_runs_on_a_file_target_with_no_tree_to_walk`). GitLab's image
discovery still runs and still raises a `TypeError` on every image, logged as an
ERROR, as it always has. What was removed is the merge of its statuses, which
never existed, into the repository's rows. #1311 decides fix or remove.
Mutations L1-L23 were all caught.

## Task B4: The accounting record, `scan-timings.json` v3, `scan_tool_runs`

**Files:** `scripts/core/scan_timings.py`, `scripts/core/history_db.py`,
`scripts/cli/jmo.py` (end-of-scan summary, `.scan_metadata.json`),
`scripts/cli/scan_orchestrator.py:307` (`classify_target_outcome`, `:988` unrouted),
`scripts/cli/rich_progress.py`, `scripts/dev/reconcile_scan_accounting.py`.

- [x] Row: `tool`, `state`, `reason`, `seconds`, `exit_code`, `attempts`, `invocations`.
  Schema v3. **Every requested tool has exactly one row per target**, including
  `skipped` ones. The reconciler reads rows instead of scraping logs, and its invariant
  becomes a test.
- [x] `scan_tool_runs(scan_id, target, tool, state, reason, seconds, exit_code, attempts)`,
  `CREATE TABLE IF NOT EXISTS` in `init_database` like `scan_metadata`. Test against
  every historical schema shape in `tests/` (the 1.1.0 `CHECK(profile)` trap).
  `store_scan` reads the rows from each target's `scan-timings.json`.
- [x] `jmo history show <id>` prints per-tool state and seconds (#722's "why is my scan
  slow" question).

**Done (2026-09-25).** `ToolRun` (`scripts/core/scan_timings.py`) refuses a
state/reason pair that does not go together, and the reasons are a closed enum.
Rulings: the row also carries `detail` (in JSON only); the table adds `target_type`
to its key, because a repository and an IaC file can share a name; and `store_scan`
reads `.scan_metadata.json`'s `tool_runs`, not each `scan-timings.json`, because a
target whose job raised writes no timings file but still has rows.

`tests/unit/test_history_tool_runs.py` drops the table from the 1.2.0, 1.1.0 and
post-v2 shapes and stores into each. The table is created, the rows land, the old
scan's findings survive, and `integrity_check` is `ok`. `history show` prints a
"Tool Runs" section, and a read-only database without the table still shows.

The reconciler checks rows now: missing, duplicate, stray, invalid, `ran` with no
parseable output, and a timings document the metadata does not know. Each of those
checks has a negative control. Mutations H1-H13, R1-R6, S1-S3 and M1-M2 were all
caught. H6, S3 and M2 first survived on test inputs too narrow to tell, and each got
a sharper test.

## Task B5: One exclusion list, rendered for every tool (#1235)

**Files:** `scripts/cli/scan_utils.py` (`excluded_dirs_for`, `tool_exclusion_flags`),
`scripts/core/yara_runner.py`.

- [x] Tiers: source readers and secret scanners get `VENDORED_DIRS` + the in-tree results
  directory; syft and grype get the results directory only, plus `.venv`/`venv` for
  grype. Every descriptor declares a style, and **"none" is not a style**: a tool with
  no exclusion syntax is walk-fed or documented as unable to exclude. Test: the rendered
  command for every descriptor excludes an in-tree `results/`, **syft included**.
- [x] Measure on the Next.js application from the decision above, through `jmo scan`:
  trufflehog time and findings before/after. Record counts only.
- [x] File grype's `.venv` exclusion issue (promised on #1235) and roster it in this PR, or
  fold it into #1235's corrected body if Jimmy prefers. Decide at PR time. **Folded
  into #1235** (Jimmy, 2026-09-25): PR B implements it, and #1235's body says so.

**Done (2026-09-25); the grype `.venv` item is folded into #1235.** On the Next.js application,
through `jmo scan --tools trufflehog`: **281.0 s and 253 findings (222 in
`node_modules`) before, 12.0 s and 31 (0 there) after.** With an in-tree `results/`
holding a previous scan's `requirements.txt`, syft and grype read it on the old code
and skip it on the new one.

Styles are rendered as measured in B1. trufflehog's patterns are anchored
`(^|[\\/])N[\\/]`, so a root `results/` is excluded in git mode too. yara_runner
takes `--exclude-dir` (a ruling: an INLINE style to JMo's own runner). Its
`SKIP_DIRS` is `VENDORED_DIRS` itself, not a copy. semgrep's built-in list stays,
and `docs/KNOWN_LIMITATIONS.md` records it (Unresolved #3, decided). Mutations
E1-E2, Y1-Y3 and L15-L18 were all caught.

## Task B6: G2 — zero examined is `failed` (#1231)

- [x] Target level: a repository whose walk yields 0 files after exclusions is
  `failed:no files to scan` before any tool runs.
- [x] Tool level: a descriptor with `scanned_count` whose output says 0, on a target where
  the walk found files, is `failed:examined 0 files`. Fixture: #1231's A/B, a plain
  directory under an unrelated git work tree, where semgrep reports `paths.scanned` 0.

**Done (2026-09-25).** On an empty tree, the old code graded trivy and semgrep
`success` with rc 0. Now both rows read `failed:no files to scan` and the scan exits
1. The tool level reads semgrep's `paths.scanned` and gosec's `Stats.files` from the
output file, as B1 decided. gosec's has read 0 on every run on this host and in the
image, which have no Go toolchain, so on a Go repository it is now
`failed:examined 0 files`, where it used to pass as success (filed, see the routed
defects). The #1231 A/B was not re-run as a real semgrep scan inside a foreign work
tree. The tests feed the loop semgrep output with `paths.scanned` of 0 and of 4.
Mutations L4, L5, D8 and D9 were all caught.

## Task B7: Tool names (#1279)

**Files:** `scripts/cli/jmo.py:80-92,203-206`, `scripts/core/config.py:309-310`,
`scripts/cli/scan_orchestrator.py:988-994`; the six e2e sites in
`tests/e2e/test_scan_workflows.py` and `test_docker_workflows.py`.

- [x] Split on commas and whitespace for `--tools`, `--skip-tools` and `tools:`; an unknown
  name exits 2 with its name, and "removed in v2.0.0" for the cut sixteen. Red first
  with `--tools trivy,syft` and `--tools bandit`.
- [x] Defaulted tools never produce the "requested but applicable to no target type"
  line; they are `skipped:needs --url` rows.

**Done (2026-09-25).** Measured against the old code:

| Input | Old | New |
|---|---|---|
| `--tools checkov,trivy` | rc 1, "None of the requested tools are installed: checkov,trivy" | rc 0, both ran |
| `--tools bandit` | rc 1, "applicable to no target type" | rc 2, "removed in v2.0.0" |
| `jmo.yml` `tools: [trivy, bandit]` | rc 0, one WARN | rc 2, naming it |

`parse_tool_names` is the one parser, used by the argparse action and by `jmo.yml`.
`ScanConfig.explicit_tools` keeps the "applicable to no target type" warning to
names the user typed. Two riders were decided in B1:

- `--dest` without `--tsv` now exits 2 (it used to run with rc 0).
- `include`/`exclude` drop a TSV row before it is cloned.

The six e2e `--tools trivy,syft` sites now select two tools, because the parser
changed and not the sites. Mutations D10-D13, J1-J2, F1-F3 and O1 were all caught.

## Task B8: Gates, then PR B

- [x] Acceptance on a fixture with no Dockerfile, shell or IaC, through `jmo scan`: rows
  sum to `len(TOOL_MATRIX)`, each `ran` or `skipped:<reason>`; hadolint, shellcheck,
  gosec, checkov `skipped` with the content reason, zap and nuclei `skipped:needs --url`.
  Repeat with `HOME` and `PATH` stripped: every row `failed:not installed`, still summing.
- [x] #722: `scan_tool_runs` holds a row with `seconds` for every tool of that scan.

**Acceptance measured (2026-09-25).**

- **Plain fixture.** 12 rows, each `ran` or `skipped:<reason>`. The one exception is
  yara, `failed:not installed`, because this host lacks yara-python. The reconciler
  passes.
- **`HOME` and `PATH` stripped.** 12 rows: 10 are `failed:not installed`, and zap and
  nuclei are `skipped:needs --url`. rc 1, and the reconciler passes. The old code
  exited 1 before any target and wrote 0 rows.

That second count is a ruling. The plan's order decides off-target before the binary
(B3), so the two URL tools say why they did not run, not whether they are installed.

URL, run with the real tools:

| Tool | Old | New |
|---|---|---|
| zap | rc 1, "Unable to access jarfile" | ran in 18.9 s, `zap.json` 16.6 KB |
| nuclei | rc 2, `-json` undefined | ran in 113 s |

`scan_tool_runs` gets a row per tool with its seconds
(`test_every_row_reaches_scan_tool_runs`, `test_each_row_keeps_its_targets_type`).

**Final review (2026-09-25).** A fresh reviewer found 0 Critical, 3 Important and 14
Minor. The three Important, plus two Minor re-graded by their effect, were fixed, each
red before green:

- **#787 regressed.** Pre-flight now keeps a missing tool, so `scans.tools` and
  `findings.json`'s `meta.tools` named uninstalled tools. They now come from the
  rows: a tool with a `ran` row.
- **Resume lost rows.** A resumed scan's skipped targets had no rows. The session
  keeps each completed target's rows, under the name its job recorded them by.
- **Exclusions matched the scan root.** Measured with the real binaries:
  - trufflehog read nothing in a repository under `vendor/`. Its patterns are now
    anchored below one resolved root.
  - gosec's `.git` also dropped `.github/x`, a substring match. The claim that it
    matched the root was measured false: gosec matches root-relative paths. Its
    names are now escaped, whole-segment regexes.
  - `collect_files` tested absolute parts. It now tests parts relative to the repo.
- **`jmo ci` ignored the scan's exit 2** and ran its report over an earlier run's
  results. It now stops there.
- **A scan in which no tool ran was stored in history**, where it reads as every
  finding resolved. It is not stored now.

Routed, not fixed: #1312 (URL and IaC folder collisions, #1303's class) and #1313
(checkov's `--skip-path` substrings, unmeasured). Measured false and closed: semgrep on
a docs-only repository scans both files (`paths.scanned` 2). Suite 8960 / 98 / 0.
- [ ] Suite ID-set diff; `windows-2022` log line; both CI events.

---

## Task C1: Measure first (PR C)

- [ ] gitleaks 8.30.1 release assets and checksum file for each OS/arch the installer
  supports; whether `versions.yaml`'s `release_pattern` shape fits.
- [ ] Dedup between the two modes: a secret present in the tree **and** in history,
  through `jmo report`. Is it one finding or two, per tool and after cross-tool dedup
  (pre-dedup ≠ post-dedup)?
- [ ] Every consumer that globs `<out_dir>/*.json` (the report loader, the reconciler,
  e2e file counts, `.scan_metadata.json` readers), before choosing the git-mode file
  name (`<tool>.git.json`, loader maps the stem before its first `.`).

## Task C2: gitleaks wired

**Files:** `versions.yaml` (then `update_versions.py --sync`), `scripts/core/install_config.py`,
`scripts/core/tool_descriptors.py`, `scripts/cli/tool_manager.py` (probe),
`Dockerfile` (via sync only); the ~25 documents
`test_tool_catalogue_count_claims.py` names when `TOOL_MATRIX` reaches 13.

- [ ] Descriptor: `gitleaks dir <repo> --report-format sarif --report-path <out>
  --no-banner --exit-code 0 --config <generated>`; the config renders the single
  exclusion list.
- [ ] Gate through `jmo scan` on the archived juice-shop at `1618a611`: **69**, the Phase 1
  golden. Report the post-dedup number beside it.

## Task C3: G1 — history for both secret scanners

**Files:** `scripts/core/tool_descriptors.py` (a `git` invocation on trufflehog and
gitleaks, gated on `.git`), `scripts/core/adapters/trufflehog_adapter.py`,
`scripts/core/adapters/sarif_common.py` (+ the gitleaks spec),
`scripts/core/plugin_loader.py` / `normalize_and_report.py` (the naming rule).

- [ ] Fixture helper in `tests/`: build a repository, commit a key generated at test time,
  delete it in the next commit. Never a checked-in key: Defender and the repository's
  own secret scanning both act on one.
- [ ] Red first, through `jmo scan`: today 0 findings. After: one finding per tool with
  `secretContext.commit` = the adding commit, plus `author` and `date`, and
  `location.path`/`startLine` from `Data.Git` / the SARIF location.
  `secretContext.secret` is never written.
- [ ] One accounting row per tool: invocations `[dir|filesystem, git]`, `failed` if either
  failed, and the reason names the invocation.
- [ ] Exclusions apply to git mode (this repository's history is the noise case).
- [ ] Gate: the fixture reports the commit hash through both tools; time on this
  repository with and without git mode recorded in the PR.

---

## Acceptance (Phase 3)

On a fixture with no Dockerfile, shell or IaC, the accounting sums to **13**, each tool
`ran` or `skipped:<reason>`. A repository whose only secret is in a deleted commit reports
it with a commit hash, through trufflehog and gitleaks. Exclusions are rendered for every
tool, syft included. A scan of zero files is `failed`. #722's per-tool duration is in
`scan_tool_runs`. gitleaks through `jmo scan` on juice-shop = 69. Every command the
wizard generates, native and Docker, parses through `build_parser()`, and `jmo scan
--tsv` scans what it cloned. Suite green;
`windows-2022` shows no new failures against 8685 / 90 / 181.

## Unresolved

1. **trufflehog verifies secrets over the network by default**, and git mode adds calls.
   Spec §11's "no network call" is a program criterion. Does `--no-verification` become
   the default (and verification a `--with` option), and in which phase?
2. ~~**grype's `.venv` exclusion:** its own issue (as promised on #1235) or folded into
   #1235's body? Decide at PR B.~~ Folded into #1235 (Jimmy, 2026-09-25).
3. **semgrep brings a second exclusion list.** With no `.semgrepignore`, semgrep applies
   a built-in one (`tests/`, `test/`, `node_modules/`, …): measured in A4, a directory
   under `tests/` scanned 0 files on Windows and on Linux. B5's single list competes
   with it. Measure it in B1: what a real scan's semgrep skips, and whether B5 renders
   an explicit `.semgrepignore`.
4. ~~The shellcheck contract sample is neutered.~~ Resolved in PR A (a rider, Jimmy
   2026-09-25): see "PR A riders".
5. ~~The wizard's Docker branch drops four more settings.~~ Resolved in PR A under #1298
   (Jimmy 2026-09-25): see "PR A riders".
