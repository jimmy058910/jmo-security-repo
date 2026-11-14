# Phase 7 — memory-gated scheduler, process trees, Ctrl-C: task plan

> **Status: approved 2026-11-05 (10:05 EST), every recommended option** (see
> [Decided](#decided-2026-11-05-jimmy)). PR 7a, the small measured fixes, lands first;
> PR 7b builds this.
>
> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use
> checkbox (`- [ ]`) syntax.

**Goal:** a scan's tools run under one scan-wide memory budget and one CPU slot count,
each tool carrying a measured cost class; Ctrl-C stops the scan and leaves no process
behind on any platform; opengrep's findings stop depending on what else runs; and
these open issues close: #1208, #1308, the osv-scanner retry round's #1373, zap's
issue #1422, `--timeout`'s #1486, the startup version probe's #1581, the
`--gitlab-group` placeholder of #1407, opengrep's loss under load (#1591), and
zizmor's unread `.pre-commit-config.yaml` (#1592) (PR 7a closes #1406).

**Architecture:** one PR, 7b, after 7a merges. The gate and the process registry are
two small objects in `scripts/core/tool_runner.py` that `scan_all` installs for the
scan and clears after it; every tool run passes through both. Cost classes live on
`ToolDescriptor`, beside `timeout_floor`.

**Spec:** program plan § Phase 7 (`2026-09-12-v2.0.0-program.md`, A4), measured below.

## Measured before this plan (2026-11-05, Debian, `1406db9f`, app B)

App B: the private npm web app the program plan names (485 MB checkout). Tree memory
was sampled at 4 Hz over the whole process tree (`jmo` and every child, the sampler a
child subreaper so orphans stay counted); PSS agreed with RSS within 4%. Scratch HOME
with its own osv database; about 10 GB free; nothing else contaminated a run.

| What | Number |
|---|---|
| Default matrix, peak tree RSS | **1,314 MB** (PSS 1,292); a second run 1,302 MB |
| At that peak | osv-scanner 593, opengrep 523 (core 317, CLI 160, launcher 46), yara-x 147, jmo 48 |
| Wall | 85 s: 40 s startup version probe, 40 s scan, 4 s report |
| Ctrl-C 3 s into the scan phase | after 5 s: jmo and 5 scanner processes alive; the scan **finished 13.6 s later, wrote its report and history, exit 0** |
| Ctrl-C during the startup probe | jmo and the probe die (rc -2), 0 left |
| Threads alive at the end of a `tests/cli` session | **115**: 114 `refresh_loop`, 1 `run_server` (2,755 passed) |

Each tool alone through `jmo scan --tools <t>` (peak tree including jmo's ~45 MB), and
direct runs of the exact command where a flag was tried. The `jmo scan --tools`
runs (09:51:38-09:54:19 EST) were on a quiet machine, as was the baseline above. The
direct opengrep `-j` and trufflehog `--concurrency` runs (09:56-09:57) overlapped
another lane's full test suite on 4 of the 8 cores (09:54:23-10:04:37): a tool's own
memory is its own, so their peaks stand, but their wall times are upper bounds.

| Tool | Peak | Wall | Note |
|---|---|---|---|
| trufflehog | 1,037 MB | 12 s | two runs at once: filesystem 488 alone, git 553-565 alone; `--concurrency 2` changes neither |
| opengrep `-j 4` (today) | 662 MB direct, 680-732 via jmo | 12 s | 42 findings at every `-j` |
| opengrep `-j 2` | 507 MB | 13 s | |
| opengrep `-j 1` | 393 MB | 14 s | |
| osv-scanner | 632 MB | 11-23 s | npm's offline database loaded whole |
| gitleaks | 240-373 MB | 3-6 s | two runs (tree, history) |
| syft, trivy | 245 MB each | 10 s, 6 s | |
| yara-x | 199 MB | 16 s | |
| shellcheck, jmo-native, zizmor | 93, 81, 65 MB | 2-4 s | mostly jmo's own 45 MB |

Not measured here: checkov, hadolint (app B has no IaC or Dockerfile), zap, nuclei
(URL tools). Two hidden costs seen: trufflehog's history run clones the repository into
`$TMPDIR`, which is RAM on a tmpfs `/tmp` and invisible to process RSS; and the startup
probe runs zap's `-version` through `zap.sh`, which sized its JVM at `-Xmx7008m`
(385 MB RSS, 26 s, on a scan with no URL target: #1581, Task B8).

**opengrep loses findings under load** (measured by the golden lane, 2026-11-05,
opengrep 1.32.0 at `-j 4`, 12 tools concurrent). juice-shop `1618a611`: `jmo scan
--tools opengrep` reads 223 raw results, twice; the full matrix reads 204, all 19
missing from `frontend/src/assets/private/three.js`. WebGoat `7e198f39`: 428 alone,
twice, against 402 in the full scan, all 26 missing from
`src/main/resources/webgoat/static/js/libs/ace.js`. In the full scan opengrep logs
`Memprof_limits.Limit_reached` ("Other syntax error") on that file and returns nothing
from it; alone, no error. Scanned-path sets identical, no timeout. JMo passes no memory
limit: the core runs with `-max_memory 0 -j 4 -timeout 5 -timeout_threshold 3`
(measured here), so what trips is not a limit JMo sets. A user's finding count moves
with machine load, which is the 1,314 MB overlap from another angle.

**Where concurrency comes from today:** `scan_all`'s pool runs `threads` targets
(`jmo.yml` 4, else `_get_max_workers`), and each target's `ToolRunner` runs 4 tools
(`tool_runner.py` `max_workers: int = 4`, never overridden by `tool_loop.py:928,956`).
One target: 4 tools at once. A `--repos-dir` of many: up to 16.

**Why Ctrl-C does nothing:** `cmd_scan` installs a SIGINT/SIGTERM handler that sets
`stop_flag` and saves the session (`jmo.py:3304-3320`); nothing reads `stop_flag`. The
scanners run with `start_new_session=True` (`tool_runner.py` `_run_bounded`), so a
terminal's SIGINT never reaches them, and if jmo is killed they are orphaned. On
Windows there is no Job Object; `taskkill /T` runs only on a timeout.

**What the 700 MB target implies:** opengrep alone at `-j 4` peaks at 680-732 MB with
jmo, and trufflehog's two concurrent runs at 1,037 MB, so no schedule of today's
invocations stays under 700 MB. With opengrep at `-j 2` and every tool over ~300 MB
run one at a time, the predicted peak is the largest single run plus jmo and a light
tool: about 640-700 MB. The scan phase on app B would go from about 40 s to about
70-80 s (the sum of the heavy tools' walls above). On this 28 GB machine a
RAM-derived budget would change nothing.

## Decided from measurement (veto any in review)

1. **Cost classes are per invocation, in MB, measured, on the descriptor:**
   `ToolDescriptor.memory_mb`, a run's peak rounded up to 50 MB, its source in a
   comment. trufflehog 600, opengrep 550 (at `-j 2`), osv-scanner 650, gitleaks 400,
   syft 250, trivy 250, yara-x 200, shellcheck 100, zizmor 100, jmo-native 100.
   checkov, hadolint, zap and nuclei are measured in Task B1 before a value is set; a
   tool with none gets 500 until measured (`tests/unit/test_tool_descriptors.py`
   fails on a missing one).
2. **opengrep runs at `-j 2`** (`tool_descriptors.py:989`): 507 MB against 662,
   1 s slower, the same 42 findings.
3. **One gate per scan, not per target.** A target pool of 4 times 4 tools is the
   multiplication the gate exists to bound. `ToolRunner` keeps its per-target pool
   for ordering, and every run waits on the scan's gate.
4. **The gate admits a run when the running total plus its cost fits the budget, or
   when nothing else is running** (a run larger than the budget runs alone, never
   blocks forever). First come, first served, so a large run is not starved by small
   ones. A second limit, CPU slots, is `threads`: the gate replaces `threads x 4`.
5. **zap is exclusive** (#1422): `ToolDescriptor.exclusive=True`, one zap run per scan
   at a time, so two URL targets no longer share one ZAP home at once.
6. **A killed run is `failed:interrupted`**, a new `Reason`, never `ran` with whatever
   it wrote.
7. **trufflehog's temporary clone moves to disk.** Its history run clones the
   repository into `$TMPDIR`; on a tmpfs `/tmp` that is RAM no process's RSS shows, so
   the gate could not count it. trufflehog runs with `TMPDIR` set to a folder under the
   scan's results directory, removed after the run. Its clone size on app B is measured
   in Task B1 and recorded. **Changed in review (2026-11-05):** the folder is
   `~/.jmo/tmp/<jmo pid>-<target hash>-trufflehog-git`, not under the results, which CI
   uploads whole: a clone a killed jmo leaves holds the history's secrets. A scan's
   start removes what a jmo no longer running left there. Accepted by the coordinator
   for that reason, 2026-11-05.
8. **opengrep's loss under load (#1591) is its per-file timeout, so the lever is that
   timeout** (measured in Task B1, below; not memory: JMo passes `-max_memory 0`).
   opengrep runs with an explicit `--timeout 30`; the gate (Task B2) is the second line.
   Excluding minified vendored bundles stays the last resort, since it trades the loss
   for a coverage gap. Accepted only on the counts: juice-shop 223 and WebGoat 444 under
   the full matrix at the default budget, three runs each. (This said 428, golden's count
   with opengrep alone at its own 5 s timeout, which drops `ace.js`'s 16 results even
   alone; at 30 s opengrep alone reads 444. Measured in Task B7.)

## Tasks (PR 7b)

### Task B1: measure the rest, then cost classes on the descriptors

**Files:** `scripts/core/tool_descriptors.py`, `scripts/dev/peakmem.py` (new: the
sampler used above, so the numbers can be re-run), `tests/unit/test_tool_descriptors.py`

- [x] Commit the sampler as `scripts/dev/peakmem.py` (Linux `/proc`; prints peak RSS
  and PSS, wall, and the processes left N s after a SIGINT).
- [x] Measure checkov and hadolint on a fixture with IaC and Dockerfiles, nuclei and zap
  on the ZAP fixture site, and osv-scanner's per-lockfile retry round on 20 npm
  lockfiles with one truncated (#1373).
- [x] trufflehog's history clone on app B: its size in `$TMPDIR` (Decided 7).
- [x] opengrep under load (#1591, Decided 8): reproduce golden's loss on juice-shop's
  `three.js` and WebGoat's `ace.js` with opengrep alone beside a process holding a
  fixed amount of memory, stepping it up; record the free memory at which
  `Limit_reached` appears, at `-j 4` and `-j 2`, and with `--max-memory` set. That
  says which lever moves it.
- [x] Test first: every descriptor has `memory_mb > 0`; trufflehog's two invocations
  each carry it. Then add the field and the values.

### Task B1 record (measured 2026-11-05)

Each tool alone through `jmo scan --tools <t>` under `scripts/dev/peakmem.py --pss`,
scratch HOME, peak of the tree including jmo's ~45 MB:

| Run | Peak RSS | Peak PSS | Wall | Note |
|---|---|---|---|---|
| nuclei, the ZAP fixture site | 1,449 MB | 1,441 MB | 303 s | nuclei alone 1,404 MB: its whole template set, the largest single run |
| osv-scanner retry round, 21 npm lockfiles, one truncated (#1373) | 2,447 MB | 2,326 MB | 60 s | 4 runs at once, about 600 MB each: npm's database per run |
| zap, the ZAP fixture site | 600 MB | 588 MB | 23 s | java 554 MB on a small site; `zap.sh` had sized the heap at `-Xmx7008m` (a quarter of RAM), not 512 MB |
| checkov, terragoat (47 `.tf`) | 390 MB | 235 MB | 8 s | two processes sharing pages: PSS is the honest figure |
| hadolint, juice-shop (3 Dockerfiles) | 54 MB | 42 MB | 1 s | finished in 0.06 s, under one sample |
| trufflehog's history clone in `$TMPDIR`, app B | 329 MB | | | files, not RSS: RAM on a tmpfs `/tmp` (Decided 7) |

**opengrep loses findings to its own per-file timeout** (#1591), on juice-shop
`1618a611`, opengrep alone unless named:

| Run | Results | Error on `three.js` |
|---|---|---|
| default (`-timeout 5`, opengrep's own) | 223 | one rule `Timeout`, even at rest |
| `--timeout 1` | **204**, golden's full-matrix count | "Other syntax error ... Memprof_limits.Limit_reached: token set", golden's error |
| `--timeout 30` | 223 | none |
| full matrix, default, load average 15.6 | 223 | one rule `Timeout` |
| full matrix, `--timeout 30`, load average 9.9 | 223 | none |

The timeout is delivered through the `Memprof_limits` token, so a parse it cuts short
reads as a syntax error and the whole 836 KB file is dropped: 19 findings. Under load
the loss is intermittent: it happens when parsing the file crosses 5 s, which the
full-matrix run at load 15.6 did not. WebGoat's `ace.js` is not yet measured.

### Task B2: the scan-wide gate

**Files:** `scripts/core/tool_runner.py`, `scripts/cli/scan_orchestrator.py`,
`scripts/cli/scan_jobs/tool_loop.py`, `tests/unit/test_tool_runner.py`

- [x] Test first, with fake tools that only sleep: under a 600 MB budget two 550 MB
  runs never overlap and two 100 MB runs do; a 900 MB run under a 600 MB budget runs
  alone and finishes; a waiting run wakes when the stop event is set; CPU slots bound
  the count whatever the budget.
- [x] `MemoryGate` (a `threading.Condition` with a FIFO ticket) and `CpuSlots`; a
  module-level `scan_limits()` that `scan_all` sets for the scan and clears in
  `finally`, unlimited when unset so a direct `ToolRunner` use is unchanged.
- [x] `ToolDefinition.memory_mb` from the descriptor in `tool_loop.definition()`;
  `ToolRunner.run_tool` holds a slot and the gate around the run, retries included.
- [x] Budget: `jmo.yml` `memory_budget_mb` and `--memory-budget`; the default is half
  the memory free at scan start, never below 700 MB (Decided 1), read with `psutil`
  (Decided 2). `psutil` reaches `pyproject.toml` and `uv.lock` in the installer lane's
  PR 1; until it merges it is installed into this worktree's `.venv` only
  (`uv pip install psutil`), and 7b rebases onto `dev` after it.
- [x] `tool_loop.py` lines 792-803 (the missing-tool message) are the installer lane's
  (#1577): this task keeps clear of them, and whichever lands second rebases.

### Task B3: process trees die with the scan

**Files:** `scripts/core/tool_runner.py`, `scripts/cli/clone_from_tsv.py`,
`scripts/cli/scan_jobs/gitlab_scanner.py`, `tests/unit/test_tool_runner.py`,
`tests/cli/test_clone_from_tsv.py`

- [x] A process registry in `tool_runner.py`: `_run_bounded` adds each `Popen` on
  start and removes it on exit; `terminate_all()` kills every registered tree
  (`_terminate_tree`, which already does `killpg` and `taskkill /T`).
- [x] Windows: at scan start jmo assigns itself to a Job Object with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (ctypes, `kernel32`), so every descendant dies
  when jmo exits however it exits. Nested jobs need Windows 8 or later.
- [x] The first-run lane's guard (#1285) requires `timeout=` on every
  `subprocess.run`, `check_output` and `call` under `scripts/cli` and `scripts/core`.
  It does not cover `Popen`, which `_run_bounded` uses; every `Popen` here is bounded by
  `communicate(timeout=)` and killed as a tree on expiry, and a unit test says so for
  each `Popen` in the file.
- [x] #1308: `clone_from_tsv.run` and the GitLab clone go through `_run_bounded`.
  Test first: a fake `git` that starts a sleeping grandchild and writes its pid;
  timed out at 1 s, the grandchild is gone (POSIX `os.kill(pid, 0)`).

### Task B4: Ctrl-C

**Files:** `scripts/cli/jmo.py` (the handler in `cmd_scan`), `scripts/cli/scan_orchestrator.py`,
`scripts/core/tool_runner.py`, `scripts/core/scan_timings.py` (the new `Reason`),
`tests/cli/test_scan_interrupt.py` (new)

- [x] Test first (POSIX, subprocess): `jmo scan` with two fake tools that each start a
  sleeping grandchild; SIGINT to jmo's process group once both run; within 5 s jmo has
  exited 130 and no process it started is alive. Negative control: the same test
  against today's code shows them alive.
- [x] The handler sets a scan-wide stop event and calls `terminate_all()`; the gate
  wakes its waiters; `scan_all` stops submitting (`shutdown(cancel_futures=True)`);
  killed runs are `failed:interrupted`; the session is saved; jmo exits 130 with no
  report, and `jmo scan --resume` finishes the scan (Decided 3). A second Ctrl-C exits
  at once.

### Task B5: no thread outlives the test session (#1208)

**Files:** `scripts/cli/jmo.py` (`ProgressTracker`; the first-run lane adds an early
return to `_write_progress_line`, #1082, and the rest is this task's),
`tests/cli/test_progress_tracker.py`, `tests/conftest.py` (p9-code's file: the
session-end check is approved for 7b, added beside p9-code's `pytest_configure` git-env
scrub once its PR 2 is in `dev`)

Measured baseline: **115 threads alive at the end of a `tests/cli` session** (2,755
passed): 114 `refresh_loop`, 1 `run_server`. The target is 0.

- [x] `ProgressTracker` is a context manager whose exit calls `stop()`; `cmd_scan` uses
  it; the tests that start one stop it.
- [ ] A session-end check that no non-daemon thread and no `refresh_loop` thread is
  alive (the one `run_server` thread seen is a test server, to be found and closed).
  Built for `refresh_loop`; after the fix one thread is left, `run_server`, a
  dependency's, so a check on every non-daemon thread would fail on it.

### Task B6: zap (#1422), `--timeout` (#1486), the placeholder (#1407), zizmor (#1592)

**Files:** `scripts/core/tool_descriptors.py`, `scripts/cli/scan_utils.py`
(`tool_timeout`), `scripts/cli/jmo.py` (`--timeout` help), `scripts/cli/scan_orchestrator.py`

- [x] zap `exclusive=True`; test: two URL targets, both zap rows `ran`.
- [x] zap's heap: `per_tool.zap.heap`, default `512m`, passed as `-Xmx` to `zap.sh` and
  to the java line alike (Decided 4). A run reserves heap + 90 MB (`zap_heap`); a size
  without a unit is refused with a warning, since java reads `1024` as bytes.
- [x] An explicit `--timeout` wins over opengrep's and zap's 900 s floors, as
  `per_tool.<tool>.timeout` does; `jmo.yml`'s `timeout` does not; the help says so
  (Decided 5).
- [x] Once the first-run lane has removed `--gitlab-group`, delete
  `_discover_gitlab_repos`' `group:` placeholder (`scan_orchestrator.py:967`).
- [x] zizmor reads `.pre-commit-config.yaml` (#1592): zizmor 1.31 audits it
  (`archived-uses`, `typosquat-uses`, `insecure-url-scheme`), and JMo never hands it
  over. Add `.pre-commit-config.yaml` and `.pre-commit-config.yml` to zizmor's
  `file_patterns`. The golden lane's
  `tests/integration/test_zizmor_answer_key.py::test_jmo_hands_zizmor_no_pre_commit_config`
  (PR F) then fails by design: in the same commit it is flipped into the answer key's
  scope, so this item waits for PR F in `dev`.

### Task B8: the startup probe asks only the tools a scan can run (#1581)

**Files:** `scripts/cli/jmo.py` (`_warn_critical_updates`, `_check_scan_tools`),
`tests/cli/` (the probe's tests)

Measured: 44.5 s before the first scan line on a first run, 25.9 s of it zap's
`-version` (its JVM sized at `-Xmx7008m`), on a repository scan where zap cannot run.

- [x] Test first: a repository-only scan probes no URL-only tool (zap, nuclei), counted
  through a recording `ToolManager`; a scan with a URL target still probes them.
- [x] Restrict both to the requested tools that read at least one present target type
  (`TOOL_SCAN_TYPES`). A tool left out still gets its row, `skipped`, as today.
- [x] Record first-run startup on app B before and after.

### Task B7: gates, then PR 7b

- [ ] Targeted tests; one full suite with the coordinator's go-ahead.
- [x] **The evidence CI cannot give:** app B's default matrix under
  `scripts/dev/peakmem.py`, with `--memory-budget 700` (the 700 MB acceptance, Decided
  6) and at the default budget: peak, wall, and processes left 5 s after a SIGINT 3 s
  into the scan phase, against the baseline above (1,314 MB, 85 s, 6 alive). Measured
  with no other suite running. Numbers in the PR body.
- [x] opengrep's counts under the full matrix at the default budget (#1591): juice-shop 223,
  WebGoat 444, three runs each (Decided 8).
- [x] The thread count at the end of a `tests/cli` session: 0 (was 115).
- [ ] Windows: Ctrl-C and the Job Object checked on a Windows machine by a script Jimmy
  runs (CI cannot send a console Ctrl-C).

### Task B7 record (measured 2026-11-05)

App B, default matrix, scratch HOME, `scripts/dev/peakmem.py --pss`, 14:13-14:15 EST,
load average about 2 on 8 cores, no other suite running. Head `0eef180a`:

| Run | Peak RSS / PSS | Wall | Findings |
|---|---|---|---|
| Baseline this morning, `1406db9f` | 1,314 MB | 85 s | |
| `dev` `2662c99a`, same afternoon | 1,295 / 1,274 MB | 28.1 s | 313 |
| Head, `--memory-budget 700` | 647 / 639 MB | 34.8 s | 313, same ids and rows |
| Head, default budget (10,020 MB here) | 1,399 / 1,374 MB | 19.1 s | 313, same ids and rows |

- At 700 MB the peak is the largest run plus jmo (osv-scanner 598 MB, jmo 48 MB), as
  predicted.
- Ctrl-C 3 s into the scan phase: jmo exited 130, 0.53 s after the signal, with 0
  processes left 5 s later (the baseline had 6 left).
- trufflehog's clone stayed out of `/tmp`, and nothing was left after the run.
- Startup to "Starting scan" (#1581), warm: base 13.1, 4.7 and 13.0 s; head 4.4, 4.3
  and 4.3 s. zap's `-version` alone takes 8.8 s warm.

opengrep under the full matrix at the default budget (#1591), three runs each. Every run
read juice-shop's 223 and WebGoat's 444, with no `Limit` error and no timeout on
`three.js` or `ace.js`. With opengrep alone on WebGoat, head reads 444 and `dev` reads
428. All 16 extra results are in `ace.js`, where `dev` times out even alone, and `dev`
finds nothing head misses.

The osv-scanner retry round (#1373), 21 npm lockfiles with one truncated:

| Budget | Peak RSS / PSS | Wall |
|---|---|---|
| `--memory-budget 700` | 643 / 635 MB | 153.7 s |
| default | 2,434 / 2,317 MB | 50.7 s |

The row is the same in both.

Built differently from the plan's wording:

- The gate and the slots are one object, `ScanLimits`, which `scan_limits()` holds for
  the scan.
- Its stop is `request_stop()`.
- `threads` now bounds tool runs across the scan, so `--threads 1` runs one tool at a
  time.

Changed in review:

- `jmo ci` writes no report after Ctrl-C.
- The scan gives SIGINT and SIGTERM back when it ends.
- A process that starts as Ctrl-C arrives is killed as it registers.
- A Ctrl-C during a `--tsv` clone kills git's tree.
- The default budget also reads a container's cgroup limit.
- trufflehog's folder moved (Decided 7).
- "start" is shown when a run is admitted.

zap's heap (Decided 4, re-confirmed on the corrected premise below) was built on
2026-11-14, after 7b was rebased onto dev `6b7190c4`; with it 7b closes #1422.

## Decided 2026-11-05 (Jimmy)

"Approve as recommended", 10:05 EST. Commit bodies cite them as "Decided 2026-11-05: ...".

1. **Default memory budget:** half the memory free at scan start, never below 700 MB.
2. **Free memory:** `psutil`, a runtime dependency added by the installer lane.
3. **After Ctrl-C:** exit 130 with no report; the session is saved for
   `jmo scan --resume`.
4. **zap's heap** (#1422): `per_tool.zap.heap`, default `512m`, passed as `-Xmx`.
   Re-confirmed 2026-11-05 after the premise was corrected. `zap.sh` sizes the heap at a
   quarter of RAM on Linux and macOS (`-Xmx7008m` on the 28 GB machine), not 512 MB, so
   this lowers it there. The gate reserves the heap plus 90 MB, and `per_tool.zap.heap`
   raises it for wide sites.
5. **`--timeout` against the floors** (#1486, which names semgrep; Phase 5 replaced it
   with opengrep, which kept the floor): an explicit `--timeout` wins.
6. **The 700 MB acceptance** is measured with `--memory-budget 700`; the default
   budget's peak is recorded beside it.
