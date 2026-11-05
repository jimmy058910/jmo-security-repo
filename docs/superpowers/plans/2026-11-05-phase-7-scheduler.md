# Phase 7 — memory-gated scheduler, process trees, Ctrl-C: task plan (draft)

> **Status: draft for Jimmy's decisions (end of file).** Nothing below is built until
> they are made. PR 7a (the small measured fixes) is separate and does not depend on
> this plan.
>
> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use
> checkbox (`- [ ]`) syntax.

**Goal:** a scan's tools run under one scan-wide memory budget and one CPU slot count,
each tool carrying a measured cost class; Ctrl-C stops the scan and leaves no process
behind on any platform; and these open Phase 7 issues close: #1208, #1308,
the osv-scanner retry round's #1373, zap's #1422, `--timeout`'s #1486, and the
`--gitlab-group` placeholder of #1407 (PR 7a closes #1406).

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
direct runs of the exact command where a flag was tried:

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
(385 MB RSS, 26 s, on a scan with no URL target; drafted to the coordinator as its own
issue).

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

## Tasks (PR 7b)

### Task B1: measure the rest, then cost classes on the descriptors

**Files:** `scripts/core/tool_descriptors.py`, `scripts/dev/peakmem.py` (new: the
sampler used above, so the numbers can be re-run), `tests/unit/test_tool_descriptors.py`

- [ ] Commit the sampler as `scripts/dev/peakmem.py` (Linux `/proc`; prints peak RSS
  and PSS, wall, and the processes left N s after a SIGINT).
- [ ] Measure checkov and hadolint on a fixture with IaC and Dockerfiles, nuclei and zap
  on the ZAP fixture site, and osv-scanner's per-lockfile retry round on 20 npm
  lockfiles with one truncated (#1373).
- [ ] Test first: every descriptor has `memory_mb > 0`; trufflehog's two invocations
  each carry it. Then add the field and the values.

### Task B2: the scan-wide gate

**Files:** `scripts/core/tool_runner.py`, `scripts/cli/scan_orchestrator.py`,
`scripts/cli/scan_jobs/tool_loop.py`, `tests/unit/test_tool_runner.py`

- [ ] Test first, with fake tools that only sleep: under a 600 MB budget two 550 MB
  runs never overlap and two 100 MB runs do; a 900 MB run under a 600 MB budget runs
  alone and finishes; a waiting run wakes when the stop event is set; CPU slots bound
  the count whatever the budget.
- [ ] `MemoryGate` (a `threading.Condition` with a FIFO ticket) and `CpuSlots`; a
  module-level `scan_limits()` that `scan_all` sets for the scan and clears in
  `finally`, unlimited when unset so a direct `ToolRunner` use is unchanged.
- [ ] `ToolDefinition.memory_mb` from the descriptor in `tool_loop.definition()`;
  `ToolRunner.run_tool` holds a slot and the gate around the run, retries included.
- [ ] Budget: `jmo.yml` `memory_budget_mb` and `--memory-budget`, default per
  Decision 1. Free memory read per Decision 2.

### Task B3: process trees die with the scan

**Files:** `scripts/core/tool_runner.py`, `scripts/cli/clone_from_tsv.py`,
`scripts/cli/scan_jobs/gitlab_scanner.py`, `tests/unit/test_tool_runner.py`,
`tests/cli/test_clone_from_tsv.py`

- [ ] A process registry in `tool_runner.py`: `_run_bounded` adds each `Popen` on
  start and removes it on exit; `terminate_all()` kills every registered tree
  (`_terminate_tree`, which already does `killpg` and `taskkill /T`).
- [ ] Windows: at scan start jmo assigns itself to a Job Object with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (ctypes, `kernel32`), so every descendant dies
  when jmo exits however it exits. Nested jobs need Windows 8 or later.
- [ ] #1308: `clone_from_tsv.run` and the GitLab clone go through `_run_bounded`.
  Test first: a fake `git` that starts a sleeping grandchild and writes its pid;
  timed out at 1 s, the grandchild is gone (POSIX `os.kill(pid, 0)`).

### Task B4: Ctrl-C

**Files:** `scripts/cli/jmo.py` (the handler in `cmd_scan`), `scripts/cli/scan_orchestrator.py`,
`scripts/core/tool_runner.py`, `scripts/core/scan_timings.py` (the new `Reason`),
`tests/cli/test_scan_interrupt.py` (new)

- [ ] Test first (POSIX, subprocess): `jmo scan` with two fake tools that each start a
  sleeping grandchild; SIGINT to jmo's process group once both run; within 5 s jmo has
  exited 130 and no process it started is alive. Negative control: the same test
  against today's code shows them alive.
- [ ] The handler sets a scan-wide stop event and calls `terminate_all()`; the gate
  wakes its waiters; `scan_all` stops submitting (`shutdown(cancel_futures=True)`);
  killed runs are `failed:interrupted`; the session is saved; behaviour after that
  per Decision 3. A second Ctrl-C exits at once.

### Task B5: no thread outlives the test session (#1208)

**Files:** `scripts/cli/jmo.py` (`ProgressTracker`), `tests/cli/test_progress_tracker.py`,
`tests/conftest.py` (**p9-code's**: the session-end guard is theirs to place or approve)

- [ ] `ProgressTracker` is a context manager whose exit calls `stop()`; `cmd_scan` uses
  it; the tests that start one stop it.
- [ ] A session-end check that no non-daemon thread and no `refresh_loop` thread is
  alive (the one `run_server` thread seen is a test server, to be found and closed).

### Task B6: zap's concurrency and heap (#1422), `--timeout` (#1486), the placeholder (#1407)

**Files:** `scripts/core/tool_descriptors.py`, `scripts/cli/scan_utils.py`
(`tool_timeout`), `scripts/cli/jmo.py` (`--timeout` help), `scripts/cli/scan_orchestrator.py`

- [ ] zap `exclusive=True`; test: two URL targets, both zap rows `ran`.
- [ ] zap's heap per Decision 4.
- [ ] `--timeout` per Decision 5; its help says which wins.
- [ ] Once the first-run lane has removed `--gitlab-group`, delete
  `_discover_gitlab_repos`' `group:` placeholder (`scan_orchestrator.py:967`).

### Task B7: gates, then PR 7b

- [ ] Targeted tests; one full suite with the coordinator's go-ahead.
- [ ] **The evidence CI cannot give:** app B's default matrix under
  `scripts/dev/peakmem.py`, with the budget at 700 and at the default: peak, wall, and
  processes left 5 s after a SIGINT 3 s into the scan phase. Numbers in the PR body.
- [ ] Windows: Ctrl-C and the Job Object checked on a Windows machine by a script Jimmy
  runs (CI cannot send a console Ctrl-C).

## Decisions for Jimmy

1. **The default budget.** (a) 700 MB, the program plan's target: app B's scan phase
   goes from about 40 s to about 70-80 s. (b, recommended) Half the memory free at scan
   start, never below 700 MB: unchanged on a large machine, bounded on a small one; the
   700 MB number is then measured with `--memory-budget 700`.
2. **Reading free memory.** (a, recommended) `psutil`, a new runtime dependency in
   `pyproject.toml` and `uv.lock` (the installer lane's files). (b) The standard
   library: `/proc/meminfo` on Linux, `sysctl` on macOS, `GlobalMemoryStatusEx` through
   ctypes on Windows, about 40 lines to keep.
3. **After Ctrl-C.** (a, recommended) Exit 130 with no report: the session is saved and
   `jmo scan --resume` finishes the scan. (b) Write a report of the targets that
   finished, marked partial.
4. **zap's heap** (#1422). (a, recommended) `per_tool.zap.heap` (default `512m`),
   passed as `-Xmx`, `zap.sh` and the java line alike. (b) Honour `_JAVA_OPTIONS`, which
   overrides `-Xmx` (measured in PR API), and document it.
5. **`--timeout` against a tool's floor** (#1486). (a, recommended) An explicit
   `--timeout` wins over opengrep's and zap's 900 s floors (#1486 says semgrep, which
   Phase 5 replaced; opengrep kept the floor), as `per_tool.<tool>.timeout`
   already does; `jmo.yml`'s `timeout` does not. (b) Keep the floors and say so in the
   help.
6. **The 700 MB acceptance.** Keep it as a target recorded with `--memory-budget 700`
   (predicted 640-700 MB on app B), or move it to what the default budget gives.
