# Remediating the newly-published `.claude/` skills and agents

**Status:** chunks A, B, C, D, E and H complete (79/103); F, G remain
**Branch:** one branch per chunk off `dev`; PR into `dev`. Never `main`.
**Tracking issue:** [#718](https://github.com/jimmy058910/jmo-security-repo/issues/718)
**Endgame:** land all 103 on `dev`, then `dev -> main` as **v1.0.9**

### Decided 2026-08-08: all 103 land before v1.0.9

The alternative was cutting v1.0.9 early, at 60/103, and shipping E/F/G in
v1.0.10. The case for it: every one of the 43 remaining findings is inside
`.claude/`, which is contributor tooling with no runtime effect on the released
package, while `dev` is holding user-facing fixes — #725 (`slim` scans silently
discarded), #746 (trufflehog reporting pytest function names as verified
secrets), #734, #729.

**Rejected in favour of one clean release.** v1.0.9 ships the full remediation
and closes #718 with the tag, rather than splitting it across two releases.
E (19) → F (13) → G (11) first; expect roughly one chunk per session.

Do not re-open this at the start of the next session.

### Release gate at 103/103, before tagging: [#752](https://github.com/jimmy058910/jmo-security-repo/issues/752)

None of these 103 findings is executed by a test, so green CI proves only that
nothing *else* broke. Before `dev -> main`, run the full Juice Shop pass plus
`jmo validate --tier full` and `reconcile_scan_accounting.py`, and compare
finding counts to the baselines in `docs/internal/MANUAL_TESTING_CHECKLIST.md`.

**Read the job logs, not the check ticks.** Both Juice Shop E2E steps
(`scheduled.yml:841`, `:927`) are `continue-on-error: true`, so they report
green over real failures — the same trap as the `windows-2022` shard.

## What happened

PR #717 split `.claude/` by audience and published 12 contributor skills plus 7
agents. That put ~16,400 lines of instructional content under review for the
first time in the project's history. The review returned **103 findings**:
2 Critical, 61 Major, 38 Minor, 2 Trivial, across 53 files.

None of this is a regression from #717. It is pre-existing drift that
publication exposed — the content had never been linted, link-checked, or
reviewed because it had never been tracked.

## Discovery: the findings are not 103 independent problems

Three things came out of reading them that change how the work should be run.

### 1. Clusters collapse to single root causes

The 13 `jmo-profile-optimizer` findings all reduce to one fact: **the skill
documents a `timings.json` schema that has never existed.**

| | Real (`scripts/cli/report_orchestrator.py:344-348`) | What the skill reads |
|---|---|---|
| total | `aggregate_seconds` | `total_duration_seconds` |
| per-tool | `jobs: [{tool, path, seconds, count}]` — a flat list | `tools: {name: {...}}` — a dict |
| profile | *absent* | `profile` |
| timeouts / failures | **not recorded at all** | per-tool `timeouts`, `failures` |

Its documented Phase 1 raises `KeyError` on the first line against real CLI
output, and its timeout-rate analysis has no data source in the first place.
Fixing the schema resolves most of the 13 as a side effect.

Expect other clusters to behave the same way. **Read a cluster whole before
fixing any member of it.**

### 2. Finding density varies by more than 20x

Density is the best available proxy for "is this content maintained."

| Skill | Findings | Lines | Per 100 lines |
|---|---:|---:|---:|
| `jmo-dashboard-builder` | 7 | 379 | **1.85** |
| `jmo-profile-optimizer` | 13 | 1033 | **1.26** |
| `jmo-documentation-updater` | 6 | 755 | 0.79 |
| `jmo-target-type-expander` | 11 | 1484 | 0.74 |
| `jmo-refactoring-assistant` | 6 | 964 | 0.62 |
| `jmo-security-hardening` | 8 | 1340 | 0.60 |
| `jmo-compliance-mapper` | 3 | 575 | 0.52 |
| `jmo-ci-debugger` | 13 | 3008 | 0.43 |
| `jmo-adapter-generator` | 4 | 1343 | 0.30 |
| `jmo-test-fabricator` | 11 | 3752 | 0.29 |
| `jmo-systematic-debugging` | 1 | 1219 | 0.08 |
| `jmo-e2e-verify` | **0** | 411 | **0.00** |

`jmo-e2e-verify` is the control: it is the one skill that was already tracked
before #717, and it came back clean. That is the standard the rest should meet.

### 3. Verification cuts both ways — never batch-apply

Measured on the findings worked so far:

- **3/3** claims against `check_doc_links.py` were real, including one the
  author (me) had introduced that same day.
- The `exit_codes` batch was right about 5 sites where a naive grep found 2 —
  **but** it also implied changing two `memory-integration.md` blocks where
  string keys are *correct*, because those blocks are JSON documents.

So: **verify every claim against the code, then fix or dismiss with a stated
reason.** A finding dismissed with a reason is a completed finding.

## The policy decision to make first

Several skills document APIs and schemas that do not exist. For those, there are
two honest responses, and the choice should be made **once, up front**, not
per-file:

- **Repair** — rewrite the example against the real code. Costly, and it only
  holds until the next drift, because nothing tests instructional prose.
- **Delete the fiction** — remove the invented example and point at the real
  module. Cheaper, shorter, and cannot drift, because there is nothing left to
  disagree with reality.

**Recommendation: delete by default, repair only where the example teaches
something the source does not.** A skill that says "read
`scripts/cli/report_orchestrator.py:344` for the timings schema" is correct
forever. A skill that reproduces that schema is wrong the moment it changes,
and has been wrong for months already without anyone noticing.

The instruction covering this work is explicit that deleting content that is no
longer active or needed is in scope.

## Segmentation

Ordered by value: skills that **cannot work as documented** first, then density,
then breadth. Each chunk is one session, one commit series, one push.

| # | Chunk | Findings | Why this grouping |
|---|---|---:|---|
| **A** | `jmo-profile-optimizer` | 13 | Both Criticals live here, and the whole cluster is one fictional schema. Decide repair-vs-delete here and set the precedent. |
| **B** | `jmo-dashboard-builder` + `jmo-documentation-updater` | 13 | Highest density, smallest files — fastest ratio of findings closed to lines read. |
| **C** | `jmo-adapter-generator` + `jmo-test-fabricator` | 15 | The scaffold a contributor copies. Highest external blast radius; the `exit_codes` class already found here. |
| **D** | `jmo-ci-debugger` | 13 | 3008 lines, the largest single reference corpus. Needs a whole session. |
| **E** | `jmo-target-type-expander` + `jmo-security-hardening` | 19 | Both mid-density, both heavy on example code. |
| **F** | 7 agents | 13 | Different shape: report templates, not procedures. Several are stale counts and commands. |
| **G** | `jmo-refactoring-assistant`, `jmo-compliance-mapper`, `jmo-systematic-debugging`, `references/` | 11 | The tail. Low density; likely mostly dismissals. |

Chunk A also carries one setup task: 4–5 findings have their claim nested such
that only HTML comments trail the analysis block. Read those individually from
the PR conversation.

### Per-chunk protocol

1. Pull that chunk's findings from the PR review.
2. Read the whole cluster before editing — look for the single root cause.
3. Verify each claim against real code. Record the verdict.
4. Fix, or delete the fiction, or dismiss with a reason. All three are done.
5. Run `python scripts/dev/check_doc_links.py` and the unit tests.
6. Check line endings: `git diff --numstat` must equal
   `git diff --ignore-cr-at-eol --numstat` on every changed file.
7. Commit with the verdicts in the message; push; comment the tally on #718.

### Acceptance

- Every one of the 103 findings is fixed, deleted, or dismissed-with-reason.
- `check_doc_links.py` passes over all 162 tracked Markdown files.
- No published skill documents a schema, flag, or API that does not exist —
  spot-check by grepping each documented symbol against `scripts/`.
- Then `dev -> main` as **v1.0.9**.

## Standing traps for every session

- **`main` is never touched by this work.** Branch off `dev`; PR into `dev`.
- **Line endings**: this repo is mixed CRLF/LF with no `.gitattributes`.
  `Path.write_text()` and `sed -i` under MSYS both rewrite whole files. Use
  `write_bytes()`. `cat -A` through an MSYS pipe misreports; the numstat
  comparison is the only reliable check.
- **Formatters are repo-wide.** `make fmt` runs `black .`; `.claude/` is
  excluded via `pyproject.toml`, so leave that exclusion in place — the
  adapter templates contain `{Tool}` placeholders and are not parseable Python.
- **Console output**: anything printing repository content must go through
  `harden_console_streams()` + `safe_print()` from `scripts/core/unicode_utils`.
- **Read the `windows-2022` job log, not its check tick** — it is
  `continue-on-error: true` and reports success over failures. Same applies to
  the two Juice Shop E2E steps (`scheduled.yml:841`, `:927`).

### Learned in chunk E — apply to F and G

- **Precision is not evidence — it is camouflage.** Chunk E's three worst
  findings were all *specific*: `require('@cloudflare/turnstile')` (npm 404),
  `X-Frame-Options` in a `<meta>` tag (inert), `--cov-fail-under=85` (set
  nowhere; CI's real floor is 70%). Each read as authoritative precisely
  because it named a thing. A vague claim invites checking; a precise one
  deflects it. Check the named thing.
- **Verify the fix's own mechanism, not just the finding's.** Executing my
  replacement for the cache-miss finding proved *it* was broken: `jq -e ...
  2>/dev/null || echo "cache miss"` reports a miss for every lookup on a box
  without `jq`. Second time this session a self-authored recipe failed on
  first execution (chunk D's `sha256sum -c` was the first). Run what you write.
- **Don't invent a flag to make a fix land.** A first draft here added
  `--header-from-env` to graphql-cop — a tool not in `versions.yaml`, so the
  flag could not be verified and was almost certainly imaginary. Removing
  fiction by adding fiction is not progress. If the safe API cannot be named,
  document the exposure instead.
- **Prefer package metadata to web research.** ScoutSuite's entry point was
  settled by downloading the 5.14.0 wheel and reading `entry_points.txt`
  (`scout = ScoutSuite.__main__:run_from_cli`, no `scoutsuite`), not by
  trusting the search result that said the same thing.
- **The Grep tool and `grep` disagreed once.** A Grep-tool search for
  `os.environ` in `.claude/skills` returned no matches while plain `grep -rn`
  found two. Cross-check a *negative* result before concluding a pattern is
  absent. (Recursive `grep -r` from Bash still times out at 120s — it bit twice
  this session; scope it to one directory.)

### Learned in chunks C and D — apply to E, F, G

- **Verify the anchored file actually contains the cited symbol.** Chunk D had
  4 findings whose API `path` *and* `diff_hunk` said `jmo-ci-debugger/references/
  memory-integration.md`, while the bodies analysed Python that exists only in
  `jmo-compliance-mapper/references/memory-integration.md` — at identical line
  numbers, because the two files share a basename and a similar length. Grep the
  cited symbol before editing.
- **Findings understate their own scope; grep for siblings.** Every multi-site
  finding in C and D named fewer sites than existed (1 reported vs 4 real, twice).
  Read the whole construct, not the cited line.
- **"Battle-tested" is a claim to check, not a reason to trust.** The ci-debugger
  skill asserted every fix had been proven in production; its pattern #13 remedy
  appears in no commit (`git log -S`) and its premise was measurably false against
  this repo's own ruleset. Test the claim against `git log` and the live API.
- **A doc that cannot fail is a doc that never ran.** Recurring shape: a `grep`
  that returns 0 every time (chunk B), an assertion that could never pass (C), an
  import of a module that does not exist (A, D), a `sha256sum -c` that can never
  resolve its file (D). If an example has a pass/fail step, **execute it** — that
  is what caught three of these, including one of my own.
- **`\|` inside a Markdown table is the GFM escape, not a regex escape.** It
  renders as a bare `|`. Removing it splits the cell and drops a column. Check
  rendering with `gh api markdown` (no leading slash — MSYS mangles `/markdown`
  into a path).
