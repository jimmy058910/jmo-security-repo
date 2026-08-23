# Known Limitations

Behaviour that is deliberate, unfinished, or environment-bound, and that you may
reasonably hit while using JMo Security. Each entry says what happens, why, and
what to do instead.

This file covers **limitations we intend to keep documenting**. Defects with a
fix planned are GitHub issues instead — a file has no close mechanism, so
anything trackable belongs where it can be closed. Search the
[issue tracker](https://github.com/jimmy058910/jmo-security-repo/issues) before
assuming something here is unfixable.

---

## Attestation

### Local signing needs a browser; CI signing does not

`jmo attest --sign` uses Sigstore keyless signing, which authenticates through an
OIDC redirect. In CI (GitHub Actions, GitLab CI) the ambient OIDC token is picked
up automatically and signing works unattended. Run locally, it opens a browser
for the OAuth redirect — so on a headless server, over SSH, or inside a container
it fails with sigstore's own error about being unable to complete the flow.

> This paragraph used to promise "a `RuntimeError` naming the missing browser".
> That exception lives in `SigstoreSigner._get_local_oidc_token`, which
> **nothing calls** — `sign()` shells out to `sigstore sign` and lets sigstore
> run its own OIDC. The documented failure mode belonged to unreachable code.

**What to do:** sign in CI, where the token is ambient. If you must sign on a
headless machine, run the command somewhere with a browser and transfer the
resulting bundle.

---

### Verifying a signature requires naming the signer you expect

`jmo verify` checks the subject digest, the attestation's shape and its tamper
indicators on every run. It checks the **signature** only when you pass both
`--cert-identity` and `--cert-oidc-issuer`; otherwise it prints
`Signature: NOT CHECKED` and says so in the output.

That is deliberate. Keyless signing proves *who* signed, so a bundle validated
without an expected signer establishes only that somebody signed it — which is
not a security property, and reporting it as "verified" would be worse than
reporting nothing. A bundle sitting next to an attestation is not evidence on
its own.

```bash
jmo verify results/summaries/findings.json \
  --cert-identity you@example.com \
  --cert-oidc-issuer https://oauth2.sigstore.dev/auth
```

---

## MCP server

### The server does not authenticate callers at all

**There is no way to turn authentication on.** Every client that can reach the
server process is trusted, and setting `JMO_MCP_API_KEYS` does not change that.

This section used to say the opposite — that setting `JMO_MCP_API_KEYS` would
"enable it" and that "keys are compared as SHA-256 hashes". The keys *are*
hashed at startup, and then nothing ever compares them against anything. MCP's
stdio transport hands the tool functions no request context, so there is no
caller credential to check a key against.

The startup line said `Authentication: enabled` in that state. It now says:

```text
WARNING  Authentication: NOT ENFORCED -- 1 key(s) configured via
         JMO_MCP_API_KEYS, but no transport supplies a caller credential to
         compare them against. EVERY caller is trusted.
```

`get_server_info()` reports the same thing as `authentication_enforced: false`,
which is the machine-readable form for a client to check.

**What to do:** treat the server the way you would treat a shell. Run it as a
subprocess of the client that needs it (the normal MCP arrangement — see
[MCP_SETUP.md](MCP_SETUP.md)), and do not expose the process to anything you
would not give a shell to. `JMO_MCP_RATE_LIMIT_*` works and is enforced; it is
a throttle, not an access control, and it uses one shared bucket for all
callers.

**One tool writes to your repository.** `mark_resolved` appends a suppression
entry to `jmo.suppress.yml`, so an unauthenticated caller can stop a security
finding being reported. Two things bound it, and neither is authentication:
every entry it writes **expires** (90 days by default, 365 at most — there is
no permanent option through the tool), and `jmo.suppress.yml` is a tracked
file, so the change shows up in `git diff` and in review like any other. No
other tool writes anything.

### `apply_fix` cannot apply a fix

`apply_fix` validates a patch and returns it for review. `dry_run=False` writes
nothing and returns `success: False`. Applying a patch needs traversal
validation, backup-and-rollback, and a post-apply test run — a patch-writing
subsystem, deliberately not built during an audit release. Tracked as
[#951](https://github.com/jimmy058910/jmo-security-repo/issues/951) and
deferred past v1.1.0.

**What to do:** treat it as a reviewer, not an applier. Take `dry_run_preview`
and apply it with `git apply` yourself.

### One client at a time

MCP's stdio transport is a single stdin/stdout pipe, so one server process serves
exactly one client. This is the transport's design, not a JMo restriction.

**What to do:** run one server instance per client.

### Memory use over long sessions is unmeasured

The server starts, serves and shuts down cleanly, and that path is tested — but
no extended profiling has been run, so there is no measured figure for growth
over a session lasting hours. Because stdio is single-client and sessions are
normally short, this has not mattered in practice; it is untested rather than
known-good.

**What to do:** if you keep a server alive for a long-running client, watch its
RSS and restart it between large batches. Report anything that grows without
bound — that would be a defect, not this limitation.

---

## Scanning

### `--repo` pointing at a path that does not exist exits 0

`jmo scan --repo /nonexistent` warns `No scan targets provided` and exits **0**,
not 2. A scan with nothing to scan is treated as a scan that found nothing, which
is consistent with how the CLI reports an empty result elsewhere.

**What to do:** in CI, check that the results directory contains the scan you
expected rather than relying on the exit code alone to prove a target was read.

### Concurrent scans on Windows are not verified

Two scans writing into the same results directory or history database at once has
not been tested on Windows. SQLite provides its own locking and scan output files
are write-once, so the risk is low — but it is untested, not proven.

**What to do:** on Windows, give concurrent scans separate `--results-dir` paths.

---

## Deduplication

### Cross-tool clustering only ever merges findings from *different* tools

Clustering runs in two phases. Phase 1 deduplicates by exact content
fingerprint. Phase 2 clusters findings that different tools reported for the
same underlying issue, and **a cluster holds at most one finding per tool** — so
if one tool reports several distinct rules against the same line, they stay
several findings. That is deliberate: within a single tool, "same location" is
the normal case rather than evidence, and Phase 1 has already made the exact
judgment about that tool's own output.

Composite similarity is weighted **toward location** — `0.50` location, `0.25`
message, `0.25` metadata — so two tools agreeing on a `path:line` are most of
the way to the `0.65` default threshold before their wording is considered.
Trivy's `:latest tag used` and Hadolint's `DL3006` on the same Dockerfile line
score `0.82` and do cluster, via the rule-equivalence table in
`scripts/core/rule_equivalence.py`.

No findings are lost — anything not clustered is reported separately.

**What to do:** lower `deduplication.similarity_threshold` toward `0.5` if you
would rather over-cluster than under-cluster, or raise it toward `1.0` for the
opposite. Values outside `0.5`–`1.0` are rejected at config load. How much
clustering you see depends heavily on how much your profile's tools overlap: a
scan whose tools examine different things (SBOM, secrets, SAST) will cluster
very little, because there is nothing for them to agree on.

> This section previously said clustering was "conservative", that similarity
> was "weighted toward message text", and that the Trivy/Hadolint pair scored
> "about `0.39`". All three were measured false — the weights favour location,
> and that exact pair scores `0.82`. The sentence "no findings are lost" was
> also untrue until the one-finding-per-tool rule landed: clustering was
> merging distinct findings from a single tool and dropping them from the
> report.

---

## Comparing scans

### A finding whose message text changes is reported as resolved plus new

`jmo diff` matches findings by their id, and that id is a hash of
`tool | ruleId | path | line | message`, with the message truncated at 120
characters. So if a tool changes the wording of a finding — commonly after
upgrading the tool — the finding's identity changes with it, and the diff
reports one **resolved** and one **new** rather than one **modified**.

The engine does track a `message` change type, but it can only fire when the
message is longer than 120 characters *and* the edit falls entirely beyond that
point, leaving the hashed prefix intact. Measured on two real corpora: 6 of 34
findings from a `bandit` scan and 106 of 263 from a mixed one have messages long
enough to qualify at all.

**What to do about it.** When a diff shows a suspiciously symmetric jump — N
resolved and about N new, with the same rules and files on both sides — check
whether a scanner was upgraded between the two scans before treating any of it
as real movement.

This is not fixed because `path` and `message` are inputs to the fingerprint by
design: changing what goes into it invalidates every baseline and every row
already in the history database. See [#861](https://github.com/jimmy058910/jmo-security-repo/issues/861),
which has to solve the same migration for path normalization.

### Clustering keeps a finding's diff identity, but only through its members

Cross-tool clustering rewrites a consensus finding's id to
`cluster-<fingerprint>`. `jmo diff` accounts for that: it matches on the
representative's fingerprint recovered from the prefix, and on every id listed
in `context.duplicates`. A finding that gains or loses a corroborating tool
between two scans is therefore reported as unchanged, not as fixed-and-reopened.

The limit is that this depends on the cluster recording its members. A finding
that both joins a cluster **and** changes its own fingerprint in the same
interval — a tool upgrade that reworded it, say — is still reported as resolved
plus new, for the reason in the section above.

---

## Scheduling

### Exported workflows carry the paths you created the schedule with

`jmo schedule export --backend github-actions` writes the schedule's stored
target paths into the workflow verbatim. A schedule created on Windows against
`C:\Projects\myrepo` exports a workflow whose `--repo C:\Projects\myrepo` means
nothing on a Linux runner.

**What to do:** edit the exported workflow's paths for the CI environment before
committing it, or create the schedule with the paths the runner will see.

### Survival across a reboot is not verified automatically

`jmo schedule install` writes a normal crontab entry — Linux and macOS only;
there is no Windows Scheduled Task backend, so on Windows use
`jmo schedule export` and run the schedule from CI instead. Install/uninstall is
tested under WSL, but no automated test reboots a machine, because that is too
disruptive to run on a dev box or a CI runner. Standard crontab entries do
persist across reboots, so the expected behaviour is that your schedule simply
resumes; it is unproven here rather than doubtful.

**What to do:** after your first install, confirm it by hand once —
`jmo schedule list` (or `crontab -l`) following a reboot. Worth re-checking on a
machine where something else manages cron, such as a container or a hardened
image that resets `/var/spool/cron`.

---

## Defects shipping in v1.1.0

Everything above is behaviour we intend to keep documenting. **This section is
different.** These are defects with fixes planned — they would normally live only
in the issue tracker, per this file's own rule. They are listed here because a
user can hit them in v1.1.0 and the symptom is hard to interpret without knowing
the cause.

Each links to the issue that will close it. The set was fixed by dispositioning
every open issue before the tag, in the v1.1.0 audit campaign
([#785](https://github.com/jimmy058910/jmo-security-repo/issues/785), chunk 22);
every one carries the `disposition:SHIP-WITH-IT` and `user-reachable` labels, so
the list can be regenerated rather than trusted:

```bash
gh issue list --repo jimmy058910/jmo-security-repo --state open \
  --label disposition:SHIP-WITH-IT --label user-reachable
```

### Scanning and tool execution

- A scanner that **could not read a file reports it as clean.** No adapter reads
  its tool's own error channel, so an unparseable or unreadable file is silently
  absent from findings rather than flagged. [#837](https://github.com/jimmy058910/jmo-security-repo/issues/837)
- `--allow-missing-tools` **records a tool that never ran as a success**, so the
  run summary overstates coverage. [#825](https://github.com/jimmy058910/jmo-security-repo/issues/825)
- `jmo tools check` **exits 0 when tools are missing**, contradicting its own
  documented contract — do not use its exit code as a CI gate.
  [#788](https://github.com/jimmy058910/jmo-security-repo/issues/788)
- The `deep` profile **omits `shellcheck`**, which `fast`, `slim` and `balanced`
  all run — the most comprehensive profile is not a superset of the others.
  [#795](https://github.com/jimmy058910/jmo-security-repo/issues/795)
- `scancode` is invoked with no detection flag, so **its adapter can never
  produce a finding**. Licence and copyright results will always be empty.
  [#835](https://github.com/jimmy058910/jmo-security-repo/issues/835)
- A path target containing `~` is **never expanded**, so a cron-installed
  schedule scans a literal `~` directory. Use absolute paths.
  [#926](https://github.com/jimmy058910/jmo-security-repo/issues/926)
- The `gitlab` target type is the only one that **never writes
  `scan-timings.json`**. [#824](https://github.com/jimmy058910/jmo-security-repo/issues/824)
- A per-profile `per_tool` entry **replaces a tool's whole entry** instead of
  merging, silently dropping sibling keys.
  [#791](https://github.com/jimmy058910/jmo-security-repo/issues/791)
- Unrecognised keys in `jmo.yml` are **ignored silently** — a typo'd key reads as
  a working config. [#859](https://github.com/jimmy058910/jmo-security-repo/issues/859)
- First-run output points at two commands that do not exist (`jmo config`,
  `jmo subscribe`), and the first-run config write **clobbers other keys**.
  [#790](https://github.com/jimmy058910/jmo-security-repo/issues/790) ·
  [#931](https://github.com/jimmy058910/jmo-security-repo/issues/931)
- `jmo schedule delete` raises `EOFError` on a non-TTY; every sibling prompt
  catches it. [#789](https://github.com/jimmy058910/jmo-security-repo/issues/789)
- The report auto-storage hook **swallows every exception**, so a scan can report
  success having stored nothing.
  [#801](https://github.com/jimmy058910/jmo-security-repo/issues/801)

### Reporting, exports and the dashboard

- **A released (pip-installed) JMo cannot build the React dashboard.** The wheel
  carries no `scripts/dashboard/` sources, so `jmo report` falls back to a
  **vendored build dated 2025-11-17** — which is also what CI renders. The
  dashboard you get from a released install is that fixture, not a fresh build.
  **What to do:** clone the repository and build from source if you need the
  current dashboard. [#862](https://github.com/jimmy058910/jmo-security-repo/issues/862) ·
  [#864](https://github.com/jimmy058910/jmo-security-repo/issues/864)
- Finding locations are **not normalised**: one file can appear under four
  spellings, and **the host's absolute path is written into SARIF and the
  dashboard**. Treat exported artifacts as containing local filesystem paths
  before sharing them.
  [#861](https://github.com/jimmy058910/jmo-security-repo/issues/861)
- Three compliance artifacts and `SUPPRESSIONS.md` **cannot be turned off** —
  `outputs: []` still writes four files.
  [#867](https://github.com/jimmy058910/jmo-security-repo/issues/867)
- `--log-level` and `--human-logs` are **missing from `diff`, `history`, `trends`
  and `policy`**. [#879](https://github.com/jimmy058910/jmo-security-repo/issues/879)
- The documented "30-40% noise reduction" figure is unattributed and **measures
  about 1%** on both available corpora. Treat it as unverified.
  [#855](https://github.com/jimmy058910/jmo-security-repo/issues/855)

### History

- `jmo fast`, `jmo balanced` and `jmo full` **store no scan history**, while
  `jmo scan` and `jmo ci` do — history will look empty if you use the shorthand
  commands. [#870](https://github.com/jimmy058910/jmo-security-repo/issues/870)
- History records **the config's tool list and profile, not what actually ran**,
  so the `tools` column overstates the scan.
  [#787](https://github.com/jimmy058910/jmo-security-repo/issues/787)
- `jmo history store` **aborts the whole scan** when two findings lack an `id`.
  [#901](https://github.com/jimmy058910/jmo-security-repo/issues/901)
- Every *read* command rewrites the database header to WAL, so a copy taken
  between reads is **not byte-stable**. Use `jmo history` exports rather than
  file-level diffing to compare snapshots.
  [#894](https://github.com/jimmy058910/jmo-security-repo/issues/894)

### Deduplication, compliance and prioritisation

- Phase-1 deduplication **silently discards any finding with a falsy `id`**.
  [#848](https://github.com/jimmy058910/jmo-security-repo/issues/848)
- Compliance mapping is starved upstream: **CWEs present in tool output never
  reach `risk.cwe`**, so framework coverage under-reports.
  [#845](https://github.com/jimmy058910/jmo-security-repo/issues/845)
- `RULE_EQUIVALENCE` declares **genuinely different controls equivalent**, so
  some cross-tool merges join findings that are not the same issue.
  [#846](https://github.com/jimmy058910/jmo-security-repo/issues/846)
- EPSS enrichment makes **one HTTP request per finding** whose CVE is unknown,
  and builds an unbounded bulk URL — slow, and network-dependent, on large scans.
  [#849](https://github.com/jimmy058910/jmo-security-repo/issues/849)
- The `hipaa-compliance` docs describe a NIST CSF gate; **the policy actually
  enforces CWEs and 164.312 safeguards.**
  [#923](https://github.com/jimmy058910/jmo-security-repo/issues/923)

### Suppression

- A suppression written by the MCP `mark_resolved` tool gets an expiry date
  computed in **UTC**, but the suppression engine decides whether it is still
  active using the machine's **local** date. Its effective lifetime is therefore
  up to a day longer or shorter than the number of days you asked for, depending
  on your timezone. **What to do:** if a suppression's exact lapse day matters,
  set the expiry a day earlier than the boundary you care about.
  [#967](https://github.com/jimmy058910/jmo-security-repo/issues/967)

### Scheduling

- `validate_cron_expression` **rejects named weekdays** (`MON`, `FRI`) that both
  GitHub Actions and POSIX cron accept. Use numeric days.
  [#927](https://github.com/jimmy058910/jmo-security-repo/issues/927)
- The GitLab CI generator **silently drops IaC, GitLab and Kubernetes targets**
  from the exported pipeline.
  [#928](https://github.com/jimmy058910/jmo-security-repo/issues/928)
- **One unknown key in `schedules.json` makes every schedule unreadable**,
  reported as a bare Python `TypeError`.
  [#934](https://github.com/jimmy058910/jmo-security-repo/issues/934)

### Attestation

- An **uppercase hex digest is reported as `TAMPER DETECTED`** on an unmodified
  subject. If you see tamper detection on an artifact you trust, check the digest
  casing first. [#950](https://github.com/jimmy058910/jmo-security-repo/issues/950)
- Attestations **carry no git commit** — the metadata-capture subsystem has no
  callers. [#945](https://github.com/jimmy058910/jmo-security-repo/issues/945)
- The in-toto Statement is **v0.1 paired with a SLSA Provenance v1 predicate**,
  a combination consumers may reject.
  [#946](https://github.com/jimmy058910/jmo-security-repo/issues/946)

### MCP server

- The rate limiter uses **one shared bucket**, so a single caller can exhaust
  everyone's budget. [#952](https://github.com/jimmy058910/jmo-security-repo/issues/952)
- `query_findings_db`'s read-only keyword scan **rejects legitimate security
  queries** whose text happens to contain a blocked keyword.
  [#953](https://github.com/jimmy058910/jmo-security-repo/issues/953)
- `jmo mcp-server` can **prompt on stdin and consume the client's first JSON-RPC
  message**, which presents as a client that never finishes connecting. Set
  `JMO_NON_INTERACTIVE=1`.
  [#958](https://github.com/jimmy058910/jmo-security-repo/issues/958)

### Windows

- 56 `subprocess.run(text=True)` call sites **decode as cp1252**, so non-ASCII
  tool output can raise `UnicodeDecodeError`; one of them crashes
  `jmo build validate`. Setting `PYTHONUTF8=1` avoids it.
  [#963](https://github.com/jimmy058910/jmo-security-repo/issues/963)

### Build

- `jmo build` **aborts on version validation** (`cdxgen` routed to PyPI, `falco`
  pinned to a `0.0.0` placeholder), and its pre-build version gate **fails open**
  on three error paths, reporting "validation passed" when it did not run.
  [#935](https://github.com/jimmy058910/jmo-security-repo/issues/935) ·
  [#939](https://github.com/jimmy058910/jmo-security-repo/issues/939)

---

## Reporting something not listed here

Open an issue with the `bug` label. If it is a limitation rather than a defect —
something that works as designed but surprised you — say so, and it may end up on
this page.
