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

## Reporting something not listed here

Open an issue with the `bug` label. If it is a limitation rather than a defect —
something that works as designed but surprised you — say so, and it may end up on
this page.
