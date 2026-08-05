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
for the OAuth redirect — so it fails on a headless server, over SSH, or inside a
container with a `RuntimeError` naming the missing browser.

**What to do:** sign in CI, where the token is ambient. If you must sign on a
headless machine, run the command somewhere with a browser and transfer the
resulting bundle.

---

## MCP server

### Authentication is off unless you set `JMO_MCP_API_KEYS`

The server starts with authentication disabled and logs
`Authentication: disabled (dev mode)`. Set `JMO_MCP_API_KEYS` to a
comma-separated list of keys to enable it; keys are compared as SHA-256 hashes.

**Read the startup log line before exposing the server to anything.** "Disabled
(dev mode)" means every caller is trusted.

```bash
export JMO_MCP_API_KEYS="$(openssl rand -hex 32)"
```

See [MCP_SETUP.md](MCP_SETUP.md) for the full configuration reference.

### One client at a time

MCP's stdio transport is a single stdin/stdout pipe, so one server process serves
exactly one client. This is the transport's design, not a JMo restriction.

**What to do:** run one server instance per client.

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

### Cross-tool clustering is conservative by default

The default `deduplication.similarity_threshold` of `0.65` (in `jmo.yml`) produces
limited clustering *across* tools on real scans. Composite similarity is weighted
toward message text, so two tools reporting the same problem in different words
score low even when they agree on the location. Trivy's `:latest tag used` and
Hadolint's `DL3006` on the same Dockerfile line score about `0.39`.

No findings are lost — they are reported separately rather than clustered.

**What to do:** lower `deduplication.similarity_threshold` toward `0.5` if you
would rather over-cluster than under-cluster. Values outside `0.5`–`1.0` are
rejected at config load.

---

## Scheduling

### Exported workflows carry the paths you created the schedule with

`jmo schedule export --backend github-actions` writes the schedule's stored
target paths into the workflow verbatim. A schedule created on Windows against
`C:\Projects\myrepo` exports a workflow whose `--repo C:\Projects\myrepo` means
nothing on a Linux runner.

**What to do:** edit the exported workflow's paths for the CI environment before
committing it, or create the schedule with the paths the runner will see.

---

## Reporting something not listed here

Open an issue with the `bug` label. If it is a limitation rather than a defect —
something that works as designed but surprised you — say so, and it may end up on
this page.
