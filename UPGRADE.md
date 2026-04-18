# Upgrade Guide

Migration guide for users upgrading to JMo Security v1.0.x from earlier releases.

## Scope

The only pre-v1.0 release tag currently available is **v0.8.0** (2025-10). If you're on an earlier version (v0.3.x through v0.7.x), upgrade to v0.8.0 first — see [its release notes](https://github.com/jimmy058910/jmo-security-repo/releases/tag/v0.8.0) — then follow this guide.

This guide is evidence-based: every migration step below is grounded in a diff between `v0.8.0` and the current `v1.0.x` tree. If you hit a behavior change that isn't covered here, please [open an issue](https://github.com/jimmy058910/jmo-security-repo/issues/new).

---

## Am I affected?

Answer these three questions:

- **How do you install?** If Docker, see [Docker users](#docker-users). If pip, see [pip users](#pip-users).
- **Do you have a `.jmo/history.db` from v0.8.0?** No — history storage is new in v1.0.0. See [New features worth adopting](#new-features-worth-adopting).
- **Do you have CI pipelines calling `jmo scan` or `jmo ci`?** Re-read [CLI flag changes](#cli-flag-changes) before bumping your image or package version.

---

## Breaking changes

### CLI flag: `--profile` renamed to `--profile-name` on `scan` and `ci`

Affected subcommands: `jmo scan`, `jmo ci`.

**Before (v0.8.0):**

```bash
jmo scan --repo . --profile balanced
jmo ci --repo . --profile balanced --fail-on HIGH
```

**After (v1.0.x):**

```bash
jmo scan --repo . --profile-name balanced
jmo ci --repo . --profile-name balanced --fail-on HIGH
```

**Why this changed:** avoids argument-name collision with the `--profile` boolean flag that enables scan timing collection. See commit `ce4403e`.

**What to do:** search your CI configs, Makefiles, and scripts for `--profile <name>` patterns used with `jmo scan` or `jmo ci` and rename to `--profile-name`. Other subcommands (`jmo tools`, `jmo wizard`) keep their own `--profile` usage.

---

## CommonFinding schema changes

The schema is additive — existing fields kept, new fields added. No field renames, no removals. If you parse findings JSON downstream, existing code continues to work.

New helpers in `scripts/core/common_finding.py`:

- `Severity.from_string(value)` — normalize tool-specific severity labels (`"INFORMATIONAL"`, `"NOTE"`, `"STYLE"`, etc.) to the canonical `CRITICAL/HIGH/MEDIUM/LOW/INFO` set.
- `TOOL_SEVERITY_MAPPINGS` — module-level dict for per-tool severity translation used by adapters.

If you wrote a custom adapter, consider adopting `map_tool_severity()` from the common module instead of hand-rolling severity normalization.

---

## History DB migration

**Clean break, not a migration.** `scripts/core/history_db.py` did not exist in v0.8.0 — the SQLite history feature ships fresh in v1.0.0.

If you're upgrading in place:

- You won't have a `.jmo/history.db` file. That's expected. The first v1.0.x scan creates it automatically.
- If you want backfill, re-run historical scans (or just accept that history starts fresh from your v1.0.x adoption date).
- The DB lives at `.jmo/history.db` by default. Docker users should mount the `.jmo/` directory to persist across container runs:

  ```bash
  docker run --rm \
    -v "$(pwd)/.jmo:/scan/.jmo" \
    -v "$(pwd):/scan" \
    ghcr.io/jimmy058910/jmo-security:v1.0.1 scan --repo /scan
  ```

No manual schema migration is required — the DB is versioned and auto-initialized on first use.

---

## Docker users

### Image reference

v0.8.0 was published as `jmo-security:v0.8.0`. v1.0.x uses the same registry but new tag format:

```bash
# Before
docker pull ghcr.io/jimmy058910/jmo-security:v0.8.0

# After — pin to a specific version
docker pull ghcr.io/jimmy058910/jmo-security:v1.0.1
# OR pull the latest tag for the :latest rolling pointer
docker pull ghcr.io/jimmy058910/jmo-security:latest
```

### Variants

v1.0.x ships 4 variants (previously 1):

| Tag suffix | Tools | Use case |
|------------|-------|----------|
| `:fast`, `:v1.0.1-fast` | 8 | Pre-commit, PR validation |
| `:slim`, `:v1.0.1-slim` | 14 | Cloud/IaC (AWS/Azure/GCP/K8s) |
| `:balanced`, `:v1.0.1-balanced` | 18 | Production scans, CI/CD |
| `:latest`, `:v1.0.1-full` (default) | 28 | Compliance audits, pentests |

Pick the smallest variant that covers your scanners to reduce pull time. See [docs/PROFILES_AND_TOOLS.md](docs/PROFILES_AND_TOOLS.md) for the full tool list per variant.

### Registries (new)

v1.0.x is published to three registries simultaneously. Use whichever fits your environment:

- **GHCR (primary):** `ghcr.io/jimmy058910/jmo-security`
- **Docker Hub:** `jmogaming/jmo-security`
- **ECR Public:** `public.ecr.aws/m2d8u2k1/jmo-security`

GHCR is authoritative; the other two are replicated from it on each release.

---

## pip users

### Package metadata unchanged

Install/upgrade command is the same:

```bash
pip install --upgrade jmo-security
jmo --version  # should print 1.0.1
```

### New optional extras

```bash
pip install "jmo-security[mcp]"           # AI remediation (MCP server)
pip install "jmo-security[attestation]"   # SLSA attestation signing
```

These are new in v1.0.0. Base install still works without them.

---

## New features worth adopting

None of these are required for upgrading, but they're the reason v1.0 exists. Pointers for each:

### SQLite historical storage

Tracks scan history, deltas, and trends. Opt in by running any scan — the DB initializes automatically. Query via:

```bash
jmo history list
jmo history show <scan-id>
```

See [docs/HISTORY_GUIDE.md](docs/HISTORY_GUIDE.md).

### Machine-readable diffs

Compare two scan result directories and detect regressions:

```bash
jmo diff results-baseline/ results-current/ --format md > diff.md
```

See [docs/DIFF_GUIDE.md](docs/DIFF_GUIDE.md).

### Trend analysis (Mann-Kendall)

Statistical trend detection over scan history:

```bash
jmo trend --branch main --scans 10
```

See [docs/TRENDS_GUIDE.md](docs/TRENDS_GUIDE.md).

### Policy-as-Code (OPA)

5 built-in policies (zero-secrets, owasp-top-10, pci-dss, production-hardening, hipaa-compliance) plus custom policy authoring:

```bash
jmo ci --repo . --policy zero-secrets --fail-on-policy-violation
```

See [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md).

### Automated scheduling

Recurring scans via GitHub Actions, GitLab CI, or local cron:

```bash
jmo schedule create --name weekly --cron "0 2 * * 1" --profile balanced
jmo schedule export weekly > .gitlab-ci.yml
```

See [docs/SCHEDULE_GUIDE.md](docs/SCHEDULE_GUIDE.md).

### Interactive setup wizard

First-time users: run `jmo wizard` for a guided walk-through (target selection, profile choice, tool installation, first scan). New in v1.0.x.

### MCP server for AI remediation

Expose security findings to Copilot/Claude via the Model Context Protocol:

```bash
pip install "jmo-security[mcp]"
jmo mcp-server
```

See [docs/MCP_SETUP.md](docs/MCP_SETUP.md).

### Additional CLI commands

All new in v1.0.x:

- `jmo tools` — install, check, clean security tools
- `jmo validate` — pre-release validation scorecard
- `jmo build` — build management (internal; usually invoked by release pipeline)

Run `jmo <command> --help` for each.

---

## Post-upgrade checklist

- [ ] `jmo --version` prints `1.0.1` (or current)
- [ ] CI/CD configs updated: `--profile` → `--profile-name` on `scan` and `ci` subcommands
- [ ] Docker volume mount for `.jmo/` directory if you want persistent history
- [ ] First scan completes — history DB auto-creates at `.jmo/history.db`
- [ ] Verify Docker pull: `docker pull ghcr.io/jimmy058910/jmo-security:v1.0.1`

---

## Troubleshooting

If a scan fails after upgrade, check [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) first. For issues not covered there, open a GitHub Issue with:

- Output of `jmo --version`
- Output of `jmo tools check`
- The command that failed and its full output

---

**Last Updated:** April 2026 | **JMo Security v1.0.1**
