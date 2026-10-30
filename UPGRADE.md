# Upgrade Guide

Migration guide for users upgrading JMo Security. [Upgrading to v2.0.0](#upgrading-to-v200) covers the move from v1.x; the rest of this guide covers upgrading to v1.0.x from earlier releases.

## Upgrading to v2.0.0

v2.0.0 removes scan profiles, 17 tools and all but one Docker image, and replaces Semgrep with opengrep. There are no aliases and no deprecation period: a removed flag or subcommand now fails with an argument error (exit code 2).

### Scan profiles are removed

`jmo scan` and `jmo ci` consider one tool list, the 15 scanners in [docs/TOOLS.md](docs/TOOLS.md), and the target's content decides which of them run. To narrow the list:

- `--tools trivy opengrep` or `--skip-tools zap` on the command line
- a top-level `tools:` list in `jmo.yml`

Removed, with no replacement flag:

- `--profile-name` on `jmo scan` and `jmo ci`. `jmo scan --profile balanced` only ever worked as an abbreviation of `--profile-name`, so it fails too.
- The profile-named subcommands `fast`, `balanced` and `full`, which ran a scan with that profile
- `--profile` on `jmo tools check`, `jmo tools install`, `jmo tools list`, `jmo wizard`, `jmo schedule create`, `jmo schedule update`, `jmo history store` and `jmo history list`
- `jmo tools list --profiles`
- `jmo build --variant` and `jmo build --all` (`jmo build` builds the one image)

**Not removed:** `jmo report --profile` and `jmo ci --profile`, with no value, are the parse-timing flag that writes `timings.json`. They never selected a profile and still work.

```bash
# v1.x
jmo scan --repo . --profile-name balanced
jmo ci --repo . --profile-name fast --fail-on HIGH
jmo tools install --profile balanced

# v2.0.0
jmo scan --repo .
jmo ci --repo . --tools trufflehog opengrep trivy --fail-on HIGH
jmo tools install
```

`jmo tools install` installs the scanners plus OPA, the policy engine; jmo-native is part of JMo and needs no install. `jmo tools check` lists the scanners in its table and OPA on its own "Policy engine" line below it.

### `jmo.yml`: profile settings move to the top level

The `profiles:` and `default_profile:` keys are gone. A `jmo.yml` that still carries them loads, logs a warning that the key is unknown, and ignores it: none of the profile's settings apply. Move what you need to the top-level keys `tools`, `threads`, `timeout`, `retries`, `per_tool`, `policy` and `include`/`exclude`:

```yaml
# v1.x
default_profile: balanced
profiles:
  balanced:
    tools: [trufflehog, semgrep, trivy]
    threads: 4
    timeout: 600
    per_tool:
      trivy:
        flags: [--no-progress]

# v2.0.0
tools: [trufflehog, opengrep, trivy]
threads: 4
timeout: 600
per_tool:
  trivy:
    flags: [--no-progress]
```

### Semgrep is replaced by opengrep

opengrep, a fork of Semgrep's engine, is the code scanner. It is a single static binary, and it runs a rule bundle that ships with JMo (`scripts/jmo_rules/`, 1,456 security rules; [docs/RULE_BUNDLE.md](docs/RULE_BUNDLE.md)). A scan fetches no rule: it runs offline and gives the same rules on every machine, where `semgrep --config auto` asked semgrep.dev which rules applied.

- **The tool's name changed.** `--tools semgrep`, `--skip-tools semgrep` and a `semgrep` entry in `tools:` fail with exit code 2, saying semgrep was removed in v2.0.0 and that opengrep replaced it. Use `opengrep`. The raw output is `opengrep.json`, where it was `semgrep.json`.
- **`per_tool.semgrep` becomes `per_tool.opengrep`.** A `jmo.yml` that still carries `per_tool.semgrep` loads, logs one warning that names each key the entry carries under `per_tool.opengrep` (`per_tool.opengrep.configs` for packs, `per_tool.opengrep.flags` for flags), and ignores the entry: your own packs and flags stop applying until you move them.

  ```yaml
  # v1.x
  per_tool:
    semgrep:
      configs: [p/python, ./rules/mine.yml]
      flags: [--exclude, generated]

  # v2.0.0
  per_tool:
    opengrep:
      configs: [./rules/mine.yml]
      flags: [--exclude, generated]
  ```

  `configs` replaces the bundle, as it replaced `auto`; it takes rule files and directories. A registry pack such as `p/python` still works through opengrep, but it fetches its rules over the network, which the bundle never does. A flag in `flags` that sets the output format, the number of jobs or rule-id rewriting is dropped with a warning, because JMo sets those itself ([docs/TOOLS.md](docs/TOOLS.md#opengrep)).
- **Every SAST finding id changes, once.** A finding's id hashes the tool's name, so each finding that semgrep reported has a new id under opengrep, even when it is the same flaw at the same line. A suppression in `jmo.suppress.yml` that names a finding by its id stops matching, and `jmo diff` against a scan stored before the upgrade reports the old findings as fixed and the same flaws as new. This change alters no other tool's ids; trivy's misconfiguration and secret ids change in this release for a different reason ([CHANGELOG.md](CHANGELOG.md)). Suppress by rule or path instead of by id where you can.
- **The rules are the bundle's.** It holds security rules only, one file per language, and a scan loads the files of the languages the repository has. Do not expect the same findings as `--config auto`: read an empty result on JavaScript or TypeScript as the bundle's coverage, not as current coverage ([Known limitations](docs/KNOWN_LIMITATIONS.md#most-of-the-rule-bundle-is-a-frozen-snapshot-javascript-and-typescript-included)). A repository with no file in a language the bundle covers, and none that only `generic.yaml`'s rules read (an nginx config, Bicep, Handlebars), is `skipped:no files in a language the rule bundle reads`; one that has such a file runs with `generic.yaml`. If you scan incrementally with `--baseline-commit` in `per_tool.opengrep.flags`, a commit that changes no file opengrep reads (it only deletes files, or touches only `tests/` or `*.min.js`) is `skipped:no changed file opengrep reads since the baseline commit`, and the scan still exits 0 ([docs/SCAN_OPTIMIZATION.md](docs/SCAN_OPTIMIZATION.md)).
- **The results directory holds matched source text.** opengrep's debug log lands in `<results-dir>/individual-*/<target>/.opengrep/semgrep.log` and records the source text of each match. Treat the results directory like the code it scanned, for example before uploading it as a CI artifact ([docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md#the-results-directory-structure)).
- **Installing.** `jmo tools install opengrep` downloads the pinned release binary into `~/.jmo/bin/`. The semgrep virtual environment is not removed for you; `jmo tools clean --force` removes the isolated venvs, and checkov's is recreated by `jmo tools install checkov`.

### Removed tools

These 17 tools are no longer installed, run or parsed. Their `per_tool` blocks in `jmo.yml` have nothing left to configure.

| Tool | Why it was removed |
|------|--------------------|
| kubescape | Trivy's config scan covers the same ground, and kubescape fetched its rules at scan time |
| semgrep-secrets, bandit (as a scanner) | semgrep-secrets scanned 0 files and bandit's results were dominated by `.venv` noise; opengrep's rule bundle covers SAST |
| trivy-rbac | Its output was identical to Trivy's config scan |
| checkov-cicd | Folded into checkov, which never actually read `.github/workflows` under JMo (its `.git` exclusion also matched `.github`, #1313); checkov's repository run was then narrowed to Terraform and CloudFormation only, dropping its other CI/CD and secrets frameworks there. zizmor now audits workflows -- see [docs/TOOLS.md](docs/TOOLS.md#when-each-tool-runs) |
| gosec | It examined 0 files on every run, because neither the image nor `jmo tools install` provides the Go toolchain it loads packages with. opengrep's Go rules cover Go |
| noseyparker, prowler, akto, scancode, cdxgen, dependency-check, horusec, falco (with falcoctl), afl++, mobsf, lynis | Never installable on Windows, not a repository scanner, a duplicate of a kept tool, or abandoned upstream |

Bandit remains this repository's own pre-commit hook and lint step; only bandit as a JMo scanner is gone. Details: [docs/TOOLS.md](docs/TOOLS.md#removed-in-v200).

### Tool names are checked

`--tools`, `--skip-tools` and `jmo.yml`'s `tools:` split on commas as well as spaces. `--tools trivy,syft` now selects two tools. In v1.x it was one tool named `trivy,syft`, which ran nowhere.

A name that is not in the matrix is a usage error, exit code 2, naming it. That includes the 17 removed tools, whose error says so. In v1.x, `--tools bandit` scanned with nothing and exited 1, and a typo selected nothing without a word.

### Every tool gets a row: `scan-timings.json` v4

Each target's `scan-timings.json` is at `schema_version` 4. It has one row for **every requested tool**, including the ones that did not run. Each row is `ran`, `skipped:<reason>` or `failed:<reason>`, so a tool that was not installed, had nothing to read, or read zero files says so. v2 listed only the tools that ran, and those tools' fields changed:

| v2 | v4 |
|----|----|
| `status`, `timed_out`, `error_message` | `state` (`ran` / `skipped` / `failed`), `reason` (for example `timed out`, `not installed`, `no Dockerfiles`), `detail` |
| `duration` | `seconds` |
| `returncode` (`-1` for any failure) | `exit_code` (a failed run's own code, or `null` when there was none) |
| `output_file` | removed: the output is `<tool>.json` beside the document |
| (none) | `kept_findings`: on a failed row, what its runs that worked still found, counted before de-duplication ([What a scan records](docs/TOOLS.md#what-a-scan-records)) |

`.scan_metadata.json` loses `stubbed_tools` and gains `tool_runs`, the same rows for every target.

Two outcomes changed with it. A repository with no files outside the excluded directories now fails every tool that reads it (`failed:no files to scan`), where v1.x graded the tools a success. So does a tool whose own output reports 0 files examined (`failed:examined 0 files`), except opengrep run with `--baseline-commit`, which has nothing to read when the commit changed no file it scans (`skipped:no changed file opengrep reads since the baseline commit`).

### One Docker image

There is one image, built from `Dockerfile`: `ghcr.io/jimmy058910/jmo-security:latest` and version tags such as `:2.0.0` (Docker Hub: `jmogaming/jmo-security`). It carries the 15 scanners plus OPA.

The `:fast`, `:slim`, `:balanced`, `:deep` and `:full` tags, and the tags with a variant suffix, are no longer built. Existing tags are not deleted, but they will never receive another update. Switch to `:latest` or a version tag.

### TruffleHog no longer verifies secrets

TruffleHog used to send each candidate secret to the service that issued it, to ask whether it
was live, and graded a live one HIGH. It no longer does unless `jmo.yml` asks:

```yaml
per_tool:
  trufflehog:
    verify: true
```

Every secret TruffleHog or Gitleaks reports is graded HIGH either way, so `--fail-on HIGH` still
stops on a leaked secret, verified or not; the tags say which. The `zero-secrets` policy blocks
verified secrets only, so without `verify: true` it passes.

Both secret scanners also read the repository's git history now, when it has a `.git` of its own
and is not a shallow clone. In CI, fetch the full history (`actions/checkout` with
`fetch-depth: 0`) to have secrets in deleted commits reported.

### History database

Scans no longer record a profile, so the history database has no `profile` column. Run `jmo history migrate` to drop it from an existing `.jmo/history.db`. You can also skip that step: the next scan that stores history drops the column itself. Findings are kept either way.

`findings.json` `meta`, attestations and diff output no longer carry a profile either.

The database also gains a `scan_tool_runs` table: one row per target and tool, with its state, reason and seconds. `jmo history show <scan-id>` prints it. It is created the first time a scan stores into the database. Scans stored before then have no rows.

### Findings name their target, and every id changes

Each finding now carries `target`, the kind of target it was scanned from and the name of its results folder, which for a repository is the checkout's directory name: `"target": {"type": "repo", "name": "app-one"}`. A finding's id is derived from that target, so the same finding in two targets of one scan is two findings. Before, the second was dropped as a duplicate of the first, and two repositories' root `package-lock.json` were one dependency cluster.

- **Every finding id changes, once.** A suppression in `jmo.suppress.yml` that names a finding by its id stops matching, and `jmo diff` against a scan stored before the upgrade reports every old finding as fixed and every one of them as new. Suppress by rule or path instead where you can.
- **Ids now change when a checkout directory is renamed**, because the directory's name is part of the id. Keep a repository's directory name stable between scans you mean to compare.
- `location.path` is unchanged: it is still relative to the target. The target is `properties.target` on a SARIF result, a `target` column in `findings.csv` (before `path`), and a column in the dashboard. A `csv.columns` list in `jmo.yml` is used as written, so add `target` to it.

### Schedules

Stored schedules (`~/.jmo/schedules.json`) lose their `profile`. An existing schedule still loads, its `profile` is ignored, and the command it generates no longer passes `--profile-name`.

A copy generated before the upgrade still passes the old flag and will fail. Regenerate it: `jmo schedule export <name>` for a CI workflow file, or `jmo schedule install <name>` for a local cron entry.

---

## Scope

The only pre-v1.0 release tag currently available is **v0.8.0** (2025-10). If you're on an earlier version (v0.3.x through v0.7.x), upgrade to v0.8.0 first — see [its release notes](https://github.com/jimmy058910/jmo-security-repo/releases/tag/v0.8.0) — then follow this guide.

This guide is evidence-based: every migration step below is grounded in a diff between `v0.8.0` and the current `v1.0.x` tree. If you hit a behavior change that isn't covered here, please [open an issue](https://github.com/jimmy058910/jmo-security-repo/issues/new).

---

## Am I affected?

Answer these three questions:

- **How do you install?** If Docker, see [Docker users](#docker-users). If pip, see [pip users](#pip-users).
- **Do you have a `.jmo/history.db` from v0.8.0?** No — history storage is new in v1.0.0. See [New features worth adopting](#new-features-worth-adopting).
- **Do you have CI pipelines calling `jmo scan` or `jmo ci`?** Re-read [CLI flag changes](#cli-flag-profile-selection-on-scan-and-ci) before bumping your image or package version.

---

## Breaking changes

### CLI flag: profile selection on `scan` and `ci`

Affected subcommands: `jmo scan`, `jmo ci`.

**Before (v0.8.0):**

```bash
jmo scan --repo . --profile balanced
```

v1.0.x renamed this selector to `--profile-name`, to free `--profile` for the boolean flag that enables timing collection (commit `ce4403e`). v2.0.0 then removed scan profiles entirely, so `--profile-name` no longer exists either.

**After (v2.0.0):**

```bash
jmo scan --repo .
jmo ci --repo . --fail-on HIGH
```

**What to do:** search your CI configs, Makefiles, and scripts for `--profile <name>` and `--profile-name <name>` used with `jmo scan` or `jmo ci`, and delete them. To run fewer tools, use `--tools` or `--skip-tools`. See [Upgrading to v2.0.0](#upgrading-to-v200).

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
jmo trends analyze --branch main --last 10
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
jmo schedule create --name weekly --cron "0 2 * * 1" --repos-dir ~/repos
jmo schedule export weekly > .gitlab-ci.yml
```

See [docs/SCHEDULE_GUIDE.md](docs/SCHEDULE_GUIDE.md).

### Interactive setup wizard

First-time users: run `jmo wizard` for a guided walk-through (target selection, tool installation, first scan). New in v1.0.x.

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
- [ ] CI/CD configs updated: no `--profile <name>` or `--profile-name` on `scan` and `ci` subcommands
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

**Last Updated:** August 2026 | **JMo Security v1.1.1**
