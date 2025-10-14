# JMO Security Suite — User Guide

This guide walks you through everything from a 2‑minute quick start to advanced configuration. Simple tasks are at the top; deeper features follow.

Note: The CLI is available as the console command `jmo` (via PyPI) and also as a script at `scripts/cli/jmo.py` in this repo. The examples below use the `jmo` command, but you can replace it with `python3 scripts/cli/jmo.py` if running from source.

If you're brand new, you can also use the beginner‑friendly wrapper `jmotools` described below.

## Quick start (2 minutes)

Prereqs: Linux, WSL, or macOS with Python 3.10+ recommended (3.8+ supported).

1. Install the CLI

```bash
# Preferred (isolated):
pipx install "jmo-security[reporting]"

# Or using pip (user site):
pip install --user "jmo-security[reporting]"
```

The `reporting` extra bundles PyYAML and jsonschema so YAML output and schema validation work automatically. If you only need JSON/Markdown/SARIF, install the base package (`jmo-security`) instead.

1. Verify your environment and get install tips for optional tools

```bash
make verify-env
```

1. Run a fast multi-repo scan + report in one step

```bash
# Scan all immediate subfolders under ~/repos with the default (balanced) profile
jmo ci --repos-dir ~/repos --fail-on HIGH --profile --human-logs

# Open the dashboard
xdg-open results/summaries/dashboard.html  # Linux
open results/summaries/dashboard.html       # macOS
```

Outputs are written under `results/` by default, with unified summaries in `results/summaries/` (JSON/MD/YAML/HTML/SARIF). SARIF is enabled by default via `jmo.yml`.

### Beginner mode: jmotools wrapper (optional, simpler commands)

Prefer memorable commands that verify tools, optionally clone from a TSV, run the right profile, and open results at the end? Use `jmotools`:

```bash
# Quick fast scan (auto-opens results)
jmotools fast --repos-dir ~/security-testing

# Deep/full scan using the curated 'deep' profile
jmotools full --repos-dir ~/security-testing --allow-missing-tools

# Clone from TSV first, then balanced scan
jmotools balanced --tsv ./candidates.tsv --dest ./repos-tsv

# Bootstrap and verify curated tools (Linux/WSL/macOS)
jmotools setup --check
jmotools setup --auto-install
```

Makefile shortcuts are also available:

```bash
make setup             # jmotools setup --check (installs package if needed)
make fast DIR=~/repos  # jmotools fast --repos-dir ~/repos
make balanced DIR=~/repos
make full DIR=~/repos
```

## Everyday basics

- Scan a single repo quickly

```bash
jmo scan --repo /path/to/repo --human-logs
```

- Scan a directory of repos with a named profile

```bash
jmo scan --repos-dir ~/repos --profile-name fast --human-logs
```

- Report/aggregate from existing results only

```bash
jmo report ./results --profile --human-logs
# or equivalently
jmo report --results-dir ./results --profile --human-logs
```

- Allow missing tools (generate empty stubs instead of failing)

```bash
jmo scan --repos-dir ~/repos --allow-missing-tools
```

- Use curated helpers to prepare repos

```bash
# Clone sample repos quickly (parallel, shallow)
./scripts/core/populate_targets.sh --dest ~/security-testing --parallel 8
```

Tip: You can also run `make tools` to install/upgrade the curated external scanners (semgrep, trivy, syft, checkov, tfsec, bandit, gitleaks, trufflehog, hadolint, osv-scanner, etc.) and `make verify-env` to validate your setup.

## Output overview

Unified summaries live in `results/summaries/`:

- findings.json — Machine‑readable normalized findings
- SUMMARY.md — Human summary
- findings.yaml — Optional YAML (if PyYAML available)
- dashboard.html — Self‑contained interactive dashboard
- findings.sarif — SARIF 2.1.0 output (enabled by default)
- timings.json — Present when `jmo report --profile` is used
- SUPPRESSIONS.md — Summary of filtered IDs when suppressions are applied

Per‑repo raw tool output is under `results/individual-repos/<repo>/`.

Data model: Aggregated findings conform to a CommonFinding shape used by all reporters. See `docs/schemas/common_finding.v1.json` for the full schema. At a glance, each finding includes:

- id (stable fingerprint), ruleId, severity (CRITICAL|HIGH|MEDIUM|LOW|INFO)
- tool { name, version }, message, location { path, startLine, endLine? }
- optional: title, description, remediation, references, tags, cvss, context, raw

## Configuration (jmo.yml)

`jmo.yml` controls what runs and how results are emitted. Top‑level fields supported by the CLI include:

- tools: [gitleaks, noseyparker, semgrep, syft, trivy, checkov, hadolint, tfsec, trufflehog, bandit, osv-scanner]
- outputs: [json, md, yaml, html, sarif]
- fail_on: "CRITICAL|HIGH|MEDIUM|LOW|INFO" (empty means do not gate)
- threads: integer worker hint (auto if unset)
- include / exclude: repo name glob filters (applied when using --repos-dir or --targets)
- timeout: default per‑tool timeout seconds
- log_level: DEBUG|INFO|WARN|ERROR (defaults to INFO)
- retries: global retry count for flaky tool invocations (0 by default)
- default_profile: name of the profile to use when --profile-name is not provided
- profiles: named profile blocks
- per_tool: global per‑tool overrides (merged with per‑profile overrides)

Example:

```yaml
tools: [gitleaks, noseyparker, semgrep, syft, trivy, checkov, hadolint]
outputs: [json, md, yaml, html, sarif]
fail_on: ""
default_profile: balanced
threads: 4
retries: 0

profiles:
  fast:
    tools: [gitleaks, semgrep]
    threads: 8
    timeout: 300
    include: ["*"]
    exclude: ["big-monorepo*"]
    per_tool:
      semgrep:
        flags: ["--exclude", "node_modules", "--exclude", ".git"]
  balanced:
    tools: [gitleaks, noseyparker, semgrep, syft, trivy, checkov, hadolint]
    threads: 4
    timeout: 600
    per_tool:
      trivy:
        flags: ["--no-progress"]
  deep:
    tools: [gitleaks, noseyparker, trufflehog, semgrep, syft, trivy, checkov, tfsec, hadolint, bandit, osv-scanner]
    threads: 4
    timeout: 900
    retries: 1
```

Use a profile at runtime:

```bash
jmo scan --repos-dir ~/repos --profile-name fast
```

Notes and precedence:

- Severity order is CRITICAL > HIGH > MEDIUM > LOW > INFO. Thresholds gate at and above the chosen level.
- Threads/timeout/tool lists are merged from config + profile; CLI flags override config/profile where provided.
- Per‑tool overrides are merged with root config; values set in a profile win over root.

## Key CLI commands and flags

Subcommands: scan, report, ci

Common flags:
- --config jmo.yml: choose a config file (default: jmo.yml)
- --profile-name NAME: apply a named profile from config
- --threads N: set workers (scan/report)
- --timeout SECS: default per‑tool timeout (scan)
- --tools ...: override tool list (scan/ci)
- --fail-on SEVERITY: gate the exit code during report/ci
- --human-logs: color, human‑friendly logs on stderr (default logs are JSON)
- --allow-missing-tools: write empty JSON stubs if a tool is not found (scan/ci)
- --profile (report/ci): write timings.json with summary and per‑job timings

Notes on exit codes:
- Some tools intentionally return non‑zero to signal “findings.” The CLI treats these as success codes internally (gitleaks/trivy/checkov: 0/1; semgrep: 0/1/2) to avoid false failures.
- The overall exit code of report/ci can be gated by --fail-on or fail_on in config.

Graceful cancel:
- During scans, Ctrl‑C (SIGINT) will request a graceful stop after in‑flight tasks finish.

Environment variables:
- JMO_THREADS: when set, influences worker selection during scan; report also seeds this internally based on `--threads` or config to optimize aggregation.
- JMO_PROFILE: when set to 1, aggregation collects timing metadata; `--profile` toggles this automatically for report/ci and writes `timings.json`.

## Per‑tool overrides and retries

You can supply global `per_tool` overrides at the root and/or inside a profile; profile values win and are merged. Supported keys are free‑form; commonly used keys include `flags` (list of strings) and `timeout` (int).

Example:

```yaml
per_tool:
  trivy:
    flags: ["--ignore-unfixed"]
    timeout: 1200
profiles:
  balanced:
    per_tool:
      semgrep:
        flags: ["--exclude", "node_modules", "--exclude", ".git"]
```

Retries:
- Set `retries: N` at the root or inside a profile to automatically retry failing tool commands up to N times.
- Human logs will show attempts when > 1, e.g. `attempts={'semgrep': 2}`.

Threading and performance:
- Scan workers: precedence is CLI/profile threads > JMO_THREADS env > config default > auto.
- Report workers: set via `--threads` (preferred) or config; the aggregator will also suggest `recommended_threads` in `timings.json` based on CPU count.

## Suppressions

You can suppress specific finding IDs during report/ci. The reporter looks for `jmo.suppress.yml` first in `results/` and then in the current working directory.

File format:

```yaml
suppress:
  - id: abcdef1234567890
    reason: false positive (hashing rule)
    expires: 2025-12-31   # optional ISO date; omit to never expire
  - id: 9999deadbeef
    reason: accepted risk for demo
```

Behavior:
- Active suppressions remove matching findings from outputs.
- A suppression summary (`SUPPRESSIONS.md`) is written alongside summaries listing the filtered IDs.

Search order for the suppression file is: `<results_dir>/jmo.suppress.yml` first, then `./jmo.suppress.yml` in the current working directory.

## SARIF and HTML dashboard

- SARIF emission is enabled by default in this repo (`outputs: [json, md, yaml, html, sarif]`). If you remove `sarif` from outputs, SARIF won’t be written.
- The HTML dashboard (`dashboard.html`) is fully self‑contained and supports client‑side sorting, tool filtering, CSV/JSON export, persisted filters/sort, and deep‑linkable URLs.
- When `--profile` is used during report/ci, a `timings.json` file is produced; the dashboard shows a profiling panel when this file is present.

## OS notes (installing tools)

Run `make verify-env` to detect your OS/WSL and see smart install hints. Typical options:

- macOS: `brew install gitleaks semgrep trivy syft checkov hadolint tfsec`
- Linux: use apt/yum/pacman for basics; use official install scripts for trivy/syft; use pipx for Python‑based tools like checkov/semgrep; see hints printed by `verify-env`.

You can run with `--allow-missing-tools` to generate empty stubs for any tools you haven’t installed yet.

Curated installer:

```bash
make tools           # install core scanners
make tools-upgrade   # upgrade/refresh installed scanners
make verify-env      # detect OS/WSL/macOS and show install hints
```

### Nosey Parker on WSL (native recommended) and auto-fallback (Docker)

On Windows Subsystem for Linux (WSL), the most reliable approach is a native Nosey Parker install. Prebuilt binaries can fail on older glibc; building from source works well.

Native (WSL/Linux) install steps:

```bash
# 1) Prereqs
sudo apt-get update -y
sudo apt-get install -y build-essential pkg-config libssl-dev libsqlite3-dev zlib1g-dev libboost-all-dev

# Ensure a recent CMake (>= 3.18) is available; upgrade if needed for your distro.
cmake --version || true

# 2) Rust toolchain
curl https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"

# 3) Build from source
git clone --depth=1 https://github.com/praetorian-inc/noseyparker /tmp/noseyparker-src
cd /tmp/noseyparker-src
cargo build --release

# 4) Put on PATH
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/target/release/noseyparker-cli" "$HOME/.local/bin/noseyparker"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
noseyparker --version
```

The CLI will use the local `noseyparker` binary when available. If it’s missing or fails to run, it automatically falls back to a Docker-based runner and writes:

```text
results/individual-repos/<repo-name>/noseyparker.json
```

Requirements for fallback: Docker running and access to `ghcr.io/praetorian-inc/noseyparker:latest`.

Manual invocation (optional):

```bash
bash scripts/core/run_noseyparker_docker.sh \
  --repo /path/to/repo \
  --out results/individual-repos/<repo-name>/noseyparker.json
```

You do not need to call this manually during normal `jmo scan/ci`; it’s used automatically if needed.

## CI and local verification

- Local “CI” bundle: `make verify` runs lint, tests, and a basic security sweep where configured.
- One‑shot CI flow: `jmo ci` combines scan + report and gates on `--fail-on`. Example:

```bash
jmo ci --repos-dir ~/repos --profile-name balanced --fail-on HIGH --profile
```

Outputs include: `summaries/findings.json`, `SUMMARY.md`, `findings.yaml`, `findings.sarif`, `dashboard.html`, and `timings.json` (when profiling).

### Interpreting CI failures (deeper guide)

Common failure modes in `.github/workflows/tests.yml` and how to fix them:

- Workflow validation (actionlint)
  - Symptom: step “Validate GitHub workflows (actionlint)” fails early.
  - Why: Invalid `uses:` reference, missing version tag, or schema errors.
  - Fix locally: run `pre-commit run actionlint --all-files`. See the action: https://github.com/rhysd/actionlint and our workflow at `.github/workflows/tests.yml`.

- Pre-commit hooks (YAML/format/lint)
  - Symptom: pre-commit step fails on YAML (`yamllint`), markdownlint, ruff/black, or shell checks.
  - Fix locally: `make pre-commit-run` or run individual hooks. Config lives in `.pre-commit-config.yaml`; YAML rules in `.yamllint.yaml`; ruff/black use defaults in this repo. Docs: https://pre-commit.com/

- Test coverage threshold not met
  - Symptom: Tests pass, but `--cov-fail-under=85` fails the job.
  - Fix locally: run `pytest -q --maxfail=1 --disable-warnings --cov=. --cov-report=term-missing` to identify gaps, then add tests. High‑leverage areas include adapters’ malformed/empty JSON handling and reporters’ edge cases. Pytest‑cov docs: https://pytest-cov.readthedocs.io/

- Codecov upload warnings (tokenless OIDC)
  - Symptom: Codecov step asks for a token or indicates OIDC not enabled.
  - Context: Public repos usually don’t require `CODECOV_TOKEN`. This repo uses tokenless OIDC with `codecov/codecov-action@v5` and minimal permissions (`contents: read`).
  - Fix: Ensure `coverage.xml` exists (the tests step emits it) and confirm OIDC is enabled in your Codecov org/repo. Action docs: https://github.com/codecov/codecov-action and OIDC docs: https://docs.codecov.com/docs/tokenless-uploads

- Canceled runs (concurrency)
  - Symptom: A run is marked “canceled.”
  - Why: Concurrency is enabled to cancel in‑progress runs on rapid pushes. Re‑run or push again once ready.

- Matrix differences (Ubuntu vs macOS)
  - Symptom: Step passes on one OS but fails on another.
  - Tips: Confirm tool availability/paths on macOS (Homebrew), line endings, and case‑sensitive paths. Use conditional install steps if needed.

If the failure isn’t listed, expand the step logs in GitHub Actions for detailed stderr/stdout. When opening an issue, include the exact failing step and error snippet.

## Troubleshooting

Tools not found
- Run `make verify-env` for detection and install hints, or install missing tools; use `--allow-missing-tools` for exploratory runs.

No repositories to scan
- Ensure you passed `--repo`, `--repos-dir`, or `--targets`; when using `--repos-dir`, only immediate subfolders are considered.

Slow scans
- Reduce the toolset via a lighter profile (`fast`), or increase threads; use `report --profile` to inspect `timings.json` and adjust.

YAML reporter missing
- If PyYAML isn’t installed, YAML output is skipped with a DEBUG log; install `pyyaml` to enable.

Permission denied on scripts
- Ensure scripts are executable: `find scripts -type f -name "*.sh" -exec chmod +x {} +`

Hadolint shows no results
- Hadolint only runs when a `Dockerfile` exists at the repo root; this is expected. With `--allow-missing-tools`, a stub may be created when appropriate so reporting still works.

TruffleHog output looks empty
- Depending on flags and repo history, TruffleHog may stream JSON objects rather than a single array. The CLI captures and writes this stream verbatim; empty output is valid if no secrets are detected.

## Reference: CLI synopsis

Scan

```bash
jmo scan [--repo PATH | --repos-dir DIR | --targets FILE] \
  [--results-dir DIR] [--config FILE] [--tools ...] [--timeout SECS] [--threads N] \
  [--allow-missing-tools] [--profile-name NAME] [--log-level LEVEL] [--human-logs]
```

Report

```bash
jmo report RESULTS_DIR [--out DIR] [--config FILE] [--fail-on SEV] [--profile] \
  [--threads N] [--log-level LEVEL] [--human-logs]
```

CI (scan + report)

```bash
jmo ci [--repo PATH | --repos-dir DIR | --targets FILE] \
  [--results-dir DIR] [--config FILE] [--tools ...] [--timeout SECS] [--threads N] \
  [--allow-missing-tools] [--profile-name NAME] [--fail-on SEV] [--profile] \
  [--log-level LEVEL] [--human-logs]
```

—

Happy scanning!
