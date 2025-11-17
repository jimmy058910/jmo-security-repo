# Copilot instructions for jmo-security-repo

These guidelines help AI coding agents work effectively in this repository. Focus on the concrete patterns, commands, and structure used here. Keep changes small, additive, and validated by running quick checks.

## Big picture

- Terminal-first security audit toolkit with a Python CLI (`scripts/cli/jmo.py`) and supporting modules under `scripts/core/`.
- Two main phases:
  1) scan: invoke external scanners (semgrep, trivy, checkov, bandit, noseyparker, syft, trufflehog, hadolint, zap, falco, afl++) and write raw JSON per repo under `results/individual-repos/<repo>/`.
  2) report: normalize + dedupe into a CommonFinding shape and emit summaries (`findings.json`, `SUMMARY.md`, `dashboard.html`, optional SARIF) under `results/summaries/`.

- Goals: unified outputs, stable fingerprints for dedupe, resilient to missing tools, and fast local iteration.

## Key entry points

- CLI: `scripts/cli/jmo.py`
  - Subcommands: `scan`, `report`, `ci`. Common flags: `--results-dir`, `--config jmo.yml`, `--threads`, `--profile`, `--human-logs`.
  - `scan` discovers repos from `--repo`, `--repos-dir`, or `--targets` and writes tool JSON to `results/individual-repos/<repo>/`.
  - `report` aggregates and writes to `<results_dir>/summaries` (JSON/MD/YAML/HTML/SARIF). Supports `--fail-on` severity threshold and profiling to `timings.json`.
  - `ci` = `scan` then `report` in one go; accepts same flags plus `--fail-on`.
- Aggregator: `scripts/core/normalize_and_report.py:gather_results(results_dir)`
  - Loads each tool JSON via adapters in `scripts/core/adapters/*_adapter.py`.
  - Dedupes by fingerprint id and optionally enriches Trivy findings with Syft SBOM context.
  - `PROFILE_TIMINGS` records timing when `JMO_PROFILE=1`.
- Reporters: `scripts/core/reporters/*.py` write `findings.json`, `SUMMARY.md`, `findings.yaml`, `dashboard.html`, `findings.sarif`, `SUPPRESSIONS.md`.

## Conventions & patterns

- Results layout:
  - Base dir default: `results/`
  - Raw per-repo: `results/individual-repos/<repo>/{semgrep,trivy,checkov,bandit,noseyparker,syft,trufflehog,hadolint,zap,falco,afl++}.json`
  - Summaries: `results/summaries/`
- Config: `jmo.yml`
  - Keys: `tools`, `outputs`, `fail_on`, `threads`, `profiles`, `per_tool`, `retries`.
  - Profiles can override tools/timeouts; `--profile-name` applies a profile in `scan`.
- Missing tools: if `--allow-missing-tools` is set, `scan` writes empty stubs via `_write_stub()` instead of failing.
- Severities: ordered `CRITICAL>HIGH>MEDIUM>LOW>INFO`; `--fail-on` triggers non-zero exit if any finding at or above threshold.
- Logging: machine JSON by default, human-friendly with `--human-logs`. Effective log level comes from CLI or config.
- Threading: `scan` parallelizes per-repo; `report` parallelizes adapter loads; threads can be set via `--threads` or env `JMO_THREADS`.
- Suppressions: optional `jmo.suppress.yml` in results dir or cwd filters findings; summary written to `SUPPRESSIONS.md`.

## Developer workflows (examples)

- Quick scan of a directory of repos:
  - `python3 scripts/cli/jmo.py scan --repos-dir ~/repos --human-logs`
  - `python3 scripts/cli/jmo.py report ./results --profile --human-logs`
- CI-like flow with threshold:
  - `python3 scripts/cli/jmo.py ci --repos-dir ~/repos --fail-on HIGH --profile`
- Make targets:
  - `make dev-deps` (pytest, ruff, bandit, black, pyyaml, jsonschema)
  - `make fmt` / `make lint` / `make test`
  - `make report RESULTS_DIR=/path/to/results [OUT=...] [CONFIG=jmo.yml] [FAIL_ON=]`
  - `make verify-env` to see detected tools and install hints

## Testing guidance

- Tests live under `tests/` (unit, adapters, integration). Use `make test` or `pytest -q`.
- Many tests fabricate `tmp_path / "results"` trees with minimal tool JSONs. When adding adapters/reporters, mirror these patterns.
- Exit codes: several tests assert `report` writes `dashboard.html`/`SUMMARY.md`, and verify `--fail-on` behavior.

## External tools & integration

- Tools invoked via subprocess without shell: semgrep, trivy, checkov, bandit, noseyparker (local or docker fallback), syft, trufflehog, hadolint, zap, falco, afl++.
- Respect tool-specific return codes: semgrep (0/1/2), trivy (0/1), checkov (0/1), bandit (0/1). The CLI treats these as success when outputs are produced.
- Nosey Parker: if local binary fails or missing, attempts docker via `scripts/core/run_noseyparker_docker.sh`.

## Safe change checklist for agents

- Don’t change public CLI flags/subcommands without updating `README.md`, `QUICKSTART.md`, and tests.
- When introducing a new tool adapter, update:
  - `scripts/core/normalize_and_report.py` (loader imports + scheduling)
  - `_write_stub()` and `cmd_scan()` in `scripts/cli/jmo.py`
  - docs (README, QUICKSTART) and tests that assert presence of files in `individual-repos/`.
- Keep output directory defaults: base `results/`, summaries in `results/summaries/`.
- Prefer small diffs and run `make test` locally.

## Pointers to key files

- CLI: `scripts/cli/jmo.py`
- Aggregation: `scripts/core/normalize_and_report.py`
- Config loader: `scripts/core/config.py`
- Reporters: `scripts/core/reporters/`
- Adapters: `scripts/core/adapters/`
- Docs: `README.md`, `QUICKSTART.md`, `SAMPLE_OUTPUTS.md`, `TEST.md`
- Make targets: `Makefile`

## Maintainers’ appendix

### Profiles in `jmo.yml` (default_profile: balanced)

- fast
  - tools: [trufflehog, semgrep, trivy]
  - threads: 8
  - timeout: 300
  - per_tool:
    - semgrep.flags: ["--exclude", "node_modules", "--exclude", ".git"]

- balanced (default)
  - tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, zap]
  - threads: 4
  - timeout: 600
  - per_tool:
    - semgrep.flags: ["--exclude", "node_modules", "--exclude", ".git"]
    - trivy.flags: ["--no-progress"]

- deep
  - tools: [trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, falco, afl++]
  - threads: 2
  - timeout: 900
  - retries: 1
  - per_tool:
    - semgrep.flags: ["--exclude", "node_modules", "--exclude", ".git"]
    - trivy.flags: ["--no-progress"]

Notes

- You can override a profile at runtime via `--profile-name` (scan/ci) and still pass per-tool flags using `jmo.yml` `per_tool`.
- `allow-missing-tools` writes stub outputs instead of failing; useful for constrained CI environments.

### CommonFinding fields used by reporters

Required fields (consumed across reporters)

- schemaVersion: string (e.g., "1.0.0")
- id: string fingerprint (stable; used for dedupe)
- ruleId: string (rule/check identifier)
- severity: one of [CRITICAL, HIGH, MEDIUM, LOW, INFO]
- tool: object { name: string, version: string }
- location: object { path: string, startLine: number, endLine?: number }
- message: string (primary display text)

Common optional fields (preserved in JSON/YAML; selectively rendered elsewhere)

- title: short string
- description: long string
- remediation: string or object
- references: string[] (URLs/Docs)
- tags: string[]
- cvss: object (e.g., { score, vector })
- context: object (e.g., sbom enrichment: { sbom: { name, version, path } })
- raw: object (original tool payload for traceability)

Reporter specifics

- JSON (`findings.json`): emits the full list of findings as-is.
- Markdown (`SUMMARY.md`): uses severity counts and top rules via `ruleId`.
- YAML (`findings.yaml`): same fields as JSON; requires PyYAML.
- HTML (`dashboard.html`): expects `severity`, `tool.name`, `location.path`/`startLine`, and `message/title` for display.
- SARIF (`findings.sarif`): maps `ruleId`, `severity`, and `location` to SARIF schema; `tool` is used for tool metadata.

Fingerprinting and dedupe

- Fingerprint (`id`) is computed from: `tool | ruleId | path | startLine | message[:120]` for stability across runs.
