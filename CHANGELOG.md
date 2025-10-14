# Changelog

For the release process, see docs/RELEASE.md.

## Unreleased

Developer experience improvements:
- Optional reproducible dev deps via pip-tools and uv:
	- Added `requirements-dev.in` and Make targets: `upgrade-pip`, `deps-compile`, `deps-sync`, `deps-refresh`, `uv-sync`.
	- Local pre-commit hook auto-runs `deps-compile` when `requirements-dev.in` changes.
	- CI workflow `deps-compile-check` ensures `requirements-dev.txt` stays fresh on PRs.

No changes to runtime packaging. Existing workflows (`make dev-deps`, `make dev-setup`) continue to work unchanged.

## 0.3.0 (2025-10-12)

Highlights:
- Documentation now reflects the `jmo report <results_dir>` syntax across README, Quickstart, User Guide, and example workflows.
- Packaging adds a `reporting` extra (`pip install jmo-security[reporting]`) bundling PyYAML and jsonschema for YAML output and schema validation.
- Acceptance suite updated to exercise the current dashboard generator and wrapper scripts end-to-end.
- Shell/Python lint fixes ensure `make lint` runs cleanly in CI and locally.

Operational notes:
- Acceptance fixtures expanded to cover additional TruffleHog output shapes while cleaning up temp artifacts automatically.
- Repository metadata bumped to 0.3.0 (`pyproject.toml`, roadmap) to align with this release.

## 0.2.0

Highlights:
- HTML reporter enhancements: sortable columns, tool filter dropdown, CSV/JSON export, persisted filters/sort, deep-links, and theme toggle.
- Profiling mode (`--profile`) now records per-job timings and thread recommendations. Timing metadata exposed.
- Thread control improvements: `--threads` flag with precedence over env/config; config supports `threads:`.
- New adapters: Syft (SBOM), Hadolint (Dockerfiles), Checkov and tfsec (IaC). Aggregator wired to load their outputs when present.
- Devcontainer now installs gitleaks, trufflehog, and semgrep for turnkey use.
- Packaging scaffold via `pyproject.toml` with `jmo` console script.
- Profiles and per-tool overrides in config (tools/threads/timeout/include/exclude; per_tool flags/timeout)
- Retries for flaky tool invocations with success-code awareness per tool
- Graceful cancel in scan (SIGINT/SIGTERM)
- Optional human-friendly colored logs via `--human-logs`

Roadmap items completed in this release:
- Profiles and per-tool overrides; retries; graceful cancel; human logs
- Syft→Trivy enrichment and expanded adapters (Syft, Trivy, Hadolint, Checkov, tfsec)
- HTML dashboard improvements and profiling summary
- CLI consolidation (scan/report/ci) with robust exit codes
- Local verification scripts (verify-env, populate_targets), docs and examples

Notes:
- Syft adapter emits INFO package entries and vulnerability entries when present; used for context and future cross-linking.
- Backwards compatibility maintained; features are additive.

Planned (future ideas):
- Additional adapters and policy scanners
- Richer cross-tool correlation and dedupe
- Configurable SARIF tuning and rule metadata enrichment
- Optional containerized all-in-one image for turnkey runs

## 0.1.0
- Initial CLI and adapters (Gitleaks, TruffleHog, Semgrep, Nosey Parker, OSV, Trivy)
- Unified reporters (JSON, Markdown, YAML, HTML, SARIF) and suppression report
- Config file, aggregation, and basic performance optimizations

---

## Roadmap Summary (Steps 1–13)

- Step 1 — Repo hygiene & DX: Pre-commit, Black/Ruff/Bandit/ShellCheck/shfmt/markdownlint; Makefile targets; strict shell conventions.
- Step 2 — Local verification: `ci-local.sh`, `install_tools.sh`, and `make verify` for terminal-first validation without remote CI.
- Step 3 — CommonFinding schema: v1.0.0 schema established for normalized finding outputs.
- Step 4 — Adapters: Secrets (gitleaks, trufflehog, noseyparker), SAST (semgrep, bandit), SBOM/vuln (syft, trivy), IaC (checkov, tfsec), Dockerfile (hadolint), OSV.
- Step 5 — Config-driven runs: profiles, per-tool overrides, include/exclude, threads, timeouts, retries, log levels; CLI precedence wired.
- Step 6 — Reporters & outputs: JSON/MD/YAML/HTML/SARIF; suppression report; profiling metadata (timings.json) consumed by HTML.
- Step 7 — CLI consolidation: `jmo scan|report|ci` with clear exit codes; human logs option; robust help.
- Step 8 — Reliability & DX polish: retries with tool-specific success codes, graceful cancel, per-tool timeouts, concurrency, Syft→Trivy enrichment.
- Step 9 — Testing: Unit, integration, snapshot tests across adapters/reporters/CLI; coverage gate (~85%).
- Step 10 — Supply chain & optional CI: SBOM (Syft), Trivy scan, optional SARIF-ready outputs for code scanning; remote CI optional.
- Step 11 — Tooling expansion: additional adapters and normalization; severity harmonization and dedupe.
- Step 12 — Distribution & dev envs: packaging via `pyproject.toml`, devcontainer, curated tools in dev env.
- Step 13 — Docs & examples: polished README/QUICKSTART/USER_GUIDE; examples and screenshots; suppression docs.

Notes
- These steps are broadly complete; ongoing incremental polish may land across releases.
