# Release Notes

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
- Syft↔Trivy enrichment and expanded adapters (Syft, Trivy, Hadolint, Checkov, tfsec)
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
