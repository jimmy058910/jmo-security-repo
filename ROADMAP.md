# JMO Security Suite — Roadmap

Purpose
- Terminal-first, cross-platform (Linux, WSL, macOS) security automation to scan full repos locally from the command line.
- Extensible architecture, unified outputs (human-readable + machine-friendly), strong local verification and tests.

OS support goals
- Linux (native) and WSL: first-class support. Avoid GNU-only quirks; prefer POSIX sh where possible.
- macOS: supported. Provide brew-based tooling bootstrap alongside apt for Linux/WSL.
- Add/finish a simple verify-env script to detect OS/WSL and adapt install/run instructions.

How to use this roadmap
- Steps are roughly chronological. Keep PRs small and focused per step.
- Each step lists actions and acceptance criteria; status notes call out what’s done.

Status dashboard
- [x] Step 1 — Repo hygiene and developer workflow
- [x] Step 2 — Terminal-first quality and security checks
- [x] Step 3 — CommonFinding schema foundation
- [x] Step 4 — Adapters (normalize current tools)
- [x] Step 5 — Config-driven runs (profiles, per-tool, retries)
- [x] Step 6 — Reporters and outputs
- [x] Step 7 — CLI consolidation and UX
- [x] Step 8 — Reliability & DX polish
- [x] Step 9 — Testing depth and coverage guard (gate enforced)
- [x] Step 10 — Supply chain and optional remote CI
- [x] Step 11 — Tooling expansion (adapters, curated selection)
- [x] Step 12 — Distribution and dev environments
- [x] Step 13 — Docs, examples, and community (README polish, examples/screenshots)

Step 1 — Repo hygiene and developer workflow
Objective
- Standardize formatting and shell safety; add convenient Makefile targets.
Actions
- Add .editorconfig and .pre-commit-config.yaml (Black/Ruff/Bandit/ShellCheck/shfmt/markdownlint).
- Add Makefile: fmt, lint, test, verify, build, clean.
- Enforce shell strict mode in scripts: set -Eeuo pipefail; IFS=$'\n\t'; trap cleanup.
Acceptance
- pre-commit passes locally; make lint/test run without errors on Linux, WSL, and macOS.
Status
- Pre-commit, Ruff, Black, Bandit, ShellCheck, shfmt, markdownlint configured.
  - Fine-grained Bandit tuning added: bandit.yaml for source-only strict scan; Makefile runs a separate tests/ scan with B101/B404 skipped to reduce test noise while keeping source strict.
- Makefile targets present. Devcontainer provided.

Step 2 — Terminal-first quality and security checks (revised)
Objective
- Local, reproducible verification without requiring GitHub Actions/Dependabot.
Actions
- Add scripts/dev/ci-local.sh to run lint, unit tests, output snapshot tests, and basic security checks (semgrep, gitleaks) locally.
- Add scripts/dev/install_tools.sh with OS detection (apt for Linux/WSL, brew for macOS) to bootstrap required CLIs.
- Add make verify to call ci-local.sh and fail on thresholds/coverage.
Notes
- Confirmation: GitHub Actions and Dependabot are optional remote automations and do not provide terminal-based scanning. This project prioritizes local CLI workflows; CI can be added later as optional.
Acceptance
- One command (make verify) validates the project locally with clear pass/fail and exit codes.
Status
- Scripts present and used during local workflows; iterate as toolset expands.

Step 3 — CommonFinding schema foundation
Objective
- Normalize tool outputs to a stable schema.
Actions
- Add docs/schemas/common_finding.v1.json (JSON Schema).
- Fields: id (fingerprint), ruleId, severity, tool (name/version), location (path/lines), message, description, remediation, tags, raw.
Acceptance
- Schema committed; parsers and reporters reference schemaVersion=1.0.0.

Step 4 — Adapters (normalize current tools)
Objective
- Map each tool’s native output → CommonFinding.
Actions
- Implement Python adapters: gitleaks, trufflehog, semgrep, noseyparker; cloc for repo metadata.
- Deterministic fingerprint: hash(tool|ruleId|path|startLine|message snippet).
- Unit + snapshot tests per adapter.
Acceptance
- Adapters return validated CommonFinding objects; snapshots stable across OSes.

Step 5 — Config-driven runs
Objective
Actions
Acceptance
- Config now supports threads, outputs, fail_on, include/exclude globs, default timeout, and log_level.
Status: Implemented
- Profiles and per-tool overrides wired into scan and ci; retries supported.
- Profile selection via `--profile-name` or `default_profile`.
- Per-tool flags/timeouts supported via `per_tool` at root/inside profiles.
- include/exclude, threads, timeout pulled from selected profile with CLI precedence.
- Tests added for include/exclude, flag injection, and retry behavior.
Step 6 — Reporters and outputs (summary + detailed with tests)
Objective
- First-class outputs for humans and machines; test both summary and detailed forms.
Actions
- Implement reporters: json, yaml, md (summary), html (filters), table (CLI), sarif 2.1.0.
- Snapshot tests:
  - Summary: CLI table and Markdown summary.
  - Detailed: JSON, YAML, SARIF, HTML.
- Validate SARIF against schema; HTML loads locally without network.
Acceptance
- All reporters have snapshot tests; outputs are unified and consistent across OSes.

Status update
- Implemented JSON, Markdown, YAML, HTML reporters with tests (YAML optional if PyYAML missing).
- Added SARIF reporter and tests; CLI can emit SARIF when configured.
- Suppression workflow implemented with SUPPRESSIONS.md reporter.
- HTML reporter enhanced with client-side sorting, tool filter, CSV/JSON export, persisted filters/sort, URL deep-links, and theme toggle.
- Optional profiling summary panel appears in HTML when timings.json is present.

Step 7 — CLI consolidation and UX
Objective
- One clear CLI with robust help and exit codes.
Actions
 Python CLI: jmo scan|report|ci.
 Flags: --config, --profile-name, --tools, --threads, --timeout, --out, --fail-on, repo selectors (--repo|--repos-dir|--targets).
 Exit codes: 0 success; 1 threshold failure; 2 runtime error.
Acceptance
- Help text complete; exit codes honored by ci-local.sh.

 Added CLI with `report`, `scan`, and `ci`.
 `scan` runs tools (stubs when allowed if missing).
 `ci` composes scan+report for pipelines.
 Human logs via `--human-logs`; structured JSON by default.
- Make targets remain available; shell orchestrators preserved but CLI-first path is ready.

Step 8 — Reliability & DX polish
Objective
- Improve robustness and user experience of scans.
Status: Done for scan
- Retries for flaky tools with per-tool success-code awareness.
- Per-tool retry counters logged in scan output when attempts > 1.
- Human-friendly colored logs via `--human-logs` (default remains JSON).
- Graceful cancel on SIGINT/SIGTERM during scan.
- Per-tool timeouts and concurrency; threads configurable.
- Trivy findings enriched with Syft SBOM package context.

Step 9 — Testing depth and coverage guard
Objective
- High confidence via unit, integration, and property-based tests.
Actions
- Unit: adapters, reporters, config, fingerprinting, CLI args.
- Integration: seed repos with known findings; golden outputs (JSON/SARIF/HTML).
- Property-based: parser fuzzing (Hypothesis) and malformed JSON cases.
- Enforce coverage ≥85% locally via pytest-cov and make verify.
Acceptance
- Coverage gate enforced; goldens stable.

Status update
- Unit tests cover adapters (gitleaks, trufflehog, semgrep, noseyparker, osv-scanner, trivy, hadolint, checkov, tfsec), reporters (json/md/yaml/html/sarif), and aggregation.
- Integration tests cover CLI profiling/threads, profiles include/exclude, per-tool flags injection, retries, scan and ci flows, and schema validation.
- Suppression filtering tests and SARIF snapshot tests included.
- CI workflow runs tests with coverage and enforces a threshold.

Step 10 — Supply chain and optional remote CI
Objective
- Secure artifacts and optional hosted checks.
Actions
- Local: generate SBOM (Syft) and scan (Trivy) via make verify-supplychain.
- Optional GitHub-only: Actions for CodeQL/Semgrep/Gitleaks/OSV and release automation (release-please). Not required for local terminal workflows.
Acceptance
- Local SBOM and Trivy runs pass; remote CI can be enabled later without affecting local use.

Status note
- SARIF output available for optional code scanning integrations without requiring remote CI.

Step 11 — Tooling expansion (adapters)
Objective
- Increase coverage areas beyond secrets and SAST.
Actions
- Add adapters: OSV-Scanner (deps), Syft (SBOM), Trivy (fs/repo), Hadolint (Dockerfiles), Checkov/tfsec (IaC).
- Severity normalization and cross-tool dedupe.
Acceptance
- New tools normalized; duplicates reduced without losing signal.

Status update
- Implemented OSV-Scanner, Trivy, Syft (SBOM), Hadolint (Dockerfiles), and Checkov/tfsec (IaC) adapters with severity normalization and tests.
- Cross-links: Trivy findings are annotated with matching Syft package metadata where possible.

Curated selection guidance
- Goal: maximize detection breadth while minimizing overlap.
- Recommended baselines by category:
  - Secrets: gitleaks (fast) + noseyparker (deep). Consider adding trufflehog only in deep sweeps.
  - SAST: semgrep as primary (config=auto); extend rulesets per repo domain.
  - SBOM/Vuln/Misconfig/Secrets: syft (SBOM) + trivy (fs scanners vuln,secret,misconfig) for broad coverage.
  - IaC: checkov as primary; enable tfsec only for specific stacks or to cross-check critical IaC.
  - Containers: hadolint for Dockerfiles.
- Profiles map this guidance into fast/balanced/deep presets (see jmo.yml) so teams can right-size runs.

Step 12 — Distribution and dev environments
Objective
- Frictionless install and reproducible development.
Actions
- Package for pipx/uvx; Docker image with preinstalled toolchain (Linux/WSL/macOS via Docker).
- Devcontainer for VS Code; brew/apt steps in docs; Nix optional.
Acceptance
- Users start in minutes via pipx or Docker; devcontainer works out of the box.

Status update
- Packaging present (pyproject.toml) with `jmo` console script; version set to 0.3.0 with optional reporting extras.
- GitHub Actions: tests (pytest+coverage) and a release workflow to publish to PyPI on tag.
- Devcontainer installs jq/curl/git and preinstalls gitleaks, trufflehog, and semgrep for turnkey onboarding.

Step 13 — Docs, examples, and community
Objective
- Clear onboarding and contribution flow.
Actions
- README: tool matrix, OS support table (Linux, WSL, macOS), screenshots/gifs, quickstart, examples.
- CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, issue/PR templates.
- Architecture docs: plugin model, data flow, schemas, error handling.
- Sample intentionally vulnerable mini-repos for demos/tests.
Acceptance
- Users can run end-to-end locally in <5 minutes; contributors add a tool in <1 hour using docs.

Status note
- ROADMAP kept private and updated; examples and screenshots added (see `docs/examples` and `docs/screenshots`).

---

Release plan
- v0.3.0 (current):
  - CLI documentation and examples aligned on `jmo report <results_dir>` usage, plus refreshed quickstart guidance.
  - Optional `reporting` extra published to bundle PyYAML/jsonschema; version bumped in `pyproject.toml`.
  - Acceptance suite exercises dashboard generation and wrapper orchestration against current paths.
  - Shell/Python lint debt resolved; `make lint` is CI-ready alongside existing unit/integration coverage.

Near-term next steps
- [x] Docs polish: README quickstart and config examples for profiles/per_tool/retries/human-logs/graceful cancel.
- [x] Security posture note for contributors: subprocess/Bandit policy
  - We invoke external CLI tools (gitleaks, trufflehog, semgrep, etc.) via Python's subprocess without shell=True and with fixed argument lists. Inputs are derived from vetted config and repository paths, not raw user strings.
  - Bandit rules: B404 (import_subprocess) and B603 (subprocess.run) are expected and acceptable in this context. Where flagged, we annotate with targeted `# nosec` and a brief justification. We do not disable these rules globally.
  - Guidance: Never use shell=True; avoid passing untrusted strings into the command list; prefer explicit allowlists for tool binaries; log failures at DEBUG and fail gracefully. If dynamic arguments are required, validate/sanitize them first and add a short inline comment explaining the safety rationale.
- [x] Verify environment script: finalize OS/WSL/macOS detection and bootstrap instructions. (see scripts/dev/verify-env.sh)
 [x] Expand examples and add screenshots/gifs of the HTML dashboard. (docs/examples, docs/screenshots; capture.sh added)
- [x] Decide on CI coverage threshold target — Raised to 85% in CI tests workflow.
 [x] Prepare badges (build, coverage, PyPI) to README. (see docs/badges.md)

Later ideas
- Additional adapters (e.g., Kubernetes/policy scanners), cross-tool dedupe and richer correlation.
- Configurable SARIF tuning (level mappings, rule metadata enrichment).
- Optional Docker image for all-in-one runs across OSes.

References
- Semgrep — https://github.com/returntocorp/semgrep
- Gitleaks — https://github.com/gitleaks/gitleaks
- TruffleHog — https://github.com/trufflesecurity/trufflehog
- Nosey Parker — https://github.com/praetorian-inc/noseyparker
- OSV-Scanner — https://github.com/google/osv-scanner
- Syft — https://github.com/anchore/syft
- Trivy — https://github.com/aquasecurity/trivy
- SARIF 2.1.0 — https://github.com/oasis-tcs/sarif-spec
- CycloneDX — https://cyclonedx.org