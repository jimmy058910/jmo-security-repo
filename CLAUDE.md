# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JMo Security Audit Tool Suite is a terminal-first, cross-platform security audit toolkit that orchestrates multiple scanners with a unified Python CLI, normalized outputs, and an HTML dashboard. The project scans repositories for secrets, vulnerabilities, misconfigurations, and security issues using industry-standard tools.

**Key Philosophy:**

- Two-phase architecture: **scan** (invoke tools, write raw JSON) → **report** (normalize, dedupe, emit unified outputs)
- Unified CommonFinding schema with stable fingerprinting for deduplication
- Profile-based configuration for different scan depths (fast/balanced/deep)
- Resilient to missing tools with fallback mechanisms

## Core Commands

### Development Setup

```bash
# Install Python dev dependencies
make dev-deps

# Install pre-commit hooks (YAML/Actions validation, formatting, linting)
make pre-commit-install

# Install external security tools (semgrep, trivy, checkov, etc.)
make tools

# Verify environment and tool availability
make verify-env

# Format code (shfmt, black, ruff)
make fmt

# Lint code (shellcheck, ruff, bandit, pre-commit)
make lint

# Run tests with coverage (CI requires ≥85%)
make test
```

### Dependency Management

```bash
# Compile requirements-dev.in → requirements-dev.txt (pip-tools)
make deps-compile

# Sync environment to compiled requirements
make deps-sync

# Upgrade pip/setuptools/wheel
make upgrade-pip

# Alternative: use uv for faster compilation/sync
make uv-sync
```

### Running Scans

```bash
# Interactive wizard (recommended for first-time users)
jmotools wizard

# Non-interactive wizard with defaults
jmotools wizard --yes

# Fast scan with wrapper command
jmotools fast --repos-dir ~/repos

# Balanced scan (default profile)
jmotools balanced --repos-dir ~/repos

# Full deep scan
jmotools full --repos-dir ~/repos

# Manual scan using Python CLI
python3 scripts/cli/jmo.py scan --repos-dir ~/repos --profile-name balanced --human-logs

# Aggregate and report
python3 scripts/cli/jmo.py report ./results --profile --human-logs

# CI mode: scan + report + threshold gating in one command
python3 scripts/cli/jmo.py ci --repos-dir ~/repos --fail-on HIGH --profile
```

### Running a Single Test

```bash
# Run specific test file
pytest tests/unit/test_common_and_sarif.py -v

# Run specific test function
pytest tests/unit/test_common_and_sarif.py::test_write_sarif -v

# Run with coverage
pytest tests/unit/ --cov=scripts --cov-report=term-missing

# Run adapter tests (useful when adding new tool adapters)
pytest tests/adapters/test_gitleaks_adapter.py -v

# Run integration tests (end-to-end CLI workflows)
pytest tests/integration/test_cli_scan_ci.py -v

# Run tests by category
pytest tests/unit/ -v         # All unit tests
pytest tests/adapters/ -v     # All adapter tests
pytest tests/reporters/ -v    # All reporter tests
pytest tests/integration/ -v  # All integration tests
```

## Architecture

### Directory Structure

```text
scripts/
├── cli/
│   ├── jmo.py          # Main CLI entry point (scan/report/ci commands)
│   ├── jmotools.py     # Wrapper commands (fast/balanced/full/setup)
│   └── wizard.py       # Interactive wizard for guided scanning
├── core/
│   ├── normalize_and_report.py  # Aggregation engine: loads tool outputs, dedupes, enriches
│   ├── config.py       # Config loader for jmo.yml
│   ├── suppress.py     # Suppression logic (jmo.suppress.yml)
│   ├── common_finding.py  # CommonFinding schema and fingerprinting
│   ├── adapters/       # Tool output parsers (gitleaks, semgrep, trivy, etc.)
│   │   ├── gitleaks_adapter.py
│   │   ├── semgrep_adapter.py
│   │   ├── trivy_adapter.py
│   │   └── ...
│   └── reporters/      # Output formatters
│       ├── basic_reporter.py    # JSON + Markdown
│       ├── yaml_reporter.py     # YAML (optional, requires PyYAML)
│       ├── html_reporter.py     # Interactive dashboard
│       ├── sarif_reporter.py    # SARIF 2.1.0
│       └── suppression_reporter.py  # Suppression summary
└── dev/               # Helper scripts for tool installation and CI

tests/
├── unit/              # Core logic tests
├── adapters/          # Adapter tests with fabricated JSON fixtures
├── reporters/         # Reporter tests
├── integration/       # End-to-end CLI tests
└── cli/               # CLI argument and smoke tests
```

### Key Concepts

**Two-Phase Workflow:**

1. **Scan Phase** (`jmo scan`):
   - Discovers repos from `--repo`, `--repos-dir`, or `--targets`
   - Invokes tools in parallel (configurable threads)
   - Writes raw JSON to `results/individual-repos/<repo>/{tool}.json`
   - Supports timeouts, retries, and per-tool overrides
   - Gracefully handles missing tools with `--allow-missing-tools` (writes empty stubs)

2. **Report Phase** (`jmo report`):
   - Loads all tool outputs via adapters
   - Normalizes to CommonFinding schema
   - Deduplicates by fingerprint ID
   - Enriches Trivy findings with Syft SBOM context
   - Writes unified outputs: `findings.json`, `SUMMARY.md`, `dashboard.html`, `findings.sarif`, etc.
   - Supports severity-based failure thresholds (`--fail-on HIGH`)

**CommonFinding Schema:**

All tool outputs are converted to a unified shape defined in `docs/schemas/common_finding.v1.json`:

- **Required fields:** `schemaVersion`, `id` (fingerprint), `ruleId`, `severity`, `tool` (name/version), `location` (path/lines), `message`
- **Optional fields:** `title`, `description`, `remediation`, `references`, `tags`, `cvss`, `context`, `raw` (original tool payload)
- **Fingerprinting:** Deterministic ID computed from `tool | ruleId | path | startLine | message[:120]` to enable cross-run deduplication

**Profiles:**

Configuration via `jmo.yml` supports named profiles for different scan depths:

- **fast:** Minimal tools (gitleaks, semgrep), 300s timeout, 4 threads
- **balanced:** Default comprehensive (gitleaks, noseyparker, semgrep, syft, trivy, checkov, hadolint), 600s timeout
- **deep:** All tools including tfsec, bandit, trufflehog, osv-scanner, 900s timeout, retries enabled

Profiles can override tools, timeouts, threads, and per-tool flags. Use `--profile-name <name>` to apply.

**Interactive Wizard:**

The wizard (`scripts/cli/wizard.py`) provides guided onboarding for first-time users:

- **Interactive mode:** Step-by-step prompts for profile selection, target configuration, execution mode (Docker/native)
- **Non-interactive mode:** `--yes` flag uses smart defaults for automation
- **Artifact generation:** Can emit Makefile targets (`--emit-make-target`), shell scripts (`--emit-script`), or GitHub Actions workflows (`--emit-gha`) for reusable configurations
- **Docker integration:** Automatically detects Docker availability and offers zero-installation scanning
- Auto-opens results dashboard after scan completion

### Tool Adapters

Each adapter in `scripts/core/adapters/` follows this pattern:

1. Check if output file exists
2. Parse tool-specific JSON format
3. Map to CommonFinding schema
4. Generate stable fingerprint ID
5. Return list of findings

**Supported Tools:**

- **Secrets:** gitleaks, noseyparker (local + Docker fallback), trufflehog
- **SAST:** semgrep, bandit
- **SBOM+Vuln:** syft (SBOM generation), trivy (vuln/misconfig/secrets scanning)
- **IaC:** checkov, tfsec
- **Dockerfile:** hadolint

**Nosey Parker Fallback:**

When local binary is missing/fails, automatically falls back to Docker-based runner via `scripts/core/run_noseyparker_docker.sh`. Requires Docker installed and `ghcr.io/praetorian-inc/noseyparker:latest` image.

### Output Formats

Report phase writes to `<results_dir>/summaries/`:

- `findings.json` — Unified normalized findings (machine-readable)
- `SUMMARY.md` — Human-readable summary with severity counts and top rules
- `findings.yaml` — Optional YAML format (requires `pip install -e ".[reporting]"`)
- `dashboard.html` — Self-contained interactive HTML dashboard
- `findings.sarif` — SARIF 2.1.0 for code scanning platforms (GitHub, GitLab, etc.)
- `SUPPRESSIONS.md` — Summary of suppressed findings (when `jmo.suppress.yml` is present)
- `timings.json` — Profiling data (when `--profile` flag used)

### Configuration

**jmo.yml** controls tool selection, output formats, thresholds, and profiles:

```yaml
default_profile: balanced
tools: [gitleaks, noseyparker, semgrep, syft, trivy, checkov, hadolint]
outputs: [json, md, yaml, html, sarif]
fail_on: ""  # Optional: CRITICAL/HIGH/MEDIUM/LOW/INFO
retries: 0   # Global retry count for flaky tools
threads: 4   # Default parallelism

profiles:
  fast:
    tools: [gitleaks, semgrep]
    timeout: 300
    per_tool:
      semgrep:
        flags: ["--exclude", "node_modules"]

per_tool:
  trivy:
    flags: ["--ignore-unfixed"]
    timeout: 1200
```

**jmo.suppress.yml** (optional) filters findings:

```yaml
suppressions:

  - id: "fingerprint-id-here"
    reason: "False positive, accepted risk"

  - ruleId: "G101"
    path: "tests/*"
    reason: "Test files excluded"
```

## Testing Strategy

- **Unit tests** (`tests/unit/`): Core logic, config parsing, helpers
- **Adapter tests** (`tests/adapters/`): Parse fabricated tool JSON fixtures, validate CommonFinding mapping
- **Reporter tests** (`tests/reporters/`): Verify output formats (JSON/MD/YAML/HTML/SARIF)
- **Integration tests** (`tests/integration/`): End-to-end CLI flows, profile/thread behavior, CI gating

**Test Patterns:**

- Use `tmp_path` fixture for isolated file operations
- Fabricate minimal tool JSONs to test adapters
- Mock subprocess calls when testing tool invocation logic
- Assert on specific exit codes for `--fail-on` thresholds

**Coverage:**

CI enforces ≥85% coverage (see `.github/workflows/tests.yml`). Upload to Codecov uses OIDC (tokenless) for public repos.

## CI/CD

**GitHub Actions Workflows:**

- `.github/workflows/tests.yml` — Test matrix (Ubuntu/macOS × Python 3.10/3.11/3.12), coverage upload, pre-commit checks
- `.github/workflows/release.yml` — Automated PyPI publishing on `v*` tags using Trusted Publishers (OIDC, no token required)

**Pre-commit Hooks:**

Configured via `.pre-commit-config.yaml`:

- **Formatting:** Black, Ruff, shfmt (shell scripts)
- **Linting:** Ruff, shellcheck, yamllint, markdownlint
- **Validation:** actionlint (GitHub Actions), check-yaml, detect-private-key
- **Security:** Bandit (local only; skipped in CI pre-commit stage but covered by `make lint`)

Run `make pre-commit-run` before committing. CI enforces these checks.

## Common Development Tasks

### Adding a New Tool Adapter

1. Create `scripts/core/adapters/<tool>_adapter.py` following existing patterns:
   - `load_<tool>(path: Path) -> List[Dict[str, Any]]`
   - Map tool output to CommonFinding schema
   - Generate stable fingerprint via `common_finding.py` utilities
2. Update `scripts/core/normalize_and_report.py`:
   - Import the loader
   - Add to the loop in `gather_results()`
3. Update `scripts/cli/jmo.py`:
   - Add tool invocation logic to `cmd_scan()`
   - Update `_write_stub()` for empty JSON structure
4. Add fabricated test JSON to `tests/adapters/test_<tool>_adapter.py`
5. Update docs: `README.md`, `QUICKSTART.md`, `jmo.yml` tool lists

### Modifying Output Formats

- Reporters live in `scripts/core/reporters/`
- JSON/Markdown: `basic_reporter.py`
- YAML: `yaml_reporter.py` (requires PyYAML)
- HTML: `html_reporter.py` (self-contained template)
- SARIF: `sarif_reporter.py` (maps to SARIF 2.1.0 schema)
- Update `scripts/cli/jmo.py:cmd_report()` to call new reporter
- Add tests in `tests/reporters/`

### Changing CLI Behavior

- Main CLI: `scripts/cli/jmo.py`
- Subcommands: `scan`, `report`, `ci`
- When modifying flags/behavior:
  1. Update `parse_args()` function
  2. Update `README.md`, `QUICKSTART.md`, `SAMPLE_OUTPUTS.md`
  3. Add/update tests in `tests/cli/` and `tests/integration/`

### Updating Dependencies

- **Runtime deps:** Minimal; declared in `pyproject.toml` under `[project.dependencies]` (currently empty)
- **Optional deps:** `[project.optional-dependencies]` for reporters (PyYAML, jsonschema)
- **Dev deps:** `requirements-dev.in` → compile with `make deps-compile` → commit `requirements-dev.txt`
- **External tools:** Install via `make tools` (see `scripts/dev/install_tools.sh`)
- **Pre-commit hooks:** Update with `pre-commit autoupdate`

CI validates that `requirements-dev.txt` matches `requirements-dev.in` on PRs.

## Important Conventions

### Tool Invocation

- Tools invoked via `subprocess.run()` without shell (`shell=False`)
- Respect tool-specific exit codes:
  - semgrep: 0 (clean), 1 (findings), 2 (errors) — treat 0/1/2 as success when output exists
  - trivy/checkov/bandit: 0/1 treated as success
  - gitleaks/trufflehog: 0/1 treated as success
- Timeout enforcement per tool (configurable via `jmo.yml` per_tool overrides)
- Retry logic: global `retries` or per-profile; skips retries for "findings" exit codes

### Logging

- Machine JSON logs by default (structured for parsing)
- Human-friendly colored logs with `--human-logs` flag
- Log levels: DEBUG/INFO/WARN/ERROR (controlled by `--log-level` or config)
- Always log to stderr, never stdout (stdout reserved for tool outputs)

### Security Practices

- Never commit secrets (pre-commit hook checks via `detect-private-key`)
- Bandit scans `scripts/` with strict config (`bandit.yaml`)
- Test files scanned with B101,B404 skipped
- No shell=True in subprocess calls (use list args)
- Validate all file paths from user input

### Results Directory Layout

```text
results/
├── individual-repos/
│   └── <repo-name>/
│       ├── gitleaks.json
│       ├── semgrep.json
│       ├── trivy.json
│       └── ...
└── summaries/
    ├── findings.json
    ├── SUMMARY.md
    ├── findings.yaml
    ├── dashboard.html
    ├── findings.sarif
    ├── SUPPRESSIONS.md
    └── timings.json (when --profile used)
```

Never change default paths without updating all tests and documentation.

## Release Process

1. Bump version in `pyproject.toml` under `[project] version`
2. Update `CHANGELOG.md` with changes
3. Commit with message: `release: vX.Y.Z`
4. Create and push tag: `git tag vX.Y.Z && git push --tags`
5. CI publishes to PyPI automatically using Trusted Publishers (OIDC)

**Prerequisites:**

- Configure repo as Trusted Publisher in PyPI settings (one-time setup)
- No `PYPI_API_TOKEN` required with OIDC workflow

## Troubleshooting

### Tests Failing

- Run `make test` locally with `--maxfail=1` to stop at first failure
- Check coverage with `pytest --cov --cov-report=term-missing`
- Ensure `requirements-dev.txt` is up to date: `make deps-compile`

### Tool Not Found

- Run `make verify-env` to see detected tools and install hints
- Install missing tools: `make tools` (Linux/WSL/macOS detection)
- Use `--allow-missing-tools` to write empty stubs instead of failing

### Pre-commit Hook Failures

- Run `make pre-commit-run` to see all violations
- Format code: `make fmt`
- Lint code: `make lint`
- Update hooks: `pre-commit autoupdate`

### CI Failures

- Matrix tests run on Ubuntu/macOS × Python 3.10/3.11/3.12
- Check coverage ≥85% threshold
- Verify `requirements-dev.txt` matches `requirements-dev.in`
- Pre-commit checks must pass (actionlint, yamllint, etc.)

## Additional Resources

- User Guide: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
- Quick Start: [QUICKSTART.md](QUICKSTART.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Testing: [TEST.md](TEST.md)
- Release Process: [docs/RELEASE.md](docs/RELEASE.md)
- CommonFinding Schema: [docs/schemas/common_finding.v1.json](docs/schemas/common_finding.v1.json)
- Copilot Instructions: [.github/copilot-instructions.md](.github/copilot-instructions.md)
- Project Homepage: [jmotools.com](https://jmotools.com)

## Perfect Documentation Structure

**IMPORTANT: This section defines the canonical documentation structure. Follow this guidance to avoid creating unnecessary or duplicate documentation files.**

### Documentation Hierarchy and Purpose

```text
/
├── README.md                          # Project overview, "Three Ways to Get Started", badges
├── QUICKSTART.md                      # 5-minute guide for all user types
├── CONTRIBUTING.md                    # Contributor setup and workflow
├── CHANGELOG.md                       # Version history with user-facing changes
├── ROADMAP.md                         # Future plans and completed milestones
├── SAMPLE_OUTPUTS.md                  # Example outputs from real scans
├── TEST.md                            # Testing guide for contributors
└── docs/
    ├── index.md                       # Documentation hub with all links
    ├── USER_GUIDE.md                  # Comprehensive reference guide
    ├── DOCKER_README.md               # Docker deep-dive (variants, CI/CD, troubleshooting)
    ├── docs/DOCKER_README.md # Complete beginner Docker tutorial
    ├── WIZARD_IMPLEMENTATION.md       # Wizard implementation details (for contributors)
    ├── RELEASE.md                     # Release process for maintainers
    ├── MCP_SETUP.md                   # MCP server setup instructions
    ├── examples/
    │   ├── README.md                  # Examples index
    │   ├── wizard-examples.md         # Wizard workflows and patterns
    │   ├── scan_from_tsv.md           # TSV scanning tutorial
    │   └── github-actions-docker.yml  # CI/CD examples
    ├── screenshots/
    │   └── README.md                  # Screenshot capture guide
    └── schemas/
        └── common_finding.v1.json     # CommonFinding data schema
```

### User Journey-Based Documentation

**Entry points based on user persona:**

1. **Complete Beginner** (Never used security tools)
   - Start: [docs/DOCKER_README.md#quick-start-absolute-beginners](docs/DOCKER_README.md#quick-start-absolute-beginners) OR run `jmotools wizard`
   - Reason: Zero-installation path with step-by-step guidance
   - Next: [docs/examples/wizard-examples.md](docs/examples/wizard-examples.md)

2. **Developer** (Familiar with CLI, wants quick start)
   - Start: [QUICKSTART.md](QUICKSTART.md)
   - Reason: Fast 5-minute setup with platform-specific instructions
   - Next: [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for deeper features

3. **DevOps/SRE** (CI/CD integration focus)
   - Start: [docs/DOCKER_README.md](docs/DOCKER_README.md)
   - Reason: Container-based deployment, CI/CD patterns
   - Next: [docs/examples/github-actions-docker.yml](docs/examples/github-actions-docker.yml)

4. **Advanced User** (Fine-tuning, custom profiles)
   - Start: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
   - Reason: Comprehensive configuration reference
   - See also: `jmo.yml` examples and per-tool overrides

5. **Contributor** (Code contributions)
   - Start: [CONTRIBUTING.md](CONTRIBUTING.md)
   - Reason: Dev setup, coding standards, PR workflow
   - Next: [TEST.md](TEST.md) and [docs/RELEASE.md](docs/RELEASE.md)

### Documentation Content Guidelines

**README.md:**

- Purpose: First impression, project value proposition, quick navigation
- Content: Badges, "Three Ways to Get Started" (Wizard/Docker/Local), features overview, tool list
- Length: Moderate (current length is appropriate)
- Updates: When major features added (Docker, Wizard) or key workflows change

**QUICKSTART.md:**

- Purpose: Get ANY user from zero to first scan in 5 minutes
- Content: Platform-specific setup (Linux/WSL/macOS), basic scan commands, result viewing
- Length: Concise, scannable
- Updates: When default workflows or commands change

**docs/USER_GUIDE.md:**

- Purpose: Comprehensive reference for all features
- Content: Configuration reference, CLI synopsis, profiles, suppressions, CI troubleshooting
- Length: Long (current length appropriate)
- Updates: When new CLI flags, config options, or features added

**docs/DOCKER_README.md:**

- Purpose: Complete Docker guide for all skill levels
- Content: Image variants, CI/CD patterns, troubleshooting, security considerations
- Length: Medium-long
- Updates: When new Docker images, variants, or CI examples added

**docs/DOCKER_README.md#quick-start-absolute-beginners:**

- Purpose: Hand-holding tutorial for absolute beginners
- Content: Docker installation, first scan, understanding results, common scenarios
- Length: Long (step-by-step requires detail)
- Updates: When beginner workflows or Docker commands change

**docs/examples/wizard-examples.md:**

- Purpose: Wizard workflows and use cases
- Content: Interactive mode, non-interactive mode, artifact generation, common patterns
- Length: Medium
- Updates: When wizard features or flags added

**docs/index.md:**

- Purpose: Documentation hub - single source of truth for all doc links
- Content: Links to all docs organized by purpose, quick links, FAQ
- Length: Short (just navigation)
- Updates: When ANY documentation file is added, moved, or removed

### What NOT to Create

**Do NOT create these files unless explicitly requested:**

1. ❌ `ARCHITECTURE.md` - Architecture covered in CLAUDE.md
2. ❌ `INSTALLATION.md` - Installation covered in QUICKSTART.md and README.md
3. ❌ `CONFIGURATION.md` - Configuration covered in USER_GUIDE.md
4. ❌ `API.md` - Not applicable (CLI tool, not library)
5. ❌ `TUTORIAL.md` - Tutorials split appropriately (Docker beginner, Wizard examples)
6. ❌ `FAQ.md` - FAQ embedded in docs/index.md and relevant guides
7. ❌ `DEVELOPMENT.md` - Development covered in CONTRIBUTING.md
8. ❌ Additional `ROADMAP_*.md` files - Single ROADMAP.md is sufficient
9. ❌ Multiple beginner guides - One comprehensive Docker guide is enough
10. ❌ Duplicate quick starts - QUICKSTART.md is the canonical 5-minute guide

### Documentation Update Triggers

**When to update documentation:**

1. **New Major Feature** (Docker images, Wizard, etc.)
   - Update: README.md, QUICKSTART.md, docs/index.md, relevant deep-dive docs
   - Add: Examples in docs/examples/ if workflow patterns emerge
   - Update: CHANGELOG.md with user-facing changes

2. **New CLI Flag or Command**
   - Update: docs/USER_GUIDE.md (CLI synopsis section)
   - Update: QUICKSTART.md if it affects basic workflows
   - Update: docs/examples/ if it enables new patterns

3. **New Configuration Option**
   - Update: docs/USER_GUIDE.md (Configuration section)
   - Update: Example `jmo.yml` snippets throughout docs
   - Update: docs/index.md FAQ if commonly asked

4. **Breaking Change**
   - Update: ALL affected documentation files
   - Add: Migration guide in CHANGELOG.md
   - Add: Deprecation notices in relevant docs

5. **Bug Fix (User-Facing)**
   - Update: CHANGELOG.md only
   - Update: Troubleshooting sections if behavior change affects common issues

6. **Contributor Workflow Change**
   - Update: CONTRIBUTING.md, TEST.md, docs/RELEASE.md
   - Update: CLAUDE.md if dev setup changes

### Documentation Cross-References

**Always use relative links:**

- ✅ `[docs/USER_GUIDE.md](docs/USER_GUIDE.md)`
- ❌ `https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/USER_GUIDE.md` (breaks in forks)

**Link to section anchors when helpful:**

- ✅ `[USER_GUIDE.md — Configuration](docs/USER_GUIDE.md#configuration-jmoyml)`
- ✅ `[QUICKSTART.md — Docker Mode](QUICKSTART.md#docker-mode)`

**Maintain bi-directional links:**

- README.md → QUICKSTART.md → USER_GUIDE.md → docs/examples/
- Each doc should link back to docs/index.md or README.md

### Documentation Maintenance Checklist

When adding/updating documentation:

- [ ] Updated docs/index.md with new links
- [ ] Updated CHANGELOG.md if user-facing
- [ ] Verified all cross-references still work
- [ ] Checked for duplicate content (consolidate if found)
- [ ] Used relative links (no absolute GitHub URLs)
- [ ] Added section to table of contents if new doc
- [ ] Ran markdownlint (`make pre-commit-run`)
- [ ] Verified examples are copy-pasteable
- [ ] Updated CLAUDE.md if documentation structure changed

## Key Files Reference

| File | Purpose |
|------|---------|
| `scripts/cli/jmo.py` | Main CLI entry point (scan/report/ci) |
| `scripts/cli/jmotools.py` | Wrapper commands (wizard, fast, balanced, full, setup) |
| `scripts/cli/wizard.py` | Interactive wizard implementation |
| `scripts/core/normalize_and_report.py` | Aggregation engine, deduplication, enrichment |
| `scripts/core/config.py` | Config loader for jmo.yml |
| `scripts/core/common_finding.py` | CommonFinding schema and fingerprinting |
| `scripts/core/adapters/*.py` | Tool output parsers |
| `scripts/core/reporters/*.py` | Output formatters (JSON/MD/YAML/HTML/SARIF) |
| `jmo.yml` | Main configuration file |
| `pyproject.toml` | Python package metadata and build config |
| `Makefile` | Developer shortcuts for common tasks |
| `Dockerfile`, `Dockerfile.slim`, `Dockerfile.alpine` | Docker image variants |
| `.pre-commit-config.yaml` | Pre-commit hook configuration |
| `.github/workflows/tests.yml` | CI test matrix and coverage |
| `.github/workflows/release.yml` | Automated PyPI publishing |
