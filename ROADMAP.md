# JMo Security Suite — Roadmap

**Note:** Steps 1–13 completed. See `CHANGELOG.md` for details. Implementation log archived in `docs/archive/IMPLEMENTATION_LOG_10-14-25.md`.

**Recently Completed (October 2025):**

- Phase 1: Core fixes (OSV integration, XSS fix, Severity enum, SARIF enrichment, config improvements)
- Phase 2: Testing & type safety (15 edge case tests with Hypothesis, MyPy integration, zero TODOs)
- **Phase 3: ROADMAP Item #1 - Docker All-in-One Image** ✅ **COMPLETE** (October 14, 2025)
  - 3 Docker variants (full/slim/alpine) with multi-arch support (amd64/arm64)
  - Complete CI/CD automation with GitHub Actions
  - Comprehensive documentation and 8 workflow examples
  - Full integration test suite (122 tests passing, 88% coverage)
  - See: [docs/DOCKER_README.md](docs/DOCKER_README.md) and [CHANGELOG.md](CHANGELOG.md)
- **Phase 4: ROADMAP Item #2 - Interactive Wizard (Beginner Onboarding)** ✅ **COMPLETE** (October 14, 2025)
  - Interactive 6-step guided flow for first-time users
  - Docker mode integration with auto-detection (leverages ROADMAP #1)
  - Non-interactive mode with smart defaults (`--yes` flag)
  - Artifact generation (Makefile/shell/GitHub Actions workflows)
  - Comprehensive test suite (18 tests, 100% pass rate)
  - See: [docs/examples/wizard-examples.md](docs/examples/wizard-examples.md) and [docs/WIZARD_IMPLEMENTATION.md](docs/WIZARD_IMPLEMENTATION.md)
- Current Status: 140 tests passing, 88% coverage, production-ready

**Active Migration:**

- **tfsec → Trivy IaC Scanning** ([#41](https://github.com/jimmy058910/jmo-security-repo/issues/41))
  - tfsec is deprecated (archived by Aqua Security)
  - Migration to Trivy's IaC scanning capabilities
  - See issue for implementation plan and timeline

---

## Implementation Order

Items are ordered by optimal implementation priority based on user value, dependencies, and logical progression.

### Quick Reference

| # | Feature | Status | Phase | GitHub Issue |
|---|---------|--------|-------|--------------|
| 1 | Docker All-in-One Image | ✅ Complete | A - Foundation | [#29](https://github.com/jimmy058910/jmo-security-repo/issues/29) |
| 2 | Interactive Wizard | ✅ Complete | A - Foundation | [#30](https://github.com/jimmy058910/jmo-security-repo/issues/30) |
| 3 | CI Linting - Full Pre-commit | 🚧 In Progress | A - Foundation | [#31](https://github.com/jimmy058910/jmo-security-repo/issues/31) |
| 4 | Machine-Readable Diff Reports | 📋 Planned | B - CI/CD | [#32](https://github.com/jimmy058910/jmo-security-repo/issues/32) |
| 5 | Scheduled Scans & Cron | 📋 Planned | B - CI/CD | [#33](https://github.com/jimmy058910/jmo-security-repo/issues/33) |
| 6 | Plugin System | 📋 Planned | C - Extensibility | [#34](https://github.com/jimmy058910/jmo-security-repo/issues/34) |
| 7 | Policy-as-Code (OPA) | 📋 Planned | C - Extensibility | [#35](https://github.com/jimmy058910/jmo-security-repo/issues/35) |
| 8 | Supply Chain Attestation (SLSA) | 📋 Planned | D - Enterprise | [#36](https://github.com/jimmy058910/jmo-security-repo/issues/36) |
| 9 | GitHub App Integration | 📋 Planned | D - Enterprise | [#37](https://github.com/jimmy058910/jmo-security-repo/issues/37) |
| 10 | Web UI for Results | 📋 Planned | E - Advanced UI | [#38](https://github.com/jimmy058910/jmo-security-repo/issues/38) |
| 11 | React/Vue Dashboard | 📋 Planned | E - Advanced UI | [#39](https://github.com/jimmy058910/jmo-security-repo/issues/39) |

---

## 1. Docker All-in-One Image ✅ **COMPLETE**

**Status:** ✅ Production-ready (October 14, 2025)
**Implementation:** [docs/DOCKER_IMPLEMENTATION.md](docs/DOCKER_IMPLEMENTATION.md)
**Documentation:** [docs/DOCKER_README.md](docs/DOCKER_README.md)
**GitHub Issue:** [#29](https://github.com/jimmy058910/jmo-security-repo/issues/29)

**Why First:** Removes installation friction, enables immediate CI/CD usage, broadest impact.

**Objective:** Single Docker image with all security tools pre-installed for zero-setup scanning.

**Key Benefits:**

- New users scan without installing 10+ tools
- Portable, reproducible scans in any CI system
- Everyone uses same tool versions

**Implementation:**

- Base: `ubuntu:22.04` or `alpine:3.18` (slim variant)
- Tools: gitleaks, trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, tfsec, hadolint, osv-scanner
- Image sizes: ~500MB (full), ~200MB (slim), ~150MB (alpine)
- Distribution: GitHub Container Registry + Docker Hub
- Multi-arch: linux/amd64, linux/arm64

**Usage:**

```bash
# Pull and run
docker pull ghcr.io/jimmy058910/jmo-security:latest
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  jmo scan --repo /scan --results /scan/results --profile balanced

# GitHub Actions
container:
  image: ghcr.io/jimmy058910/jmo-security:latest
steps:

  - run: jmo scan --repo . --results results --fail-on HIGH
```

**Deliverables:**

- Dockerfile with all tools
- docker-compose.yml example
- GitHub Actions integration example
- Multi-arch builds (amd64, arm64)
- Published to GHCR and Docker Hub

---

## 2. Interactive Wizard ✅ **COMPLETE**

**Status:** ✅ Production-ready (October 14, 2025)
**Implementation:** [docs/WIZARD_IMPLEMENTATION.md](docs/WIZARD_IMPLEMENTATION.md)
**Documentation:** [docs/examples/wizard-examples.md](docs/examples/wizard-examples.md)
**GitHub Issue:** [#30](https://github.com/jimmy058910/jmo-security-repo/issues/30)

**Why Second:** Complements Docker image with guided first-run experience, removes knowledge barrier.

**Objective:** Interactive guided flow for beginners to complete first scan without knowing flags.

**Key Features:**

1. Profile selection with context (fast/balanced/deep with time estimates)
2. Target selection (single repo, repos-dir, targets file, clone from TSV)
3. Smart defaults (CPU-based thread recommendations, profile-based timeouts)
4. Tool bootstrap with profile-aware suggestions
5. Docker mode selection (use pre-built images or native tools) — *leverages completed ROADMAP #1*
6. Preflight summary with generated command for copy/paste
7. Run execution with human-readable progress
8. Results opening (dashboard.html, SUMMARY.md)
9. Generate reusable artifacts (Make target, shell script, GitHub Actions workflow with Docker support)

**CLI:**

```bash
# Interactive mode
jmotools wizard

# Non-interactive with flags
jmotools wizard --profile balanced --repos-dir ~/repos --yes

# Docker mode (skip tool installation)
jmotools wizard --docker

# Generate artifacts
jmotools wizard --emit-make-target scan-repos
jmotools wizard --emit-gha .github/workflows/security.yml --docker
```

**Implementation:**

- `jmotools wizard` command (scripts/cli/wizard.py - ~800 lines)
- Interactive prompts with smart defaults and ANSI colors
- Docker mode integration with auto-detection
- Non-interactive mode (`--yes`) for automation
- Command synthesis with preview before execution
- Artifact generators:
  - `--emit-make-target`: Makefile targets
  - `--emit-script`: Executable shell scripts
  - `--emit-gha`: GitHub Actions workflows (native & Docker variants)

**Deliverables:**

- ✅ `jmotools wizard` command
- ✅ Interactive prompts with smart defaults
- ✅ Docker mode selection (leverages ROADMAP #1)
- ✅ Command synthesis and preview
- ✅ Make target / shell script / GHA workflow generation
- ✅ Comprehensive documentation with examples
- ✅ 18 comprehensive tests (100% pass rate)

---

## 3. CI Linting - Full Pre-commit Coverage

**Status:** 🚧 In Progress
**GitHub Issue:** [#31](https://github.com/jimmy058910/jmo-security-repo/issues/31)

**Why Third:** Establishes quality baseline before adding more features.

**Objective:** Enable full pre-commit hook coverage in CI while keeping PR feedback fast.

**Current State:**

- CI runs structural checks only (actionlint, yamllint)
- Full hook set available locally via `.pre-commit-config.yaml`

**Full Hook Set:**

- Basic: trailing-whitespace, end-of-file-fixer, check-yaml, check-json, check-toml, mixed-line-ending, detect-private-key, check-added-large-files
- YAML: yamllint (`.yamllint.yaml`)
- Actions: actionlint
- Markdown: markdownlint
- Python: ruff (lint + format), black, bandit (`scripts/` only)
- Shell: shellcheck, shfmt

**Implementation Plan:**

1. Check-only mode for formatters (ruff-format, black, shfmt in CI - no writes)
2. Markdown lint tuning (`.markdownlint.json` with rule relaxations)
3. Python lint policy (pin ruff version, minimal allowlist, expand gradually)
4. Shell formatting (shfmt check-only with pinned version)
5. Security linting (bandit on `scripts/` with `bandit.yaml`)
6. Nightly `lint-full` workflow (all hooks in check-only)
7. Migrate to PR CI after 2 weeks stable on main

**Acceptance Criteria:**

- PR CI remains <5–7 min
- Nightly `lint-full` green on main for 2 weeks before gating PRs
- Clear contributor docs for local auto-fixes

---

## 4. Machine-Readable Diff Reports

**Status:** 📋 Planned
**GitHub Issue:** [#32](https://github.com/jimmy058910/jmo-security-repo/issues/32)

**Why Fourth:** Essential for PR reviews and CI/CD workflows, builds on Docker foundation.

**Objective:** Compare scan results across time/commits to identify new/resolved findings and track security trends.

**Key Use Cases:**

- **PR Reviews:** "Show only NEW findings introduced by this PR"
- **Trend Analysis:** "Are we getting better or worse over time?"
- **Sprint KPIs:** "How many findings did we fix this sprint?"

**Implementation:**

```bash
# PR diff workflow
jmo diff main-results/ pr-results/ --output pr-diff.md
# Shows: 3 new, 1 resolved, 2 unchanged

# Sprint retrospective
jmo diff sprint-14-results/ sprint-15-results/ --format html

# Continuous monitoring
jmo diff --baseline week-1/ week-2/ week-3/ week-4/
```

**Diff Algorithm:**

1. Load findings from both directories
2. Match by fingerprint ID (stable deduplication)
3. Classify: New, Resolved, Unchanged, Modified
4. Generate report with summary tables

**Output Formats:**

- JSON (machine-readable)
- Markdown (human-readable tables)
- HTML (interactive dashboard with filters)

**Implementation Phases:**

### Phase 1: Core Diff Engine (Week 1)

**Scope:** Foundation for fingerprint-based comparison

**Tasks:**

1. Add `diff` subcommand to `scripts/cli/jmo.py`
   - CLI arguments: `--baseline`, `--compare`, `--output`, `--format`
   - Support single comparison and multi-baseline modes
2. Create `scripts/core/diff_engine.py`:
   - `load_findings(results_dir)` - Reuse `gather_results()` logic
   - `compare_findings(baseline, compare)` - Match by fingerprint ID
   - Classification logic: `new`, `resolved`, `unchanged`, `modified`
   - Handle edge cases: missing directories, empty scans
3. Support baseline comparison (multiple directories for trend analysis)
4. Core data structures:
   ```python
   DiffResult = {
       "new": List[Finding],       # In compare, not in baseline
       "resolved": List[Finding],  # In baseline, not in compare
       "unchanged": List[Finding], # Same fingerprint, same severity
       "modified": List[Finding]   # Same fingerprint, changed severity/details
   }
   ```

**Deliverables:**

- ✅ `jmo diff` CLI command
- ✅ Fingerprint matching algorithm
- ✅ Classification engine
- ✅ Unit tests for diff logic

**Estimated Effort:** 5-6 days

---

### Phase 2: Diff Reporters (Week 2)

**Scope:** Human and machine-readable output formats

**Tasks:**

1. Create `scripts/core/reporters/diff_reporter.py`:
   - `write_diff_json(diff_result, output_path)` - Machine-readable
   - `write_diff_markdown(diff_result, output_path)` - Human-readable tables
   - `write_diff_html(diff_result, output_path)` - Interactive dashboard
2. JSON format:
   ```json
   {
     "summary": {
       "new": 3, "resolved": 1, "unchanged": 10, "modified": 0,
       "baseline_dir": "main-results/", "compare_dir": "pr-results/"
     },
     "by_severity": {
       "CRITICAL": {"new": 1, "resolved": 0},
       "HIGH": {"new": 2, "resolved": 1}
     },
     "findings": {
       "new": [...], "resolved": [...], "unchanged": [...], "modified": [...]
     }
   }
   ```
3. Markdown format:
   - Summary table with counts
   - Detailed tables by status (new/resolved/modified)
   - Grouped by severity within each section
4. HTML dashboard:
   - Interactive filters (severity, status, tool)
   - Sortable tables
   - Diff visualization (red for new, green for resolved)
   - Reuse existing `html_reporter.py` patterns

**Deliverables:**

- ✅ Three output formats (JSON/MD/HTML)
- ✅ Summary statistics
- ✅ Severity-based grouping
- ✅ Tests for each reporter

**Estimated Effort:** 5-6 days

---

### Phase 3: CI Integration & Documentation (Week 3)

**Scope:** GitHub Actions integration and production readiness

**Tasks:**

1. GitHub Actions workflow examples:
   - `docs/examples/pr-diff-workflow.yml` - PR comment integration
   - `docs/examples/trend-monitoring-workflow.yml` - Nightly trend analysis
2. PR comment formatter:
   - Markdown summary for GitHub comments
   - Collapsible sections for detailed findings
   - Badge-style severity indicators
3. Example workflow:
   ```yaml
   - name: Run baseline scan
     run: jmo scan --repo . --results baseline-results/

   - name: Run PR scan
     run: jmo scan --repo . --results pr-results/

   - name: Generate diff
     run: jmo diff baseline-results/ pr-results/ --format md --output pr-diff.md

   - name: Comment on PR
     uses: actions/github-script@v7
     with:
       script: |
         const fs = require('fs');
         const diff = fs.readFileSync('pr-diff.md', 'utf8');
         github.rest.issues.createComment({
           issue_number: context.issue.number,
           body: diff
         });
   ```
4. Documentation:
   - Update `README.md` with diff examples
   - Add `docs/DIFF_GUIDE.md` with use cases
   - Update `docs/USER_GUIDE.md` with diff command reference
   - Add examples to `SAMPLE_OUTPUTS.md`

**Deliverables:**

- ✅ GitHub Actions workflow examples
- ✅ PR comment integration pattern
- ✅ Comprehensive documentation
- ✅ End-to-end integration tests

**Estimated Effort:** 4-5 days

---

**Total Effort:** 2-3 weeks (14-17 days)

**Dependencies:**

- Existing fingerprinting in `common_finding.py`
- Reporter infrastructure in `scripts/core/reporters/`
- `gather_results()` in `normalize_and_report.py`

**Success Criteria:**

- Diff accurately identifies new/resolved findings
- All three output formats work correctly
- GitHub Actions example posts PR comments successfully
- Documentation covers all use cases
- Test coverage ≥85% for new code

---

## 5. Scheduled Scans & Cron Support

**Status:** 📋 Planned
**GitHub Issue:** [#33](https://github.com/jimmy058910/jmo-security-repo/issues/33)

**Why Fifth:** Automation layer for continuous monitoring, simple to implement.

**Objective:** Run scans automatically on schedule without manual intervention.

**Implementation:**

```bash
# Install cron job
jmo schedule --cron "0 2 * * *" --repos-dir ~/repos --profile balanced

# List scheduled scans
jmo schedule --list

# Remove scheduled scan
jmo schedule --remove <id>
```

**Platform Support:**

- Linux: cron integration
- systemd timers (alternative)
- Notification integration (email on failures)

**Deliverables:**

- `jmo schedule` command
- Cron job management
- systemd timer support
- Notification hooks

---

## 6. Plugin System for Custom Adapters

**Status:** 📋 Planned
**GitHub Issue:** [#34](https://github.com/jimmy058910/jmo-security-repo/issues/34)

**Why Sixth:** Enables community contributions and proprietary tool support, unlocks ecosystem.

**Objective:** Allow users to add custom security tools without forking codebase.

**Key Benefits:**

- Proprietary tools support (company-internal scanners)
- Niche tools (regional compliance, domain-specific)
- Community contribution (lower barrier)

**Plugin API:**

```python
# ~/.jmo/plugins/my_tool_adapter.py
from jmo.plugin import AdapterPlugin, Finding, Severity

class MyToolAdapter(AdapterPlugin):
    name = "my-tool"
    version = "1.0.0"

    def parse(self, output_path: Path) -> List[Finding]:
        # Parse tool output
        # Return list of Finding objects
        pass

register_adapter(MyToolAdapter)
```

**Usage:**

```bash
# Install plugin
jmo plugin install ~/.jmo/plugins/my_tool_adapter.py

# Use in scan
jmo scan --repo . --tools gitleaks,semgrep,my-tool
```

**Deliverables:**

- Plugin API design and base classes
- Plugin discovery and loading
- Plugin registry (optional marketplace)
- Documentation and examples

---

## 7. Policy-as-Code Integration (OPA)

**Status:** 📋 Planned
**GitHub Issue:** [#35](https://github.com/jimmy058910/jmo-security-repo/issues/35)

**Why Seventh:** Builds on plugin system, provides advanced flexibility for teams.

**Objective:** Enable custom security gating policies using Open Policy Agent (OPA) Rego language for context-aware rules beyond simple severity thresholds.

**Key Benefits:**

- Flexibility (different requirements per team/project)
- Context-aware (gate on paths, repos, finding age, tool combinations)
- Compliance (encode regulatory requirements as testable policies)
- Gradual adoption (strict on new code, relaxed on legacy)

**Example Policies:**

Path-based gating:

```rego
# Block HIGH+ findings in src/, allow in tests/
deny[msg] {
    finding := input.findings[_]
    finding.severity == "HIGH" or finding.severity == "CRITICAL"
    startswith(finding.location.path, "src/")
    msg := sprintf("HIGH+ finding blocked in src/: %v", [finding.ruleId])
}
```

CWE-specific requirements:

```rego
# Zero tolerance for SQL injection (CWE-89)
deny[msg] {
    finding := input.findings[_]
    finding.tags[_] == "CWE-89"
    msg := sprintf("SQL injection detected: %v at %v:%v", [
        finding.ruleId, finding.location.path, finding.location.startLine
    ])
}
```

**CLI:**

```bash
# Basic usage
jmo report ./results --policy my-policy.rego

# Install curated policy
jmo policy install owasp-top-10
jmo report ./results --policy ~/.jmo/policies/owasp-top-10.rego

# Test policy
jmo policy test my-policy.rego
jmo policy dry-run my-policy.rego ./results

# Generate template
jmo policy init --template zero-secrets > my-policy.rego
```

**Policy Marketplace:**

- `owasp-top-10.rego` - OWASP compliance
- `pci-dss.rego` - PCI-DSS requirements
- `hipaa.rego` - HIPAA compliance
- `zero-secrets.rego` - No secrets allowed

**Deliverables:**

- OPA integration with `--policy` flag
- Policy testing and dry-run commands
- Curated policy marketplace (5+ policies)
- Policy authoring guide and cookbook

---

## 8. Supply Chain Attestation (SLSA)

**Status:** 📋 Planned
**GitHub Issue:** [#36](https://github.com/jimmy058910/jmo-security-repo/issues/36)

**Why Eighth:** Enterprise compliance feature, requires mature scanning foundation.

**Objective:** Generate signed attestations for scan results, enabling verifiable provenance and tamper-proof audit trails.

**Key Benefits:**

- Trust (prove scan results are authentic/unmodified)
- Compliance (SOC2, ISO27001, PCI-DSS require verifiable audit trails)
- Supply chain security (like signing container images)
- Non-repudiation (cryptographic proof of scan execution)

**SLSA Level 2 Implementation:**

- Provenance: Record what was scanned, when, by which tools
- Signing: Sigstore (keyless) or custom keys
- Verification: Anyone can verify authenticity

**Attestation Format (in-toto SLSA Provenance v1.0):**

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{
    "name": "findings.json",
    "digest": {"sha256": "abc123..."}
  }],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://jmotools.com/scan@v1",
      "externalParameters": {
        "profile": "balanced",
        "tools": ["gitleaks", "semgrep", "trivy"]
      }
    },
    "runDetails": {
      "builder": {"id": "https://github.com/jimmy058910/jmo-security-repo"},
      "metadata": {
        "invocationId": "scan-20251013-102030",
        "startedOn": "2025-10-13T10:20:30Z",
        "finishedOn": "2025-10-13T10:35:45Z"
      }
    }
  }
}
```

**CLI:**

```bash
# Generate and sign attestation
jmo attest results/findings.json --sign --keyless --output attestation.json

# Verify attestation
jmo verify results/findings.json --attestation attestation.json

# Auto-attest in CI
jmo ci --repo . --attest --results results/
```

**Dependencies:**

- Sigstore Python SDK for keyless signing
- in-toto library for attestation format
- Optional: cosign CLI for external verification

**Deliverables:**

- `jmo attest` command with Sigstore integration
- `jmo verify` command
- Auto-attest in CI mode
- Attestation guide and best practices

---

## 9. GitHub App Integration

**Status:** 📋 Planned
**GitHub Issue:** [#37](https://github.com/jimmy058910/jmo-security-repo/issues/37)

**Why Ninth:** Revenue driver, requires all CI/CD features to be mature.

**Objective:** Auto-scan pull requests and post findings as comments (SaaS offering).

**Key Features:**

- Automatic PR scanning on push
- Comment with findings directly on PR
- Status checks (block merge on thresholds)
- Issue creation for critical findings
- Diff reports (show only new findings in PR)

**GitHub App Flow:**

1. User installs app on repo
2. PR opened/updated → webhook triggered
3. App clones repo, runs scan with diff
4. Posts comment with new findings
5. Sets status check (pass/fail based on policy)

**Pricing Tiers:**

- Free: Public repos, basic scanning
- Pro: Private repos, advanced policies
- Enterprise: Unlimited repos, SLSA attestation, SLA

**Deliverables:**

- GitHub App implementation
- Webhook handlers
- PR comment formatting
- Status check integration
- Admin dashboard for app management

**Note:** Full implementation plan in `docs/archive/BUSINESS_MODEL.md` (if archived with IMPLEMENTATION_LOG).

---

## 10. Web UI for Results Exploration

**Status:** 📋 Planned
**GitHub Issue:** [#38](https://github.com/jimmy058910/jmo-security-repo/issues/38)

**Why Tenth:** Advanced feature for large result sets, requires server infrastructure.

**Objective:** Launch `jmo serve` command to start local web server with interactive dashboard, better for large result sets than static HTML.

**Key Benefits:**

- Large scans (1000+ findings easier to navigate)
- Sharing (share results with team without copying files)
- Advanced queries (SQL-like filtering, grouping, aggregations)

**Features:**

- Server-side search/filter (faster for large datasets)
- Advanced queries: "Show HIGH+ findings in files modified in last 30 days"
- Saved searches/bookmarks
- Team annotations (requires database)

**Implementation:**

```bash
# Start server
jmo serve results/ --port 8080
# Opens browser to http://localhost:8080
```

**Tech Stack:**

- Backend: FastAPI + SQLite (optional persistence)
- Frontend: Same HTML dashboard with API calls
- Optional: Team collaboration features (annotations, assignments)

**Deliverables:**

- `jmo serve` command with FastAPI backend
- Server-side search and filtering
- Advanced query language
- Optional database for persistence

---

## 11. React/Vue Dashboard Alternative

**Status:** 📋 Planned
**GitHub Issue:** [#39](https://github.com/jimmy058910/jmo-security-repo/issues/39)

**Why Last:** Polish/modernization, existing HTML dashboard works well.

**Objective:** Modern SPA dashboard as alternative to self-contained HTML, with richer interactivity.

**Key Benefits:**

- More responsive for large datasets
- Advanced visualizations (D3.js charts, trend graphs)
- Better mobile experience
- Progressive web app capabilities

**Implementation:**

- Framework: Next.js or Vue 3 + Vite
- API backend: FastAPI (from Step 10)
- Progressive enhancement (works without JS)
- Advanced features: charts, trends, heatmaps

**Deliverables:**

- Modern SPA dashboard
- Feature parity with HTML dashboard
- Advanced visualizations
- Mobile-responsive design

---

## Summary

**Optimal Implementation Order:**

**Phase A - Foundation & Distribution:**

1. Docker All-in-One Image
2. Interactive Wizard
3. CI Linting - Full Pre-commit Coverage

**Phase B - CI/CD Integration:**

4. Machine-Readable Diff Reports
5. Scheduled Scans & Cron Support

**Phase C - Extensibility & Flexibility:**

6. Plugin System for Custom Adapters
7. Policy-as-Code Integration (OPA)

**Phase D - Enterprise & Revenue:**

8. Supply Chain Attestation (SLSA)
9. GitHub App Integration

**Phase E - Advanced UI:**

10. Web UI for Results Exploration
11. React/Vue Dashboard Alternative

**Rationale:** This order prioritizes user adoption (Docker, Wizard), then workflow integration (Diff Reports, Scheduling), then extensibility (Plugins, Policies), then enterprise features (Attestation, GitHub App), and finally UI polish (Web UI, Modern Dashboard).

---

## Contributing to the Roadmap

Want to help implement these features? Check out our [good first issues](https://github.com/jimmy058910/jmo-security-repo/labels/good%20first%20issue) and [help wanted](https://github.com/jimmy058910/jmo-security-repo/labels/help%20wanted) labels:

**Good First Issues (Easy Contributions):**

- [#17](https://github.com/jimmy058910/jmo-security-repo/issues/17) - Docs: Add "Try it with fixtures" snippet to README
- [#18](https://github.com/jimmy058910/jmo-security-repo/issues/18) - Tests: Add smoke test for `dashboard.html` generation
- [#20](https://github.com/jimmy058910/jmo-security-repo/issues/20) - Docs: Packaging note for `long_description_content_type`
- [#23](https://github.com/jimmy058910/jmo-security-repo/issues/23) - Tests: Add unit test for fingerprint stability
- [#24](https://github.com/jimmy058910/jmo-security-repo/issues/24) - CI: Add `make lint` check to tests workflow
- [#25](https://github.com/jimmy058910/jmo-security-repo/issues/25) - UX: Add `make screenshots-demo` snippet to README

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and workflow.

---

**Status:** All roadmap items are planned. Implementation will proceed in order based on user feedback and business priorities. See individual GitHub issues for detailed tracking.
