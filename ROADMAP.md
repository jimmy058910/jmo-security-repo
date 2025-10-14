# JMO Security Suite — Roadmap

Note: Steps 1–13 have been completed and are summarized in `CHANGELOG.md` under “Roadmap Summary (Steps 1–13)”. This roadmap now tracks only active/planned work.

Recently completed infra hardening (October 2025)
- CI: actionlint pinned, concurrency enabled, OS+Python matrix, job-level timeouts
- Coverage: tokenless uploads with Codecov v5
- Release: PyPI Trusted Publisher (OIDC) with `pypa/gh-action-pypi-publish@v1`
- DevEx: pre-commit consolidated, `.yamllint.yaml` added, additional adapter/reporter edge tests

## CI Linting — Full Pre-commit Coverage (Planned)

Context
- To keep PR feedback tight and CI reliable, the current lint job intentionally runs only structural checks (actionlint, yamllint). Auto-fixing and noisy hooks were skipped to avoid flakiness while we stabilized workflows.

Full Hook Set (from `.pre-commit-config.yaml`)
- pre-commit-hooks: trailing-whitespace, end-of-file-fixer, check-yaml, check-json, check-toml, mixed-line-ending, detect-private-key, check-added-large-files
- yamllint (config: `.yamllint.yaml`)
- actionlint (GitHub workflows)
- markdownlint
- ruff (lint) and ruff-format
- black
- bandit (config: `bandit.yaml`, limited to `scripts/`)
- shellcheck (errors only; excludes: SC2016, SC2028)
- shfmt

Plan to Re-enable in CI (staged)
1. Check-only mode for formatters
  - Switch ruff-format/black/shfmt to check-only in CI (no writes) and gate with clear messages.
  - Keep auto-fix local via pre-commit to reduce CI churn.
1. Markdown lint tuning
  - Add project-specific `.markdownlint.json` with rule relaxations for docs (line length, code blocks).
  - Enable markdownlint in CI after config lands.
1. Python lint policy
  - Pin ruff version; add minimal allowlist of rules to start (E, F) and gradually enable more.
  - Gate on ruff in CI once baseline passes; add rule-by-rule PRs to expand coverage.
1. Shell formatting
  - Configure shfmt style (indent, binary ops) and pin version; run in check-only in CI.
1. Security linting
  - Keep bandit limited to `scripts/` with explicit `-c bandit.yaml`; consider a weekly scheduled job for full repo scan in “info-only” mode.
1. Scheduling and PR signal
  - Add a nightly `lint-full` workflow running all hooks in check-only; PR CI remains fast/structural.
  - Post summary annotations; if stable for >2 weeks, migrate checks into PR CI gating.

Acceptance Criteria
- PR CI remains <5–7 min typical.
- Nightly `lint-full` is green on main for 2 weeks before gating PRs.
- Clear contributor docs on how to run auto-fixes locally with pre-commit.

Developer Guidance
- Local: run `pre-commit install` and `pre-commit run -a` before pushing.
- CI gating will error on check-only violations; fix locally (formatter applies changes) and re-push.

## Step 14 — Interactive Wizard (Beginner Onboarding)

Objective
- Provide an interactive, end-to-end guided flow for beginners to complete a successful first run without knowing flags. The wizard complements `jmotools setup` (tools bootstrap) by handling choices about profile, targets, runtime options, and outputs, then executing the scan and opening results.

Why now
- We now have: profiles (fast/balanced/deep), TSV cloning, a robust `ci` path, and a beginner wrapper (`jmotools`). A wizard stitches these into a single guided experience and outputs a reusable one-liner/Make target/CI workflow to remove future friction.

Scope (User-facing)
- New command: `jmotools wizard` (interactive by default; supports non-interactive flags to pre-answer prompts).
- Runs on Linux/WSL/macOS TTY; degrades gracefully in non-interactive shells.

Feature Breakdown
1) Guided scan configuration
   - Profile selection with context:
     - fast: “2–5 min, secrets + SAST (gitleaks, semgrep).”
     - balanced: “6–15 min, broad coverage (gitleaks, noseyparker, semgrep, syft, trivy, checkov, hadolint).”
     - full/deep: “10–30+ min, maximum coverage including trufflehog, tfsec, bandit, osv-scanner.”
   - Targets selection:
     - Single repo path
     - Repos directory (immediate subfolders)
     - Existing targets file
     - Clone from TSV (prompt for TSV path, dest, optional max)
   - Optional: “Unshallow repos?” for better secret scanning (applies only when clonable/updateable).

2) Smart defaults & recommendations
   - Detect CPU cores → recommend threads (min 2, max 8; default 4).
   - Recommend timeouts per profile (fast=300, balanced=600, deep=900) with explanation.
   - Offer `--fail-on` (default none; suggest HIGH for CI-like gating with a brief description of exit codes).

3) Tool bootstrap with context
   - Run the same checks as `jmotools setup`, but highlight tools required by the chosen profile.
   - Offer auto-install (Linux/WSL) or print commands; detect Docker for Nosey Parker fallback.
   - Offer to install PyYAML if user wants YAML output.

4) Preflight & preview
   - Show a concise summary: profile, targets, threads, timeout, fail-on, results dir.
   - Generate and display the exact non-interactive command (final `jmo ci` invocation) for copy/paste.
   - Optional: save a preset file (e.g., `.jmotools.preset.json`) for reuse.
   - Optional: generate a Make target or a shell script with the above command.
   - Optional: generate a minimal GitHub Actions workflow that mirrors the configuration.

5) Run & progress
   - Execute the scan/report; use `--human-logs` for readable progress.
   - Print ETA bands from heuristics (repos × profile baseline).
   - Handle cancel (SIGINT) gracefully, mirroring `jmo scan` behavior.

6) Results & follow-up
   - Open `dashboard.html` and `SUMMARY.md` (print paths if headless).
   - Print severity counts and final exit threshold status.
   - Offer to re-run report-only or view suppression guidance.

7) Quality-of-life extras
   - Remember last choices; offer “reuse last config.”
   - Non-interactive/CI mode: if no TTY or `--yes`, use recommended defaults; still print the final command.
   - Provide links to docs sections (config, suppressions, reporters).

CLI/UX Contract (Wizard)
- Command: `jmotools wizard [options]`
  - Interactive by default; prompts unless provided values short-circuit them.
- Non-interactive flags (optional):
  - `--profile {fast,balanced,deep}`
  - `--repo PATH | --repos-dir DIR | --targets FILE | --tsv FILE [--dest DIR] [--max N] [--unshallow]`
  - `--threads N` `--timeout SECONDS` `--fail-on SEVERITY`
  - `--results-dir DIR` `--no-open` `--allow-missing-tools` `--strict`
  - `--save-preset [FILE]` `--emit-make-target [NAME]` `--emit-script [FILE]` `--emit-gha [FILE]`
  - `--yes` (accept recommended defaults for all prompts)

Data & Dependencies
- Reuse:
  - Tool checks: `scripts/core/check_and_install_tools.sh`
  - TSV clone: `scripts/cli/clone_from_tsv.py`
  - Scan/Report: `scripts/cli/jmo.py ci`
- Read config defaults from `jmo.yml` and selected profile (threads, timeout, per_tool flags).
- No new heavy dependencies; prefer stdlib input/printing. If a prompt lib is added later, keep it optional.

Implementation Plan
- Phase 1 (MVP):
  - Add `jmotools wizard` command.
  - Prompts for profile + targets + threads/timeout + fail-on.
  - Run preflight summary; print final command; execute; open outputs; save last choices.
- Phase 2 (Convenience):
  - TSV clone prompts (tsv, dest, max) + unshallow option.
  - Profile-aware tool bootstrap suggestions (and auto-install hooks where supported).
  - Preset save/load; emit Make target or shell script.
- Phase 3 (Polish):
  - Emit GitHub Actions workflow.
  - ETA heuristics & better progress.
  - Rich suppression guidance linking to SUPPRESSIONS.md.

Edge Cases & Handling
- No repos found: warn and offer to pick a different target source or to clone from TSV.
- Missing tools: when `--allow-missing-tools` is selected (default for beginners), write stubs and continue; surface which tools were stubbed.
- Headless environment: skip opening files; always print output paths.
- Non-interactive shells: auto-switch to dry-run or use `--yes` defaults; exit with clear message if insufficient info.
- Permissions/network issues during clone: retry guidance and clear error messages.
- OS constraints: Windows not prioritized; Linux/WSL/macOS focus.

Acceptance Criteria
- Interactive flow completes a successful scan from at least three entry modes: repos-dir, single repo, TSV clone.
- Preflight prints an exact one-liner command that, when run, reproduces the wizarded run.
- Outputs are opened or paths printed; severity counts shown; threshold respected.
- Non-interactive usage supported (pass flags; wizard prompts are skipped).
- Documentation updated with a quick demo and examples.

Testing Strategy
- Unit tests for prompt parsing helpers, defaults selection, and command synthesis.
- Integration tests with a tiny repo fixture covering: fast/balanced/deep flows; TSV path; headless mode (`--no-open`).
- Snapshot tests of synthesized command and preflight summary.
- Smoke tests verifying `--yes` defaults execute without prompts in CI.

Risks & Mitigations
- Prompt UX dependency: keep to stdlib to avoid heavy deps; a nicer prompt lib could be optional.
- Time estimates may be noisy: position them as “rough bands.”
- Tool auto-install can vary by OS: keep optional and provide print-commands fallback.

Docs & Examples
- README: brief “Wizard” blurb with a gif + copy/paste command.
- QUICKSTART: wizard path in Step 3 alongside the CLI and wrapper.
- Examples page: TSV flow, preset save/load, emitting a Make target and GH Action.

Status
- Planned. Wrapper (`jmotools`) and setup flow are in place; wizard will be additive and reuse existing scripts.

---

## Step 15 — Policy-as-Code Integration (OPA)

### Objective
Enable custom security gating policies using Open Policy Agent (OPA) Rego language, allowing teams to define context-aware rules beyond simple severity thresholds.

### Why This Matters
- **Flexibility**: Different teams/projects have different security requirements
- **Context-aware**: Gate on file paths, repo names, finding age, tool combinations
- **Compliance**: Encode regulatory requirements as testable policies
- **Gradual adoption**: Start strict on new code, relaxed on legacy

### Use Cases

**Example 1: Path-based gating**

```rego
# Block HIGH+ findings in src/, allow in tests/
deny[msg] {
    finding := input.findings[_]
    finding.severity == "HIGH" or finding.severity == "CRITICAL"
    startswith(finding.location.path, "src/")
    msg := sprintf("HIGH+ finding blocked in src/: %v", [finding.ruleId])
}
```


**Example 2: Tool combination requirements**

```rego
# Require gitleaks + trufflehog for secrets
deny[msg] {
    tools_run := {tool | tool := input.findings[_].tool.name}
    not tools_run["gitleaks"]
    msg := "gitleaks is required for all scans"
}
```


**Example 3: CWE-specific requirements**

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


### Implementation Plan

**Phase 1: Basic OPA Integration**
1. Add `--policy` flag to `jmo report` command
2. Load Rego policy file and evaluate against findings JSON
3. Exit with code 1 if policy violations found
4. Print violation messages to stderr

**Phase 2: Policy Marketplace**
1. Create `policies/` directory with curated policies:
   - `owasp-top-10.rego` - OWASP compliance
   - `pci-dss.rego` - PCI-DSS requirements
   - `hipaa.rego` - HIPAA compliance
   - `zero-secrets.rego` - No secrets allowed
2. Command: `jmo policy install owasp-top-10`
3. Usage: `jmo report --policy policies/owasp-top-10.rego`

**Phase 3: Policy Testing & Validation**
1. `jmo policy test` - Validate policy syntax
2. `jmo policy dry-run` - Show what would be blocked
3. Policy templates with examples

### CLI Interface

```bash
# Basic usage
jmo report ./results --policy my-policy.rego

# Install curated policy
jmo policy install owasp-top-10
jmo report ./results --policy ~/.jmo/policies/owasp-top-10.rego

# Test policy before enforcing
jmo policy test my-policy.rego
jmo policy dry-run my-policy.rego ./results

# Generate policy template
jmo policy init --template zero-secrets > my-policy.rego
```


### Configuration in jmo.yml

```yaml
# Optional: default policy for all scans
policy:
  enabled: true
  file: policies/company-standard.rego
  fail_on_violation: true
```


### Dependencies

- `regal` or `opa` CLI tool (Go binary, ~20MB)
- Python binding: `opa-python` or direct subprocess invocation

### Testing Strategy

- Unit tests: Policy evaluation with fabricated findings
- Integration tests: End-to-end with sample policies
- Example policies with test cases in `policies/tests/`

### Documentation

- Policy authoring guide in `docs/POLICY_GUIDE.md`
- Policy cookbook with 10+ examples
- Video tutorial on writing first policy

### Rollout Plan

1. Month 1: Basic `--policy` flag, OPA subprocess integration
2. Month 2: Curated policy marketplace (5 policies)
3. Month 3: Policy testing commands, templates
4. Month 4: SaaS integration (policy management UI)

---

## Step 16 — Supply Chain Attestation (SLSA)

### Objective
Generate signed attestations for scan results, enabling verifiable provenance and tamper-proof audit trails for compliance and supply chain security.

### Why This Matters
- **Trust**: Prove scan results are authentic and unmodified
- **Compliance**: SOC2, ISO27001, PCI-DSS require verifiable audit trails
- **Supply chain security**: Like signing container images, but for security scans
- **Non-repudiation**: Cryptographic proof of when/where scan occurred

### SLSA (Supply-chain Levels for Software Artifacts)

SLSA is an industry framework for software supply chain security. We'll implement **SLSA Level 2** for scan attestations:
- **Provenance**: Record what was scanned, when, by which tools
- **Signing**: Use Sigstore (keyless signing) or custom keys
- **Verification**: Anyone can verify attestation authenticity

### Use Cases

**Use Case 1: Audit Trail for Compliance**
- Generate attestation after each scan
- Store attestations alongside findings
- Auditors verify attestations during reviews
- Prove no tampering occurred

**Use Case 2: CI/CD Integration**
- Scan produces findings.json + attestation.json
- Both artifacts published to artifact registry
- Deployment pipeline verifies attestation before deploy
- Reject deployments with invalid/missing attestations

**Use Case 3: Third-Party Verification**
- Share scan results with partners/customers
- They verify attestation to trust results
- No need to trust you directly - trust the signature

### Implementation Plan

**Phase 1: Attestation Generation**
1. Add `jmo attest` command
2. Generate in-toto attestation format (SLSA Provenance v1.0)
3. Include: scan timestamp, tool versions, repo commit SHA, findings hash
4. Sign with Sigstore (keyless) or local key

**Phase 2: Verification**
1. Add `jmo verify` command
2. Validate attestation signature
3. Check findings hash matches
4. Display: who signed, when, repo details

**Phase 3: Automation**
1. Auto-attest in CI mode: `jmo ci --attest`
2. Store attestations in results directory
3. Upload to transparency log (Rekor)

### Attestation Format (in-toto SLSA Provenance)

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
      },
      "resolvedDependencies": [{
        "uri": "git+https://github.com/acme/repo",
        "digest": {"gitCommit": "abc123"}
      }]
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/jimmy058910/jmo-security-repo"
      },
      "metadata": {
        "invocationId": "scan-20251013-102030",
        "startedOn": "2025-10-13T10:20:30Z",
        "finishedOn": "2025-10-13T10:35:45Z"
      }
    }
  }
}
```


### CLI Interface

```bash
# Generate attestation
jmo attest results/findings.json --output attestation.json

# Sign with Sigstore (keyless)
jmo attest results/findings.json --sign --keyless --output attestation.json

# Sign with local key
jmo attest results/findings.json --sign --key ~/.jmo/signing-key.pem --output attestation.json

# Verify attestation
jmo verify results/findings.json --attestation attestation.json
# Output:
# ✓ Verified: findings.json was produced by jmo@0.4.0 on 2025-10-13 10:20:30 UTC
# ✓ Signed by: jimmy058910@github (via Sigstore)
# ✓ Repo: https://github.com/acme/repo @ commit abc123
# ✓ Profile: balanced (tools: gitleaks, semgrep, trivy)

# Auto-attest in CI
jmo ci --repo . --attest --results results/
# Produces: results/summaries/findings.json + attestation.json
```


### Dependencies

- **Sigstore Python SDK** (`sigstore-python`) for keyless signing
- **in-toto** library for attestation format
- Optional: **cosign** CLI for verification by external parties

### Configuration in jmo.yml

```yaml
# Attestation settings
attestation:
  enabled: false  # Enable with --attest or ci mode
  signing:
    method: sigstore  # or "key" for local key
    key_path: ~/.jmo/signing-key.pem  # if method=key
  transparency_log:
    enabled: true  # Upload to Rekor (Sigstore transparency log)
```


### Testing Strategy

- Unit tests: Attestation generation with mocked Sigstore
- Integration tests: Sign + verify round-trip
- Key rotation tests
- Timestamp validation tests

### Documentation

- Attestation guide: `docs/ATTESTATION_GUIDE.md`
- Setup Sigstore for keyless signing
- Key management best practices
- Verification examples for CI/CD

### Business Model Integration

**Pricing:**
- Free tier: View attestations, verify existing
- Pro tier: Generate 100 attestations/month
- Enterprise tier: Unlimited + custom signing keys + dedicated transparency log

**Value Prop for Enterprises:**
- Meets SOC2/ISO27001 audit requirements
- Verifiable compliance documentation
- Supply chain security best practices

### Rollout Plan

1. Month 1: Attestation generation (in-toto format)
2. Month 2: Sigstore keyless signing integration
3. Month 3: Verification command + docs
4. Month 4: CI auto-attest, SaaS dashboard integration

---

## Step 17 — Docker All-in-One Image

### Objective
Provide a single Docker image with all security tools pre-installed for zero-setup scanning.

### Why This Matters
- **Onboarding**: New users can scan without installing 10+ tools
- **CI/CD**: Portable, reproducible scans in any CI system
- **Consistency**: Everyone uses same tool versions

### Image Contents

**Base:** `ubuntu:22.04` or `alpine:3.18` (slim variant)

**Tools included:**
- gitleaks, trufflehog, noseyparker
- semgrep, bandit
- syft, trivy
- checkov, tfsec, hadolint
- osv-scanner
- jmo CLI (Python package)

**Image size:** ~500MB (full), ~200MB (slim without Java tools)

### Usage

```bash
# Pull image
docker pull ghcr.io/jimmy058910/jmo-security:latest

# Scan local repo
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  jmo scan --repo /scan --results /scan/results --profile balanced

# Open dashboard
open results/summaries/dashboard.html
```


### docker-compose.yml Support

```yaml
version: '3.8'
services:
  jmo-scanner:
    image: ghcr.io/jimmy058910/jmo-security:latest
    volumes:
      - ./repos:/repos:ro
      - ./results:/results
    command: jmo scan --repos-dir /repos --results /results --profile deep
```


### GitHub Actions Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/jimmy058910/jmo-security:latest
    steps:
      - uses: actions/checkout@v4
      - run: jmo scan --repo . --results results --fail-on HIGH
      - uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: results/
```


### Implementation

**Dockerfile:**

```dockerfile
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# Install base tools
RUN apt-get update && apt-get install -y \
    python3 python3-pip git curl wget \
    && rm -rf /var/lib/apt/lists/*

# Install security tools
RUN pip3 install semgrep bandit
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz \
    && tar -xzf gitleaks_8.18.0_linux_x64.tar.gz -C /usr/local/bin \
    && rm gitleaks_8.18.0_linux_x64.tar.gz
# ... repeat for other tools

# Install jmo-security
COPY . /tmp/jmo
RUN pip3 install /tmp/jmo && rm -rf /tmp/jmo

WORKDIR /scan
ENTRYPOINT ["jmo"]
CMD ["--help"]
```


### Testing

- Build and scan test repos
- Verify all tools work
- Test volume mounting
- CI integration smoke tests

### Distribution

- GitHub Container Registry: `ghcr.io/jimmy058910/jmo-security`
- Docker Hub: `jmosecurity/scanner`
- Multi-arch: `linux/amd64`, `linux/arm64`

### Variants

- `jmo-security:latest` - Full suite (~500MB)
- `jmo-security:slim` - Secrets + SAST only (~200MB)
- `jmo-security:alpine` - Alpine-based (~150MB, limited tools)

### Rollout

1. Month 1: Build Dockerfile, publish to GHCR
2. Month 2: CI integration examples, docs
3. Month 3: Slim variant, ARM support

---

## Step 18 — Machine-Readable Diff Reports

### Objective
Compare scan results across time/commits to identify new findings, resolved findings, and track security posture trends.

### Why This Matters
- **PR reviews**: "Show me only NEW findings introduced by this PR"
- **Trend analysis**: "Are we getting better or worse over time?"
- **KPI tracking**: "How many findings did we fix this sprint?"

### Use Cases

**Use Case 1: PR Diffs**

```bash
# Scan PR branch
jmo scan --repo . --results pr-results/

# Scan base branch
git checkout main
jmo scan --repo . --results main-results/

# Generate diff
jmo diff main-results/ pr-results/ --output pr-diff.md
# Shows: 3 new findings, 1 resolved, 2 unchanged
```


**Use Case 2: Sprint Retrospective**

```bash
# Compare this sprint vs last sprint
jmo diff sprint-14-results/ sprint-15-results/ --format html
# Output: trend charts, top fixes, top new issues
```


**Use Case 3: Continuous Monitoring**

```bash
# Weekly scans, track over time
jmo diff --baseline week-1/ week-2/ week-3/ week-4/
# Output: Time-series chart of finding counts by severity
```


### Implementation

**Command:**

```bash
jmo diff <baseline_dir> <current_dir> [options]
```


**Options:**
- `--output <file>` - Output file (default: stdout)
- `--format <json|md|html>` - Output format
- `--show-resolved` - Include resolved findings in output
- `--show-unchanged` - Include unchanged findings
- `--severity <sev>` - Filter by severity

**Diff Algorithm:**
1. Load findings from both directories
2. Match by fingerprint ID (stable across scans)
3. Classify:
   - **New**: In current, not in baseline
   - **Resolved**: In baseline, not in current
   - **Unchanged**: In both (same fingerprint)
   - **Modified**: Same location but different severity/message

**Output (Markdown):**

```markdown
# Security Scan Diff: sprint-14 → sprint-15

## Summary
- ✅ 5 findings resolved
- 🆕 3 new findings
- ➡️ 12 unchanged

## New Findings (3)
| Severity | Tool | Rule | Location |
|----------|------|------|----------|
| HIGH | gitleaks | aws-key | config.py:42 |
| MEDIUM | semgrep | sql-inject | api.py:102 |
| LOW | trivy | CVE-2023-1234 | requirements.txt |

## Resolved Findings (5)
| Severity | Tool | Rule | Location |
|----------|------|------|----------|
| CRITICAL | gitleaks | github-pat | .env:12 |
...
```


**Output (HTML):**
- Interactive dashboard like main dashboard
- Color-coded: green (resolved), red (new), gray (unchanged)
- Filter by new/resolved
- Export capabilities

### Rollout

1. Month 1: Basic diff command (JSON output)
2. Month 2: Markdown/HTML outputs
3. Month 3: GitHub Actions integration (comment on PRs)

---

## Step 19 — Web UI for Results Exploration

### Objective
Launch `jmo serve` command to start a local web server with interactive results dashboard, better for large result sets than static HTML.

### Why This Matters
- **Large scans**: 1000+ findings hard to navigate in static HTML
- **Sharing**: Share results with team without copying files
- **Advanced queries**: SQL-like filtering, grouping, aggregations

### Features

**Server:**
- `jmo serve results/ --port 8080`
- Starts Flask/FastAPI server
- Opens browser to `http://localhost:8080`

**UI Features:**
- All features of HTML dashboard +
- Server-side search/filter (faster for large datasets)
- Advanced queries: "Show HIGH+ findings in files modified in last 30 days"
- Saved searches/bookmarks
- Team annotations (requires database)

### Implementation

- Backend: FastAPI + SQLite (optional)
- Frontend: Same HTML dashboard but with API calls
- Database: Optional for persistence/team features

### Rollout

1. Month 1: Basic serve command (read-only)
2. Month 2: Advanced queries
3. Month 3: Team collaboration (annotations, assignments)

---

## Step 20 — Plugin System for Custom Adapters

### Objective
Enable users to add custom security tools without forking the codebase.

### Why This Matters
- **Proprietary tools**: Companies have internal security scanners
- **Niche tools**: Regional compliance tools, domain-specific scanners
- **Community contribution**: Lower barrier to adding tools

### Plugin API

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

# Register plugin
register_adapter(MyToolAdapter)
```


### Usage

```bash
# Install plugin
jmo plugin install ~/.jmo/plugins/my_tool_adapter.py

# Use in scan
jmo scan --repo . --tools gitleaks,semgrep,my-tool
```


### Rollout

1. Month 1: Plugin API design, documentation
2. Month 2: Plugin registry, discovery
3. Month 3: Community plugin submissions

---

## Step 21 — Scheduled Scans & Cron Support

### Objective
Run scans automatically on a schedule without manual intervention.

### Implementation

```bash
# Install cron job
jmo schedule --cron "0 2 * * *" --repos-dir ~/repos --profile balanced

# Installs cron job:
# 0 2 * * * cd ~/repos && jmo ci --repos-dir . --profile balanced

# List scheduled scans
jmo schedule --list

# Remove scheduled scan
jmo schedule --remove <id>
```


### Rollout

1. Month 1: Basic cron integration
2. Month 2: systemd timer support (Linux)
3. Month 3: Notification integration (email on failures)

---

## Step 22 — GitHub App Integration

### Objective
Auto-scan pull requests and post findings as comments (detailed in BUSINESS_MODEL.md Phase 2).

### Features

- Automatic PR scanning
- Comment with findings on PR
- Status checks (block merge on thresholds)
- Issue creation for critical findings

### Rollout

See BUSINESS_MODEL.md for full implementation plan.

---

## Step 23 — React/Vue Dashboard Alternative

### Objective
Modern SPA dashboard as alternative to self-contained HTML, with richer interactivity.

### Why

- More responsive for large datasets
- Advanced visualizations (D3.js charts)
- Better mobile experience

### Implementation

- Next.js or Vue 3 + Vite
- API backend (FastAPI)
- Progressive enhancement (works without JS)

### Rollout

1. Month 1: POC dashboard with basic features
2. Month 2: Feature parity with HTML dashboard
3. Month 3: Advanced features (charts, trends)

---

**Notes:** Steps 15-23 are future enhancements tracked for prioritization. Steps 1-14 are complete or in progress. See DEVELOPER_ROADMAP.md for active development tasks.
