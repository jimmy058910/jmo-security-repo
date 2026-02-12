# JMo Security CLI Reference

Complete reference for all CLI commands and flags. Run `jmo <command> --help` for the latest options.

**Version:** 1.0.0
**Last Updated:** January 2026

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `jmo wizard` | Interactive guided scanning |
| `jmo fast` | Quick scan (8 tools, 5-10 min) |
| `jmo balanced` | Production scan (18 tools, 18-25 min) |
| `jmo full` | Comprehensive audit (28 tools, 40-70 min) |
| `jmo scan` | Low-level scan with full control |
| `jmo report` | Generate reports from scan results |
| `jmo ci` | Scan + report for CI/CD pipelines |
| `jmo diff` | Compare two scans |
| `jmo tools` | Manage security tool installation |
| `jmo history` | Manage scan history database |
| `jmo trends` | Analyze security trends |
| `jmo schedule` | Manage scheduled scans |
| `jmo policy` | Policy-as-Code management |
| `jmo attest` | Generate SLSA attestations |
| `jmo verify` | Verify attestations |
| `jmo build` | Build Docker images |
| `jmo mcp-server` | Start AI remediation server |
| `jmo setup` | First-time setup |
| `jmo adapters` | Manage adapter plugins |

---

## Common Flags

These flags are shared across multiple commands:

| Flag | Description | Used By |
|------|-------------|---------|
| `--config FILE` | Config file (default: `jmo.yml`) | scan, report, ci, fast, balanced, full |
| `--human-logs` | Human-friendly colored logs instead of JSON | all commands |
| `--log-level LEVEL` | Log level: `DEBUG`, `INFO`, `WARN`, `ERROR` | all commands |
| `--results-dir DIR` | Results directory | scan, ci, report, fast, balanced, full |
| `--db PATH` | SQLite database path (default: `.jmo/history.db`) | history, trends, diff, wizard |
| `--profile-name NAME` | Scan profile from config | scan, ci |
| `--threads N` | Worker thread count | scan, report, ci |
| `--timeout SECS` | Per-tool timeout | scan, ci, fast, balanced, full |
| `--tools TOOL...` | Override tool list | scan, ci |
| `--fail-on SEV` | Severity threshold for exit code | report, ci, fast, balanced, full |
| `--allow-missing-tools` | Skip missing tools instead of failing | scan, ci |

---

## Commands

### jmo scan

Run security scans against repositories, images, URLs, and infrastructure.

**Target Selection (mutually exclusive for repos):**

| Flag | Description |
|------|-------------|
| `--repo PATH` | Path to a single repository to scan |
| `--repos-dir DIR` | Directory whose immediate subfolders are repos to scan |
| `--targets FILE` | File listing repo paths (one per line) |

**Additional Targets (can combine with repo targets):**

| Flag | Description |
|------|-------------|
| `--image IMAGE` | Container image to scan (format: `registry/image:tag`) |
| `--images-file FILE` | File with one image per line |
| `--url URL` | Web application URL to scan |
| `--urls-file FILE` | File with URLs (one per line) |
| `--api-spec FILE_OR_URL` | OpenAPI/Swagger spec URL or file |
| `--terraform-state FILE` | Terraform state file to scan |
| `--cloudformation FILE` | CloudFormation template to scan |
| `--k8s-manifest FILE` | Kubernetes manifest file to scan |

**GitLab Integration:**

| Flag | Description |
|------|-------------|
| `--gitlab-url URL` | GitLab instance URL (e.g., `https://gitlab.com`) |
| `--gitlab-token TOKEN` | GitLab access token (or use `GITLAB_TOKEN` env var) |
| `--gitlab-group GROUP` | GitLab group to scan |
| `--gitlab-repo REPO` | Single GitLab repo (format: `group/repo`) |

**Kubernetes Live Cluster:**

| Flag | Description |
|------|-------------|
| `--k8s-context CONTEXT` | Kubernetes context to scan |
| `--k8s-namespace NS` | Kubernetes namespace to scan |
| `--k8s-all-namespaces` | Scan all namespaces |

**Scan Configuration:**

| Flag | Description |
|------|-------------|
| `--results-dir DIR` | Base results directory (default: `results`) |
| `--config FILE` | Config file (default: `jmo.yml`) |
| `--profile-name NAME` | Scan profile: `fast`, `slim`, `balanced`, `deep` |
| `--tools TOOL [TOOL ...]` | Override tools list from config |
| `--timeout SECS` | Per-tool timeout in seconds (default: 600) |
| `--threads N` | Concurrent repos to scan (default: auto) |
| `--allow-missing-tools` | Skip missing tools instead of failing (creates empty JSON) |

**History Storage:**

| Flag | Description |
|------|-------------|
| `--no-store-history` | Disable automatic history storage (enabled by default) |
| `--history-db PATH` | Path to history database (default: `.jmo/history.db`) |
| `--no-store-raw-findings` | Don't store raw findings (security: prevents secret persistence) |
| `--encrypt-findings` | Encrypt findings in database (requires `JMO_ENCRYPTION_KEY` env var) |
| `--collect-metadata` | Collect hostname/username metadata (default: disabled for privacy) |

**Logging:**

| Flag | Description |
|------|-------------|
| `--log-level LEVEL` | Log level: `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `--human-logs` | Human-friendly colored logs instead of JSON |

---

### jmo report

Generate reports from completed scan results.

| Flag | Description |
|------|-------------|
| `RESULTS_DIR` | Directory with `individual-repos/*` tool outputs (positional) |
| `--results-dir DIR` | Same as positional argument (optional form) |
| `--out DIR` | Output directory (default: `<results_dir>/summaries`) |
| `--config FILE` | Config file (default: `jmo.yml`) |
| `--fail-on SEV` | Exit non-zero if findings at severity or above (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `--profile` | Collect per-tool timing and write `timings.json` |
| `--threads N` | Worker threads for aggregation (default: auto) |
| `--policy NAME` | Policy to evaluate (repeatable: `--policy owasp-top-10 --policy zero-secrets`) |
| `--allow-missing-tools` | Accepted for compatibility; reporting tolerates missing tool outputs by default |
| `--log-level LEVEL` | Log level: `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `--human-logs` | Human-friendly colored logs instead of JSON |

---

### jmo ci

Combined scan + report for CI/CD pipelines. Supports all `jmo scan` flags plus:

| Flag | Description |
|------|-------------|
| `--fail-on SEV` | Exit non-zero at severity threshold |
| `--profile` | Collect `timings.json` during report |
| `--policy NAME` | Policy to evaluate (repeatable: `--policy owasp-top-10 --policy zero-secrets`) |
| `--fail-on-policy-violation` | Exit code 1 if any policy violations found |
| `--strict-versions` | Fail if tool versions don't match `versions.yaml` (for reproducible builds) |

---

### jmo fast / balanced / full

Beginner-friendly shortcut commands with sensible defaults.

| Command | Tools | Time | Description |
|---------|-------|------|-------------|
| `jmo fast` | 8 | 5-10 min | Quick pre-commit/PR validation |
| `jmo balanced` | 18 | 18-25 min | Production scans |
| `jmo full` | 28 | 40-70 min | Comprehensive audits |

**Common flags (all three commands):**

| Flag | Description |
|------|-------------|
| `--repo PATH` | Path to repository to scan |
| `--repos-dir DIR` | Directory of repos to scan |
| `--targets FILE` | File listing repo paths (one per line) |
| `--results-dir DIR` | Results directory (default: `results`) |
| `--threads N` | Override thread count |
| `--timeout SECS` | Override per-tool timeout |
| `--fail-on SEV` | Severity threshold to fail (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) |
| `--no-open` | Don't open results after run |
| `--strict` | Fail if tools are missing (no stubs) |
| `--human-logs` | Human-friendly logs |
| `--config FILE` | Config file (default: `jmo.yml`) |

---

### jmo wizard

Interactive setup wizard for guided security scanning.

| Flag | Description |
|------|-------------|
| `--yes` | Non-interactive mode with defaults |
| `--auto-fix` | Automatically install missing tools without prompting |
| `--install-deps` | Automatically install runtime dependencies (Java, Node.js) |
| `--native` | Force native execution mode (skip Docker check) |
| `--emit-script [FILE]` | Generate shell script (default: `jmo-scan.sh`) |
| `--emit-make-target [FILE]` | Generate Makefile target (default: `Makefile.jmo`) |
| `--emit-gha [FILE]` | Generate GitHub Actions workflow (default: `.github/workflows/jmo-security.yml`) |
| `--policy NAME` | Policy to evaluate after scan (repeatable) |
| `--skip-policies` | Skip policy evaluation entirely (overrides config defaults) |
| `--db PATH` | Path to SQLite history database (default: `~/.jmo/history.db`) |

**Tool Pre-flight Check:**

The wizard performs a pre-flight check showing tool availability in clear categories:

```text
Balanced profile: 18 tools

✅ READY TO SCAN (13 tools)

⚠️ NOT INSTALLED (3 tools):
   scancode, zap, nuclei
   Install with: jmo tools install <tool-name>

🚫 PLATFORM INCOMPATIBLE (1 tool, windows):
   bearer

📖 REQUIRES MANUAL SETUP (1 tool):
   prowler
   See: docs/MANUAL_INSTALLATION.md

Expected findings from: 13 tools
   (5 tools will be skipped)
```

Use `--auto-fix` to automatically install missing tools, or use Docker mode for full tool coverage.

---

### jmo setup

Verify tool installation and optionally auto-install missing tools.

| Flag | Description |
|------|-------------|
| `--auto-install` | Attempt to auto-install missing tools |
| `--print-commands` | Print installation commands without executing |
| `--force-reinstall` | Force reinstallation of all tools |
| `--strict` | Exit with error if any tools are missing |
| `--human-logs` | Human-friendly logs |

---

### jmo diff

Compare two scans to identify new, resolved, and modified findings.

**Modes:**

1. **Auto mode:** Auto-detect scans based on Git context (`--auto`)
2. **Directory mode:** Compare scan result directories (positional arguments)
3. **SQLite mode:** Compare historical scan IDs (`--scan abc --scan def`)

| Flag | Description |
|------|-------------|
| `BASELINE CURRENT` | Two directories to compare (positional) |
| `--auto` | Auto-detect baseline/current scans based on Git context |
| `--scan ID` | SQLite scan ID (use twice: `--scan abc --scan def`) |
| `--format FORMAT` | Output: `json`, `md`, `html`, `sarif` (default: `md`) |
| `--output FILE` | Output file path (default: stdout for md/json) |
| `--no-modifications` | Disable modification detection (faster) |
| `--severity SEV` | Filter by severity (comma-separated: `CRITICAL,HIGH`) |
| `--tool TOOL` | Filter by tool (comma-separated: `semgrep,trivy`) |
| `--only TYPE` | Show only: `new`, `resolved`, `modified` |
| `--db PATH` | Path to SQLite database (default: `~/.jmo/scans.db`) |

---

### jmo attest

Generate SLSA provenance attestation for scan results.

| Flag | Description |
|------|-------------|
| `SUBJECT` | File to attest, e.g., `findings.json` (positional, required) |
| `--output`, `-o FILE` | Output path (default: `<subject>.att.json`) |
| `--sign` | Sign attestation with Sigstore (requires cosign) |
| `--rekor` | Upload to Rekor transparency log |
| `--scan-args FILE` | JSON file with original scan arguments |
| `--tools TOOL [...]` | Tools used in scan (e.g., `trivy semgrep`) |
| `--human-logs` | Human-friendly logs |
| `--log-level LEVEL` | Log level: `DEBUG`, `INFO`, `WARN`, `ERROR` |

---

### jmo verify

Verify cryptographic attestation and detect tampering.

| Flag | Description |
|------|-------------|
| `SUBJECT` | File to verify, e.g., `findings.json` (positional, required) |
| `--attestation`, `-a FILE` | Attestation file (default: `<subject>.att.json`) |
| `--rekor-check` | Verify against Rekor transparency log |
| `--policy FILE` | Policy file for additional verification rules |
| `--human-logs` | Human-friendly logs |
| `--log-level LEVEL` | Log level: `DEBUG`, `INFO`, `WARN`, `ERROR` |

**Exit codes:**

- `0` - Verification succeeded
- `1` - Verification failed or tampering detected

---

### jmo policy

Manage OPA-based policies for security governance.

**Policy Locations:**

- Built-in: `policies/builtin/`
- User: `~/.jmo/policies/`

**jmo policy list**

List all available policies (builtin + user). No flags.

**jmo policy validate**

| Flag | Description |
|------|-------------|
| `POLICY` | Policy name without `.rego` extension (positional, required) |

**jmo policy test**

| Flag | Description |
|------|-------------|
| `POLICY` | Policy name without `.rego` extension (positional, required) |
| `--findings-file FILE` | Path to JSON file with findings (required) |

**jmo policy show**

| Flag | Description |
|------|-------------|
| `POLICY` | Policy name without `.rego` extension (positional, required) |

**jmo policy install**

| Flag | Description |
|------|-------------|
| `POLICY` | Policy name to install (positional, required) |
| `--force` | Overwrite existing policy if already installed |

---

### jmo tools

Manage security tool installation and updates.

**jmo tools check**

| Flag | Description |
|------|-------------|
| `[TOOLS ...]` | Specific tools to check (positional) |
| `--profile PROFILE` | Check tools for profile: `fast`, `slim`, `balanced`, `deep` |
| `--json` | Output as JSON |

**Tool Status Categories:**

| Status | Icon | Description |
|--------|------|-------------|
| OK | ✅ | Tool installed and ready to use |
| OUTDATED | ⚠️ | Newer version available (still functional) |
| SKIPPED | 🚫 | Not applicable for current platform/mode |
| MISSING | ❌ | Not installed but can be installed |
| FAILED | 💥 | Installed but broken (startup crash, missing deps) |

Example output:

```text
Balanced profile: 18 tools
  ✅ 13 ready
  ⚠️ 2 outdated (run 'jmo tools update' when convenient)
  🚫 1 platform-skipped (bearer - Windows not supported)
  ❌ 2 not installed (scancode, zap)
```

**jmo tools install**

| Flag | Description |
|------|-------------|
| `[TOOLS ...]` | Specific tools to install (positional) |
| `--profile PROFILE` | Install tools for profile (default: `balanced`) |
| `--yes`, `-y` | Non-interactive mode |
| `--dry-run` | Show what would be installed |
| `--print-script` | Print install script |
| `--sequential`, `-S` | Install sequentially (slower, for debugging) |
| `--jobs N`, `-j N` | Parallel jobs (default: 4, max: 8) |

**jmo tools update**

| Flag | Description |
|------|-------------|
| `[TOOLS ...]` | Specific tools to update (positional) |
| `--critical-only` | Update only critical tools |
| `--yes`, `-y` | Non-interactive mode |

**jmo tools list**

| Flag | Description |
|------|-------------|
| `--profile PROFILE` | List tools in profile: `fast`, `slim`, `balanced`, `deep` |
| `--profiles` | List available profiles |
| `--json` | Output as JSON |

**jmo tools outdated**

| Flag | Description |
|------|-------------|
| `--critical-only` | Only show critical tools |
| `--json` | Output as JSON |

**jmo tools uninstall**

| Flag | Description |
|------|-------------|
| `--all`, `-a` | Also uninstall all security tools |
| `--dry-run` | Show what would be removed without removing |
| `--yes`, `-y` | Skip confirmation prompt |

**jmo tools debug**

Debug version detection for specific tools.

| Flag | Description |
|------|-------------|
| `[TOOLS ...]` | Tools to debug (positional) |
| `--all`, `-a` | Debug all tools in balanced profile |

**jmo tools clean**

Clean isolated virtual environments (for tools with pip conflicts).

| Flag | Description |
|------|-------------|
| `--force`, `-f` | Actually remove (default is dry run) |

---

### jmo history

Manage SQLite scan history database.

**Database Location:** `.jmo/history.db` (default)

**jmo history store**

Manually store a completed scan.

| Flag | Description |
|------|-------------|
| `--results-dir DIR` | Path to results directory (required) |
| `--profile PROFILE` | Scan profile that was used: `fast`, `balanced`, `deep` |
| `--commit HASH` | Git commit hash (auto-detected if not provided) |
| `--branch NAME` | Git branch name (auto-detected if not provided) |
| `--tag TAG` | Git tag (auto-detected if not provided) |
| `--db PATH` | Path to SQLite database (default: `.jmo/history.db`) |

**jmo history list**

| Flag | Description |
|------|-------------|
| `--branch NAME` | Filter by branch name |
| `--profile PROFILE` | Filter by profile: `fast`, `balanced`, `deep` |
| `--since DELTA` | Filter by time delta (e.g., `7d`, `30d`, `90d`) |
| `--limit N` | Maximum number of results (default: 50) |
| `--json` | Output as JSON |
| `--db PATH` | Path to SQLite database |

**jmo history show**

| Flag | Description |
|------|-------------|
| `SCAN_ID` | Scan UUID, full or partial (positional, required) |
| `--findings` | Include all findings in output |
| `--json` | Output as JSON |
| `--db PATH` | Path to SQLite database |

**jmo history query**

Execute custom SQL query.

| Flag | Description |
|------|-------------|
| `QUERY` | SQL query to execute (positional, required) |
| `--format FORMAT` | Output format: `table`, `json`, `csv` (default: `table`) |
| `--db PATH` | Path to SQLite database |

**jmo history prune**

Delete old scans.

| Flag | Description |
|------|-------------|
| `--older-than DELTA` | Delete scans older than time delta (e.g., `30d`, `90d`, `180d`) (required) |
| `--dry-run` | Show what would be deleted without deleting |
| `--force` | Skip confirmation prompt |
| `--db PATH` | Path to SQLite database |

**jmo history export**

Export scans to JSON/CSV.

| Flag | Description |
|------|-------------|
| `--scan-id ID` | Export specific scan by UUID |
| `--since DELTA` | Export scans from time delta (e.g., `30d`) |
| `--format FORMAT` | Output format: `json`, `csv` (default: `json`) |
| `--db PATH` | Path to SQLite database |

**jmo history stats**

Show database statistics.

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |
| `--db PATH` | Path to SQLite database |

**jmo history diff**

Compare two scans.

| Flag | Description |
|------|-------------|
| `SCAN_ID_1` | First scan ID (baseline) (positional, required) |
| `SCAN_ID_2` | Second scan ID (comparison) (positional, required) |
| `--json` | Output as JSON |
| `--db PATH` | Path to SQLite database |

**jmo history trends**

Show security trends over time for a branch.

| Flag | Description |
|------|-------------|
| `--branch NAME` | Branch name (default: `main`) |
| `--days N` | Number of days to analyze (default: 30) |
| `--json` | Output as JSON |
| `--db PATH` | Path to SQLite database |

**jmo history optimize**

Optimize database performance (VACUUM, ANALYZE).

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON |
| `--db PATH` | Path to SQLite database |

**jmo history migrate**

Apply pending database schema migrations.

| Flag | Description |
|------|-------------|
| `--target-version VERSION` | Target schema version (default: apply all pending) |
| `--json` | Output results as JSON |
| `--db PATH` | Path to SQLite database |

**jmo history verify**

Verify database integrity (PRAGMA checks).

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON |
| `--db PATH` | Path to SQLite database |

**jmo history repair**

Repair corrupted database (dump/reimport).

| Flag | Description |
|------|-------------|
| `--force` | Skip confirmation prompt |
| `--json` | Output results as JSON |
| `--db PATH` | Path to SQLite database |

---

### jmo trends

Statistical trend analysis using historical scan data.

**jmo trends analyze**

Analyze security trends with flexible filters.

| Flag | Description |
|------|-------------|
| `--days N` | Number of days to analyze |
| `--last N` | Last N scans to analyze |
| `--scan-ids ID [ID ...]` | Specific scan IDs to analyze |
| `--branch NAME` | Git branch to analyze (default: `main`) |
| `--validate-statistics` | Run Mann-Kendall statistical validation |
| `--format FORMAT` | Output format: `terminal`, `json` (default: `terminal`) |
| `--verbose` | Show detailed output (top rules, etc.) |
| `--export-json FILE` | Export analysis to JSON file |
| `--export-html FILE` | Export analysis to HTML file |
| `--db PATH` | Path to SQLite database |

**jmo trends show**

Show trend context for a specific scan.

| Flag | Description |
|------|-------------|
| `SCAN_ID` | Scan ID to show context for (positional, required) |
| `--context N` | Number of scans before/after to show (default: 5) |
| `--branch NAME` | Git branch to analyze (default: `main`) |
| `--db PATH` | Path to SQLite database |

**jmo trends regressions**

List all detected regressions.

| Flag | Description |
|------|-------------|
| `--last N` | Last N scans to analyze |
| `--severity SEV` | Filter by severity: `CRITICAL`, `HIGH` |
| `--fail-on-any` | Exit with error code 1 if any regressions found (for CI) |
| `--branch NAME` | Git branch to analyze (default: `main`) |
| `--db PATH` | Path to SQLite database |

**jmo trends score**

Show security posture score history.

| Flag | Description |
|------|-------------|
| `--last N` | Last N scans to analyze |
| `--days N` | Number of days to analyze |
| `--branch NAME` | Git branch to analyze (default: `main`) |
| `--db PATH` | Path to SQLite database |

**jmo trends compare**

Compare two specific scans side-by-side.

| Flag | Description |
|------|-------------|
| `SCAN_ID_1` | First scan ID (positional, required) |
| `SCAN_ID_2` | Second scan ID (positional, required) |
| `--verbose` | Show sample findings from diff |
| `--branch NAME` | Git branch to analyze (default: `main`) |
| `--db PATH` | Path to SQLite database |

**jmo trends insights**

List all automated insights.

| Flag | Description |
|------|-------------|
| `--last N` | Last N scans to analyze |
| `--branch NAME` | Git branch to analyze (default: `main`) |
| `--db PATH` | Path to SQLite database |

**jmo trends explain**

Explain how trend metrics are calculated.

| Flag | Description |
|------|-------------|
| `METRIC` | Metric to explain: `score`, `mann-kendall`, `regressions`, `trend`, `all` (positional, default: `all`) |

**jmo trends developers**

Show developer remediation rankings.

| Flag | Description |
|------|-------------|
| `--last N` | Last N scans to analyze |
| `--top N` | Show top N developers (default: 10) |
| `--branch NAME` | Git branch to analyze (default: `main`) |
| `--db PATH` | Path to SQLite database |

---

### jmo schedule

Manage scheduled scans using CI/CD or local cron.

**jmo schedule create**

Create a new schedule.

| Flag | Description |
|------|-------------|
| `--name NAME` | Schedule name (required) |
| `--cron EXPR` | Cron expression, e.g., `0 2 * * *` (required) |
| `--profile PROFILE` | Scan profile: `fast`, `balanced`, `deep` (required) |
| `--repos-dir DIR` | Repository directory to scan |
| `--image IMAGE` | Container image to scan (repeatable) |
| `--url URL` | Web URL to scan (repeatable) |
| `--backend BACKEND` | Backend: `github-actions`, `gitlab-ci`, `local-cron` |
| `--timezone TZ` | Timezone for schedule (default: UTC) |
| `--description TEXT` | Human-readable description |
| `--label KEY=VALUE` | Label in KEY=VALUE format (repeatable) |
| `--slack-webhook URL` | Slack webhook URL for notifications |

**jmo schedule list**

| Flag | Description |
|------|-------------|
| `--format FORMAT` | Output format: `table`, `json`, `yaml` |
| `--label KEY=VALUE` | Filter by label |

**jmo schedule get**

| Flag | Description |
|------|-------------|
| `NAME` | Schedule name (positional, required) |
| `--format FORMAT` | Output format: `json`, `yaml` |

**jmo schedule update**

| Flag | Description |
|------|-------------|
| `NAME` | Schedule name (positional, required) |
| `--cron EXPR` | New cron expression |
| `--profile PROFILE` | New scan profile: `fast`, `balanced`, `deep` |
| `--suspend` | Suspend schedule |
| `--resume` | Resume schedule |

**jmo schedule export**

Export workflow file.

| Flag | Description |
|------|-------------|
| `NAME` | Schedule name (positional, required) |
| `--backend BACKEND` | Override backend: `github-actions`, `gitlab-ci` |
| `--output`, `-o FILE` | Output file (default: stdout) |

**jmo schedule delete**

| Flag | Description |
|------|-------------|
| `NAME` | Schedule name (positional, required) |
| `--force` | Skip confirmation prompt |

**jmo schedule validate**

Validate schedule configuration.

| Flag | Description |
|------|-------------|
| `NAME` | Schedule name (positional, required) |

**jmo schedule install**

Install to local cron (Linux/macOS only).

| Flag | Description |
|------|-------------|
| `NAME` | Schedule name (positional, required) |

**jmo schedule uninstall**

Remove from local cron.

| Flag | Description |
|------|-------------|
| `NAME` | Schedule name (positional, required) |

---

### jmo build

Build Docker images for JMo Security.

**Variants:**

| Variant | Tools | Size | Use Case |
|---------|-------|------|----------|
| `fast` | 8 | ~502 MB | CI/CD, pre-commit hooks |
| `slim` | 14 | ~557 MB | Cloud/IaC focused |
| `balanced` | 18 | ~1.4 GB | Production scans (default) |
| `deep` | 28 | ~2.0 GB | Comprehensive audits |

| Flag | Description |
|------|-------------|
| `--variant VARIANT` | Docker variant: `fast`, `slim`, `balanced`, `deep` (default: `balanced`) |
| `--all` | Build all variants |
| `--local` | Use local tags (e.g., `jmo-security:local-balanced`) for testing |
| `--tag TAG` | Image tag (default: `latest`) |
| `--registry REGISTRY` | Docker registry (default: `ghcr.io`) |
| `--org ORG` | Docker organization (default: `jmosecurity`) |
| `--push` | Push images to registry after building |
| `--no-cache` | Build without using cache |
| `--skip-validate` | Skip version validation before building |
| `--platform PLATFORM` | Target platform: `amd64`, `arm64` (default: auto-detect) |

**jmo build validate**

Validate tool versions exist upstream (GitHub, PyPI, npm). No flags.

**jmo build test**

Test a built Docker image.

| Flag | Description |
|------|-------------|
| `--variant VARIANT` | Variant to test: `fast`, `slim`, `balanced`, `deep` (default: `balanced`) |
| `--local` | Test local-tagged image |
| `--registry REGISTRY` | Docker registry (default: `ghcr.io`) |
| `--org ORG` | Docker organization (default: `jmosecurity`) |
| `--tag TAG` | Image tag (default: `latest`) |

---

### jmo mcp-server

Start MCP server for AI-powered remediation orchestration.

The MCP server provides a standardized interface for AI tools to query security findings and suggest fixes. Supports GitHub Copilot, Claude Code, OpenAI Codex, and any MCP-compatible client.

| Flag | Description |
|------|-------------|
| `--results-dir DIR` | Path to results directory (default: `./results`) |
| `--repo-root PATH` | Path to repository root (default: current directory) |
| `--api-key KEY` | API key for authentication (enables production mode) |
| `--log-level LEVEL` | Log level: `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `--human-logs` | Human-friendly colored logs instead of JSON |

**Environment Variables:**

| Variable | Description |
|----------|-------------|
| `MCP_RESULTS_DIR` | Path to results directory (overrides `--results-dir`) |
| `MCP_REPO_ROOT` | Path to repository root (overrides `--repo-root`) |
| `MCP_API_KEY` | API key for authentication (overrides `--api-key`) |

---

### jmo adapters

Manage adapter plugins.

**jmo adapters list**

List all loaded adapter plugins. No flags.

**jmo adapters validate**

Validate an adapter plugin file.

| Flag | Description |
|------|-------------|
| `FILE` | Path to adapter plugin file (positional, required) |

---

## Examples

### Basic Scanning

```bash
# Quick scan of a single repository
jmo fast --repo ./myapp

# Production scan of multiple repositories
jmo balanced --repos-dir ~/repos --human-logs

# CI/CD pipeline with failure threshold
jmo ci --repo . --fail-on HIGH --profile-name balanced
```

### Multi-Target Scanning

```bash
# Scan container image
jmo scan --image nginx:latest --tools trivy syft

# Scan web application
jmo scan --url https://example.com --tools zap nuclei

# Comprehensive scan combining all target types
jmo scan \
  --repo ./myapp \
  --image myapp:latest \
  --terraform-state infrastructure.tfstate \
  --url https://myapp.com
```

### History and Trends

```bash
# View recent scans
jmo history list --limit 10

# Analyze trends over last 30 days
jmo trends analyze --days 30 --validate-statistics

# Check for regressions (fail CI if any found)
jmo trends regressions --fail-on-any
```

### Diff and Comparisons

```bash
# Compare two scan directories
jmo diff baseline-results/ current-results/ --format md

# Auto-detect scans based on Git context
jmo diff --auto

# Compare historical scans from database
jmo diff --scan abc123 --scan def456
```

### Tool Management

```bash
# Check tool status for profile
jmo tools check --profile balanced

# Install tools (parallel, interactive)
jmo tools install --profile balanced

# Update critical tools only
jmo tools update --critical-only --yes
```

### Docker Builds

```bash
# Build balanced variant locally
jmo build --variant balanced --local

# Build all variants and push to registry
jmo build --all --push --tag v1.0.0

# Test a built image
jmo build test --variant balanced --local
```

---

## See Also

- [USER_GUIDE.md](USER_GUIDE.md) - Comprehensive tutorial and configuration guide
- [PROFILES_AND_TOOLS.md](PROFILES_AND_TOOLS.md) - Scan profiles and tool details
- [DOCKER_README.md](DOCKER_README.md) - Docker usage guide
- [POLICY_AS_CODE.md](POLICY_AS_CODE.md) - OPA policy documentation
- [HISTORY_GUIDE.md](HISTORY_GUIDE.md) - SQLite history and persistence
- [TRENDS_GUIDE.md](TRENDS_GUIDE.md) - Trend analysis documentation
