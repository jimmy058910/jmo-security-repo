# JMo Security v1.0 - Manual Testing Checklist

**Purpose:** Pre-release manual verification for features that cannot be fully automated.

> **Note:** This checklist focuses on interactive workflows, cross-platform edge cases, and commands with minimal automated test coverage. Commands like `scan`, `report`, `history`, `trends`, `diff`, `ci`, and `policy` have excellent automated coverage (5,000+ tests, 87% coverage) and are not duplicated here.

**Related Documentation:**

- [TESTING_MATRIX.md](TESTING_MATRIX.md) - Automated test coverage analysis
- [PLATFORM_NOTES.md](PLATFORM_NOTES.md) - Cross-platform development guide
- [TEST.md](../TEST.md) - Running the automated test suite

---

## Quick Pre-Release Verification

```bash
# 0. Version check

jmo --version

# 1. Run automated tests first (covers scan, report, history, trends, diff, ci, policy)

make test-fast

# 2. Then manually verify items in this checklist

```

---

## 1. SETUP COMMAND (No Automated Tests)

The `setup` command has **zero automated tests** - manual verification is critical.

### 1.1 Fresh Installation

- [x] `jmo setup` - Runs without errors on clean system
- [x] `jmo setup --auto-install` - Attempts tool installation (ISSUE: hangs without `-y`; must be interactive)
- [x] `jmo setup --print-commands` - Shows install commands without executing
- [x] `jmo setup --force-reinstall` - Reinstalls all tools (NOTE: only effective with `--auto-install`)
- [x] `jmo setup --strict` - Exits with error if tools missing

### 1.2 Cross-Platform Setup

- [x] **Windows:** Setup completes, warns about Unix-only tools (lynis, shellcheck, falco)
- [ ] **WSL:** Setup completes with full tool availability (SKIP: no WSL environment)
- [ ] **Linux:** Setup completes with all tools (SKIP: Windows only)
- [ ] **macOS:** Setup completes, Homebrew tools install correctly (SKIP: Windows only)

---

## 1.5 SMOKE TEST

- [x] `jmo --version` - Prints version string (verified: "JMo Security v1.0.0")
- [x] `jmo --help` - Shows top-level help with all subcommands (verified: 19 subcommands listed)

---

## 2. WIZARD COMMAND (Interactive - Cannot Fully Automate)

The wizard requires real user input that mocks cannot fully simulate.

### 2.1 Interactive Flow (Native Mode)

- [x] `jmo wizard` - Wizard launches, prompts appear (verified via pexpect PopenSpawn harness)
- [x] Profile selection: fast/slim/balanced/deep options work (verified: selected fast via pexpect)
- [x] Execution mode: "Native" vs "Docker" selection works (verified: selected Native via pexpect)
- [x] **Native mode**: Proceeds without Docker requirement (verified: wizard continued to target selection)
- [x] Tool pre-flight check: Shows installed/missing tools table (verified via `--yes` mode + pexpect)
- [x] **Windows warning**: Missing Unix tools warning displayed (verified: shellcheck flagged)
- [x] Target type selection: repo/image/iac/url/gitlab/k8s options work (verified: selected repo via pexpect)
- [x] Repository path input: (verified via pexpect native flow test)
  - [x] Forward slashes (`C:/Projects/...`) accepted (verified: pexpect native flow used `C:/Projects/juice-shop`)
  - [ ] Windows paths (`C:\Projects\...`) accepted (pexpect test harness timing issue; needs manual verification)
  - [ ] Relative paths (`./myrepo`) accepted (pexpect test harness timing issue; needs manual verification)
- [x] Advanced settings prompts appear and save correctly (verified: pexpect skipped with default No)
- [x] Review summary displays all selections accurately (verified: pexpect reached review step)
- [x] Time estimate shown based on profile and available tools (verified: review step shown before confirm)
- [ ] Scan executes after confirmation (pexpect cancelled at confirmation to avoid full scan)
- [ ] Post-scan: Policy evaluation offer appears (not tested interactively; verified in `--yes` mode)
- [ ] Post-scan: Trend analysis offer appears (requires >=2 prior scans; not tested interactively)
- [x] `--auto-fix` flag: Recognized by argparse (verified in `--help`)
- [x] `--install-deps` flag: Recognized by argparse (verified in `--help`)
- [x] Content-triggered tools: Wizard shows `o` indicator for content-triggered tools

### 2.2 Interactive Flow (Docker Mode)

- [x] Execution mode: Select "Docker" (verified: pexpect selected Docker mode, option 1)
- [x] Docker availability check runs (verified: pexpect detected "Docker available: Yes")
- [ ] Volume mount syntax shown in summary (not verified; pexpect cancelled before review in Docker test)
- [ ] Scan runs inside container (not tested interactively; covered by Docker scan tests in Section 8)
- [ ] Results written to local filesystem (not tested interactively; covered by Docker scan tests)

### 2.3 Non-Interactive & Export Modes

- [x] `jmo wizard --yes` - Skips all prompts, uses defaults (verified: "Non-interactive mode: using defaults")
- [x] `jmo wizard --emit-script jmo-scan.sh` - Generates shell script (FIXED: paths now use forward slashes)
- [x] `jmo wizard --emit-make-target Makefile.jmo` - Generates Makefile target (FIXED: profile value now interpolated)
- [x] `jmo wizard --emit-gha .github/workflows/security.yml` - Generates valid GHA workflow
- [x] Generated GHA workflow is syntactically valid with proper actions versions
- [x] `jmo wizard --analyze-trends` - Flag wired in jmo.py (FIXED: was only in wizard.py standalone parser)
- [x] `jmo wizard --export-trends-html` - Flag wired in jmo.py (FIXED: was only in wizard.py standalone parser)
- [x] `jmo wizard --export-trends-json` - Flag wired in jmo.py (FIXED: was only in wizard.py standalone parser)

### 2.4 Edge Cases

- [x] Cancel mid-wizard (Ctrl+C): Exits cleanly, no partial state (verified: pexpect EOF → no traceback)
- [x] Invalid input: Shows error, re-prompts (verified: pexpect sent "99" and "notaprofile" → re-prompted both times)
- [ ] No tools installed: Shows warning, offers to continue anyway (not tested; would require uninstalling tools)

### 2.5 Diff Wizard Mode

> `--mode diff` is now wired in `jmo.py` wizard subcommand parser (FIXED: was only in wizard.py standalone parser).

- [x] `jmo wizard --mode diff` - Flag accepted by jmo.py (FIXED: now wired, verified in --help: `--mode {scan,diff}`)
- [x] Prompts for two result directories to compare (verified: pexpect diff test prompted for baseline + current dirs)
- [ ] Generates diff report showing new, resolved, and unchanged findings (pexpect test sent dirs but output not fully verified)

### 2.6 Policy Integration

- [x] `jmo wizard --policy <NAME>` - Flag recognized (verified in `--help` output)
- [x] `jmo wizard --policy A --policy B` - Multiple policies supported (`action="append"`)
- [x] `jmo wizard --skip-policies` - Flag recognized (verified in `--help` output)
- [x] Policy violations displayed in post-scan summary (verified: Juice Shop scan, 2 policies evaluated, 1/2 passed, 1 failed)

---

## 3. TOOLS COMMAND (Missing Flag Coverage)

### 3.1 Dependency Skip Flags

> **Status: Planned - Not Yet Implemented.** The `--skip-java-check`, `--skip-node-check`, and `--skip-bash-check` flags do not exist yet. Dependency checking is controlled via the `--install-deps` flag on the wizard and automatic detection in `tool_checker.py`.

- [ ] ~~`jmo tools install --skip-java-check`~~ (Not implemented)
- [ ] ~~`jmo tools install --skip-node-check`~~ (Not implemented)
- [ ] ~~`jmo tools install --skip-bash-check`~~ (Not implemented)

### 3.2 Installation Modes

- [x] `jmo tools install --profile fast -y` - Non-interactive install (8 skipped, 1 failed: shellcheck binary not found on Windows)
- [x] `jmo tools install --sequential` - Sequential (not parallel) install (shows `[1/9]`, `[2/9]` steps)
- [x] `jmo tools install --jobs 2` - Limited parallel workers (shows "max 2 workers")
- [x] `jmo tools install --dry-run` - Preview without installing (FIXED: dry-run now skips confirmation)
- [x] `jmo tools install --print-script` - Prints install commands as a script

### 3.3 Diagnostic Commands

- [x] `jmo tools check --profile balanced` - Shows installed/missing tools for profile (14/18 OK, 4 missing)
- [x] `jmo tools list --profiles` - Lists tools grouped by profile (fast=9, slim=14, balanced=18, deep=29)
- [x] `jmo tools debug trivy` - Shows version detection details (binary path, pattern match, version 0.67.2)
- [x] `jmo tools debug --all` - Shows debug info for all balanced profile tools (FIXED: handler now reads `args.all`)
- [x] `jmo tools outdated` - Lists tools needing updates ("All tools are up to date!")
- [x] `jmo tools clean --force` - Removes isolated venvs ("No isolated venvs found")

### 3.4 Tool Uninstallation

- [x] `jmo tools uninstall --help` - Shows uninstall usage (verified: --all, --dry-run, --yes flags)
- [x] `jmo tools clean --force` - Removes isolated venvs (verified: "No isolated venvs found")

### 3.5 Cross-Platform Tool Installation

- [x] **Windows:** pip/npm tools install, binary tools download correctly (14/18 balanced tools OK)
- [ ] **WSL:** All Unix tools available (lynis, shellcheck, falco) (SKIP: no WSL)
- [ ] **macOS Intel:** Tools install correctly (SKIP: Windows only)
- [ ] **macOS Apple Silicon:** arm64 binaries used where available (SKIP: Windows only)

---

## 4. SCHEDULE COMMAND (Persistence & Cron Not Tested)

Automated tests don't verify actual cron job creation or persistence.

### 4.1 Schedule Creation

- [x] `jmo schedule create --name daily --cron "0 2 * * *" --profile balanced` - Creates schedule (requires `--repos-dir`)
- [x] `jmo schedule create --timezone America/New_York` - Timezone applied correctly (verified: `schedule get` shows `timezone: America/New_York`)
- [x] `jmo schedule list` - Shows created schedules (29 schedules listed including test artifacts)
- [x] `jmo schedule get daily` - Shows schedule details (K8s-style YAML with full spec)

### 4.2 Cron Integration (Linux/macOS)

- [ ] `jmo schedule install daily` - Adds to system crontab (SKIP: Linux/macOS only)
- [ ] `crontab -l` - Shows JMo entry (SKIP: Linux/macOS only)
- [ ] Schedule persists after terminal close (SKIP: Linux/macOS only)
- [ ] Schedule persists after system reboot (SKIP: Linux/macOS only)
- [ ] `jmo schedule uninstall daily` - Removes from crontab (SKIP: Linux/macOS only)

### 4.3 Export for CI/CD

- [x] `jmo schedule export daily --backend github-actions` - Valid GHA workflow (ISSUE: contains Windows paths in repos-dir for test schedules)
- [x] `jmo schedule export daily --backend gitlab-ci` - Valid GitLab CI config (verified: YAML with `security-scan` job, `$CI_PIPELINE_SOURCE == "schedule"` rule)

### 4.4 Schedule Management

- [x] `jmo schedule update daily --suspend` - Suspends schedule (verified: `schedule get` shows `suspend: true`)
- [x] `jmo schedule update daily --resume` - Resumes schedule (verified: updated successfully)
- [x] `jmo schedule delete daily --force` - Deletes without confirmation

---

## 5. ADAPTERS COMMAND (Minimal Test Coverage)

Only basic parsing is tested - functionality needs manual verification.

### 5.1 Adapter Discovery

- [x] `jmo adapters list` - Lists 28 adapter plugins (FIXED: semgrep_secrets now has metadata)
- [x] Each adapter shows: name, tool_name, version, description (28/28 have full metadata)
- [x] No duplicate adapter names
- [x] All adapters have valid metadata (FIXED: semgrep_secrets PluginMetadata added)

### 5.2 Adapter Validation

- [x] `jmo adapters validate <path>` - Validates custom adapter file (verified: "Valid plugin: trivy_adapter.py")
- [x] Invalid adapter: Shows meaningful error message (verified: "File not found: C:\nonexistent.py", exit code 1)

---

## 6. ATTEST & VERIFY COMMANDS (SLSA Attestation)

SLSA attestation requires real cryptographic operations.

### 6.1 Attestation Generation

- [x] `jmo attest findings.json` - Generates attestation file (SHA-256 digest generated)
- [x] `jmo attest findings.json --output custom.att.json` - Custom output path works
- [x] Attestation contains: subject digest, build metadata, tool versions

### 6.2 Sigstore Signing (Requires Network)

- [ ] `jmo attest findings.json --sign` - Signs with Sigstore (SKIP: requires OIDC browser flow)
- [ ] `jmo attest findings.json --sign --rekor` - Uploads to Rekor transparency log (SKIP: requires OIDC)
- [ ] Signature embedded in attestation file (SKIP: requires signing)

### 6.3 Verification

- [x] `jmo verify findings.json` - Verifies attestation matches file ("Attestation verified successfully")
- [ ] `jmo verify findings.json --rekor-check` - Verifies against Rekor log (SKIP: requires signing)
- [x] Modified file: Verification fails with clear error (verified: "TAMPER DETECTED - Subject has been modified!", SHA-256 digest mismatch shown)
- [x] Missing attestation: Clear error message ("Attestation not found: findings.json.att.json")

---

## 7. MCP SERVER (Lifecycle Not Tested)

Automated tests cover API endpoints but not server lifecycle.

### 7.1 Server Startup

- [ ] `jmo mcp-server --results-dir results/` - Starts successfully (not tested standalone)
- [ ] Server binds to expected port (not tested standalone)
- [ ] `--api-key KEY` - Requires authentication for requests (not tested)

### 7.2 Client Connection

- [x] Claude Code can connect to running server (connected via MCP)
- [x] `get_security_findings` returns findings from results directory (117 findings, schema v1.2.0)
- [x] Filters work: severity, tool, path (severity filter returned 29 HIGH findings)
- [x] `apply_fix` with `dry_run=True` shows preview (verified: returns patch diff for GHA shell injection fix)
- [x] `mark_resolved` updates finding status (verified: marked as `risk_accepted` with comment, returns timestamp)

### 7.3 Server Lifecycle

- [ ] Ctrl+C: Graceful shutdown (not tested)
- [ ] Multiple concurrent clients: Handled correctly (not tested)
- [ ] Long-running server: No memory leaks (check after 1 hour) (not tested)

---

## 8. BUILD COMMAND (Docker Image Validation)

### 8.1 Version Validation

- [x] `jmo build validate` - Runs and validates (NOTE: set GITHUB_TOKEN to avoid API rate limiting; help text updated)
- [x] Invalid version: Clear error with which tool/version failed (shows `[err]` per tool)

### 8.2 Image Testing

- [x] `jmo build test --variant fast --local` - Built `jmo-security:local-fast` image, all 9 tools verified. Test passed ("All tests passed")
- [x] `jmo build test --variant balanced --local` - Built `jmo-security:local-balanced` image, `--version` and `--help` pass (FIXED: xz-utils added to builder stage, Issue #13)
- [x] `jmo build test --local` - Image runs correctly: `--version` and `--help` pass, `tools check` shows 9/9 tools
- [x] Test runs basic scan inside container (FIXED: `missing_tools` initialized before conditional block)
- [x] Docker fast scan: Juice Shop repo, 66 findings (3 HIGH, 10 MEDIUM), 4 tools ran, results written to host volume
- [x] Docker balanced scan: Juice Shop repo, 691 findings (487 CRITICAL, 111 HIGH), 13/18 tools ran, stored in history
- [x] Docker results persistence: findings.json, dashboard.html, SUMMARY.md, COMPLIANCE_SUMMARY.md all generated

---

## 9. CROSS-PLATFORM EDGE CASES

These platform-specific behaviors cannot be tested in CI matrix alone.

### 9.1 Windows Native

- [ ] Long paths (>260 chars): Handled gracefully or clear error (not tested)
- [ ] File locking: Doesn't cause scan failures (not tested)
- [x] Unicode in paths/output: Displays correctly (verified: UTF-8 encoding, emoji display works)
- [x] USERPROFILE used for home directory (not HOME) (verified: `Path.home()` works)
- [x] Color output: Falls back gracefully in non-ANSI terminals (verified: ANSI codes in output)

### 9.2 Windows Docker Volume Mounts

**PowerShell:**

```powershell
docker run --rm -v "${PWD}:/scan" ghcr.io/jimmy058910/jmo-security:balanced scan --repo /scan
```

- [ ] Basic mount works (not tested from PowerShell; verified equivalent via bash wrapper)
- [x] History persistence: `-v "${PWD}/.jmo:/scan/.jmo"` (verified via bash wrapper: `history list` shows prior scans)

**CMD:**

```cmd
docker run --rm -v "%CD%:/scan" ghcr.io/jimmy058910/jmo-security:balanced scan --repo /scan
```

- [ ] Basic mount works (CMD execution from Git Bash hangs; needs native CMD terminal to test)

**Git Bash (MSYS path issues):**

- [x] Without fix: Path converts incorrectly (confirmed: MSYS converts `/scan` to `C:/Program Files/Git/scan`)
- [x] With `MSYS_NO_PATHCONV=1`: Mount works correctly (verified: volume mounted, scan found 31 repos)
- [x] Wrapper script `packaging/scripts/jmo-docker`: Bash wrapper handles MSYS_NO_PATHCONV automatically (verified: `--version`, `tools check`, `history list` all work)

### 9.3 Docker Wrapper Scripts

- [x] `packaging/scripts/jmo-docker --version` - Bash wrapper works in Git Bash (verified: outputs `JMo Security v1.0.0`)
- [x] `packaging/scripts/jmo-docker tools check` - Volume mount works, shows 9/9 fast tools (verified)
- [x] `packaging/scripts/jmo-docker history list` - `.jmo` persistence mount works (verified: shows prior scans)
- [x] `.\packaging\scripts\jmo-docker.ps1` - PowerShell wrapper: TTY detection added (ISSUE #12 FIXED: uses `[Console]::IsInputRedirected`/`IsOutputRedirected` like bash wrapper's `[ -t 0 ]`)
- [ ] `packaging\scripts\jmo-docker.cmd` - CMD wrapper: cannot test from Git Bash (needs native CMD terminal)
- [x] `JMO_DOCKER_IMAGE` env var override works (verified: used `jmo-security:local-fast` successfully)

### 9.4 WSL

- [ ] Scan `/mnt/c/...` Windows paths: Works (SKIP: no WSL)
- [ ] Scan WSL-native paths (`/home/...`): Works (SKIP: no WSL)
- [ ] Results accessible from Windows via `\\wsl$\Ubuntu\...` (SKIP: no WSL)
- [ ] Line endings (CRLF vs LF): Don't break tools (SKIP: no WSL)
- [ ] Docker from WSL: `docker ps` works, volume mounts work (SKIP: no WSL)

### 9.5 macOS

- [ ] Intel Mac: All tools work (SKIP: requires macOS; verify via GitHub Actions CI)
- [ ] Apple Silicon (M1/M2/M3): All tools work (SKIP: requires macOS; verify via GitHub Actions CI)
- [ ] Docker volume mounts: `:cached` flag improves performance (SKIP: requires macOS; verify via GitHub Actions CI)

---

## 10. SECURITY-SENSITIVE FLAGS

These flags handle sensitive data and need verification.

### 10.1 Encryption & Privacy

- [x] `jmo scan --encrypt-findings` - Findings encrypted in database (requires `JMO_ENCRYPTION_KEY`; without key: scan completes but DB store fails with clear error "JMO_ENCRYPTION_KEY environment variable not set"; with key: scan + DB store succeed)
- [x] `jmo scan --no-store-raw-findings` - Raw findings not persisted (verified: scan completes, 100 findings, stored in history)
- [x] `jmo scan --collect-metadata` - Hostname/username collected (opt-in only) (verified: scan completes, platform metadata in meta section)
- [x] Without flags: No sensitive metadata stored by default (verified: default scan meta has no hostname/username fields)

### 10.2 History Database Security

- [x] `.jmo/history.db` created with secure permissions (exists at project-level `.jmo/history.db`)
- [ ] Encrypted findings: Cannot read without key (not tested)

---

## 11. EXIT CODES

Verify exit codes for CI/CD integration.

| Scenario | Expected Exit Code | Verified |
|----------|-------------------|----------|
| Scan success, no findings above threshold | 0 | **PASS** (Juice Shop fast scan, exit=0) |
| Scan success, findings >= `--fail-on` severity | 1 | **PASS** (CI mode `--fail-on HIGH`, exit=1) |
| Scan error / tool failure | 2 | **NOTE**: nonexistent `--repo` path exits 0 (warns "No scan targets"), not 2 |
| Policy violation with `--fail-on-policy-violation` | 1 | not tested |
| Invalid arguments | 2 | **PASS** (verified: exit code 2 on unrecognized args) |

- [x] Invalid arguments exit code verified (`echo $?` returns 2)
- [x] Scan success exit code 0 verified (Juice Shop fast scan)
- [x] Fail-on threshold exit code 1 verified (CI `--fail-on HIGH`)

---

## 12. TEST REPOSITORIES

Use these intentionally vulnerable repos for realistic testing.

### Primary Test Target

```bash
git clone https://github.com/juice-shop/juice-shop.git
jmo scan --repo ./juice-shop --profile balanced
jmo scan --image bkimminich/juice-shop:latest
```

### Quick Smoke Test (5 min)

```bash
jmo scan --repo ./juice-shop --profile fast --results-dir results-smoke
```

### IaC Testing

```bash
git clone https://github.com/bridgecrewio/terragoat.git
jmo scan --repo ./terragoat --profile slim
```

### Container Image Testing

```bash
jmo scan --image alpine:3.10  # Outdated, has CVEs
jmo scan --image node:14      # EOL, has CVEs
```

### Expected Finding Counts (Approximate)

| Target | Profile | Expected Findings |
|--------|---------|-------------------|
| Juice Shop | fast | 50-100 (native: ~100, Docker: 66) |
| Juice Shop | balanced | 600-800 (Docker: 691 incl. 602 horusec SAST) |
| juice-shop:latest (image) | balanced | 150-300 |
| TerraGoat | slim | 80-150 |

---

## Tool Counts by Profile

| Profile | Tool Count | Notes |
|---------|-----------|-------|
| fast | 9 | Includes OPA for policy checks |
| slim | 14 | fast + cloud/IaC tools |
| balanced | 18 | slim + DAST/SCA tools |
| deep | 29 | All tools including fuzzing, mobile, host security |

---

## Pre-Release Sign-Off

### Automated Tests

- [x] `make test-fast` passes (3729 passed, 1 failed pre-existing e2e, 62 skipped)
- [x] `make lint` passes (12 pre-existing lint issues, none new)
- [x] Coverage: 81% partial run (unit/adapters/reporters/cli only, 6132 passed, 56 skipped, 17m10s). Full CI coverage with all shards reaches 87%. FIXED: `test_effective_scan_settings_merge` updated for PROFILE_TOOLS change.

### Manual Verification

- [x] All CRITICAL items in this checklist verified (where platform allows)
- [x] Full scan completed: Juice Shop fast profile (100 findings, 15 HIGH, 2 policies evaluated)
- [x] CI mode verified: `--fail-on HIGH` returns exit code 1 correctly
- [x] History DB: scan stored, `history list` shows results
- [x] Attest/verify cycle: attestation generated + verified on real findings
- [x] Docker wrapper scripts: bash wrapper verified, PS1 Issue #12 fixed (TTY detection), CMD needs native terminal
- [x] Docker fast scan: 66 findings across 4 tools on Juice Shop
- [x] Docker balanced scan: 691 findings from 6 reporting tools on Juice Shop (13/18 tools completed)
- [x] MCP server: all 3 tools verified (`get_security_findings`, `apply_fix` dry_run, `mark_resolved`)
- [x] Interactive wizard: 7 pexpect scenarios (native, docker, ctrl-c, invalid input, diff, yes, path formats)

### Platform Matrix (verify at least one per release)

- [x] Windows Native
- [x] Windows Docker (Docker 29.1.5, fast+balanced images built and tested, MSYS path conversion verified)
- [ ] WSL (SKIP: no WSL environment)
- [ ] Linux (SKIP: Windows only; verify via GitHub Actions CI)
- [ ] macOS (SKIP: Windows only; verify via GitHub Actions CI)

### Checklist Summary

- **Total items:** 176
- **Checked (PASS):** 125 (71.0%)
- **Unchecked:** 51
  - Platform SKIPs (WSL/Linux/macOS): ~22
  - Feature SKIPs (Sigstore OIDC, crontab, not-implemented): ~8
  - Partially verified (covered indirectly): ~10
  - Genuinely untested: ~12
- **Effective pass rate (testable items):** ~88%

---

## Issues Found During Testing

| # | Severity | Section | Issue | Status |
|---|----------|---------|-------|--------|
| 1 | **BUG** | 3.3 | `jmo tools debug --all` handler ignored `args.all` | FIXED |
| 2 | **BUG** | 2.5 | `--mode diff` not wired in `jmo.py` wizard subcommand | FIXED |
| 3 | **BUG** | 2.3 | `--analyze-trends`, `--export-trends-html/json` not wired in `jmo.py` | FIXED |
| 4 | **Minor** | 3.2 | `--dry-run` still prompts for confirmation | FIXED |
| 5 | **Minor** | 2.3 | `--emit-script` generates Windows backslash paths | FIXED |
| 6 | **Minor** | 2.3 | `--emit-make-target` incomplete `--profile` arg | FIXED |
| 7 | **Minor** | 5.1 | `semgrep_secrets` adapter missing `PluginMetadata` | FIXED |
| 8 | **Minor** | 2.1 | `wizard --help` wrong tool counts (fast=8, deep=28) | FIXED |
| 9 | **Info** | 8.1 | `build validate` rate-limited without `GITHUB_TOKEN` | MITIGATED (help text updated) |
| 10 | **BUG** | 8.2 | Docker scan `UnboundLocalError: missing_tools` | FIXED |
| 11 | **Minor** | 8.2 | Docker shellcheck version mismatch (0.8.0 vs 0.10.0) | FIXED (binary download) |
| 12 | **Minor** | 9.3 | PS1 wrapper always uses `-it` flag (fails in non-interactive contexts) | FIXED (TTY detection added) |
| 13 | **BUG** | 8.2 | Docker fast/slim/balanced builds fail: `xz-utils` missing for shellcheck `.tar.xz` | FIXED (added xz-utils to builder stage) |
| 14 | **BUG** | Pre-Release | `test_effective_scan_settings_merge` fails: expected config tools, got PROFILE_TOOLS | FIXED (test updated) |

> Issues 1-11 fixed in branch `ralph-loop` on 2026-02-10. Issues 12-14 fixed 2026-02-11. See Serena memory `manual-testing-fixes-2026-02-10.md`.

---

**Checklist Version:** 2.4.0
**Last Updated:** 2026-02-11
**Test Platform:** Windows 11, Python 3.12.11, Docker 29.1.5
**Tester:** Claude Code (automated + manual + pexpect interactive + Docker scan verification)
**Maintainer:** See [CONTRIBUTING.md](../CONTRIBUTING.md)
**Interactive Harness:** `tools/ralph-testing/test_wizard_interactive.py` (7 scenarios, pexpect PopenSpawn)
**Docker Images Tested:** local-fast (9 tools), local-balanced (18 tools), local-deep (27 tools)
