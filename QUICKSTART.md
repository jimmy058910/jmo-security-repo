# Quick Start – JMo Security CLI

Get up and running in under 5 minutes using the unified Python CLI (scan/report/ci).

## Beginner mode: jmotools wrapper

Prefer simple, memorable commands? Use the wrapper:

```bash
# Quick fast scan (auto-opens results)
jmotools fast --repos-dir ~/security-testing

# Deep/full scan using the curated 'deep' profile
jmotools full --repos-dir ~/security-testing --allow-missing-tools

# Clone from TSV first, then scan
jmotools balanced --tsv ai-search/candidates.tsv --dest ./repos-tsv
```

What it does for you:
- Detects OS/WSL and verifies tools
- Optionally clones from a TSV and writes `results/targets.tsv.txt`
- Runs `jmo ci` with the selected profile
- Opens `results/summaries/dashboard.html` and `SUMMARY.md` at the end

### Bootstrap tools

```bash
jmotools setup --check
jmotools setup --auto-install       # optional, Linux/WSL
```

### Makefile shortcuts

```bash
make setup                   # verify tools (installs package if needed)
make fast DIR=~/repos        # run fast profile
make balanced DIR=~/repos    # run balanced profile
make full DIR=~/repos        # run deep profile
```

## Step 1: Verify environment

```bash
make verify-env
```

This detects Linux/WSL/macOS, checks for optional tools (gitleaks, semgrep, trivy, etc.), and prints install hints.

## Step 2: Prepare your repositories

### Option A: Use Helper Script (Recommended - Fast & Easy)

Use the automated helper script to clone multiple repositories quickly:

```bash
# Quick setup - clone sample vulnerable repos
./scripts/core/populate_targets.sh

# Or customize the destination
./scripts/core/populate_targets.sh --dest ~/my-test-repos

# For faster cloning on WSL, use shallow clones (default)
./scripts/core/populate_targets.sh --parallel 8 --dest ~/security-testing
```

The helper script will:
- ✅ Clone repositories in parallel for speed
- ✅ Use shallow clones (depth=1) for 10x faster cloning
- ✅ Automatically create the destination directory
- ✅ Skip already cloned repositories

### Option B: Manual Clone (Traditional Method)

Create a directory and clone repositories manually:

```bash
# Create testing directory
mkdir -p ~/security-testing

# Clone repositories to scan
cd ~/security-testing
git clone https://github.com/username/repo1.git
git clone https://github.com/username/repo2.git
# ... add more repos
```

### Need Full Git History?

Some secret scanners work better with full git history. If you used shallow clones:

```bash
# Unshallow all repositories
./scripts/core/populate_targets.sh --dest ~/security-testing --unshallow
```

## Step 3: Run the security audit

Use the Python CLI for a single repo or a directory of repos:

```bash
# Scan + report in one step for CI-like flow
python3 scripts/cli/jmo.py ci --repos-dir ~/security-testing --fail-on HIGH --profile --human-logs

# Or run scan and report separately
python3 scripts/cli/jmo.py scan --repos-dir ~/security-testing --profile-name balanced --human-logs
python3 scripts/cli/jmo.py report ./results --profile --human-logs
```

## Step 4: Review Results

After the scan completes, results land in `results/` (or the directory you pass via `--results-dir`). Unified artifacts live under `results/summaries/`:

- `SUMMARY.md` — human-readable overview with severity counts
- `findings.json` / `findings.yaml` — normalized data for automation (YAML requires PyYAML)
- `dashboard.html` — interactive view of all findings
- `findings.sarif` — SARIF 2.1.0 for code scanning integrations
- `timings.json` — written when `--profile` is used
- `SUPPRESSIONS.md` — appears when a suppression file filtered findings

Quick commands:

```bash
cat results/summaries/SUMMARY.md
xdg-open results/summaries/dashboard.html   # macOS: open
ls -1 results/individual-repos/infra-demo   # per-tool raw outputs
```

### Review Priority:

1. **Open the HTML Dashboard** - Visual overview of all findings
2. **Check SUMMARY_REPORT.md** - Executive summary with recommendations
3. **Review Individual Reports** - Detailed findings per repository
4. Optional: For a machine-readable format, check summaries/findings.json or summaries/findings.sarif

## Understanding the Results

### Severity Levels

| Level | Meaning | Action Required |
|-------|---------|-----------------|
| CRITICAL | Verified active secrets | Rotate/revoke immediately |
| HIGH | Likely secrets or serious issues | Fix within 24-48 hours |
| MEDIUM | Potential issues | Review and fix soon |
| LOW | Informational | Address during regular maintenance |

### Key Metrics to Monitor

- **Verified Secrets**: Confirmed active credentials (immediate action required)
- **Total Findings**: Overall security issue count
- **Unique Issue Types**: Variety of security problems found

## Example Workflows

### Workflow 1: Quick scan of single repo

```bash
# Create test directory with one repo
mkdir -p ~/quick-scan
cd ~/quick-scan
git clone https://github.com/username/test-repo.git

# Run scan (Python CLI)
python3 scripts/cli/jmo.py scan --repos-dir ~/quick-scan --human-logs

# View results
cat results/summaries/SUMMARY.md
ls -1 results/individual-repos
```

### Workflow 2: Comprehensive multi-repo audit (helper script)

```bash
# Create a custom repository list
cat > my-repos.txt << 'EOF'
https://github.com/org/repo1.git
https://github.com/org/repo2.git
https://github.com/org/repo3.git
EOF

# Clone all repos in parallel (fast shallow clones)
./scripts/core/populate_targets.sh --list my-repos.txt --dest ~/comprehensive-audit --parallel 6

# Run comprehensive scan + report via CLI
python3 scripts/cli/jmo.py ci --repos-dir ~/comprehensive-audit --profile-name deep --fail-on HIGH --profile

# Open dashboard in browser
xdg-open results/summaries/dashboard.html   # macOS: open
ls -1 results/summaries
```

### Workflow 2b: Comprehensive multi-repo audit (manual)

```bash
# Prepare multiple repositories
mkdir -p ~/comprehensive-audit
cd ~/comprehensive-audit

# Clone multiple repos
for repo in repo1 repo2 repo3; do
  git clone https://github.com/org/$repo.git
done

# Run comprehensive scan via CLI
python3 scripts/cli/jmo.py ci --repos-dir ~/comprehensive-audit --profile-name balanced --fail-on HIGH --profile

# Open dashboard in browser
xdg-open results/summaries/dashboard.html   # macOS: open
```

### Workflow 3: Scheduled weekly audit

Create a cron job or scheduled task:

```bash
# Add to crontab (runs every Monday at 9 AM)
0 9 * * 1 python3 /path/to/repo/scripts/cli/jmo.py ci --repos-dir ~/repos-to-monitor --profile-name fast --fail-on HIGH --profile

# Or use a shell script
cat > ~/weekly-audit.sh << 'EOF'
#!/bin/bash
set -euo pipefail
WORKDIR=~/weekly-security-audit
python3 /path/to/repo/scripts/cli/jmo.py ci \
  --repos-dir ~/production-repos \
  --results-dir "$WORKDIR" \
  --profile-name balanced \
  --fail-on HIGH \
  --profile
echo "Summaries written to $WORKDIR/summaries"
EOF
chmod +x ~/weekly-audit.sh
```

### Workflow 4: CI/CD integration

Add to your CI/CD pipeline:

```yaml
# Example GitHub Actions workflow
name: Security Audit
on:
  push:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install tools
        run: |
          # Install Gitleaks, TruffleHog, Semgrep

      - name: Run Security Audit (scan + report)
        run: |
          python3 scripts/cli/jmo.py ci --repos-dir . --profile-name balanced --fail-on HIGH --profile

      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-results
          path: ~/security-results-*

## CI at a glance

- Tests run on a matrix of operating systems and Python versions:
  - OS: ubuntu-latest, macos-latest
  - Python: 3.10, 3.11, 3.12
- Concurrency cancels redundant runs on rapid pushes; each job has a 20-minute timeout.
- Coverage is uploaded to Codecov using tokenless OIDC (no secret needed on public repos).
- PyPI releases use Trusted Publishers (OIDC) — no API token required once authorized in PyPI.

See `.github/workflows/tests.yml` and `.github/workflows/release.yml` for the exact configuration.
```

## Troubleshooting

### Issue: "Tools not found"

**Solution**: Install missing tools

```bash
# Check which tools are missing
./scripts/cli/security_audit.sh --check

# Install individually or follow README.md
```

### Issue: "Permission denied"

**Solution**: Make scripts executable

```bash
find scripts -type f -name "*.sh" -exec chmod +x {} +
```

### Issue: "No repositories found"

**Solution**: Ensure directory has git repositories

```bash
# Check directory structure
ls -la ~/security-testing/

# Each subdirectory should be a git repo with .git folder
```

### Issue: "Out of memory during scan"

Note for WSL users: For the best Nosey Parker experience on WSL, prefer a native install; see the User Guide section “Nosey Parker on WSL (native recommended) and auto-fallback (Docker)”.

**Solution**: Scan repos in smaller batches

```bash
# Instead of scanning all at once, batch them
./scripts/cli/security_audit.sh -d ~/batch1
./scripts/cli/security_audit.sh -d ~/batch2
```

## Interpreting CI failures (quick reference)

- Workflow syntax or logic (actionlint)
  - Symptom: step "Validate GitHub workflows (actionlint)" fails early.
  - Fix: run locally: `pre-commit run actionlint --all-files` or inspect `.github/workflows/*.yml` for typos and invalid `uses:` references. Ensure actions are pinned to valid tags.

- Pre-commit checks (YAML, formatting, lint)
  - Symptom: pre-commit step fails on YAML, markdownlint, ruff/black, etc.
  - Fix: run `make pre-commit-run` locally; address reported files. We ship `.yamllint.yaml` and validate Actions via actionlint.

- Coverage threshold not met
  - Symptom: pytest completes but `--cov-fail-under=85` causes job failure.
  - Fix: add tests for unexercised branches (see adapters’ error paths and reporters). Run `pytest -q --maxfail=1 --disable-warnings --cov=. --cov-report=term-missing` locally to identify gaps.

- Codecov upload warnings
  - Symptom: Codecov step logs request a token or OIDC; or upload skipped.
  - Context: Public repos typically don’t need `CODECOV_TOKEN`. We use tokenless OIDC on CI. If logs insist, either enable OIDC in Codecov org/repo or add `CODECOV_TOKEN` (optional).
  - Check: confirm `coverage.xml` exists; CI task runs tests before upload.

If a failure isn’t listed here, click into the failed step logs in GitHub Actions for the exact stderr. Open an issue with the error snippet for help.

## Next Steps

1. **Review all CRITICAL findings** - These require immediate action
2. **Rotate any verified secrets** - Use the tool comparison report to understand findings
3. **Implement pre-commit hooks** - Prevent future issues (see README.md)
4. **Schedule regular audits** - Weekly or monthly depending on activity
5. **Track metrics over time** - Monitor security posture improvement

## Advanced Usage

For more advanced features and customization options, see:
- [README.md](README.md) - Comprehensive documentation
- [Tool Comparison Report](tool-comparisons/comparison.md) - Understanding tool capabilities
- Individual tool documentation for detailed configuration

### Profiling and Performance

To record timing information and a heuristic thread recommendation when generating unified reports:

```bash
# After a scan completes, generate reports with profiling enabled
make profile RESULTS_DIR=/path/to/security-results

# Or directly via CLI
python3 scripts/cli/jmo.py report /path/to/security-results --profile

# Inspect timings
cat /path/to/security-results/summaries/timings.json
```

## Getting Help

If you encounter issues:
1. Check this Quick Start Guide
2. Review the main README.md
3. Check tool-specific documentation
4. Open an issue on GitHub

---

**Happy Scanning! 🔒**
