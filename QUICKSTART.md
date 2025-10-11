# Quick Start Guide - Security Audit Tool

This guide will help you get started with the security audit tools in under 5 minutes.

## Step 1: Check Prerequisites

Run the tool check to see what's installed:

```bash
./scripts/cli/security_audit.sh --check
```

If any tools are missing, install them following the instructions in the main README.md.

## Step 2: Prepare Your Repositories

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

## Step 3: Run the Security Audit

Execute the comprehensive security scan:

```bash
cd /path/to/iod-capstone
./scripts/cli/security_audit.sh -d ~/security-testing
```

The script will:
- ✅ Verify all tools are installed
- 🔍 Scan each repository with all security tools
- 📊 Generate comprehensive reports
- 🎨 Create an interactive HTML dashboard

## Step 4: Review Results

After the scan completes, you'll see output like:

```
📁 Results Directory: /home/user/security-results-20251010-111033

📊 Generated Reports:
  • Summary Report:    /home/user/security-results-20251010-111033/SUMMARY_REPORT.md
  • HTML Dashboard:    /home/user/security-results-20251010-111033/dashboard.html
  • Tool Comparison:   /home/user/security-results-20251010-111033/tool-comparisons/comparison.md

Quick Commands:
  View summary:        cat /home/user/security-results-20251010-111033/SUMMARY_REPORT.md
  Open dashboard (mac):open /home/user/security-results-20251010-111033/dashboard.html
  Open dashboard (linux):xdg-open /home/user/security-results-20251010-111033/dashboard.html
```

### Review Priority:

1. **Open the HTML Dashboard** - Visual overview of all findings
2. **Check SUMMARY_REPORT.md** - Executive summary with recommendations
3. **Review Individual Reports** - Detailed findings per repository

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

### Workflow 1: Quick Scan of Single Repo

```bash
# Create test directory with one repo
mkdir -p ~/quick-scan
cd ~/quick-scan
git clone https://github.com/username/test-repo.git

# Run scan
./scripts/cli/security_audit.sh -d ~/quick-scan

# View results
cat ~/security-results-*/SUMMARY_REPORT.md
```

### Workflow 2: Comprehensive Multi-Repo Audit (Using Helper Script)

```bash
# Create a custom repository list
cat > my-repos.txt << 'EOF'
https://github.com/org/repo1.git
https://github.com/org/repo2.git
https://github.com/org/repo3.git
EOF

# Clone all repos in parallel (fast shallow clones)
./scripts/core/populate_targets.sh --list my-repos.txt --dest ~/comprehensive-audit --parallel 6

# Run comprehensive scan
./scripts/cli/security_audit.sh -d ~/comprehensive-audit -o ~/audit-results-$(date +%Y%m%d)

# Open dashboard in browser
open ~/audit-results-*/dashboard.html
```

### Workflow 2b: Comprehensive Multi-Repo Audit (Manual Method)

```bash
# Prepare multiple repositories
mkdir -p ~/comprehensive-audit
cd ~/comprehensive-audit

# Clone multiple repos
for repo in repo1 repo2 repo3; do
    git clone https://github.com/org/$repo.git
done

# Run comprehensive scan
./scripts/cli/security_audit.sh -d ~/comprehensive-audit -o ~/audit-results-$(date +%Y%m%d)

# Open dashboard in browser
open ~/audit-results-*/dashboard.html
```

### Workflow 3: Scheduled Weekly Audit

Create a cron job or scheduled task:

```bash
# Add to crontab (runs every Monday at 9 AM)
0 9 * * 1 /path/to/iod-capstone/scripts/cli/security_audit.sh -d ~/repos-to-monitor

# Or use a shell script
cat > ~/weekly-audit.sh << 'EOF'
#!/bin/bash
AUDIT_DIR=~/weekly-security-audit-$(date +%Y%m%d)
/path/to/iod-capstone/scripts/cli/security_audit.sh -d ~/production-repos -o $AUDIT_DIR
# Email results or upload to dashboard
EOF
chmod +x ~/weekly-audit.sh
```

### Workflow 4: CI/CD Integration

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
          
      - name: Run Security Audit
        run: |
          ./scripts/cli/security_audit.sh -d .
          
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-results
          path: ~/security-results-*
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

**Solution**: Scan repos in smaller batches
```bash
# Instead of scanning all at once, batch them
./scripts/cli/security_audit.sh -d ~/batch1
./scripts/cli/security_audit.sh -d ~/batch2
```

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

## Getting Help

If you encounter issues:
1. Check this Quick Start Guide
2. Review the main README.md
3. Check tool-specific documentation
4. Open an issue on GitHub

---

**Happy Scanning! 🔒**
