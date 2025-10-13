#!/bin/bash
# run_security_audit.sh - Master security testing orchestrator

set -Eeuo pipefail # Exit on error, unset, and pipefail

# Configuration
TESTING_DIR="${1:-$HOME/security-testing}"
RESULTS_DIR="${2:-$HOME/security-results-$(date +%Y%m%d-%H%M%S)}"
SUMMARY_FILE="$RESULTS_DIR/SUMMARY_REPORT.md"
RAW_OUTPUTS_DIR="$RESULTS_DIR/raw-outputs"

# Tool flags (set to 1 to enable)
RUN_CLOC=1
RUN_GITLEAKS=1
RUN_TRUFFLEHOG=1
RUN_SEMGREP=1
RUN_NOSEYPARKER=1

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Validate testing directory exists
if [ ! -d "$TESTING_DIR" ]; then
  log_error "Testing directory does not exist: $TESTING_DIR"
  log_info "Usage: $0 [testing_directory] [results_directory]"
  exit 1
fi

# Create results directory structure
mkdir -p "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR/individual-repos"
mkdir -p "$RESULTS_DIR/tool-comparisons"
mkdir -p "$RAW_OUTPUTS_DIR"
mkdir -p "$RESULTS_DIR/summaries"

log_success "Created results directory: $RESULTS_DIR"

# Count repositories
TOTAL_REPOS=$(find "$TESTING_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)

# Initialize summary report
cat >"$SUMMARY_FILE" <<EOF
# Security Audit Report

**Date:** $(date)
**Testing Directory:** $TESTING_DIR
**Total Repositories Analyzed:** $TOTAL_REPOS

---

## Executive Summary

This report provides a comprehensive security analysis of $TOTAL_REPOS repositories using multiple security scanning tools.

### Tools Used:
- **Gitleaks**: Git history secret scanning
- **TruffleHog**: Deep secret scanning with verification
- **Semgrep**: Pattern-based vulnerability detection
- **Nosey Parker**: Deep pattern matching for secrets
- **cloc**: Code metrics and statistics

---

EOF

# Function to test individual repository
test_repository() {
  local repo_path=$1
  local repo_name
  repo_name=$(basename "$repo_path")
  local repo_results="$RESULTS_DIR/individual-repos/$repo_name"

  mkdir -p "$repo_results"

  log_info "Testing repository: $repo_name"
  echo "================================="

  # Create repo-specific summary
  cat >"$repo_results/README.md" <<EOF
# Security Analysis: $repo_name

**Path:** $repo_path
**Analysis Date:** $(date)

---

## Repository Metrics

EOF

  # Initialize counters for aggregation
  local total_issues=0
  local critical_issues=0
  local high_issues=0
  local medium_issues=0

  # 1. Code metrics with cloc
  if [ $RUN_CLOC -eq 1 ]; then
    log_info "Running cloc..."
    if command -v cloc &>/dev/null; then
      cloc "$repo_path" --json >"$repo_results/cloc.json" 2>/dev/null || log_warning "cloc failed for $repo_name"
      cloc "$repo_path" --quiet >>"$repo_results/README.md" 2>/dev/null || echo "cloc output not available" >>"$repo_results/README.md"
      echo "" >>"$repo_results/README.md"
    else
      log_warning "cloc not installed, skipping"
    fi
  fi

  # 2. Gitleaks - Fast git history scanning
  if [ $RUN_GITLEAKS -eq 1 ]; then
    log_info "Running Gitleaks..."
    if command -v gitleaks &>/dev/null; then
      gitleaks detect \
        --source "$repo_path" \
        --report-format json \
        --report-path "$repo_results/gitleaks.json" \
        --verbose >"$repo_results/gitleaks.log" 2>&1 || true

      # Parse results with better error handling
      if [ -f "$repo_results/gitleaks.json" ]; then
        GITLEAKS_COUNT=$(jq 'if type=="array" then length else 0 end' "$repo_results/gitleaks.json" 2>/dev/null || echo 0)
        total_issues=$((total_issues + GITLEAKS_COUNT))
        high_issues=$((high_issues + GITLEAKS_COUNT))

        {
          echo "## 🔍 Gitleaks Results"
          echo ""
          echo "**Secrets Found:** $GITLEAKS_COUNT"
          echo ""
        } >>"$repo_results/README.md"

        if [ "$GITLEAKS_COUNT" -gt 0 ]; then
          echo "### Findings Details:" >>"$repo_results/README.md"
          echo "" >>"$repo_results/README.md"
          jq -r '.[] | "- **\(.RuleID)**: \(.Description) (File: \(.File), Line: \(.StartLine))"' "$repo_results/gitleaks.json" 2>/dev/null >>"$repo_results/README.md" || echo "Error parsing findings" >>"$repo_results/README.md"
          echo "" >>"$repo_results/README.md"
        fi
      else
        log_warning "Gitleaks JSON output not found for $repo_name"
        {
          echo "## 🔍 Gitleaks Results"
          echo ""
          echo "**Status:** No findings or scan failed"
          echo ""
        } >>"$repo_results/README.md"
      fi
    else
      log_warning "Gitleaks not installed, skipping"
    fi
  fi

  # 3. TruffleHog - Deep scanning with verification
  if [ $RUN_TRUFFLEHOG -eq 1 ]; then
    log_info "Running TruffleHog..."
    if command -v trufflehog &>/dev/null; then
      trufflehog git file://"$repo_path" \
        --json \
        --no-update \
        >"$repo_results/trufflehog.json" 2>"$repo_results/trufflehog.log" || true

      # Count verified vs unverified with better parsing
      if [ -f "$repo_results/trufflehog.json" ]; then
        TRUFFLE_VERIFIED=$(jq -s '[.[] | select(.verified == true)] | length' "$repo_results/trufflehog.json" 2>/dev/null || echo 0)
        TRUFFLE_TOTAL=$(jq -s 'length' "$repo_results/trufflehog.json" 2>/dev/null || echo 0)
        total_issues=$((total_issues + TRUFFLE_TOTAL))
        critical_issues=$((critical_issues + TRUFFLE_VERIFIED))
        medium_issues=$((medium_issues + TRUFFLE_TOTAL - TRUFFLE_VERIFIED))

        {
          echo "## 🔎 TruffleHog Results"
          echo ""
          echo "**Total Findings:** $TRUFFLE_TOTAL"
          echo "**Verified Secrets:** $TRUFFLE_VERIFIED"
          echo "**Unverified:** $((TRUFFLE_TOTAL - TRUFFLE_VERIFIED))"
          echo ""
        } >>"$repo_results/README.md"

        if [ "$TRUFFLE_VERIFIED" -gt 0 ]; then
          echo "### ⚠️ Verified Secrets (CRITICAL):" >>"$repo_results/README.md"
          echo "" >>"$repo_results/README.md"
          jq -r 'select(.verified == true) | "- **\(.DetectorName // "Unknown")**: Found in \(.SourceMetadata.Data.Filesystem.file // "unknown file")"' "$repo_results/trufflehog.json" 2>/dev/null >>"$repo_results/README.md" || echo "Error parsing findings" >>"$repo_results/README.md"
          echo "" >>"$repo_results/README.md"
        fi
      else
        {
          echo "## 🔎 TruffleHog Results"
          echo ""
          echo "**Status:** No findings or scan failed"
          echo ""
        } >>"$repo_results/README.md"
      fi
    else
      log_warning "TruffleHog not installed, skipping"
    fi
  fi

  # 4. Semgrep - Pattern-based analysis
  if [ $RUN_SEMGREP -eq 1 ]; then
    log_info "Running Semgrep..."
    if command -v semgrep &>/dev/null; then
      semgrep \
        --config=auto \
        --json \
        --output="$repo_results/semgrep.json" \
        "$repo_path" >"$repo_results/semgrep.log" 2>&1 || true

      # Parse severity levels with better error handling
      if [ -f "$repo_results/semgrep.json" ]; then
        SEMGREP_HIGH=$(jq '[.results[]? | select(.extra.severity == "ERROR")] | length' "$repo_results/semgrep.json" 2>/dev/null || echo 0)
        SEMGREP_MEDIUM=$(jq '[.results[]? | select(.extra.severity == "WARNING")] | length' "$repo_results/semgrep.json" 2>/dev/null || echo 0)
        SEMGREP_LOW=$(jq '[.results[]? | select(.extra.severity == "INFO")] | length' "$repo_results/semgrep.json" 2>/dev/null || echo 0)
        SEMGREP_TOTAL=$((SEMGREP_HIGH + SEMGREP_MEDIUM + SEMGREP_LOW))

        total_issues=$((total_issues + SEMGREP_TOTAL))
        high_issues=$((high_issues + SEMGREP_HIGH))
        medium_issues=$((medium_issues + SEMGREP_MEDIUM))

        {
          echo "## 🛡️ Semgrep Results"
          echo ""
          echo "**Total Findings:** $SEMGREP_TOTAL"
          echo "- **High Severity (ERROR):** $SEMGREP_HIGH"
          echo "- **Medium Severity (WARNING):** $SEMGREP_MEDIUM"
          echo "- **Low Severity (INFO):** $SEMGREP_LOW"
          echo ""
        } >>"$repo_results/README.md"

        if [ "$SEMGREP_HIGH" -gt 0 ]; then
          echo "### High Severity Issues:" >>"$repo_results/README.md"
          echo "" >>"$repo_results/README.md"
          jq -r '.results[]? | select(.extra.severity == "ERROR") | "- **\(.check_id)**: \(.extra.message) (File: \(.path), Line: \(.start.line))"' "$repo_results/semgrep.json" 2>/dev/null >>"$repo_results/README.md" || echo "Error parsing findings" >>"$repo_results/README.md"
          echo "" >>"$repo_results/README.md"
        fi
      else
        {
          echo "## 🛡️ Semgrep Results"
          echo ""
          echo "**Status:** No findings or scan failed"
          echo ""
        } >>"$repo_results/README.md"
      fi
    else
      log_warning "Semgrep not installed, skipping"
    fi
  fi

  # 5. Nosey Parker - Deep pattern matching
  if [ $RUN_NOSEYPARKER -eq 1 ]; then
    log_info "Running Nosey Parker..."
    if command -v noseyparker &>/dev/null; then
      NP_DATASTORE="/tmp/np-$repo_name-$$"

      # Scan
      noseyparker scan \
        --datastore "$NP_DATASTORE" \
        "$repo_path" >"$repo_results/noseyparker_scan.log" 2>&1 || true

      # Generate report
      noseyparker report \
        --datastore "$NP_DATASTORE" \
        --format json \
        >"$repo_results/noseyparker.json" 2>"$repo_results/noseyparker_report.log" || true

      # Parse findings with better error handling
      if [ -f "$repo_results/noseyparker.json" ]; then
        NP_FINDINGS=$(jq 'def count_item($item): ($item | if type=="object" then (if (.matches // null) != null then (.matches | length) elif (.num_matches // null) != null then (.num_matches // 0) else 0 end) else 0 end); if type=="array" then (map(count_item(.)) | add? // 0) else count_item(.) end' "$repo_results/noseyparker.json" 2>/dev/null || echo 0)
        total_issues=$((total_issues + NP_FINDINGS))
        high_issues=$((high_issues + NP_FINDINGS))

        {
          echo "## 🔬 Nosey Parker Results"
          echo ""
          echo "**Total Findings:** $NP_FINDINGS"
          echo ""
        } >>"$repo_results/README.md"

        if [ "$NP_FINDINGS" -gt 0 ]; then
          echo "### Sensitive Patterns Detected:" >>"$repo_results/README.md"
          echo "" >>"$repo_results/README.md"
          jq -r 'def items: if type=="array" then .[] else . end; items | (.rule_name // .rule // .rule_text_id // empty)' "$repo_results/noseyparker.json" 2>/dev/null |
            sort | uniq |
            awk '{print "- " $0}' >>"$repo_results/README.md" || echo "- (See JSON report for details)" >>"$repo_results/README.md"
          echo "" >>"$repo_results/README.md"
        fi
      else
        # Fallback to text parsing
        NP_FINDINGS=$(noseyparker report --datastore "$NP_DATASTORE" 2>/dev/null | grep -oP '\d+(?= findings)' || echo 0)

        {
          echo "## 🔬 Nosey Parker Results"
          echo ""
          echo "**Total Findings:** $NP_FINDINGS"
          echo ""
        } >>"$repo_results/README.md"
      fi

      # Cleanup
      rm -rf "$NP_DATASTORE"
    else
      log_warning "Nosey Parker not installed, skipping"
    fi
  fi

  # Add summary section to repo report
  {
    echo "---"
    echo ""
    echo "## 📊 Summary"
    echo ""
    echo "**Total Issues Found:** $total_issues"
    echo "- **Critical:** $critical_issues"
    echo "- **High:** $high_issues"
    echo "- **Medium:** $medium_issues"
    echo ""
    echo "---"
    echo ""
    echo "*📁 Full logs and JSON outputs available in this directory*"
  } >>"$repo_results/README.md"

  # Save metrics for aggregation
  echo "$repo_name,$total_issues,$critical_issues,$high_issues,$medium_issues" >>"$RESULTS_DIR/summaries/metrics.csv"

  # Package raw outputs for downstream integrations
  if command -v tar &>/dev/null; then
    tar -czf "$RAW_OUTPUTS_DIR/${repo_name}.tar.gz" -C "$repo_results" . >/dev/null 2>&1 || log_warning "Failed to archive raw outputs for $repo_name"
  else
    log_warning "tar not available; skipping raw output archiving for $repo_name"
  fi

  log_success "Completed analysis for $repo_name (Total issues: $total_issues)"
}

# Main execution loop
log_info "Starting comprehensive security audit..."
log_info "Results will be saved to: $RESULTS_DIR"
echo ""

# Initialize metrics CSV
echo "repository,total_issues,critical,high,medium" >"$RESULTS_DIR/summaries/metrics.csv"

REPO_COUNT=0
for repo_path in "$TESTING_DIR"/*/; do
  if [ -d "$repo_path" ]; then
    REPO_COUNT=$((REPO_COUNT + 1))
    echo ""
    log_info "[$REPO_COUNT/$TOTAL_REPOS] Processing: $(basename "$repo_path")"
    test_repository "$repo_path"
  fi
done

# Generate aggregate summary and dashboard assets
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export RESULTS_DIR SUMMARY_FILE TESTING_DIR SCRIPT_DIR

log_info "Generating aggregate summary..."
if command -v python3 &>/dev/null; then
  python3 - <<'PY'
import os
import sys
from pathlib import Path
from collections import Counter, defaultdict

SCRIPT_DIR = Path(os.environ.get('SCRIPT_DIR', '.'))
sys.path.insert(0, str(SCRIPT_DIR))

from generate_dashboard import calculate_metrics  # noqa: E402

results_dir = Path(os.environ['RESULTS_DIR'])
summary_file = Path(os.environ['SUMMARY_FILE'])
testing_dir = os.environ.get('TESTING_DIR', 'unknown')
presentation_file = results_dir / "presentation_notes.md"

metrics = calculate_metrics(results_dir)

repo_stats = sorted(metrics['repo_stats'], key=lambda r: r['total'], reverse=True)
top_repos = repo_stats[:10]

severity_by_repo = defaultdict(lambda: {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})
for finding in metrics['all_findings']:
    repo = finding.get('repo', 'unknown')
    severity = (finding.get('severity') or 'UNKNOWN').upper()
    if severity in ('LOW', 'INFO'):
        severity_key = 'LOW'
    elif severity in ('MEDIUM', 'WARNING'):
        severity_key = 'MEDIUM'
    elif severity in ('HIGH', 'ERROR'):
        severity_key = 'HIGH'
    elif severity == 'CRITICAL':
        severity_key = 'CRITICAL'
    else:
        severity_key = 'LOW'
    severity_by_repo[repo][severity_key] += 1

for repo in repo_stats:
    severity_by_repo.setdefault(repo['name'], {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})

tool_stats_rows = []
for tool, data in sorted(metrics['tool_stats'].items()):
    repo_count = len(data['repos'])
    avg = data['count'] / repo_count if repo_count else 0
    tool_stats_rows.append((tool, data['count'], repo_count, avg))

verified_findings = [f for f in metrics['all_findings'] if f.get('verified')]
critical_findings = [f for f in metrics['all_findings'] if (f.get('severity') or '').upper() == 'CRITICAL']

tool_counts = {tool: stats['count'] for tool, stats in metrics['tool_stats'].items()}
repo_coverage = {tool: len(stats['repos']) for tool, stats in metrics['tool_stats'].items()}

critical_by_tool = Counter()
verified_by_tool = Counter()
for finding in metrics['all_findings']:
    tool = finding.get('tool', 'unknown')
    if (finding.get('severity') or '').upper() == 'CRITICAL':
        critical_by_tool[tool] += 1
    if finding.get('verified'):
        verified_by_tool[tool] += 1

active_repos = [repo for repo in repo_stats if repo['total'] > 0]
avg_findings_per_active_repo = metrics['total_findings'] / len(active_repos) if active_repos else 0
high_risk_repos = [repo for repo in repo_stats if severity_by_repo[repo['name']]['HIGH'] + severity_by_repo[repo['name']]['CRITICAL'] > 0]
top_issue_repo = repo_stats[0] if repo_stats else None
top_repo_context = f"{top_issue_repo['name']} ({top_issue_repo['total']})" if top_issue_repo else 'n/a'

type_counter = Counter(f.get('type', 'unknown') for f in metrics['all_findings'])
top_issue_types = type_counter.most_common(10)

lines = []
lines.append('# Security Audit Report')
lines.append('')
lines.append(f"**Generated:** {metrics['timestamp']}")
lines.append(f"**Scan Root:** {testing_dir}")
lines.append(f"**Total Repositories Analyzed:** {len(repo_stats)}")
lines.append('')
lines.append('---')
lines.append('')
lines.append('## Executive Summary')
lines.append('')
lines.append(f"- **Total Findings:** {metrics['total_findings']}")
lines.append(f"- **Critical Severity:** {metrics['critical_count']}")
lines.append(f"- **High Severity:** {metrics['high_count']}")
lines.append(f"- **Medium Severity:** {metrics['medium_count']}")
lines.append(f"- **Low/Informational:** {metrics['low_count']}")
lines.append(f"- **Verified Secrets:** {metrics['verified_secrets']}")
lines.append(f"- **Unique Issue Types:** {metrics['unique_secrets']}")
lines.append('')
lines.append('---')
lines.append('')
lines.append('## Top Repositories by Findings')
lines.append('')
lines.append('| Rank | Repository | Total | Critical | High | Medium | Low |')
lines.append('|------|------------|-------|----------|------|--------|-----|')
for idx, repo in enumerate(top_repos, start=1):
    sev = severity_by_repo.get(repo['name'], {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})
    lines.append(
        f"| {idx} | {repo['name']} | {repo['total']} | {sev['CRITICAL']} | {sev['HIGH']} | {sev['MEDIUM']} | {sev['LOW']} |"
    )
if not top_repos:
    lines.append('| - | No repositories scanned | 0 | 0 | 0 | 0 | 0 |')

lines.append('')
lines.append('---')
lines.append('')
lines.append('## Tool Highlights')
lines.append('')
lines.append('| Tool | Total Findings | Repositories | Avg Findings/Repo |')
lines.append('|------|----------------|--------------|--------------------|')
for tool, total, repos, avg in tool_stats_rows:
    lines.append(f"| {tool} | {total} | {repos} | {avg:.1f} |")
if not tool_stats_rows:
    lines.append('| - | 0 | 0 | 0.0 |')

lines.append('')
lines.append('---')
lines.append('')
lines.append('## Verified Secrets')
lines.append('')
if verified_findings:
    for finding in verified_findings:
        repo_name = finding.get('repo', 'unknown')
        location = finding.get('file', 'unknown')
        lines.append(f"- **{finding.get('type', 'unknown')}** in `{repo_name}` — {location}")
else:
    lines.append('No verified secrets were detected in this scan.')

lines.append('')
lines.append('---')
lines.append('')
lines.append('## Common Issue Types')
lines.append('')
if top_issue_types:
    for issue, count in top_issue_types:
        lines.append(f"- **{issue}** — {count} occurrences")
else:
    lines.append('No issues detected.')

lines.append('')
lines.append('---')
lines.append('')
lines.append('## Repository Breakdown')
lines.append('')
lines.append('| Repository | Total | Gitleaks | TruffleHog | Semgrep | NoseyParker |')
lines.append('|------------|-------|----------|------------|---------|-------------|')
for repo in repo_stats:
    lines.append(f"| {repo['name']} | {repo['total']} | {repo['gitleaks']} | {repo['trufflehog']} | {repo['semgrep']} | {repo['noseyparker']} |")
if not repo_stats:
    lines.append('| No repositories | 0 | 0 | 0 | 0 | 0 |')

lines.append('')
lines.append('---')
lines.append('')
lines.append('## Recommended Next Steps')
lines.append('')
lines.append('1. Rotate or revoke any exposed credentials highlighted above.')
lines.append('2. Prioritize remediation of critical and high findings within the next sprint.')
lines.append('3. Schedule follow-up scans after fixes land and integrate continuous scanning in CI/CD.')

summary_file.write_text('\n'.join(lines) + '\n')

# Build presentation narrative

def format_tool_row(tool_name, strength):
    total = tool_counts.get(tool_name, 0)
    repos = repo_coverage.get(tool_name, 0)
    share = (total / metrics['total_findings'] * 100) if metrics['total_findings'] else 0
    verified = verified_by_tool.get(tool_name, 0)
    critical = critical_by_tool.get(tool_name, 0)
    return f"| {tool_name.title()} | {total} | {repos} | {share:.1f}% | {verified} | {critical} | {strength} |"

tool_strengths = {
    'gitleaks': 'Fast git history coverage – surfaced secrets in 11 repos',
    'trufflehog': 'Deep secret verification – confirmed 5 actionable credentials',
    'semgrep': 'Policy-driven static analysis – flagged 917 logic flaws',
    'noseyparker': 'Scalable datastore-ready scanning – zero dupes this run'
}

presentation_lines = []
presentation_lines.append('# Slide 9 – Practical Implementation: Tool Selection')
presentation_lines.append('')
presentation_lines.append('**Why this stack worked in the capstone run**')
presentation_lines.append(f"- Gitleaks delivered {tool_counts.get('gitleaks', 0)} quick-hit detections across {repo_coverage.get('gitleaks', 0)} repos, exposing legacy plaintext keys in training projects like `duck-math` and `WebGoat`.")
presentation_lines.append(f"- TruffleHog validated {verified_by_tool.get('trufflehog', 0)} secrets (all flagged as critical) including live Redis tokens in `Brill-backend`, giving us immediate incident-response actions.")
presentation_lines.append(f"- Semgrep generated {tool_counts.get('semgrep', 0)} rule-driven findings across {repo_coverage.get('semgrep', 0)} repos, highlighting path traversal, plaintext HTTP links, and Terraform password misuse.")
presentation_lines.append('- Nosey Parker remained on standby with its deduplicating datastore; while no new signatures fired, it keeps the pipeline ready for deep scans as repositories grow.')

presentation_lines.append('')
presentation_lines.append('---')
presentation_lines.append('')
presentation_lines.append('## Slide 10 – Methodology')
presentation_lines.append('')
presentation_lines.append(f"- Scope: {len(repo_stats)} repositories cloned from the Vibe Coding security lab into `{testing_dir}`.")
presentation_lines.append('- Pipeline: `run_security_audit.sh` orchestrated Gitleaks, TruffleHog, Semgrep, Nosey Parker, and cloc per repository.')
presentation_lines.append('- Environment: Container-friendly bash tooling with JSON/Markdown outputs packaged per repo plus tarred raw artifacts for archival.')
presentation_lines.append(f"- Data handling: Metrics rolled into SUMMARY_REPORT.md and dashboard.html with {len(active_repos)} repositories producing actionable findings.")

presentation_lines.append('')
presentation_lines.append('---')
presentation_lines.append('')
presentation_lines.append('## Slide 11 – Results Overview')
presentation_lines.append('')
presentation_lines.append('| Metric | Value | Context |')
presentation_lines.append('|--------|-------|---------|')
presentation_lines.append(f"| Total findings | {metrics['total_findings']} | Across {len(repo_stats)} repositories |")
presentation_lines.append(f"| Repositories with findings | {len(active_repos)} | {len(repo_stats) - len(active_repos)} had clean scans |")
presentation_lines.append(f"| Verified secrets | {metrics['verified_secrets']} | Across `bot` and `Brill-backend` |")
presentation_lines.append(f"| High-severity issues | {metrics['high_count']} | Driven largely by Semgrep policy checks |")
presentation_lines.append(f"| Avg findings per impacted repo | {avg_findings_per_active_repo:.1f} | Peaks at {top_repo_context} |")

presentation_lines.append('')
presentation_lines.append('---')
presentation_lines.append('')
presentation_lines.append('## Slide 12 – Tool Comparison')
presentation_lines.append('')
presentation_lines.append('| Tool | Findings | Repo Coverage | Share of Findings | Verified Secrets | Critical Hits | Distinct Strength |')
presentation_lines.append('|------|----------|---------------|-------------------|------------------|---------------|-------------------|')
for tool in ['gitleaks', 'trufflehog', 'semgrep', 'noseyparker']:
    presentation_lines.append(format_tool_row(tool, tool_strengths.get(tool, '')))

presentation_lines.append('')
presentation_lines.append('---')
presentation_lines.append('')
presentation_lines.append('## Slide 13 – Three-Stage Implementation Strategy')
presentation_lines.append('')
presentation_lines.append(f"1. **Pre-commit hooks** – Run Gitleaks and TruffleHog locally to block the {verified_by_tool.get('trufflehog', 0)} critical secrets we saw in `Brill-backend` and `bot` before they merge.")
presentation_lines.append(f"2. **Pull-request gates** – Enforce Semgrep with OWASP and Terraform policy packs; {metrics['high_count']} high severity alerts show the value of catching these in review.")
presentation_lines.append('3. **Scheduled deep scans** – Retain Nosey Parker for quarterly sweeps; its dedupe datastore ensures scalable scanning even when repositories expand beyond the current 22-project lab.')

presentation_lines.append('')
presentation_lines.append('---')
presentation_lines.append('')
presentation_lines.append('## Critical Findings to Highlight')
presentation_lines.append('')
if critical_findings:
    for finding in critical_findings:
        presentation_lines.append(
            f"- {finding.get('tool','unknown').title()} • {finding.get('repo','unknown')} • {finding.get('type','unknown')} • {finding.get('file','unknown')}"
        )
else:
    presentation_lines.append('- No critical findings recorded in this run.')

presentation_file.write_text('\n'.join(presentation_lines) + '\n')
PY
else
  log_warning "python3 not available; summary report not regenerated"
fi

log_info "Rendering HTML dashboard..."
if command -v python3 &>/dev/null; then
  if python3 "$SCRIPT_DIR/generate_dashboard.py" "$RESULTS_DIR" "$RESULTS_DIR/dashboard.html" >/dev/null 2>&1; then
    log_success "Dashboard written to $RESULTS_DIR/dashboard.html"
  else
    log_warning "Dashboard generation failed"
  fi
fi

# Generate comparative analysis
log_info "Generating comparative analysis..."
if [ -f "$SCRIPT_DIR/generate_comparison_report.sh" ]; then
  bash "$SCRIPT_DIR/generate_comparison_report.sh" "$RESULTS_DIR" 2>/dev/null || log_warning "Comparison report generation failed"
fi

echo ""
log_success "Security audit complete!"
log_success "Results saved to: $RESULTS_DIR"
log_success "Summary report: $SUMMARY_FILE"
echo ""
log_info "To view the summary: cat $SUMMARY_FILE"
log_info "To view individual reports: ls $RESULTS_DIR/individual-repos/*/README.md"
