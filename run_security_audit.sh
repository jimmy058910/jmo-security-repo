#!/bin/bash
# run_security_audit.sh - Master security testing orchestrator

set -e  # Exit on error
set -o pipefail  # Exit on pipe failure

# Configuration
TESTING_DIR="${1:-$HOME/security-testing}"
RESULTS_DIR="${2:-$HOME/security-results-$(date +%Y%m%d-%H%M%S)}"
SUMMARY_FILE="$RESULTS_DIR/SUMMARY_REPORT.md"

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
mkdir -p "$RESULTS_DIR/raw-outputs"
mkdir -p "$RESULTS_DIR/summaries"

log_success "Created results directory: $RESULTS_DIR"

# Count repositories
TOTAL_REPOS=$(find "$TESTING_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)

# Initialize summary report
cat > "$SUMMARY_FILE" << EOF
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
    local repo_name=$(basename "$repo_path")
    local repo_results="$RESULTS_DIR/individual-repos/$repo_name"
    
    mkdir -p "$repo_results"
    
    log_info "Testing repository: $repo_name"
    echo "================================="
    
    # Create repo-specific summary
    cat > "$repo_results/README.md" << EOF
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
        if command -v cloc &> /dev/null; then
            cloc "$repo_path" --json > "$repo_results/cloc.json" 2>/dev/null || log_warning "cloc failed for $repo_name"
            cloc "$repo_path" --quiet >> "$repo_results/README.md" 2>/dev/null || echo "cloc output not available" >> "$repo_results/README.md"
            echo "" >> "$repo_results/README.md"
        else
            log_warning "cloc not installed, skipping"
        fi
    fi
    
    # 2. Gitleaks - Fast git history scanning
    if [ $RUN_GITLEAKS -eq 1 ]; then
        log_info "Running Gitleaks..."
        if command -v gitleaks &> /dev/null; then
            gitleaks detect \
                --source "$repo_path" \
                --report-format json \
                --report-path "$repo_results/gitleaks.json" \
                --verbose > "$repo_results/gitleaks.log" 2>&1 || true
            
            # Parse results with better error handling
            if [ -f "$repo_results/gitleaks.json" ]; then
                GITLEAKS_COUNT=$(jq 'if type=="array" then length else 0 end' "$repo_results/gitleaks.json" 2>/dev/null || echo 0)
                total_issues=$((total_issues + GITLEAKS_COUNT))
                high_issues=$((high_issues + GITLEAKS_COUNT))
                
                echo "## 🔍 Gitleaks Results" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
                echo "**Secrets Found:** $GITLEAKS_COUNT" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
                
                if [ "$GITLEAKS_COUNT" -gt 0 ]; then
                    echo "### Findings Details:" >> "$repo_results/README.md"
                    echo "" >> "$repo_results/README.md"
                    jq -r '.[] | "- **\(.RuleID)**: \(.Description) (File: \(.File), Line: \(.StartLine))"' "$repo_results/gitleaks.json" 2>/dev/null >> "$repo_results/README.md" || echo "Error parsing findings" >> "$repo_results/README.md"
                    echo "" >> "$repo_results/README.md"
                fi
            else
                log_warning "Gitleaks JSON output not found for $repo_name"
                echo "## 🔍 Gitleaks Results" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
                echo "**Status:** No findings or scan failed" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
            fi
        else
            log_warning "Gitleaks not installed, skipping"
        fi
    fi
    
    # 3. TruffleHog - Deep scanning with verification
    if [ $RUN_TRUFFLEHOG -eq 1 ]; then
        log_info "Running TruffleHog..."
        if command -v trufflehog &> /dev/null; then
            trufflehog git file://"$repo_path" \
                --json \
                --no-update \
                > "$repo_results/trufflehog.json" 2> "$repo_results/trufflehog.log" || true
            
            # Count verified vs unverified with better parsing
            if [ -f "$repo_results/trufflehog.json" ]; then
                TRUFFLE_VERIFIED=$(jq -s '[.[] | select(.verified == true)] | length' "$repo_results/trufflehog.json" 2>/dev/null || echo 0)
                TRUFFLE_TOTAL=$(jq -s 'length' "$repo_results/trufflehog.json" 2>/dev/null || echo 0)
                total_issues=$((total_issues + TRUFFLE_VERIFIED))
                critical_issues=$((critical_issues + TRUFFLE_VERIFIED))
                medium_issues=$((medium_issues + TRUFFLE_TOTAL - TRUFFLE_VERIFIED))
                
                echo "## 🔎 TruffleHog Results" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
                echo "**Total Findings:** $TRUFFLE_TOTAL" >> "$repo_results/README.md"
                echo "**Verified Secrets:** $TRUFFLE_VERIFIED" >> "$repo_results/README.md"
                echo "**Unverified:** $((TRUFFLE_TOTAL - TRUFFLE_VERIFIED))" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
                
                if [ "$TRUFFLE_VERIFIED" -gt 0 ]; then
                    echo "### ⚠️ Verified Secrets (CRITICAL):" >> "$repo_results/README.md"
                    echo "" >> "$repo_results/README.md"
                    jq -r 'select(.verified == true) | "- **\(.DetectorName // "Unknown")**: Found in \(.SourceMetadata.Data.Filesystem.file // "unknown file")"' "$repo_results/trufflehog.json" 2>/dev/null >> "$repo_results/README.md" || echo "Error parsing findings" >> "$repo_results/README.md"
                    echo "" >> "$repo_results/README.md"
                fi
            else
                echo "## 🔎 TruffleHog Results" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
                echo "**Status:** No findings or scan failed" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
            fi
        else
            log_warning "TruffleHog not installed, skipping"
        fi
    fi
    
    # 4. Semgrep - Pattern-based analysis
    if [ $RUN_SEMGREP -eq 1 ]; then
        log_info "Running Semgrep..."
        if command -v semgrep &> /dev/null; then
            semgrep \
                --config=auto \
                --json \
                --output="$repo_results/semgrep.json" \
                "$repo_path" > "$repo_results/semgrep.log" 2>&1 || true
            
            # Parse severity levels with better error handling
            if [ -f "$repo_results/semgrep.json" ]; then
                SEMGREP_HIGH=$(jq '[.results[]? | select(.extra.severity == "ERROR")] | length' "$repo_results/semgrep.json" 2>/dev/null || echo 0)
                SEMGREP_MEDIUM=$(jq '[.results[]? | select(.extra.severity == "WARNING")] | length' "$repo_results/semgrep.json" 2>/dev/null || echo 0)
                SEMGREP_LOW=$(jq '[.results[]? | select(.extra.severity == "INFO")] | length' "$repo_results/semgrep.json" 2>/dev/null || echo 0)
                SEMGREP_TOTAL=$((SEMGREP_HIGH + SEMGREP_MEDIUM + SEMGREP_LOW))
                
                total_issues=$((total_issues + SEMGREP_TOTAL))
                high_issues=$((high_issues + SEMGREP_HIGH))
                medium_issues=$((medium_issues + SEMGREP_MEDIUM))
                
                echo "## 🛡️ Semgrep Results" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
                echo "**Total Findings:** $SEMGREP_TOTAL" >> "$repo_results/README.md"
                echo "- **High Severity (ERROR):** $SEMGREP_HIGH" >> "$repo_results/README.md"
                echo "- **Medium Severity (WARNING):** $SEMGREP_MEDIUM" >> "$repo_results/README.md"
                echo "- **Low Severity (INFO):** $SEMGREP_LOW" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
                
                if [ "$SEMGREP_HIGH" -gt 0 ]; then
                    echo "### High Severity Issues:" >> "$repo_results/README.md"
                    echo "" >> "$repo_results/README.md"
                    jq -r '.results[]? | select(.extra.severity == "ERROR") | "- **\(.check_id)**: \(.extra.message) (File: \(.path), Line: \(.start.line))"' "$repo_results/semgrep.json" 2>/dev/null >> "$repo_results/README.md" || echo "Error parsing findings" >> "$repo_results/README.md"
                    echo "" >> "$repo_results/README.md"
                fi
            else
                echo "## 🛡️ Semgrep Results" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
                echo "**Status:** No findings or scan failed" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
            fi
        else
            log_warning "Semgrep not installed, skipping"
        fi
    fi
    
    # 5. Nosey Parker - Deep pattern matching
    if [ $RUN_NOSEYPARKER -eq 1 ]; then
        log_info "Running Nosey Parker..."
        if command -v noseyparker &> /dev/null; then
            NP_DATASTORE="/tmp/np-$repo_name-$$"
            
            # Scan
            noseyparker scan \
                --datastore "$NP_DATASTORE" \
                "$repo_path" > "$repo_results/noseyparker_scan.log" 2>&1 || true
            
            # Generate report
            noseyparker report \
                --datastore "$NP_DATASTORE" \
                --format json \
                > "$repo_results/noseyparker.json" 2>&1 || true
            
            # Parse findings with better error handling
            if [ -f "$repo_results/noseyparker.json" ]; then
                NP_FINDINGS=$(jq 'if type=="object" then (.matches // [] | length) else 0 end' "$repo_results/noseyparker.json" 2>/dev/null || echo 0)
                total_issues=$((total_issues + NP_FINDINGS))
                medium_issues=$((medium_issues + NP_FINDINGS))
                
                echo "## 🔬 Nosey Parker Results" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
                echo "**Total Findings:** $NP_FINDINGS" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
            else
                # Fallback to text parsing
                NP_FINDINGS=$(noseyparker report --datastore "$NP_DATASTORE" 2>/dev/null | grep -oP '\d+(?= findings)' || echo 0)
                
                echo "## 🔬 Nosey Parker Results" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
                echo "**Total Findings:** $NP_FINDINGS" >> "$repo_results/README.md"
                echo "" >> "$repo_results/README.md"
            fi
            
            # Cleanup
            rm -rf "$NP_DATASTORE"
        else
            log_warning "Nosey Parker not installed, skipping"
        fi
    fi
    
    # Add summary section to repo report
    echo "---" >> "$repo_results/README.md"
    echo "" >> "$repo_results/README.md"
    echo "## 📊 Summary" >> "$repo_results/README.md"
    echo "" >> "$repo_results/README.md"
    echo "**Total Issues Found:** $total_issues" >> "$repo_results/README.md"
    echo "- **Critical:** $critical_issues" >> "$repo_results/README.md"
    echo "- **High:** $high_issues" >> "$repo_results/README.md"
    echo "- **Medium:** $medium_issues" >> "$repo_results/README.md"
    echo "" >> "$repo_results/README.md"
    echo "---" >> "$repo_results/README.md"
    echo "" >> "$repo_results/README.md"
    echo "*📁 Full logs and JSON outputs available in this directory*" >> "$repo_results/README.md"
    
    # Save metrics for aggregation
    echo "$repo_name,$total_issues,$critical_issues,$high_issues,$medium_issues" >> "$RESULTS_DIR/summaries/metrics.csv"
    
    log_success "Completed analysis for $repo_name (Total issues: $total_issues)"
}

# Main execution loop
log_info "Starting comprehensive security audit..."
log_info "Results will be saved to: $RESULTS_DIR"
echo ""

# Initialize metrics CSV
echo "repository,total_issues,critical,high,medium" > "$RESULTS_DIR/summaries/metrics.csv"

REPO_COUNT=0
for repo_path in "$TESTING_DIR"/*/; do
    if [ -d "$repo_path" ]; then
        REPO_COUNT=$((REPO_COUNT + 1))
        echo ""
        log_info "[$REPO_COUNT/$TOTAL_REPOS] Processing: $(basename "$repo_path")"
        test_repository "$repo_path"
    fi
done

# Generate aggregate summary
log_info "Generating aggregate summary..."

# Calculate totals from CSV
TOTAL_ISSUES=$(awk -F',' 'NR>1 {sum+=$2} END {print sum}' "$RESULTS_DIR/summaries/metrics.csv")
TOTAL_CRITICAL=$(awk -F',' 'NR>1 {sum+=$3} END {print sum}' "$RESULTS_DIR/summaries/metrics.csv")
TOTAL_HIGH=$(awk -F',' 'NR>1 {sum+=$4} END {print sum}' "$RESULTS_DIR/summaries/metrics.csv")
TOTAL_MEDIUM=$(awk -F',' 'NR>1 {sum+=$5} END {print sum}' "$RESULTS_DIR/summaries/metrics.csv")

# Add aggregate results to summary
cat >> "$SUMMARY_FILE" << EOF
## Aggregate Results

### Overall Statistics
- **Total Issues Found:** $TOTAL_ISSUES
- **Critical Issues:** $TOTAL_CRITICAL
- **High Severity Issues:** $TOTAL_HIGH
- **Medium Severity Issues:** $TOTAL_MEDIUM

### Repository Breakdown

| Repository | Total Issues | Critical | High | Medium |
|------------|--------------|----------|------|--------|
EOF

# Add repository rows from CSV
awk -F',' 'NR>1 {printf "| %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5}' "$RESULTS_DIR/summaries/metrics.csv" >> "$SUMMARY_FILE"

cat >> "$SUMMARY_FILE" << EOF

---

## Recommendations

### Critical Actions Required:
- Review all **$TOTAL_CRITICAL critical** issues immediately
- Verified secrets should be rotated/revoked urgently

### High Priority:
- Address **$TOTAL_HIGH high severity** issues in next sprint
- Implement secret scanning in CI/CD pipeline

### Medium Priority:
- Plan remediation for **$TOTAL_MEDIUM medium severity** issues
- Update security policies and developer training

---

## Next Steps

1. **Immediate**: Review critical and verified secrets
2. **Short-term**: Fix high severity vulnerabilities
3. **Long-term**: Implement preventive measures and automation

---

*Generated by Security Audit Tool - $(date)*
EOF

# Generate comparative analysis
log_info "Generating comparative analysis..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
