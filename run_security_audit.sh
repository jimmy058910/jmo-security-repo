#!/bin/bash
# run_security_audit.sh - Master security testing orchestrator

# Configuration
TESTING_DIR="$HOME/security-testing"
RESULTS_DIR="$HOME/security-results-$(date +%Y%m%d-%H%M%S)"
SUMMARY_FILE="$RESULTS_DIR/SUMMARY_REPORT.md"

# Tool flags (set to 1 to enable)
RUN_CLOC=1
RUN_GITLEAKS=1
RUN_TRUFFLEHOG=1
RUN_SEMGREP=1
RUN_NOSEYPARKER=1

# Create results directory structure
mkdir -p "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR/individual-repos"
mkdir -p "$RESULTS_DIR/tool-comparisons"
mkdir -p "$RESULTS_DIR/raw-outputs"

# Initialize summary report
cat > "$SUMMARY_FILE" << EOF
# Security Audit Report
**Date:** $(date)
**Total Repositories Analyzed:** $(ls -d $TESTING_DIR/*/ | wc -l)

## Executive Summary
EOF

# Function to test individual repository
test_repository() {
    local repo_path=$1
    local repo_name=$(basename "$repo_path")
    local repo_results="$RESULTS_DIR/individual-repos/$repo_name"
    
    mkdir -p "$repo_results"
    
    echo "Testing repository: $repo_name"
    echo "================================="
    
    # Create repo-specific summary
    cat > "$repo_results/README.md" << EOF
# Security Analysis: $repo_name
**Path:** $repo_path
**Analysis Date:** $(date)

## Repository Metrics
EOF
    
    # 1. Code metrics with cloc
    if [ $RUN_CLOC -eq 1 ]; then
        echo "Running cloc..."
        cloc "$repo_path" --json > "$repo_results/cloc.json" 2>/dev/null
        cloc "$repo_path" --quiet >> "$repo_results/README.md"
    fi
    
    # 2. Gitleaks - Fast git history scanning
    if [ $RUN_GITLEAKS -eq 1 ]; then
        echo "Running Gitleaks..."
        gitleaks detect \
            --source "$repo_path" \
            --report-format json \
            --report-path "$repo_results/gitleaks.json" \
            --verbose > "$repo_results/gitleaks.log" 2>&1
        
        # Parse results
        if [ -f "$repo_results/gitleaks.json" ]; then
            GITLEAKS_COUNT=$(jq length "$repo_results/gitleaks.json" 2>/dev/null || echo 0)
            echo "## Gitleaks Results" >> "$repo_results/README.md"
            echo "**Secrets Found:** $GITLEAKS_COUNT" >> "$repo_results/README.md"
        fi
    fi
    
    # 3. TruffleHog - Deep scanning with verification
    if [ $RUN_TRUFFLEHOG -eq 1 ]; then
        echo "Running TruffleHog..."
        trufflehog git file://"$repo_path" \
            --json \
            --no-update \
            > "$repo_results/trufflehog.json" 2> "$repo_results/trufflehog.log"
        
        # Count verified vs unverified
        TRUFFLE_VERIFIED=$(jq '[.[] | select(.verified == true)] | length' "$repo_results/trufflehog.json" 2>/dev/null || echo 0)
        TRUFFLE_TOTAL=$(jq length "$repo_results/trufflehog.json" 2>/dev/null || echo 0)
        
        echo "## TruffleHog Results" >> "$repo_results/README.md"
        echo "**Total Findings:** $TRUFFLE_TOTAL" >> "$repo_results/README.md"
        echo "**Verified Secrets:** $TRUFFLE_VERIFIED" >> "$repo_results/README.md"
    fi
    
    # 4. Semgrep - Pattern-based analysis
    if [ $RUN_SEMGREP -eq 1 ]; then
        echo "Running Semgrep..."
        semgrep \
            --config=auto \
            --json \
            --output="$repo_results/semgrep.json" \
            "$repo_path" > "$repo_results/semgrep.log" 2>&1
        
        # Parse severity levels
        if [ -f "$repo_results/semgrep.json" ]; then
            SEMGREP_HIGH=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' "$repo_results/semgrep.json" 2>/dev/null || echo 0)
            SEMGREP_MEDIUM=$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' "$repo_results/semgrep.json" 2>/dev/null || echo 0)
            
            echo "## Semgrep Results" >> "$repo_results/README.md"
            echo "**High Severity:** $SEMGREP_HIGH" >> "$repo_results/README.md"
            echo "**Medium Severity:** $SEMGREP_MEDIUM" >> "$repo_results/README.md"
        fi
    fi
    
    # 5. Nosey Parker - Deep pattern matching
    if [ $RUN_NOSEYPARKER -eq 1 ]; then
        echo "Running Nosey Parker..."
        NP_DATASTORE="/tmp/np-$repo_name-$$"
        
        # Scan
        noseyparker scan \
            --datastore "$NP_DATASTORE" \
            "$repo_path" > "$repo_results/noseyparker_scan.log" 2>&1
        
        # Generate report
        noseyparker report \
            --datastore "$NP_DATASTORE" \
            --format json \
            > "$repo_results/noseyparker.json" 2>&1
        
        # Parse findings
        NP_FINDINGS=$(noseyparker report --datastore "$NP_DATASTORE" 2>/dev/null | grep -oP '\d+(?= findings)' || echo 0)
        
        echo "## Nosey Parker Results" >> "$repo_results/README.md"
        echo "**Total Findings:** $NP_FINDINGS" >> "$repo_results/README.md"
        
        # Cleanup
        rm -rf "$NP_DATASTORE"
    fi
    
    echo "" >> "$repo_results/README.md"
    echo "---" >> "$repo_results/README.md"
    echo "*Full logs and JSON outputs available in this directory*" >> "$repo_results/README.md"
}

# Main execution loop
echo "Starting comprehensive security audit..."
echo "Results will be saved to: $RESULTS_DIR"
echo ""

REPO_COUNT=0
for repo_path in "$TESTING_DIR"/*/; do
    if [ -d "$repo_path" ]; then
        REPO_COUNT=$((REPO_COUNT + 1))
        echo "[$REPO_COUNT] Processing: $(basename "$repo_path")"
        test_repository "$repo_path"
        echo ""
    fi
done

# Generate comparative analysis
echo "Generating comparative analysis..."
./generate_comparison_report.sh "$RESULTS_DIR"

echo "✅ Security audit complete!"
echo "📊 Results saved to: $RESULTS_DIR"
echo "📈 Summary report: $SUMMARY_FILE"
