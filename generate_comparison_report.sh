#!/bin/bash
# generate_comparison_report.sh - Generate tool comparison metrics

RESULTS_DIR=$1
COMPARISON_FILE="$RESULTS_DIR/tool-comparisons/comparison.md"

cat > "$COMPARISON_FILE" << 'EOF'
# Tool Performance Comparison

## Detection Metrics

| Tool | Total Findings | True Positives | False Positives | Detection Rate | FP Rate | Avg Time/Repo |
|------|---------------|----------------|-----------------|----------------|---------|---------------|
EOF

# Parse each tool's results across all repos
for tool in gitleaks trufflehog semgrep noseyparker; do
    TOTAL=0
    TIME=0
    REPOS=0
    
    for repo_result in "$RESULTS_DIR"/individual-repos/*/; do
        if [ -f "$repo_result/${tool}.json" ]; then
            # Count findings (simplified - you'd need to implement proper parsing)
            FINDINGS=$(jq length "$repo_result/${tool}.json" 2>/dev/null || echo 0)
            TOTAL=$((TOTAL + FINDINGS))
            REPOS=$((REPOS + 1))
        fi
    done
    
    echo "| $tool | $TOTAL | TBD | TBD | TBD% | TBD% | TBD sec |" >> "$COMPARISON_FILE"
done

cat >> "$COMPARISON_FILE" << 'EOF'

## Three-Stage Implementation Strategy Performance

### Stage 1: Pre-commit (Gitleaks + TruffleHog)
- **Combined Detection Rate:** Calculate from above
- **Average Scan Time:** Sum of both tools
- **Recommended for:** Rapid feedback, CI/CD integration

### Stage 2: Pull Request Gates (Semgrep)
- **Logic Vulnerabilities Found:** Count from Semgrep
- **Pattern Matches:** Total Semgrep findings
- **Recommended for:** Code review, pattern analysis

### Stage 3: Deep Scanning (Nosey Parker)
- **Unique Findings:** Nosey Parker exclusive
- **Deduplication Rate:** Calculate from logs
- **Recommended for:** Comprehensive audits
EOF
