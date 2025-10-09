#!/bin/bash
# generate_comparison_report.sh - Generate tool comparison metrics

RESULTS_DIR=$1

if [ -z "$RESULTS_DIR" ] || [ ! -d "$RESULTS_DIR" ]; then
    echo "Error: Invalid results directory"
    echo "Usage: $0 <results_directory>"
    exit 1
fi

COMPARISON_FILE="$RESULTS_DIR/tool-comparisons/comparison.md"

cat > "$COMPARISON_FILE" << 'EOF'
# Tool Performance Comparison

## Detection Metrics

| Tool | Total Findings | Repos Scanned | Avg Findings/Repo | Key Strength |
|------|---------------|---------------|-------------------|--------------|
EOF

# Parse each tool's results across all repos
for tool in gitleaks trufflehog semgrep noseyparker; do
    TOTAL=0
    REPOS=0
    
    for repo_result in "$RESULTS_DIR"/individual-repos/*/; do
        if [ -f "$repo_result/${tool}.json" ]; then
            # Count findings based on tool
            case $tool in
                gitleaks)
                    FINDINGS=$(jq 'if type=="array" then length else 0 end' "$repo_result/${tool}.json" 2>/dev/null || echo 0)
                    ;;
                trufflehog)
                    FINDINGS=$(jq -s 'length' "$repo_result/${tool}.json" 2>/dev/null || echo 0)
                    ;;
                semgrep)
                    FINDINGS=$(jq '.results[]? | length' "$repo_result/${tool}.json" 2>/dev/null || echo 0)
                    ;;
                noseyparker)
                    FINDINGS=$(jq 'if type=="object" then (.matches // [] | length) else 0 end' "$repo_result/${tool}.json" 2>/dev/null || echo 0)
                    ;;
            esac
            TOTAL=$((TOTAL + FINDINGS))
            REPOS=$((REPOS + 1))
        fi
    done
    
    if [ $REPOS -gt 0 ]; then
        AVG=$((TOTAL / REPOS))
    else
        AVG=0
    fi
    
    # Tool descriptions
    case $tool in
        gitleaks)
            STRENGTH="Fast git history scanning"
            ;;
        trufflehog)
            STRENGTH="Secret verification"
            ;;
        semgrep)
            STRENGTH="Pattern-based code analysis"
            ;;
        noseyparker)
            STRENGTH="Deep pattern matching"
            ;;
    esac
    
    echo "| $tool | $TOTAL | $REPOS | $AVG | $STRENGTH |" >> "$COMPARISON_FILE"
done

cat >> "$COMPARISON_FILE" << 'EOF'

---

## Tool Capabilities Matrix

| Tool | Secret Detection | Vulnerability Detection | Git History | Verification | Speed |
|------|-----------------|------------------------|-------------|--------------|-------|
| Gitleaks | ✅ Excellent | ❌ No | ✅ Yes | ❌ No | ⚡ Fast |
| TruffleHog | ✅ Excellent | ❌ No | ✅ Yes | ✅ Yes | 🐌 Slow |
| Semgrep | ⚠️ Limited | ✅ Excellent | ❌ No | ❌ No | ⚡ Fast |
| Nosey Parker | ✅ Excellent | ❌ No | ✅ Yes | ❌ No | 🐌 Slow |

---

## Three-Stage Implementation Strategy

### Stage 1: Pre-commit Hooks (Recommended: Gitleaks)
**Purpose**: Prevent secrets from entering version control

**Advantages**:
- Fast execution (suitable for developer workflow)
- Catches secrets before commit
- Minimal performance impact

**Setup**:
```bash
# Install pre-commit hook
gitleaks protect --staged
```

### Stage 2: CI/CD Pipeline (Recommended: Gitleaks + Semgrep)
**Purpose**: Automated scanning on every PR/commit

**Advantages**:
- Comprehensive scanning without blocking developers
- Pattern-based vulnerability detection
- Catches issues missed in pre-commit

**Setup**:
```yaml
# .github/workflows/security.yml
- name: Gitleaks Scan
  uses: gitleaks/gitleaks-action@v2
- name: Semgrep Scan
  uses: returntocorp/semgrep-action@v1
```

### Stage 3: Deep Periodic Audits (Recommended: All Tools)
**Purpose**: Comprehensive security assessment

**Advantages**:
- Deep historical analysis
- Secret verification (TruffleHog)
- Multi-tool cross-validation

**Frequency**: 
- Weekly for active development
- Monthly for maintenance mode

---

## Recommendations by Repository Size

### Small Repositories (< 1000 LOC)
- **Pre-commit**: Gitleaks
- **CI/CD**: Gitleaks + Semgrep
- **Periodic**: Monthly full scan

### Medium Repositories (1000-10000 LOC)
- **Pre-commit**: Gitleaks
- **CI/CD**: Gitleaks + Semgrep
- **Periodic**: Weekly TruffleHog + Nosey Parker

### Large Repositories (> 10000 LOC)
- **Pre-commit**: Gitleaks (fast mode)
- **CI/CD**: Gitleaks + Semgrep (incremental)
- **Periodic**: Bi-weekly comprehensive scan with all tools

---

## Tool Selection Guide

**Choose Gitleaks when**:
- Speed is critical
- Integrating into pre-commit hooks
- Git history scanning is primary concern

**Choose TruffleHog when**:
- Secret verification is essential
- Dealing with potential false positives
- Deep historical analysis needed

**Choose Semgrep when**:
- Looking for code vulnerabilities
- Pattern-based security rules needed
- Language-specific security checks required

**Choose Nosey Parker when**:
- Maximum coverage desired
- Deep pattern matching needed
- Complementing other tools

---

*Report generated: $(date)*
EOF
