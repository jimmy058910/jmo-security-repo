#!/bin/bash
# generate_comparison_report.sh - Generate tool comparison metrics

set -euo pipefail

RESULTS_DIR="${1-}"

if [ -z "$RESULTS_DIR" ] || [ ! -d "$RESULTS_DIR" ]; then
  echo "Error: Invalid results directory"
  echo "Usage: $0 <results_directory>"
  exit 1
fi

COMPARISON_FILE="$RESULTS_DIR/tool-comparisons/comparison.md"

# Create directory if it doesn't exist
mkdir -p "$RESULTS_DIR/tool-comparisons"

cat >"$COMPARISON_FILE" <<'EOF'
# Tool Performance Comparison

## Detection Metrics

| Tool | Total Findings | Repos Scanned | Avg Findings/Repo | Key Strength |
|------|---------------|---------------|-------------------|--------------|
EOF

# Parse each tool's results across all repos
for tool in trufflehog semgrep noseyparker; do
  TOTAL=0
  REPOS=0

  for repo_result in "$RESULTS_DIR"/individual-repos/*/; do
    if [ -f "$repo_result/${tool}.json" ]; then
      # Count findings based on tool with proper error handling
      case $tool in
      trufflehog)
        # TruffleHog outputs newline-delimited JSON (NDJSON)
        FINDINGS=$(jq -s 'length' "$repo_result/${tool}.json" 2>/dev/null || echo 0)
        ;;
      semgrep)
        # Correctly count total results, not length of each result object
        FINDINGS=$(jq '.results | length' "$repo_result/${tool}.json" 2>/dev/null || echo 0)
        ;;
      noseyparker)
        FINDINGS=$(jq 'if type=="object" then (.matches // [] | length) else 0 end' "$repo_result/${tool}.json" 2>/dev/null || echo 0)
        ;;
      esac

      # Ensure FINDINGS is a valid number
      if ! [[ $FINDINGS =~ ^[0-9]+$ ]]; then
        FINDINGS=0
      fi

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

  echo "| $tool | $TOTAL | $REPOS | $AVG | $STRENGTH |" >>"$COMPARISON_FILE"
done

cat >>"$COMPARISON_FILE" <<'EOF'

---

## Tool Capabilities Matrix

| Tool | Secret Detection | Vulnerability Detection | Git History | Verification | Speed |
|------|-----------------|------------------------|-------------|--------------|-------|
| TruffleHog | ✅ Excellent | ❌ No | ✅ Yes | ✅ Yes | 🐌 Slow |
| Semgrep | ⚠️ Limited | ✅ Excellent | ❌ No | ❌ No | ⚡ Fast |
| Nosey Parker | ✅ Excellent | ❌ No | ✅ Yes | ❌ No | 🐌 Slow |

---

## Three-Stage Implementation Strategy

### Stage 1: Pre-commit Hooks (Recommended: TruffleHog)
**Purpose**: Prevent secrets from entering version control

**Advantages**:
- Only verified secrets are reported, so the hook rarely blocks on a false positive
- Catches secrets before commit
- Scoped to the staged range, so the cost stays proportional

**Setup**:
```bash
# Scan only what is about to be committed, verified findings only
trufflehog git file://. --since-commit HEAD --results=verified --fail
```

### Stage 2: CI/CD Pipeline (Recommended: TruffleHog + Semgrep)
**Purpose**: Automated scanning on every PR/commit

**Advantages**:
- Comprehensive scanning without blocking developers
- Pattern-based vulnerability detection
- Catches issues missed in pre-commit

**Setup**:
```yaml
# .github/workflows/security.yml
- name: TruffleHog Scan
  uses: trufflesecurity/trufflehog@main
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
- **Pre-commit**: TruffleHog
- **CI/CD**: TruffleHog + Semgrep
- **Periodic**: Monthly full scan

### Medium Repositories (1000-10000 LOC)
- **Pre-commit**: TruffleHog
- **CI/CD**: TruffleHog + Semgrep
- **Periodic**: Weekly TruffleHog + Nosey Parker

### Large Repositories (> 10000 LOC)
- **Pre-commit**: TruffleHog (staged range only)
- **CI/CD**: TruffleHog + Semgrep (incremental)
- **Periodic**: Bi-weekly comprehensive scan with all tools

---

## Tool Selection Guide

**Choose TruffleHog when**:
- Secret verification is essential
- Dealing with potential false positives
- Deep historical analysis needed
- Integrating into pre-commit hooks

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
