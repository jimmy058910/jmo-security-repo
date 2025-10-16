#!/usr/bin/env bash
# Quick GitLab.com scanning validation for v0.6.0 release
# Usage: bash scripts/dev/test_gitlab_manual.sh

set -e

echo "=========================================="
echo "GitLab Scanning Manual Test"
echo "=========================================="
echo ""

# Check if GITLAB_TOKEN is set
if [[ -z "$GITLAB_TOKEN" ]]; then
  echo "❌ ERROR: GITLAB_TOKEN not set"
  echo ""
  echo "Please set your GitLab personal access token:"
  echo "  1. Go to https://gitlab.com/-/profile/personal_access_tokens"
  echo "  2. Create token with scopes: read_api, read_repository"
  echo "  3. Export token: export GITLAB_TOKEN='glpat-your-token-here'"
  echo ""
  exit 1
fi

echo "✅ GITLAB_TOKEN detected (${#GITLAB_TOKEN} chars)"
echo ""

# Prompt for GitLab repo
if [[ -z "$GITLAB_REPO" ]]; then
  echo "Enter GitLab repository (format: username/repo-name):"
  echo "Example: jimmy058910/test-repo"
  read -r GITLAB_REPO
  echo ""
fi

# Validate input
if [[ ! "$GITLAB_REPO" =~ ^[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$ ]]; then
  echo "❌ ERROR: Invalid GitLab repo format"
  echo "Expected: username/repo-name"
  echo "Got: $GITLAB_REPO"
  exit 1
fi

echo "Testing GitLab scanning with:"
echo "  - URL: https://gitlab.com"
echo "  - Repo: $GITLAB_REPO"
echo "  - Token: ${GITLAB_TOKEN:0:10}...${GITLAB_TOKEN: -4}"
echo ""

# Create results directory
RESULTS_DIR="/tmp/jmo-gitlab-test-$(date +%s)"
mkdir -p "$RESULTS_DIR"

echo "Results will be saved to: $RESULTS_DIR"
echo ""
echo "Running scan (this may take 1-2 minutes)..."
echo "=========================================="
echo ""

# Run GitLab scan
if jmo ci \
  --gitlab-url https://gitlab.com \
  --gitlab-token "$GITLAB_TOKEN" \
  --gitlab-repo "$GITLAB_REPO" \
  --results-dir "$RESULTS_DIR" \
  --profile-name fast \
  --human-logs \
  --allow-missing-tools; then

  echo ""
  echo "=========================================="
  echo "✅ GitLab scan completed successfully!"
  echo "=========================================="
  echo ""

  # Validate outputs
  if [[ -f "$RESULTS_DIR/summaries/findings.json" ]]; then
    FINDINGS_COUNT=$(jq 'length' "$RESULTS_DIR/summaries/findings.json" 2>/dev/null || echo "0")
    echo "✅ findings.json generated: $FINDINGS_COUNT findings"
  else
    echo "⚠️  findings.json not found"
  fi

  if [[ -f "$RESULTS_DIR/summaries/SUMMARY.md" ]]; then
    echo "✅ SUMMARY.md generated"
  fi

  if [[ -f "$RESULTS_DIR/summaries/dashboard.html" ]]; then
    echo "✅ dashboard.html generated"
  fi

  echo ""
  echo "View results:"
  echo "  - JSON: $RESULTS_DIR/summaries/findings.json"
  echo "  - Markdown: $RESULTS_DIR/summaries/SUMMARY.md"
  echo "  - Dashboard: $RESULTS_DIR/summaries/dashboard.html"
  echo ""
  echo "=========================================="
  echo "✅ GitLab scanning VALIDATED for v0.6.0"
  echo "=========================================="

else
  echo ""
  echo "=========================================="
  echo "❌ GitLab scan FAILED"
  echo "=========================================="
  echo ""
  echo "Common issues:"
  echo "  - Invalid token (check scopes: read_api, read_repository)"
  echo "  - Repository not accessible (check permissions)"
  echo "  - Network connectivity issues"
  echo ""
  exit 1
fi
