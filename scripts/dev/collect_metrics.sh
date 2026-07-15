#!/usr/bin/env bash
# JMo Security — Weekly Metrics Collection Script
#
# Purpose:
#   Collect adoption metrics from GitHub, PyPI, and Docker Hub for tracking
#   project growth. These are the real, external "in the wild" signals.
#
# Usage:
#   ./scripts/dev/collect_metrics.sh [--date YYYY-MM-DD]
#
# Output:
#   Writes JSON files + a markdown summary to metrics/ (gitignored)
#
# Requirements:
#   - gh (GitHub CLI) authenticated  — uses gh's built-in --jq (no standalone jq)
#   - curl
#   - python3 (or python) — used to parse PyPI/Docker Hub JSON
#
# Example:
#   ./scripts/dev/collect_metrics.sh
#   ./scripts/dev/collect_metrics.sh --date 2025-10-23

set -euo pipefail

# Configuration
REPO_OWNER="jimmy058910"
REPO_NAME="jmo-security-repo"
PYPI_PACKAGE="jmo-security"
DOCKER_REPO="jmogaming/jmo-security"

# Parse command-line arguments
DATE="${1:-$(date +%Y-%m-%d)}"
if [[ $DATE == "--date" ]]; then
  DATE="${2:-$(date +%Y-%m-%d)}"
fi

# Create metrics directory
METRICS_DIR="metrics"
mkdir -p "$METRICS_DIR"

# Python interpreter (used for PyPI/Docker JSON parsing; no standalone jq needed)
PY="$(command -v python3 || command -v python || true)"

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Helper functions
log() {
  echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

error() {
  echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Extract a value from a JSON file using python.
#   json_get <file> <python-expression-on-`d`>
# Example: json_get pypi.json "d['data']['last_week']"
json_get() {
  "$PY" -c "import json,sys
d=json.load(open(sys.argv[1], encoding='utf-8'))
v=$2
print('' if v is None else v)" "$1"
}

# Check dependencies
check_deps() {
  local missing=()

  if ! command -v gh &>/dev/null; then
    missing+=("gh (GitHub CLI)")
  fi

  if ! command -v curl &>/dev/null; then
    missing+=("curl")
  fi

  if [[ -z $PY ]]; then
    missing+=("python3 (or python)")
  fi

  if [[ ${#missing[@]} -gt 0 ]]; then
    error "Missing required dependencies: ${missing[*]}"
    echo ""
    echo "Install with:"
    echo "  macOS:  brew install gh curl python3"
    echo "  Ubuntu: sudo apt-get install gh curl python3"
    exit 1
  fi
}

# Collect GitHub repository stats (uses gh's built-in --jq)
collect_github_repo() {
  log "Collecting GitHub repository stats..."

  local output="$METRICS_DIR/github-repo-$DATE.json"

  if gh api repos/"$REPO_OWNER"/"$REPO_NAME" --jq '{
        stars: .stargazers_count,
        watchers: .watchers_count,
        forks: .forks_count,
        open_issues: .open_issues_count,
        size_kb: .size,
        created_at: .created_at,
        updated_at: .updated_at,
        default_branch: .default_branch,
        topics: .topics
    }' >"$output"; then
    log "✅ Saved to $output"
  else
    error "Failed to collect GitHub repo stats"
    return 1
  fi
}

# Collect GitHub traffic views (last 14 days)
collect_github_traffic() {
  log "Collecting GitHub traffic views (last 14 days)..."

  local output="$METRICS_DIR/github-traffic-$DATE.json"

  if gh api repos/"$REPO_OWNER"/"$REPO_NAME"/traffic/views --jq '{
        total_views: .count,
        unique_visitors: .uniques,
        views_by_day: .views
    }' >"$output"; then
    log "✅ Saved to $output"
  else
    warn "Failed to collect GitHub traffic (requires repo admin access)"
    return 0 # Non-fatal
  fi
}

# Collect GitHub clone statistics (last 14 days)
collect_github_clones() {
  log "Collecting GitHub clone statistics (last 14 days)..."

  local output="$METRICS_DIR/github-clones-$DATE.json"

  if gh api repos/"$REPO_OWNER"/"$REPO_NAME"/traffic/clones --jq '{
        total_clones: .count,
        unique_cloners: .uniques,
        clones_by_day: .clones
    }' >"$output"; then
    log "✅ Saved to $output"
  else
    warn "Failed to collect GitHub clones (requires repo admin access)"
    return 0 # Non-fatal
  fi
}

# Collect PyPI download statistics (curl + python, no jq)
collect_pypi_downloads() {
  log "Collecting PyPI download statistics..."

  local output="$METRICS_DIR/pypi-downloads-$DATE.json"

  if curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 120 \
    "https://pypistats.org/api/packages/$PYPI_PACKAGE/recent" >"$output"; then
    log "✅ Saved to $output"

    local last_week last_month
    last_week=$(json_get "$output" "d['data']['last_week']")
    last_month=$(json_get "$output" "d['data']['last_month']")
    log "   Last week: $last_week downloads | Last month: $last_month downloads"
  else
    error "Failed to collect PyPI stats"
    return 1
  fi
}

# Collect Docker Hub statistics (curl + python, no jq)
collect_docker_hub() {
  log "Collecting Docker Hub statistics..."

  local output="$METRICS_DIR/docker-hub-$DATE.json"
  local raw="$METRICS_DIR/docker-hub-raw-$DATE.json"

  if curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 120 \
    "https://hub.docker.com/v2/repositories/$DOCKER_REPO" >"$raw"; then
    # Reshape to the canonical field set using python
    "$PY" -c "import json,sys
d=json.load(open(sys.argv[1], encoding='utf-8'))
keys=['name','pull_count','star_count','description','last_updated','is_automated']
json.dump({k: d.get(k) for k in keys}, open(sys.argv[2],'w',encoding='utf-8'), indent=2)" "$raw" "$output"
    rm -f "$raw"
    log "✅ Saved to $output"

    local pulls stars
    pulls=$(json_get "$output" "d['pull_count']")
    stars=$(json_get "$output" "d['star_count']")
    log "   Pulls: $pulls | Stars: $stars"
  else
    rm -f "$raw"
    error "Failed to collect Docker Hub stats"
    return 1
  fi
}

# Generate summary report
# shellcheck disable=SC2129  # Multiple heredocs appending to same file is efficient and readable
generate_summary() {
  log "Generating summary report..."

  local summary="$METRICS_DIR/summary-$DATE.md"

  cat >"$summary" <<EOF
# JMo Security — Metrics Summary

**Date:** $DATE
**Generated:** $(date)

---

## GitHub Repository

EOF

  # Add GitHub stats
  if [[ -f "$METRICS_DIR/github-repo-$DATE.json" ]]; then
    cat >>"$summary" <<EOF
- **Stars:** $(json_get "$METRICS_DIR/github-repo-$DATE.json" "d['stars']")
- **Forks:** $(json_get "$METRICS_DIR/github-repo-$DATE.json" "d['forks']")
- **Open Issues:** $(json_get "$METRICS_DIR/github-repo-$DATE.json" "d['open_issues']")

EOF
  fi

  # Add traffic stats
  if [[ -f "$METRICS_DIR/github-traffic-$DATE.json" ]]; then
    cat >>"$summary" <<EOF
**Traffic (Last 14 Days):**
- **Total Views:** $(json_get "$METRICS_DIR/github-traffic-$DATE.json" "d['total_views']")
- **Unique Visitors:** $(json_get "$METRICS_DIR/github-traffic-$DATE.json" "d['unique_visitors']")

EOF
  fi

  # Add clone stats
  if [[ -f "$METRICS_DIR/github-clones-$DATE.json" ]]; then
    cat >>"$summary" <<EOF
**Clones (Last 14 Days):**
- **Total Clones:** $(json_get "$METRICS_DIR/github-clones-$DATE.json" "d['total_clones']")
- **Unique Cloners:** $(json_get "$METRICS_DIR/github-clones-$DATE.json" "d['unique_cloners']")

_Note: clones are dominated by this repo's own CI; treat as an automation-noise metric._

EOF
  fi

  # Add PyPI stats
  if [[ -f "$METRICS_DIR/pypi-downloads-$DATE.json" ]]; then
    cat >>"$summary" <<EOF
---

## PyPI Package

- **Last Week:** $(json_get "$METRICS_DIR/pypi-downloads-$DATE.json" "d['data']['last_week']") downloads
- **Last Month:** $(json_get "$METRICS_DIR/pypi-downloads-$DATE.json" "d['data']['last_month']") downloads

EOF
  fi

  # Add Docker Hub stats
  if [[ -f "$METRICS_DIR/docker-hub-$DATE.json" ]]; then
    cat >>"$summary" <<EOF
---

## Docker Hub

- **Pull Count:** $(json_get "$METRICS_DIR/docker-hub-$DATE.json" "d['pull_count']")
- **Stars:** $(json_get "$METRICS_DIR/docker-hub-$DATE.json" "d['star_count']")
- **Last Updated:** $(json_get "$METRICS_DIR/docker-hub-$DATE.json" "d['last_updated']")

EOF
  fi

  cat >>"$summary" <<EOF
---

**Files:**

\`\`\`
EOF
  ls -lh "$METRICS_DIR"/*"$DATE"* >>"$summary"
  cat >>"$summary" <<EOF
\`\`\`
EOF

  log "✅ Saved to $summary"
}

# Main execution
main() {
  echo ""
  log "🎯 JMo Security — Metrics Collection"
  log "Date: $DATE"
  echo ""

  # Check dependencies
  check_deps

  # Collect metrics (five real external sources)
  collect_github_repo
  collect_github_traffic
  collect_github_clones
  collect_pypi_downloads
  collect_docker_hub

  # Generate summary
  generate_summary

  echo ""
  log "✅ Metrics collection complete!"
  log "View summary: cat $METRICS_DIR/summary-$DATE.md"
  echo ""
}

# Run main function
main "$@"
