#!/usr/bin/env bash
# JMo Security — Weekly Metrics Collection Script
#
# Purpose:
#   Collect metrics from GitHub, PyPI, Docker Hub, and telemetry systems
#   for tracking project growth and adoption.
#
# Usage:
#   ./scripts/dev/collect_metrics.sh [--date YYYY-MM-DD]
#
# Output:
#   Writes JSON files to metrics/ directory (gitignored)
#
# Requirements:
#   - gh (GitHub CLI) authenticated
#   - curl, jq
#   - Environment variables (optional):
#     - JMO_TELEMETRY_GIST_ID (for telemetry collection)
#
# Example:
#   # Collect today's metrics
#   ./scripts/dev/collect_metrics.sh
#
#   # Collect metrics for specific date
#   ./scripts/dev/collect_metrics.sh --date 2025-10-23

set -euo pipefail

# Configuration
REPO_OWNER="jimmy058910"
REPO_NAME="jmo-security-repo"
PYPI_PACKAGE="jmo-security"
DOCKER_REPO="jmogaming/jmo-security"
GIST_ID="${JMO_TELEMETRY_GIST_ID:-fc897ef9a7f7ed40d001410fa369a1e1}"

# Parse command-line arguments
DATE="${1:-$(date +%Y-%m-%d)}"
if [[ "$DATE" == "--date" ]]; then
    DATE="${2:-$(date +%Y-%m-%d)}"
fi

# Create metrics directory
METRICS_DIR="metrics"
mkdir -p "$METRICS_DIR"

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

# Check dependencies
check_deps() {
    local missing=()

    if ! command -v gh &> /dev/null; then
        missing+=("gh (GitHub CLI)")
    fi

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if ! command -v jq &> /dev/null; then
        missing+=("jq")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required dependencies: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  macOS:  brew install gh curl jq"
        echo "  Ubuntu: sudo apt-get install gh curl jq"
        exit 1
    fi
}

# Collect GitHub repository stats
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
    }' > "$output"; then
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
    }' > "$output"; then
        log "✅ Saved to $output"
    else
        warn "Failed to collect GitHub traffic (requires repo admin access)"
        return 0  # Non-fatal
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
    }' > "$output"; then
        log "✅ Saved to $output"
    else
        warn "Failed to collect GitHub clones (requires repo admin access)"
        return 0  # Non-fatal
    fi
}

# Collect PyPI download statistics
collect_pypi_downloads() {
    log "Collecting PyPI download statistics..."

    local output="$METRICS_DIR/pypi-downloads-$DATE.json"

    if curl -sf "https://pypistats.org/api/packages/$PYPI_PACKAGE/recent" > "$output"; then
        log "✅ Saved to $output"

        # Print summary
        local last_week
        last_week=$(jq -r '.data.last_week' "$output")
        local last_month
        last_month=$(jq -r '.data.last_month' "$output")
        log "   Last week: $last_week downloads | Last month: $last_month downloads"
    else
        error "Failed to collect PyPI stats"
        return 1
    fi
}

# Collect Docker Hub statistics
collect_docker_hub() {
    log "Collecting Docker Hub statistics..."

    local output="$METRICS_DIR/docker-hub-$DATE.json"

    if curl -sf "https://hub.docker.com/v2/repositories/$DOCKER_REPO" | \
       jq '{
           name: .name,
           pull_count: .pull_count,
           star_count: .star_count,
           description: .description,
           last_updated: .last_updated,
           is_automated: .is_automated
       }' > "$output"; then
        log "✅ Saved to $output"

        # Print summary
        local pulls
        pulls=$(jq -r '.pull_count' "$output")
        local stars
        stars=$(jq -r '.star_count' "$output")
        log "   Pulls: $pulls | Stars: $stars"
    else
        error "Failed to collect Docker Hub stats"
        return 1
    fi
}

# Collect telemetry events from GitHub Gist
collect_telemetry() {
    log "Collecting telemetry events from GitHub Gist..."

    local output="$METRICS_DIR/telemetry-events-$DATE.jsonl"

    if [[ -z "$GIST_ID" ]]; then
        warn "JMO_TELEMETRY_GIST_ID not set, skipping telemetry collection"
        return 0
    fi

    if gh gist view "$GIST_ID" --raw > "$output" 2>/dev/null; then
        log "✅ Saved to $output"

        # Count events
        local event_count
        event_count=$(wc -l < "$output" | tr -d ' ')
        log "   Total events: $event_count"

        # Count by event type
        if [[ "$event_count" -gt 0 ]]; then
            log "   Event types:"
            jq -r '.event' "$output" | sort | uniq -c | while read -r count event; do
                log "     - $event: $count"
            done
        fi
    else
        warn "Failed to collect telemetry (check GIST_ID and gh auth)"
        return 0  # Non-fatal
    fi
}

# Generate summary report
generate_summary() {
    log "Generating summary report..."

    local summary="$METRICS_DIR/summary-$DATE.md"

    cat > "$summary" <<EOF
# JMo Security — Metrics Summary

**Date:** $DATE
**Generated:** $(date)

---

## GitHub Repository

EOF

    # Add GitHub stats
    if [[ -f "$METRICS_DIR/github-repo-$DATE.json" ]]; then
        cat >> "$summary" <<EOF
- **Stars:** $(jq -r '.stars' "$METRICS_DIR/github-repo-$DATE.json")
- **Forks:** $(jq -r '.forks' "$METRICS_DIR/github-repo-$DATE.json")
- **Open Issues:** $(jq -r '.open_issues' "$METRICS_DIR/github-repo-$DATE.json")

EOF
    fi

    # Add traffic stats
    if [[ -f "$METRICS_DIR/github-traffic-$DATE.json" ]]; then
        cat >> "$summary" <<EOF
**Traffic (Last 14 Days):**
- **Total Views:** $(jq -r '.total_views' "$METRICS_DIR/github-traffic-$DATE.json")
- **Unique Visitors:** $(jq -r '.unique_visitors' "$METRICS_DIR/github-traffic-$DATE.json")

EOF
    fi

    # Add clone stats
    if [[ -f "$METRICS_DIR/github-clones-$DATE.json" ]]; then
        cat >> "$summary" <<EOF
**Clones (Last 14 Days):**
- **Total Clones:** $(jq -r '.total_clones' "$METRICS_DIR/github-clones-$DATE.json")
- **Unique Cloners:** $(jq -r '.unique_cloners' "$METRICS_DIR/github-clones-$DATE.json")

EOF
    fi

    # Add PyPI stats
    if [[ -f "$METRICS_DIR/pypi-downloads-$DATE.json" ]]; then
        cat >> "$summary" <<EOF
---

## PyPI Package

- **Last Week:** $(jq -r '.data.last_week' "$METRICS_DIR/pypi-downloads-$DATE.json") downloads
- **Last Month:** $(jq -r '.data.last_month' "$METRICS_DIR/pypi-downloads-$DATE.json") downloads

EOF
    fi

    # Add Docker Hub stats
    if [[ -f "$METRICS_DIR/docker-hub-$DATE.json" ]]; then
        cat >> "$summary" <<EOF
---

## Docker Hub

- **Pull Count:** $(jq -r '.pull_count' "$METRICS_DIR/docker-hub-$DATE.json")
- **Stars:** $(jq -r '.star_count' "$METRICS_DIR/docker-hub-$DATE.json")
- **Last Updated:** $(jq -r '.last_updated' "$METRICS_DIR/docker-hub-$DATE.json")

EOF
    fi

    # Add telemetry stats
    if [[ -f "$METRICS_DIR/telemetry-events-$DATE.jsonl" ]]; then
        local event_count
        event_count=$(wc -l < "$METRICS_DIR/telemetry-events-$DATE.jsonl" | tr -d ' ')

        cat >> "$summary" <<EOF
---

## Telemetry

- **Total Events:** $event_count

EOF

        if [[ "$event_count" -gt 0 ]]; then
            cat >> "$summary" <<EOF
**Event Types:**

\`\`\`
EOF
            jq -r '.event' "$METRICS_DIR/telemetry-events-$DATE.jsonl" | sort | uniq -c >> "$summary"
            cat >> "$summary" <<EOF
\`\`\`

EOF
        fi
    fi

    cat >> "$summary" <<EOF
---

**Files:**

\`\`\`
EOF
    ls -lh "$METRICS_DIR"/*"$DATE"* >> "$summary"
    cat >> "$summary" <<EOF
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

    # Collect metrics
    collect_github_repo
    collect_github_traffic
    collect_github_clones
    collect_pypi_downloads
    collect_docker_hub
    collect_telemetry

    # Generate summary
    generate_summary

    echo ""
    log "✅ Metrics collection complete!"
    log "View summary: cat $METRICS_DIR/summary-$DATE.md"
    echo ""
}

# Run main function
main "$@"
