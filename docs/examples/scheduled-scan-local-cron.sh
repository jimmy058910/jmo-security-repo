#!/usr/bin/env bash
# Example: Local Cron Script for JMo Security Scans
#
# This script demonstrates how to run JMo scans via cron on Linux/macOS.
#
# Setup Option 1: Use jmo schedule (RECOMMENDED)
# ------------------------------------------------
# jmo schedule create \
#   --name nightly-scan \
#   --cron "0 2 * * *" \
#   --profile balanced \
#   --repos-dir ~/repos \
#   --backend local-cron
#
# jmo schedule install nightly-scan
#
# Setup Option 2: Manual crontab entry
# -------------------------------------
# 1. Make this script executable: chmod +x scheduled-scan-local-cron.sh
# 2. Add to crontab: crontab -e
# 3. Add line: 0 2 * * * /path/to/scheduled-scan-local-cron.sh >> /var/log/jmo-scan.log 2>&1

set -euo pipefail

# Configuration
PROFILE="${JMO_PROFILE:-balanced}"
REPOS_DIR="${JMO_REPOS_DIR:-$HOME/repos}"
RESULTS_DIR="${JMO_RESULTS_DIR:-$HOME/jmo-results/$(date +%Y-%m-%d)}"
SLACK_WEBHOOK="${SLACK_WEBHOOK_URL:-}"

# Logging
LOG_FILE="/var/log/jmo-security/scan-$(date +%Y-%m-%d).log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "========================================="
echo "JMo Security Scan - $(date)"
echo "Profile: $PROFILE"
echo "Repos: $REPOS_DIR"
echo "Results: $RESULTS_DIR"
echo "========================================="

# Run scan
if jmo scan \
    --profile "$PROFILE" \
    --repos-dir "$REPOS_DIR" \
    --results-dir "$RESULTS_DIR" \
    --allow-missing-tools \
    --human-logs; then

    echo "✅ Scan completed successfully"

    # Generate summary
    cat "$RESULTS_DIR/summaries/SUMMARY.md"

    # Optional: Send success notification to Slack
    if [ -n "$SLACK_WEBHOOK" ]; then
        curl -X POST -H 'Content-Type: application/json' \
            -d "{\"text\": \"✅ JMo Security Scan completed successfully\"}" \
            "$SLACK_WEBHOOK"
    fi

else
    echo "❌ Scan failed with exit code $?"

    # Optional: Send failure notification to Slack
    if [ -n "$SLACK_WEBHOOK" ]; then
        curl -X POST -H 'Content-Type: application/json' \
            -d "{\"text\": \"🚨 JMo Security Scan failed - check logs at $LOG_FILE\"}" \
            "$SLACK_WEBHOOK"
    fi

    exit 1
fi

# Optional: Cleanup old results (keep last 7 days)
find "$HOME/jmo-results" -maxdepth 1 -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null || true

echo "========================================="
echo "Scan complete - $(date)"
echo "========================================="
