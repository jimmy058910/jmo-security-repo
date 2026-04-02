#!/usr/bin/env bash
# JMo Security Telemetry Dashboard
# View usage analytics from GitHub Gist backend
#
# Usage:
#   ./scripts/dev/view_telemetry.sh              # Show dashboard
#   ./scripts/dev/view_telemetry.sh --raw        # Show raw JSONL
#   ./scripts/dev/view_telemetry.sh --export     # Export to CSV

set -euo pipefail

GIST_ID="${JMO_TELEMETRY_GIST_ID-}"
TELEMETRY_FILE="/tmp/jmo-telemetry-events.jsonl"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check prerequisites
if [ -z "$GIST_ID" ]; then
  echo -e "${RED}❌ Error: JMO_TELEMETRY_GIST_ID environment variable not set${NC}"
  echo "   Set it with: export JMO_TELEMETRY_GIST_ID=your-gist-id"
  exit 1
fi

if ! command -v gh &>/dev/null; then
  echo -e "${RED}❌ Error: GitHub CLI (gh) not installed${NC}"
  echo "   Install: https://cli.github.com/"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo -e "${RED}❌ Error: jq not installed${NC}"
  echo "   Install: sudo apt install jq (Linux) or brew install jq (macOS)"
  exit 1
fi

# Fetch telemetry data
echo -e "${CYAN}🔄 Fetching telemetry data from Gist...${NC}"
if ! gh gist view "$GIST_ID" --raw >"$TELEMETRY_FILE" 2>/dev/null; then
  echo -e "${RED}❌ Failed to fetch Gist data${NC}"
  echo "   Check GIST_ID and GitHub authentication: gh auth status"
  exit 1
fi

TOTAL_EVENTS=$(wc -l <"$TELEMETRY_FILE")
echo -e "${GREEN}✅ Downloaded $TOTAL_EVENTS events${NC}"
echo

# Handle command-line arguments
if [ "${1-}" = "--raw" ]; then
  cat "$TELEMETRY_FILE" | jq .
  exit 0
fi

if [ "${1-}" = "--export" ]; then
  OUTPUT_FILE="telemetry-export-$(date +%Y%m%d-%H%M%S).csv"
  echo "event,timestamp,platform,python_version,profile,mode,duration,tools_count" >"$OUTPUT_FILE"
  jq -r '[.event, .timestamp, .platform, .python_version, (.metadata.profile // ""), (.metadata.mode // ""), (.metadata.duration_bucket // ""), (.metadata.tools | length // 0)] | @csv' "$TELEMETRY_FILE" >>"$OUTPUT_FILE"
  echo -e "${GREEN}✅ Exported to $OUTPUT_FILE${NC}"
  exit 0
fi

# === TELEMETRY DASHBOARD ===

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        📊 JMo Security Telemetry Dashboard                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo

# Summary stats
echo -e "${YELLOW}📈 Summary Statistics${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
UNIQUE_USERS=$(jq -r '.anonymous_id' "$TELEMETRY_FILE" | sort -u | wc -l)
SCAN_STARTED=$(jq -r 'select(.event == "scan.started")' "$TELEMETRY_FILE" | wc -l)
SCAN_COMPLETED=$(jq -r 'select(.event == "scan.completed")' "$TELEMETRY_FILE" | wc -l)
WIZARD_COMPLETED=$(jq -r 'select(.event == "wizard.completed")' "$TELEMETRY_FILE" | wc -l)
TOOL_FAILURES=$(jq -r 'select(.event == "tool.failed")' "$TELEMETRY_FILE" | wc -l)

printf "  %-30s %10d\n" "Total Events:" "$TOTAL_EVENTS"
printf "  %-30s %10d\n" "Unique Users:" "$UNIQUE_USERS"
printf "  %-30s %10d\n" "Scans Started:" "$SCAN_STARTED"
printf "  %-30s %10d\n" "Scans Completed:" "$SCAN_COMPLETED"
printf "  %-30s %10d\n" "Wizard Sessions:" "$WIZARD_COMPLETED"
printf "  %-30s %10d\n" "Tool Failures:" "$TOOL_FAILURES"
echo

# Event type breakdown
echo -e "${YELLOW}📋 Event Type Breakdown${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
jq -r '.event' "$TELEMETRY_FILE" | sort | uniq -c | sort -rn | while read -r count event; do
  printf "  %-40s %8d\n" "$event" "$count"
done
echo

# Platform distribution
echo -e "${YELLOW}💻 Platform Distribution${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if jq -e 'select(.platform)' "$TELEMETRY_FILE" &>/dev/null; then
  jq -r 'select(.platform) | .platform' "$TELEMETRY_FILE" | sort | uniq -c | sort -rn | while read -r count platform; do
    percentage=$((count * 100 / TOTAL_EVENTS))
    printf "  %-30s %5d (%3d%%)\n" "$platform" "$count" "$percentage"
  done
else
  echo "  (No platform data yet)"
fi
echo

# Python version distribution
echo -e "${YELLOW}🐍 Python Version Distribution${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if jq -e 'select(.python_version)' "$TELEMETRY_FILE" &>/dev/null; then
  jq -r 'select(.python_version) | .python_version' "$TELEMETRY_FILE" | sort | uniq -c | sort -rn | while read -r count version; do
    printf "  %-30s %5d\n" "$version" "$count"
  done
else
  echo "  (No Python version data yet)"
fi
echo

# Profile popularity (scan.started events)
echo -e "${YELLOW}🎯 Profile Popularity${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$SCAN_STARTED" -gt 0 ]; then
  jq -r 'select(.event == "scan.started") | .metadata.profile' "$TELEMETRY_FILE" 2>/dev/null | sort | uniq -c | sort -rn | while read -r count profile; do
    percentage=$((count * 100 / SCAN_STARTED))
    printf "  %-30s %5d (%3d%%)\n" "$profile" "$count" "$percentage"
  done
else
  echo "  (No scan.started events yet)"
fi
echo

# Execution mode breakdown
echo -e "${YELLOW}🚀 Execution Mode${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$SCAN_STARTED" -gt 0 ]; then
  jq -r 'select(.event == "scan.started") | .metadata.mode' "$TELEMETRY_FILE" 2>/dev/null | sort | uniq -c | sort -rn | while read -r count mode; do
    percentage=$((count * 100 / SCAN_STARTED))
    printf "  %-30s %5d (%3d%%)\n" "$mode" "$count" "$percentage"
  done
else
  echo "  (No scan.started events yet)"
fi
echo

# Top tools used
echo -e "${YELLOW}🔧 Most Popular Tools${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$SCAN_STARTED" -gt 0 ]; then
  jq -r 'select(.event == "scan.started") | .metadata.tools[]' "$TELEMETRY_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | while read -r count tool; do
    printf "  %-30s %5d\n" "$tool" "$count"
  done
else
  echo "  (No scan.started events yet)"
fi
echo

# Tool failure analysis
echo -e "${YELLOW}❌ Tool Failures${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$TOOL_FAILURES" -gt 0 ]; then
  jq -r 'select(.event == "tool.failed") | .metadata.tool' "$TELEMETRY_FILE" 2>/dev/null | sort | uniq -c | sort -rn | while read -r count tool; do
    printf "  %-30s %5d\n" "$tool" "$count"
  done
else
  echo -e "  ${GREEN}(No tool failures - great job!)${NC}"
fi
echo

# Scan duration distribution
echo -e "${YELLOW}⏱️  Scan Duration Distribution${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$SCAN_COMPLETED" -gt 0 ]; then
  jq -r 'select(.event == "scan.completed") | .metadata.duration_bucket' "$TELEMETRY_FILE" 2>/dev/null | sort | uniq -c | sort -k2 | while read -r count bucket; do
    percentage=$((count * 100 / SCAN_COMPLETED))
    printf "  %-30s %5d (%3d%%)\n" "$bucket" "$count" "$percentage"
  done
else
  echo "  (No scan.completed events yet)"
fi
echo

# Target type distribution
echo -e "${YELLOW}🎯 Target Type Distribution${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$SCAN_STARTED" -gt 0 ]; then
  for target_type in repos images urls iac gitlab k8s; do
    total=$(jq -r "select(.event == \"scan.started\") | .metadata.target_types.$target_type // 0" "$TELEMETRY_FILE" 2>/dev/null | awk '{s+=$1} END {print s+0}')
    if [ "$total" -gt 0 ]; then
      printf "  %-30s %5d\n" "$target_type" "$total"
    fi
  done
else
  echo "  (No scan.started events yet)"
fi
echo

# Local telemetry status
echo -e "${YELLOW}🏠 Your Local Telemetry Status${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ -f ~/.jmo-security/telemetry-id ]; then
  echo "  Your anonymous ID: $(cat ~/.jmo-security/telemetry-id)"
else
  echo "  No telemetry ID found (telemetry disabled)"
fi

if [ -f ~/.jmo-security/scan-count ]; then
  local_scans=$(cat ~/.jmo-security/scan-count)
  echo "  Your local scan count: $local_scans"

  if [ "$SCAN_STARTED" -gt 0 ]; then
    contribution=$((SCAN_STARTED * 100 / local_scans))
    echo "  Events uploaded: $SCAN_STARTED / $local_scans ($contribution%)"
  fi
else
  echo "  No scan count found"
fi
echo

# Recent events (last 10)
echo -e "${YELLOW}📅 Recent Events (last 10)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$TOTAL_EVENTS" -gt 0 ]; then
  tail -10 "$TELEMETRY_FILE" | jq -r '. | "\(.timestamp) | \(.event) | \(.platform // "N/A")"' 2>/dev/null | while read -r line; do
    echo "  $line"
  done
else
  echo "  (No events)"
fi
echo

# Footer
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Dashboard updated successfully!${NC}"
echo
echo -e "${CYAN}💡 Tips:${NC}"
echo "  - View raw data: $0 --raw"
echo "  - Export to CSV: $0 --export"
echo "  - Query specific data: jq 'select(.event == \"scan.started\")' $TELEMETRY_FILE"
echo "  - Disable telemetry: Edit jmo.yml and set telemetry.enabled: false"
echo
